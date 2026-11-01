package logs

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const purgeLeaseKey = "logs/retention"
const purgeLeaseDuration = time.Minute
const purgeLimit = 1000

// Purger shares the existing fenced lease repository with certificate workers.
// Every bounded deletion transaction checks ownership, preventing an expired
// sweeper from deleting after another instance takes over.
type Purger struct {
	st        store.Store
	cfg       Config
	log       *slog.Logger
	warningMu sync.Mutex
	warned    bool
	lastWarn  time.Time
}

func NewPurger(st store.Store, cfg Config, log *slog.Logger) *Purger {
	if log == nil {
		log = slog.Default()
	}
	return &Purger{st: st, cfg: cfg.defaults(), log: slog.New(logscrub.Handler(log.Handler()))}
}
func (p *Purger) Run(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := p.Sweep(ctx); err != nil && ctx.Err() == nil {
				p.log.Warn("tenant log retention sweep failed")
			}
		}
	}
}
func (p *Purger) Sweep(ctx context.Context) error {
	if probe, ok := p.st.(store.LogsSupporter); ok {
		if err := probe.CheckLogsSupport(ctx); errors.Is(err, store.ErrLogsUnavailable) {
			p.warnUnavailable()
			return nil
		} else if err != nil {
			return err
		}
		if !probe.LogsSupported() {
			p.warnUnavailable()
			return nil
		}
	}
	lease, err := p.st.TLSAssets().ClaimLease(ctx, purgeLeaseKey, secrets.RandomString(24), purgeLeaseDuration)
	if errors.Is(err, store.ErrTLSAssetRepositoryUnavailable) {
		p.warnUnavailable()
		return nil
	}
	if errors.Is(err, store.ErrConflict) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		release, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.st.TLSAssets().ReleaseLease(release, *lease)
	}()
	before := p.cfg.Now().Add(-p.cfg.Retention)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		renewed, err := p.st.TLSAssets().RenewLease(ctx, *lease, purgeLeaseDuration)
		if err != nil {
			return err
		}
		lease = renewed
		n := 0
		err = p.st.WithTx(ctx, func(tx store.Store) error {
			if err := tx.TLSAssets().CheckLease(ctx, *lease); err != nil {
				return err
			}
			var err error
			n, err = tx.Logs().PurgeLogs(ctx, before, purgeLimit)
			return err
		})
		if errors.Is(err, store.ErrLogsUnavailable) {
			p.warnUnavailable()
			return nil
		}
		if err != nil {
			return err
		}
		if n < purgeLimit {
			return nil
		}
	}
}

func (p *Purger) warnUnavailable() {
	p.warningMu.Lock()
	defer p.warningMu.Unlock()
	now := p.cfg.Now()
	if p.warned && now.Sub(p.lastWarn) < time.Hour {
		return
	}
	p.warned = true
	p.lastWarn = now
	p.log.Warn("tenant log retention unavailable")
}
