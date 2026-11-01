package events

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const purgeLeaseKey = "events/retention"
const purgeLeaseDuration = time.Minute
const purgeLimit = 1000

type Purger struct {
	st        store.Store
	retention time.Duration
	log       *slog.Logger
}

func NewPurger(st store.Store, cfg Config, log *slog.Logger) *Purger {
	retention := cfg.Retention
	if retention == 0 {
		retention = DefaultConfig().Retention
	}
	retention = max(retention, 24*time.Hour)
	if log == nil {
		log = slog.Default()
	}
	return &Purger{st: st, retention: retention, log: log}
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
				p.log.Warn("tenant event retention sweep failed")
			}
		}
	}
}

func (p *Purger) Sweep(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if probe, ok := p.st.(store.EventsSupporter); ok {
		err := probe.CheckEventsSupport(ctx)
		if errors.Is(err, store.ErrEventsUnavailable) || err == nil && !probe.EventsSupported() {
			return nil
		}
		if err != nil {
			return err
		}
	}
	lease, err := p.st.TLSAssets().ClaimLease(ctx, purgeLeaseKey, secrets.RandomString(24), purgeLeaseDuration)
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrTLSAssetRepositoryUnavailable) {
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
	before := time.Now().Add(-p.retention)
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
			n, err = tx.Events().PurgeEvents(ctx, before, purgeLimit)
			return err
		})
		if errors.Is(err, store.ErrEventsUnavailable) {
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
