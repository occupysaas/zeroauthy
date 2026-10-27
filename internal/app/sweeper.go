package app

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// sweepInterval is how often expired records are purged.
const sweepInterval = 10 * time.Minute

// codeRetention keeps authorization codes this long after they expire, so
// a late replay is still recognized as a replay and revokes the tokens
// issued from the code.
const codeRetention = 24 * time.Hour

// deviceCodeRetention keeps an expired device code so the device's next
// poll gets expired_token once.
const deviceCodeRetention = 24 * time.Hour

// sweep deletes expired records and returns how many it removed. A failure
// in one kind of record does not stop the others.
func sweep(ctx context.Context, st store.Store, now time.Time) (int, error) {
	jobs := []struct {
		del    func(context.Context, time.Time) (int, error)
		before time.Time
	}{
		{st.AuthTransactions().DeleteExpired, now},
		{st.Sessions().DeleteExpired, now},
		{st.AuthCodes().DeleteExpired, now.Add(-codeRetention)},
		{st.PushedAuthRequests().DeleteExpired, now},
		{st.DeviceCodes().DeleteExpired, now.Add(-deviceCodeRetention)},
		{st.RefreshTokens().DeleteExpired, now},
		{st.PasswordResetTickets().DeleteExpired, now},
		{st.EmailVerificationTickets().DeleteExpired, now},
		{func(ctx context.Context, before time.Time) (int, error) {
			return st.EmailNotifications().Sweep(ctx, before, 100)
		}, now},
		{st.Jobs().DeleteExpired, now},
		{func(ctx context.Context, before time.Time) (int, error) {
			n, err := st.Federation().DeleteExpired(ctx, before)
			if errors.Is(err, store.ErrFederationUnavailable) {
				return 0, nil // an old storage plugin: no attempts exist
			}
			return n, err
		}, now},
	}
	total := 0
	var errs []error
	for _, j := range jobs {
		n, err := j.del(ctx, j.before)
		total += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	return total, errors.Join(errs...)
}

// sweepLoop runs sweep every interval until ctx is cancelled.
func (a *App) sweepLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := sweep(ctx, a.store, time.Now().UTC())
			if err != nil {
				a.log.Error("purge expired records", "err", err)
			}
			if n > 0 {
				a.log.Debug("purged expired records", "count", n)
			}
		}
	}
}
