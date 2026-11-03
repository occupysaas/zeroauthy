package app

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/jobs"
	"github.com/zeroauthy/zeroauthy/internal/logs"
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

// mfaPurgeBatch and mfaPurgeBatches bound one sweep's MFA purge so a backlog
// drains over several sweeps without one long-running delete.
const mfaPurgeBatch, mfaPurgeBatches = 500, 20

// purgeMFA deletes expired MFA tokens, challenges, tickets and browser rows.
func purgeMFA(ctx context.Context, st store.Store, before time.Time) (int, error) {
	total := 0
	for range mfaPurgeBatches {
		n, err := st.MFA().PurgeMFA(ctx, before, mfaPurgeBatch)
		if errors.Is(err, store.ErrMFAUnavailable) {
			return total, nil // an old storage plugin: no MFA rows exist
		}
		total += n
		if err != nil || n < mfaPurgeBatch {
			return total, err
		}
	}
	return total, nil
}

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
		{func(ctx context.Context, before time.Time) (int, error) {
			return jobs.SweepExpired(ctx, st.Jobs(), before)
		}, now},
		{func(ctx context.Context, before time.Time) (int, error) { return actions.PurgeJobs(ctx, st, before) }, now},
		{func(ctx context.Context, before time.Time) (int, error) {
			return actions.PurgeExecutions(ctx, st, before)
		}, now},
		{func(ctx context.Context, before time.Time) (int, error) { return purgeMFA(ctx, st, before) }, now},
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
			n, err := sweep(logs.WithRecorder(ctx, a.logs), a.store, time.Now().UTC())
			if err != nil {
				a.log.Error("purge expired records", "err", err)
			}
			if n > 0 {
				a.log.Debug("purged expired records", "count", n)
			}
		}
	}
}
