package app

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/jobs"
	"github.com/zeroauthy/zeroauthy/internal/logout"
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

// purgeMFA deletes expired MFA tokens, challenges, tickets, browser rows and abandoned pending authenticators.
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

// purgeWebAuthn deletes expired passkey and platform enrollment snoozes.
func purgeWebAuthn(ctx context.Context, st store.Store, before time.Time) (int, error) {
	total := 0
	for range mfaPurgeBatches {
		n, err := st.WebAuthn().PurgeWebAuthn(ctx, before, mfaPurgeBatch)
		if errors.Is(err, store.ErrWebAuthnUnavailable) {
			return total, nil // storage without webauthn.v1 holds no snoozes
		}
		total += n
		if err != nil || n < mfaPurgeBatch {
			return total, err
		}
	}
	return total, nil
}

// purgeJTIs deletes expired client assertion and request object jtis.
func purgeJTIs(ctx context.Context, st store.Store, before time.Time) (int, error) {
	total := 0
	for range mfaPurgeBatches {
		n, err := st.ClientCredentials().PurgeJTIs(ctx, before, mfaPurgeBatch)
		if errors.Is(err, store.ErrClientCredentialsUnavailable) {
			return total, nil // storage without client_credentials.v1 holds no jtis
		}
		total += n
		if err != nil || n < mfaPurgeBatch {
			return total, err
		}
	}
	return total, nil
}

// purgePhone deletes expired passwordless codes and links.
func purgePhone(ctx context.Context, st store.Store, before time.Time) (int, error) {
	total := 0
	for range mfaPurgeBatches {
		n, err := st.Phone().PurgePhone(ctx, before, mfaPurgeBatch)
		if errors.Is(err, store.ErrPhoneUnavailable) {
			return total, nil // an old storage plugin: no passwordless rows exist
		}
		total += n
		if err != nil || n < mfaPurgeBatch {
			return total, err
		}
	}
	return total, nil
}

func purgeRefreshII(purge func(context.Context, time.Time, int) (int, error)) func(context.Context, time.Time) (int, error) {
	return func(ctx context.Context, before time.Time) (int, error) {
		total := 0
		for range mfaPurgeBatches {
			n, err := purge(ctx, before, mfaPurgeBatch)
			if errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
				return total, nil
			}
			total += n
			if err != nil || n < mfaPurgeBatch {
				return total, err
			}
		}
		return total, nil
	}
}

// sweep deletes expired records and returns how many it removed. A failure
// in one kind of record does not stop the others.
func sweep(ctx context.Context, st store.Store, now time.Time, notifications ...*logout.Service) (int, error) {
	expireSessions := st.Sessions().DeleteExpired
	if len(notifications) > 0 && notifications[0] != nil {
		expireSessions = func(ctx context.Context, before time.Time) (int, error) {
			total := 0
			for {
				if err := ctx.Err(); err != nil {
					return total, err
				}
				n, err := notifications[0].WithStore(st).SweepExpired(ctx, before, 100)
				if errors.Is(err, store.ErrOIDCLogoutUnavailable) {
					return st.Sessions().DeleteExpired(ctx, before)
				}
				total += n
				if err != nil || n < 100 {
					return total, err
				}
				// Yield between transactions without delaying a large backlog by ten minutes.
				timer := time.NewTimer(time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return total, ctx.Err()
				case <-timer.C:
				}
			}
		}
	}
	jobs := []struct {
		del    func(context.Context, time.Time) (int, error)
		before time.Time
	}{
		{st.AuthTransactions().DeleteExpired, now},
		{expireSessions, now},
		{st.AuthCodes().DeleteExpired, now.Add(-codeRetention)},
		{st.PushedAuthRequests().DeleteExpired, now},
		{st.DeviceCodes().DeleteExpired, now.Add(-deviceCodeRetention)},
		// CIBA requests count towards the pending limit for 24 hours after
		// they expire (Plan 41c).
		{func(ctx context.Context, before time.Time) (int, error) {
			repo, err := store.CIBA(ctx, st)
			if errors.Is(err, store.ErrCIBAUnavailable) {
				return 0, nil // an old storage plugin: no requests exist
			}
			if err != nil {
				return 0, err
			}
			return repo.DeleteExpiredCIBARequests(ctx, before)
		}, now.Add(-store.CIBAPendingWindow)},
		{st.RefreshTokens().DeleteExpired, now},
		{purgeRefreshII(st.TokenQuotas().PurgeBefore), now},
		{purgeRefreshII(st.DPoP().PurgeBefore), now},
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
		{func(ctx context.Context, before time.Time) (int, error) { return purgePhone(ctx, st, before) }, now},
		{func(ctx context.Context, before time.Time) (int, error) { return purgeWebAuthn(ctx, st, before) }, now},
		{func(ctx context.Context, before time.Time) (int, error) { return purgeJTIs(ctx, st, before) }, now},
		{func(ctx context.Context, before time.Time) (int, error) {
			return purgeGlobalRevocationJTIs(ctx, st, before)
		}, now},
		{func(ctx context.Context, before time.Time) (int, error) { return purgeSAMLAssertions(ctx, st, before) }, now},
		// AD/LDAP hub sessions of replicas that stopped (Plan 38a).
		{func(ctx context.Context, before time.Time) (int, error) { return purgeADHubSessions(ctx, st, before) }, now.Add(-10 * time.Minute)},
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
			n, err := sweep(logs.WithRecorder(ctx, a.logs), a.store, time.Now().UTC(), a.logout)
			if err != nil {
				a.log.Error("purge expired records", "err", err)
			}
			if n > 0 {
				a.log.Debug("purged expired records", "count", n)
			}
		}
	}
}

func purgeGlobalRevocationJTIs(ctx context.Context, st store.Store, before time.Time) (int, error) {
	repo, ok := st.(store.GlobalRevocationStore)
	if !ok {
		return 0, nil
	}
	total := 0
	for range mfaPurgeBatches {
		n, err := repo.PurgeGlobalRevocationJTIs(ctx, before, mfaPurgeBatch)
		if errors.Is(err, store.ErrOIDCLogoutUnavailable) {
			return total, nil
		}
		total += n
		if err != nil || n < mfaPurgeBatch {
			return total, err
		}
	}
	return total, nil
}

// purgeSAMLAssertions removes expired SAML replay entries (Plan 37a).
func purgeSAMLAssertions(ctx context.Context, st store.Store, before time.Time) (int, error) {
	repo, ok := st.(store.SAMLReplayStore)
	if !ok {
		return 0, nil
	}
	total := 0
	for range mfaPurgeBatches {
		n, err := repo.PurgeSAMLAssertions(ctx, before, mfaPurgeBatch)
		if errors.Is(err, store.ErrSAMLUnavailable) {
			return total, nil
		}
		total += n
		if err != nil || n < mfaPurgeBatch {
			return total, err
		}
	}
	return total, nil
}

// purgeADHubSessions removes AD/LDAP hub session rows no replica refreshes
// any more (Plan 38a).
func purgeADHubSessions(ctx context.Context, st store.Store, before time.Time) (int, error) {
	repo, err := store.ADHub(ctx, st)
	if errors.Is(err, store.ErrADHubUnavailable) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	total := 0
	for range mfaPurgeBatches {
		n, err := repo.PurgeADHubSessions(ctx, before, mfaPurgeBatch)
		total += n
		if err != nil || n < mfaPurgeBatch {
			return total, err
		}
	}
	return total, nil
}
