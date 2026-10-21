package jobs

import (
	"context"
	"errors"
	"log/slog"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// VerificationSender sends a user the email that verifies their address.
// login.VerificationMailer implements it.
type VerificationSender interface {
	SendVerification(ctx context.Context, tenantID string, u *store.User, clientID string) error
}

// VerifyEmail runs verification_email jobs: it emails the user a
// verification link. The job's Params hold "user_id" and, optionally,
// "client_id" (strings).
type VerifyEmail struct {
	// Sender may be nil: nothing is sent and the job completes.
	Sender VerificationSender
	Log    *slog.Logger
}

// Run implements Processor. A user who was deleted since the request fails
// the job; a send error is returned for the runner to log.
func (p VerifyEmail) Run(ctx context.Context, st store.Store, j *store.Job, _ Lease) (store.JobStatus, string, error) {
	userID, _ := j.Params["user_id"].(string)
	clientID, _ := j.Params["client_id"].(string)
	u, err := st.Users().Get(ctx, j.TenantID, userID)
	if errors.Is(err, store.ErrNotFound) {
		return store.JobFailed, "", nil
	}
	if err != nil {
		return "", "", err
	}
	// Known deviation: the request's "identity" is validated and stored,
	// but VerificationSender has no connection parameter, so the email
	// verifies the user's default database identity (dbconn.VerificationConnection).
	if p.Sender == nil {
		if p.Log != nil {
			p.Log.DebugContext(ctx, "verification email job not sent: no sender is configured", "tenant", j.TenantID, "user_id", userID)
		}
		return store.JobCompleted, "", nil
	}
	if err := p.Sender.SendVerification(ctx, j.TenantID, u, clientID); err != nil {
		return "", "", err
	}
	return store.JobCompleted, "", nil
}
