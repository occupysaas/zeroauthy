package jobs

import (
	"context"
	"errors"
	"log/slog"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// VerificationSender sends a user the email that verifies their address.
// login.VerificationMailer implements it.
type VerificationSender interface {
	// host is the public host of the link.
	SendVerification(ctx context.Context, tenantID string, u *store.User, clientID, host string) error
}

// VerifyEmail runs verification_email jobs: it emails the user a
// verification link. The job's Params hold "user_id" and, optionally,
// "client_id" (strings). "selected_origin" is the link's host, chosen when
// the job was created; jobs queued before it existed use the canonical host.
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
	host, _ := j.Params["selected_origin"].(string)
	if host == "" {
		t, err := st.Tenants().Get(ctx, j.TenantID)
		if err != nil {
			return "", "", err
		}
		host = t.CanonicalHost
	}
	// Recheck just before the side effect; an unusable selection fails the
	// job visibly and sends nothing rather than switching hosts.
	switch err := customdomain.OriginUsable(ctx, st, j.TenantID, host); {
	case errors.Is(err, customdomain.ErrDomainUnavailable):
		return store.JobFailed, "The selected custom domain is not available; no email was sent.", nil
	case err != nil:
		return "", "", err
	}
	if p.Sender == nil {
		if p.Log != nil {
			p.Log.DebugContext(ctx, "verification email job not sent: no sender is configured", "tenant", j.TenantID, "user_id", userID)
		}
		return store.JobCompleted, "", nil
	}
	if err := p.Sender.SendVerification(ctx, j.TenantID, u, clientID, host); err != nil {
		return "", "", err
	}
	return store.JobCompleted, "", nil
}
