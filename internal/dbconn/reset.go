package dbconn

import (
	"context"
	"net/url"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// TicketLifetime is how long a password reset link works (D-0019).
const TicketLifetime = 24 * time.Hour

// StartReset creates a single-use ticket for user and emails the reset link.
// It sends synchronously; callers run it through h.goRun.
func (h *Handlers) StartReset(ctx context.Context, res tenant.Resolved, conn *store.Connection, user *store.User, clientID, lang string) error {
	now := h.now().UTC()
	raw := secrets.RandomString(43)
	tk := &store.PasswordResetTicket{
		TenantID: res.Tenant.ID, ID: "prt_" + secrets.RandomString(24), TokenHash: secrets.HashToken(raw),
		UserID: user.UserID, Connection: conn.Name, ClientID: clientID, Lang: lang,
		ExpiresAt: now.Add(TicketLifetime), CreatedAt: now,
	}
	if err := h.Store.PasswordResetTickets().Create(ctx, tk); err != nil {
		return err
	}
	link := res.Issuer() + "u/reset-password?" + url.Values{"ticket": {raw}}.Encode()
	m := email.ResetPassword(i18n.New(res.Tenant, lang), link)
	m.To = user.Email
	return h.Mailer.Send(ctx, m)
}

// RequestReset sends user a reset link in the background, unless the user
// is blocked or has reached the per-user send limit. The hosted
// forgot-password page and /dbconnections/change_password share the limit.
func (h *Handlers) RequestReset(res tenant.Resolved, conn *store.Connection, user *store.User, clientID, lang string) {
	if user.Blocked || !h.SendThrottle.Attempt("reset|"+res.Tenant.ID+"|"+conn.Name+"|"+user.UserID) {
		return
	}
	h.goRun(func() {
		// The request context ends with the response.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := h.StartReset(ctx, res, conn, user, clientID, lang); err != nil {
			h.log().Error("send reset email", "err", err, "tenant", res.Tenant.ID, "user_id", user.UserID)
		}
	})
}

func (h *Handlers) goRun(f func()) {
	if h.Go != nil {
		h.Go(f)
		return
	}
	go f()
}
