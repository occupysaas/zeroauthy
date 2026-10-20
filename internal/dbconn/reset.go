package dbconn

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// TicketLifetime is how long a password reset link works (D-0019).
const TicketLifetime = 24 * time.Hour

// IssueTicket stores a single-use password-reset ticket for the user's
// identity on connection, valid for lifetime from now, and returns the raw
// token for the link. Only its hash is stored.
func IssueTicket(ctx context.Context, st store.Store, tenantID, userID, connection, clientID, lang string, now time.Time, lifetime time.Duration) (string, error) {
	return IssueResetTicket(ctx, st, store.PasswordResetTicket{
		TenantID: tenantID, UserID: userID, Connection: connection, ClientID: clientID, Lang: lang,
	}, 43, now, lifetime)
}

// IssueResetTicket stores tk as a new password-reset ticket with a random
// token of tokenLen characters, valid for lifetime from now, and returns
// the raw token. It sets ID, TokenHash, ExpiresAt and CreatedAt.
func IssueResetTicket(ctx context.Context, st store.Store, tk store.PasswordResetTicket, tokenLen int, now time.Time, lifetime time.Duration) (string, error) {
	now = now.UTC()
	raw := secrets.RandomString(tokenLen)
	tk.ID, tk.TokenHash = "prt_"+secrets.RandomString(24), secrets.HashToken(raw)
	tk.ExpiresAt, tk.CreatedAt, tk.UsedAt = now.Add(lifetime), now, nil
	if err := st.PasswordResetTickets().Create(ctx, &tk); err != nil {
		return "", err
	}
	return raw, nil
}

// TicketTokenLength is the length of the token in a Management API ticket
// link: 32 letters and digits, as Auth0's (U6).
const TicketTokenLength = 32

// VerificationTicketLifetime is the default lifetime of an email
// verification or password-change ticket: 432000 seconds (5 days, U6).
const VerificationTicketLifetime = 432000 * time.Second

// IssueVerificationTicket stores tk as a new email verification ticket,
// valid for lifetime from now, and returns the raw token. It sets ID,
// TokenHash, ExpiresAt and CreatedAt.
func IssueVerificationTicket(ctx context.Context, st store.Store, tk store.EmailVerificationTicket, now time.Time, lifetime time.Duration) (string, error) {
	now = now.UTC()
	raw := secrets.RandomString(TicketTokenLength)
	tk.ID, tk.TokenHash = "evt_"+secrets.RandomString(24), secrets.HashToken(raw)
	tk.ExpiresAt, tk.CreatedAt, tk.UsedAt = now.Add(lifetime), now, nil
	if err := st.EmailVerificationTickets().Create(ctx, &tk); err != nil {
		return "", err
	}
	return raw, nil
}

// VerificationConnection is the connection a user's email is verified
// on: its database identity's, or else its first identity's.
func VerificationConnection(u *store.User) string {
	for _, id := range u.Identities {
		if id.Provider == store.StrategyDatabase {
			return id.Connection
		}
	}
	if len(u.Identities) > 0 {
		return u.Identities[0].Connection
	}
	return ""
}

// VerificationLink is the hosted email verification page for a raw
// ticket, in Auth0's form (U6): https://<host>/u/email-verification?ticket=<token>#.
func VerificationLink(issuer, raw string) string {
	return issuer + "u/email-verification?" + url.Values{"ticket": {raw}}.Encode() + "#"
}

// PasswordChangeLink is the link of a Management API password-change
// ticket, in Auth0's form (U6): https://<host>/u/reset-verify?ticket=<token>#.
// The page forwards to the new-password form.
func PasswordChangeLink(issuer, raw string) string {
	return issuer + "u/reset-verify?" + url.Values{"ticket": {raw}}.Encode() + "#"
}

// ResetLink is the hosted new-password page for a raw ticket, under the
// tenant's issuer (https://<host>/).
func ResetLink(issuer, raw string) string {
	return issuer + "u/reset-password?" + url.Values{"ticket": {raw}}.Encode()
}

// StartReset creates a single-use ticket for user and emails the reset link.
// It sends synchronously; callers run it through h.goRun.
func (h *Handlers) StartReset(ctx context.Context, res tenant.Resolved, conn *store.Connection, user *store.User, clientID, lang string) error {
	raw, err := IssueTicket(ctx, h.Store, res.Tenant.ID, user.UserID, conn.Name, clientID, lang, h.now(), TicketLifetime)
	if err != nil {
		return err
	}
	link := ResetLink(res.Issuer(), raw)
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

// goRun runs f in the background; see RunInBackground.
func (h *Handlers) goRun(f func()) { RunInBackground(h.log(), h.Go, f) }

// RunInBackground runs f through spawn (nil: a go statement). A panic in f
// is logged and swallowed so that a failed send cannot crash the server.
// The panic value is not logged, since it may hold the message (and its
// link); runtime errors, which carry no message data, are.
func RunInBackground(log *slog.Logger, spawn func(func()), f func()) {
	safe := func() {
		defer func() {
			if v := recover(); v != nil {
				attrs := []any{"panic_type", fmt.Sprintf("%T", v), "stack", string(debug.Stack())}
				if re, ok := v.(runtime.Error); ok {
					attrs = append(attrs, "err", re.Error())
				}
				log.Error("background send panicked", attrs...)
			}
		}()
		f()
	}
	if spawn != nil {
		spawn(safe)
		return
	}
	go safe()
}
