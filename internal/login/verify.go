package login

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/dbconn"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantview"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// VerificationMailer sends the email that verifies a user's address: it
// issues a fresh email verification ticket (432000 s, U6) and emails its
// link. It implements mgmt.VerificationSender and dbconn.SignupVerifier.
type VerificationMailer struct {
	Store store.Store
	// Mailer sends the email. Without one nothing is sent and nothing
	// fails, so a signup still succeeds.
	Mailer email.Mailer
	// Email routes tenant templates and providers; Mailer remains the
	// compatibility fallback when a flow has no configured template.
	Email *email.Service
	// BaseDomain is server.base_domain. It names the tenant's host when the
	// context does not carry the request's (a background job).
	BaseDomain string
	Log        *slog.Logger
	Now        func() time.Time
	Go         func(func()) // runs background sends; nil = go statement
}

func (m *VerificationMailer) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *VerificationMailer) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

// SendVerification emails u a verification link in the tenant's default
// language. clientID is the application the email is for, or empty. The
// link uses the host of the request in ctx when it was addressed to the
// tenant, otherwise the tenant's first host.
func (m *VerificationMailer) SendVerification(ctx context.Context, tenantID string, u *store.User, clientID string) error {
	if u.Email == "" {
		return nil
	}
	res, err := m.resolve(ctx, tenantID)
	if err != nil {
		return err
	}
	return m.Send(ctx, res, u, clientID, i18n.Negotiate(res.Tenant, "", ""))
}

func (m *VerificationMailer) resolve(ctx context.Context, tenantID string) (tenant.Resolved, error) {
	if res, ok := tenant.FromContext(ctx); ok && res.Tenant != nil && res.Tenant.ID == tenantID && res.Host != "" {
		return res, nil
	}
	t, err := m.Store.Tenants().Get(ctx, tenantID)
	if err != nil {
		return tenant.Resolved{}, err
	}
	issuers := tenant.Issuers(t, m.BaseDomain)
	if len(issuers) == 0 {
		return tenant.Resolved{}, fmt.Errorf("login: tenant %q has no host for a verification link", t.Name)
	}
	host := strings.TrimSuffix(strings.TrimPrefix(issuers[0], "https://"), "/")
	return tenant.Resolved{Tenant: t, Host: host}, nil
}

// Send emails u a verification link in lang. It sends synchronously.
func (m *VerificationMailer) Send(ctx context.Context, res tenant.Resolved, u *store.User, clientID, lang string) error {
	if u.Email == "" {
		return nil
	}
	if m.Mailer == nil && m.Email == nil {
		m.log().DebugContext(ctx, "verification email not sent: no mailer is configured", "tenant", res.Tenant.ID, "user_id", u.UserID)
		return nil
	}
	var policy email.Policy
	if m.Email != nil {
		var err error
		policy, err = m.Email.Resolve(ctx, res.Tenant.ID, "verify_email")
		if err != nil {
			return err
		}
		if policy.Template != nil {
			if !policy.Enabled {
				return nil
			}
			if err = email.ValidateEmailRedirect(ctx, m.Store, res.Tenant.ID, clientID, policy.ResultURL); err != nil {
				return err
			}
		}
	}
	if policy.Template != nil {
		lifetime := policy.Lifetime
		if lifetime == 0 {
			lifetime = dbconn.VerificationTicketLifetime
		}
		raw, err := dbconn.IssueVerificationTicket(ctx, m.Store, store.EmailVerificationTicket{
			TenantID: res.Tenant.ID, UserID: u.UserID, Connection: dbconn.VerificationConnection(u), ClientID: clientID, Lang: lang,
			Email: strings.ToLower(u.Email), ResultURL: policy.ResultURL, IncludeEmailInRedirect: policy.IncludeEmailInRedirect,
		}, m.now(), lifetime)
		if err != nil {
			return err
		}
		return m.Email.Send(ctx, email.Event{TenantID: res.Tenant.ID, UserID: u.UserID, ClientID: clientID, Template: "verify_email", Language: lang, URL: dbconn.VerificationLink(res.Issuer(), raw)})
	}
	raw, err := dbconn.IssueVerificationTicket(ctx, m.Store, store.EmailVerificationTicket{
		TenantID: res.Tenant.ID, UserID: u.UserID, Connection: dbconn.VerificationConnection(u), ClientID: clientID, Lang: lang,
		Email: strings.ToLower(u.Email),
	}, m.now(), dbconn.VerificationTicketLifetime)
	if err != nil {
		return err
	}
	localized, err := tenantview.Localized(ctx, m.Store, res.Tenant)
	if err != nil {
		return err
	}
	msg := email.VerifyEmailMessage(i18n.New(localized, lang), dbconn.VerificationLink(res.Issuer(), raw))
	msg.To = u.Email
	if m.Email != nil {
		return m.Email.SendMessage(ctx, res.Tenant.ID, msg)
	}
	return m.Mailer.Send(ctx, msg)
}

// SendInBackground sends the verification email after a signup without
// holding up the response. A failure is logged.
func (m *VerificationMailer) SendInBackground(res tenant.Resolved, u *store.User, clientID, lang string) {
	dbconn.RunInBackground(m.log(), m.Go, func() {
		// The request context ends with the response.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.Send(ctx, res, u, clientID, lang); err != nil {
			m.log().Error("send verification email", "err", err, "tenant", res.Tenant.ID, "user_id", u.UserID)
		}
	})
}

func (m *VerificationMailer) SendWelcomeInBackground(tenantID, userID, clientID, language string) {
	if m.Email == nil {
		return
	}
	dbconn.RunInBackground(m.log(), m.Go, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.Email.Welcome(ctx, tenantID, userID, clientID, language); err != nil {
			m.log().Error("send welcome email", "err", err, "tenant", tenantID, "user_id", userID)
		}
	})
}

// sendSignupVerification sends a new user the verification email, as
// Auth0 does on signup, when the user has an unverified email.
func (h *Handlers) sendSignupVerification(f *flow, u *store.User) {
	if h.Verification == nil || u.Email == "" || u.EmailVerified {
		return
	}
	h.Verification.SendInBackground(f.res, u, f.txn.ClientID, f.view.L.Lang())
}

// verifyOutcome names the results of opening an email verification link.
type verifyOutcome int

const (
	verifyFailed verifyOutcome = iota // unknown or expired ticket, failed verify script
	verifySuccess
	verifyReused
	verifyAlready
)

// Redirect messages, as Auth0 sends them to result_url (U6).
const (
	msgVerified        = "Your email was verified. You can continue using the application."
	msgReused          = "This URL can be used only once"
	msgAlreadyVerified = "This account is already verified."
)

// queryEscape escapes a redirect parameter value, spaces as %20.
func queryEscape(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }

// resultRedirect is resultURL with params appended to its query, in order.
func resultRedirect(resultURL string, params [][2]string) (string, bool) {
	u, err := url.Parse(resultURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	var b strings.Builder
	b.WriteString(u.RawQuery)
	for _, p := range params {
		if b.Len() > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p[0] + "=" + queryEscape(p[1]))
	}
	u.RawQuery = b.String()
	return u.String(), true
}

// finishVerification answers an opened verification link: a redirect to
// the ticket's result_url with Auth0's parameters, or the result page. A
// failed verification always gets the page: the ticket may be unknown.
func (h *Handlers) finishVerification(w http.ResponseWriter, view ui.Tenant, tk *store.EmailVerificationTicket, emailAddr string, o verifyOutcome) {
	if tk != nil && tk.ResultURL != "" && o != verifyFailed {
		var params [][2]string
		withEmail := func() {
			if tk.IncludeEmailInRedirect && emailAddr != "" {
				params = append(params, [2]string{"email", emailAddr})
			}
		}
		support := [][2]string{{"supportSignUp", "true"}, {"supportForgotPassword", "true"}}
		switch o {
		case verifySuccess:
			params = append(params, support...)
			withEmail()
			params = append(params, [2]string{"message", msgVerified}, [2]string{"success", "true"}, [2]string{"code", "success"})
		case verifyReused:
			withEmail()
			params = append(params, [2]string{"message", msgReused}, [2]string{"success", "false"})
		case verifyAlready:
			params = append(params, support...)
			params = append(params, [2]string{"message", msgAlreadyVerified}, [2]string{"success", "false"}, [2]string{"code", "already-verified"})
		}
		if loc, ok := resultRedirect(tk.ResultURL, params); ok {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Location", loc)
			w.WriteHeader(http.StatusFound)
			return
		}
	}
	d := ui.EmailVerificationData{Title: view.L.T(i18n.KeyVerifyErrorTitle), Description: view.L.T(i18n.KeyVerifyErrorDescription)}
	status := http.StatusBadRequest
	switch o {
	case verifySuccess:
		d = ui.EmailVerificationData{Title: view.L.T(i18n.KeyVerifiedTitle), Description: view.L.T(i18n.KeyVerifiedDescription), Success: true}
		status = http.StatusOK
	case verifyAlready:
		d.Description = view.L.T(i18n.KeyAlreadyVerifiedDescription)
	}
	ui.RenderEmailVerification(w, status, view, d)
}

// EmailVerificationPage serves GET /u/email-verification?ticket=…. As on
// Auth0 (U6) opening the link verifies at once, with no button: it uses
// the ticket, sets email_verified (on a custom database connection not in
// import mode, only once the verify script answers true), then redirects
// to the ticket's result_url or shows the result page.
func (h *Handlers) EmailVerificationPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok {
		h.fail(w, r, errTxn, nil)
		return
	}
	view := ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
	raw := r.URL.Query().Get("ticket")
	if raw == "" {
		h.finishVerification(w, view, nil, "", verifyFailed)
		return
	}
	hash := secrets.HashToken(raw)
	tickets := h.Store.EmailVerificationTickets()
	tk, err := tickets.GetByTokenHash(ctx, res.Tenant.ID, hash)
	if errors.Is(err, store.ErrNotFound) {
		h.finishVerification(w, view, nil, "", verifyFailed)
		return
	} else if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	view = ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, tk.Lang))
	user, err := h.Store.Users().Get(ctx, res.Tenant.ID, tk.UserID)
	if errors.Is(err, store.ErrNotFound) {
		h.finishVerification(w, view, nil, "", verifyFailed)
		return
	} else if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	switch {
	case tk.UsedAt != nil:
		h.finishVerification(w, view, tk, user.Email, verifyReused)
		return
	case !h.now().Before(tk.ExpiresAt):
		h.finishVerification(w, view, nil, "", verifyFailed)
		return
	}
	// The ticket verifies only the address it was issued for. If the
	// user's email has changed since (a Management API PATCH, a custom
	// database profile sync), it verifies nothing.
	if !ticketEmailMatches(tk, user) {
		h.finishVerification(w, view, nil, "", verifyFailed)
		return
	}
	now := h.now()
	if user.EmailVerified {
		// The ticket is spent all the same, so reopening it says so.
		if _, err := tickets.Consume(ctx, res.Tenant.ID, hash, now); err != nil && !errors.Is(err, store.ErrAlreadyUsed) && !errors.Is(err, store.ErrNotFound) {
			h.fail(w, r, err, nil)
			return
		}
		h.finishVerification(w, view, tk, user.Email, verifyAlready)
		return
	}
	conn, err := h.Store.Connections().GetByName(ctx, res.Tenant.ID, tk.Connection)
	if errors.Is(err, store.ErrNotFound) {
		h.finishVerification(w, view, nil, "", verifyFailed)
		return
	} else if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	// The legacy store is the source of truth: its verify script must
	// accept first. The ticket stays usable when it does not.
	if identity.IsLegacy(conn) && !h.legacyVerify(ctx, conn, user) {
		h.finishVerification(w, view, nil, "", verifyFailed)
		return
	}
	// Use the ticket and set email_verified in one transaction, checking
	// the email again inside it: an email change that commits in between
	// cannot be verified by this ticket, and a failed update leaves the
	// ticket usable.
	outcome := verifySuccess
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		// Lock the user before the ticket: a concurrent PATCH locks the
		// user and then deletes its tickets, so this order cannot cycle.
		cur, err := tx.Users().GetForUpdate(ctx, res.Tenant.ID, tk.UserID)
		if errors.Is(err, store.ErrNotFound) {
			outcome = verifyFailed
			return errVerifyOutcome
		} else if err != nil {
			return err
		}
		switch _, err := tx.EmailVerificationTickets().Consume(ctx, res.Tenant.ID, hash, now); {
		case errors.Is(err, store.ErrAlreadyUsed):
			outcome = verifyReused
			return errVerifyOutcome
		case errors.Is(err, store.ErrNotFound):
			outcome = verifyFailed
			return errVerifyOutcome
		case err != nil:
			return err
		}
		if !ticketEmailMatches(tk, cur) {
			outcome = verifyFailed
			return errVerifyOutcome
		}
		if cur.EmailVerified {
			return nil
		}
		cur.EmailVerified, cur.UpdatedAt = true, now
		return tx.Users().Update(ctx, cur)
	})
	switch {
	case errors.Is(err, errVerifyOutcome):
		if outcome == verifyFailed {
			tk = nil
		}
		h.finishVerification(w, view, tk, user.Email, outcome)
		return
	case err != nil:
		h.fail(w, r, err, nil)
		return
	}
	h.log().InfoContext(ctx, "email verified", "tenant", res.Tenant.ID, "user_id", tk.UserID)
	if h.Verification != nil {
		h.Verification.SendWelcomeInBackground(res.Tenant.ID, tk.UserID, tk.ClientID, tk.Lang)
	}
	h.finishVerification(w, view, tk, user.Email, verifySuccess)
}

// errVerifyOutcome ends the verification transaction without writing; the
// outcome to show is set beside it.
var errVerifyOutcome = errors.New("login: verification not applied")

// ticketEmailMatches reports whether the user's current email is the one
// the ticket was issued for.
func ticketEmailMatches(tk *store.EmailVerificationTicket, u *store.User) bool {
	return u.Email != "" && strings.ToLower(u.Email) == tk.Email
}

// legacyVerify runs conn's verify script for the user's email and reports
// whether it answered true. A failure is logged, masked.
func (h *Handlers) legacyVerify(ctx context.Context, conn *store.Connection, u *store.User) bool {
	if h.Database == nil || h.Database.Scripts == nil {
		h.log().ErrorContext(ctx, "email verification: no custom database script runner", "connection", conn.Name)
		return false
	}
	c := h.Database.Scripts
	ok, err := c.Verify(ctx, conn, u.Email)
	if err != nil {
		h.log().ErrorContext(ctx, "email verification: verify script failed", "connection", conn.Name, "user_id", u.UserID, "err", c.Redactor(conn).RedactError(err))
		return false
	}
	if !ok {
		h.log().InfoContext(ctx, "email verification: verify script answered false", "connection", conn.Name, "user_id", u.UserID)
	}
	return ok
}

// setEmailVerified sets the user's email_verified.
func (h *Handlers) setEmailVerified(ctx context.Context, tenantID, userID string, now time.Time) error {
	return h.Store.WithTx(ctx, func(tx store.Store) error {
		u, err := tx.Users().GetForUpdate(ctx, tenantID, userID)
		if err != nil || u.EmailVerified {
			return err
		}
		u.EmailVerified, u.UpdatedAt = true, now
		return tx.Users().Update(ctx, u)
	})
}

// ResetVerify serves GET /u/reset-verify?ticket=…, the link of a
// Management API password-change ticket (U6). Like Auth0's, it forwards to
// the new-password form, which checks the ticket.
func (h *Handlers) ResetVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Location", "/u/reset-password?"+url.Values{"ticket": {r.URL.Query().Get("ticket")}}.Encode())
	w.WriteHeader(http.StatusFound)
}
