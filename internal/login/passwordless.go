package login

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/passwordless"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// The hosted passwordless prompt (login-passwordless): the identifier entry
// on /u/login, then the code screen of the connection's strategy. It sends
// codes only (D-0060 P24); magic links come from /passwordless/start.

// stepPasswordlessCode is the hosted step after a code was sent: the
// transaction's HostedState holds the normalized identifier and connection.
const stepPasswordlessCode = "passwordless-code"

// passwordlessCodeSuffixes are the text keys of the code screens (the
// catalogue test lists the same suffixes).
var passwordlessCodeSuffixes = []string{"pageTitle", "title", "description", "codePlaceholder", "buttonText", "resendText", "resendActionText", "editText", "logoAltText", "invalid-code"}

func passwordlessScreen(conn *store.Connection) string {
	if conn.Strategy == connrules.StrategySMS {
		return "login-passwordless-sms-otp"
	}
	return "login-passwordless-email-code"
}

func passwordlessCodePath(conn *store.Connection) string {
	return "/u/" + passwordlessScreen(conn)
}

func passwordlessCodeLocation(f *flow) string {
	return passwordlessCodePath(f.conn) + "?" + url.Values{"state": {f.txn.ID}}.Encode()
}

// passwordlessConnection returns the passwordless connection the
// transaction's login uses, or nil when it uses another kind. Per Auth0's
// documented table: connection=email|sms selects it; without a connection
// parameter it is used only when the application has no database
// connection, and then the one created first.
func (h *Handlers) passwordlessConnection(ctx context.Context, tenantID string, txn *store.AuthTransaction) (*store.Connection, error) {
	if h.Passwordless == nil || txn.Params[store.TxnParamOrgMode] == string(authz.OrgPromptBefore) {
		return nil, nil
	}
	want := txn.Params["connection"]
	if want != "" && !connrules.IsPasswordless(want) {
		return nil, nil
	}
	client, err := h.Store.Clients().Get(ctx, tenantID, txn.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNoConnection
	}
	if err != nil {
		return nil, err
	}
	conns, _, err := h.Store.Connections().List(ctx, tenantID, store.ConnectionFilter{}, store.Page{})
	if err != nil {
		return nil, err
	}
	oc, err := orglogin.Load(ctx, h.Store, tenantID, txn.Params)
	if err != nil {
		return nil, err
	}
	var candidates []*store.Connection
	for _, c := range EligibleConnections(conns, oc) {
		if !access.ConnectionUsable(client, c) {
			continue
		}
		if c.Strategy == store.StrategyDatabase && want == "" {
			return nil, nil
		}
		if connrules.IsPasswordless(c.Strategy) && c.Name == c.Strategy && (want == "" || c.Name == want) {
			candidates = append(candidates, c)
		}
	}
	if len(candidates) == 0 {
		if want != "" {
			return nil, errNoConnection
		}
		return nil, nil
	}
	slices.SortFunc(candidates, func(a, b *store.Connection) int {
		if n := a.CreatedAt.Compare(b.CreatedAt); n != 0 {
			return n
		}
		return strings.Compare(a.Name, b.Name)
	})
	return candidates[0], nil
}

// passwordlessFlow sets f.conn to the transaction's passwordless connection.
// ok false with a nil error means the transaction does not use one.
func (h *Handlers) passwordlessFlow(r *http.Request, f *flow) (bool, error) {
	conn, err := h.passwordlessConnection(r.Context(), f.res.Tenant.ID, f.txn)
	if err != nil || conn == nil {
		return false, err
	}
	f.conn = conn
	*r = *r.WithContext(events.Enrich(r.Context(), nil, conn))
	return true, nil
}

func (h *Handlers) passwordlessData(f *flow, identifier, message string) ui.PasswordlessData {
	return ui.PasswordlessData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, Identifier: identifier, Error: message, RedirectURI: f.txn.Params["redirect_uri"],
		Action: passwordlessCodePath(f.conn), Prefix: "login-passwordless." + passwordlessScreen(f.conn) + ".",
		SMS: f.conn.Strategy == connrules.StrategySMS,
	}
}

func (h *Handlers) renderPasswordlessIdentifier(w http.ResponseWriter, r *http.Request, status int, f *flow, identifier, message string) {
	if !h.prepareHostedForm(w, r, f, "login-id", "login-id") {
		return
	}
	d := h.passwordlessData(f, identifier, message)
	d.Revision = f.txn.HostedState.Revision
	if f.txn.Params["connection"] == "" {
		d.Social = h.socialButtons(r, f)
	}
	ui.RenderPasswordlessIdentifier(w, status, f.view, d)
}

func (h *Handlers) renderPasswordlessCode(w http.ResponseWriter, r *http.Request, status int, f *flow, message string) {
	if !h.prepareHostedForm(w, r, f, "login-passwordless", passwordlessScreen(f.conn)) {
		return
	}
	d := h.passwordlessData(f, f.txn.HostedState.Identifier, message)
	d.Revision = f.txn.HostedState.Revision
	ui.RenderPasswordlessCode(w, status, f.view, d)
}

// passwordlessPage is GET /u/login for a passwordless connection.
func (h *Handlers) passwordlessPage(w http.ResponseWriter, r *http.Request, f *flow) {
	switch f.txn.HostedState.Step {
	case "", "identifier":
		if !h.captchaPage(w, r, f, "passwordless") {
			return
		}
		h.renderPasswordlessIdentifier(w, r, http.StatusOK, f, f.txn.Params["login_hint"], "")
	case stepPasswordlessCode:
		http.Redirect(w, r, passwordlessCodeLocation(f), http.StatusSeeOther)
	default:
		h.fail(w, r, errTxn, f)
	}
}

// passwordlessIdentifierPost is POST /u/login for a passwordless
// connection: it sends a code and moves to the code screen.
func (h *Handlers) passwordlessIdentifierPost(w http.ResponseWriter, r *http.Request, f *flow) {
	if step := f.txn.HostedState.Step; step != "" && step != "identifier" {
		h.fail(w, r, errTxn, f)
		return
	}
	identifier := strings.TrimSpace(r.PostForm.Get("username"))
	redisplay := func(status int, message string) { h.renderPasswordlessIdentifier(w, r, status, f, identifier, message) }
	if !h.guardHostedForm(w, r, f, "login-id", "login-id", redisplay) {
		return
	}
	invalid := i18n.KeyPasswordlessInvalidEmail
	if f.conn.Strategy == connrules.StrategySMS {
		invalid = i18n.KeyPasswordlessInvalidPhone
	}
	if identifier == "" || len(identifier) > 320 || !utf8.ValidString(identifier) {
		redisplay(http.StatusBadRequest, f.view.L.T(invalid))
		return
	}
	ident, err := passwordless.NormalizeIdentifier(f.conn.Strategy, identifier)
	if err != nil {
		redisplay(http.StatusBadRequest, f.view.L.T(invalid))
		return
	}
	*r = *r.WithContext(logscrub.WithCredentials(r.Context(), ident))
	if err := h.submitCaptcha(r, f.res, &f.view, "passwordless", f.txn.ID, secrets.RandomString(32)); err != nil {
		status, key := captchaFailure(err)
		redisplay(status, f.view.L.T(key))
		return
	}
	if status, key, err := h.sendPasswordlessCode(r, f, ident); err != nil {
		h.fail(w, r, err, f)
		return
	} else if key == i18n.KeyErrSignupDisabled {
		ui.RenderError(w, status, f.view, f.view.L.T(key))
		return
	} else if key != "" {
		redisplay(status, f.view.L.T(key))
		return
	}
	next := f.txn.HostedState.Clone()
	next.Step = stepPasswordlessCode
	next.Identifier = ident
	next.ConnectionID = f.conn.ID
	if err := h.transitionHosted(r, f, next); err != nil {
		h.fail(w, r, errTxn, f)
		return
	}
	http.Redirect(w, r, passwordlessCodeLocation(f), http.StatusSeeOther)
}

// sendPasswordlessCode sends (or resends) a code for ident. A refusal is
// returned as a status and the text key to show; err is an internal failure.
func (h *Handlers) sendPasswordlessCode(r *http.Request, f *flow, ident string) (int, string, error) {
	in := passwordless.StartInput{
		TenantID: f.res.Tenant.ID, ClientID: f.txn.ClientID, Connection: f.conn.Name, Send: passwordless.KindCode, Hosted: true,
		IP: httpx.ClientIP(r, h.TrustProxyHeaders), UserAgent: r.UserAgent(), Locale: f.view.L.Lang(),
	}
	if f.conn.Strategy == connrules.StrategySMS {
		in.PhoneNumber = ident
	} else {
		in.Email = ident
	}
	_, err := h.Passwordless.Start(r.Context(), in)
	var pe *passwordless.Error
	if !errors.As(err, &pe) {
		return 0, "", err
	}
	switch {
	case pe.Status == http.StatusTooManyRequests:
		return pe.Status, i18n.KeyPasswordlessTooManySends, nil
	case pe.Description == passwordless.DescUserBlocked:
		return http.StatusForbidden, i18n.KeyUserBlocked, nil
	case pe.Description == passwordless.DescSignupDisabled:
		return http.StatusForbidden, i18n.KeyErrSignupDisabled, nil
	case pe.Description == passwordless.DescCountryNotAllowed:
		return http.StatusBadRequest, i18n.KeyPasswordlessCountryNotAllowed, nil
	case pe.Code == "invalid_request" && pe.Status == http.StatusBadRequest:
		if f.conn.Strategy == connrules.StrategySMS {
			return pe.Status, i18n.KeyPasswordlessInvalidPhone, nil
		}
		return pe.Status, i18n.KeyPasswordlessInvalidEmail, nil
	case pe.Code == "sms_provider_error" || pe.Code == "server_error":
		return http.StatusServiceUnavailable, i18n.KeyPasswordlessSendFailed, nil
	}
	// Other refusals (client or connection changed mid-login).
	return 0, "", errNoConnection
}

// codeFlow loads the transaction of a code screen. ok false means the
// response was written.
func (h *Handlers) codeFlow(w http.ResponseWriter, r *http.Request, f *flow) bool {
	ok, err := h.passwordlessFlow(r, f)
	if err != nil {
		h.fail(w, r, err, f)
		return false
	}
	if !ok || f.txn.HostedState.Step != stepPasswordlessCode || f.txn.HostedState.ConnectionID != f.conn.ID || r.URL.Path != passwordlessCodePath(f.conn) {
		h.fail(w, r, errTxn, f)
		return false
	}
	return true
}

// PasswordlessCodePage is GET /u/login-passwordless-email-code and
// /u/login-passwordless-sms-otp.
func (h *Handlers) PasswordlessCodePage(w http.ResponseWriter, r *http.Request) {
	f, err := h.loadTxn(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !h.codeFlow(w, r, f) {
		return
	}
	h.renderPasswordlessCode(w, r, http.StatusOK, f, "")
}

// PasswordlessCodeSubmit is POST of the code screens: verify the code,
// resend it (action=resend, within the send budget) or go back to the
// identifier (action=edit).
func (h *Handlers) PasswordlessCodeSubmit(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedTxn(w, r)
	if !ok || !h.codeFlow(w, r, f) {
		return
	}
	screen := passwordlessScreen(f.conn)
	redisplay := func(status int, message string) { h.renderPasswordlessCode(w, r, status, f, message) }
	if !h.guardHostedForm(w, r, f, "login-passwordless", screen, redisplay) {
		return
	}
	ident := f.txn.HostedState.Identifier
	*r = *r.WithContext(logscrub.WithCredentials(r.Context(), ident))
	switch r.PostForm.Get("action") {
	case "resend":
		status, key, err := h.sendPasswordlessCode(r, f, ident)
		switch {
		case err != nil:
			h.fail(w, r, err, f)
		case key == i18n.KeyErrSignupDisabled:
			ui.RenderError(w, status, f.view, f.view.L.T(key))
		case key != "":
			redisplay(status, f.view.L.T(key))
		default:
			redisplay(http.StatusOK, "")
		}
		return
	case "edit":
		if err := h.transitionHosted(r, f, store.HostedLoginState{}); err != nil {
			h.fail(w, r, errTxn, f)
			return
		}
		http.Redirect(w, r, "/u/login?"+url.Values{"state": {f.txn.ID}}.Encode(), http.StatusSeeOther)
		return
	}
	h.withFlowEvent(r, f)
	code := strings.TrimSpace(r.PostForm.Get("code"))
	ctx := passwordless.WithRequest(r.Context(), passwordless.RequestInfo{
		IP: httpx.ClientIP(r, h.TrustProxyHeaders), Hostname: r.Host, Method: r.Method, UserAgent: r.UserAgent(), Language: r.Header.Get("Accept-Language"),
	})
	user, err := h.Passwordless.VerifyCode(ctx, f.res.Tenant.ID, f.txn.ClientID, f.conn.Name, ident, code)
	var denied *identity.ErrSignupDenied
	var failed *identity.ErrSignupActionFailed
	switch {
	case errors.Is(err, passwordless.ErrInvalidCode):
		h.event(r, f, "f", nil)
		redisplay(http.StatusBadRequest, f.view.L.T("login-passwordless."+screen+".invalid-code"))
		return
	case errors.Is(err, passwordless.ErrTooManyAttempts):
		redisplay(http.StatusTooManyRequests, f.view.L.T(i18n.KeyTooManyAttempts))
		return
	case errors.Is(err, passwordless.ErrUserBlocked):
		redisplay(http.StatusForbidden, f.view.L.T(i18n.KeyUserBlocked))
		return
	case errors.Is(err, passwordless.ErrSignupDisabled):
		ui.RenderError(w, http.StatusForbidden, f.view, f.view.L.T(i18n.KeyErrSignupDisabled))
		return
	case errors.As(err, &denied):
		redisplay(http.StatusBadRequest, denied.Description)
		return
	case errors.As(err, &failed):
		ui.RenderErrorReference(w, http.StatusBadRequest, f.view, f.view.L.T(i18n.KeyErrServer), failed.ExecutionID)
		return
	case err != nil:
		h.fail(w, r, err, f)
		return
	}
	if err := h.passwordlessMembership(r.Context(), f, user); err != nil {
		h.fail(w, r, err, f)
		return
	}
	h.complete(w, r, f, user)
}

// passwordlessMembership applies the organization's membership rules as a
// password login does: assign on login when the connection says so; a
// non-member keeps the session and authorization refuses it.
func (h *Handlers) passwordlessMembership(ctx context.Context, f *flow, u *store.User) error {
	if f.org.Org == nil || f.txn.Params[orglogin.InvitationIDParam] != "" {
		return nil
	}
	return h.Store.WithTx(ctx, func(tx store.Store) error {
		oc, err := orglogin.Load(ctx, tx, f.res.Tenant.ID, f.txn.Params)
		if err != nil {
			return err
		}
		if oc.Org != nil {
			err = orglogin.CheckMemberClient(ctx, tx, f.res.Tenant.ID, oc.Org.ID, f.txn.ClientID)
		}
		if err == nil {
			err = EnsureMembership(ctx, tx, oc, u.UserID, f.conn.ID)
		}
		if errors.Is(err, ErrNotMember) {
			return nil
		}
		return err
	})
}
