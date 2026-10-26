// Package login serves the hosted login and signup pages (/u/*).
package login

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/dbconn"
	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

const maxFormBytes = 16 << 10

var errTxn = errors.New("login: invalid or expired transaction")

type Handlers struct {
	Protection *protection.Service
	Store      store.Store
	Sessions   *session.Manager
	Authz      *authz.Handlers
	Database   *identity.Database
	Resets     *dbconn.Handlers // nil disables the hosted password reset pages
	// Verification sends the verification email after a signup; nil sends
	// none.
	Verification *VerificationMailer
	// Device code entry limits (/activate). Each counts misses; a code
	// that is found refunds its attempt.
	DeviceTxnThrottle    *identity.Throttle // key: transaction ID
	DeviceIPThrottle     *identity.Throttle // key: identity.IPThrottleKey(tenant, httpx.IPBucket(ip)); nil = off
	DeviceTenantThrottle *identity.Throttle // key: tenant ID; nil = off
	TrustProxyHeaders    bool
	Log                  *slog.Logger
	Now                  func() time.Time
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// flow is a validated login transaction and the connection it uses.
type flow struct {
	res  tenant.Resolved
	view ui.Tenant
	txn  *store.AuthTransaction
	conn *store.Connection
	// clientName is the application's name, or its client ID when it has none.
	clientName string
	config     *store.HostedLoginConfig
}

// loadTxn validates the transaction named by state: it must exist in this
// tenant, be unexpired, and be bound to this browser's za_txn cookie. The
// returned flow has no connection.
func (h *Handlers) loadTxn(r *http.Request, state string) (*flow, error) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok || state == "" {
		return nil, errTxn
	}
	txn, err := h.Store.AuthTransactions().Get(ctx, res.Tenant.ID, state)
	if err != nil || res.CheckOrigin(txn.Origin) != nil {
		return nil, errTxn
	}
	c, err := r.Cookie(authz.TxnCookiePrefix + txn.ID)
	if err != nil || subtle.ConstantTimeCompare([]byte(secrets.HashToken(c.Value)), []byte(txn.CookieHash)) != 1 {
		return nil, errTxn
	}
	if !h.now().Before(txn.ExpiresAt) {
		return nil, errTxn
	}
	config := hostedlogin.Configuration(ctx)
	if config == nil && !res.Tenant.Reserved {
		config, err = (hostedlogin.Service{Store: h.Store}).Load(ctx, res.Tenant.ID)
		if err != nil {
			return nil, err
		}
	}
	viewRequest := r
	if config != nil {
		res.Tenant = hostedlogin.LocalizedTenant(res.Tenant, config)
		viewRequest = r.WithContext(hostedlogin.WithConfiguration(ctx, config))
	}
	clientName, named := txn.ClientID, false
	if c, err := h.Store.Clients().Get(ctx, res.Tenant.ID, txn.ClientID); err == nil && c.Name != "" {
		clientName, named = c.Name, true
	}
	l := i18n.ForRequest(res.Tenant, r, txn.Params["ui_locales"]).WithVar("clientName", clientName)
	if r.Method == http.MethodPost && txn.HostedState.FormLanguage != "" {
		l = i18n.New(res.Tenant, txn.HostedState.FormLanguage).WithVar("clientName", clientName)
	}
	f := &flow{res: res, view: ui.RequestTenant(viewRequest, res.Tenant, l), txn: txn, clientName: clientName, config: config}
	f.view.HasClientName = named
	return f, nil
}

// load is loadTxn plus the connection the transaction uses. The flow is
// returned with the error so the error page keeps the transaction's
// language; conn is nil in that case.
func (h *Handlers) load(r *http.Request, state string) (*flow, error) {
	f, err := h.loadTxn(r, state)
	if err != nil {
		return f, err
	}
	f.conn, err = h.connection(r.Context(), f.res.Tenant.ID, f.txn)
	return f, err
}

var errNoConnection = errors.New("login: no enabled connection")

// connection picks the requested connection, or the first database
// connection enabled for the client, by name in byte order. The store lists
// connections case-insensitively (the Management API's order), so the order
// is fixed here: which connection a tenant's login uses must not depend on it.
func (h *Handlers) connection(ctx context.Context, tenantID string, txn *store.AuthTransaction) (*store.Connection, error) {
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
	conns = slices.SortedFunc(slices.Values(conns), func(a, b *store.Connection) int { return strings.Compare(a.Name, b.Name) })
	want := txn.Params["connection"]
	for _, c := range conns {
		if c.Strategy != store.StrategyDatabase || !access.ConnectionUsable(client, c) {
			continue
		}
		if want == "" || c.Name == want {
			return c, nil
		}
	}
	return nil, errNoConnection
}

// fail renders an error page. f is the verified flow when there is one,
// so the page keeps the transaction's language; otherwise the language
// comes from the request alone.
func (h *Handlers) fail(w http.ResponseWriter, r *http.Request, err error, f *flow) {
	view := ui.Tenant{}
	if f != nil {
		view = f.view
	} else if res, ok := tenant.FromContext(r.Context()); ok {
		view = ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
	}
	switch {
	case errors.Is(err, errTxn):
		ui.RenderError(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrSessionExpired))
	case errors.Is(err, errNoConnection):
		ui.RenderError(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrNoConnection))
	default:
		h.log().ErrorContext(r.Context(), "login page", "err", err)
		ui.RenderError(w, http.StatusInternalServerError, view, view.L.T(i18n.KeyErrServer))
	}
}

func signupURL(f *flow) string {
	if f.conn.DisableSignup {
		return ""
	}
	return "/u/signup?" + url.Values{"state": {f.txn.ID}}.Encode()
}

// forgotURL links the login page to the forgot-password page, or is empty
// when password resets are not served.
func (h *Handlers) forgotURL(f *flow) string {
	if h.Resets == nil {
		return ""
	}
	return "/u/reset-password/request?" + url.Values{"state": {f.txn.ID}}.Encode()
}

func (h *Handlers) LoginPage(w http.ResponseWriter, r *http.Request) {
	f, err := h.load(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	switch f.txn.HostedState.Step {
	case "identifier":
		h.renderIdentifier(w, r, http.StatusOK, f, h.stageData(f, f.txn.Params["login_hint"]))
		return
	case "password":
		http.Redirect(w, r, passwordLocation(f), http.StatusSeeOther)
		return
	case "authenticating":
		h.fail(w, r, errTxn, f)
		return
	}
	if !h.captchaPage(w, r, f, "login") {
		return
	}
	h.renderLoginStage(w, r, http.StatusOK, f, ui.LoginData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, Login: f.txn.Params["login_hint"], SignupURL: signupURL(f),
		ForgotURL: h.forgotURL(f), RedirectURI: f.txn.Params["redirect_uri"],
	})
}

// postedTxn parses a form POST and checks its transaction and CSRF token.
func (h *Handlers) postedTxn(w http.ResponseWriter, r *http.Request) (*flow, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		h.fail(w, r, errTxn, nil)
		return nil, false
	}
	f, err := h.loadTxn(r, r.PostForm.Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(f.txn.CSRFToken)) != 1 {
		h.fail(w, r, errTxn, f)
		return nil, false
	}
	return f, true
}

// postedFlow is postedTxn plus the transaction's connection.
func (h *Handlers) postedFlow(w http.ResponseWriter, r *http.Request) (*flow, bool) {
	f, ok := h.postedTxn(w, r)
	if !ok {
		return nil, false
	}
	var err error
	if f.conn, err = h.connection(r.Context(), f.res.Tenant.ID, f.txn); err != nil {
		h.fail(w, r, err, f)
		return nil, false
	}
	return f, true
}

func (h *Handlers) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	if f.txn.HostedState.Step == "identifier" {
		h.identifierPost(w, r, f)
		return
	}
	if f.txn.HostedState.Step != "" {
		h.fail(w, r, errTxn, f)
		return
	}
	if !h.guardHostedForm(w, r, f, "login", "login", func(status int, message string) {
		data := h.stageData(f, r.PostForm.Get("username")).LoginData
		data.Error = message
		h.renderLoginStage(w, r, status, f, data)
	}) {
		return
	}
	h.authenticateLogin(w, r, f, r.PostForm.Get("username"))
}

func (h *Handlers) authenticateLogin(w http.ResponseWriter, r *http.Request, f *flow, login string) {
	ctx := r.Context()
	data := ui.LoginData{State: f.txn.ID, CSRF: f.txn.CSRFToken, Login: login, SignupURL: signupURL(f), ForgotURL: h.forgotURL(f), RedirectURI: f.txn.Params["redirect_uri"]}

	svc := h.protectionService()
	decision, err := svc.Begin(ctx, protection.Attempt{Tenant: f.res.Tenant, Connection: f.conn, Identifier: login, IP: httpx.ClientIP(r, h.TrustProxyHeaders), Flow: "login"})
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !decision.Allowed {
		data.Error = f.view.L.T(i18n.KeyTooManyAttempts)
		h.renderLoginStage(w, r, http.StatusTooManyRequests, f, data)
		return
	}

	attemptID := secrets.RandomString(32)
	if err := h.submitCaptcha(r, f.res, &f.view, "login", f.txn.ID, attemptID); err != nil {
		if finishErr := svc.Finish(ctx, decision.Receipt, "refund"); finishErr != nil {
			h.fail(w, r, finishErr, f)
			return
		}
		status, key := captchaFailure(err)
		data.Error = f.view.L.T(key)
		h.renderLoginStage(w, r, status, f, data)
		return
	}

	var breachErr error
	user, err := h.Database.LoginWithCheck(ctx, f.conn, login, r.PostForm.Get("password"), func(ctx context.Context) error {
		breachErr = svc.CheckPasswordForUser(ctx, f.res.Tenant, "login", identity.EffectivePassword(f.conn, r.PostForm.Get("password")), decision.SubjectID)
		return breachErr
	})
	outcome := protection.CredentialOutcome(err)
	if breachErr != nil {
		// Credentials were proved before the policy refusal.
		outcome = "success"
	}
	if finishErr := svc.Finish(ctx, decision.Receipt, outcome); finishErr != nil {
		h.fail(w, r, finishErr, f)
		return
	}
	riskErr := err
	if breachErr != nil {
		riskErr = breachErr
	}
	if err := h.recordFailure(r, f.res, "login", attemptID, riskErr); err != nil {
		h.fail(w, r, err, f)
		return
	}
	// Refresh widget state after a failure may cross the local risk threshold.
	if riskErr != nil {
		if !h.captchaPage(w, r, f, "login") {
			return
		}
	}

	if breachErr != nil {
		status, key := breachFailure(breachErr, http.StatusUnauthorized)
		data.Error = f.view.L.T(key)
		h.renderLoginStage(w, r, status, f, data)
		return
	}
	var ue *identity.UnauthorizedError
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials):
		h.log().InfoContext(ctx, "login failed", "tenant", f.res.Tenant.ID, "connection", f.conn.Name)
		data.Error = f.view.L.T(i18n.KeyWrongCredentials)
		h.renderLoginStage(w, r, http.StatusUnauthorized, f, data)
		return
	case errors.Is(err, identity.ErrPasswordChangeRequired):
		h.log().InfoContext(ctx, "login failed: password change required", "tenant", f.res.Tenant.ID, "connection", f.conn.Name)
		data.Error = f.view.L.T(i18n.KeyPasswordChangeRequired)
		h.renderLoginStage(w, r, http.StatusForbidden, f, data)
		return
	case errors.Is(err, identity.ErrUserBlocked):
		data.Error = f.view.L.T(i18n.KeyUserBlocked)
		h.renderLoginStage(w, r, http.StatusForbidden, f, data)
		return
	case errors.As(err, &ue):
		// A custom database script refused the user with a message meant
		// for them (D-0023); the attempt still counts.
		data.Error = ue.Message
		h.renderLoginStage(w, r, http.StatusUnauthorized, f, data)
		return
	case err != nil:
		// A failure the script raised counts as a failed attempt; one that
		// kept the script from answering does not (D-0023).
		h.fail(w, r, err, f)
		return
	}
	h.complete(w, r, f, user)
}

func (h *Handlers) SignupPage(w http.ResponseWriter, r *http.Request) {
	f, err := h.load(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if f.conn.DisableSignup {
		ui.RenderError(w, http.StatusForbidden, f.view, f.view.L.T(i18n.KeyErrSignupDisabled))
		return
	}
	if !h.captchaPage(w, r, f, "signup") {
		return
	}
	h.renderSignup(w, r, http.StatusOK, f, ui.SignupData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, Email: f.txn.Params["login_hint"],
		RequiresUsername: f.conn.RequiresUsername, LoginURL: "/u/login?" + url.Values{"state": {f.txn.ID}}.Encode(),
		RedirectURI: f.txn.Params["redirect_uri"],
	})
}

func (h *Handlers) SignupSubmit(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	email, username := r.PostForm.Get("email"), r.PostForm.Get("username")
	data := ui.SignupData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, Email: email, Username: username,
		RequiresUsername: f.conn.RequiresUsername, LoginURL: "/u/login?" + url.Values{"state": {f.txn.ID}}.Encode(),
		RedirectURI: f.txn.Params["redirect_uri"],
	}
	if !h.guardHostedForm(w, r, f, "signup", "signup", func(status int, message string) { data.Error = message; h.renderSignup(w, r, status, f, data) }) {
		return
	}
	// Missing required fields are malformed forms, not registration attempts.
	// Nonempty passwords still reach policy validation after the reservation.
	var malformed error
	switch {
	case strings.TrimSpace(email) == "":
		malformed = identity.CheckEmail("")
	case r.PostForm.Get("password") == "":
		malformed = identity.CheckPassword(f.conn, identity.Person{}, "", nil)
	case f.conn.RequiresUsername && strings.TrimSpace(username) == "":
		malformed = identity.CheckUsername(f.conn, "")
	}
	if malformed != nil {
		var pe *identity.PolicyError
		if errors.As(malformed, &pe) {
			data.Error = policyMessage(f.view.L, pe)
		} else {
			h.fail(w, r, malformed, f)
			return
		}
		h.renderSignup(w, r, http.StatusBadRequest, f, data)
		return
	}
	svc := h.protectionService()
	decision, err := svc.Begin(r.Context(), protection.Attempt{Tenant: f.res.Tenant, Connection: f.conn, Identifier: email, IP: httpx.ClientIP(r, h.TrustProxyHeaders), Flow: "signup"})
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !decision.Allowed {
		data.Error = f.view.L.T(i18n.KeyTooManyAttempts)
		h.renderSignup(w, r, http.StatusTooManyRequests, f, data)
		return
	}
	attemptID := secrets.RandomString(32)
	if err := h.submitCaptcha(r, f.res, &f.view, "signup", f.txn.ID, attemptID); err != nil {
		if finishErr := svc.Finish(r.Context(), decision.Receipt, "refund"); finishErr != nil {
			h.fail(w, r, finishErr, f)
			return
		}
		status, key := captchaFailure(err)
		data.Error = f.view.L.T(key)
		h.renderSignup(w, r, status, f, data)
		return
	}

	// Registration spends its token regardless of the credential outcome.
	if err := svc.Finish(r.Context(), decision.Receipt, "failure"); err != nil {
		h.fail(w, r, err, f)
		return
	}

	if err := svc.CheckPassword(r.Context(), f.res.Tenant, "pre-user-registration", identity.EffectivePassword(f.conn, r.PostForm.Get("password"))); err != nil {
		if riskErr := h.recordFailure(r, f.res, "signup", attemptID, err); riskErr != nil {
			h.fail(w, r, riskErr, f)
			return
		}
		if !h.captchaPage(w, r, f, "signup") {
			return
		}
		status, key := breachFailure(err, http.StatusBadRequest)
		data.Error = f.view.L.T(key)
		h.renderSignup(w, r, status, f, data)
		return
	}
	user, err := h.Database.Signup(r.Context(), f.conn, identity.SignupInput{
		ClientID: f.txn.ClientID, Email: email, Username: username, Password: r.PostForm.Get("password"),
	})
	if riskErr := h.recordFailure(r, f.res, "signup", attemptID, err); riskErr != nil {
		h.fail(w, r, riskErr, f)
		return
	}
	if err != nil {
		if !h.captchaPage(w, r, f, "signup") {
			return
		}
	}
	var pe *identity.PolicyError
	var ue *identity.UnauthorizedError
	switch {
	case errors.As(err, &ue):
		data.Error = ue.Message
		h.renderSignup(w, r, http.StatusUnauthorized, f, data)
		return
	case errors.As(err, &pe):
		data.Error = policyMessage(f.view.L, pe)
		h.renderSignup(w, r, http.StatusBadRequest, f, data)
		return
	case errors.Is(err, identity.ErrUserExists):
		data.Error = f.view.L.T(i18n.KeyEmailInUse)
		h.renderSignup(w, r, http.StatusBadRequest, f, data)
		return
	case errors.Is(err, identity.ErrSignupDisabled):
		ui.RenderError(w, http.StatusForbidden, f.view, f.view.L.T(i18n.KeyErrSignupDisabled))
		return
	case err != nil:
		h.fail(w, r, err, f)
		return
	}
	h.sendSignupVerification(f, user)
	h.complete(w, r, f, user)
}

// complete starts the session and hands back to /authorize processing.
func (h *Handlers) complete(w http.ResponseWriter, r *http.Request, f *flow, user *store.User) {
	ctx := r.Context()
	now := h.now()
	sess, err := h.Sessions.Start(ctx, w, r, f.res.Tenant, user.UserID, f.conn.Name, now)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if err := h.Store.Users().RecordLogin(ctx, f.res.Tenant.ID, user.UserID, now, httpx.RecordedIP(r, h.TrustProxyHeaders)); err != nil {
		h.log().WarnContext(ctx, "record login", "tenant", f.res.Tenant.ID, "err", err)
	}
	h.Authz.Resume(w, r, f.res, f.txn, sess)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// policyMessage is the text shown for a rejected signup or new password.
func policyMessage(l *i18n.Localizer, pe *identity.PolicyError) string {
	if pe.Key != "" {
		return policyText(l, pe)
	}
	return capitalize(pe.Reason) + "."
}

// passwordPolicyKeys are the messages Auth0's password-policy-not-conformant
// key stands for: the complexity messages. History, dictionary and personal
// data have their own.
var passwordPolicyKeys = []string{
	i18n.KeyPasswordTooShort, i18n.KeyPasswordTooLong, i18n.KeyPasswordClasses, i18n.KeyPasswordTypes,
	i18n.KeyPasswordIdentical, i18n.KeyPasswordSequential,
}

// policyText localizes a keyed policy error. A password policy message uses
// the tenant's custom text for Auth0's password-policy-not-conformant key
// when the language has one, and its own zeroauthy key otherwise.
func policyText(l *i18n.Localizer, pe *identity.PolicyError) string {
	if slices.Contains(passwordPolicyKeys, pe.Key) && l.HasCustom(i18n.KeyPasswordPolicyAlias) {
		return l.T(i18n.KeyPasswordPolicyAlias, pe.Vars...)
	}
	return l.T(pe.Key, pe.Vars...)
}

func (h *Handlers) protectionService() *protection.Service {
	if h.Protection != nil {
		return h.Protection
	}
	return &protection.Service{Store: h.Store, Now: h.Now, Log: h.Log}
}

// These availability/error choices are local A5 compatibility fallbacks.
func breachFailure(err error, status int) (int, string) {
	if errors.Is(err, protection.ErrPasswordLeaked) {
		return status, i18n.KeyPasswordLeaked
	}
	return http.StatusServiceUnavailable, i18n.KeyBreachUnavailable
}
