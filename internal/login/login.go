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

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

const maxFormBytes = 16 << 10

var errTxn = errors.New("login: invalid or expired transaction")

type Handlers struct {
	Store             store.Store
	Sessions          *session.Manager
	Authz             *authz.Handlers
	Database          *identity.Database
	UserThrottle      *identity.Throttle
	IPThrottle        *identity.Throttle
	TrustProxyHeaders bool
	Log               *slog.Logger
	Now               func() time.Time
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
}

// load validates the transaction named by state: it must exist in this
// tenant, be unexpired, and be bound to this browser's za_txn cookie.
func (h *Handlers) load(r *http.Request, state string) (*flow, error) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok || state == "" {
		return nil, errTxn
	}
	txn, err := h.Store.AuthTransactions().Get(ctx, res.Tenant.ID, state)
	if err != nil {
		return nil, errTxn
	}
	c, err := r.Cookie(authz.TxnCookiePrefix + txn.ID)
	if err != nil || subtle.ConstantTimeCompare([]byte(secrets.HashToken(c.Value)), []byte(txn.CookieHash)) != 1 {
		return nil, errTxn
	}
	if !h.now().Before(txn.ExpiresAt) {
		return nil, errTxn
	}
	clientName, named := txn.ClientID, false
	if c, err := h.Store.Clients().Get(ctx, res.Tenant.ID, txn.ClientID); err == nil && c.Name != "" {
		clientName, named = c.Name, true
	}
	l := i18n.ForRequest(res.Tenant, r, txn.Params["ui_locales"]).WithVar("clientName", clientName)
	f := &flow{res: res, view: ui.TenantView(res.Tenant, l), txn: txn}
	f.view.HasClientName = named
	// The flow is returned with the error so the error page keeps the
	// transaction's language; conn is nil in that case.
	f.conn, err = h.connection(ctx, res.Tenant.ID, txn)
	return f, err
}

var errNoConnection = errors.New("login: no enabled connection")

// connection picks the requested connection, or the first database
// connection (by name) enabled for the client.
func (h *Handlers) connection(ctx context.Context, tenantID string, txn *store.AuthTransaction) (*store.Connection, error) {
	conns, err := h.Store.Connections().List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	want := txn.Params["connection"]
	for _, c := range conns {
		if c.Strategy != store.StrategyDatabase || !slices.Contains(c.EnabledClients, txn.ClientID) {
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
		view = ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
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

func (h *Handlers) LoginPage(w http.ResponseWriter, r *http.Request) {
	f, err := h.load(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	ui.RenderLogin(w, http.StatusOK, f.view, ui.LoginData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, Login: f.txn.Params["login_hint"], SignupURL: signupURL(f),
		RedirectURI: f.txn.Params["redirect_uri"],
	})
}

// postedFlow parses a form POST and checks its transaction and CSRF token.
func (h *Handlers) postedFlow(w http.ResponseWriter, r *http.Request) (*flow, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		h.fail(w, r, errTxn, nil)
		return nil, false
	}
	f, err := h.load(r, r.PostForm.Get("state"))
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

func (h *Handlers) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	login := r.PostForm.Get("username")
	data := ui.LoginData{State: f.txn.ID, CSRF: f.txn.CSRFToken, Login: login, SignupURL: signupURL(f), RedirectURI: f.txn.Params["redirect_uri"]}

	userKey := identity.UserThrottleKey(f.res.Tenant.ID, f.conn.Name, login)
	ipKey := identity.IPThrottleKey(f.res.Tenant.ID, httpx.ClientIP(r, h.TrustProxyHeaders))
	// Attempt counts the try up front; it is undone or cleared below once
	// the password turns out to be correct.
	if !h.IPThrottle.Attempt(ipKey) || !h.UserThrottle.Attempt(userKey) {
		data.Error = f.view.L.T(i18n.KeyTooManyAttempts)
		ui.RenderLogin(w, http.StatusTooManyRequests, f.view, data)
		return
	}

	user, err := h.Database.Login(ctx, f.conn, login, r.PostForm.Get("password"))
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials):
		h.log().InfoContext(ctx, "login failed", "tenant", f.res.Tenant.ID, "connection", f.conn.Name)
		data.Error = f.view.L.T(i18n.KeyWrongCredentials)
		ui.RenderLogin(w, http.StatusUnauthorized, f.view, data)
		return
	case errors.Is(err, identity.ErrUserBlocked):
		h.UserThrottle.Success(userKey)
		h.IPThrottle.Refund(ipKey)
		data.Error = f.view.L.T(i18n.KeyUserBlocked)
		ui.RenderLogin(w, http.StatusForbidden, f.view, data)
		return
	case err != nil:
		h.UserThrottle.Refund(userKey)
		h.IPThrottle.Refund(ipKey)
		h.fail(w, r, err, f)
		return
	}
	h.UserThrottle.Success(userKey)
	h.IPThrottle.Refund(ipKey)
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
	ui.RenderSignup(w, http.StatusOK, f.view, ui.SignupData{
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
	// Every signup hashes a password and stores a user, so each attempt
	// counts against the IP limit and none is refunded.
	if !h.IPThrottle.Attempt(identity.IPThrottleKey(f.res.Tenant.ID, httpx.ClientIP(r, h.TrustProxyHeaders))) {
		data.Error = f.view.L.T(i18n.KeyTooManyAttempts)
		ui.RenderSignup(w, http.StatusTooManyRequests, f.view, data)
		return
	}
	user, err := h.Database.Signup(r.Context(), f.conn, identity.SignupInput{
		Email: email, Username: username, Password: r.PostForm.Get("password"),
	})
	var pe *identity.PolicyError
	switch {
	case errors.As(err, &pe):
		if pe.Key != "" {
			data.Error = policyText(f.view.L, pe)
		} else {
			data.Error = capitalize(pe.Reason) + "."
		}
		ui.RenderSignup(w, http.StatusBadRequest, f.view, data)
		return
	case errors.Is(err, identity.ErrUserExists):
		data.Error = f.view.L.T(i18n.KeyEmailInUse)
		ui.RenderSignup(w, http.StatusBadRequest, f.view, data)
		return
	case errors.Is(err, identity.ErrSignupDisabled):
		ui.RenderError(w, http.StatusForbidden, f.view, f.view.L.T(i18n.KeyErrSignupDisabled))
		return
	case err != nil:
		h.fail(w, r, err, f)
		return
	}
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
	if err := h.Store.Users().RecordLogin(ctx, f.res.Tenant.ID, user.UserID, now); err != nil {
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

// passwordPolicyKeys are the messages Auth0's password-policy-not-conformant
// key stands for.
var passwordPolicyKeys = []string{i18n.KeyPasswordTooShort, i18n.KeyPasswordTooLong, i18n.KeyPasswordClasses}

// policyText localizes a keyed policy error. A password policy message uses
// the tenant's custom text for Auth0's password-policy-not-conformant key
// when the language has one, and its own zeroauthy key otherwise.
func policyText(l *i18n.Localizer, pe *identity.PolicyError) string {
	if slices.Contains(passwordPolicyKeys, pe.Key) && l.HasCustom(i18n.KeyPasswordPolicyAlias) {
		return l.T(i18n.KeyPasswordPolicyAlias, pe.Vars...)
	}
	return l.T(pe.Key, pe.Vars...)
}
