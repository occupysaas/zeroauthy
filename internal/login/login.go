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
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

const maxFormBytes = 16 << 10

// User-facing messages (original wording).
const (
	msgBadCredentials = "Incorrect email/username or password."
	msgBlocked        = "This account has been blocked. Contact the application's support."
	msgTooMany        = "Too many attempts. Wait a few minutes and try again."
	msgExpired        = "Your login session has expired or is invalid. Return to the application and start again."
	msgNoConnection   = "No login method is enabled for this application."
	msgSignupDisabled = "Sign-up is not available for this application."
	msgUserExists     = "An account with this email or username already exists."
	msgServer         = "Something went wrong on our side. Please try again."
)

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
	conn, err := h.connection(ctx, res.Tenant.ID, txn)
	if err != nil {
		return nil, err
	}
	return &flow{res: res, view: ui.TenantView(res.Tenant), txn: txn, conn: conn}, nil
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

func (h *Handlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	view := ui.Tenant{}
	if res, ok := tenant.FromContext(r.Context()); ok {
		view = ui.TenantView(res.Tenant)
	}
	switch {
	case errors.Is(err, errTxn):
		ui.RenderError(w, http.StatusBadRequest, view, msgExpired)
	case errors.Is(err, errNoConnection):
		ui.RenderError(w, http.StatusBadRequest, view, msgNoConnection)
	default:
		h.log().ErrorContext(r.Context(), "login page", "err", err)
		ui.RenderError(w, http.StatusInternalServerError, view, msgServer)
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
		h.fail(w, r, err)
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
		h.fail(w, r, errTxn)
		return nil, false
	}
	f, err := h.load(r, r.PostForm.Get("state"))
	if err != nil {
		h.fail(w, r, err)
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(f.txn.CSRFToken)) != 1 {
		h.fail(w, r, errTxn)
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

	userKey := "user|" + f.res.Tenant.ID + "|" + f.conn.Name + "|" + identity.NormalizeLogin(login)
	ipKey := "ip|" + f.res.Tenant.ID + "|" + clientIP(r, h.TrustProxyHeaders)
	// Attempt counts the try up front; it is undone or cleared below once
	// the password turns out to be correct.
	if !h.IPThrottle.Attempt(ipKey) || !h.UserThrottle.Attempt(userKey) {
		data.Error = msgTooMany
		ui.RenderLogin(w, http.StatusTooManyRequests, f.view, data)
		return
	}

	user, err := h.Database.Login(ctx, f.conn, login, r.PostForm.Get("password"))
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials):
		h.log().InfoContext(ctx, "login failed", "tenant", f.res.Tenant.ID, "connection", f.conn.Name)
		data.Error = msgBadCredentials
		ui.RenderLogin(w, http.StatusUnauthorized, f.view, data)
		return
	case errors.Is(err, identity.ErrUserBlocked):
		h.UserThrottle.Success(userKey)
		h.IPThrottle.Refund(ipKey)
		data.Error = msgBlocked
		ui.RenderLogin(w, http.StatusForbidden, f.view, data)
		return
	case err != nil:
		h.UserThrottle.Refund(userKey)
		h.IPThrottle.Refund(ipKey)
		h.fail(w, r, err)
		return
	}
	h.UserThrottle.Success(userKey)
	h.IPThrottle.Refund(ipKey)
	h.complete(w, r, f, user)
}

func (h *Handlers) SignupPage(w http.ResponseWriter, r *http.Request) {
	f, err := h.load(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if f.conn.DisableSignup {
		ui.RenderError(w, http.StatusForbidden, f.view, msgSignupDisabled)
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
	if !h.IPThrottle.Attempt("ip|" + f.res.Tenant.ID + "|" + clientIP(r, h.TrustProxyHeaders)) {
		data.Error = msgTooMany
		ui.RenderSignup(w, http.StatusTooManyRequests, f.view, data)
		return
	}
	user, err := h.Database.Signup(r.Context(), f.conn, email, username, r.PostForm.Get("password"))
	var pe *identity.PolicyError
	switch {
	case errors.As(err, &pe):
		data.Error = capitalize(pe.Reason) + "."
		ui.RenderSignup(w, http.StatusBadRequest, f.view, data)
		return
	case errors.Is(err, identity.ErrUserExists):
		data.Error = msgUserExists
		ui.RenderSignup(w, http.StatusBadRequest, f.view, data)
		return
	case errors.Is(err, identity.ErrSignupDisabled):
		ui.RenderError(w, http.StatusForbidden, f.view, msgSignupDisabled)
		return
	case err != nil:
		h.fail(w, r, err)
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
		h.fail(w, r, err)
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
