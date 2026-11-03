package passwordless

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// Handlers serve GET and POST /passwordless/verify_redirect: browser
// verification of a typed code (auth0.js) or a magic link, continuing the
// authorization as a hosted login would (session, MFA, Actions, consent).
type Handlers struct {
	Service           *Service
	Authz             *authz.Handlers
	Sessions          *session.Manager
	TrustProxyHeaders bool
	Log               *slog.Logger
}

const (
	stateLabel    = "passwordless-confirm/v1"
	stateLifetime = 10 * time.Minute
	wrongCode     = "Wrong email or verification code."
	wrongPhone    = "Wrong phone number or verification code."
)

type confirmState struct {
	Hash      string     `json:"h"`
	ExpiresAt time.Time  `json:"e"`
	Params    url.Values `json:"p"`
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func (h *Handlers) view(r *http.Request, res tenant.Resolved) ui.Tenant {
	return ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, r.URL.Query().Get("ui_locales")))
}

func (h *Handlers) errorPage(w http.ResponseWriter, r *http.Request, res tenant.Resolved, detail string) {
	v := h.view(r, res)
	ui.RenderErrorDetail(w, http.StatusBadRequest, v, v.L.T(i18n.KeyErrAccessDenied), detail)
}

func digitsOnly(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

func (h *Handlers) request(r *http.Request) RequestInfo {
	ip := httpx.ClientIP(r, h.TrustProxyHeaders)
	return RequestInfo{IP: ip, Hostname: r.Host, Method: r.Method, UserAgent: r.UserAgent(), Language: r.Header.Get("Accept-Language")}
}

// validate checks the authorization parameters the verification continues.
// ok false means the response was written (error page).
func (h *Handlers) validate(w http.ResponseWriter, r *http.Request, res tenant.Resolved, params url.Values) (*store.Client, authz.Request, bool) {
	req := authz.ParseRequest(params)
	client, verr, redirectable := authz.ValidateRequest(r.Context(), h.Service.Store, res.Tenant, &req)
	if verr != nil {
		if redirectable {
			h.Authz.Deny(w, r, res, client, req, verr.Code, verr.Description)
		} else {
			h.errorPage(w, r, res, verr.Description)
		}
		return nil, req, false
	}
	return client, req, true
}

// VerifyRedirect is GET /passwordless/verify_redirect. A typed code is
// verified and consumed; a magic-link token is only peeked and answered with
// a confirmation page whose form posts back (P3).
func (h *Handlers) VerifyRedirect(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	q := r.URL.Query()
	code := q.Get("verification_code")
	ctx := logscrub.WithCredentials(r.Context(), code)
	*r = *r.WithContext(ctx)
	if q.Get("client_id") == "" || q.Get("connection") == "" || code == "" {
		h.errorPage(w, r, res, "client_id, connection and verification_code are required")
		return
	}
	if !digitsOnly(code) {
		h.confirmPage(w, r, res, code)
		return
	}
	client, req, ok := h.validate(w, r, res, q)
	if !ok {
		return
	}
	conn := q.Get("connection")
	ident := q.Get("email")
	wrong := wrongCode
	if conn == "sms" {
		ident, wrong = q.Get("phone_number"), wrongPhone
	}
	ctx = WithRequest(ctx, h.request(r))
	u, err := h.Service.VerifyCode(ctx, res.Tenant.ID, client.ClientID, conn, ident, code)
	if err != nil {
		h.refused(w, r, res, client, req, conn, err, wrong)
		return
	}
	c, err := h.Service.passwordlessConnection(ctx, res.Tenant.ID, conn)
	if err != nil {
		h.Authz.Deny(w, r, res, client, req, "server_error", "internal error")
		return
	}
	h.continueAuthorization(w, r, res, client, req, u, c)
}

func (h *Handlers) refused(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req authz.Request, connName string, err error, wrong string) {
	description := wrong
	var denied *identity.ErrSignupDenied
	switch {
	case errors.Is(err, ErrInvalidCode):
		e := logs.FromRequest(r)
		e.Type, e.ClientID, e.ClientName, e.Description = "f", client.ClientID, client.Name, wrong
		if c, cerr := h.Service.passwordlessConnection(r.Context(), res.Tenant.ID, connName); cerr == nil {
			e.Connection, e.ConnectionID, e.Strategy, e.StrategyType = c.Name, c.ID, c.Strategy, "passwordless"
		}
		logs.RecordEvent(r.Context(), h.Service.Recorder, e)
	case errors.Is(err, ErrTooManyAttempts):
		description = "too many attempts; wait a few minutes and try again"
	case errors.Is(err, ErrSignupDisabled):
		description = "signups are disabled for this connection"
	case errors.Is(err, ErrUserBlocked):
		description = "user is blocked"
	case errors.Is(err, store.ErrPhoneUnavailable):
		description = "passwordless authentication is not available with this storage plugin"
	case errors.As(err, &denied):
		description = denied.Description
	default:
		h.log().ErrorContext(r.Context(), "passwordless verification", "tenant", res.Tenant.ID, "err", err)
		description = "the sign-in could not be completed"
	}
	h.Authz.Deny(w, r, res, client, req, "access_denied", description)
}

// confirmPage peeks a magic link without consuming it.
func (h *Handlers) confirmPage(w http.ResponseWriter, r *http.Request, res tenant.Resolved, token string) {
	row, params, err := h.Service.PeekLink(r.Context(), res.Tenant.ID, token)
	if err != nil {
		if !errors.Is(err, ErrInvalidCode) {
			h.log().ErrorContext(r.Context(), "passwordless link peek", "tenant", res.Tenant.ID, "err", err)
		}
		// Unknown, used, replaced or expired: redirect with access_denied
		// when the query names a valid redirect.
		if client, req, ok := h.validate(w, r, res, r.URL.Query()); ok {
			h.Authz.Deny(w, r, res, client, req, "access_denied", wrongCode)
		}
		return
	}
	plain, err := json.Marshal(confirmState{Hash: row.CodeHash, ExpiresAt: h.Service.now().Add(stateLifetime), Params: params})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sealed, err := keys.SealBound(h.Service.Wrapper, stateLabel, []string{res.Tenant.ID}, plain)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ui.RenderPasswordlessLink(w, h.view(r, res), ui.PasswordlessLinkData{Code: token, StateToken: base64.RawURLEncoding.EncodeToString(sealed)})
}

// VerifyRedirectConfirm is POST /passwordless/verify_redirect: it consumes
// the magic link once and continues the authorization.
func (h *Handlers) VerifyRedirectConfirm(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, r, res, "malformed form")
		return
	}
	token := r.PostForm.Get("verification_code")
	ctx := logscrub.WithCredentials(r.Context(), token)
	*r = *r.WithContext(ctx)
	var st confirmState
	sealed, derr := base64.RawURLEncoding.DecodeString(r.PostForm.Get("state_token"))
	plain, oerr := keys.OpenBound(h.Service.Wrapper, stateLabel, []string{res.Tenant.ID}, sealed)
	if derr != nil || oerr != nil || json.Unmarshal(plain, &st) != nil || st.Hash != secrets.HashToken(token) || !h.Service.now().Before(st.ExpiresAt) {
		h.errorPage(w, r, res, "the confirmation form has expired; open the link from your email again")
		return
	}
	client, req, ok := h.validate(w, r, res, st.Params)
	if !ok {
		return
	}
	ctx = WithRequest(ctx, h.request(r))
	g, err := h.Service.VerifyLink(ctx, res.Tenant.ID, token)
	if err != nil {
		h.refused(w, r, res, client, req, "email", err, wrongCode)
		return
	}
	h.continueAuthorization(w, r, res, client, req, g.User, g.Connection)
}

// continueAuthorization starts the session and resumes the authorization in
// a fresh transaction, exactly as a hosted login does after its password.
func (h *Handlers) continueAuthorization(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req authz.Request, u *store.User, conn *store.Connection) {
	ctx := r.Context()
	if !enabledFor(conn, client.ClientID) {
		h.Authz.Deny(w, r, res, client, req, "access_denied", notEnabled)
		return
	}
	*r = *r.WithContext(logs.WithEvent(ctx, logs.Event{UserID: u.UserID, UserName: u.Name, Connection: conn.Name, ConnectionID: conn.ID, Strategy: conn.Strategy, StrategyType: "passwordless"}))
	now := h.Service.now()
	sess, err := h.Sessions.Start(r.Context(), w, r, res.Tenant, u.UserID, conn.Name, now)
	if err != nil {
		h.log().ErrorContext(ctx, "passwordless: start session", "tenant", res.Tenant.ID, "err", err)
		h.Authz.Deny(w, r, res, client, req, "server_error", "internal error")
		return
	}
	if err := h.Service.Store.Users().RecordLogin(ctx, res.Tenant.ID, u.UserID, now, httpx.RecordedIP(r, h.TrustProxyHeaders)); err != nil {
		h.log().WarnContext(ctx, "record login", "tenant", res.Tenant.ID, "err", err)
	}
	txn, err := h.Authz.CreateTxn(w, r, res, client.ClientID, req.Params(), "/u")
	if err != nil {
		h.log().ErrorContext(ctx, "passwordless: create transaction", "tenant", res.Tenant.ID, "err", err)
		h.Authz.Deny(w, r, res, client, req, "server_error", "internal error")
		return
	}
	h.Authz.Resume(w, r, res, txn, sess)
}
