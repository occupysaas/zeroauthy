package passwordless

import (
	"crypto/subtle"
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
	// confirmCookie binds a confirmation form to the browser that rendered
	// it (login CSRF): the sealed form state carries the cookie's hash.
	confirmCookie = "za_pwl_confirm"
	stateLabel    = "passwordless-confirm/v1"
	stateLifetime = 10 * time.Minute
	wrongCode     = "Wrong email or verification code."
	wrongPhone    = "Wrong phone number or verification code."
)

type confirmState struct {
	Hash string `json:"h"`
	// Kind is KindCode for a typed code, empty for a magic link.
	Kind string `json:"k,omitempty"`
	// Browser is the hash of the rendering browser's confirmCookie.
	Browser   string     `json:"b"`
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

// VerifyRedirect is GET /passwordless/verify_redirect. Neither a typed code
// nor a magic-link token is consumed here: the GET answers a confirmation
// page whose form, bound to this browser, posts back (P3; D-0060 LR30).
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
	// A typed code is verified only by the confirmation POST from the
	// browser that rendered the form, so a crafted link cannot sign a
	// victim's browser in to another account (login CSRF).
	if _, _, ok := h.validate(w, r, res, q); !ok {
		return
	}
	params := url.Values{}
	for k, v := range q {
		if k != "verification_code" {
			params[k] = v
		}
	}
	ident := q.Get("email")
	if q.Get("connection") == "sms" {
		ident = q.Get("phone_number")
	}
	h.renderConfirm(w, r, res, confirmState{Hash: secrets.HashToken(code), Kind: KindCode, Params: params}, code, ident)
}

// verifyCode verifies a confirmed typed code and continues the
// authorization.
func (h *Handlers) verifyCode(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req authz.Request, params url.Values, code string) {
	ctx := r.Context()
	conn := params.Get("connection")
	ident := params.Get("email")
	wrong := wrongCode
	if conn == "sms" {
		ident, wrong = params.Get("phone_number"), wrongPhone
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
	h.renderConfirm(w, r, res, confirmState{Hash: row.CodeHash, Params: params}, token, row.Identifier)
}

// browserBinding returns this browser's confirmation cookie, setting a new
// one when it has none.
func (h *Handlers) browserBinding(w http.ResponseWriter, r *http.Request) string {
	value := ""
	if c, err := r.Cookie(confirmCookie); err == nil && len(c.Value) >= 32 && len(c.Value) <= 64 {
		value = c.Value
	} else {
		value = secrets.RandomString(32)
	}
	http.SetCookie(w, &http.Cookie{Name: confirmCookie, Value: value, Path: verifyPath, MaxAge: int(stateLifetime / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	return value
}

// renderConfirm renders the confirmation page whose sealed form state is
// bound to this browser. identifier is the account the sign-in is for, shown
// so that a user sent someone else's link can notice.
func (h *Handlers) renderConfirm(w http.ResponseWriter, r *http.Request, res tenant.Resolved, st confirmState, token, identifier string) {
	_, req, ok := h.validate(w, r, res, st.Params)
	if !ok {
		return
	}
	st.Browser = secrets.HashToken(h.browserBinding(w, r))
	st.ExpiresAt = h.Service.now().Add(stateLifetime)
	plain, err := json.Marshal(st)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sealed, err := keys.SealBound(h.Service.Wrapper, stateLabel, []string{res.Tenant.ID}, plain)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ui.RenderPasswordlessLink(w, h.view(r, res), ui.PasswordlessLinkData{Code: token, StateToken: base64.RawURLEncoding.EncodeToString(sealed), Identifier: identifier, RedirectURI: req.RedirectURI})
}

// VerifyRedirectConfirm is POST /passwordless/verify_redirect: from the
// browser that rendered the form, it consumes the magic link (or verifies the
// typed code) once and continues the authorization.
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
	// The form must come from the browser that rendered it (login CSRF).
	c, cerr := r.Cookie(confirmCookie)
	if cerr != nil || st.Browser == "" || subtle.ConstantTimeCompare([]byte(secrets.HashToken(c.Value)), []byte(st.Browser)) != 1 {
		h.errorPage(w, r, res, "this confirmation was opened in another browser; open the link again in this browser")
		return
	}
	client, req, ok := h.validate(w, r, res, st.Params)
	if !ok {
		return
	}
	if st.Kind == KindCode {
		h.verifyCode(w, r, res, client, req, st.Params, token)
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
	*r = *r.WithContext(logs.WithEvent(ctx, logs.Event{UserID: u.UserID, UserName: MaskIdentifier(conn.Strategy, u.Name), Connection: conn.Name, ConnectionID: conn.ID, Strategy: conn.Strategy, StrategyType: "passwordless"}))
	now := h.Service.now()
	sess, err := h.Sessions.Start(r.Context(), w, r, res.Tenant, u.UserID, conn.Name, now, store.AuthMethod{Name: conn.Strategy})
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
