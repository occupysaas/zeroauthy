package login

import (
	"context"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// Social login (Plan 24): buttons on the login page post to
// /u/login/social; /authorize?connection=<federated> starts the same flow;
// providers return to /login/callback on the transaction's origin.

// socialConnections lists the application's usable federated connections.
func (h *Handlers) socialConnections(ctx context.Context, f *flow, includeHidden bool) ([]*store.Connection, error) {
	if h.Federation == nil {
		return nil, nil
	}
	client, err := h.Store.Clients().Get(ctx, f.res.Tenant.ID, f.txn.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	conns, _, err := h.Store.Connections().List(ctx, f.res.Tenant.ID, store.ConnectionFilter{}, store.Page{})
	if err != nil {
		return nil, err
	}
	return federation.SocialChoices(client, conns, includeHidden), nil
}

// socialButtons are the login page's provider choices; a listing failure
// shows none rather than failing the page.
func (h *Handlers) socialButtons(r *http.Request, f *flow) []ui.SocialButton {
	conns, err := h.socialConnections(r.Context(), f, false)
	if err != nil {
		h.log().WarnContext(r.Context(), "list social connections", "tenant", f.res.Tenant.ID, "err", err)
		return nil
	}
	out := make([]ui.SocialButton, len(conns))
	for i, c := range conns {
		out[i] = ui.SocialButton{Connection: c.Name, Label: federation.ButtonLabel(c)}
	}
	return out
}

// explicitSocial returns the usable federated connection the transaction
// names with connection=, or nil.
func (h *Handlers) explicitSocial(r *http.Request, f *flow) *store.Connection {
	want := f.txn.Params["connection"]
	if want == "" || h.Federation == nil {
		return nil
	}
	conns, err := h.socialConnections(r.Context(), f, true)
	if err != nil {
		return nil
	}
	for _, c := range conns {
		if c.Name == want {
			return c
		}
	}
	return nil
}

// renderSocialOnly renders the login page of an application with no
// database connection: provider buttons only.
func (h *Handlers) renderSocialOnly(w http.ResponseWriter, r *http.Request, status int, f *flow, buttons []ui.SocialButton, message string) {
	if !h.captchaPage(w, r, f, "login") {
		return
	}
	ui.RenderLogin(w, status, f.view, ui.LoginData{State: f.txn.ID, CSRF: f.txn.CSRFToken, Social: buttons, NoPassword: true,
		Error: message, RedirectURI: f.txn.Params["redirect_uri"]})
}

// SocialStart is POST /u/login/social: the user chose a provider.
func (h *Handlers) SocialStart(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedTxn(w, r)
	if !ok {
		return
	}
	if f.txn.HostedState.Step == "authenticating" {
		h.fail(w, r, errTxn, f)
		return
	}
	name := r.PostForm.Get("connection")
	conns, err := h.socialConnections(r.Context(), f, true)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	var conn *store.Connection
	for _, c := range conns {
		if c.Name == name {
			conn = c
		}
	}
	if conn == nil {
		h.fail(w, r, errNoConnection, f)
		return
	}
	attemptID := secrets.RandomString(32)
	if err := h.submitCaptcha(r, f.res, &f.view, "login", f.txn.ID, attemptID); err != nil {
		status, key := captchaFailure(err)
		h.rerenderLogin(w, r, f, status, f.view.L.T(key))
		return
	}
	h.startSocial(w, r, f, conn)
}

// rerenderLogin shows the login page again with a message.
func (h *Handlers) rerenderLogin(w http.ResponseWriter, r *http.Request, f *flow, status int, message string) {
	buttons := h.socialButtons(r, f)
	conn, err := h.connection(r.Context(), f.res.Tenant.ID, f.txn)
	if errors.Is(err, errNoConnection) && len(buttons) > 0 {
		h.renderSocialOnly(w, r, status, f, buttons, message)
		return
	}
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	f.conn = conn
	data := h.stageData(f, f.txn.Params["login_hint"]).LoginData
	data.Error = message
	h.renderLoginStage(w, r, status, f, data)
}

// startSocial applies the social-login protection budget and redirects to
// the provider.
func (h *Handlers) startSocial(w http.ResponseWriter, r *http.Request, f *flow, conn *store.Connection) {
	ctx := r.Context()
	svc := h.protectionService()
	decision, err := svc.Begin(ctx, protection.Attempt{Tenant: f.res.Tenant, Connection: conn, IP: httpx.ClientIP(r, h.TrustProxyHeaders), Flow: "social-login"})
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !decision.Allowed {
		h.rerenderLogin(w, r, f, http.StatusTooManyRequests, f.view.L.T(i18n.KeyTooManyAttempts))
		return
	}
	// A provider redirect spends the pre-login token whatever happens there.
	if err := svc.Finish(ctx, decision.Receipt, "failure"); err != nil {
		h.fail(w, r, err, f)
		return
	}
	client, err := h.Store.Clients().Get(ctx, f.res.Tenant.ID, f.txn.ClientID)
	if err != nil {
		h.fail(w, r, errNoConnection, f)
		return
	}
	origin := f.txn.Origin
	if origin == "" {
		origin = tenant.CanonicalOrigin(f.res.Tenant)
	}
	begun, err := h.Federation.Begin(ctx, federation.BeginInput{Tenant: f.res.Tenant, Origin: origin, Txn: f.txn, Client: client, Connection: conn})
	if err != nil {
		h.socialFailure(w, r, f, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: begun.CookieName, Value: begun.CookieValue, Path: federation.CallbackPath, Expires: begun.ExpiresAt,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, begun.URL, http.StatusSeeOther)
}

// socialFailure renders safe copy for a federation error; details go to the
// operator log only as error classes.
func (h *Handlers) socialFailure(w http.ResponseWriter, r *http.Request, f *flow, err error) {
	view := ui.Tenant{}
	if f != nil {
		view = f.view
	} else if res, ok := tenant.FromContext(r.Context()); ok {
		view = ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
	}
	switch {
	case errors.Is(err, federation.ErrProviderDenied):
		ui.RenderError(w, http.StatusUnauthorized, view, view.L.T(i18n.KeyErrSocialDenied))
	case errors.Is(err, errSocialTooMany):
		ui.RenderError(w, http.StatusTooManyRequests, view, view.L.T(i18n.KeyTooManyAttempts))
	case errors.Is(err, federation.ErrUserBlocked):
		ui.RenderError(w, http.StatusForbidden, view, view.L.T(i18n.KeyUserBlocked))
	case errors.Is(err, federation.ErrCallbackRejected), errors.Is(err, federation.ErrAttemptStale):
		ui.RenderError(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrSessionExpired))
	case errors.Is(err, federation.ErrConnectionUnusable):
		ui.RenderError(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrNoConnection))
	default:
		h.log().WarnContext(r.Context(), "social login failed", "err", federationErrorClass(err))
		ui.RenderError(w, http.StatusBadGateway, view, view.L.T(i18n.KeyErrSocialFailed))
	}
}

var errSocialTooMany = errors.New("login: too many social registrations from this address")

// callbackConnection is the connection ID of the attempt a callback names.
func callbackConnection(ctx context.Context, h *Handlers, res tenant.Resolved, p federation.CallbackParams) string {
	a, err := h.Store.Federation().GetAttempt(ctx, res.Tenant.ID, federation.StateHash(p.State))
	if err != nil {
		return ""
	}
	return a.ConnectionID
}

// federationErrorClass names an error without its text.
func federationErrorClass(err error) string {
	for _, c := range []struct {
		err  error
		name string
	}{
		{federation.ErrScriptUnavailable, "script runtime unavailable"}, {federation.ErrProfile, "invalid profile"},
		{federation.ErrNetworkPolicy, "network policy"}, {federation.ErrResponseTooLarge, "response too large"},
		{federation.ErrProviderResponse, "provider response"}, {federation.ErrIdentityConflict, "identity conflict"},
		{context.DeadlineExceeded, "timeout"}, {store.ErrFederationUnavailable, "store federation unavailable"},
	} {
		if errors.Is(err, c.err) {
			return c.name
		}
	}
	return "internal"
}

// SocialCallback is GET /login/callback.
func (h *Handlers) SocialCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	res, ok := tenant.FromContext(ctx)
	if !ok || h.Federation == nil || r.Method != http.MethodGet {
		h.socialFailure(w, r, nil, federation.ErrCallbackRejected)
		return
	}
	params, err := federation.ParseCallback(r.URL.RawQuery)
	if err != nil {
		h.socialFailure(w, r, nil, err)
		return
	}
	cookieName := federation.AttemptCookiePrefix + federation.StateHash(params.State)[:16]
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		h.socialFailure(w, r, nil, federation.ErrCallbackRejected)
		return
	}
	ip := httpx.ClientIP(r, h.TrustProxyHeaders)
	if blocked, err := h.protectionService().IPBlocked(ctx, res.Tenant.ID, ip); err != nil || blocked {
		ui.RenderError(w, http.StatusTooManyRequests, ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, "")),
			i18n.ForRequest(res.Tenant, r, "").T(i18n.KeyTooManyAttempts))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: federation.CallbackPath, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	var sess *store.LoginSession
	done, err := h.Federation.Complete(ctx, federation.CompleteInput{
		Tenant: res.Tenant, Origin: res.Origin(), Params: params, CookieValue: c.Value,
		BeforeProvision: func(ctx context.Context) error {
			svc := h.protectionService()
			d, err := svc.Begin(ctx, protection.Attempt{Tenant: res.Tenant, Connection: &store.Connection{ID: callbackConnection(ctx, h, res, params)}, IP: ip, Flow: "social-signup"})
			if err != nil {
				return err
			}
			if !d.Allowed {
				return errSocialTooMany
			}
			return svc.Finish(ctx, d.Receipt, "failure")
		},
		RecheckOrigin: func(ctx context.Context) error {
			cur, ok := tenant.FromContext(ctx)
			if !ok {
				return errTxn
			}
			fresh, err := h.Store.Tenants().Get(ctx, cur.Tenant.ID)
			if err != nil {
				return err
			}
			return (tenant.Resolved{Tenant: fresh, Host: cur.Host}).CheckOrigin(res.Origin())
		},
		Commit: func(tx store.Store, user *store.User, txn *store.AuthTransaction, conn *store.Connection) error {
			bound := session.Manager{Store: tx, Now: h.Sessions.Now, TrustProxyHeaders: h.Sessions.TrustProxyHeaders}
			var err error
			sess, err = bound.Start(ctx, w, r, res.Tenant, user.UserID, conn.Name, h.now())
			if err != nil {
				return err
			}
			return tx.Users().RecordLogin(ctx, res.Tenant.ID, user.UserID, h.now(), httpx.RecordedIP(r, h.TrustProxyHeaders))
		},
	})
	if err != nil {
		h.socialFailure(w, r, nil, err)
		return
	}
	h.Authz.Resume(w, r, res, done.Transaction, sess)
}
