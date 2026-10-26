package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// logoutCSRFCookie binds a logout confirmation form to the browser that
// was shown it.
const logoutCSRFCookie = "za_logout"

const maxLogoutFormBytes = 16 << 10

// confirmedFields are the request parameters the confirmation page posts
// back.
var confirmedFields = []string{"id_token_hint", "logout_hint", "client_id", "post_logout_redirect_uri", "state", "ui_locales"}

// OidcLogout implements OpenID Connect RP-Initiated Logout 1.0 at GET and
// POST /oidc/logout (D-0015). The request is validated before anything
// changes; without a hint that matches the browser's session the user is
// asked to confirm.
func (h *Handlers) OidcLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxLogoutFormBytes)
	}
	if err := r.ParseForm(); err != nil {
		view := ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
		ui.RenderError(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrLogoutInvalid))
		return
	}
	p := r.Form
	view := ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, p.Get("ui_locales")))
	fail := func(status int, key string) { ui.RenderError(w, status, view, view.L.T(key)) }
	confirmed := r.Method == http.MethodPost && p.Get("confirm") == "yes"
	if confirmed && !confirmationValid(r, p.Get("csrf")) {
		fail(http.StatusBadRequest, i18n.KeyErrLogoutInvalid)
		return
	}

	clientID, hintSID := p.Get("client_id"), ""
	if raw := p.Get("id_token_hint"); raw != "" {
		aud, sid, ok, err := h.idTokenHint(ctx, res, raw)
		if err != nil {
			h.log().ErrorContext(ctx, "verify id_token_hint", "tenant", res.Tenant.ID, "err", err)
			fail(http.StatusInternalServerError, i18n.KeyErrServer)
			return
		}
		if !ok || (clientID != "" && clientID != aud) {
			fail(http.StatusBadRequest, i18n.KeyErrLogoutInvalid)
			return
		}
		clientID, hintSID = aud, sid
	}
	logoutHint := p.Get("logout_hint")
	if hintSID != "" && logoutHint != "" && hintSID != logoutHint {
		fail(http.StatusBadRequest, i18n.KeyErrLogoutInvalid)
		return
	}

	allowed := res.Tenant.AllowedLogoutURLs
	if clientID != "" {
		c, err := h.Store.Clients().Get(ctx, res.Tenant.ID, clientID)
		if errors.Is(err, store.ErrNotFound) {
			fail(http.StatusBadRequest, i18n.KeyErrLogoutUnknownClient)
			return
		}
		if err != nil {
			h.log().ErrorContext(ctx, "load client", "tenant", res.Tenant.ID, "err", err)
			fail(http.StatusInternalServerError, i18n.KeyErrServer)
			return
		}
		allowed = c.AllowedLogoutURLs
	}
	target := p.Get("post_logout_redirect_uri")
	if target != "" && !authz.AllowedURL(allowed, target) {
		fail(http.StatusBadRequest, i18n.KeyErrLogoutURL)
		return
	}

	sess, err := h.Sessions.Lookup(ctx, r, res.Tenant)
	if err != nil {
		h.log().ErrorContext(ctx, "load session", "tenant", res.Tenant.ID, "err", err)
		fail(http.StatusInternalServerError, i18n.KeyErrServer)
		return
	}
	hinted := sess != nil && ((hintSID != "" && hintSID == sess.ID) || (logoutHint != "" && logoutHint == sess.ID))
	if sess != nil && !hinted && !confirmed {
		h.renderLogoutConfirm(w, view, p, target)
		return
	}
	if confirmed {
		http.SetCookie(w, &http.Cookie{Name: logoutCSRFCookie, Value: "", Path: "/oidc/logout", MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	}
	if !h.endSession(w, r, res, view) {
		return
	}
	if target == "" {
		ui.RenderLoggedOut(w, view)
		return
	}
	if state := p.Get("state"); state != "" {
		// Append to the registered URL byte for byte. AllowedURL rejects
		// fragments, so the query is the end of the string.
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target += sep + "state=" + url.QueryEscape(state)
	}
	redirect(w, r, target)
}

// idTokenHint verifies an ID token this tenant issued and returns its
// audience and sid. Expired tokens are accepted (RP-Initiated Logout §2).
// ok is false for tokens that are invalid; err is set only for internal
// failures.
func (h *Handlers) idTokenHint(ctx context.Context, res tenant.Resolved, raw string) (aud, sid string, ok bool, err error) {
	var std jwt.Claims
	var extra struct {
		SID string `json:"sid"`
	}
	if err := h.Keys.Verify(ctx, res.Tenant.ID, raw, &std, &extra); err != nil {
		if errors.Is(err, keys.ErrInvalidToken) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	if std.Issuer != res.Issuer() || len(std.Audience) != 1 {
		return "", "", false, nil
	}
	return std.Audience[0], extra.SID, true, nil
}

func (h *Handlers) renderLogoutConfirm(w http.ResponseWriter, view ui.Tenant, p url.Values, target string) {
	token := secrets.RandomString(32)
	http.SetCookie(w, &http.Cookie{Name: logoutCSRFCookie, Value: token, Path: "/oidc/logout", MaxAge: 600,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	fields := url.Values{}
	for _, k := range confirmedFields {
		if v := p.Get(k); v != "" {
			fields.Set(k, v)
		}
	}
	ui.RenderLogoutConfirm(w, view, ui.LogoutConfirmData{CSRF: token, Fields: fields, RedirectURI: target})
}

// confirmationValid reports whether the posted csrf token equals the
// browser's za_logout cookie.
func confirmationValid(r *http.Request, csrf string) bool {
	c, err := r.Cookie(logoutCSRFCookie)
	return err == nil && c.Value != "" && csrf != "" && subtle.ConstantTimeCompare([]byte(c.Value), []byte(csrf)) == 1
}
