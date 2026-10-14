package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// Logout implements GET /v2/logout (D-0014). The request is validated
// before the session ends; an invalid request changes nothing.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
	q := r.URL.Query()
	returnTo := q.Get("returnTo")
	allowed := res.Tenant.AllowedLogoutURLs
	if id := q.Get("client_id"); id != "" {
		c, err := h.Store.Clients().Get(ctx, res.Tenant.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			ui.RenderError(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrLogoutUnknownClient))
			return
		}
		if err != nil {
			h.log().ErrorContext(ctx, "load client", "tenant", res.Tenant.ID, "err", err)
			ui.RenderError(w, http.StatusInternalServerError, view, view.L.T(i18n.KeyErrServer))
			return
		}
		allowed = c.AllowedLogoutURLs
		if returnTo == "" {
			returnTo = firstConcrete(allowed)
		}
	}
	if returnTo != "" && !returnToAllowed(allowed, returnTo) {
		ui.RenderError(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrLogoutURL))
		return
	}
	if !h.endSession(w, r, res, view) {
		return
	}
	if returnTo == "" {
		ui.RenderLoggedOut(w, view)
		return
	}
	redirect(w, r, returnTo)
}

// returnToAllowed applies the /v2/logout rule: the query string and
// fragment are not compared, and scheme and host are case-insensitive. Both
// returnTo and each registered URL are normalized the same way.
func returnToAllowed(allowed []string, returnTo string) bool {
	n, ok := normalizeLogoutURL(returnTo)
	if !ok {
		return false
	}
	norm := make([]string, 0, len(allowed))
	for _, a := range allowed {
		if x, ok := normalizeLogoutURL(a); ok {
			norm = append(norm, x)
		}
	}
	return authz.AllowedURL(norm, n)
}

// normalizeLogoutURL drops the query and fragment and lowercases scheme and
// host. It reports false for URLs that do not parse, have no scheme, or
// carry userinfo.
func normalizeLogoutURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.User != nil {
		return "", false
	}
	u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = "", false, "", ""
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	return u.String(), true
}

// firstConcrete returns the first allowed URL that is not a wildcard
// pattern, or "".
func firstConcrete(allowed []string) string {
	for _, u := range allowed {
		if !strings.Contains(u, "*") {
			return u
		}
	}
	return ""
}

// endSession ends the browser's session. On a store failure it renders the
// error page and returns false.
func (h *Handlers) endSession(w http.ResponseWriter, r *http.Request, res tenant.Resolved, view ui.Tenant) bool {
	ctx := r.Context()
	s, err := h.Sessions.End(ctx, w, r, res.Tenant)
	if err != nil {
		h.log().ErrorContext(ctx, "end session", "tenant", res.Tenant.ID, "err", err)
		ui.RenderError(w, http.StatusInternalServerError, view, view.L.T(i18n.KeyErrServer))
		return false
	}
	if s != nil {
		h.log().InfoContext(ctx, "logged out", "tenant", res.Tenant.ID, "session", s.ID, "user_id", s.UserID)
	}
	return true
}

func redirect(w http.ResponseWriter, r *http.Request, to string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, to, http.StatusFound)
}
