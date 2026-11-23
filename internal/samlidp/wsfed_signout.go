package samlidp

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// wsfedSignOut handles wsignout1.0 and wsignoutcleanup1.0 (LR37b-9).
// wsignout1.0 is /v2/logout for the application: the session ends (with
// upstream and back-channel logout) and the browser returns to wreply,
// which must be an allowed logout URL. wsignoutcleanup1.0 only ends the
// session and answers with the signed-out page.
func (h *Handler) wsfedSignOut(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, p WSFedParams) {
	if p.Action == wsfedSignOut {
		q := url.Values{"client_id": {client.ClientID}}
		if p.Reply != "" {
			q.Set("returnTo", p.Reply)
		}
		http.Redirect(w, r, "/v2/logout?"+q.Encode(), http.StatusFound)
		return
	}
	if _, err := h.Sessions.End(r.Context(), w, r, res.Tenant); err != nil {
		h.log().ErrorContext(r.Context(), "wsfed: end session", "tenant", res.Tenant.ID, "err", err)
		h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	ui.RenderLoggedOut(w, ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, "")))
}

// WSFedMetadata serves the federation metadata: the tenant's at
// /wsfed/FederationMetadata/2007-06/FederationMetadata.xml (clientID
// empty) and an application's under /wsfed/{client_id}/.
func (h *Handler) WSFedMetadata(w http.ResponseWriter, r *http.Request, clientID string) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	endpoint := res.Origin() + "/wsfed"
	if clientID != "" {
		client, err := h.Store.Clients().Get(r.Context(), res.Tenant.ID, clientID)
		if errors.Is(err, store.ErrNotFound) || err == nil && !hasWSFed(client) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		endpoint += "/" + url.PathEscape(client.ClientID)
	}
	certs, err := h.Keys.SAMLCertificates(r.Context(), res.Tenant.ID)
	if err != nil {
		h.log().ErrorContext(r.Context(), "wsfed: metadata certificates", "tenant", res.Tenant.ID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	md := samlcore.BuildWSFedMetadata(issuer(res, &store.SAMLAddon{}), endpoint, certs)
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(md)
	raw, err := doc.WriteToBytes()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(raw)
}
