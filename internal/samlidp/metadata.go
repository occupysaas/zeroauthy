package samlidp

import (
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

// Metadata serves GET /samlp/metadata/{client_id}: the IdP EntityDescriptor
// with the current and next signing certificates.
func (h *Handler) Metadata(w http.ResponseWriter, r *http.Request, clientID string) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	client, err := h.Store.Clients().Get(r.Context(), res.Tenant.ID, clientID)
	if errors.Is(err, store.ErrNotFound) || err == nil && (client.Addons == nil || client.Addons.SAMLP == nil) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	certs, err := h.Keys.SAMLCertificates(r.Context(), res.Tenant.ID)
	if err != nil {
		h.log().ErrorContext(r.Context(), "saml: metadata certificates", "tenant", res.Tenant.ID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sso := res.Origin() + "/samlp/" + client.ClientID
	md := samlcore.BuildMetadata(samlcore.EntityDescriptor{EntityID: issuer(res, client.Addons.SAMLP), IdP: &samlcore.IdPDescriptor{
		SigningCerts:  certs,
		NameIDFormats: []string{samlcore.NameIDEmail, samlcore.NameIDUnspecified, samlcore.NameIDPersistent, samlcore.NameIDTransient},
		SSO:           []samlcore.Endpoint{{Binding: samlcore.BindingRedirect, Location: sso}, {Binding: samlcore.BindingPOST, Location: sso}},
		SLO:           []samlcore.Endpoint{{Binding: samlcore.BindingRedirect, Location: sso + "/logout"}, {Binding: samlcore.BindingPOST, Location: sso + "/logout"}},
	}})
	writeXML(w, md)
}

func writeXML(w http.ResponseWriter, el *etree.Element) {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(el)
	raw, err := doc.WriteToBytes()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(raw)
}
