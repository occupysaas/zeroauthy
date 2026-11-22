package samlidp

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

const defaultLifetime = 3600 // node-samlp default (D-0130)

func newID() string { return "_" + secrets.RandomString(32) }

// issuer is the add-on issuer or urn:{tenant host} (S37-6).
func issuer(res tenant.Resolved, addon *store.SAMLAddon) string {
	if addon.Issuer != "" {
		return addon.Issuer
	}
	host := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(res.Issuer(), "https://"), "http://"), "/")
	return "urn:" + host
}

func (h *Handler) signer(r *http.Request, res tenant.Resolved, addon *store.SAMLAddon) (*samlcore.Signer, error) {
	key, cert, err := h.Keys.SAMLSigner(r.Context(), res.Tenant.ID)
	if err != nil {
		return nil, err
	}
	return &samlcore.Signer{Key: key, Cert: cert, Algorithm: addon.SignatureAlgorithm, Digest: addon.DigestAlgorithm}, nil
}

// post auto-submits the SAML response to the ACS with RelayState.
func post(w http.ResponseWriter, r *http.Request, res tenant.Resolved, acs string, resp *etree.Element, relayState string) {
	params := url.Values{samlcore.ParamResponse: {samlcore.EncodePOST(resp)}}
	if relayState != "" {
		params.Set("RelayState", relayState)
	}
	ui.RenderFormPost(w, i18n.ForRequest(res.Tenant, r, ""), acs, params)
}

// Respond completes a samlp transaction with a signed assertion for the
// session's user (authz.SAMLResponder).
func (h *Handler) Respond(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, binding, orgID string, sess *store.LoginSession, eff *actions.Effects) {
	b, err := decodeBinding(binding)
	if err != nil || client.Addons == nil || client.Addons.SAMLP == nil {
		h.page(w, r, res, http.StatusBadRequest, "The SAML request is no longer valid.")
		return
	}
	addon := client.Addons.SAMLP
	user, err := h.Store.Users().Get(r.Context(), res.Tenant.ID, sess.UserID)
	if err != nil {
		h.log().ErrorContext(r.Context(), "saml: load user", "tenant", res.Tenant.ID, "err", err)
		h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	now := h.now()
	lifetime := defaultLifetime
	if addon.LifetimeInSeconds != nil {
		lifetime = *addon.LifetimeInSeconds
	}
	extra := map[string]any{}
	if orgID != "" {
		extra["org_id"] = orgID
	}
	m := buildAttributes(user, addon, extra)
	nameIDFormat := addon.NameIdentifierFormat
	if nameIDFormat == "" {
		nameIDFormat = samlcore.NameIDUnspecified
	}
	authn := now
	if !sess.AuthenticatedAt.IsZero() {
		authn = sess.AuthenticatedAt.UTC()
	}
	spec := samlcore.AssertionSpec{ID: newID(), IssueInstant: now, Issuer: issuer(res, addon), NameID: m.NameID, NameIDFormat: nameIDFormat,
		Audience: b.Audience, Recipient: b.ACS, InResponseTo: b.RequestID, NotBefore: now, NotOnOrAfter: now.Add(time.Duration(lifetime) * time.Second),
		AuthnInstant: authn, SessionIndex: sess.ID, AuthnContextClassRef: addon.AuthnContextClassRef, Attributes: m.Attributes,
		TypedAttributes: flag(addon.TypedAttributes, true), IncludeNameFormat: flag(addon.IncludeAttributeNameFormat, true)}
	signer, err := h.signer(r, res, addon)
	if err != nil {
		h.log().ErrorContext(r.Context(), "saml: signing key", "tenant", res.Tenant.ID, "err", err)
		h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	assertion, err := signer.SignEnveloped(samlcore.BuildAssertion(spec))
	if err != nil {
		h.log().ErrorContext(r.Context(), "saml: sign assertion", "tenant", res.Tenant.ID, "err", err)
		h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	destination := addon.Destination
	if destination == "" {
		destination = b.ACS
	}
	resp := samlcore.BuildResponse(samlcore.ResponseSpec{ID: newID(), InResponseTo: b.RequestID, Destination: destination, Issuer: spec.Issuer,
		IssueInstant: now, StatusCode: samlcore.StatusSuccess}, assertion)
	if flag(addon.SignResponse, false) {
		if resp, err = signer.SignEnveloped(resp); err != nil {
			h.log().ErrorContext(r.Context(), "saml: sign response", "tenant", res.Tenant.ID, "err", err)
			h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
			return
		}
	}
	if rec, ok := h.Store.Sessions().(store.SAMLSessionRecorder); ok {
		p := store.SAMLParticipant{ClientID: client.ClientID, NameID: m.NameID, NameIDFormat: nameIDFormat, SessionIndex: sess.ID}
		if err := rec.RecordSAMLParticipant(r.Context(), res.Tenant.ID, sess.ID, p); err != nil {
			h.log().WarnContext(r.Context(), "saml: record session participant", "tenant", res.Tenant.ID, "err", err)
		}
	}
	post(w, r, res, b.ACS, resp, b.RelayState)
}

// Fail answers a samlp transaction that cannot complete with a SAML error
// response to the (already validated) ACS (authz.SAMLResponder).
func (h *Handler) Fail(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, binding, code, description string) {
	b, err := decodeBinding(binding)
	if err != nil || client == nil || client.Addons == nil || client.Addons.SAMLP == nil {
		h.page(w, r, res, http.StatusBadRequest, description)
		return
	}
	addon := client.Addons.SAMLP
	status := samlcore.StatusResponder
	if code == "access_denied" || code == "login_required" || code == "unauthorized" {
		status = samlcore.StatusAuthnFail
	}
	resp := samlcore.BuildResponse(samlcore.ResponseSpec{ID: newID(), InResponseTo: b.RequestID, Destination: b.ACS, Issuer: issuer(res, addon),
		IssueInstant: h.now(), StatusCode: status, StatusMessage: description}, nil)
	if signer, err := h.signer(r, res, addon); err == nil {
		if signed, err := signer.SignEnveloped(resp); err == nil {
			resp = signed
		}
	}
	post(w, r, res, b.ACS, resp, b.RelayState)
}
