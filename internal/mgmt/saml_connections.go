package mgmt

import (
	"context"
	"encoding/pem"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
)

// samlMetadata fills a samlp connection's IdP settings from options.metadataUrl
// (Plan 37a): the fetched metadata supplies signInEndpoint, signOutEndpoint
// and signingCert, as Auth0 derives them. Values given in the written
// options win; an options write without signingCert takes the IdP's current
// certificate, which is how a rotation is picked up.
func (h *Handlers) samlMetadata(ctx context.Context, spec *connrules.Spec) error {
	if spec.Strategy != rules.SAMLP {
		return nil
	}
	u, _ := spec.Options.Extra["metadataUrl"].(string)
	derived, err := h.fetchSAMLMetadata(ctx, u)
	if err != nil {
		return err
	}
	applySAMLMetadata(spec, derived)
	return nil
}

// fetchSAMLMetadata fetches and reads metadataUrl; it makes an outbound
// request, so callers run it outside store transactions. "" fetches nothing.
func (h *Handlers) fetchSAMLMetadata(ctx context.Context, u string) (map[string]string, error) {
	if u == "" {
		return nil, nil
	}
	if h.SAMLMetadata == nil {
		return nil, badBody("options.metadataUrl cannot be fetched by this server")
	}
	if err := rules.ValidateEndpoint(u, false); err != nil {
		return nil, badBody("options.metadataUrl must be a public https URL")
	}
	raw, err := h.SAMLMetadata(ctx, u)
	if err != nil {
		return nil, badBody("options.metadataUrl could not be fetched")
	}
	md, err := samlcore.ParseMetadata(raw)
	if err != nil || md.IdP == nil || len(md.IdP.SigningCerts) == 0 {
		return nil, badBody("options.metadataUrl is not identity provider metadata with a signing certificate")
	}
	out := map[string]string{}
	sso := md.IdP.SSOLocation(samlcore.BindingRedirect)
	if sso == "" {
		sso = md.IdP.SSOLocation(samlcore.BindingPOST)
		out["protocolBinding"] = samlcore.BindingPOST
	}
	out["signInEndpoint"] = sso
	out["signOutEndpoint"] = md.IdP.SLOLocation(samlcore.BindingRedirect)
	out["signingCert"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: md.IdP.SigningCerts[0].Raw}))
	return out, nil
}

// applySAMLMetadata sets derived values the options do not give.
func applySAMLMetadata(spec *connrules.Spec, derived map[string]string) {
	for k, v := range derived {
		if _, given := spec.Options.Extra[k]; !given && v != "" {
			spec.Options.Extra[k] = v
		}
	}
}
