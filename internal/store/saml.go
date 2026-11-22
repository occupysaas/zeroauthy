package store

import (
	"context"
	"errors"
	"maps"
	"slices"
)

// ClientAddons are an application's add-ons (Plan 37a). Only samlp exists.
type ClientAddons struct {
	SAMLP *SAMLAddon `json:"samlp,omitempty"`
}

// SAMLAddon is the validated samlp add-on (Auth0 member names). Pointer
// fields distinguish "absent" (the documented default applies) from a value.
type SAMLAddon struct {
	Mappings                       map[string][]string `json:"mappings,omitempty"`
	Audience                       string              `json:"audience,omitempty"`
	Recipient                      string              `json:"recipient,omitempty"`
	CreateUpnClaim                 *bool               `json:"createUpnClaim,omitempty"`
	MapUnknownClaimsAsIs           *bool               `json:"mapUnknownClaimsAsIs,omitempty"`
	PassthroughClaimsWithNoMapping *bool               `json:"passthroughClaimsWithNoMapping,omitempty"`
	MapIdentities                  *bool               `json:"mapIdentities,omitempty"`
	SignatureAlgorithm             string              `json:"signatureAlgorithm,omitempty"`
	DigestAlgorithm                string              `json:"digestAlgorithm,omitempty"`
	Issuer                         string              `json:"issuer,omitempty"`
	Destination                    string              `json:"destination,omitempty"`
	LifetimeInSeconds              *int                `json:"lifetimeInSeconds,omitempty"`
	SignResponse                   *bool               `json:"signResponse,omitempty"`
	NameIdentifierFormat           string              `json:"nameIdentifierFormat,omitempty"`
	NameIdentifierProbes           []string            `json:"nameIdentifierProbes,omitempty"`
	AuthnContextClassRef           string              `json:"authnContextClassRef,omitempty"`
	Logout                         *SAMLAddonLogout    `json:"logout,omitempty"`
	Binding                        string              `json:"binding,omitempty"`
	TypedAttributes                *bool               `json:"typedAttributes,omitempty"`
	IncludeAttributeNameFormat     *bool               `json:"includeAttributeNameFormat,omitempty"`
	SigningCert                    string              `json:"signingCert,omitempty"`
}

// SAMLAddonLogout is the add-on's single logout settings.
type SAMLAddonLogout struct {
	Callback   string `json:"callback,omitempty"`
	SLOEnabled *bool  `json:"slo_enabled,omitempty"`
}

func cloneBool(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}

// Clone returns a deep copy.
func (a *ClientAddons) Clone() *ClientAddons {
	if a == nil {
		return nil
	}
	return &ClientAddons{SAMLP: a.SAMLP.Clone()}
}

// Clone returns a deep copy.
func (s *SAMLAddon) Clone() *SAMLAddon {
	if s == nil {
		return nil
	}
	out := *s
	if s.Mappings != nil {
		out.Mappings = maps.Clone(s.Mappings)
		for k, v := range out.Mappings {
			out.Mappings[k] = slices.Clone(v)
		}
	}
	out.NameIdentifierProbes = slices.Clone(s.NameIdentifierProbes)
	for _, p := range []**bool{&out.CreateUpnClaim, &out.MapUnknownClaimsAsIs, &out.PassthroughClaimsWithNoMapping, &out.MapIdentities, &out.SignResponse, &out.TypedAttributes, &out.IncludeAttributeNameFormat} {
		*p = cloneBool(*p)
	}
	if s.LifetimeInSeconds != nil {
		v := *s.LifetimeInSeconds
		out.LifetimeInSeconds = &v
	}
	if s.Logout != nil {
		l := *s.Logout
		l.SLOEnabled = cloneBool(s.Logout.SLOEnabled)
		out.Logout = &l
	}
	return &out
}

// ErrSAMLUnavailable reports a storage plugin without the saml.v1 capability.
var ErrSAMLUnavailable = errors.New("store: saml.v1 unavailable")

// SAMLSupporter is implemented by stores that can tell whether they support
// Plan 37a's state.
type SAMLSupporter interface{ CheckSAMLSupport(context.Context) error }

// CheckSAMLSupport reports whether s stores Plan 37a's state. Stores that do
// not implement SAMLSupporter (memory, SQL) support it.
func CheckSAMLSupport(ctx context.Context, s Store) error {
	if capability, ok := s.(SAMLSupporter); ok {
		return capability.CheckSAMLSupport(ctx)
	}
	return nil
}

// ClientNeedsSAML reports whether writing c needs saml.v1.
func ClientNeedsSAML(c *Client) bool { return c != nil && c.Addons != nil }
