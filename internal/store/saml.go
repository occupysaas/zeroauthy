package store

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"
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

// SAMLParticipant is a SAML service provider a session answered: what a
// LogoutRequest to it must name.
type SAMLParticipant struct {
	// ConnectionID marks the upstream SAML IdP this session signed in with
	// (SP single logout); ClientID is then empty.
	ConnectionID string `json:"connection_id,omitempty"`
	ClientID     string `json:"client_id"`
	NameID       string `json:"name_id"`
	NameIDFormat string `json:"name_id_format,omitempty"`
	SessionIndex string `json:"session_index"`
}

// SAMLSessionRecorder records a session's SAML participants (saml.v1). A
// client recorded again replaces its earlier entry and moves last; the
// client is also added to the session's clients.
type SAMLSessionRecorder interface {
	RecordSAMLParticipant(ctx context.Context, tenantID, id string, p SAMLParticipant) error
}

// UpsertSAMLParticipant returns ps with p replacing any entry for its client,
// appended last.
func UpsertSAMLParticipant(ps []SAMLParticipant, p SAMLParticipant) []SAMLParticipant {
	out := make([]SAMLParticipant, 0, len(ps)+1)
	for _, e := range ps {
		if e.ClientID != p.ClientID || e.ConnectionID != p.ConnectionID {
			out = append(out, e)
		}
	}
	return append(out, p)
}

// SAMLReplayStore makes SAML assertion IDs single use (saml.v1, LR37a-3).
// UseSAMLAssertion records an assertion ID for a tenant and connection until
// exp; ErrConflict means it was already used and has not expired. It must
// run inside the transaction that commits the login.
type SAMLReplayStore interface {
	UseSAMLAssertion(ctx context.Context, tenantID, connectionID, assertionID string, exp, now time.Time) error
	PurgeSAMLAssertions(ctx context.Context, before time.Time, limit int) (int, error)
}
