package federation

import (
	"errors"
	"fmt"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

// ErrImmutable reports an attempt to change a binding that requires a new
// connection.
var ErrImmutable = errors.New("federation: immutable connection setting changed")

// Config is a federated connection's validated runtime configuration. It
// holds a reference to the sealed credentials, never the plaintext secret.
type Config struct {
	MicrosoftAuthority   string
	MicrosoftMultiTenant bool
	Strategy             string
	ClientID             string
	// SecretReference is the sealed credential record (a copy); empty when
	// the secret is only being supplied in plaintext by the current write.
	SecretReference  []byte
	AuthorizationURL string
	TokenURL         string
	DiscoveryURL     string
	Scopes           []string
	// ProfileSync is the set_user_root_attributes policy.
	ProfileSync string
	// Script is the OAuth2 fetchUserProfile source.
	Script string
	// Issuer is the immutable issuer binding: fixed for Google, pinned at the
	// first successful discovery for OIDC, empty for OAuth2.
	Issuer               string
	Revision             int64
	AuthenticationActive bool
	IsSocial             bool
}

// ParseConfig validates spec, a federated connection in connrules form, and
// returns its runtime configuration.
func ParseConfig(spec connrules.Spec) (Config, error) {
	if !spec.Federated() {
		return Config{}, fmt.Errorf("federation: strategy %q is not federated", spec.Strategy)
	}
	settings, errs := rules.Parse(spec.FederationInput())
	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	c := Config{
		MicrosoftAuthority:   settings.MicrosoftAuthority,
		MicrosoftMultiTenant: settings.MicrosoftMultiTenant,
		Strategy:             settings.Strategy,
		ClientID:             settings.ClientID,
		SecretReference:      slices.Clone(spec.FederationSecretsSealed),
		AuthorizationURL:     settings.AuthorizationURL,
		TokenURL:             settings.TokenURL,
		DiscoveryURL:         settings.DiscoveryURL,
		Scopes:               settings.Scopes,
		ProfileSync:          settings.ProfileSync,
		Script:               settings.Script,
		Revision:             spec.FederationRevision,
		AuthenticationActive: settings.AuthenticationActive,
		IsSocial:             rules.IsSocial(settings.Strategy),
	}
	switch c.Strategy {
	case StrategyGoogle:
		c.Issuer = rules.GoogleIssuer
	case StrategyWindowsLive, StrategyWAAD, StrategyOIDC:
		c.Issuer = spec.FederationIssuer
	}
	return c, nil
}

// ValidateConfigUpdate checks that next keeps every immutable binding of
// prev: strategy, client ID, discovery and OAuth endpoints, profile script
// and a pinned issuer. Scopes, profile sync, purpose and secret rotation stay
// editable.
func ValidateConfigUpdate(prev, next Config) error {
	type binding struct {
		name       string
		prev, next string
	}
	for _, b := range []binding{
		{"strategy", prev.Strategy, next.Strategy},
		{"client_id", prev.ClientID, next.ClientID},
		{"discovery_url", prev.DiscoveryURL, next.DiscoveryURL},
		{"authorizationURL", prev.AuthorizationURL, next.AuthorizationURL},
		{"tokenURL", prev.TokenURL, next.TokenURL},
		{"scripts.fetchUserProfile", prev.Script, next.Script},
	} {
		if b.prev != b.next {
			return fmt.Errorf("%w: %s; create a new connection instead", ErrImmutable, b.name)
		}
	}
	if prev.MicrosoftAuthority != next.MicrosoftAuthority || prev.MicrosoftMultiTenant != next.MicrosoftMultiTenant {
		return fmt.Errorf("%w: Microsoft authority; create a new connection instead", ErrImmutable)
	}
	if prev.Issuer != "" && next.Issuer != prev.Issuer {
		return fmt.Errorf("%w: issuer; create a new connection instead", ErrImmutable)
	}
	return nil
}

// EffectiveChange reports whether next differs from prev in a setting that
// affects authentication, so the connection's FederationRevision must
// increase and pending attempts become stale.
func EffectiveChange(prev, next Config) bool {
	return prev.MicrosoftAuthority != next.MicrosoftAuthority || prev.MicrosoftMultiTenant != next.MicrosoftMultiTenant || prev.Strategy != next.Strategy || prev.ClientID != next.ClientID ||
		!slices.Equal(prev.SecretReference, next.SecretReference) ||
		prev.AuthorizationURL != next.AuthorizationURL || prev.TokenURL != next.TokenURL ||
		prev.DiscoveryURL != next.DiscoveryURL || !slices.Equal(prev.Scopes, next.Scopes) ||
		prev.ProfileSync != next.ProfileSync || prev.Script != next.Script ||
		prev.Issuer != next.Issuer || prev.AuthenticationActive != next.AuthenticationActive
}
