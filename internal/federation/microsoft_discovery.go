package federation

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

const (
	microsoftBaseURL        = "https://login.microsoftonline.com"
	microsoftIssuerTemplate = microsoftBaseURL + "/{tenantid}/v2.0"
	microsoftConsumerTenant = "9188040d-6c67-4c5b-b112-36a304b66dad"
)

var canonicalMicrosoftGUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// MicrosoftOverride changes transport destinations for local provider fixtures.
// Issuers and tenant/key restrictions always retain their production policy.
// No configuration, API, seed option or environment variable reaches this hook.
type MicrosoftOverride struct {
	AuthorityBaseURL string
	JWKSURL          string
}

// WithMicrosoftFixture is construction-only, before any provider use.
func (ps *Providers) WithMicrosoftFixture(o MicrosoftOverride) *Providers {
	ps.microsoftFix = &o
	return ps
}

// DiscoverMicrosoft validates Microsoft's public-cloud metadata separately from
// generic OIDC. Configuration and claims cannot override the derived URL policy.
func (ps *Providers) DiscoverMicrosoft(ctx context.Context, key CacheKey, cfg Config) (Metadata, error) {
	authority := cfg.MicrosoftAuthority
	if !validMicrosoftAuthority(authority) ||
		(cfg.Strategy != StrategyWindowsLive && cfg.Strategy != StrategyWAAD) ||
		(cfg.Strategy == StrategyWindowsLive) != (authority == "consumers") ||
		cfg.MicrosoftMultiTenant != (authority == "organizations") {
		return Metadata{}, fmt.Errorf("%w: Microsoft authority", ErrInvalidConfig)
	}
	discoveryURL := ps.microsoftEndpoint("/" + authority + "/v2.0/.well-known/openid-configuration")
	ck := key.with("microsoft-discovery", authority, cfg.Issuer, discoveryURL)
	if m, ok := ps.discovery.get(ck); ok {
		return m, nil
	}
	var raw map[string]any
	if err := ps.getJSON(ctx, discoveryURL, "", &raw); err != nil {
		return Metadata{}, err
	}
	m, err := ps.validateMicrosoftMetadata(raw, authority, cfg.Issuer)
	if err != nil {
		return Metadata{}, err
	}
	ps.discovery.put(ck, m)
	return m, nil
}

func validMicrosoftAuthority(authority string) bool {
	if authority == "consumers" || authority == "organizations" {
		return true
	}
	normalized, _, err := rules.MicrosoftAuthority(rules.WAAD, map[string]any{"tenant_domain": authority})
	return err == nil && normalized == authority
}

func microsoftTenantIssuer(tenant string) string { return microsoftBaseURL + "/" + tenant + "/v2.0" }

// microsoftIssuerTenant accepts only a concrete, canonical public-cloud issuer.
func microsoftIssuerTenant(issuer string) (string, bool) {
	tenant := strings.TrimSuffix(strings.TrimPrefix(issuer, microsoftBaseURL+"/"), "/v2.0")
	return tenant, canonicalMicrosoftGUID.MatchString(tenant) && issuer == microsoftTenantIssuer(tenant)
}

func (ps *Providers) validateMicrosoftMetadata(raw map[string]any, authority, pinnedIssuer string) (Metadata, error) {
	bad := func(what string) (Metadata, error) {
		return Metadata{}, fmt.Errorf("%w: Microsoft discovery %s", ErrProviderResponse, what)
	}
	str := func(k string) string { s, _ := raw[k].(string); return s }
	issuer := str("issuer")
	tenant, concrete := microsoftIssuerTenant(issuer)
	switch authority {
	case "organizations":
		if issuer != microsoftIssuerTemplate {
			return bad("requires the organizational issuer template")
		}
	case "consumers":
		if issuer != microsoftIssuerTemplate && (!concrete || tenant != microsoftConsumerTenant) {
			return bad("personal issuer mismatch")
		}
	default:
		if !concrete || tenant == microsoftConsumerTenant || (canonicalMicrosoftGUID.MatchString(authority) && tenant != authority) {
			return bad("directory issuer mismatch")
		}
	}
	if pinnedIssuer != "" && pinnedIssuer != issuer {
		return bad("pinned issuer mismatch")
	}
	authPath := "/" + authority + "/oauth2/v2.0/authorize"
	tokenPath := "/" + authority + "/oauth2/v2.0/token"
	jwks := str("jwks_uri")
	if !microsoftEndpointMatches(str("authorization_endpoint"), authPath) || !microsoftEndpointMatches(str("token_endpoint"), tokenPath) || !microsoftJWKSMatches(jwks, authority) {
		return bad("endpoint refused")
	}
	methods, ok := strictStringSlice(raw["token_endpoint_auth_methods_supported"])
	if !ok || !slices.Contains(methods, authPost) {
		return bad("does not advertise client_secret_post")
	}
	for field, required := range map[string]string{"code_challenge_methods_supported": "S256", "id_token_signing_alg_values_supported": "RS256"} {
		if value, exists := raw[field]; exists {
			list, ok := strictStringSlice(value)
			if !ok || !slices.Contains(list, required) {
				return bad("unsupported or malformed algorithm metadata")
			}
		}
	}
	m := Metadata{Issuer: issuer, AuthorizationEndpoint: str("authorization_endpoint"), TokenEndpoint: str("token_endpoint"), JWKSURI: jwks, TokenAuthMethod: authPost}
	// UserInfo is deliberately absent; this subset uses only verified ID-token claims.
	if ps.microsoftFix != nil {
		m.AuthorizationEndpoint = ps.microsoftEndpoint(authPath)
		m.TokenEndpoint = ps.microsoftEndpoint(tokenPath)
		u, _ := url.Parse(jwks) // validated above
		m.JWKSURI = ps.microsoftJWKSURL(u.Path)
	}
	for _, endpoint := range []string{m.AuthorizationEndpoint, m.TokenEndpoint, m.JWKSURI} {
		if ps.policy.CheckEndpoint(endpoint) != nil {
			return bad("transport endpoint refused")
		}
	}
	return m, nil
}

func strictStringSlice(v any) ([]string, bool) {
	values, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(values))
	for i, value := range values {
		s, ok := value.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func microsoftEndpointMatches(raw, path string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && (u.Host == "login.microsoftonline.com" || u.Host == "login.microsoftonline.com:443") && u.User == nil && u.Path == path && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(raw, "#")
}

func microsoftJWKSMatches(raw, authority string) bool {
	return microsoftEndpointMatches(raw, "/common/discovery/v2.0/keys") || microsoftEndpointMatches(raw, "/"+authority+"/discovery/v2.0/keys")
}

func (ps *Providers) microsoftEndpoint(path string) string {
	if ps.microsoftFix != nil {
		return strings.TrimRight(ps.microsoftFix.AuthorityBaseURL, "/") + path
	}
	return microsoftBaseURL + path
}

func (ps *Providers) microsoftJWKSURL(path string) string {
	if ps.microsoftFix != nil && ps.microsoftFix.JWKSURL != "" {
		return ps.microsoftFix.JWKSURL
	}
	return ps.microsoftEndpoint(path)
}
