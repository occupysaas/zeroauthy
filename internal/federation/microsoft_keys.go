package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/go-jose/go-jose/v4"
)

// microsoftSigningKey retains the Microsoft extension alongside the JOSE key.
// Callers must verify the JWS before treating any claims as authenticated.
type microsoftSigningKey struct {
	Key    jose.JSONWebKey
	Issuer string
}

func (ps *Providers) microsoftKey(ctx context.Context, cache CacheKey, authority, jwksURL, kid, tokenIssuer, tenantID string) (*jose.JSONWebKey, error) {
	key, err := ps.microsoftSigningKey(ctx, cache, authority, jwksURL, kid, tokenIssuer, tenantID)
	if err != nil {
		return nil, err
	}
	return &key.Key, nil
}

// microsoftSigningKey selects a key using claims only as validation inputs.
// authority and jwksURL must come from the connection/attempt, never a token.
// The caller verifies the signature, then rechecks the retained Issuer against
// verified claims. This preserves issuer bindings even when raw keys are cached.
func (ps *Providers) microsoftSigningKey(ctx context.Context, cache CacheKey, authority, jwksURL, kid, tokenIssuer, tenantID string) (*microsoftSigningKey, error) {
	bad := func(what string) (*microsoftSigningKey, error) {
		return nil, fmt.Errorf("%w: Microsoft signing key %s", ErrProviderResponse, what)
	}
	if !validMicrosoftAuthority(authority) || !canonicalMicrosoftGUID.MatchString(tenantID) || tokenIssuer != microsoftTenantIssuer(tenantID) {
		return bad("issuer or tenant is invalid")
	}
	if (authority == "consumers") != (tenantID == microsoftConsumerTenant) || (canonicalMicrosoftGUID.MatchString(authority) && tenantID != authority) {
		return bad("tenant is outside the authority policy")
	}
	if kid == "" || len(kid) > 1024 || strings.IndexFunc(kid, unicode.IsControl) >= 0 {
		return bad("kid is missing or invalid")
	}
	allowed := microsoftJWKSMatches(jwksURL, authority)
	if ps.microsoftFix != nil {
		allowed = jwksURL == ps.microsoftJWKSURL("/common/discovery/v2.0/keys") || jwksURL == ps.microsoftJWKSURL("/"+authority+"/discovery/v2.0/keys")
	}
	if !allowed || ps.policy.CheckEndpoint(jwksURL) != nil {
		return bad("JWKS endpoint refused")
	}
	ck := cache.with("microsoft-jwks", authority, jwksURL)
	selected, err := ps.keys.selectKey(ctx, ck, jwksURL, func(set *keySet) (*cachedSigningKey, error) {
		return pickKey(set.keys, kid, func(key *cachedSigningKey) bool {
			var issuer string
			return json.Unmarshal(key.issuer, &issuer) == nil && (issuer == tokenIssuer || issuer == microsoftIssuerTemplate)
		})
	})
	if err != nil {
		return nil, err
	}
	var issuer string
	_ = json.Unmarshal(selected.issuer, &issuer) // selector required a valid string
	return &microsoftSigningKey{Key: selected.Key, Issuer: issuer}, nil
}
