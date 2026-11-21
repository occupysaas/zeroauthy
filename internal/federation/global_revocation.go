package federation

import (
	"context"
	"errors"
	"strings"
	"time"
)

var ErrGlobalRevocationToken = errors.New("federation: invalid global revocation authentication")

type GlobalRevocationAuthentication struct {
	JTI       string
	ExpiresAt time.Time
}

// VerifyGlobalRevocation uses only the selected connection's pinned issuer and
// JWKS. Neither token headers nor subject identifiers choose a key source.
func (ps *Providers) VerifyGlobalRevocation(ctx context.Context, cache CacheKey, cfg Config, raw, audience string, now time.Time) (GlobalRevocationAuthentication, error) {
	bad := GlobalRevocationAuthentication{}
	if ps == nil || len(raw) > 16*1024 || strings.Count(raw, ".") != 2 || cfg.Issuer == "" || cfg.ClientID == "" || (cfg.Strategy != StrategyOIDC && cfg.Strategy != StrategyOkta) {
		return bad, ErrGlobalRevocationToken
	}
	obj, err := parseIDTokenAlgorithms(raw, cfg.IDTokenAlgs)
	if err != nil || obj.Signatures[0].Protected.ExtraHeaders["typ"] != "global-token-revocation+jwt" {
		return bad, ErrGlobalRevocationToken
	}
	metadata, err := ps.ResolveEnterpriseMetadata(ctx, cache, cfg)
	if err != nil || metadata.Issuer != cfg.Issuer {
		return bad, ErrGlobalRevocationToken
	}
	key, err := ps.keys.keyForAlgorithm(ctx, cache.with("global-revocation-jwks", cfg.Issuer, metadata.JWKSURI), metadata.JWKSURI, obj.Signatures[0].Header.KeyID, obj.Signatures[0].Header.Algorithm)
	if err != nil {
		return bad, ErrGlobalRevocationToken
	}
	payload, err := obj.Verify(key)
	if err != nil {
		return bad, ErrGlobalRevocationToken
	}
	c, err := decodeIDTokenClaims(payload)
	if err != nil {
		return bad, ErrGlobalRevocationToken
	}
	iss, _ := c["iss"].(string)
	sub, _ := c["sub"].(string)
	aud, okAud := singleAudience(c["aud"])
	jti, _ := c["jti"].(string)
	exp, okExp := numericDate(c["exp"])
	iat, okIat := numericDate(c["iat"])
	// Expiry is strict (the replay table keeps each jti until exp); only
	// the upstream clock running ahead is tolerated.
	if iss != cfg.Issuer || sub != cfg.ClientID || !okAud || aud != audience || jti == "" || len(jti) > 256 || !okExp || !okIat || !exp.After(now) || exp.After(now.Add(5*time.Minute+GlobalRevocationClockSkew)) || iat.After(now.Add(GlobalRevocationClockSkew)) || !exp.After(iat) || exp.Sub(iat) > 5*time.Minute {
		return bad, ErrGlobalRevocationToken
	}
	if value, exists := c["nbf"]; exists {
		nbf, ok := numericDate(value)
		if !ok || nbf.After(now.Add(GlobalRevocationClockSkew)) {
			return bad, ErrGlobalRevocationToken
		}
	}
	return GlobalRevocationAuthentication{JTI: jti, ExpiresAt: exp}, nil
}

// GlobalRevocationClockSkew is how far ahead of this server an upstream
// issuer's clock may run (iat, nbf and the lifetime ceiling).
const GlobalRevocationClockSkew = 60 * time.Second

// singleAudience accepts aud as a string or as an array holding exactly one
// string (RFC 7519 §4.1.3 allows both). An array naming more audiences is
// refused: such a token would also be accepted by another recipient.
func singleAudience(v any) (string, bool) {
	switch aud := v.(type) {
	case string:
		return aud, aud != ""
	case []any:
		if len(aud) != 1 {
			return "", false
		}
		s, ok := aud[0].(string)
		return s, ok && s != ""
	}
	return "", false
}
