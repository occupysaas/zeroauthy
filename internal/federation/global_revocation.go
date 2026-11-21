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
	aud, _ := c["aud"].(string)
	jti, _ := c["jti"].(string)
	exp, okExp := numericDate(c["exp"])
	iat, okIat := numericDate(c["iat"])
	if iss != cfg.Issuer || sub != cfg.ClientID || aud != audience || jti == "" || len(jti) > 256 || !okExp || !okIat || !exp.After(now) || exp.After(now.Add(5*time.Minute)) || iat.After(now) || !exp.After(iat) || exp.Sub(iat) > 5*time.Minute {
		return bad, ErrGlobalRevocationToken
	}
	if value, exists := c["nbf"]; exists {
		nbf, ok := numericDate(value)
		if !ok || nbf.After(now) {
			return bad, ErrGlobalRevocationToken
		}
	}
	return GlobalRevocationAuthentication{JTI: jti, ExpiresAt: exp}, nil
}
