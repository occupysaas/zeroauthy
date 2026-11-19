package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// ResolveEnterpriseMetadata uses supplied metadata before explicit URLs or
// discovery. All resulting endpoints pass the same operator network policy.
func (ps *Providers) ResolveEnterpriseMetadata(ctx context.Context, key CacheKey, cfg Config) (Metadata, error) {
	var raw map[string]any
	cache := key.with("enterprise-discovery", cfg.DiscoveryURL, cfg.Issuer, cfg.Channel, cfg.PKCE, cfg.TokenAuth)
	if cfg.Explicit != nil && len(cfg.Explicit.Metadata) > 0 {
		raw = cfg.Explicit.Metadata
	} else if cfg.Explicit != nil && (cfg.DiscoveryURL == "" || cfg.Strategy == StrategyOkta && cfg.Explicit.Authorization != "" && cfg.Explicit.JWKS != "") {
		e := cfg.Explicit
		raw = map[string]any{"issuer": e.Issuer, "authorization_endpoint": e.Authorization, "token_endpoint": e.Token, "jwks_uri": e.JWKS, "userinfo_endpoint": e.UserInfo}
	} else {
		if m, ok := ps.discovery.get(cache); ok {
			return m, nil
		}
		if e := ps.getJSONLimit(ctx, cfg.DiscoveryURL, "", &raw, 128*1024); e != nil {
			return Metadata{}, e
		}
	}
	b, e := json.Marshal(raw)
	if e != nil || len(b) > 128*1024 {
		return Metadata{}, fmt.Errorf("%w: discovery exceeds metadata limit", ErrProviderResponse)
	}
	str := func(k string) string { s, _ := raw[k].(string); return s }
	m := Metadata{Issuer: str("issuer"), AuthorizationEndpoint: str("authorization_endpoint"), TokenEndpoint: str("token_endpoint"), JWKSURI: str("jwks_uri"), UserInfoEndpoint: str("userinfo_endpoint"), PAREndpoint: str("pushed_authorization_request_endpoint")}
	if cfg.PAREndpoint != "" {
		m.PAREndpoint = cfg.PAREndpoint
	}
	for _, url := range []string{m.Issuer, m.AuthorizationEndpoint, m.JWKSURI} {
		if url == "" || ps.policy.CheckEndpoint(url) != nil {
			return Metadata{}, fmt.Errorf("%w: missing or refused enterprise endpoint", ErrProviderResponse)
		}
	}
	if cfg.Channel != "front_channel" && m.TokenEndpoint == "" {
		return Metadata{}, fmt.Errorf("%w: token endpoint missing", ErrProviderResponse)
	}
	for _, url := range []string{m.TokenEndpoint, m.UserInfoEndpoint, m.PAREndpoint} {
		if url != "" && ps.policy.CheckEndpoint(url) != nil {
			return Metadata{}, fmt.Errorf("%w: enterprise endpoint refused", ErrProviderResponse)
		}
	}
	if cfg.Issuer != "" && m.Issuer != cfg.Issuer {
		return Metadata{}, idTokenError("issuer mismatch")
	}
	if cfg.Channel != "front_channel" {
		methods, _ := stringSlice(raw["token_endpoint_auth_methods_supported"])
		m.TokenAuthMethod = cfg.TokenAuth
		if m.TokenAuthMethod == "" {
			switch {
			case len(methods) == 0 || slices.Contains(methods, authBasic):
				m.TokenAuthMethod = authBasic
			case slices.Contains(methods, authPost):
				m.TokenAuthMethod = authPost
			default:
				return Metadata{}, fmt.Errorf("%w: unusable client authentication", ErrProviderResponse)
			}
		}
	}
	if cfg.Channel == "front_channel" {
		m.ResponseType = "id_token"
	} else {
		m.ResponseType = "code"
		switch strings.ToLower(cfg.PKCE) {
		case "s256":
			m.PKCEMethod = "S256"
		case "plain":
			m.PKCEMethod = "plain"
		case "disabled":
		case "auto", "":
			methods, _ := stringSlice(raw["code_challenge_methods_supported"])
			if slices.Contains(methods, "S256") {
				m.PKCEMethod = "S256"
			} else if slices.Contains(methods, "plain") {
				m.PKCEMethod = "plain"
			}
		}
	}
	if cfg.PAR && m.PAREndpoint == "" {
		return Metadata{}, fmt.Errorf("%w: PAR endpoint missing", ErrProviderResponse)
	}
	if cfg.Explicit == nil {
		ps.discovery.put(cache, m)
	}
	return m, nil
}
