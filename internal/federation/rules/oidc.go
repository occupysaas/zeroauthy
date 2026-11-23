package rules

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

const Okta = "okta"

var AssertionAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "ES256", "ES384"}
var IDTokenAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
var EncryptionAlgorithms = []string{"RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"}
var ContentAlgorithms = []string{"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"}

type ExplicitEndpoints struct {
	Issuer, Authorization, Token, JWKS, UserInfo string
	Metadata                                     map[string]any
}
type AttrMap struct {
	Mode          string
	Attributes    map[string]string
	UserinfoScope string
}

func IsEnterprise(strategy string) bool {
	return strategy == OIDC || strategy == Okta || strategy == WAAD || strategy == SAMLP || strategy == ADFS || strategy == AD
}
func enterpriseOption(k string) bool {
	return slices.Contains([]string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "oidc_metadata", "token_endpoint_auth_method", "token_endpoint_auth_signing_alg", "domain_aliases", "attribute_map", "tenant_domain", "domain"}, k)
}

func parseOIDC(o map[string]any, out *Settings) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	text := func(k, def string) string {
		v, ok := o[k]
		if !ok || v == nil {
			return def
		}
		s, ok := v.(string)
		if !ok || !cleanText(s) {
			fail("options.%s must be a string", k)
		}
		return s
	}
	boolean := func(k string, def bool) bool {
		v, ok := o[k]
		if !ok {
			return def
		}
		b, ok := v.(bool)
		if !ok {
			fail("options.%s must be a boolean", k)
		}
		return b
	}
	enum := func(k, def string, allowed []string) string {
		s := text(k, def)
		if s != "" && !slices.Contains(allowed, s) {
			fail("options.%s has an unsupported value", k)
		}
		return s
	}
	out.Channel = enum("type", "front_channel", []string{"front_channel", "back_channel"})
	if out.Strategy == Okta {
		if _, ok := o["type"]; !ok {
			out.Channel = "back_channel"
		}
		if out.Channel != "back_channel" {
			fail("options.type must be back_channel for okta")
		}
		if _, ok := o["discovery_url"]; ok {
			fail("options.discovery_url is not supported for okta")
		}
		d := strings.ToLower(text("domain", ""))
		if !validDNS(d) {
			fail("options.domain must be a DNS host name without a scheme, path or port")
		}
		out.OktaDomain = d
		out.DiscoveryURL = "https://" + d + "/.well-known/openid-configuration"
	} else if v, ok := o["discovery_url"]; ok {
		if v != nil {
			out.DiscoveryURL = endpoint(o, "discovery_url", false, fail)
		}
	}
	scopeKey := "scope"
	if _, ok := o[scopeKey]; !ok {
		scopeKey = "scopes"
	}
	scope := text(scopeKey, "")
	out.Scopes = scopeList(scope, "options."+scopeKey, fail)
	if !slices.Contains(out.Scopes, "openid") {
		fail("options.%s must contain openid", scopeKey)
	}
	if a, ok := o["scope"]; ok {
		if b, named := o["scopes"]; named {
			as, aok := a.(string)
			bs, bok := b.(string)
			if !aok || !bok || as != bs {
				fail("options.scope and options.scopes conflict")
			}
		}
	}
	out.TokenAuth = enum("token_endpoint_auth_method", "", []string{"client_secret_post", "private_key_jwt"})
	out.AssertionAlg = enum("token_endpoint_auth_signing_alg", "RS256", AssertionAlgorithms)
	out.AssertionAud = enum("token_endpoint_jwtca_aud_format", "issuer", []string{"issuer", "token_endpoint"})
	out.SendNonce = boolean("send_back_channel_nonce", true)
	if out.Channel == "front_channel" {
		if _, ok := o["client_secret"]; ok {
			fail("options.client_secret is not used by front_channel")
		}
		if out.TokenAuth != "" {
			fail("options.token_endpoint_auth_method requires back_channel")
		}
	}
	out.PKCE = "auto"
	if v, ok := o["connection_settings"]; ok {
		cs, ok := v.(map[string]any)
		if !ok {
			fail("options.connection_settings must be an object")
		} else if v, ok := cs["pkce"]; ok {
			p, ok := v.(string)
			if !ok || !slices.Contains([]string{"auto", "s256", "plain", "disabled"}, strings.ToLower(p)) {
				fail("options.connection_settings.pkce is unsupported")
			}
			out.PKCE = p
		}
	}
	list := func(k string, allowed []string) []string {
		v, ok := o[k]
		if !ok || v == nil {
			return nil
		}
		var a []string
		switch v := v.(type) {
		case []string:
			a = slices.Clone(v)
		case []any:
			for _, x := range v {
				s, ok := x.(string)
				if !ok {
					fail("options.%s must contain strings", k)
				}
				a = append(a, s)
			}
		default:
			fail("options.%s must be an array", k)
		}
		if len(a) > 100 {
			fail("options.%s has too many entries", k)
		}
		for _, s := range a {
			if !slices.Contains(allowed, s) {
				fail("options.%s has an unsupported algorithm", k)
			}
		}
		return a
	}
	out.IDTokenAlgs = list("id_token_signed_response_algs", IDTokenAlgorithms)
	if o["id_token_signed_response_algs"] != nil && len(out.IDTokenAlgs) == 0 {
		fail("options.id_token_signed_response_algs must not be empty")
	}
	out.EncAlg = enum("id_token_encrypted_response_alg", "", EncryptionAlgorithms)
	out.EncEncs = list("id_token_encrypted_response_encs", ContentAlgorithms)
	if v := o["dpop_signing_alg"]; v != nil {
		fail("options.dpop_signing_alg is not supported")
	}
	out.PAR = boolean("enable_pushed_authorization_requests", false)
	if out.PAR && out.Channel != "back_channel" {
		fail("upstream PAR requires back_channel")
	}
	if _, ok := o["pushed_authorization_request_endpoint"]; ok {
		out.PAREndpoint = endpoint(o, "pushed_authorization_request_endpoint", false, fail)
	}
	var metadata map[string]any
	if v, ok := o["oidc_metadata"]; ok && v != nil {
		var valid bool
		metadata, valid = v.(map[string]any)
		b, e := json.Marshal(v)
		if !valid || e != nil || len(b) > 128*1024 {
			fail("options.oidc_metadata must be an object at most 128 KiB")
		}
	}
	explicit := &ExplicitEndpoints{Metadata: maps.Clone(metadata)}
	required := out.DiscoveryURL == "" && len(metadata) == 0
	for _, entry := range []struct {
		k                  string
		target             *string
		req, authorization bool
	}{{"issuer", &explicit.Issuer, required, false}, {"authorization_endpoint", &explicit.Authorization, required, true}, {"token_endpoint", &explicit.Token, required && out.Channel == "back_channel", false}, {"jwks_uri", &explicit.JWKS, required, false}, {"userinfo_endpoint", &explicit.UserInfo, false, false}} {
		if _, ok := o[entry.k]; ok || entry.req {
			*entry.target = endpoint(o, entry.k, entry.authorization, fail)
		}
	}
	if required || explicit.Issuer != "" || explicit.Authorization != "" || explicit.Token != "" || explicit.JWKS != "" || explicit.UserInfo != "" || len(metadata) > 0 {
		out.Explicit = explicit
	}
	if len(metadata) > 0 {
		for _, k := range []string{"issuer", "authorization_endpoint", "jwks_uri"} {
			s, ok := metadata[k].(string)
			if !ok || ValidateEndpoint(s, k == "authorization_endpoint") != nil {
				fail("options.oidc_metadata.%s is required and must be HTTPS", k)
			}
		}
		for _, k := range []string{"token_endpoint", "userinfo_endpoint", "pushed_authorization_request_endpoint"} {
			if v, ok := metadata[k]; ok {
				s, ok := v.(string)
				if !ok || ValidateEndpoint(s, false) != nil {
					fail("options.oidc_metadata.%s must be HTTPS", k)
				}
			} else if k == "token_endpoint" && out.Channel == "back_channel" {
				fail("options.oidc_metadata.token_endpoint is required")
			}
		}
	}
	if v, ok := o["attribute_map"]; ok {
		m, ok := v.(map[string]any)
		if !ok {
			fail("options.attribute_map must be an object")
		} else {
			am := &AttrMap{Attributes: map[string]string{}}
			if v, present := m["mapping_mode"]; present {
				var valid bool
				am.Mode, valid = v.(string)
				if !valid || am.Mode == "" {
					fail("options.attribute_map.mapping_mode must be a nonempty string")
				}
			}
			if v, present := m["userinfo_scope"]; present {
				var valid bool
				am.UserinfoScope, valid = v.(string)
				if !valid {
					fail("options.attribute_map.userinfo_scope must be a string")
				}
			}
			if am.Mode == "" {
				if out.Strategy == Okta {
					am.Mode = "basic_profile"
				} else {
					am.Mode = "bind_all"
				}
			}
			if !slices.Contains([]string{"bind_all", "use_map", "basic_profile"}, am.Mode) || (am.Mode == "bind_all" && out.Strategy == Okta) || (am.Mode == "basic_profile" && out.Strategy != Okta) {
				fail("options.attribute_map.mapping_mode is unsupported")
			}
			if v, ok := m["attributes"]; ok {
				a, ok := v.(map[string]any)
				if !ok {
					fail("options.attribute_map.attributes must be an object")
				} else {
					for k, v := range a {
						s, ok := v.(string)
						if !ok || len(s) > 1024 {
							fail("attribute map templates must be strings at most 1024 bytes")
						}
						am.Attributes[k] = s
					}
				}
			}
			if len(am.Attributes) > 100 {
				fail("attribute map permits at most 100 attributes")
			}
			out.AttrMap = am
		}
	}
	if err := ValidateAttrMap(out.AttrMap, out.Strategy, out.Channel); err != nil {
		errs = append(errs, err)
	}
	return errs
}
