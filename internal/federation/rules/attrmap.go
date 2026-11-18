package rules

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// RestrictedTargets includes reserved claims and server-owned user fields.
// The same set governs write validation and bind_all filtering.
var RestrictedTargets = []string{
	"ath", "attest", "client_id", "dest", "entitlements", "events", "groups", "sub_jwk", "acr", "act", "active", "amr", "at_hash", "aud", "auth_time", "authorization_details", "azp", "c_hash", "cnf", "cty", "exp", "gty", "htm", "htu", "iat", "internalService", "iss", "jcard", "jku", "jti", "jwe", "jwk", "kid", "may_act", "mky", "nbf", "nonce", "object_id", "org_id", "org_name", "orig", "origid", "permissions", "roles", "rph", "s_hash", "sid", "sip_callid", "sip_cseq_num", "sip_date", "sip_from_tag", "sip_via_branch", "sub", "toe", "txn", "typ", "uuid", "vot", "vtm", "x5t#S256",
	"user_id", "identities", "app_metadata", "user_metadata", "blocked", "logins_count", "last_login", "last_ip", "created_at", "updated_at", "email_verified_at", "password", "password_hash", "password_set_date", "tenant_id", "connection", "connection_id", "provider", "isSocial", "multifactor", "guardian_authenticators", "enrollments", "access_token", "refresh_token", "id_token", "client_secret", "private_key",
}

func RestrictedTarget(k string) bool {
	return slices.Contains(RestrictedTargets, k) || strings.HasPrefix(k, "_") || strings.HasPrefix(k, "zeroauthy")
}

type MapPart struct{ Literal, Source, Claim string }

func ParseTemplate(template string) ([]MapPart, error) {
	if len(template) > 1024 || !utf8.ValidString(template) || strings.ContainsRune(template, 0) {
		return nil, fmt.Errorf("attribute template exceeds text limits")
	}
	var parts []MapPart
	for len(template) > 0 {
		i := strings.Index(template, "${")
		if i < 0 {
			parts = append(parts, MapPart{Literal: template})
			break
		}
		if i > 0 {
			parts = append(parts, MapPart{Literal: template[:i]})
		}
		template = template[i+2:]
		j := strings.IndexByte(template, '}')
		if j < 0 {
			return nil, fmt.Errorf("unterminated attribute template")
		}
		path := template[:j]
		template = template[j+1:]
		p := MapPart{}
		for _, prefix := range []string{"context.tokenset.", "context.userinfo.", "context.connection."} {
			if strings.HasPrefix(path, prefix) {
				p.Source = strings.TrimSuffix(strings.TrimPrefix(prefix, "context."), ".")
				p.Claim = strings.TrimPrefix(path, prefix)
				break
			}
		}
		if p.Source == "" || p.Claim == "" {
			return nil, fmt.Errorf("unsupported attribute template reference")
		}
		if p.Source == "connection" && p.Claim != "id" && p.Claim != "strategy" {
			return nil, fmt.Errorf("unsupported connection attribute")
		}
		for _, c := range p.Claim {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_-:./", c)) {
				return nil, fmt.Errorf("invalid attribute claim name")
			}
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		parts = []MapPart{{Literal: ""}}
	}
	return parts, nil
}
func ValidateAttrMap(m *AttrMap, strategy, channel string) error {
	if m == nil {
		return nil
	}
	if len(m.Attributes) > 100 {
		return fmt.Errorf("attribute map permits at most 100 attributes")
	}
	if m.Mode != "use_map" && m.Mode != "bind_all" && !(m.Mode == "basic_profile" && strategy == Okta) {
		return fmt.Errorf("unsupported attribute mapping mode")
	}
	if m.Mode == "bind_all" && strategy != OIDC {
		return fmt.Errorf("bind_all requires oidc")
	}
	if len(m.UserinfoScope) > maxScopeBytes || !cleanText(m.UserinfoScope) {
		return fmt.Errorf("attribute userinfo_scope exceeds limits")
	}
	if channel == "front_channel" && m.UserinfoScope != "" {
		return fmt.Errorf("userinfo requires back_channel")
	}
	for k, v := range m.Attributes {
		if RestrictedTarget(k) || k == "" || len(k) > 256 || !cleanText(k) {
			return fmt.Errorf("restricted attribute map target")
		}
		parts, err := ParseTemplate(v)
		if err != nil {
			return err
		}
		for _, p := range parts {
			if p.Source == "userinfo" && channel == "front_channel" {
				return fmt.Errorf("userinfo requires back_channel")
			}
		}
	}
	return nil
}
