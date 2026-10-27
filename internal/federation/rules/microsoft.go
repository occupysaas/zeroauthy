package rules

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

var microsoftGUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var microsoftDNSLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// MicrosoftAuthority validates the local public-cloud authority policy without network access.
func MicrosoftAuthority(strategy string, options map[string]any) (string, bool, error) {
	if strategy == WindowsLive {
		return "consumers", false, nil
	}
	if strategy != WAAD {
		return "", false, fmt.Errorf("not a Microsoft strategy")
	}
	multi := false
	if v, ok := options["useCommonEndpoint"]; ok {
		var valid bool
		multi, valid = v.(bool)
		if !valid {
			return "", false, fmt.Errorf("options.useCommonEndpoint must be a boolean")
		}
	}
	if multi {
		if _, ok := options["tenant_domain"]; ok {
			return "", false, fmt.Errorf("options.tenant_domain conflicts with useCommonEndpoint")
		}
		return "organizations", true, nil
	}
	tenant, ok := options["tenant_domain"].(string)
	if !ok || tenant == "" || len(tenant) > 253 {
		return "", false, fmt.Errorf("options.tenant_domain must be a GUID or ASCII DNS name")
	}
	tenant = strings.ToLower(tenant)
	if tenant == "common" || tenant == "organizations" || tenant == "consumers" || tenant == "9188040d-6c67-4c5b-b112-36a304b66dad" {
		return "", false, fmt.Errorf("options.tenant_domain is reserved")
	}
	if !microsoftGUID.MatchString(tenant) {
		for _, label := range strings.Split(tenant, ".") {
			if !microsoftDNSLabel.MatchString(label) {
				return "", false, fmt.Errorf("options.tenant_domain must be a GUID or ASCII DNS name")
			}
		}
	}
	return tenant, false, nil
}

func parseMicrosoft(o map[string]any, out *Settings) []error {
	var errs []error
	fail := func(k string) {
		errs = append(errs, fmt.Errorf("options.%s is not supported by the Microsoft sign-in subset", k))
	}
	if !microsoftGUID.MatchString(out.ClientID) {
		fail("client_id")
	}
	// GUID casing does not create another upstream application binding.
	out.ClientID = strings.ToLower(out.ClientID)
	authority, multi, err := MicrosoftAuthority(out.Strategy, o)
	if err != nil {
		errs = append(errs, err)
	}
	out.MicrosoftAuthority, out.MicrosoftMultiTenant = authority, multi
	base := "https://login.microsoftonline.com/" + authority
	out.AuthorizationURL = base + "/oauth2/v2.0/authorize"
	out.TokenURL = base + "/oauth2/v2.0/token"
	out.DiscoveryURL = base + "/v2.0/.well-known/openid-configuration"
	out.Scopes = []string{"openid", "profile", "email"}
	if v, ok := o["scope"]; ok {
		list, valid := v.([]any)
		var scopes []string
		for _, e := range list {
			s, ok := e.(string)
			valid = valid && ok
			scopes = append(scopes, s)
		}
		if !valid || !sameSet(scopes, out.Scopes) {
			fail("scope")
		}
	}
	if out.Strategy == WindowsLive {
		if v, ok := o["strategy_version"]; ok {
			valid := false
			switch n := v.(type) {
			case float64:
				valid = n == 2
			case int:
				valid = n == 2
			case json.Number:
				valid = n == "2"
			}
			if !valid {
				fail("strategy_version")
			}
		}
		for _, k := range []string{"identity_api", "waad_protocol", "userid_attribute", "useCommonEndpoint", "tenant_domain", "domain"} {
			if _, ok := o[k]; ok {
				fail(k)
			}
		}
	} else {
		for k, want := range map[string]string{"identity_api": "microsoft-identity-platform-v2.0", "waad_protocol": "openid-connect", "userid_attribute": "oid"} {
			if v, ok := o[k]; ok && v != want {
				fail(k)
			}
		}
		if _, ok := o["strategy_version"]; ok {
			fail("strategy_version")
		}
		if v, ok := o["domain"]; ok {
			s, valid := v.(string)
			if !valid || len(s) > 253 || !cleanText(s) {
				fail("domain")
			}
		}
	}
	for _, k := range []string{"ext_groups", "ext_profile", "ext_nested_groups", "ext_group_memberships", "api_enable_users", "api_enable_groups", "api_enable_contacts", "basic_profile", "use_wsfed"} {
		if v, ok := o[k]; ok && v != false {
			fail(k)
		}
	}
	for _, k := range microsoftRejected {
		if _, ok := o[k]; ok {
			fail(k)
		}
	}
	for _, m := range inertMaps {
		if v, ok := o[m]; ok {
			if key := microsoftReservedReference(v); key != "" {
				fail(m + "." + key)
			}
		}
	}
	return errs
}

// These are wire option names, not the inventory's value-case row names.
var microsoftRejected = []string{
	"discovery_url", "authorizationURL", "tokenURL", "offline_access",
	"trust_email_verified", "email_verified", "should_trust_email_verified_connection",
	"scripts", "scripts.fetchUserProfile", "graph_api", "scopes", "pkce_disabled",
	"connection_settings", "tenant_discovery_endpoint", "jwks", "client_auth_method",
	"certificate", "client_assertion", "development_keys", "connected_accounts",
	"token_vault", "domain_restriction", "max_groups_to_retrieve", "resource", "audience",
	"response_type", "response_mode", "nonce", "state", "redirect_uri", "code_challenge",
	"login_hint", "prompt", "claims", "acr_values", "max_age",
}

func microsoftReservedReference(v any) string {
	switch x := v.(type) {
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(x)) {
			e := x[k]
			if microsoftReserved(k) {
				return k
			}
			if r := microsoftReservedReference(e); r != "" {
				return r
			}
		}
	case []any:
		for _, e := range x {
			if r := microsoftReservedReference(e); r != "" {
				return r
			}
		}
	case string:
		if microsoftReserved(strings.TrimSpace(x)) {
			return x
		}
	}
	return ""
}
func microsoftReserved(k string) bool {
	for r := range rejectedOptions {
		if strings.EqualFold(k, r) {
			return true
		}
	}
	for _, r := range append(append([]string{}, microsoftRejected...), "tenant_domain", "useCommonEndpoint", "userid_attribute", "identity_api", "waad_protocol", "strategy_version", "email_verified", "domain_aliases", "ext_groups", "ext_profile", "ext_nested_groups", "ext_group_memberships", "api_enable_users", "api_enable_groups", "api_enable_contacts", "basic_profile", "use_wsfed") {
		if strings.EqualFold(k, r) {
			return true
		}
	}
	return isRejectedKey(k)
}
