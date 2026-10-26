// Package rules validates the options of the federated connection strategies
// (google-oauth2, oauth2 and back-channel oidc) against the frozen Plan 24
// inventory (internal/federation/inventory.json). It is a leaf package so that
// connrules, which dispatches every strategy, and federation, which consumes
// connrules.Spec, can share one validation authority without an import cycle.
//
// Parse never returns a plaintext client secret: callers that seal a secret
// read it with ClientSecret.
package rules

import (
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"
)

// The federated strategies.
const (
	Google = "google-oauth2"
	OAuth2 = "oauth2"
	OIDC   = "oidc"
)

// Profile synchronization policies (options.set_user_root_attributes).
const (
	SyncOnEachLogin  = "on_each_login"
	SyncOnFirstLogin = "on_first_login"
	SyncNeverOnLogin = "never_on_login"
)

// Local limits from the inventory.
const (
	MaxScriptBytes  = 65536
	MaxSubjectBytes = 1024
	maxURLBytes     = 2048
	maxInertBytes   = 16384
	maxInertDepth   = 8
	maxScopeBytes   = 4096
	maxClientID     = 1024
	maxSecretBytes  = 4096
)

// Fixed Google endpoints and the documented issuer forms.
const (
	GoogleIssuer           = "https://accounts.google.com"
	GoogleIssuerAlias      = "accounts.google.com"
	GoogleAuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
	GoogleTokenURL         = "https://oauth2.googleapis.com/token"
	GoogleJWKSURL          = "https://www.googleapis.com/oauth2/v3/certs"
	GoogleDiscoveryURL     = "https://accounts.google.com/.well-known/openid-configuration"
)

// IsFederated reports whether strategy is one of the federated strategies.
func IsFederated(strategy string) bool {
	return strategy == Google || strategy == OAuth2 || strategy == OIDC
}

// IsSocial reports whether identities of strategy are social (isSocial).
// OIDC is an enterprise strategy.
func IsSocial(strategy string) bool { return strategy == Google || strategy == OAuth2 }

// RejectedKeys are the upstream parameter names that no inert map may target
// or alias (inventory upstream_parameter_policy.rejected_keys). Matching is
// case-insensitive.
var RejectedKeys = []string{
	"response_type", "response_mode", "client_id", "client_secret", "redirect_uri",
	"state", "nonce", "code", "code_verifier", "code_challenge", "code_challenge_method",
	"grant_type", "scope", "scopes", "token_endpoint_auth_method", "hd", "domain",
	"domain_hint", "hosted_domain", "allowed_domains", "authentication", "authorization",
	"acr_values", "max_age", "claims", "prompt",
}

// inertMaps hold stored-only upstream parameter configuration.
var inertMaps = []string{"upstream_params", "authParams", "authParamsMap"}

// rejectedOptions are options whose presence would ask for behavior this
// subset cannot provide, whatever their value.
var rejectedOptions = map[string]string{
	"customHeaders":                   "custom token request authentication is not supported",
	"fieldsMap":                       "automatic field mapping is not supported; use scripts.fetchUserProfile",
	"allowed_domains":                 "domain restrictions are not supported",
	"domain":                          "domain restrictions are not supported",
	"domain_aliases":                  "domain restrictions are not supported",
	"hosted_domain":                   "domain restrictions are not supported",
	"hd":                              "domain restrictions are not supported",
	"tenant_domain":                   "domain restrictions are not supported",
	"freeform_scopes":                 "freeform scopes are not supported",
	"connection_scope":                "connection_scope forwarding is not supported",
	"access_type":                     "access_type forwarding is not supported",
	"attribute_map":                   "claim mapping is not supported",
	"issuer":                          "issuer comes from discovery and cannot be configured",
	"authorization_endpoint":          "endpoints come from discovery and cannot be configured",
	"token_endpoint":                  "endpoints come from discovery and cannot be configured",
	"jwks_uri":                        "endpoints come from discovery and cannot be configured",
	"userinfo_endpoint":               "endpoints come from discovery and cannot be configured",
	"oidc_metadata":                   "metadata comes from discovery and cannot be configured",
	"token_endpoint_auth_method":      "the client authentication method is fixed",
	"token_endpoint_auth_signing_alg": "the client authentication method is fixed",
}

// googleScopeFlags are Google API permission flags beyond email/profile.
// true is rejected; false is inert and may round-trip.
var googleScopeFlags = []string{
	"adsense_management", "analytics", "blogger", "calendar", "chrome_web_store",
	"contacts", "content_api_for_shopping", "coordinate", "coordinate_readonly",
	"document_list", "gmail", "google_affiliate_network", "google_books",
	"google_cloud_storage", "google_drive", "google_drive_files", "latitude_best",
	"latitude_city", "moderator", "orkut", "picasa_web", "sites", "spreadsheets",
	"tasks", "url_shortener", "webmaster_tools", "youtube",
}

// Input is a federated connection's settings in the form connrules holds.
type Input struct {
	Strategy string
	Name     string
	// Options are the option keys connrules keeps untyped (Options.Extra).
	Options        map[string]any
	RootAttributes string
	// Authentication is the top-level purpose object; nil means not named.
	Authentication map[string]any
	// HasSealedSecret reports that a sealed client secret is already stored.
	HasSealedSecret bool
}

// Settings are the validated runtime settings. They never contain the
// plaintext client secret.
type Settings struct {
	Strategy             string
	ClientID             string
	HasPlainSecret       bool
	AuthorizationURL     string
	TokenURL             string
	DiscoveryURL         string
	Scopes               []string
	Script               string
	ProfileSync          string
	AuthenticationActive bool
}

// ClientSecret returns the plaintext options.client_secret, and whether it is
// named at all. A named non-string or empty value returns ("", true).
func ClientSecret(options map[string]any) (string, bool) {
	v, ok := options["client_secret"]
	if !ok {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

// Parse validates in and returns its settings with every problem found.
func Parse(in Input) (Settings, []error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	out := Settings{Strategy: in.Strategy, AuthenticationActive: true}
	if !IsFederated(in.Strategy) {
		fail("strategy %q is not a federated strategy", in.Strategy)
		return out, errs
	}
	if strings.Contains(in.Name, "|") {
		fail("name must not contain |")
	}
	o := in.Options
	if o == nil {
		o = map[string]any{}
	}

	if id, ok := o["client_id"].(string); !ok || strings.TrimSpace(id) == "" {
		fail("options.client_id is required")
	} else if len(id) > maxClientID || !cleanText(id) {
		fail("options.client_id is invalid")
	} else {
		out.ClientID = id
	}
	if v, named := o["client_secret"]; named {
		s, ok := v.(string)
		switch {
		case !ok || s == "":
			fail("options.client_secret must be a nonempty string")
		case len(s) > maxSecretBytes || !cleanText(s):
			fail("options.client_secret is invalid")
		default:
			out.HasPlainSecret = true
		}
	} else if !in.HasSealedSecret {
		fail("options.client_secret is required")
	}

	switch in.RootAttributes {
	case "":
		out.ProfileSync = SyncOnEachLogin
	case SyncOnEachLogin, SyncOnFirstLogin, SyncNeverOnLogin:
		out.ProfileSync = in.RootAttributes
	default:
		fail("set_user_root_attributes %q must be %s, %s or %s", in.RootAttributes, SyncOnEachLogin, SyncOnFirstLogin, SyncNeverOnLogin)
	}

	if in.Authentication != nil {
		for _, k := range slices.Sorted(maps.Keys(in.Authentication)) {
			if k != "active" {
				fail("authentication.%s is not supported; use authentication.active", k)
			}
		}
		if v, ok := in.Authentication["active"]; ok {
			b, isBool := v.(bool)
			if !isBool {
				fail("authentication.active must be a boolean")
			}
			out.AuthenticationActive = b
		}
	}

	for _, k := range slices.Sorted(maps.Keys(rejectedOptions)) {
		if _, ok := o[k]; ok {
			fail("options.%s: %s", k, rejectedOptions[k])
		}
	}
	if v, ok := o["pkce_enabled"]; ok && v != true {
		fail("options.pkce_enabled must be true; S256 PKCE is required")
	}
	if v, ok := o["icon_url"]; ok {
		if s, isStr := v.(string); !isStr || len(s) > maxURLBytes || !cleanText(s) {
			fail("options.icon_url must be a string of at most %d bytes", maxURLBytes)
		}
	}
	for _, m := range inertMaps {
		v, ok := o[m]
		if !ok {
			continue
		}
		obj, isObj := v.(map[string]any)
		if !isObj {
			fail("options.%s must be an object", m)
			continue
		}
		if size, depth := jsonSize(obj, 1); size > maxInertBytes || depth > maxInertDepth {
			fail("options.%s is larger than %d bytes or deeper than %d", m, maxInertBytes, maxInertDepth)
		}
		if key := rejectedReference(obj); key != "" {
			fail("options.%s must not name or alias the reserved parameter %q", m, key)
		}
	}

	switch in.Strategy {
	case Google:
		errs = append(errs, parseGoogle(o, &out)...)
	case OAuth2:
		errs = append(errs, parseOAuth2(o, &out)...)
	case OIDC:
		errs = append(errs, parseOIDC(o, &out)...)
	}
	return out, errs
}

func parseGoogle(o map[string]any, out *Settings) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	flag := func(k string) bool {
		v, ok := o[k]
		if !ok {
			return true
		}
		b, isBool := v.(bool)
		if !isBool {
			fail("options.%s must be a boolean", k)
			return true
		}
		return b
	}
	scopes := []string{"openid"}
	if flag("profile") {
		scopes = append(scopes, "profile")
	}
	if flag("email") {
		scopes = append(scopes, "email")
	}
	for _, k := range googleScopeFlags {
		if v, ok := o[k]; ok && v != false {
			fail("options.%s: additional Google API scopes are not supported", k)
		}
	}
	if v, ok := o["scope"]; ok && v != nil {
		list, isList := v.([]any)
		if !isList {
			fail("options.scope must be an array of strings")
		} else {
			var got []string
			for _, e := range list {
				s, isStr := e.(string)
				if !isStr {
					fail("options.scope must be an array of strings")
					return errs
				}
				got = append(got, s)
			}
			if !sameSet(got, scopes) {
				fail("options.scope must match the email and profile flags (%s)", strings.Join(scopes, " "))
			}
		}
	}
	out.Scopes = scopes
	out.AuthorizationURL, out.TokenURL, out.DiscoveryURL = GoogleAuthorizationURL, GoogleTokenURL, GoogleDiscoveryURL
	return errs
}

func parseOAuth2(o map[string]any, out *Settings) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	out.AuthorizationURL = endpoint(o, "authorizationURL", true, fail)
	out.TokenURL = endpoint(o, "tokenURL", false, fail)
	switch v := o["scope"].(type) {
	case string:
		out.Scopes = scopeList(v, "options.scope", fail)
		if len(out.Scopes) == 0 {
			fail("options.scope is required")
		}
	case nil:
		fail("options.scope is required")
	default:
		fail("options.scope must be a space-delimited string")
	}
	scripts, ok := o["scripts"].(map[string]any)
	if !ok {
		fail("options.scripts.fetchUserProfile is required")
		return errs
	}
	src, ok := scripts["fetchUserProfile"].(string)
	switch {
	case !ok || strings.TrimSpace(src) == "":
		fail("options.scripts.fetchUserProfile is required")
	case len(src) > MaxScriptBytes || !utf8.ValidString(src) || strings.ContainsRune(src, 0):
		fail("options.scripts.fetchUserProfile must be valid UTF-8 of at most %d bytes", MaxScriptBytes)
	default:
		out.Script = src
	}
	for _, k := range slices.Sorted(maps.Keys(scripts)) {
		if _, isStr := scripts[k].(string); !isStr {
			fail("options.scripts.%s must be a string", k)
		}
	}
	return errs
}

func parseOIDC(o map[string]any, out *Settings) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if v, ok := o["type"]; ok && v != "back_channel" {
		fail("options.type must be back_channel; front-channel OIDC is not supported")
	}
	if _, ok := o["scope"]; ok {
		fail("options.scope is not accepted for oidc; use options.scopes")
	}
	out.DiscoveryURL = endpoint(o, "discovery_url", false, fail)
	switch v := o["scopes"].(type) {
	case string:
		out.Scopes = scopeList(v, "options.scopes", fail)
		if !slices.Contains(out.Scopes, "openid") {
			fail("options.scopes must contain openid")
		}
	case nil:
		fail("options.scopes is required")
	default:
		fail("options.scopes must be a space-delimited string")
	}
	if v, ok := o["send_back_channel_nonce"]; ok && v != true {
		fail("options.send_back_channel_nonce must be true")
	}
	if v, ok := o["connection_settings"]; ok {
		cs, isObj := v.(map[string]any)
		if !isObj {
			fail("options.connection_settings must be an object")
		} else if p, named := cs["pkce"]; named && p != "s256" && p != "auto" {
			fail("options.connection_settings.pkce must be s256 or auto")
		}
	}
	return errs
}

// endpoint validates the absolute HTTPS URL option k.
func endpoint(o map[string]any, k string, authorization bool, fail func(string, ...any)) string {
	s, ok := o[k].(string)
	if !ok || s == "" {
		fail("options.%s is required", k)
		return ""
	}
	if err := ValidateEndpoint(s, authorization); err != nil {
		fail("options.%s %v", k, err)
		return ""
	}
	return s
}

// ValidateEndpoint checks a provider endpoint URL: absolute HTTPS, a host
// that is not a literal non-public address or localhost, no credentials or
// fragment, bounded. An authorization endpoint may not preset reserved
// protocol parameters in its query.
func ValidateEndpoint(raw string, authorization bool) error {
	if len(raw) > maxURLBytes || !cleanText(raw) {
		return fmt.Errorf("must be a URL of at most %d bytes", maxURLBytes)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("must be an absolute https URL")
	}
	if u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("must not contain credentials or a fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("must name a public host")
	}
	if ip, err := netip.ParseAddr(host); err == nil && !PublicAddr(ip) {
		return fmt.Errorf("must name a public host")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("has an invalid query")
	}
	for k := range q {
		if authorization && isRejectedKey(k) {
			return fmt.Errorf("must not preset the reserved parameter %q", k)
		}
	}
	return nil
}

// PublicAddr reports whether ip is a globally routable unicast address: not
// loopback, private, link-local, multicast, unspecified, CGNAT, documentation,
// benchmarking or another reserved range (including metadata addresses).
func PublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
		"2002::/16", "3fff::/20", "5f00::/16", "fc00::/7",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func scopeList(v, field string, fail func(string, ...any)) []string {
	if len(v) > maxScopeBytes || !cleanText(v) {
		fail("%s must be at most %d bytes of text", field, maxScopeBytes)
		return nil
	}
	var out []string
	for _, s := range strings.Fields(v) {
		if strings.ContainsAny(s, `"\`) {
			fail("%s contains an invalid scope", field)
			return nil
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func isRejectedKey(k string) bool {
	for _, r := range RejectedKeys {
		if strings.EqualFold(r, k) {
			return true
		}
	}
	return false
}

// rejectedReference returns the first reserved key that v names as a key or
// as a string value (an alias), at any depth, or "".
func rejectedReference(v any) string {
	switch x := v.(type) {
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(x)) {
			if isRejectedKey(k) {
				return k
			}
			if r := rejectedReference(x[k]); r != "" {
				return r
			}
		}
	case []any:
		for _, e := range x {
			if r := rejectedReference(e); r != "" {
				return r
			}
		}
	case string:
		if isRejectedKey(strings.TrimSpace(x)) {
			return x
		}
	}
	return ""
}

// jsonSize approximates the encoded size of a JSON value and its depth.
func jsonSize(v any, depth int) (int, int) {
	switch x := v.(type) {
	case map[string]any:
		size, maxDepth := 2, depth
		for k, e := range x {
			s, d := jsonSize(e, depth+1)
			size += len(k) + 4 + s
			maxDepth = max(maxDepth, d)
		}
		return size, maxDepth
	case []any:
		size, maxDepth := 2, depth
		for _, e := range x {
			s, d := jsonSize(e, depth+1)
			size += s + 1
			maxDepth = max(maxDepth, d)
		}
		return size, maxDepth
	case string:
		return len(x) + 2, depth
	}
	return 8, depth
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// cleanText reports whether s is valid UTF-8 without NUL or other C0
// control characters.
func cleanText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
