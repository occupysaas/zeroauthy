package rules

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/federation/providers"
)

// SocialSettings are the descriptor strategy settings beyond the scope
// (Plan 39b, D-0180).
type SocialSettings struct {
	// Separator joins the scope sent upstream.
	Separator string
	// StrategyVersion is LinkedIn's strategy_version (default 3).
	StrategyVersion int
	// Protocol is Twitter's protocol: oauth2 (default) or oauth1.
	Protocol string
	// CommunityBaseURL is salesforce-community's base URL.
	CommunityBaseURL string
	// BaseURL is the chosen regional base URL (Exact, LR39d-2).
	BaseURL string
	// FreeScope reports that the operator's scope is requested (LR39d-1).
	FreeScope bool
}

const (
	maxFreeformScopes = 20
	maxFreeformBytes  = 128
)

var freeformScopeRE = regexp.MustCompile(`^[\x21-\x2b\x2d-\x7e]{1,128}$`) // printable, no space or comma

// socialRejected are endpoint and script options no descriptor strategy
// accepts: its endpoints are fixed (LR39b-2).
var socialRejected = []string{"authorizationURL", "tokenURL", "profileURL", "userInfoURL", "userinfoURL",
	"api_host", "scripts", "requestTokenURL", "accessTokenURL", "userAuthorizationURL"}

// Twitter is the twitter strategy (protocol oauth2 or oauth1).
const Twitter = "twitter"

// Twitter's OAuth 1.0a endpoints (protocol oauth1, LR39b-10).
const (
	TwitterRequestTokenURL   = "https://api.x.com/oauth/request_token"
	TwitterAuthenticateURL   = "https://api.x.com/oauth/authenticate"
	TwitterAccessTokenURL    = "https://api.x.com/oauth/access_token"
	TwitterVerifyCredentials = "https://api.x.com/1.1/account/verify_credentials.json?include_email=true&skip_status=true"
)

// IsDescriptorSocial reports whether strategy runs on a Plan 39b descriptor.
func IsDescriptorSocial(strategy string) bool { return providers.Is(strategy) }

func parseSocial(strategy string, o, connectedAccounts map[string]any, out *Settings) []error {
	d, _ := providers.Get(strategy)
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	for _, k := range socialRejected {
		if _, ok := o[k]; ok {
			fail("options.%s is not supported on %s connections", k, strategy)
		}
	}
	if v, ok := connectedAccounts["active"]; ok && v != nil && v != false {
		fail("connected_accounts.active is not supported on %s connections", strategy)
	}
	enabled := func(option string, def bool) bool {
		v, ok := o[option]
		if !ok || v == nil {
			return def
		}
		b, isBool := v.(bool)
		if !isBool {
			fail("options.%s must be a boolean", option)
			return def
		}
		return b
	}
	for _, k := range d.StoredOnly {
		if v, ok := o[k]; ok && v != nil {
			if _, isBool := v.(bool); !isBool {
				fail("options.%s must be a boolean", k)
			}
		}
	}
	var extra []string
	if v, ok := o["freeform_scopes"]; ok && v != nil {
		list, isList := v.([]any)
		switch {
		case !isList:
			fail("options.freeform_scopes must be an array of strings")
		case !d.FreeformScopes && len(list) > 0:
			fail("options.freeform_scopes: freeform scopes are not supported on %s connections", strategy)
		case len(list) > maxFreeformScopes:
			fail("options.freeform_scopes has more than %d entries", maxFreeformScopes)
		default:
			for _, e := range list {
				s, isStr := e.(string)
				if !isStr || !freeformScopeRE.MatchString(s) {
					fail("options.freeform_scopes entries must be 1 to %d printable characters without spaces or commas", maxFreeformBytes)
					extra = nil
					break
				}
				extra = append(extra, s)
			}
		}
	}
	social := &SocialSettings{Separator: d.Separator()}
	errs = append(errs, parseSocialHook(d, o, social)...)
	scopes := d.EffectiveScopes(enabled, extra)
	if social.Protocol == "oauth1" || d.Protocol == providers.ProtocolOAuth1 {
		scopes = []string{} // OAuth 1.0a has no scope
	}
	if d.FreeScope {
		social.FreeScope = true
		if v, ok := o["scope"]; ok && v != nil {
			got, valid := scopeInput(v)
			if !valid || len(got) > maxFreeformScopes {
				fail("options.scope must be at most %d scopes", maxFreeformScopes)
			}
			for _, sc := range got {
				if !freeformScopeRE.MatchString(sc) {
					fail("options.scope entries must be 1 to %d printable characters without spaces or commas", maxFreeformBytes)
					break
				}
			}
			if valid && len(got) > 0 {
				scopes = got
			}
		}
	} else if v, ok := o["scope"]; ok && v != nil {
		got, valid := scopeInput(v)
		if !valid {
			fail("options.scope must be an array of strings or a scope string")
		} else if !sameSet(got, scopes) {
			fail("options.scope must match the scope flags (%s)", strings.Join(scopes, " "))
		}
	}
	out.Scopes = scopes
	out.Social = social
	out.AuthorizationURL, out.TokenURL = d.AuthorizationURL, d.TokenURL
	if social.Protocol == "oauth1" {
		out.OAuth1 = &OAuth1Settings{RequestTokenURL: TwitterRequestTokenURL, AccessTokenURL: TwitterAccessTokenURL,
			UserAuthorizationURL: TwitterAuthenticateURL, SignatureMethod: "HMAC-SHA1"}
		out.AuthorizationURL, out.TokenURL = TwitterAuthenticateURL, TwitterAccessTokenURL
	}
	if len(d.BaseURLHosts) > 0 {
		base, ok := baseURLOption(o["baseUrl"], d.BaseURLHosts)
		if !ok {
			fail("options.baseUrl must be https://<host> for one of %s", strings.Join(d.BaseURLHosts, ", "))
		} else {
			social.BaseURL = base
			out.AuthorizationURL = strings.Replace(d.AuthorizationURL, providers.BaseURLPlaceholder, base, 1)
			out.TokenURL = strings.Replace(d.TokenURL, providers.BaseURLPlaceholder, base, 1)
		}
	}
	if o1 := d.OAuth1; o1 != nil {
		out.OAuth1 = &OAuth1Settings{RequestTokenURL: o1.RequestTokenURL, AccessTokenURL: o1.AccessTokenURL, UserAuthorizationURL: o1.AuthorizationURL,
			SignatureMethod: "HMAC-SHA1", EmptySecret: o1.EmptySecret}
		out.AuthorizationURL, out.TokenURL = o1.AuthorizationURL, o1.AccessTokenURL
	}
	if social.CommunityBaseURL != "" {
		out.AuthorizationURL = strings.Replace(d.AuthorizationURL, providers.CommunityPlaceholder, social.CommunityBaseURL, 1)
		out.TokenURL = strings.Replace(d.TokenURL, providers.CommunityPlaceholder, social.CommunityBaseURL, 1)
	}
	return errs
}

// scopeInput accepts an array of strings or a space- or comma-separated
// string (Facebook's scope is a comma-separated string).
func scopeInput(v any) ([]string, bool) {
	switch t := v.(type) {
	case string:
		return strings.FieldsFunc(t, func(r rune) bool { return r == ' ' || r == ',' }), true
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// parseSocialHook validates the options a hook adds.
func parseSocialHook(d *providers.Descriptor, o map[string]any, s *SocialSettings) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	switch d.Hook {
	case providers.HookSalesforce:
		v, named := o["community_base_url"]
		if d.Strategy != "salesforce-community" {
			break // stored only
		}
		raw, isStr := v.(string)
		if !named || !isStr || raw == "" {
			fail("options.community_base_url is required for salesforce-community")
			break
		}
		u, err := url.Parse(raw)
		if verr := ValidateEndpoint(raw, false); verr != nil || err != nil || u.RawQuery != "" || strings.Contains(raw, "?") {
			fail("options.community_base_url must be an https URL of a public host without query, fragment or credentials")
			break
		}
		s.CommunityBaseURL = strings.TrimSuffix(raw, "/")
	case providers.HookTwitter:
		s.Protocol = "oauth2"
		if v, ok := o["protocol"]; ok && v != nil {
			if v != "oauth1" && v != "oauth2" {
				fail("options.protocol must be oauth1 or oauth2")
			} else {
				s.Protocol = v.(string)
			}
		}
	case providers.HookLinkedIn:
		s.StrategyVersion = 3
		if v, ok := o["strategy_version"]; ok && v != nil {
			n, isInt := intOption(v)
			if !isInt || n < 1 || n > 3 {
				fail("options.strategy_version must be 1, 2 or 3")
			} else {
				s.StrategyVersion = n
			}
		}
	}
	return errs
}

// intOption reads an integer option sent as a JSON number.
func intOption(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n == math.Trunc(n) && math.Abs(n) < 1<<31 {
			return int(n), true
		}
	case json.Number:
		i, err := n.Int64()
		if err == nil && i > -(1<<31) && i < 1<<31 {
			return int(i), true
		}
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}

// baseURLOption accepts exactly "https://<host>" (an optional trailing slash)
// for a host in hosts.
func baseURLOption(v any, hosts []string) (string, bool) {
	raw, ok := v.(string)
	if !ok {
		return "", false
	}
	raw = strings.TrimSuffix(raw, "/")
	host, ok := strings.CutPrefix(raw, "https://")
	if !ok || !slices.Contains(hosts, host) {
		return "", false
	}
	return raw, true
}
