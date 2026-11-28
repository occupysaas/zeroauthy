package rules

import (
	"maps"
	"reflect"
	"strings"
	"testing"
)

func socialInput(strategy string, extra map[string]any) Input {
	o := map[string]any{"client_id": "throwaway-client", "client_secret": "throwaway-secret"}
	maps.Copy(o, extra)
	return Input{Strategy: strategy, Name: strategy, Options: o}
}

func TestSocialStrategiesAreFederatedAndSocial(t *testing.T) {
	if !IsFederated("amazon") || !IsSocial("amazon") || IsEnterprise("amazon") {
		t.Fatal("amazon classification")
	}
	if IsFederated("not-a-strategy") {
		t.Fatal("unknown strategy federated")
	}
}

func TestSocialScopes(t *testing.T) {
	for _, c := range []struct {
		name string
		o    map[string]any
		want []string
	}{
		{"default", nil, []string{"profile"}},
		{"flag", map[string]any{"postal_code": true}, []string{"profile", "postal_code"}},
		{"flag off", map[string]any{"postal_code": false}, []string{"profile"}},
		{"stored only flag", map[string]any{"profile": false}, []string{"profile"}},
		{"freeform", map[string]any{"freeform_scopes": []any{"custom:read", "profile"}}, []string{"profile", "custom:read"}},
		{"scope equal", map[string]any{"postal_code": true, "scope": []any{"postal_code", "profile"}}, []string{"profile", "postal_code"}},
		{"scope string", map[string]any{"postal_code": true, "scope": "postal_code profile"}, []string{"profile", "postal_code"}},
		{"scope comma string", map[string]any{"postal_code": true, "scope": "postal_code,profile"}, []string{"profile", "postal_code"}},
		{"unknown flag stored", map[string]any{"made_up": true}, []string{"profile"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, errs := Parse(socialInput("amazon", c.o))
			if len(errs) > 0 {
				t.Fatal(errs)
			}
			if !reflect.DeepEqual(s.Scopes, c.want) {
				t.Fatalf("scopes %v, want %v", s.Scopes, c.want)
			}
			if s.AuthorizationURL != "https://www.amazon.com/ap/oa" || s.TokenURL != "https://api.amazon.com/auth/o2/token" {
				t.Fatalf("endpoints %s %s", s.AuthorizationURL, s.TokenURL)
			}
		})
	}
}

func TestSocialRejects(t *testing.T) {
	for name, o := range map[string]map[string]any{
		"flag not bool":      {"postal_code": "yes"},
		"scope mismatch":     {"scope": []any{"profile", "extra"}},
		"scope not strings":  {"scope": []any{1}},
		"freeform not list":  {"freeform_scopes": "a b"},
		"freeform space":     {"freeform_scopes": []any{"a b"}},
		"freeform comma":     {"freeform_scopes": []any{"a,b"}},
		"freeform empty":     {"freeform_scopes": []any{""}},
		"freeform too long":  {"freeform_scopes": []any{strings.Repeat("a", 129)}},
		"freeform too many":  {"freeform_scopes": manyScopes(21)},
		"authorization url":  {"authorizationURL": "https://evil.example/authorize"},
		"token url":          {"tokenURL": "https://evil.example/token"},
		"profile url":        {"profileURL": "https://evil.example/me"},
		"userinfo url":       {"userInfoURL": "https://evil.example/me"},
		"script":             {"scripts": map[string]any{"fetchUserProfile": "function(){}"}},
		"pkce off":           {"pkce_enabled": false},
		"domain restriction": {"domain": "example.com"},
		"secret empty":       {"client_secret": ""},
		"client id missing":  {"client_id": nil},
	} {
		t.Run(name, func(t *testing.T) {
			in := socialInput("amazon", o)
			if o["client_id"] == nil {
				if _, named := o["client_id"]; named {
					delete(in.Options, "client_id")
				}
			}
			if _, errs := Parse(in); len(errs) == 0 {
				t.Fatal("accepted")
			}
		})
	}
	in := socialInput("amazon", nil)
	in.ConnectedAccounts = map[string]any{"active": true}
	if _, errs := Parse(in); len(errs) == 0 {
		t.Fatal("connected_accounts.active accepted")
	}
	in = socialInput("amazon", nil)
	delete(in.Options, "client_secret")
	if _, errs := Parse(in); len(errs) == 0 {
		t.Fatal("create without client_secret accepted")
	}
	in.HasSealedSecret = true
	if _, errs := Parse(in); len(errs) > 0 {
		t.Fatalf("patch keeping the sealed secret: %v", errs)
	}
}

func manyScopes(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = "s" + strings.Repeat("x", i+1)
	}
	return out
}

func TestSocialFacebookAndLinkedInRules(t *testing.T) {
	s, errs := Parse(socialInput("facebook", nil))
	if len(errs) > 0 || !reflect.DeepEqual(s.Scopes, []string{"public_profile"}) || s.Social.Separator != "," {
		t.Fatalf("facebook default %v %v", s.Scopes, errs)
	}
	if _, errs := Parse(socialInput("facebook", map[string]any{"email": true, "scope": "public_profile,email"})); len(errs) > 0 {
		t.Fatalf("facebook comma scope %v", errs)
	}
	if _, errs := Parse(socialInput("facebook", map[string]any{"allow_context_profile_field": "x"})); len(errs) == 0 {
		t.Fatal("stored-only flag must still be a boolean")
	}
	for v, ok := range map[any]bool{1.0: true, 2.0: true, 3.0: true, 4.0: false, "3": false, 1.5: false} {
		s, errs := Parse(socialInput("linkedin", map[string]any{"strategy_version": v}))
		if ok != (len(errs) == 0) {
			t.Fatalf("strategy_version %v: %v", v, errs)
		}
		if ok && s.Social.StrategyVersion != int(v.(float64)) {
			t.Fatalf("strategy_version %v stored as %d", v, s.Social.StrategyVersion)
		}
	}
	if s, _ := Parse(socialInput("linkedin", nil)); s.Social.StrategyVersion != 3 || !reflect.DeepEqual(s.Scopes, []string{"openid", "profile"}) {
		t.Fatalf("linkedin default %+v %v", s.Social, s.Scopes)
	}
}

func TestSocialSalesforceCommunityRules(t *testing.T) {
	for name, c := range map[string]struct {
		v  any
		ok bool
	}{
		"valid":    {"https://community.example.com", true},
		"path":     {"https://community.example.com/partners", true},
		"missing":  {nil, false},
		"http":     {"http://community.example.com", false},
		"query":    {"https://community.example.com/?x=1", false},
		"fragment": {"https://community.example.com/#x", false},
		"userinfo": {"https://u:p@community.example.com", false},
		"loopback": {"https://127.0.0.1", false},
		"number":   {42.0, false},
	} {
		t.Run(name, func(t *testing.T) {
			o := map[string]any{}
			if c.v != nil {
				o["community_base_url"] = c.v
			}
			s, errs := Parse(socialInput("salesforce-community", o))
			if c.ok != (len(errs) == 0) {
				t.Fatalf("%v", errs)
			}
			if c.ok && !strings.HasPrefix(s.AuthorizationURL, c.v.(string)+"/services/oauth2/authorize") {
				t.Fatalf("authorization URL %s", s.AuthorizationURL)
			}
		})
	}
	if _, errs := Parse(socialInput("salesforce", map[string]any{"community_base_url": "https://c.example.com"})); len(errs) > 0 {
		t.Fatalf("salesforce stores community_base_url: %v", errs)
	}
	if _, errs := Parse(socialInput("yahoo", map[string]any{"freeform_scopes": []any{"x"}})); len(errs) == 0 {
		t.Fatal("yahoo accepted freeform_scopes")
	}
}

func TestSocialTwitterProtocol(t *testing.T) {
	s, errs := Parse(socialInput("twitter", nil))
	if len(errs) > 0 || s.OAuth1 != nil || !reflect.DeepEqual(s.Scopes, []string{"tweet.read", "users.read"}) || s.AuthorizationURL != "https://x.com/i/oauth2/authorize" {
		t.Fatalf("default %+v %v", s, errs)
	}
	s, errs = Parse(socialInput("twitter", map[string]any{"protocol": "oauth1", "tweet_read": true}))
	if len(errs) > 0 || s.OAuth1 == nil || len(s.Scopes) != 0 || s.OAuth1.RequestTokenURL != "https://api.x.com/oauth/request_token" ||
		s.OAuth1.UserAuthorizationURL != "https://api.x.com/oauth/authenticate" || s.OAuth1.AccessTokenURL != "https://api.x.com/oauth/access_token" || s.OAuth1.SignatureMethod != "HMAC-SHA1" {
		t.Fatalf("oauth1 %+v %+v %v", s, s.OAuth1, errs)
	}
	for _, v := range []any{"oauth3", "OAUTH1", 1.0} {
		if _, errs := Parse(socialInput("twitter", map[string]any{"protocol": v})); len(errs) == 0 {
			t.Fatalf("protocol %v accepted", v)
		}
	}
}

func TestSocialFreeScope(t *testing.T) {
	s, errs := Parse(socialInput("wordpress", nil))
	if len(errs) > 0 || !reflect.DeepEqual(s.Scopes, []string{"auth"}) {
		t.Fatalf("default %v %v", s.Scopes, errs)
	}
	for _, v := range []any{[]any{"global", "auth"}, "global auth", "global,auth"} {
		s, errs := Parse(socialInput("wordpress", map[string]any{"scope": v}))
		if len(errs) > 0 || !reflect.DeepEqual(s.Scopes, []string{"global", "auth"}) {
			t.Fatalf("scope %v: %v %v", v, s.Scopes, errs)
		}
	}
	for name, v := range map[string]any{
		"21 tokens":  manyScopes(21),
		"not string": []any{1},
		"too long":   []any{strings.Repeat("a", 129)},
		"object":     map[string]any{"a": 1},
	} {
		if _, errs := Parse(socialInput("wordpress", map[string]any{"scope": v})); len(errs) == 0 {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestExactBaseURL(t *testing.T) {
	for _, host := range []string{"nl", "be", "co.uk", "com", "de", "fr", "es"} {
		base := "https://start.exactonline." + host
		s, errs := Parse(socialInput("exact", map[string]any{"baseUrl": base, "profile": true}))
		if len(errs) > 0 || s.AuthorizationURL != base+"/api/oauth2/auth" || s.TokenURL != base+"/api/oauth2/token" || s.Social.BaseURL != base || len(s.Scopes) != 0 {
			t.Fatalf("%s: %+v %v", host, s, errs)
		}
	}
	if _, errs := Parse(socialInput("exact", map[string]any{"baseUrl": "https://start.exactonline.nl/"})); len(errs) > 0 {
		t.Fatalf("trailing slash: %v", errs)
	}
	for _, bad := range []any{nil, "https://start.exactonline.nl.evil.com", "http://start.exactonline.nl", "https://u@start.exactonline.nl",
		"https://start.exactonline.nl/x", "https://start.exactonline.nl:8443", "https://start.exactonline.nl?x=1", "https://evil.com/start.exactonline.nl", 42.0} {
		o := map[string]any{}
		if bad != nil {
			o["baseUrl"] = bad
		}
		if _, errs := Parse(socialInput("exact", o)); len(errs) == 0 {
			t.Fatalf("baseUrl %v accepted", bad)
		}
	}
}

func TestSocialOAuth1Descriptor(t *testing.T) {
	s, errs := Parse(socialInput("evernote", nil))
	if len(errs) > 0 || s.OAuth1 == nil || s.OAuth1.RequestTokenURL != "https://www.evernote.com/oauth" || s.OAuth1.UserAuthorizationURL != "https://www.evernote.com/OAuth.action" ||
		!s.OAuth1.EmptySecret || len(s.Scopes) != 0 {
		t.Fatalf("evernote %+v %v", s.OAuth1, errs)
	}
	if s, _ := Parse(socialInput("evernote-sandbox", nil)); s.OAuth1 == nil || s.OAuth1.AccessTokenURL != "https://sandbox.evernote.com/oauth" {
		t.Fatalf("sandbox %+v", s.OAuth1)
	}
	if s, _ := Parse(socialInput("twitter", map[string]any{"protocol": "oauth1"})); s.OAuth1 == nil || s.OAuth1.EmptySecret {
		t.Fatal("twitter oauth1 must not allow an empty token secret")
	}
}
