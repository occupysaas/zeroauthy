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
