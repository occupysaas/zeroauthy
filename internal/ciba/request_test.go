package ciba

import (
	"net/url"
	"strings"
	"testing"
)

const iss = "https://acme.example/"

func hint(sub string) string {
	return `{"format":"iss_sub","iss":"` + iss + `","sub":"` + sub + `"}`
}

func TestParseTable(t *testing.T) {
	base := func(mut func(url.Values)) url.Values {
		v := url.Values{"scope": {"openid email"}, "login_hint": {hint("auth0|u1")}, "binding_message": {"ORDER-42"}, "requested_expiry": {"600"}}
		if mut != nil {
			mut(v)
		}
		return v
	}
	ok, err := Parse(base(nil), iss)
	if err != nil || ok.UserID != "auth0|u1" || ok.Expiry != 600 || ok.BindingMessage != "ORDER-42" || strings.Join(ok.Scopes, " ") != "openid email" {
		t.Fatalf("valid: %+v %v", ok, err)
	}
	cases := map[string]struct {
		mut  func(url.Values)
		code string
	}{
		"no openid":           {func(v url.Values) { v.Set("scope", "email") }, "invalid_scope"},
		"no scope":            {func(v url.Values) { v.Del("scope") }, "invalid_scope"},
		"no hint":             {func(v url.Values) { v.Del("login_hint") }, "invalid_request"},
		"plain hint":          {func(v url.Values) { v.Set("login_hint", "auth0|u1") }, "invalid_request"},
		"other issuer":        {func(v url.Values) { v.Set("login_hint", strings.Replace(hint("u"), iss, "https://evil.example/", 1)) }, "invalid_request"},
		"other format":        {func(v url.Values) { v.Set("login_hint", `{"format":"email","email":"a@b"}`) }, "invalid_request"},
		"empty sub":           {func(v url.Values) { v.Set("login_hint", hint("")) }, "invalid_request"},
		"id_token_hint":       {func(v url.Values) { v.Set("id_token_hint", "x") }, "invalid_request"},
		"login_hint_token":    {func(v url.Values) { v.Set("login_hint_token", "x") }, "invalid_request"},
		"no binding message":  {func(v url.Values) { v.Del("binding_message") }, "invalid_request"},
		"long binding":        {func(v url.Values) { v.Set("binding_message", strings.Repeat("a", 65)) }, "invalid_request"},
		"space in binding":    {func(v url.Values) { v.Set("binding_message", "two words") }, "invalid_request"},
		"markup in binding":   {func(v url.Values) { v.Set("binding_message", "<b>x</b>") }, "invalid_request"},
		"expiry zero":         {func(v url.Values) { v.Set("requested_expiry", "0") }, "invalid_request"},
		"expiry too long":     {func(v url.Values) { v.Set("requested_expiry", "259201") }, "invalid_request"},
		"expiry not a number": {func(v url.Values) { v.Set("requested_expiry", "soon") }, "invalid_request"},
		"push window":         {func(v url.Values) { v.Set("requested_expiry", "300") }, "invalid_request"},
		"default expiry":      {func(v url.Values) { v.Del("requested_expiry") }, "invalid_request"},
		"rar":                 {func(v url.Values) { v.Set("authorization_details", "[]") }, "invalid_request"},
		"user_code":           {func(v url.Values) { v.Set("user_code", "1234") }, "invalid_request"},
	}
	for name, tc := range cases {
		_, err := Parse(base(tc.mut), iss)
		if err == nil || err.Code != tc.code {
			t.Errorf("%s: %v, want %s", name, err, tc.code)
		}
	}
	// The longest expiry and the full binding alphabet are accepted.
	if _, err := Parse(base(func(v url.Values) { v.Set("requested_expiry", "259200"); v.Set("binding_message", "aZ09+-_.,:#") }), iss); err != nil {
		t.Fatalf("edge values: %v", err)
	}
}
