package authz

import (
	"context"
	"net/url"
	"testing"
)

const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" // RFC 7636 Appendix B

func goodQuery() url.Values {
	return url.Values{
		"client_id":             {"spa"},
		"redirect_uri":          {"https://app.acme.test/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"st"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
}

func with(q url.Values, kv ...string) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			out.Del(kv[i])
		} else {
			out.Set(kv[i], kv[i+1])
		}
	}
	return out
}

func TestValidateOK(t *testing.T) {
	f := newFixture(t)
	req := ParseRequest(goodQuery())
	c, err, _ := validate(context.Background(), f.st, f.tenant, &req)
	if err != nil {
		t.Fatalf("unexpected error %+v", err)
	}
	if c.ClientID != "spa" || req.ResponseMode != "query" {
		t.Fatalf("client=%v mode=%q", c.ClientID, req.ResponseMode)
	}
}

func TestValidateErrors(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name         string
		q            url.Values
		code         string
		redirectable bool
	}{
		{"no client", with(goodQuery(), "client_id", ""), "invalid_request", false},
		{"unknown client", with(goodQuery(), "client_id", "nope"), "invalid_request", false},
		{"client of other tenant", with(goodQuery(), "client_id", "globex-spa", "redirect_uri", "https://app.globex.test/cb"), "invalid_request", false},
		{"no redirect_uri", with(goodQuery(), "redirect_uri", ""), "invalid_request", false},
		// Review focus 1: lookalike redirect URIs are never redirected to.
		{"trailing slash", with(goodQuery(), "redirect_uri", "https://app.acme.test/callback/"), "invalid_request", false},
		{"case differs", with(goodQuery(), "redirect_uri", "https://app.acme.test/Callback"), "invalid_request", false},
		{"extra query", with(goodQuery(), "redirect_uri", "https://app.acme.test/callback?x=1"), "invalid_request", false},
		{"fragment", with(goodQuery(), "redirect_uri", "https://app.acme.test/callback#x"), "invalid_request", false},
		{"userinfo", with(goodQuery(), "redirect_uri", "https://evil.test@app.acme.test/callback"), "invalid_request", false},
		{"other port", with(goodQuery(), "redirect_uri", "https://app.acme.test:8443/callback"), "invalid_request", false},
		{"wildcard two labels", with(goodQuery(), "redirect_uri", "https://a.b.preview.acme.test/cb"), "invalid_request", false},
		{"wildcard suffix trick", with(goodQuery(), "redirect_uri", "https://evil.test/.preview.acme.test/cb"), "invalid_request", false},
		{"wildcard scheme", with(goodQuery(), "redirect_uri", "http://x.preview.acme.test/cb"), "invalid_request", false},
		{"query-wildcard abuse", with(goodQuery(), "redirect_uri", "https://evilapp.acme.test/cb2?next=https://wildcard.x"), "invalid_request", false},
		{"wildcard fullwidth dot", with(goodQuery(), "redirect_uri", "https://evil\u3002com.preview.acme.test/cb"), "invalid_request", false},
		{"wildcard quote label", with(goodQuery(), "redirect_uri", "https://x\".preview.acme.test/cb"), "invalid_request", false},
		{"wildcard encoded path", with(goodQuery(), "redirect_uri", "https://x.preview.acme.test/%63b"), "invalid_request", false},
		{"wildcard percent label", with(goodQuery(), "redirect_uri", "https://x%25.preview.acme.test/cb"), "invalid_request", false},
		{"unregistered private-use", with(goodQuery(), "redirect_uri", "com.example.app:/other"), "invalid_request", false},
		{"private-use with fragment", with(goodQuery(), "redirect_uri", "com.example.app:/oauth2redirect#x"), "invalid_request", false},
		{"web_message unregistered origin", with(goodQuery(), "redirect_uri", "http://localhost:3000/", "response_mode", "web_message"), "invalid_request", false},
		// Redirectable errors.
		{"no response_type", with(goodQuery(), "response_type", ""), "invalid_request", true},
		{"implicit", with(goodQuery(), "response_type", "token"), "unsupported_response_type", true},
		{"bad response_mode", with(goodQuery(), "response_mode", "jwt"), "invalid_request", true},
		{"grant not allowed", with(goodQuery(), "client_id", "m2m", "redirect_uri", "https://m2m.acme.test/cb"), "unauthorized_client", true},
		{"public without pkce", with(goodQuery(), "code_challenge", "", "code_challenge_method", ""), "invalid_request", true},
		{"plain pkce", with(goodQuery(), "code_challenge_method", "plain"), "invalid_request", true},
		{"pkce without method", with(goodQuery(), "code_challenge_method", ""), "invalid_request", true},
		{"short challenge", with(goodQuery(), "code_challenge", "abc"), "invalid_request", true},
		{"bad max_age", with(goodQuery(), "max_age", "-1"), "invalid_request", true},
		{"prompt none plus login", with(goodQuery(), "prompt", "none login"), "invalid_request", true},
		{"unknown prompt", with(goodQuery(), "prompt", "nonsense"), "invalid_request", true},
		{"unknown audience", with(goodQuery(), "audience", "https://nope.test"), "access_denied", true},
		{"organization", with(goodQuery(), "organization", "org_1"), "invalid_request", true},
		{"connection not enabled", with(goodQuery(), "connection", "Other-DB"), "invalid_request", true},
		{"unknown connection", with(goodQuery(), "connection", "Nope"), "invalid_request", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := ParseRequest(tc.q)
			_, err, redirectable := validate(context.Background(), f.st, f.tenant, &req)
			if err == nil || err.Code != tc.code || redirectable != tc.redirectable {
				t.Fatalf("got err=%+v redirectable=%v, want %s/%v", err, redirectable, tc.code, tc.redirectable)
			}
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	f := newFixture(t)
	for name, q := range map[string]url.Values{
		"wildcard one label":     with(goodQuery(), "redirect_uri", "https://pr-42.preview.acme.test/cb"),
		"private-use exact":      with(goodQuery(), "redirect_uri", "com.example.app:/oauth2redirect"),
		"localhost http":         with(goodQuery(), "redirect_uri", "http://localhost:3000/"),
		"web_message registered": with(goodQuery(), "response_mode", "web_message", "prompt", "none"),
		"form_post":              with(goodQuery(), "response_mode", "form_post"),
		"known audience":         with(goodQuery(), "audience", "https://api.acme.test"),
		"enabled connection":     with(goodQuery(), "connection", "Username-Password-Authentication"),
		"max_age zero":           with(goodQuery(), "max_age", "0"),
		"consent prompt ignored": with(goodQuery(), "prompt", "consent"),
		"confidential no pkce":   with(goodQuery(), "client_id", "web", "redirect_uri", "https://web.acme.test/cb", "code_challenge", "", "code_challenge_method", ""),
	} {
		t.Run(name, func(t *testing.T) {
			req := ParseRequest(q)
			if _, err, _ := validate(context.Background(), f.st, f.tenant, &req); err != nil {
				t.Fatalf("unexpected error %+v", err)
			}
		})
	}
}

func TestDefaultAudience(t *testing.T) {
	f := newFixture(t)
	f.tenant.DefaultAudience = "https://api.acme.test"
	req := ParseRequest(goodQuery())
	if _, err, _ := validate(context.Background(), f.st, f.tenant, &req); err != nil || req.Audience != "https://api.acme.test" {
		t.Fatalf("audience = %q, err %+v", req.Audience, err)
	}
}

func TestRequestParamsRoundTrip(t *testing.T) {
	req := ParseRequest(with(goodQuery(), "nonce", "n", "max_age", "60", "login_hint", "a@b.test"))
	if got := RequestFromParams(req.Params()); got != req {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, req)
	}
}
