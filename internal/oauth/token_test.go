package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type tokenCall struct {
	host        string
	form        url.Values
	json        string // when set, sent as an application/json body instead of form
	basicID     string
	basicSecret string
	header      map[string]string
}

func (f *fixture) call(t *testing.T, strict bool, c tokenCall) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var req *http.Request
	if c.json != "" {
		req = httptest.NewRequest("POST", "https://"+c.host+"/oauth/token", strings.NewReader(c.json))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest("POST", "https://"+c.host+"/oauth/token", strings.NewReader(c.form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c.basicID != "" {
		req.SetBasicAuth(url.QueryEscape(c.basicID), url.QueryEscape(c.basicSecret))
	}
	for k, v := range c.header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.server(t, strict).ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func cc(clientID, secret string, extra ...string) url.Values {
	v := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}}
	if secret != "" {
		v.Set("client_secret", secret)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func TestClientCredentialsSuccess(t *testing.T) {
	f := newFixture(t)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test",
		form: cc("m2m", "m2m-secret", "audience", "https://api.acme.test")})
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	if body["token_type"] != "Bearer" || body["expires_in"] != float64(3600) || body["scope"] != "read:things write:things" {
		t.Errorf("body = %v", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Errorf("headers = %v", rec.Header())
	}
	claims, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	want := map[string]any{
		"iss": "https://acme.example.test/", "sub": "m2m@clients", "aud": "https://api.acme.test",
		"azp": "m2m", "gty": "client-credentials", "scope": "read:things write:things",
		"exp": float64(fixedNow().Unix() + 3600),
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("claim %s = %#v, want %#v", k, claims[k], v)
		}
	}
}

func TestClientCredentialsVariants(t *testing.T) {
	f := newFixture(t)

	t.Run("json body", func(t *testing.T) {
		rec, body := f.call(t, true, tokenCall{host: "acme.example.test",
			json: `{"grant_type":"client_credentials","client_id":"m2m","client_secret":"m2m-secret","audience":"https://api.acme.test"}`})
		if rec.Code != 200 {
			t.Fatalf("status %d: %v", rec.Code, body)
		}
	})

	t.Run("basic auth", func(t *testing.T) {
		rec, body := f.call(t, true, tokenCall{host: "acme.example.test",
			form:    url.Values{"grant_type": {"client_credentials"}, "audience": {"https://api.acme.test"}},
			basicID: "m2m-basic", basicSecret: "p@ss:w+rd"})
		if rec.Code != 200 || body["scope"] != "read:things" {
			t.Fatalf("status %d: %v", rec.Code, body)
		}
	})

	t.Run("default audience", func(t *testing.T) {
		rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret")})
		if rec.Code != 200 {
			t.Fatalf("status %d: %v", rec.Code, body)
		}
		claims, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
		if claims["aud"] != "https://api.acme.test" {
			t.Fatalf("aud = %v", claims["aud"])
		}
	})

	t.Run("token lifetime default", func(t *testing.T) {
		rec, body := f.call(t, true, tokenCall{host: "globex.example.test", form: cc("globex-m2m", "globex-secret", "audience", "https://api.globex.test")})
		if rec.Code != 200 || body["expires_in"] != float64(86400) {
			t.Fatalf("status %d: %v", rec.Code, body)
		}
	})

	t.Run("scope narrowing", func(t *testing.T) {
		rec, body := f.call(t, true, tokenCall{host: "acme.example.test",
			form: cc("m2m", "m2m-secret", "audience", "https://api.acme.test", "scope", "write:things  write:things")})
		if rec.Code != 200 || body["scope"] != "write:things" {
			t.Fatalf("status %d: %v", rec.Code, body)
		}
	})
}

func TestTokenErrors(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name       string
		strict     bool
		call       tokenCall
		wantStatus int
		wantError  string
	}{
		{"missing grant_type", false, tokenCall{host: "acme.example.test", form: url.Values{"client_id": {"m2m"}}}, 400, "invalid_request"},
		{"unsupported grant", true, tokenCall{host: "acme.example.test", form: url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "client_id": {"m2m"}}}, 400, "unsupported_grant_type"},
		{"bad secret", true, tokenCall{host: "acme.example.test", form: cc("m2m", "wrong")}, 401, "invalid_client"},
		{"grant type not allowed", true, tokenCall{host: "acme.example.test", form: cc("web", "web-secret")}, 403, "unauthorized_client"},
		{"public client", true, tokenCall{host: "acme.example.test", form: cc("spa", "")}, 403, "unauthorized_client"},
		{"unknown audience", true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", "https://nope.test")}, 403, "access_denied"},
		{"no grant for audience", true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", "https://billing.acme.test")}, 403, "access_denied"},
		{"no audience and no default", true, tokenCall{host: "globex.example.test", form: cc("globex-m2m", "globex-secret")}, 400, "invalid_request"},
		{"no requested scope granted", true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "scope", "read:invoices")}, 400, "invalid_scope"},
		// Review focus 5: cross-tenant.
		{"client of other tenant", true, tokenCall{host: "globex.example.test", form: cc("m2m", "m2m-secret", "audience", "https://api.globex.test")}, 401, "invalid_client"},
		{"audience of other tenant", true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", "https://api.globex.test")}, 403, "access_denied"},
		{"unknown host", true, tokenCall{host: "nobody.test", form: cc("m2m", "m2m-secret")}, 404, "not_found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := f.call(t, tc.strict, tc.call)
			if rec.Code != tc.wantStatus || body["error"] != tc.wantError {
				t.Fatalf("got %d %v, want %d %s", rec.Code, body, tc.wantStatus, tc.wantError)
			}
			if _, leaked := body["access_token"]; leaked {
				t.Fatal("error response contains a token")
			}
		})
	}

	t.Run("basic failure sends challenge", func(t *testing.T) {
		rec, _ := f.call(t, true, tokenCall{host: "acme.example.test",
			form: url.Values{"grant_type": {"client_credentials"}}, basicID: "m2m-basic", basicSecret: "wrong"})
		if rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("got %d %v", rec.Code, rec.Header())
		}
	})
}
