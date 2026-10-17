package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

func (f *fixture) par(t *testing.T, host, contentType, body string, basic ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	h := contract.WrapResponses(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthPar)))
	req := httptest.NewRequest("POST", "https://"+host+"/oauth/par", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	if len(basic) == 2 {
		req.SetBasicAuth(basic[0], basic[1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

const formType = "application/x-www-form-urlencoded"

func parForm(extra ...string) url.Values {
	v := url.Values{
		"client_id": {"par-web"}, "client_secret": {"par-web-secret"},
		"response_type": {"code"}, "redirect_uri": {"https://par.acme.test/cb"},
		"scope": {"openid"}, "state": {"s1"},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func TestPARStoresRequest(t *testing.T) {
	f := newFixture(t)
	rec, body := f.par(t, "acme.example.test", formType, parForm("ext-tenant_hint", "blue", "foo", "bar").Encode())
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, body %v", rec.Code, body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || body["expires_in"] != float64(30) {
		t.Fatalf("headers %v body %v", rec.Header(), body)
	}
	uri, _ := body["request_uri"].(string)
	id, ok := strings.CutPrefix(uri, authz.RequestURIPrefix)
	if !ok || len(id) != 64 {
		t.Fatalf("request_uri = %q", uri)
	}
	p, err := f.st.PushedAuthRequests().Get(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(id))
	if err != nil {
		t.Fatal(err)
	}
	if p.ClientID != "par-web" || p.Params["state"] != "s1" || p.Params["ext-tenant_hint"] != "blue" ||
		p.Params["foo"] != "" || p.Params["client_secret"] != "" || p.Params["za_pushed"] != "1" {
		t.Fatalf("stored params = %v", p.Params)
	}
	if !p.ExpiresAt.Equal(fixedNow().Add(authz.PARLifetime)) {
		t.Fatalf("ExpiresAt = %v", p.ExpiresAt)
	}
}

func TestPARWithBasicAuth(t *testing.T) {
	f := newFixture(t)
	form := parForm()
	form.Del("client_secret")
	form.Set("client_id", "par-basic")
	rec, body := f.par(t, "acme.example.test", formType, form.Encode(), "par-basic", "par-basic-secret")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, body %v", rec.Code, body)
	}
}

func TestPARRefusals(t *testing.T) {
	f := newFixture(t)
	elevenExt := parForm()
	for i := range 11 {
		elevenExt.Set(fmt.Sprintf("ext-a%d", i), "x")
	}
	tenExt := parForm()
	for i := range 10 {
		tenExt.Set(fmt.Sprintf("ext-a%d", i), "x")
	}
	public := url.Values{"client_id": {"code-spa"}, "response_type": {"code"}, "redirect_uri": {"https://app.acme.test/cb"}}
	strict := parForm("client_id", "par-strict", "client_secret", "par-strict-secret", "redirect_uri", "https://partner.acme.test/cb",
		"code_challenge", strings.Repeat("a", 43), "code_challenge_method", "S256")
	cases := []struct {
		name, host, ctype, body string
		status                  int
		code                    string
	}{
		{"P2a bad redirect_uri", "acme.example.test", formType, parForm("redirect_uri", "https://evil.test/cb").Encode(), 400, "invalid_request"},
		{"P2b response_type", "acme.example.test", formType, parForm("response_type", "token").Encode(), 501, "unsupported_response_type"},
		{"unknown audience", "acme.example.test", formType, parForm("audience", "https://nope.test").Encode(), 403, "access_denied"},
		{"P2c eleven ext", "acme.example.test", formType, elevenExt.Encode(), 400, "invalid_request"},
		{"P2d oversized", "acme.example.test", formType, parForm("ext-big", strings.Repeat("x", 11000)).Encode(), 413, "payload_too_large"},
		{"P2e json", "acme.example.test", "application/json", `{"client_id":"par-web","client_secret":"par-web-secret","response_type":"code"}`, 400, "invalid_request"},
		{"repeated", "acme.example.test", formType, parForm().Encode() + "&state=s2", 400, "invalid_request"},
		{"P3a wrong secret", "acme.example.test", formType, parForm("client_secret", "nope").Encode(), 401, "invalid_client"},
		{"P3b public", "acme.example.test", formType, public.Encode(), 400, "invalid_request"},
		{"P6a request_uri", "acme.example.test", formType, parForm("request_uri", authz.RequestURIPrefix+"x").Encode(), 400, "invalid_request"},
		{"P6b tenant off", "globex.example.test", formType, url.Values{"client_id": {"globex-web"}, "client_secret": {"globex-web-secret"}, "response_type": {"code"}, "redirect_uri": {"https://web.globex.test/cb"}}.Encode(), 400, "invalid_request"},
		{"request object", "acme.example.test", formType, parForm("request", "eyJhbGciOiJub25lIn0.e30.").Encode(), 400, "request_not_supported"},
		{"P9 strict", "acme.example.test", formType, strict.Encode(), 400, "invalid_request"},
		{"P9 permissive", "acme.example.test", formType, url.Values{"client_id": {"partner"}, "client_secret": {"partner-secret"}, "response_type": {"code"}, "redirect_uri": {"https://partner.acme.test/cb"}}.Encode(), 400, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := f.par(t, tc.host, tc.ctype, tc.body)
			if rec.Code != tc.status || body["error"] != tc.code {
				t.Fatalf("got %d %v; want %d %s", rec.Code, body, tc.status, tc.code)
			}
		})
	}
	t.Run("ten ext allowed", func(t *testing.T) {
		if rec, body := f.par(t, "acme.example.test", formType, tenExt.Encode()); rec.Code != http.StatusCreated {
			t.Fatalf("got %d %v", rec.Code, body)
		}
	})
}
