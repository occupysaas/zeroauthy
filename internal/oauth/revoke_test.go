package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

func (f *fixture) revoke(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	h := contract.WrapResponses(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthRevoke)))
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestRevokeRevokesFamily(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, "")
	_, body := f.refresh(t, refreshForm("rt-spa", raw)) // rotate once so the family has two tokens
	next := body["refresh_token"].(string)

	code, body := f.revoke(t, url.Values{"client_id": {"rt-spa"}, "token": {next}})
	if code != 200 || body != nil {
		t.Fatalf("revoke = %d %v", code, body)
	}
	for _, tok := range []string{raw, next} {
		if got := f.storedRT(t, tok); got.RevokedAt == nil {
			t.Errorf("token in the family not revoked: %+v", got)
		}
	}
	if code, body := f.refresh(t, refreshForm("rt-spa", next)); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("refresh after revoke = %d %v", code, body)
	}
}

func TestRevokeVariants(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, "")
	cases := map[string]struct {
		form   url.Values
		status int
		code   string
	}{
		"unknown token":     {url.Values{"client_id": {"rt-spa"}, "token": {"no-such-token"}}, 200, ""},
		"another client":    {url.Values{"client_id": {"rt-web"}, "client_secret": {"rt-web-secret"}, "token": {raw}}, 400, "invalid_grant"},
		"missing token":     {url.Values{"client_id": {"rt-spa"}}, 400, "invalid_request"},
		"bad client secret": {url.Values{"client_id": {"rt-web"}, "client_secret": {"wrong"}, "token": {raw}}, 401, "invalid_client"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			code, body := f.revoke(t, tc.form)
			if code != tc.status || (tc.code != "" && body["error"] != tc.code) {
				t.Fatalf("got %d %v; want %d %s", code, body, tc.status, tc.code)
			}
		})
	}
	if got := f.storedRT(t, raw); got.RevokedAt != nil {
		t.Fatalf("a failed revocation changed the token: %+v", got)
	}
}
