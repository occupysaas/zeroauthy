package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

const dcrSeed = `
tenants:
  - name: dyn
    domains: [dyn.example.test]
    settings:
      flags: {enable_dynamic_client_registration: true}
  - name: closed
    domains: [closed.example.test]
`

func newDCRServer(t *testing.T) http.Handler {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	f, err := seed.Parse([]byte(dcrSeed))
	if err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	if err := seed.Apply(ctx, st, f, nil, w); err != nil {
		t.Fatal(err)
	}
	km := keys.NewManager(st.SigningKeys(), w)
	for _, name := range []string{"dyn", "closed"} {
		tn, _ := st.Tenants().GetByName(ctx, name)
		if err := km.Ensure(ctx, tn.ID); err != nil {
			t.Fatal(err)
		}
	}
	return contract.Wrap(t, New(Deps{
		Store: st, Keys: km, Wrapper: w, Resolver: tenant.NewResolver(st.Tenants(), "", false),
		Sessions: &session.Manager{Store: st}, Mailer: discardMailer{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}))
}

func postJSON(h http.Handler, target, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// A registered confidential client authenticates at /oauth/token with its
// secret, and cannot use client_credentials (Plan 41b, Review Focus 1).
func TestDynamicRegistrationThroughServer(t *testing.T) {
	h := newDCRServer(t)
	if rec := postJSON(h, "https://closed.example.test/oidc/register", `{"redirect_uris":["https://app.example/cb"]}`); rec.Code != http.StatusNotFound {
		t.Fatalf("closed tenant: %d %s", rec.Code, rec.Body)
	}
	rec := postJSON(h, "https://dyn.example.test/oidc/register", `{"client_name":"Dyn","redirect_uris":["https://app.example/cb"],"grant_types":["client_credentials","authorization_code"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	var reg struct{ ClientID, ClientSecret string }
	_ = json.Unmarshal(rec.Body.Bytes(), &struct {
		ClientID     *string `json:"client_id"`
		ClientSecret *string `json:"client_secret"`
	}{&reg.ClientID, &reg.ClientSecret})
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {reg.ClientID}, "client_secret": {reg.ClientSecret}, "audience": {"https://dyn.example.test/api/v2/"}}
	r := httptest.NewRequest(http.MethodPost, "https://dyn.example.test/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tok := httptest.NewRecorder()
	h.ServeHTTP(tok, r)
	if tok.Code == http.StatusOK || !strings.Contains(tok.Body.String(), "unauthorized_client") {
		t.Fatalf("client_credentials for a DCR client: %d %s", tok.Code, tok.Body)
	}
	// A wrong secret is invalid_client: the stored secret is the one returned.
	form.Set("client_secret", "wrong")
	r = httptest.NewRequest(http.MethodPost, "https://dyn.example.test/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad := httptest.NewRecorder()
	h.ServeHTTP(bad, r)
	if bad.Code != http.StatusUnauthorized || !strings.Contains(bad.Body.String(), "invalid_client") {
		t.Fatalf("wrong secret: %d %s", bad.Code, bad.Body)
	}
	disc := get(h, "https://dyn.example.test/.well-known/openid-configuration")
	if !strings.Contains(disc.Body.String(), `"registration_endpoint":"https://dyn.example.test/oidc/register"`) {
		t.Fatalf("discovery: %s", disc.Body)
	}
}
