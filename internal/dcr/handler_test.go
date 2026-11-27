package dcr

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type fixture struct {
	h   *Handler
	st  store.Store
	tn  *store.Tenant
	now time.Time
}

func newFixture(t *testing.T, settings map[string]any) *fixture {
	t.Helper()
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	t.Cleanup(func() { st.Close() })
	tn := &store.Tenant{ID: "ten", Name: "ten", SettingsExtra: settings}
	if err := st.Tenants().Create(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	f := &fixture{st: st, tn: tn, now: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)}
	f.h = NewHandler(st, w, nil)
	f.h.Now = func() time.Time { return f.now }
	return f
}

func enabled(extra map[string]any) map[string]any {
	s := map[string]any{"flags": map[string]any{"enable_dynamic_client_registration": true}}
	for k, v := range extra {
		s[k] = v
	}
	return s
}

func (f *fixture) post(t *testing.T, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://ten.example/oidc/register", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: f.tn, Host: "ten.example"}))
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

var tpc = regexp.MustCompile(`^tpc_[0-9A-Za-z]{22}$`)

func TestRegisterOffIs404(t *testing.T) {
	f := newFixture(t, nil)
	w, _ := f.post(t, `{"redirect_uris":["https://app.example/cb"]}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d", w.Code)
	}
}

func TestRegisterConfidentialStrict(t *testing.T) {
	f := newFixture(t, enabled(nil))
	w, out := f.post(t, `{"client_name":"Dyn","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code","client_credentials"],"logo_uri":"https://app.example/l.png"}`)
	if w.Code != http.StatusCreated || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d cache %q body %s", w.Code, w.Header().Get("Cache-Control"), w.Body)
	}
	id, _ := out["client_id"].(string)
	secret, _ := out["client_secret"].(string)
	if !tpc.MatchString(id) || len(secret) < 32 || out["client_secret_expires_at"] != float64(0) ||
		out["token_endpoint_auth_method"] != "client_secret_post" || out["client_name"] != "Dyn" {
		t.Fatalf("answer %v", out)
	}
	if gt, _ := out["grant_types"].([]any); len(gt) != 1 || gt[0] != "authorization_code" {
		t.Fatalf("grant_types %v", out["grant_types"])
	}
	c, err := f.st.Clients().Get(context.Background(), "ten", id)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsFirstParty || c.ThirdPartySecurityMode != store.SecurityModeStrict || c.AppType != store.AppTypeRegularWeb ||
		c.External == nil || c.External.Type != store.ExternalMetadataDCR || c.External.CreatedBy != store.ExternalCreatedByClient ||
		len(c.Callbacks) != 1 || c.Callbacks[0] != "https://app.example/cb" || len(c.Secrets) != 1 || c.Secrets[0].Hash != "" {
		t.Fatalf("stored %+v", c)
	}
	opened, err := keys.OpenClientSecret(f.h.Wrapper, "ten", id, c.Secrets[0].Sealed)
	if err != nil || opened != secret {
		t.Fatalf("sealed secret: %v", err)
	}
}

func TestRegisterPublicPermissive(t *testing.T) {
	f := newFixture(t, enabled(map[string]any{"dynamic_client_registration_security_mode": "permissive"}))
	w, out := f.post(t, `{"redirect_uris":["http://localhost:3000/cb"],"token_endpoint_auth_method":"none","response_types":["code"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	if _, has := out["client_secret"]; has || out["client_name"] != "My App" {
		t.Fatalf("answer %v", out)
	}
	c, err := f.st.Clients().Get(context.Background(), "ten", out["client_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if c.AppType != store.AppTypeSPA || c.TokenEndpointAuthMethod != store.AuthMethodNone || len(c.Secrets) != 0 || c.ThirdPartySecurityMode != store.SecurityModePermissive ||
		len(c.AllowedOrigins) != 1 || c.AllowedOrigins[0] != "http://localhost:3000" {
		t.Fatalf("stored %+v", c)
	}
}

func TestRegisterErrorsAreRFC7591(t *testing.T) {
	f := newFixture(t, enabled(nil))
	w, out := f.post(t, `{"redirect_uris":["http://app.example/cb"]}`)
	if w.Code != http.StatusBadRequest || out["error"] != "invalid_redirect_uri" || out["error_description"] == "" {
		t.Fatalf("status %d %v", w.Code, out)
	}
	w, out = f.post(t, `{"redirect_uris":["https://app.example/cb"],"response_types":["id_token"]}`)
	if w.Code != http.StatusBadRequest || out["error"] != "invalid_client_metadata" {
		t.Fatalf("status %d %v", w.Code, out)
	}
	w, out = f.post(t, `{"redirect_uris":["https://app.example/cb"],"padding":"`+strings.Repeat("x", maxBody)+`"}`)
	if w.Code != http.StatusBadRequest || out["error"] != "invalid_client_metadata" {
		t.Fatalf("oversized: status %d %v", w.Code, out)
	}
	clients, _, _ := f.st.Clients().List(context.Background(), "ten", store.ClientFilter{}, store.Page{})
	if len(clients) != 0 {
		t.Fatalf("refused registrations created %d clients", len(clients))
	}
}

func TestRegisterRateLimit(t *testing.T) {
	f := newFixture(t, enabled(nil))
	for i := range 5 {
		if w, _ := f.post(t, `{"redirect_uris":["https://app.example/cb"]}`); w.Code != http.StatusCreated {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	w, out := f.post(t, `{"redirect_uris":["https://app.example/cb"]}`)
	if w.Code != http.StatusTooManyRequests || out["error"] != "too_many_requests" || w.Header().Get("Retry-After") == "" {
		t.Fatalf("sixth: %d %v", w.Code, out)
	}
	// Another tenant has its own bucket; time refills this one.
	other := &store.Tenant{ID: "other", Name: "other", SettingsExtra: enabled(nil)}
	f.tn = other
	if err := f.st.Tenants().Create(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if w, _ := f.post(t, `{"redirect_uris":["https://app.example/cb"]}`); w.Code != http.StatusCreated {
		t.Fatalf("other tenant: %d", w.Code)
	}
	f.tn = &store.Tenant{ID: "ten", Name: "ten", SettingsExtra: enabled(nil)}
	if w, _ := f.post(t, `{"redirect_uris":["https://app.example/cb"]}`); w.Code != http.StatusTooManyRequests {
		t.Fatalf("still limited: %d", w.Code)
	}
	f.now = f.now.Add(time.Second)
	if w, _ := f.post(t, `{"redirect_uris":["https://app.example/cb"]}`); w.Code != http.StatusCreated {
		t.Fatalf("after a second: %d", w.Code)
	}
}
