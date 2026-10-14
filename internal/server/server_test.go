package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/zeroauthy/zeroauthy/api"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

const testSeed = `
tenants:
  - name: acme
    domains: [acme.example.test]
    resource_servers: [{identifier: "https://api.acme.test", scopes: [{value: "read:things"}]}]
    clients: [{client_id: m2m, app_type: non_interactive, client_secret: s3cret, grant_types: [client_credentials]}]
    client_grants: [{client_id: m2m, audience: "https://api.acme.test", scopes: ["read:things"]}]
`

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	f, err := seed.Parse([]byte(testSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(ctx, st, f, nil); err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if err := km.Ensure(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	return New(Deps{
		Store:    st,
		Keys:     km,
		Resolver: tenant.NewResolver(st.Tenants(), "", false),
		Sessions: &session.Manager{Store: st},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),

		UserThrottle: identity.NewThrottle(10, time.Minute, time.Minute),
		IPThrottle:   identity.NewThrottle(100, time.Minute, time.Minute),
	})
}

func get(h http.Handler, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", target, nil))
	return rec
}

func TestOperationalEndpoints(t *testing.T) {
	h := newTestServer(t)
	if rec := get(h, "http://any.host/healthz"); rec.Code != 200 {
		t.Errorf("healthz %d", rec.Code)
	}
	if rec := get(h, "http://any.host/readyz"); rec.Code != 200 {
		t.Errorf("readyz %d", rec.Code)
	}
	rec := get(h, "http://any.host/openapi.yaml")
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), api.AuthenticationYAML) || rec.Header().Get("Content-Type") != "application/yaml" {
		t.Errorf("openapi.yaml %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = get(h, "http://any.host/docs")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "createApiReference") || !strings.Contains(rec.Body.String(), "/openapi.yaml") {
		t.Errorf("docs %d", rec.Code)
	}
}

func TestAPIRoutesThroughServer(t *testing.T) {
	h := contract.Wrap(t, newTestServer(t))

	if rec := get(h, "https://acme.example.test/.well-known/openid-configuration"); rec.Code != 200 {
		t.Errorf("discovery %d: %s", rec.Code, rec.Body)
	}
	if rec := get(h, "https://acme.example.test/.well-known/jwks.json"); rec.Code != 200 {
		t.Errorf("jwks %d: %s", rec.Code, rec.Body)
	}
	if rec := get(h, "https://unknown.test/.well-known/jwks.json"); rec.Code != 404 {
		t.Errorf("unknown tenant %d", rec.Code)
	}

	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"m2m"}, "client_secret": {"s3cret"}, "audience": {"https://api.acme.test"}}
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "access_token") {
		t.Errorf("token %d: %s", rec.Code, rec.Body)
	}
}

func TestRecovererWritesJSON(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	h := middleware.RequestID(recoverer(log)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "https://x.test/", nil))
	if rec.Code != 500 || rec.Header().Get("Content-Type") != "application/json" ||
		!strings.Contains(rec.Body.String(), `"error":"server_error"`) {
		t.Fatalf("got %d %q %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
	if !strings.Contains(logs.String(), "boom") || !strings.Contains(logs.String(), "request_id") {
		t.Errorf("panic not logged with request id: %s", logs.String())
	}
}

func TestDocsPageIsPinnedAndLockedDown(t *testing.T) {
	rec := get(newTestServer(t), "http://any.host/docs")
	body := rec.Body.String()
	if !strings.Contains(body, `integrity="sha384-VXnKAz61Xwc3tbw1P+KKrUP7YbcsSl1Ik4is5UnogJyw9XEYZ5Ay/T1i0zPYtSZH"`) ||
		!strings.Contains(body, `crossorigin="anonymous"`) ||
		!strings.Contains(body, "@scalar/api-reference@1.74.0/dist/browser/standalone.js") {
		t.Fatalf("docs script is not pinned with SRI:\n%s", body)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'sha256-", "https://cdn.jsdelivr.net", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
}

func TestAuthorizeThroughServer(t *testing.T) {
	h := contract.Wrap(t, newTestServer(t))

	rec := get(h, "https://acme.example.test/authorize?client_id=nope&redirect_uri=https://x.test/cb&response_type=code")
	if rec.Code != 400 || rec.Header().Get("Location") != "" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("unknown client = %d %v %s", rec.Code, rec.Header(), rec.Body)
	}

	rec = get(h, "https://acme.example.test/authorize?client_id=a&client_id=b")
	if rec.Code != 400 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") || !strings.Contains(rec.Body.String(), `"invalid_request"`) {
		t.Errorf("repeated client_id = %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
}

// Query parameters the handlers read must appear in the contract, so the
// generated wrapper binds and documents them.
func TestContractDocumentsUILocales(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(api.AuthenticationYAML)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/authorize", "/oidc/logout"} {
		op := doc.Paths.Find(path).Get
		if op == nil || op.Parameters.GetByInAndName("query", "ui_locales") == nil {
			t.Errorf("GET %s does not document ui_locales", path)
		}
	}
	_ = authapi.AuthorizeParams{UiLocales: new(string)} // the generated wrapper binds it
}
