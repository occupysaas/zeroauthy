package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/ratelimit"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func newLimitedServer(t *testing.T, rate float64, burst int) http.Handler {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	f, err := seed.Parse([]byte(testSeed + `
  - name: globex
    domains: [globex.example.test]
`))
	if err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	if err := seed.Apply(ctx, st, f, nil, w); err != nil {
		t.Fatal(err)
	}
	km := keys.NewManager(st.SigningKeys(), w)
	for _, name := range []string{"acme", "globex"} {
		tn, _ := st.Tenants().GetByName(ctx, name)
		if err := km.Ensure(ctx, tn.ID); err != nil {
			t.Fatal(err)
		}
	}
	r := ratelimit.Rate{PerSecond: rate, Burst: burst}
	groups := map[ratelimit.Group]ratelimit.Rate{}
	for _, g := range ratelimit.Groups {
		groups[g] = r
	}
	return New(Deps{
		Store: st, Keys: km, Wrapper: w,
		Resolver:  tenant.NewResolver(st.Tenants(), "", false),
		Sessions:  &session.Manager{Store: st},
		Mailer:    discardMailer{},
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		RateLimit: ratelimit.New(ratelimit.Config{Enabled: true, MaxKeys: 1000, Groups: groups}),
	})
}

// Routes that need no general Authentication API limit: operational
// endpoints, and the Management API, console and export downloads, which
// require a token or a signed link.
var unlimitedRoutes = []string{
	"/healthz", "/readyz", "/openapi.yaml", "/docs",
	"/api/v2/*", "/api/system/*", "/api/console/*", "/export/{job}/{file}", "/admin", "/admin/*",
}

// Every tenant Authentication API route must sit behind the limiter. The
// routes come from the router itself, so a new route is checked without
// editing this test.
func TestEveryAuthenticationRouteIsRateLimited(t *testing.T) {
	h := newLimitedServer(t, 1000, 100000)
	type route struct{ method, path string }
	var routes []route
	if err := chi.Walk(h.(chi.Routes), func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !slices.Contains(unlimitedRoutes, path) {
			routes = append(routes, route{method, path})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(routes) < 40 {
		t.Fatalf("walked only %d routes", len(routes))
	}
	param := regexp.MustCompile(`\{[^}]+\}`)
	for _, rt := range routes {
		target := "https://acme.example.test" + param.ReplaceAllString(rt.path, "x")
		req := httptest.NewRequest(rt.method, target, strings.NewReader(""))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Header().Get("X-RateLimit-Limit") == "" {
			t.Errorf("%s %s: no rate limit (status %d)", rt.method, rt.path, rec.Code)
		}
	}
}

func TestAuthGroups(t *testing.T) {
	for path, want := range map[string]ratelimit.Group{
		"/oauth/token":                      ratelimit.GroupToken,
		"/authorize":                        ratelimit.GroupAuthorize,
		"/userinfo":                         ratelimit.GroupUserinfo,
		"/.well-known/openid-configuration": ratelimit.GroupDiscovery,
		"/.well-known/jwks.json":            ratelimit.GroupDiscovery,
		"/oauth/par":                        ratelimit.GroupOther,
		"/oauth/device/code":                ratelimit.GroupOther,
		"/oauth/revoke":                     ratelimit.GroupOther,
		"/dbconnections/signup":             ratelimit.GroupOther,
		"/dbconnections/change_password":    ratelimit.GroupOther,
		"/passwordless/start":               ratelimit.GroupOther,
		"/mfa/challenge":                    ratelimit.GroupOther,
		"/u/login":                          ratelimit.GroupOther,
		"/v2/logout":                        ratelimit.GroupOther,
	} {
		if got := authGroup(path); got != want {
			t.Errorf("%s: group %s, want %s", path, got, want)
		}
	}
}

func TestRateLimitThroughServer(t *testing.T) {
	h := newLimitedServer(t, 0.001, 2)
	for i := range 2 {
		if rec := get(h, "https://acme.example.test/.well-known/jwks.json"); rec.Code != 200 {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	rec := get(h, "https://acme.example.test/.well-known/jwks.json")
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), `"error":"too_many_requests"`) {
		t.Fatalf("over the limit: %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "0" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("headers = %v", rec.Header())
	}
	// Discovery is its own group; another tenant has its own buckets.
	if rec := get(h, "https://acme.example.test/.well-known/openid-configuration"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("discovery shares the JWKS group: %d", rec.Code)
	}
	if rec := get(h, "https://acme.example.test/userinfo"); rec.Code == http.StatusTooManyRequests {
		t.Error("userinfo throttled by the discovery group")
	}
	if rec := get(h, "https://globex.example.test/.well-known/jwks.json"); rec.Code != 200 {
		t.Errorf("other tenant throttled: %d", rec.Code)
	}
	// Another client address has its own bucket.
	req := httptest.NewRequest("GET", "https://acme.example.test/.well-known/jwks.json", nil)
	req.RemoteAddr = "198.51.100.7:4444"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("other IP throttled: %d", rec.Code)
	}
	// The Management API is not limited here.
	if rec := get(h, "https://acme.example.test/api/v2/clients"); rec.Header().Get("X-RateLimit-Limit") != "" {
		t.Error("Management API rate limited")
	}
}
