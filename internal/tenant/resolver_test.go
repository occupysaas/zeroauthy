package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	s := memory.New()
	ctx := context.Background()
	for _, tn := range []*store.Tenant{
		{ID: "ten_acme", Name: "acme", CanonicalHost: "acme.auth.example.test", Domains: []string{"login.acme.test"}},
		{ID: "ten_globex", Name: "globex", Domains: []string{"localhost:8443"}},
	} {
		if err := s.Tenants().Create(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestResolve(t *testing.T) {
	r := NewResolver(newTestStore(t).Tenants(), "Auth.Example.Test", false)
	cases := []struct {
		host, wantTenant, wantHost string
	}{
		{"login.acme.test", "ten_acme", "login.acme.test"},
		{"LOGIN.acme.test.:443", "ten_acme", "login.acme.test"},
		{"acme.auth.example.test", "ten_acme", "acme.auth.example.test"},
		{"localhost:8443", "ten_globex", "localhost:8443"},
	}
	for _, tc := range cases {
		got, err := r.Resolve(context.Background(), tc.host)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", tc.host, err)
		}
		if got.Tenant.ID != tc.wantTenant || got.Host != tc.wantHost {
			t.Errorf("Resolve(%q) = %s @ %s, want %s @ %s", tc.host, got.Tenant.ID, got.Host, tc.wantTenant, tc.wantHost)
		}
	}
	if got, _ := r.Resolve(context.Background(), "login.acme.test"); got.Issuer() != "https://login.acme.test/" {
		t.Errorf("Issuer = %q", got.Issuer())
	}
	for _, host := range []string{"unknown.test", "auth.example.test", "x.acme.auth.example.test", "nobody.auth.example.test"} {
		if _, err := r.Resolve(context.Background(), host); !errors.Is(err, ErrUnknownTenant) {
			t.Errorf("Resolve(%q) err = %v, want ErrUnknownTenant", host, err)
		}
	}
}

func TestMiddleware(t *testing.T) {
	st := newTestStore(t)
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, ok := FromContext(r.Context())
		if !ok {
			t.Error("no tenant in context")
		}
		_, _ = w.Write([]byte(res.Tenant.ID + " " + res.Issuer()))
	})

	t.Run("resolves host", func(t *testing.T) {
		h := NewResolver(st.Tenants(), "", false).Middleware(echo)
		req := httptest.NewRequest("GET", "https://login.acme.test/x", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 || rec.Body.String() != "ten_acme https://login.acme.test/" {
			t.Fatalf("got %d %q", rec.Code, rec.Body)
		}
	})

	t.Run("unknown host is 404 JSON", func(t *testing.T) {
		h := NewResolver(st.Tenants(), "", false).Middleware(echo)
		req := httptest.NewRequest("GET", "https://evil.test/x", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", cc)
		}
		if rec.Code != 404 || body["error"] != "not_found" || body["error_description"] != "unknown tenant" {
			t.Fatalf("got %d %v", rec.Code, body)
		}
	})

	// Review focus 1: forwarded host only when trusted.
	t.Run("X-Forwarded-Host ignored unless trusted", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://login.acme.test/x", nil)
		req.Header.Set("X-Forwarded-Host", "localhost:8443")

		rec := httptest.NewRecorder()
		NewResolver(st.Tenants(), "", false).Middleware(echo).ServeHTTP(rec, req)
		if rec.Body.String() != "ten_acme https://login.acme.test/" {
			t.Fatalf("untrusted: got %q", rec.Body)
		}

		rec = httptest.NewRecorder()
		NewResolver(st.Tenants(), "", true).Middleware(echo).ServeHTTP(rec, req)
		if rec.Body.String() != "ten_globex https://localhost:8443/" {
			t.Fatalf("trusted: got %q", rec.Body)
		}
	})

	t.Run("X-Forwarded-Host list uses first entry", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://internal.test/x", nil)
		req.Header.Set("X-Forwarded-Host", "login.acme.test, proxy.internal")
		rec := httptest.NewRecorder()
		NewResolver(st.Tenants(), "", true).Middleware(echo).ServeHTTP(rec, req)
		if rec.Body.String() != "ten_acme https://login.acme.test/" {
			t.Fatalf("got %q", rec.Body)
		}
	})
}

func TestMiddlewareStoreErrorIsNoStore500(t *testing.T) {
	h := NewResolver(failingTenants{newTestStore(t).Tenants()}, "", false).Middleware(http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "https://login.acme.test/x", nil))
	if rec.Code != 500 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("got %d cache-control %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
}

type failingTenants struct{ store.Tenants }

func (failingTenants) GetByDomain(context.Context, string) (*store.Tenant, error) {
	return nil, errors.New("db down")
}

// A custom domain that looks like another tenant's base-domain host must
// never shadow that tenant: the pinned canonical claim owns the name.
func TestBaseDomainHostBeatsCustomDomain(t *testing.T) {
	s := newTestStore(t)
	err := s.Tenants().Create(context.Background(), &store.Tenant{
		ID: "ten_evil", Name: "evil", Domains: []string{"acme.auth.example.test"},
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("shadowing claim = %v", err)
	}
	r := NewResolver(s.Tenants(), "auth.example.test", false)
	got, err := r.Resolve(context.Background(), "acme.auth.example.test")
	if err != nil || got.Tenant.ID != "ten_acme" {
		t.Fatalf("got %+v, %v; want ten_acme", got.Tenant, err)
	}
}

func TestSystemHost(t *testing.T) {
	for _, tc := range []struct{ base, host, want string }{
		{"", "Admin.Localhost:8443", "admin.localhost:8443"},
		{"Auth.Example.TEST", "", "system.auth.example.test"},
		{"auth.example.test", "console.example.test", "console.example.test"},
		{"", "", ""},
	} {
		if got := SystemHost(tc.base, tc.host); got != tc.want {
			t.Errorf("SystemHost(%q, %q) = %q, want %q", tc.base, tc.host, got, tc.want)
		}
	}
}

// The system tenant is found by its stored host (server.system_host) and,
// with a base domain, by system.<base domain>.
func TestResolveSystemHost(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten_sys", Name: SystemName, Reserved: true, Domains: []string{"admin.localhost:8443"}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ base, host string }{
		{"", "Admin.Localhost:8443"},
		{"auth.example.test", "admin.localhost:8443"},
		{"auth.example.test", "system.auth.example.test"},
	} {
		got, err := NewResolver(st.Tenants(), tc.base, false).Resolve(ctx, tc.host)
		if err != nil || got.Tenant.ID != "ten_sys" {
			t.Errorf("base %q, host %q: %+v, %v", tc.base, tc.host, got, err)
		}
	}
}

// A name match must not route an unclaimed hostname before reconciliation.
func TestResolverRequiresActiveRegistry(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "a", Name: "a", Domains: []string{"a.example.test"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "a.auth.example.test", TenantID: "a", DomainID: "pending", Kind: store.HostPublic}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewResolver(st.Tenants(), "auth.example.test", false).Resolve(ctx, "a.auth.example.test"); !errors.Is(err, ErrUnknownTenant) {
		t.Fatalf("pending name resolved: %v", err)
	}
}
