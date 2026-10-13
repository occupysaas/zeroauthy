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
		{ID: "ten_acme", Name: "acme", Domains: []string{"login.acme.test"}},
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
