package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

type unavailableHostedStore struct{ store.Store }

func (unavailableHostedStore) HostedLogins() store.HostedLogins {
	return store.UnimplementedHostedLogins{}
}

func TestHostedPresentationMiddleware(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	tn := &store.Tenant{ID: "t", Name: "Acme"}
	if err := st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	source := `<html><head>{% auth0:head %}</head><body><aside>Tenant wrapper</aside>{% auth0:widget %}</body></html>`
	c := &store.HostedLoginConfig{TenantID: "t", Template: &source, Branding: map[string]any{"logo_url": "https://assets.test/logo.svg"}, CustomText: store.CustomText{"login": {"en": {"login": {"title": "Canonical title"}}}}}
	if err := st.HostedLogins().Put(ctx, c, 0); err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, _ := tenant.FromContext(r.Context())
		view := ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
		ui.RenderLogin(w, 200, view, ui.LoginData{State: "s", CSRF: "c"})
	})
	r := httptest.NewRequest("GET", "https://tenant.test/u/login", nil)
	r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: tn, Host: "tenant.test"}))
	rec := httptest.NewRecorder()
	hostedPresentation(st)(next).ServeHTTP(rec, r)
	for _, want := range []string{"Tenant wrapper", "Canonical title", "https://assets.test/logo.svg"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
	if tn.CustomText != nil {
		t.Fatal("shared tenant mutated")
	}
	rec = httptest.NewRecorder()
	hostedPresentation(unavailableHostedStore{st})(next).ServeHTTP(rec, r)
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "Tenant wrapper") {
		t.Fatalf("store failure=%d", rec.Code)
	}
}

func TestHostedPresentationSystemTenantExcluded(t *testing.T) {
	st := memory.New()
	tn := &store.Tenant{ID: "system", Name: "System", Reserved: true}
	r := httptest.NewRequest("GET", "https://system.test/u/login", nil)
	r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: tn}))
	called := false
	rec := httptest.NewRecorder()
	hostedPresentation(unavailableHostedStore{st})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rec, r)
	if !called {
		t.Fatal("system login depended on tenant branding repository")
	}
}
