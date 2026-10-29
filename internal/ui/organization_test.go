package ui

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/brandingrules"
	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func orgView() *store.Organization {
	logo := "https://org-assets.test/logo.svg?a=1&b=2"
	return &store.Organization{ID: "org_bound", Name: "acme", DisplayName: "Acme <Org>", Metadata: map[string]string{"tier": "gold"}, Branding: &store.OrgBranding{LogoURL: &logo, Colors: &store.OrgColors{Primary: "#abcdef", PageBackground: "#fedcba"}}}
}

func TestOrganizationBranding(t *testing.T) {
	cfg := &store.HostedLoginConfig{TenantID: "t", Branding: map[string]any{"logo_url": "https://tenant.test/logo.svg", "colors": map[string]any{"primary": "#123456"}}, DefaultThemeID: "theme", Themes: map[string]map[string]any{"theme": {"fonts": map[string]any{"reference_text_size": float64(18), "font_url": "https://fonts.test/tenant.woff2"}, "borders": map[string]any{"widget_corner_radius": float64(21)}, "colors": map[string]any{"primary_button": "#112233", "links_focused_components": "#223344"}, "page_background": map[string]any{"background_color": "#334455", "page_layout": "left"}, "widget": map[string]any{"logo_url": "https://theme.test/logo.svg"}}}}
	req := httptest.NewRequest("GET", "https://tenant.test/u/login", nil)
	req = req.WithContext(hostedlogin.WithConfiguration(context.Background(), cfg))
	for _, name := range []string{"login", "signup", "consent", "error"} {
		t.Run(name, func(t *testing.T) {
			view := RequestTenant(req, &store.Tenant{ID: "t", Name: "Tenant"}, i18n.Default())
			baseline := httptest.NewRecorder()
			render(baseline, 200, name, view, map[string]any{}, "'self'")
			if !strings.Contains(baseline.Body.String(), "https://theme.test/logo.svg") {
				t.Fatal("individual theme changed")
			}
			view.Organization = orgView()
			rec := httptest.NewRecorder()
			render(rec, 400, name, view, map[string]any{}, "'self'")
			for _, want := range []string{"https://org-assets.test/logo.svg?a=1&amp;b=2", "--accent:#abcdef", "--za-colors-primary-button:#abcdef", "--za-colors-links-focused-components:#abcdef", "--za-page-background-background-color:#fedcba", "--za-borders-widget-corner-radius:21px", "--za-fonts-reference-text-size:18px", "https://fonts.test/tenant.woff2", "--za-page-background-page-layout:start"} {
				if !strings.Contains(rec.Body.String(), want) {
					t.Errorf("missing %s", want)
				}
			}
			if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "https://org-assets.test") {
				t.Error("org logo blocked by CSP")
			}
			view.Organization.Branding.Colors.Primary = "red;display:none"
			rec = httptest.NewRecorder()
			render(rec, 400, name, view, map[string]any{}, "'self'")
			if strings.Contains(rec.Body.String(), "red;display:none") {
				t.Error("unvalidated CSS")
			}
		})
	}
}

func TestOrganizationTemplates(t *testing.T) {
	view := brandedView(t, `<html><head>{% auth0:head %}</head><body><p>[{{organization.id}}|{{organization.name}}|{{organization.display_name}}|{{organization.metadata.tier}}|{{organization.branding.logo_url}}|{{organization.branding.colors.primary}}|{{organization.branding.colors.page_background}}]</p>{% auth0:widget %}</body></html>`)
	view.Organization = orgView()
	rec := httptest.NewRecorder()
	RenderLogin(rec, 200, view, LoginData{})
	if !strings.Contains(rec.Body.String(), "[org_bound|acme|Acme &lt;Org&gt;|gold|https://org-assets.test/logo.svg?a=1&amp;b=2|#abcdef|#fedcba]") {
		t.Fatal(rec.Body.String())
	}
	view.Organization = nil
	rec = httptest.NewRecorder()
	RenderLogin(rec, 200, view, LoginData{})
	if !strings.Contains(rec.Body.String(), "[||||||]") {
		t.Fatal("organization not empty")
	}
}

// Both organization screens consume their own accepted custom-text entries.
func TestOrganizationTemplatesCustomText(t *testing.T) {
	cfg := &store.HostedLoginConfig{TenantID: "t"}
	next, err := brandingrules.Merge(cfg, "text:organizations:en", []byte(`{"organization-selection":{"title":"Custom selection"},"organization-picker":{"title":"Custom picker"}}`))
	if err != nil {
		t.Fatal(err)
	}
	tenant := hostedlogin.LocalizedTenant(&store.Tenant{ID: "t", Name: "Acme"}, next)
	for screen, want := range map[string]string{"organization-selection": "Custom selection", "organization-picker": "Custom picker"} {
		r := httptest.NewRecorder()
		RenderOrganization(r, 200, TenantView(tenant, i18n.New(tenant, "en")), OrganizationData{}, screen)
		if !strings.Contains(r.Body.String(), want) {
			t.Fatalf("%s custom text missing", screen)
		}
	}
}

// A real browser enforces form-action before submitting either hosted step.
func TestOrganizationFormAction(t *testing.T) {
	for _, screen := range []string{"organization-selection", "organization-picker"} {
		rec := httptest.NewRecorder()
		RenderOrganization(rec, 200, TenantView(&store.Tenant{Name: "Acme"}, i18n.Default()), OrganizationData{}, screen)
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self';") {
			t.Fatalf("%s blocks its own form: %s", screen, csp)
		}
	}
}

func TestOrganizationFormActionCallback(t *testing.T) {
	for _, screen := range []string{"organization-selection", "organization-picker"} {
		rec := httptest.NewRecorder()
		RenderOrganization(rec, 200, TenantView(&store.Tenant{Name: "Acme"}, i18n.Default()), OrganizationData{RedirectURI: "https://app.example.test/callback"}, screen)
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://app.example.test;") {
			t.Fatalf("%s blocks validated callback: %s", screen, csp)
		}
	}
}
