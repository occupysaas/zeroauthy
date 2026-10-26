package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func brandedView(t *testing.T, source string) Tenant {
	t.Helper()
	cfg := &store.HostedLoginConfig{TenantID: "t", Template: &source, Branding: map[string]any{"colors": map[string]any{"primary": "#123456"}, "logo_url": "https://assets.test/logo.svg"}}
	r := httptest.NewRequest("GET", "https://tenant.test/u/login", nil)
	r = r.WithContext(hostedlogin.WithConfiguration(context.Background(), cfg))
	return RequestTenant(r, &store.Tenant{ID: "t", Name: "Acme"}, i18n.Default())
}

func TestHostedPageTemplate(t *testing.T) {
	view := brandedView(t, `<html><head>{% auth0:head %}<style>.za-decoration {color:#112233}</style></head><body><aside class="za-decoration">Branded {{tenant.name}}</aside>{% auth0:widget %}</body></html>`)
	rec := httptest.NewRecorder()
	RenderLogin(rec, http.StatusUnauthorized, view, LoginData{State: "state", CSRF: "csrf", RedirectURI: "https://client.test/callback"})
	body := rec.Body.String()
	for _, want := range []string{"Branded Acme", `name="csrf" value="csrf"`, `name="state" value="state"`, `id="password"`, `<form`, "#123456"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
	checkNonce(t, rec.Header().Get("Content-Security-Policy"), body)
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "form-action 'self' https://client.test") {
		t.Fatal("callback form action lost")
	}
}

func TestBrandingFailureFallback(t *testing.T) {
	view := brandedView(t, `<html><head>{% auth0:head %}</head><body>{% if prompt.name == 'never' %}{% auth0:widget %}{% endif %}</body></html>`)
	rec := httptest.NewRecorder()
	RenderLogin(rec, http.StatusBadRequest, view, LoginData{State: "s", CSRF: "c", Error: "Try again"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `name="csrf" value="c"`) || !strings.Contains(rec.Body.String(), "Try again") {
		t.Fatalf("fallback broke widget: %d %s", rec.Code, rec.Body.String())
	}
}

func TestBrandingProtocolPagesExcluded(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderWebMessage(rec, "https://client.test", map[string]string{"code": "secret"})
	if strings.Contains(rec.Body.String(), "Branded") || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors https://client.test") {
		t.Fatal("protocol page changed")
	}
}

func TestHostedPageBrandingMatrix(t *testing.T) {
	data := map[string]any{
		"login": LoginData{State: "s", CSRF: "c"}, "signup": SignupData{State: "s", CSRF: "c"}, "consent": ConsentData{State: "s", CSRF: "c"},
		"error": errorData{Message: "Error"}, "logout_confirm": LogoutConfirmData{CSRF: "c"}, "logged_out": nil,
		"reset_request": ResetRequestData{State: "s", CSRF: "c"}, "reset_email_sent": nil, "reset_password": ResetFormData{Ticket: "ticket", CSRF: "c"},
		"reset_success": nil, "reset_error": ResetErrorData{Title: "Expired", Description: "Restart"}, "email_verification": EmailVerificationData{Title: "Verified", Description: "Done", Success: true},
		"device_code": DeviceCodeData{State: "s", CSRF: "c"}, "device_confirm": DeviceConfirmData{State: "s", CSRF: "c"}, "device_result": true,
	}
	for name, d := range data {
		t.Run(name, func(t *testing.T) {
			view := brandedView(t, `<html><head>{% auth0:head %}</head><body><aside>Tenant wrapper</aside>{% auth0:widget %}</body></html>`)
			rec := httptest.NewRecorder()
			render(rec, http.StatusTeapot, name, view, d, "'self'")
			if rec.Code != http.StatusTeapot || !strings.Contains(rec.Body.String(), "Tenant wrapper") || strings.Count(rec.Body.String(), "<main>") != 1 {
				t.Fatalf("page lost status/wrapper/widget: %d %s", rec.Code, rec.Body.String())
			}
			checkNonce(t, rec.Header().Get("Content-Security-Policy"), rec.Body.String())
		})
	}
}

func TestBrandingCSP(t *testing.T) {
	view := brandedView(t, `<html><head>{% auth0:head %}</head><body><img src="https://decoration.test/image.svg" alt="">{% auth0:widget %}</body></html>`)
	view.Captcha = &Captcha{Provider: "hcaptcha", SiteKey: "public"}
	rec := httptest.NewRecorder()
	RenderLogin(rec, 200, view, LoginData{CSRF: "c"})
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"https://assets.test", "https://decoration.test", "https://js.hcaptcha.com", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("missing %q in %s", want, csp)
		}
	}
	for _, bad := range []string{"img-src https:;", "unsafe-inline", "unsafe-eval"} {
		if strings.Contains(csp, bad) {
			t.Errorf("unsafe CSP %s", csp)
		}
	}
}

func TestOversizedLegacyTextFallback(t *testing.T) {
	tenant := &store.Tenant{Name: "Acme", CustomText: store.CustomText{"login": {"en": {"login": {"title": strings.Repeat("a", 1<<20)}}}}}
	rec := httptest.NewRecorder()
	RenderLogin(rec, 200, TenantView(tenant, i18n.New(tenant, "en")), LoginData{State: "s", CSRF: "c"})
	if rec.Code != 200 || rec.Body.Len() > 512<<10 || !strings.Contains(rec.Body.String(), `name="csrf" value="c"`) || !strings.Contains(rec.Body.String(), "Sign in") {
		t.Fatalf("legacy fallback=%d bytes=%d", rec.Code, rec.Body.Len())
	}
}
