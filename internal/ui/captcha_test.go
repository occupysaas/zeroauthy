package ui

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCaptchaCSP(t *testing.T) {
	for _, provider := range []string{"recaptcha_v2", "recaptcha_enterprise", "hcaptcha", "friendly_captcha"} {
		w := httptest.NewRecorder()
		RenderLogin(w, 200, Tenant{Captcha: &Captcha{Provider: provider, SiteKey: "site", Action: "login"}}, LoginData{})
		body, csp := w.Body.String(), w.Header().Get("Content-Security-Policy")
		if w.Code != 200 || !strings.Contains(body, "captcha-help") || !strings.Contains(csp, "connect-src") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "*") {
			t.Fatal(provider, w.Code, csp, body)
		}
	}
	w := httptest.NewRecorder()
	RenderLogin(w, 200, Tenant{}, LoginData{})
	if strings.Contains(w.Body.String(), "captcha-help") || strings.Contains(w.Header().Get("Content-Security-Policy"), "connect-src") {
		t.Fatal("nonchallenge page loads provider")
	}
}
