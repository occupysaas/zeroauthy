package ui

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var nonceAttr = regexp.MustCompile(`nonce="([^"]+)"`)

func checkNonce(t *testing.T, csp, body string) {
	t.Helper()
	m := nonceAttr.FindAllStringSubmatch(body, -1)
	if len(m) == 0 {
		t.Fatal("no nonce attribute in body")
	}
	for _, x := range m {
		if !strings.Contains(csp, "'nonce-"+x[1]+"'") {
			t.Fatalf("nonce %q not in CSP %q", x[1], csp)
		}
	}
}

func TestRenderLogin(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderLogin(rec, 200, Tenant{Name: "Acme", PrimaryColor: "#112233", LogoURL: "https://cdn.acme.test/l.png"}, LoginData{
		State: "st", CSRF: "cs", Login: `"><script>alert(1)</script>`, SignupURL: "/u/signup?state=st", Error: "Nope",
	})
	body, h := rec.Body.String(), rec.Header()
	for _, want := range []string{`name="state" value="st"`, `name="csrf" value="cs"`, `id="username"`, `id="password"`,
		`type="submit"`, "Acme", "#112233", "https://cdn.acme.test/l.png", "/u/signup?state=st", "Nope"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("login hint not escaped")
	}
	csp := h.Get("Content-Security-Policy")
	checkNonce(t, csp, body)
	for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "form-action 'self'", "img-src https:"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if h.Get("X-Frame-Options") != "DENY" || h.Get("Cache-Control") != "no-store" || h.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("headers = %v", h)
	}
}

func TestRenderLoginWithoutSignup(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderLogin(rec, 200, Tenant{Name: "Acme"}, LoginData{State: "st", CSRF: "cs"})
	if strings.Contains(rec.Body.String(), "/u/signup") {
		t.Fatal("signup link shown without SignupURL")
	}
}

func TestRenderSignupAndError(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderSignup(rec, 400, Tenant{Name: "Acme"}, SignupData{State: "st", CSRF: "cs", Email: "a@b.test", RequiresUsername: true, LoginURL: "/u/login?state=st", Error: "Too short"})
	body := rec.Body.String()
	for _, want := range []string{`id="email"`, `id="username"`, `id="password"`, "Too short", "/u/login?state=st"} {
		if !strings.Contains(body, want) {
			t.Errorf("signup lacks %q", want)
		}
	}
	if rec.Code != 400 {
		t.Errorf("status %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	RenderError(rec, 400, Tenant{Name: "Acme"}, "Something <b>bad</b>")
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "Something &lt;b&gt;bad&lt;/b&gt;") {
		t.Fatalf("error page = %d %s", rec.Code, rec.Body)
	}
}

func TestRenderFormPost(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderFormPost(rec, nil, "https://app.test/cb?x=1", url.Values{"code": {"abc"}, "state": {`"><x`}})
	body, csp := rec.Body.String(), rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{`method="post"`, `action="https://app.test/cb?x=1"`, `name="code" value="abc"`, `value="&#34;&gt;&lt;x"`} {
		if !strings.Contains(body, want) {
			t.Errorf("form_post lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `value=""><x`) {
		t.Fatal("form_post value not escaped")
	}
	checkNonce(t, csp, body)
	if !strings.Contains(csp, "form-action https://app.test") {
		t.Errorf("CSP %q does not allow posting to the client", csp)
	}
}

func TestRenderWebMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderWebMessage(rec, "https://app.test", map[string]string{"code": "abc", "state": "</script><script>alert(1)"})
	body, h := rec.Body.String(), rec.Header()
	if strings.Contains(body, "</script><script>alert(1)") {
		t.Fatal("response not escaped in script context")
	}
	// html/template escapes "/" inside JS strings, so match the host only.
	for _, want := range []string{"authorization_response", "postMessage", "app.test"} {
		if !strings.Contains(body, want) {
			t.Errorf("web_message lacks %q:\n%s", want, body)
		}
	}
	csp := h.Get("Content-Security-Policy")
	checkNonce(t, csp, body)
	if !strings.Contains(csp, "frame-ancestors https://app.test") || h.Get("X-Frame-Options") != "" {
		t.Errorf("web_message must be frameable by its origin only: csp=%q xfo=%q", csp, h.Get("X-Frame-Options"))
	}
}

func TestRenderWebMessageRefusesBadOrigins(t *testing.T) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	for _, bad := range []string{
		"*", "", "https://a.test https:", "https://a.test;script-src *", "https://a.test/path",
		"https://a.test;script-src", "https://a.test,*", "https://*", "javascript://x", "https://a.test:99999999",
	} {
		rec := httptest.NewRecorder()
		RenderWebMessage(rec, bad, map[string]string{"code": "abc"})
		body := rec.Body.String()
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("origin %q: status %d, want 500", bad, rec.Code)
		}
		if strings.Contains(body, "postMessage") {
			t.Errorf("origin %q: page rendered", bad)
		}
		if rec.Header().Get("Content-Security-Policy") != "" || rec.Header().Get("X-Frame-Options") != "" {
			t.Errorf("origin %q: security headers set on refused response", bad)
		}
	}
}

func TestRenderWebMessageAcceptsGoodOrigins(t *testing.T) {
	for _, good := range []string{"https://app.test", "http://localhost:3000", "https://[::1]:8443", "https://127.0.0.1:3443"} {
		rec := httptest.NewRecorder()
		RenderWebMessage(rec, good, map[string]string{"code": "abc"})
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "postMessage") {
			t.Errorf("origin %q: status %d, want 200 with page", good, rec.Code)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors "+good) {
			t.Errorf("origin %q: CSP %q", good, csp)
		}
	}
}

func TestRenderLoginNeutralisesHostileStyleAndHref(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderLogin(rec, 200, Tenant{Name: "Acme", PrimaryColor: "red;}body{display:none}"}, LoginData{
		State: "st", CSRF: "cs", SignupURL: "javascript:alert(1)",
	})
	body := rec.Body.String()
	if strings.Contains(body, "red;}body{display:none}") {
		t.Fatal("hostile primary color emitted raw")
	}
	if !strings.Contains(body, "ZgotmplZ") {
		t.Error("hostile primary color not replaced with ZgotmplZ")
	}
	if strings.Contains(body, `href="javascript:alert(1)"`) {
		t.Fatal("javascript: signup URL emitted as href")
	}
}

func TestRenderFormPostRejectsBadActionOrigin(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderFormPost(rec, nil, "https://a.test;script-src/cb", url.Values{"code": {"abc"}})
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'none'") {
		t.Errorf("CSP %q does not refuse form-action for an invalid origin", csp)
	}
}

func TestFormPagesAllowRedirectOriginInFormAction(t *testing.T) {
	for redirect, want := range map[string]string{
		"https://app.test:3443/cb?x=1":    "form-action 'self' https://app.test:3443;",
		"com.example.app://cb":            "form-action 'self' com.example.app:;",
		"com.example.app:/oauth2redirect": "form-action 'self' com.example.app:;",
		"java script:foo":                 "form-action 'self';",
		"a;b:/x":                          "form-action 'self';",
		"1abc:/x":                         "form-action 'self';",
		"javascript:alert(1)":             "form-action 'self';",
		"":                                "form-action 'self';",
	} {
		rec := httptest.NewRecorder()
		RenderLogin(rec, 200, Tenant{Name: "Acme"}, LoginData{State: "st", CSRF: "cs", RedirectURI: redirect})
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, want) {
			t.Errorf("login with redirect %q: CSP %q lacks %q", redirect, csp, want)
		}
		rec = httptest.NewRecorder()
		RenderSignup(rec, 200, Tenant{Name: "Acme"}, SignupData{State: "st", CSRF: "cs", RedirectURI: redirect})
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, want) {
			t.Errorf("signup with redirect %q: CSP %q lacks %q", redirect, csp, want)
		}
	}
}

func TestRenderLoggedOut(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderLoggedOut(rec, Tenant{Name: "Acme"})
	csp := rec.Header().Get("Content-Security-Policy")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "logged out") ||
		!strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "form-action 'none'") {
		t.Fatalf("logged-out page = %d %q %s", rec.Code, csp, rec.Body)
	}
}

func TestRenderLogoutConfirm(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderLogoutConfirm(rec, Tenant{Name: "Acme"}, LogoutConfirmData{
		CSRF:        "tok",
		Fields:      url.Values{"state": {`"><script>alert(1)</script>`}, "client_id": {"spa"}},
		RedirectURI: "https://app.acme.test/bye",
	})
	body, csp := rec.Body.String(), rec.Header().Get("Content-Security-Policy")
	if rec.Code != 200 || !strings.Contains(body, `name="csrf" value="tok"`) || !strings.Contains(body, `name="client_id" value="spa"`) ||
		strings.Contains(body, "<script>alert(1)") || !strings.Contains(csp, "form-action 'self' https://app.acme.test;") {
		t.Fatalf("confirmation page = %d %q\n%s", rec.Code, csp, body)
	}
}

func frenchTenant() *store.Tenant {
	return &store.Tenant{Name: "acme", EnabledLocales: []string{"en", "fr"}, CustomText: store.CustomText{
		"login": {"fr": {"login": {"title": "Connexion", "buttonText": "Continuer"}}},
	}}
}

func TestRenderLoginLocalized(t *testing.T) {
	tn := frenchTenant()
	rec := httptest.NewRecorder()
	RenderLogin(rec, 200, TenantView(tn, i18n.New(tn, "fr")), LoginData{State: "st", CSRF: "cs"})
	body := rec.Body.String()
	for _, want := range []string{`<html lang="fr" dir="ltr">`, "Connexion", "Continuer", "Email or username"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
}

func TestRTLDirection(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderLoggedOut(rec, TenantView(&store.Tenant{Name: "acme"}, i18n.New(nil, "ar")))
	if !strings.Contains(rec.Body.String(), `<html lang="ar" dir="rtl">`) {
		t.Fatalf("body = %s", rec.Body)
	}
}

func TestCustomTextIsEscaped(t *testing.T) {
	tn := &store.Tenant{Name: `<b>acme</b>`, CustomText: store.CustomText{
		"login": {"en": {"login": {"title": `<script>alert(1)</script> ${companyName}`}}},
	}}
	rec := httptest.NewRecorder()
	RenderLogin(rec, 200, TenantView(tn, i18n.New(tn, "en")), LoginData{State: "st", CSRF: "cs"})
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)") || strings.Contains(body, "<b>acme</b>") {
		t.Fatalf("custom text or variable not escaped:\n%s", body)
	}
}

func TestRenderErrorDetail(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderErrorDetail(rec, 400, Tenant{Name: "Acme"}, "Localized message", "redirect_uri is not registered")
	body := rec.Body.String()
	if rec.Code != 400 || !strings.Contains(body, "Localized message") || !strings.Contains(body, "redirect_uri is not registered") {
		t.Fatalf("got %d %s", rec.Code, body)
	}
}
