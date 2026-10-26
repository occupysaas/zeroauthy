package server

import (
	"io/fs"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/console"
)

func TestConsoleServedOnSystemHost(t *testing.T) {
	h := newMgmtServer(t)
	get := func(target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", target, nil))
		return rec
	}
	sys := "https://" + mgmtSystemHost

	if rec := get(sys + "/admin"); rec.Code != 301 || rec.Header().Get("Location") != "/admin/" {
		t.Errorf("/admin = %d %v", rec.Code, rec.Header())
	}
	index, err := fs.ReadFile(console.Files(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	// The index and every deep link (Review Focus 5) answer the console.
	for _, p := range []string{"/admin/", "/admin/callback?code=x&state=y", "/admin/t/acme/applications/xyz", "/admin/t/acme/"} {
		rec := get(sys + p)
		if rec.Code != 200 || regexp.MustCompile(`<meta name="zeroauthy-preview-style-nonce" content="[A-Za-z0-9_-]{22}">`).ReplaceAllString(rec.Body.String(), "") != string(index) || rec.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("%s = %d %q", p, rec.Code, rec.Header().Get("Cache-Control"))
		}
		csp := rec.Header().Get("Content-Security-Policy")
		nonce := regexp.MustCompile(`<meta name="zeroauthy-preview-style-nonce" content="([A-Za-z0-9_-]{22})">`).FindStringSubmatch(rec.Body.String())
		if len(nonce) != 2 || !strings.Contains(csp, "style-src 'self' 'nonce-"+nonce[1]+"'") {
			t.Fatal("preview style nonce not bound to document CSP")
		}

		for _, want := range []string{"script-src 'self'", "frame-ancestors 'none'", "connect-src 'self' https://acme.example.test https://login.acme.test https://" + mgmtSystemHost, "default-src 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q lacks %q", p, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: CSP allows inline code: %q", p, csp)
		}
	}
	// No inline scripts or styles in the built page.
	if regexp.MustCompile(`<script(?:\s[^>]*)?>\s*[^<\s]`).Match(index) || strings.Contains(string(index), "<style") {
		t.Error("index.html has inline script or style")
	}

	asset := regexp.MustCompile(`/admin/(assets/[^"]+\.js)`).FindStringSubmatch(string(index))
	if asset == nil {
		t.Fatalf("no script in %s", index)
	}
	rec := get(sys + "/admin/" + asset[1])
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "javascript") || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("asset = %d %v", rec.Code, rec.Header())
	}
	if rec := get(sys + "/admin/assets/missing.js"); rec.Code != 404 {
		t.Errorf("missing asset = %d", rec.Code)
	}
	// Only on the system host.
	for _, target := range []string{"https://acme.example.test/admin/", "https://acme.example.test/admin/" + asset[1]} {
		if rec := get(target); rec.Code != 404 {
			t.Errorf("%s = %d", target, rec.Code)
		}
	}
}
