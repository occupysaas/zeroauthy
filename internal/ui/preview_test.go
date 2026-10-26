package ui

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestBrandingPreviewIsolation(t *testing.T) {
	source := `<html><head>{% auth0:head %}</head><body><img src="https://real.example.test/image.svg" alt="External"><a href="https://real.example.test">Help</a>{% auth0:widget %}</body></html>`
	c := &store.HostedLoginConfig{TenantID: "real-tenant-id", Template: &source, Branding: map[string]any{"logo_url": "https://real.example.test/logo.svg", "font": map[string]any{"url": "https://real.example.test/font.woff2"}}}
	out, err := Preview(context.Background(), c, "login", "en")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"real-tenant-id", "https://real.example.test", "unsafe-inline", "allow-scripts"} {
		if strings.Contains(out.HTML, bad) {
			t.Errorf("preview contains %q", bad)
		}
	}
	for _, want := range []string{"form-action &#39;none&#39;", "script-src &#39;none&#39;", "External image blocked", "name=\"csrf\""} {
		if !strings.Contains(out.HTML, want) {
			t.Errorf("preview lacks %q", want)
		}
	}
	if c.Branding["logo_url"] != "https://real.example.test/logo.svg" {
		t.Fatal("preview changed saved config")
	}
	if _, err := Preview(context.Background(), c, "unknown-screen", "en"); err == nil {
		t.Fatal("unknown screen accepted")
	}
}
