package hostedlogin

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
	"testing"
)

func TestThemePrecedence(t *testing.T) {
	c := &store.HostedLoginConfig{Branding: map[string]any{"logo_url": "https://example.test/base.svg", "colors": map[string]any{"primary": "#112233", "page_background": "#eeeeee"}}, DefaultThemeID: "theme", Themes: map[string]map[string]any{"theme": {"colors": map[string]any{"primary_button": "#445566"}, "widget": map[string]any{"logo_url": "https://example.test/theme.svg"}, "fonts": map[string]any{"reference_text_size": float64(20), "title": map[string]any{"size": float64(150), "bold": true}}}}}
	theme, err := ResolveTheme(c)
	if err != nil {
		t.Fatal(err)
	}
	if theme.LogoURL != "https://example.test/theme.svg" || theme.BackgroundColor != "#eeeeee" || theme.Properties["--za-colors-primary-button"] != "#445566" || theme.Properties["--za-fonts-title-size"] != "30px" {
		t.Fatalf("theme=%+v", theme)
	}
	c.DefaultThemeID = ""
	base, err := ResolveTheme(c)
	if err != nil {
		t.Fatal(err)
	}
	if base.LogoURL != "https://example.test/base.svg" || strings.Contains(base.CSS(), "#445566") {
		t.Fatalf("deleted default did not restore base: %+v", base)
	}
}

func TestThemeRejectsUnsafeValues(t *testing.T) {
	for _, fields := range []map[string]any{
		{"colors": map[string]any{"primary_button": "red;display:none"}},
		{"colors": map[string]any{"x;color": "#ffffff"}},
		{"widget": map[string]any{"logo_url": "javascript:alert(1)"}},
		{"widget": map[string]any{"logo_height": float64(-1)}},
		{"fonts": map[string]any{"title": map[string]any{"size": float64(999)}}},
		{"fonts": map[string]any{"font_url": "https://example.test/font.css"}},
	} {
		if _, err := ResolveTheme(&store.HostedLoginConfig{DefaultThemeID: "id", Themes: map[string]map[string]any{"id": fields}}); err == nil {
			t.Errorf("accepted %v", fields)
		}
	}
}
