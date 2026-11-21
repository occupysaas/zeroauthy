package federation

import (
	"strings"
	"testing"
)

func TestOIDCStandardIdentityClaims(t *testing.T) {
	p, err := profileFromClaims("upstream", map[string]any{"name": "Root", "locale": "en", "middle_name": "Middle", "address": map[string]any{"country": "GB", "secret": "drop"}, "app_metadata": map[string]any{"role": "admin"}, "zoneinfo": true})
	if err != nil {
		t.Fatal(err)
	}
	if p.ProviderData["locale"] != "en" || p.ProviderData["middle_name"] != "Middle" {
		t.Fatalf("missing standard profile: %v", p.ProviderData)
	}
	if p.ProviderData["zoneinfo"] != nil || p.ProviderData["app_metadata"] != nil {
		t.Fatal("unsupported data retained")
	}
	if p.ProviderData["address"].(map[string]any)["secret"] != nil {
		t.Fatal("unknown address member retained")
	}
	p, err = profileFromClaims("upstream", map[string]any{"locale": strings.Repeat("x", maxProfileBytes+1)})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ProviderData) != 0 {
		t.Fatal("oversized optional profile retained")
	}
}

func TestScriptStandardIdentityClaims(t *testing.T) {
	p, err := NormalizeProfile([]byte(`{"user_id":"upstream","locale":"en","website":"https://profile.example/","address":{"country":"GB"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.ProviderData["locale"] != "en" || p.ProviderData["website"] != "https://profile.example/" {
		t.Fatal("standard script profile claims lost")
	}
	if p.ProviderData["address"].(map[string]any)["country"] != "GB" {
		t.Fatal("script address lost")
	}
}
