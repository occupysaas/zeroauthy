package brandingrules

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
	"testing"
)

func TestBrandingMergePresence(t *testing.T) {
	current := &store.HostedLoginConfig{TenantID: "t1", Branding: map[string]any{"colors": map[string]any{"primary": "#112233", "page_background": "#ffffff"}, "logo_url": "https://example.test/logo.svg"}}
	next, err := Merge(current, "branding", []byte(`{"colors":{"primary":"#abcdef"},"logo_url":null}`))
	if err != nil {
		t.Fatal(err)
	}
	colors := next.Branding["colors"].(map[string]any)
	if colors["primary"] != "#abcdef" || colors["page_background"] != "#ffffff" {
		t.Fatalf("merge lost nested colors: %#v", colors)
	}
	if _, ok := next.Branding["logo_url"]; ok {
		t.Fatalf("null failed to clear URL: %#v", next.Branding)
	}
	if current.Branding["logo_url"] != "https://example.test/logo.svg" {
		t.Fatal("input was mutated")
	}
	if _, err = Merge(next, "branding", []byte(`{"colors":{"primary":null}}`)); err == nil {
		t.Fatal("required color accepted null")
	}
}
func TestThemeDefaultLifecycle(t *testing.T) {
	c := &store.HostedLoginConfig{TenantID: "t1"}
	first, err := Merge(c, "theme:create", []byte(`{"colors":{"primary_button":"#112233"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.DefaultThemeID) != 32 {
		t.Fatalf("bad theme id %q", first.DefaultThemeID)
	}
	firstID := first.DefaultThemeID
	second, err := Merge(first, "theme:create", []byte(`{"colors":{"primary_button":"#445566"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if second.DefaultThemeID == firstID || len(second.Themes) != 2 {
		t.Fatal("new theme did not become default while retaining old theme")
	}
	deleted, err := Merge(second, "theme:delete:"+second.DefaultThemeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.DefaultThemeID != "" || len(deleted.Themes) != 1 {
		t.Fatal("delete reactivated old theme or removed it")
	}
}
func TestHostedLoginLimits(t *testing.T) {
	c := &store.HostedLoginConfig{TenantID: "t1", CustomText: store.CustomText{"login": {"en": {"login": {"title": strings.Repeat("a", 1<<20)}}}}}
	if err := Validate(c); err == nil {
		t.Fatal("oversized new aggregate accepted")
	}
	smaller := c.Clone()
	smaller.CustomText["login"]["en"]["login"]["title"] = strings.Repeat("a", (1<<20)-1)
	if err := ValidateUpdate(c, smaller); err != nil {
		t.Fatalf("oversize reduction rejected: %v", err)
	}
	if err := ValidateUpdate(c, c); err == nil {
		t.Fatal("nonreducing oversize update accepted")
	}
}
func TestLegacyProjection(t *testing.T) {
	tenant := &store.Tenant{ID: "t1", Branding: store.Branding{LogoURL: "https://example.test/a.svg", PrimaryColor: "#010203"}, CustomText: store.CustomText{"login": {"en": {"login": {"title": "Welcome"}}}}}
	c := FromLegacy(tenant)
	if c.Branding["logo_url"] != "https://example.test/a.svg" || c.CustomText["login"]["en"]["login"]["title"] != "Welcome" {
		t.Fatalf("legacy projection lost values: %#v", c)
	}
	c.CustomText["login"]["en"]["login"]["title"] = "Changed"
	if tenant.CustomText["login"]["en"]["login"]["title"] != "Welcome" {
		t.Fatal("legacy text mutated")
	}
}
func TestPromptDisposition(t *testing.T) {
	c := &store.HostedLoginConfig{TenantID: "t1"}
	n, err := Merge(c, "prompts", []byte(`{"identifier_first":true,"webauthn_platform_first_factor":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if n.Prompts["identifier_first"] != true || n.Prompts["webauthn_platform_first_factor"] != true {
		t.Fatalf("lost prompt fields: %#v", n.Prompts)
	}
	if _, err := Merge(n, "prompts", []byte(`{"invented_feature":true}`)); err == nil {
		t.Fatal("unknown prompt accepted")
	}
}

func TestThemeRejectsUnknownNestedField(t *testing.T) {
	c := &store.HostedLoginConfig{TenantID: "t1"}
	if _, err := Merge(c, "theme:create", []byte(`{"colors":{"invented":"#112233"}}`)); err == nil {
		t.Fatal("unknown theme color silently accepted")
	}
}
func TestThemeCountBound(t *testing.T) {
	c := &store.HostedLoginConfig{TenantID: "t1"}
	for i := 0; i < 20; i++ {
		var err error
		c, err = Merge(c, "theme:create", []byte(`{"colors":{"primary_button":"#112233"}}`))
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Merge(c, "theme:create", []byte(`{"colors":{"primary_button":"#112233"}}`)); err == nil {
		t.Fatal("21st theme accepted")
	}
}

func TestDeployPromptDiscoveryFutureGroups(t *testing.T) {
	for _, prompt := range []string{"mfa-push", "phone-identifier-enrollment", "login-email-verification", "common", "captcha", "brute-force-protection"} {
		if !ValidTextPrompt(prompt) {
			t.Errorf("pinned deploy client probes documented future text group %q", prompt)
		}
	}
	if ValidTextPrompt("unrecognized-prompt") {
		t.Fatal("unknown group accepted")
	}
}
