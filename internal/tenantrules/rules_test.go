package tenantrules

import (
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"reflect"
	"strings"
	"testing"
)

func TestTenantSettingsDurations(t *testing.T) {
	seed := &store.Tenant{SessionLifetime: 3600}
	if got := Public(seed)["session_lifetime"]; got != float64(1) {
		t.Fatalf("seed hours = %v", got)
	}
	for _, tc := range []struct {
		key     string
		value   any
		seconds int
		hours   float64
	}{{"session_lifetime", 1, 3600, 1}, {"session_lifetime_in_minutes", 90, 5400, 1.5}, {"session_lifetime", json.Number("2"), 7200, 2}} {
		out, err := Apply(seed, map[string]any{tc.key: tc.value})
		if err != nil {
			t.Fatal(err)
		}
		if out.SessionLifetime != tc.seconds || Public(out)["session_lifetime"] != tc.hours {
			t.Fatalf("duration = %+v", out)
		}
		if _, ok := Public(out)["session_lifetime_in_minutes"]; ok {
			t.Fatal("write alias leaked")
		}
	}
	for _, p := range []map[string]any{{"session_lifetime": 1.5}, {"session_lifetime": 0}, {"session_lifetime": nil}, {"session_lifetime": 1, "session_lifetime_in_minutes": 60}, {"session_lifetime": json.Number("9223372036854775807")}} {
		if _, err := Apply(seed, p); err == nil {
			t.Fatalf("accepted %v", p)
		}
	}
	if seed.SessionLifetime != 3600 {
		t.Fatal("mutated seed")
	}
}
func TestTenantSettingsPartialPatch(t *testing.T) {
	current := &store.Tenant{DeviceFlowCharset: "digits", DeviceFlowMask: "***", SettingsExtra: map[string]any{"flags": map[string]any{"enable_sso": true, "enable_pipeline2": true}}}
	out, err := Apply(current, map[string]any{"device_flow": map[string]any{"mask": "****"}, "flags": map[string]any{"enable_sso": false}, "allowed_logout_urls": []any{}, "session_cookie": map[string]any{"mode": "non-persistent"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.DeviceFlowCharset != "digits" || out.DeviceFlowMask != "****" || out.SessionCookieMode != "non-persistent" {
		t.Fatalf("patch = %+v", out)
	}
	flags := Public(out)["flags"].(map[string]any)
	if flags["enable_sso"] != false || flags["enable_pipeline2"] != true {
		t.Fatal(flags)
	}
	flags["enable_pipeline2"] = false
	if Public(current)["flags"].(map[string]any)["enable_sso"] != true || Public(out)["flags"].(map[string]any)["enable_pipeline2"] != true {
		t.Fatal("shared nested data")
	}
	before := current.Clone()
	for _, p := range []map[string]any{{}, {"unknown": true}, {"flags": nil}, {"flags": map[string]any{"disable_impersonation": false}}, {"device_flow": map[string]any{"unknown": true}}, {"sessions": map[string]any{"mode": "persistent"}}, {"enabled_locales": []string{}}, {"enabled_locales": []string{"bogus"}}} {
		if _, err := Apply(current, p); err == nil {
			t.Fatalf("accepted %v", p)
		}
	}
	if !reflect.DeepEqual(before, current) {
		t.Fatal("rejected patch changed input")
	}
}
func TestTenantSettingsInventory(t *testing.T) {
	for _, p := range []map[string]any{
		{"support_email": "name@example.com", "support_url": "https://example.com/help"},
		{"country_codes": map[string]any{"list": []string{"US"}, "mode": "allow"}},
		{"access_token": map[string]any{"claims_mapping": map[string]any{"custom_claims": []any{map[string]any{"name": "role", "expression": "app_metadata.role"}}}}},
		{"default_token_quota": map[string]any{"clients": map[string]any{"client_credentials": map[string]any{"per_day": 1}, "extension": true}}},
		{"device_flow": nil, "pushed_authorization_requests_supported": nil},
	} {
		if _, err := Apply(&store.Tenant{}, p); err != nil {
			t.Fatalf("valid %v: %v", p, err)
		}
	}
	for _, p := range []map[string]any{
		{"support_email": "Display <name@example.com>"}, {"default_redirection_uri": "http://example.com"}, {"sandbox_version": "123456789"},
		{"country_codes": map[string]any{"list": []string{"us"}}}, {"default_token_quota": map[string]any{}},
		{"default_token_quota": map[string]any{"clients": map[string]any{}}},
		{"sessions": map[string]any{"anonymous": map[string]any{"lifetime_in_minutes": 525601}}},
		{"access_token": map[string]any{"claims_mapping": map[string]any{"custom_claims": []any{map[string]any{"name": "role"}}}}},
	} {
		if _, err := Apply(&store.Tenant{}, p); err == nil {
			t.Fatalf("accepted %v", p)
		}
	}
}

func TestTenantSettingsExplicitEmptyMask(t *testing.T) {
	out, err := Apply(&store.Tenant{}, map[string]any{"device_flow": map[string]any{"mask": ""}})
	if err != nil {
		t.Fatal(err)
	}
	if got := Public(out)["device_flow"].(map[string]any)["mask"]; got != "" {
		t.Fatalf("explicit empty mask lost: %v", got)
	}
	reset, err := Apply(out, map[string]any{"device_flow": nil})
	if err != nil {
		t.Fatal(err)
	}
	if got := Public(reset)["device_flow"].(map[string]any)["mask"]; got != "****-****" {
		t.Fatalf("reset mask = %v", got)
	}
}
func TestTenantSettingsExtraCannotShadowTyped(t *testing.T) {
	current := &store.Tenant{SessionLifetime: 3600, SupportEmail: "real@example.com", SettingsExtra: map[string]any{"session_lifetime": 999, "session_lifetime_in_minutes": 99, "support_email": "fake@example.com", "device_flow": map[string]any{"charset": "evil"}}}
	got := Public(current)
	if got["session_lifetime"] != float64(1) || got["support_email"] != "real@example.com" || got["device_flow"].(map[string]any)["charset"] != "base20" {
		t.Fatal(got)
	}
	if _, ok := got["session_lifetime_in_minutes"]; ok {
		t.Fatal("minute alias leaked")
	}
}

func TestTenantSettingsNestedSecurityHeaders(t *testing.T) {
	valid := map[string]any{"security_headers": map[string]any{"content_security_policy": map[string]any{"policies": []any{map[string]any{"mode": "reporting", "directives": map[string]any{"script-src": []any{"'self'"}}, "flags": []string{"upgrade-insecure-requests"}, "reporting": map[string]any{"report_uri": "/report"}}}}}}
	if _, err := Apply(&store.Tenant{}, valid); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []map[string]any{{"mode": "other"}, {"flags": []string{"unsafe-inline"}}, {"directives": map[string]any{"script-src": "'self'"}}, {"reporting": map[string]any{"unknown": true}}} {
		_, err := Apply(&store.Tenant{}, map[string]any{"security_headers": map[string]any{"content_security_policy": map[string]any{"policies": []any{policy}}}})
		var fieldError *Error
		if !errors.As(err, &fieldError) || !errors.Is(err, store.ErrInvalid) || !strings.HasPrefix(fieldError.Field, "security_headers.content_security_policy.policies[0].") {
			t.Fatalf("missing nested path: %v", err)
		}
	}
}

func TestPictureURLCanonicalBranding(t *testing.T) {
	current := &store.Tenant{Branding: store.Branding{LogoURL: "https://example.test/old"}}
	out, err := Apply(current, map[string]any{"picture_url": "https://example.test/new"})
	if err != nil || out.Branding.LogoURL != "https://example.test/new" {
		t.Fatal("picture does not update runtime branding", err)
	}
	out, err = Apply(current, map[string]any{"friendly_name": "Name"})
	if err != nil || out.Branding.LogoURL != current.Branding.LogoURL {
		t.Fatal("omission changed branding", err)
	}
}
