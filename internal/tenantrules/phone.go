package tenantrules

import (
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// protectionKey is the hidden SettingsExtra key behind the
// attack-protection/phone-provider-protection routes. It is not part of the
// tenant settings schema, so Public never returns it and PATCH /tenants/settings
// cannot set it.
const protectionKey = "phone_provider_protection"

// ProtectionTypes are the accepted phone-provider-protection values.
var ProtectionTypes = []string{"default", "exponential"}

// CountryCodes is the allow or deny list of ISO 3166-1 alpha-2 countries.
type CountryCodes struct {
	List []string
	Mode string // allow|deny
}

// PhoneSettings are the enforced phone-related tenant settings (D-0060 P9,
// P14, P20). Delivery and passwordless code read them through PhoneSettingsOf.
type PhoneSettings struct {
	// Consolidated routes MFA, passwordless SMS, phone reset and verification
	// through the branding provider and templates. Absent on existing tenants
	// is false; tenants created after Plan 34 start true.
	Consolidated bool
	// CountryCodes is nil when no restriction is set.
	CountryCodes                         *CountryCodes
	EnforceClientAuthOnPasswordlessStart bool
	// DisableSMSObfuscation is Auth0's documented default true.
	DisableSMSObfuscation bool
	ProviderProtection    string // default|exponential
}

// PhoneSettingsOf reads the phone settings of a tenant with local defaults.
func PhoneSettingsOf(t *store.Tenant) PhoneSettings {
	s := PhoneSettings{DisableSMSObfuscation: true, ProviderProtection: "default"}
	if t == nil {
		return s
	}
	x := t.SettingsExtra
	if b, ok := x["phone_consolidated_experience"].(bool); ok {
		s.Consolidated = b
	}
	if flags, ok := x["flags"].(map[string]any); ok {
		if b, ok := flags["enforce_client_authentication_on_passwordless_start"].(bool); ok {
			s.EnforceClientAuthOnPasswordlessStart = b
		}
		if b, ok := flags["disable_management_api_sms_obfuscation"].(bool); ok {
			s.DisableSMSObfuscation = b
		}
	}
	if cc, ok := x["country_codes"].(map[string]any); ok {
		c := &CountryCodes{Mode: "allow", List: stringsArray(cc["list"])}
		if m, ok := cc["mode"].(string); ok && m != "" {
			c.Mode = m
		}
		s.CountryCodes = c
	}
	if p, ok := x[protectionKey].(string); ok && slices.Contains(ProtectionTypes, p) {
		s.ProviderProtection = p
	}
	return s
}

// CountryAllowed reports whether an SMS or voice destination in the ISO
// alpha-2 country may be messaged.
func (s PhoneSettings) CountryAllowed(country string) bool {
	if s.CountryCodes == nil {
		return true
	}
	in := slices.Contains(s.CountryCodes.List, country)
	if s.CountryCodes.Mode == "deny" {
		return !in
	}
	return in
}

// WithProviderProtection returns a copy of t with the protection type set.
func WithProviderProtection(t *store.Tenant, typ string) *store.Tenant {
	out := t.Clone()
	if out.SettingsExtra == nil {
		out.SettingsExtra = map[string]any{}
	}
	out.SettingsExtra[protectionKey] = typ
	return out
}

// ApplyNewTenantDefaults sets the defaults of a tenant created now (P9).
func ApplyNewTenantDefaults(t *store.Tenant) {
	if t.SettingsExtra == nil {
		t.SettingsExtra = map[string]any{}
	}
	if _, ok := t.SettingsExtra["phone_consolidated_experience"]; !ok {
		t.SettingsExtra["phone_consolidated_experience"] = true
	}
}
