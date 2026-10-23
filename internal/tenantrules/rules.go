// Package tenantrules validates Management settings without HTTP or store access.
// Audience/directory existence must be checked within the tenant by the caller.
package tenantrules

import (
	"reflect"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/settingsrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type Error = settingsrules.Error

var schema = settingsrules.Parse(inventory)

var stringFields = map[string]string{"friendly_name": "FriendlyName", "picture_url": "PictureURL", "support_email": "SupportEmail", "support_url": "SupportURL", "default_audience": "DefaultAudience", "default_directory": "DefaultDirectory"}
var boolFields = map[string]string{"pushed_authorization_requests_supported": "PushedAuthorizationRequestsSupported", "skip_non_verifiable_callback_uri_confirmation_prompt": "SkipNonVerifiableCallbackURIConfirmationPrompt"}
var durationFields = map[string]string{"session_lifetime": "SessionLifetime", "idle_session_lifetime": "IdleSessionLifetime", "ephemeral_session_lifetime": "EphemeralSessionLifetime", "idle_ephemeral_session_lifetime": "IdleEphemeralSessionLifetime"}
var durationDefaults = map[string]int{"session_lifetime": 168 * 3600, "idle_session_lifetime": 72 * 3600, "ephemeral_session_lifetime": 72 * 3600, "idle_ephemeral_session_lifetime": 24 * 3600}

// Apply validates the complete patch before changing an independent copy.
// API hours/minutes are converted exactly to checked internal seconds. Null is
// accepted only where inventoried, resetting to local default/absence.
func Apply(current *store.Tenant, patch map[string]any) (*store.Tenant, error) {
	if current == nil {
		return nil, settingsrules.Invalid("", "tenant is required")
	}
	if err := schema.Validate(patch, ""); err != nil {
		return nil, err
	}
	for key := range durationFields {
		_, hours := patch[key]
		_, minutes := patch[key+"_in_minutes"]
		if hours && minutes {
			return nil, settingsrules.Invalid(key, "hours and minute alias cannot coexist")
		}
	}
	out := current.Clone()
	v := reflect.ValueOf(out).Elem()
	extra := store.CloneSettings(patch)
	for key, field := range stringFields {
		if value, ok := patch[key]; ok {
			v.FieldByName(field).SetString(value.(string))
			delete(extra, key)
		}
	}
	if picture, ok := patch["picture_url"]; ok {
		out.Branding.LogoURL = picture.(string)
	}
	for key, field := range boolFields {
		if value, ok := patch[key]; ok {
			b, _ := value.(bool)
			v.FieldByName(field).SetBool(b)
			delete(extra, key)
		}
	}
	for key, field := range durationFields {
		raw, ok := patch[key]
		unit := int64(3600)
		alias := key + "_in_minutes"
		if minute, exists := patch[alias]; exists {
			raw, ok, unit = minute, true, 60
		}
		if ok {
			n, _ := settingsrules.Integer(raw)
			maxInt := int64(^uint(0) >> 1)
			if n > maxInt/unit {
				return nil, settingsrules.Invalid(key, "duration overflows seconds")
			}
			v.FieldByName(field).SetInt(n * unit)
			delete(extra, key)
			delete(extra, alias)
		}
	}
	for key, field := range map[string]string{"allowed_logout_urls": "AllowedLogoutURLs", "enabled_locales": "EnabledLocales"} {
		if raw, ok := patch[key]; ok {
			v.FieldByName(field).Set(reflect.ValueOf(stringsArray(raw)))
			delete(extra, key)
		}
	}
	if raw, ok := patch["device_flow"]; ok {
		if raw == nil {
			out.DeviceFlowCharset = ""
			out.DeviceFlowMask = ""
			delete(out.SettingsPresence, "device_flow.mask")
		} else {
			obj := raw.(map[string]any)
			if x, ok := obj["charset"]; ok {
				out.DeviceFlowCharset = x.(string)
			}
			if x, ok := obj["mask"]; ok {
				out.DeviceFlowMask = x.(string)
				if out.SettingsPresence == nil {
					out.SettingsPresence = map[string]bool{}
				}
				out.SettingsPresence["device_flow.mask"] = true
			}
		}
		delete(extra, "device_flow")
	}
	if raw, ok := patch["session_cookie"]; ok {
		out.SessionCookieMode = ""
		if raw != nil {
			out.SessionCookieMode = raw.(map[string]any)["mode"].(string)
		}
		delete(extra, "session_cookie")
	}
	out.SettingsExtra = settingsrules.Merge(out.SettingsExtra, extra)
	// Remove any shadowed legacy/foreign Extra fields, even if this patch did not
	// mention them. Typed runtime settings are the single source of truth.
	for key := range stringFields {
		delete(out.SettingsExtra, key)
	}
	for key := range boolFields {
		delete(out.SettingsExtra, key)
	}
	for key := range durationFields {
		delete(out.SettingsExtra, key)
		delete(out.SettingsExtra, key+"_in_minutes")
	}
	for _, key := range []string{"allowed_logout_urls", "enabled_locales", "device_flow", "session_cookie"} {
		delete(out.SettingsExtra, key)
	}
	return out, nil
}
func stringsArray(raw any) []string {
	switch a := raw.(type) {
	case []string:
		out := make([]string, len(a))
		copy(out, a)
		return out
	case []any:
		out := make([]string, len(a))
		for i, v := range a {
			out[i] = v.(string)
		}
		return out
	}
	return nil
}

// Public returns canonical public settings. Stored-only fields retain presence;
// enforced settings use explicit local defaults, unlike Auth0's sparse GET.
// Every returned nested map/slice is independent of stored state.
func Public(t *store.Tenant) map[string]any {
	if t == nil {
		return map[string]any{}
	}
	out := store.CloneSettings(t.SettingsExtra)
	if out == nil {
		out = map[string]any{}
	}
	// Extra is not an escape hatch to emit unknown roots or write-only aliases.
	for key := range out {
		if _, ok := schema.Properties[key]; !ok || strings.HasSuffix(key, "_in_minutes") {
			delete(out, key)
		}
	}
	v := reflect.ValueOf(t).Elem()
	for key, field := range stringFields {
		out[key] = v.FieldByName(field).String()
	}
	for key, field := range boolFields {
		out[key] = v.FieldByName(field).Bool()
	}
	for key, field := range durationFields {
		seconds := int(v.FieldByName(field).Int())
		if seconds == 0 {
			seconds = durationDefaults[key]
		}
		out[key] = float64(seconds) / 3600
	}
	out["allowed_logout_urls"] = stringsArray(t.AllowedLogoutURLs)
	if len(t.EnabledLocales) == 0 {
		out["enabled_locales"] = []string{"en"}
	} else {
		out["enabled_locales"] = stringsArray(t.EnabledLocales)
	}
	charset, mask := t.DeviceFlowCharset, t.DeviceFlowMask
	if charset == "" {
		charset = "base20"
	}
	if mask == "" && !t.SettingsPresence["device_flow.mask"] {
		mask = "****-****"
	}
	out["device_flow"] = map[string]any{"charset": charset, "mask": mask}
	mode := t.SessionCookieMode
	if mode == "" {
		mode = "persistent"
	}
	out["session_cookie"] = map[string]any{"mode": mode}
	return out
}
