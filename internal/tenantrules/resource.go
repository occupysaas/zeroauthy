package tenantrules

import "github.com/zeroauthy/zeroauthy/internal/store"

func ResourceParameterProfile(t *store.Tenant) string {
	if t != nil && t.SettingsExtra["resource_parameter_profile"] == "compatibility" {
		return "compatibility"
	}
	return "audience"
}

// ResourceAudience canonicalizes the compatibility alias before audience and
// consent checks. The default profile ignores the resource parameter entirely.
func ResourceAudience(t *store.Tenant, audience string, resources []string) (string, string) {
	if ResourceParameterProfile(t) != "compatibility" || len(resources) == 0 {
		return audience, ""
	}
	if len(resources) != 1 || resources[0] == "" {
		return "", "invalid_target"
	}
	if audience != "" && audience != resources[0] {
		return "", "invalid_request"
	}
	return resources[0], ""
}
