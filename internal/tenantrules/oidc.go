package tenantrules

import (
	"github.com/zeroauthy/zeroauthy/internal/claims"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"slices"
)

// ACRValuesSupported intersects tenant choices with implemented contexts.
// An absent/null choice uses the supported default; an empty list disables it.
func ACRValuesSupported(t *store.Tenant) []string {
	if t == nil {
		return []string{claims.ACRMultiFactor}
	}
	raw, exists := t.SettingsExtra["acr_values_supported"]
	if !exists || raw == nil {
		return []string{claims.ACRMultiFactor}
	}
	switch values := raw.(type) {
	case []any:
		for _, value := range values {
			if value == claims.ACRMultiFactor {
				return []string{claims.ACRMultiFactor}
			}
		}
	case []string:
		if slices.Contains(values, claims.ACRMultiFactor) {
			return []string{claims.ACRMultiFactor}
		}
	}
	return []string{}
}
