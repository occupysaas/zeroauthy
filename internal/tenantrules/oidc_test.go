package tenantrules

import (
	"github.com/zeroauthy/zeroauthy/internal/claims"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"reflect"
	"testing"
)

func TestEffectiveACRValues(t *testing.T) {
	for _, tc := range []struct {
		settings map[string]any
		want     []string
	}{
		{nil, []string{claims.ACRMultiFactor}},
		{map[string]any{"acr_values_supported": nil}, []string{claims.ACRMultiFactor}},
		{map[string]any{"acr_values_supported": []any{}}, []string{}},
		{map[string]any{"acr_values_supported": []any{"unknown", claims.ACRMultiFactor, claims.ACRMultiFactor}}, []string{claims.ACRMultiFactor}},
	} {
		if got := ACRValuesSupported(&store.Tenant{SettingsExtra: tc.settings}); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("settings=%v got=%v want=%v", tc.settings, got, tc.want)
		}
	}
}
