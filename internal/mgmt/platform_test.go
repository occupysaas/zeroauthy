package mgmt_test

import (
	"maps"
	"slices"
	"testing"
)

// Enabling platform alone is accepted, and every factor row keeps Auth0's
// exact shape: exported configuration (Deploy CLI dumps rows verbatim and
// sends them back on import) must stay deployable to Auth0. The console
// derives its platform-only warning from the enabled flags.
func TestPlatformRulesGuardian(t *testing.T) {
	e := newClientsEnv(t)
	r, _ := mfaCall(t, e, "SetGuardianFactor", "", "webauthn-platform", map[string]any{"enabled": true}, "")
	if r.Code != 200 {
		t.Fatalf("platform alone %d %s", r.Code, r.Body)
	}
	r, out := mfaCall(t, e, "GetGuardianFactors", "", "", nil, "")
	if r.Code != 200 {
		t.Fatalf("factors %d %s", r.Code, r.Body)
	}
	var found bool
	for _, entry := range out.([]any) {
		row := entry.(map[string]any)
		if keys := slices.Sorted(maps.Keys(row)); !slices.Equal(keys, []string{"enabled", "name", "trial_expired"}) {
			t.Fatalf("row %v has keys %v", row, keys)
		}
		if row["name"] == "webauthn-platform" {
			found = row["enabled"] == true
		}
	}
	if !found {
		t.Fatal("platform not enabled")
	}
}
