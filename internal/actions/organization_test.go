package actions_test

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions"
)

// Actual Action commands cannot spoof an organization's reserved claims,
// including when the grant has no organization claim to overwrite.
func TestOrganizationReservedClaims(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", actions.TriggerPostLogin, "org-spoof", `exports.onExecutePostLogin=async(event,api)=>{for(const token of [api.idToken,api.accessToken]){token.setCustomClaim("org_id","org_forged");token.setCustomClaim("org_name","forged");token.setCustomClaim("https://example.test/control","kept");}};`, nil, false)
	h.bind("t1", actions.TriggerPostLogin, a)
	result := h.mustPostLogin("t1")
	for i, custom := range []map[string]any{result.Effects.AccessClaims, result.Effects.IDClaims} {
		claims, err := actions.FilterClaims(actions.ClaimTarget(i), nil, custom, false)
		if err != nil {
			t.Fatal(err)
		}
		if claims["org_id"] != nil || claims["org_name"] != nil || claims["https://example.test/control"] != "kept" {
			t.Fatalf("custom claims=%v", claims)
		}
	}
}
