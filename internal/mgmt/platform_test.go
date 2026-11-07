package mgmt_test

import "testing"

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
		if row["name"] == "webauthn-platform" {
			found = true
			if row["requires_other_factor"] != true {
				t.Fatalf("warning %v", row)
			}
		}
	}
	if !found {
		t.Fatal("platform missing")
	}
	r, _ = mfaCall(t, e, "SetGuardianFactor", "", "otp", map[string]any{"enabled": true}, "")
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	_, out = mfaCall(t, e, "GetGuardianFactors", "", "", nil, "")
	for _, entry := range out.([]any) {
		row := entry.(map[string]any)
		if row["name"] == "webauthn-platform" && row["requires_other_factor"] != false {
			t.Fatalf("stale warning %v", row)
		}
	}
}
