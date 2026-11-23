package logscrub_test

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

// A WS-Fed wresult is a bearer token (Plan 37b): its form field is hidden
// wherever it is logged, as SAML responses' values are.
func TestWSFedTokenKeys(t *testing.T) {
	for _, key := range []string{"wresult", "WResult", "w_result"} {
		if !logscrub.SensitiveKey(key) {
			t.Errorf("WS-Fed token key %q is public", key)
		}
		got := logscrub.ScrubValue(map[string]any{key: "<t:RequestSecurityTokenResponse/>", "wctx": "visible"}).(map[string]any)
		if got[key] != logscrub.Marker || got["wctx"] != "visible" {
			t.Errorf("WS-Fed token field %q not scrubbed: %v", key, got)
		}
	}
}
