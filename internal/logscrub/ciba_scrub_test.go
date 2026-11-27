package logscrub

import (
	"strings"
	"testing"
)

// TestCIBAAuthReqIDScrubbed: the CIBA auth_req_id (Plan 41c) redeems
// tokens; no log carries it under its name.
func TestCIBAAuthReqIDScrubbed(t *testing.T) {
	for _, k := range []string{"auth_req_id", "authReqId", "AUTH-REQ-ID"} {
		if !SensitiveKey(k) {
			t.Errorf("%s not sensitive", k)
		}
	}
	out, err := Scrub([]byte(`{"auth_req_id":"req-value-0123456789","expires_in":600,"interval":5}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "req-value-0123456789") || !strings.Contains(string(out), `"interval":5`) {
		t.Fatalf("scrubbed %s", out)
	}
}
