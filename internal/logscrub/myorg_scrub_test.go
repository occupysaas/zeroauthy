package logscrub

import (
	"strings"
	"testing"
)

// TestMyOrgSCIMTokenScrubbed: the My Organization API's SCIM token create
// response (Plan 42b Phase B) never reaches a log with its token value,
// and the identity provider options' client_secret neither.
func TestMyOrgSCIMTokenScrubbed(t *testing.T) {
	for _, k := range []string{"token", "client_secret"} {
		if !SensitiveKey(k) {
			t.Errorf("%s not sensitive", k)
		}
	}
	out, err := Scrub([]byte(`{"token_id":"tok_1","token":"scim-token-value-123","options":{"client_secret":"s3cret-value"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "scim-token-value-123") || strings.Contains(string(out), "s3cret-value") {
		t.Fatalf("scrubbed %s", out)
	}
}
