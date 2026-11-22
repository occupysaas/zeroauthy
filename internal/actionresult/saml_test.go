package actionresult

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

// The Action-supplied SAML signing key serializes under a name the log
// scrubber hides (AGENTS.md: extend logscrub for secret-bearing fields).
func TestSAMLKeyNameIsScrubbed(t *testing.T) {
	raw, _ := json.Marshal(SAMLEffects{Key: "pem"})
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for name := range m {
		if !logscrub.SensitiveKey(name) {
			t.Fatalf("field %q carrying the private key is not scrubbed (%s)", name, strings.TrimSpace(string(raw)))
		}
	}
}
