package logscrub

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScrubWebAuthnKeys(t *testing.T) {
	for _, key := range []string{"authn_response", "auth_session", "attestationObject", "authenticatorData", "clientDataJSON", "signature", "userHandle", "user_handle", "challenge_id"} {
		for _, k := range []string{key, strings.ToUpper(key), "prefix-" + key} {
			t.Run(k, func(t *testing.T) {
				doc, _ := json.Marshal(map[string]any{"nested": []any{map[string]any{k: "secret-value"}}, "plain": "visible"})
				out, err := Scrub(doc)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(out), "secret-value") || !strings.Contains(string(out), "visible") {
					t.Fatalf("scrub = %s", out)
				}
			})
		}
	}
}

func TestScrubWebAuthnKeysEmbeddedJSON(t *testing.T) {
	inner, _ := json.Marshal(map[string]any{"deep": []any{map[string]any{"UsEr_HaNdLe": "secret-handle", "CLIENTDATAJSON": "secret-client"}}})
	doc, _ := json.Marshal(map[string]any{"outer": []any{map[string]any{"encoded": string(inner)}}})
	out, err := Scrub(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "secret-") {
		t.Fatalf("embedded secret: %s", out)
	}
}
