package logscrub_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

func FuzzScrub(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3}, "hunter2!!")
	f.Add([]byte{3, 2, 1, 0, 3}, `{"Password":"secret"}`)
	f.Fuzz(func(t *testing.T, shape []byte, value string) {
		// Every generated level wraps a sensitive property independently of the
		// production SensitiveKey implementation. Limit test work, not scrub depth.
		if len(shape) > 12 {
			shape = shape[:12]
		}
		var doc any = map[string]any{"Password": value, "public": "keep"}
		for _, b := range shape {
			switch b % 4 {
			case 0:
				doc = map[string]any{"nested": doc, "x-api-key": value}
			case 1:
				doc = []any{doc, map[string]any{"client_secret": []any{value}}}
			case 2:
				encoded, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				doc = map[string]any{"body": string(encoded), "otp_code": 7}
			case 3:
				doc = map[string]any{"metadata": doc, "private_key": nil}
			}
		}
		input, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		output, err := logscrub.Scrub(input)
		if err != nil {
			t.Fatal(err)
		}
		var got any
		if err := json.Unmarshal(output, &got); err != nil {
			t.Fatal(err)
		}
		assertNoSecrets(t, got)
	})
}

func assertNoSecrets(t *testing.T, v any) {
	t.Helper()
	switch v := v.(type) {
	case map[string]any:
		for key, value := range v {
			switch key {
			case "Password", "x-api-key", "client_secret", "otp_code", "private_key":
				if value != "[REDACTED]" {
					t.Fatalf("sensitive key %q retained %#v", key, value)
				}
			default:
				assertNoSecrets(t, value)
			}
		}
	case []any:
		for _, value := range v {
			assertNoSecrets(t, value)
		}
	case string:
		if strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[") {
			var nested any
			if json.Unmarshal([]byte(v), &nested) == nil {
				assertNoSecrets(t, nested)
			}
		}
	}
}
