package logstream

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// These exact outbound payloads are asserted by the mounted StreamEdit tests.
// Keep server validation real: an accepting frontend HTTP fake cannot prove it.
func TestConsolePayloadsConfigure(t *testing.T) {
	body, err := os.ReadFile("testdata/console-payloads.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]map[string]json.RawMessage
	if err = json.Unmarshal(body, &fixtures); err != nil {
		t.Fatal(err)
	}
	for name, raw := range fixtures {
		t.Run(name, func(t *testing.T) {
			stream := &store.LogStream{Type: "http", Status: "active", Sink: map[string]any{"httpEndpoint": "https://sink.example.test", "httpContentType": "application/json", "httpContentFormat": "JSONLINES"}}
			private := map[string]any{"httpAuthorization": "previous-secret"}
			if name == "configured" {
				stream.PII = &store.LogStreamPII{LogFields: []string{"email"}, Method: "mask", Algorithm: "xxhash"}
			}
			if err := Configure(stream, raw, name == "create", false, private); err != nil {
				t.Fatal(err)
			}
			if name == "configured" {
				if stream.PII == nil || stream.PII.Method != "hash" {
					t.Fatal(stream.PII)
				}
			} else if stream.PII != nil {
				t.Fatal("unexpected PII", stream.PII)
			}
		})
	}
}
