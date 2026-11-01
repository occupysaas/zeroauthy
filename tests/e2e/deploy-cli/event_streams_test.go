package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/deploymigration"
)

func TestEventStreamMigrationComparator(t *testing.T) {
	m := Manifest{Resources: []ManifestResource{{Name: "eventStreams", Status: "included"}, {Name: "actions", Status: "included"}}}
	b, err := os.ReadFile("fixtures/event-streams.json")
	if err != nil {
		t.Fatal(err)
	}
	makeExport := func(raw []byte) deploymigration.Export {
		return deploymigration.Export{Resources: map[string]json.RawMessage{"eventStreams": raw, "actions": json.RawMessage(`[{"name":"Deploy event-stream"}]`)}}
	}
	var rows []map[string]any
	json.Unmarshal(b, &rows)
	for i, row := range rows {
		row["id"] = string(rune('a' + i))
	}
	dst, _ := json.Marshal(rows)
	if r := Compare(makeExport(b), makeExport(dst), m, Domains{}); !r.Equivalent {
		t.Fatalf("generated IDs differ: %+v", r.Differences)
	}
	for _, field := range []string{"name", "subscriptions", "destination", "status"} {
		t.Run(field, func(t *testing.T) {
			var changed []map[string]any
			json.Unmarshal(dst, &changed)
			delete(changed[0], field)
			bad, _ := json.Marshal(changed)
			if Compare(makeExport(b), makeExport(bad), m, Domains{}).Equivalent {
				t.Fatalf("lost %s accepted", field)
			}
		})
	}
}
func TestEventStreamManifestFixture(t *testing.T) {
	m, err := LoadManifest("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range m.Resources {
		if entry.Name == "eventStreams" {
			if entry.Status != "included" || entry.Fixture == nil {
				t.Fatal("eventStreams still excluded")
			}
			if _, err = os.Stat(filepath.Clean(*entry.Fixture)); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("missing eventStreams handler")
}

// Action IDs may be destination-local; matching is restricted to the Action
// inventory of each export. Opaque webhook strings must never be rewritten.
func TestEventStreamActionReferencesAndSecretPrivacy(t *testing.T) {
	m := Manifest{Resources: []ManifestResource{{Name: "actions", Status: "included"}, {Name: "eventStreams", Status: "included"}}}
	makeExport := func(id, ref string) deploymigration.Export {
		return deploymigration.Export{Resources: map[string]json.RawMessage{
			"actions":      json.RawMessage(`[{"id":"` + id + `","name":"Receive","supported_triggers":[{"id":"event-stream","version":"v1"}]}]`),
			"eventStreams": json.RawMessage(`[{"name":"Events","status":"disabled","subscriptions":[{"event_type":"user.created"}],"destination":{"type":"action","configuration":{"action_id":"` + ref + `"}}}]`),
		}}
	}
	source, target := makeExport("source-action", "source-action"), makeExport("target-action", "target-action")
	if r := Compare(source, target, m, Domains{}); !r.Equivalent {
		t.Fatalf("logical Action references differ: %+v", r.Differences)
	}
	for _, ref := range []string{"foreign-action", ""} {
		bad := makeExport("target-action", ref)
		if Compare(bad, bad, m, Domains{}).Equivalent {
			t.Fatal("dangling Action reference passed")
		}
	}
	source = makeExport("source-action", "Receive")
	target = makeExport("target-action", "Receive")
	if r := Compare(source, target, m, Domains{}); !r.Equivalent {
		t.Fatalf("canonical Action name references differ: %+v", r.Differences)
	}
	m = Manifest{Resources: []ManifestResource{{Name: "eventStreams", Status: "included"}}}
	for _, field := range []string{"token", "password", "header_value"} {
		raw := json.RawMessage(`[{"name":"Events","destination":{"type":"webhook","configuration":{"webhook_endpoint":"https://source.test/intake","webhook_authorization":{"method":"bearer","` + field + `":"opaque-private-value"}}}}]`)
		e := deploymigration.Export{Resources: map[string]json.RawMessage{"eventStreams": raw}}
		r := Compare(e, e, m, Domains{})
		if r.Equivalent {
			t.Fatal("public export secret accepted")
		}
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), "opaque-private-value") {
			t.Fatal("report leaked credential")
		}
	}
}

func TestEventStreamPinnedCredentialPlaceholders(t *testing.T) {
	m := Manifest{Resources: []ManifestResource{{Name: "eventStreams", Status: "included"}}}
	for _, tc := range []struct{ method, field, marker string }{{"bearer", "token", "##EVENT_STREAM_WEBHOOK_BEARER_TOKEN##"}, {"basic", "password", "##EVENT_STREAM_WEBHOOK_BASIC_AUTH_PASSWORD##"}, {"custom_header", "header_value", "##EVENT_STREAM_WEBHOOK_HEADER_VALUE##"}} {
		t.Run(tc.method, func(t *testing.T) {
			makeExport := func(value string) deploymigration.Export {
				row := map[string]any{"name": "Events", "destination": map[string]any{"type": "webhook", "configuration": map[string]any{"webhook_authorization": map[string]any{"method": tc.method, tc.field: value}}}}
				b, err := json.Marshal([]any{row})
				if err != nil {
					t.Fatal(err)
				}
				return deploymigration.Export{Resources: map[string]json.RawMessage{"eventStreams": b}}
			}
			e := makeExport(tc.marker)
			if r := Compare(e, e, m, Domains{}); !r.Equivalent {
				t.Fatalf("pinned nonsecret placeholder rejected: %+v", r.Differences)
			}
			if Compare(e, makeExport("##ARBITRARY_SECRET##"), m, Domains{}).Equivalent {
				t.Fatal("arbitrary marker accepted")
			}
		})
	}
}
