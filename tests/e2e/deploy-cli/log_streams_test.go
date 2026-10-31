package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/deploymigration"
)

func TestLogStreamMigrationComparator(t *testing.T) {
	m := Manifest{Resources: []ManifestResource{{Name: "logStreams", Status: "included"}}}
	b, err := os.ReadFile("fixtures/log-streams.json")
	if err != nil {
		t.Fatal(err)
	}
	makeExport := func(raw []byte) deploymigration.Export {
		return deploymigration.Export{Resources: map[string]json.RawMessage{"logStreams": raw}}
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
	for _, field := range []string{"name", "type", "status", "sink", "filters", "pii_config", "isPriority"} {
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
func TestLogStreamManifestFixture(t *testing.T) {
	m, err := LoadManifest("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range m.Resources {
		if entry.Name == "logStreams" {
			if entry.Status != "included" || entry.Fixture == nil {
				t.Fatal("logStreams still excluded")
			}
			if _, err = os.Stat(filepath.Clean(*entry.Fixture)); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("missing logStreams handler")
}
