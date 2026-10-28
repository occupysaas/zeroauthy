package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/deploymigration"
)

func TestActionsMigrationComparator(t *testing.T) {
	m := testManifest()
	m.Resources = append(m.Resources, ManifestResource{Name: "actions", Status: "included"}, ManifestResource{Name: "triggers", Status: "included"})
	source, target := comparisonFixture(), comparisonFixture()
	source.Resources["actions"] = json.RawMessage(`[{"id":"source-id","name":"Claim","code":"./actions/Claim/code.js","secrets":[{"name":"KEY"}]}]`)
	source.Resources["triggers"] = json.RawMessage(`{"post-login":[{"action_name":"Claim","display_name":"Claim"}]}`)
	target.Resources["actions"] = json.RawMessage(`[{"id":"target-id","name":"Claim","code":"./actions/Claim/code.js","secrets":[{"name":"KEY"}]}]`)
	target.Resources["triggers"] = source.Resources["triggers"]
	source.Files = map[string][]byte{"actions/Claim/code.js": []byte("exports.onExecutePostLogin=()=>{}")}
	target.Files = map[string][]byte{"actions/Claim/code.js": source.Files["actions/Claim/code.js"]}
	if r := Compare(source, target, m, Domains{}); !r.Equivalent {
		t.Fatalf("equal Actions differ: %+v", r.Differences)
	}
	for _, name := range []string{"actions", "triggers"} {
		original := target.Resources[name]
		delete(target.Resources, name)
		if Compare(source, target, m, Domains{}).Equivalent {
			t.Fatalf("missing %s accepted", name)
		}
		target.Resources[name] = original
	}
	target.Files["actions/Claim/code.js"] = []byte("changed")
	if Compare(source, target, m, Domains{}).Equivalent {
		t.Fatal("changed code accepted")
	}
	target.Files["actions/Claim/code.js"] = source.Files["actions/Claim/code.js"]
	for _, bad := range []struct {
		resource string
		raw      json.RawMessage
	}{
		{"triggers", json.RawMessage(`{"post-login":[{"action_name":"Missing"}]}`)},
		{"actions", json.RawMessage(`[{"name":"Claim","code":"./actions/Claim/code.js","secrets":[{"name":"KEY","value":"must-not-export"}]}]`)},
	} {
		savedSource, savedTarget := source.Resources[bad.resource], target.Resources[bad.resource]
		source.Resources[bad.resource], target.Resources[bad.resource] = bad.raw, bad.raw
		if Compare(source, target, m, Domains{}).Equivalent {
			t.Fatalf("equally invalid %s exports accepted", bad.resource)
		}
		source.Resources[bad.resource], target.Resources[bad.resource] = savedSource, savedTarget
	}
}

func TestActionsDirectoryAndMissingCode(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "actions", "Claim"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "triggers"), 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "actions", "Claim.json"), []byte(`{"name":"Claim","code":"./actions/Claim/code.js"}`), 0600)
	os.WriteFile(filepath.Join(dir, "actions", "Claim", "code.js"), []byte("claim"), 0600)
	os.WriteFile(filepath.Join(dir, "triggers", "triggers.json"), []byte(`{"post-login":[{"action_name":"Claim"}]}`), 0600)
	got, err := deploymigration.LoadExport(dir, "directory")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Resources["actions"]) == 0 || len(got.Resources["triggers"]) == 0 {
		t.Fatalf("Action resources not loaded: %+v", got.Resources)
	}
	os.Remove(filepath.Join(dir, "actions", "Claim", "code.js"))
	if _, err := deploymigration.LoadExport(dir, "directory"); err == nil {
		t.Fatal("missing Action code accepted")
	}
}
