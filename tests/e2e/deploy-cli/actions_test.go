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
	if err := os.MkdirAll(filepath.Join(dir, "action-modules", "shared"), 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "action-modules", "shared.json"), []byte(`{"name":"shared","code":"./action-modules/shared/code.js","latest_version_number":1}`), 0600)
	os.WriteFile(filepath.Join(dir, "action-modules", "shared", "code.js"), []byte("exports.value=()=>1"), 0600)
	got, err := deploymigration.LoadExport(dir, "directory")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Resources["actions"]) == 0 || len(got.Resources["triggers"]) == 0 || len(got.Resources["actionModules"]) == 0 || len(got.Files["action-modules/shared/code.js"]) == 0 {
		t.Fatalf("Action resources not loaded: %+v", got.Resources)
	}
	os.Remove(filepath.Join(dir, "action-modules", "shared", "code.js"))
	if _, err := deploymigration.LoadExport(dir, "directory"); err == nil {
		t.Fatal("missing module code accepted")
	}
	os.WriteFile(filepath.Join(dir, "action-modules", "shared", "code.js"), []byte("exports.value=()=>1"), 0600)
	os.Remove(filepath.Join(dir, "actions", "Claim", "code.js"))
	if _, err := deploymigration.LoadExport(dir, "directory"); err == nil {
		t.Fatal("missing Action code accepted")
	}
}

func TestActionModulesMigrationComparator(t *testing.T) {
	m := testManifest()
	m.Resources = append(m.Resources, ManifestResource{Name: "actionModules", Status: "included"}, ManifestResource{Name: "actions", Status: "included"})
	m.Normalizations = append(m.Normalizations, Normalization{Resource: "actionModules", Path: "latest_version_number", Rule: "read-only"})
	source, target := comparisonFixture(), comparisonFixture()
	source.Resources["actionModules"] = json.RawMessage(`[{"id":"source-module","name":"shared","code":"./action-modules/shared/code.js","latest_version_number":1,"secrets":[]}]`)
	target.Resources["actionModules"] = json.RawMessage(`[{"id":"target-module","name":"shared","code":"./action-modules/shared/code.js","latest_version_number":4,"secrets":[]}]`)
	source.Resources["actions"] = json.RawMessage(`[{"name":"consumer","modules":[{"module_name":"shared","module_version_number":1}]}]`)
	target.Resources["actions"] = source.Resources["actions"]
	source.Files = map[string][]byte{"action-modules/shared/code.js": []byte("exports.value=()=>1")}
	target.Files = map[string][]byte{"action-modules/shared/code.js": source.Files["action-modules/shared/code.js"]}
	if r := Compare(source, target, m, Domains{}); !r.Equivalent {
		t.Fatalf("canonical module names/version numbers differ: %+v", r.Differences)
	}
	for _, bad := range []json.RawMessage{json.RawMessage(`[{"name":"consumer","modules":[{"module_name":"missing","module_version_number":1}]}]`), json.RawMessage(`[{"name":"consumer","modules":[{"module_name":"shared","module_version_number":2}]}]`)} {
		target.Resources["actions"] = bad
		if Compare(source, target, m, Domains{}).Equivalent {
			t.Fatal("invalid module reference accepted")
		}
	}
	target.Resources["actions"] = source.Resources["actions"]
	target.Files["action-modules/shared/code.js"] = []byte("exports.value=()=>2")
	if Compare(source, target, m, Domains{}).Equivalent {
		t.Fatal("changed module code accepted")
	}
	target.Files["action-modules/shared/code.js"] = source.Files["action-modules/shared/code.js"]
	// A target-local version 2 exists, but changing an Action's pin still differs.
	target.Resources["actions"] = json.RawMessage(`[{"name":"consumer","modules":[{"module_name":"shared","module_version_number":2}]}]`)
	if Compare(source, target, m, Domains{}).Equivalent {
		t.Fatal("changed canonical pin accepted")
	}
	target.Resources["actions"] = source.Resources["actions"]
	delete(target.Resources, "actionModules")
	if Compare(source, target, m, Domains{}).Equivalent {
		t.Fatal("missing module accepted")
	}
}

func TestActionModuleReferencesRejectFractionalVersions(t *testing.T) {
	m := testManifest()
	m.Resources = append(m.Resources, ManifestResource{Name: "actionModules", Status: "included"}, ManifestResource{Name: "actions", Status: "included"})
	source, target := comparisonFixture(), comparisonFixture()
	modules := json.RawMessage(`[{"name":"shared","latest_version_number":4}]`)
	actions := json.RawMessage(`[{"name":"consumer","modules":[{"module_name":"shared","module_version_number":1.5}]}]`)
	for _, export := range []*deploymigration.Export{&source, &target} {
		export.Resources["actionModules"] = modules
		export.Resources["actions"] = actions
	}
	if Compare(source, target, m, Domains{}).Equivalent {
		t.Fatal("two equally malformed fractional module pins accepted")
	}
}
