package deploymigration

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadExportBoundaries(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "duplicate.yaml")
	if err := os.WriteFile(bad, []byte("clients:\n  - client_id: a\n    client_id: b\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExport(bad, "yaml"); err == nil {
		t.Fatal("duplicate YAML key accepted")
	}
	if _, err := LoadExport(dir, "json"); err == nil {
		t.Fatal("unsupported format accepted")
	}
	dupDir := filepath.Join(dir, "duplicate-json")
	if err := os.Mkdir(dupDir, 0700); err != nil {
		t.Fatal(err)
	}
	dupJSON := filepath.Join(dupDir, "clients.json")
	if err := os.WriteFile(dupJSON, []byte(`{"clients":[{"client_id":"a","client_id":"b"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExport(dupDir, "directory"); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
	parent := filepath.Join(dir, "parent.yaml")
	if err := os.WriteFile(parent, []byte("clients:\n  - client_id: a\n    config_file: file://../outside.json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExport(parent, "yaml"); err == nil {
		t.Fatal("parent file reference accepted")
	}
	local := filepath.Join(dir, "local.yaml")
	if err := os.WriteFile(local, []byte("clients:\n  - client_id: a\n    config_file: file://configs/client.json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "configs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "configs", "client.json"), []byte(`{"x":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadExport(local, "yaml")
	if err != nil {
		t.Fatalf("safe relative reference rejected: %v", err)
	}
	if string(loaded.Files["configs/client.json"]) != `{"x":1}` {
		t.Fatal("referenced file was not hashed as input data")
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "configs", "escape.json")); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(dir, "escape.yaml")
	if err := os.WriteFile(escape, []byte("clients:\n  - client_id: a\n    config_file: file://configs/escape.json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExport(escape, "yaml"); err == nil {
		t.Fatal("symlink escape reference accepted")
	}

	// Script payloads are retained as bytes and are never evaluated.
	scriptRoot := filepath.Join(dir, "script-export")
	script := filepath.Join(scriptRoot, "scripts", "seed.js")
	if err := os.MkdirAll(filepath.Dir(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("throw new Error('must remain inert')"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadExport(scriptRoot, "directory")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Files["scripts/seed.js"]) != "throw new Error('must remain inert')" {
		t.Fatal("script payload was not preserved inertly")
	}
}
