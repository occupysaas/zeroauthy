package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestCoverage(t *testing.T) {
	m, err := LoadManifest("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(m.Resources))
	for _, r := range m.Resources {
		names = append(names, r.Name)
	}
	if err := ValidateManifest(m, names); err != nil {
		t.Fatalf("manifest self-coverage failed: %v", err)
	}
	for _, resource := range m.Resources {
		if resource.Status != "included" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(".", *resource.Fixture))
		if err != nil || len(b) == 0 {
			t.Fatalf("included fixture missing for %s", resource.Name)
		}
	}
	if err := ValidateManifest(m, append(names, "newHandler")); err == nil {
		t.Fatal("registry additions were silently ignored")
	}
	dup := append(append([]string{}, names...), names[0])
	if err := ValidateManifest(m, dup); err == nil {
		t.Fatal("duplicate registry handler accepted")
	}
	bad := m
	bad.Normalizations = append(append([]Normalization{}, m.Normalizations...), Normalization{Resource: "clients", Path: "*", Rule: "drop", Reason: "broad"})
	if err := ValidateManifest(bad, names); err == nil {
		t.Fatal("broad normalization path accepted")
	}
}

func TestMigrationSystemNameCollision(t *testing.T) {
	if err := PreflightInventory([]byte(`[{"name":"Auth0 Management API"}]`)); err == nil {
		t.Fatal("non-system reserved-name API accepted")
	}
	if err := PreflightInventory([]byte(`[{"name":"Auth0 Management API","is_system":true}]`)); err != nil {
		t.Fatalf("system API rejected: %v", err)
	}
}

func TestYAMLReferencedScriptsRemainInert(t *testing.T) {
	export, err := load("fixtures/yaml-ref/deploy.yaml", "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := export.Files["scripts/login.js"]; !ok {
		t.Fatal("referenced script bytes not included")
	}
}

func TestCLIRegistryValidation(t *testing.T) {
	dir := t.TempDir()
	mp := filepath.Join(dir, "manifest.json")
	rp := filepath.Join(dir, "registry.json")
	if err := os.WriteFile(mp, []byte(`{"toolVersion":"x","resources":[{"name":"r","status":"excluded","owner":"roadmap: x","reason":"x"}],"normalizations":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rp, []byte(`[`+`"r"`+`]`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := commandOutput([]string{"validate-manifest", "--registry", rp, "--manifest", mp}); err != nil {
		t.Fatal(err)
	}
	var got []string
	b, err := commandOutput([]string{"exclusions", "--manifest", mp})
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(b, &got) != nil || len(got) != 1 || got[0] != "r" {
		t.Fatalf("exclusions: %s", b)
	}
}

func TestManifestToolUnsupportedIsExplicitlyExcluded(t *testing.T) {
	m := Manifest{Resources: []ManifestResource{{Name: "databases", Status: "tool-unsupported"}}}
	if got := Exclusions(m); len(got) != 1 || got[0] != "databases" {
		t.Fatalf("unavailable handler would be invoked: %v", got)
	}
}
func TestManifestRejectsUnownedFieldNormalization(t *testing.T) {
	m, err := LoadManifest("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range m.Resources {
		names = append(names, r.Name)
	}
	m.Normalizations = append(m.Normalizations, Normalization{Resource: "clients", Path: "name", Rule: "read-only", Reason: "would conceal changed application identity"})
	if ValidateManifest(m, names) == nil {
		t.Fatal("client identity could be discarded by unapproved normalization")
	}
}
