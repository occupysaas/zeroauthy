package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runMigrate(t *testing.T, cfgPath string) string {
	t.Helper()
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"migrate", "--config", cfgPath})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestMigrateCommand(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "zeroauthy.yaml")
	_ = os.WriteFile(cfgPath, []byte("storage:\n  dsn: sqlite://"+filepath.Join(dir, "z.db")+"\n"), 0o600)

	if out := runMigrate(t, cfgPath); !strings.Contains(out, "migrated schema from version 0 to ") {
		t.Fatalf("first run output = %q", out)
	}
	if out := runMigrate(t, cfgPath); !strings.Contains(out, "schema is up to date (version ") {
		t.Fatalf("second run output = %q", out)
	}
}

func TestMigrateCommandMemory(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "zeroauthy.yaml")
	_ = os.WriteFile(cfgPath, []byte("storage:\n  dsn: memory://\n"), 0o600)
	if out := runMigrate(t, cfgPath); !strings.Contains(out, "nothing to migrate") {
		t.Fatalf("output = %q", out)
	}
}

func TestSeedCommandRefusesUnmigratedDatabase(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.yaml")
	cfgPath := filepath.Join(dir, "zeroauthy.yaml")
	_ = os.WriteFile(seedPath, []byte("tenants:\n  - name: acme\n"), 0o600)
	_ = os.WriteFile(cfgPath, []byte("storage:\n  dsn: sqlite://"+filepath.Join(dir, "z.db")+"\n"), 0o600)
	cmd := newRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"seed", "--config", cfgPath, "--file", seedPath})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "run zeroauthy migrate") {
		t.Fatalf("err = %v", err)
	}
}
