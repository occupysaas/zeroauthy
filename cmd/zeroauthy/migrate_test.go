package main

import (
	"bytes"
	"encoding/base64"
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
	// seed loads the master key to seal connection configuration.
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	_ = os.WriteFile(cfgPath, []byte("storage:\n  dsn: sqlite://"+filepath.Join(dir, "z.db")+"\nsecurity:\n  master_key: "+key+"\n"), 0o600)
	cmd := newRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"seed", "--config", cfgPath, "--file", seedPath})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "run zeroauthy migrate") {
		t.Fatalf("err = %v", err)
	}
}

// TestMigrateCommandIgnoresTestDSNVariables guards against the SQL test
// variables (set by scripts/test-sql.sh and CI) being read as config keys:
// config.Load rejects unknown ZEROAUTHY_* variables.
func TestMigrateCommandIgnoresTestDSNVariables(t *testing.T) {
	t.Setenv("ZA_TEST_POSTGRES_DSN", "postgres://postgres:zeroauthy@127.0.0.1:55432/postgres?sslmode=disable")
	t.Setenv("ZA_TEST_MYSQL_DSN", "mysql://root:zeroauthy@127.0.0.1:53306/")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "zeroauthy.yaml")
	_ = os.WriteFile(cfgPath, []byte("storage:\n  dsn: sqlite://"+filepath.Join(dir, "z.db")+"\n"), 0o600)
	if out := runMigrate(t, cfgPath); !strings.Contains(out, "migrated schema from version 0 to ") {
		t.Fatalf("output = %q", out)
	}
}
