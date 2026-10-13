package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeedCommand(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.yaml")
	cfgPath := filepath.Join(dir, "zeroauthy.yaml")
	_ = os.WriteFile(seedPath, []byte("tenants:\n  - name: acme\n  - name: globex\n"), 0o600)
	_ = os.WriteFile(cfgPath, []byte("storage:\n  dsn: memory://\n"), 0o600)

	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"seed", "--config", cfgPath, "--file", seedPath})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "2 tenant(s)") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestSeedCommandNeedsFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "zeroauthy.yaml")
	_ = os.WriteFile(cfgPath, []byte("storage:\n  dsn: memory://\n"), 0o600)
	cmd := newRootCmd()
	cmd.SetArgs([]string{"seed", "--config", cfgPath})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "no seed file") {
		t.Fatalf("err = %v", err)
	}
}
