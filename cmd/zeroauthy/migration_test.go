package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationBootstrapFlags(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"migration", "bootstrap"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "required flag") {
		t.Fatalf("missing required flags: %v", err)
	}
	bootstrap, _, err := cmd.Find([]string{"migration", "bootstrap"})
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.Flags().Lookup("check") == nil || bootstrap.Flags().Lookup("credentials-file") == nil || bootstrap.Flags().Lookup("exclude-client-id") == nil {
		t.Fatal("migration bootstrap flags missing")
	}
}

func TestMigrationBootstrapCredentialFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(`{"client":"secret-sentinel"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredentialFile(path); err == nil || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatalf("unsafe permissions were accepted or secret leaked: %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	values, err := readCredentialFile(path)
	if err != nil || values["client"] != "secret-sentinel" {
		t.Fatalf("protected credentials read failed: %v", err)
	}
}
