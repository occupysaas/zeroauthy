package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestAdminCreate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "zeroauthy.yaml")
	_ = os.WriteFile(cfgPath, []byte(`server:
  system_host: admin.localhost:8443
storage:
  dsn: sqlite://`+filepath.Join(dir, "z.db")+`
  auto_migrate: true
security:
  master_key: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
`), 0o600)
	run := func(args ...string) (string, error) {
		cmd := newRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), err
	}
	if _, err := run("migrate", "--config", cfgPath); err != nil {
		t.Fatal(err)
	}
	out, err := run("admin", "create", "--config", cfgPath, "--email", "root@example.test")
	if err != nil {
		t.Fatal(err)
	}
	link := regexp.MustCompile(`https://admin\.localhost:8443/u/reset-password\?ticket=[A-Za-z0-9_-]+`)
	if !link.MatchString(out) || !strings.Contains(out, "1 hour") {
		t.Fatalf("output = %q", out)
	}
	if _, err := run("admin", "create", "--config", cfgPath); err == nil || !strings.Contains(err.Error(), "--email") {
		t.Fatalf("no email: %v", err)
	}
	if _, err := run("admin", "create", "--config", cfgPath, "--email", "nope"); err == nil {
		t.Fatal("a bad address was accepted")
	}
}
