package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFileAndEnv(t *testing.T) {
	path := writeFile(t, "zeroauthy.yaml", `
server:
  listen: ":9000"
  base_domain: auth.example.test
storage:
  dsn: memory://
seed: /etc/zeroauthy/seed.yaml
`)
	cfg, err := Load(path, []string{
		"ZEROAUTHY_SERVER__LISTEN=:9100",
		"ZEROAUTHY_SERVER__TRUST_PROXY_HEADERS=true",
		"ZEROAUTHY_LOG__LEVEL=debug",
		"UNRELATED=1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != ":9100" {
		t.Errorf("listen = %q, want env override :9100", cfg.Server.Listen)
	}
	if cfg.Server.BaseDomain != "auth.example.test" || cfg.Storage.DSN != "memory://" || cfg.Seed != "/etc/zeroauthy/seed.yaml" {
		t.Errorf("file values not loaded: %+v", cfg)
	}
	if !cfg.Server.TrustProxyHeaders {
		t.Error("bool env override not applied")
	}
	if cfg.Log.Level != "debug" || cfg.Log.Format != "json" {
		t.Errorf("log = %+v, want level debug (env) and format json (default)", cfg.Log)
	}
}

func TestLoadEnvOnly(t *testing.T) {
	cfg, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("default listen = %q", cfg.Server.Listen)
	}
}

func TestLoadIgnoresConfigPathVariable(t *testing.T) {
	_, err := Load("", []string{
		"ZEROAUTHY_CONFIG=/some/path.yaml",
		"ZEROAUTHY_STORAGE__DSN=memory://",
	})
	if err != nil {
		t.Fatalf("ZEROAUTHY_CONFIG must not be treated as a setting: %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]struct {
		file string
		env  []string
		want string
	}{
		"missing dsn":      {env: nil, want: "storage.dsn is required"},
		"half tls":         {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__TLS_CERT_FILE=/c.pem"}, want: "tls_cert_file and server.tls_key_file"},
		"bad level":        {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_LOG__LEVEL=loud"}, want: "log.level"},
		"bad format":       {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_LOG__FORMAT=xml"}, want: "log.format"},
		"both master keys": {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SECURITY__MASTER_KEY=x", "ZEROAUTHY_SECURITY__MASTER_KEY_FILE=/k"}, want: "only one of"},
		"unknown env key":  {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SECURITY__MASTERKEY=x"}, want: "masterkey"},
		"unknown top env":  {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_BOGUS=1"}, want: "bogus"},
		"unknown file key": {file: writeFile(t, "bad.yaml", "storage:\n  dsn: memory://\nserver:\n  listn: \":1\"\n"), want: "listn"},
		"missing file":     {file: "/nonexistent/zeroauthy.yaml", want: "no such file"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(tc.file, tc.env)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestMasterKeyBytes(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc := base64.StdEncoding.EncodeToString(key)

	got, err := Security{MasterKey: enc}.MasterKeyBytes()
	if err != nil || string(got) != string(key) {
		t.Fatalf("inline key: %v %v", got, err)
	}

	file := writeFile(t, "master.key", enc+"\n")
	got, err = Security{MasterKeyFile: file}.MasterKeyBytes()
	if err != nil || string(got) != string(key) {
		t.Fatalf("file key: %v %v", got, err)
	}

	got, err = Security{}.MasterKeyBytes()
	if err != nil || got != nil {
		t.Fatalf("unset key: %v %v", got, err)
	}

	if _, err := (Security{MasterKey: base64.StdEncoding.EncodeToString([]byte("short"))}).MasterKeyBytes(); err == nil {
		t.Fatal("short key accepted")
	}
}
func TestLoginThrottleSettings(t *testing.T) {
	cfg, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://"})
	if err != nil || cfg.Security.LoginMaxAttempts != 10 || cfg.Security.LoginLockoutSeconds != 900 {
		t.Fatalf("defaults = %+v, %v", cfg.Security, err)
	}
	cfg, err = Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SECURITY__LOGIN_MAX_ATTEMPTS=5", "ZEROAUTHY_SECURITY__LOGIN_LOCKOUT_SECONDS=60"})
	if err != nil || cfg.Security.LoginMaxAttempts != 5 || cfg.Security.LoginLockoutSeconds != 60 {
		t.Fatalf("overrides = %+v, %v", cfg.Security, err)
	}
	if _, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SECURITY__LOGIN_MAX_ATTEMPTS=0"}); err == nil {
		t.Fatal("zero attempts accepted")
	}
}

func TestEmailSettings(t *testing.T) {
	base := "ZEROAUTHY_STORAGE__DSN=memory://"
	cfg, err := Load("", []string{base})
	if err != nil || cfg.Email.Driver != "log" || cfg.Email.From != "zeroauthy@localhost" || cfg.Email.SMTP.Port != 587 {
		t.Fatalf("defaults = %+v, %v", cfg.Email, err)
	}
	cfg, err = Load("", []string{base, "ZEROAUTHY_EMAIL__SMTP__PORT=2525"})
	if err != nil || cfg.Email.SMTP.Port != 2525 {
		t.Fatalf("port override = %+v, %v", cfg.Email, err)
	}
	cases := map[string]struct {
		env  []string
		want string
	}{
		"dir without dir":   {[]string{base, "ZEROAUTHY_EMAIL__DRIVER=dir"}, "email.dir is required"},
		"smtp without host": {[]string{base, "ZEROAUTHY_EMAIL__DRIVER=smtp"}, "email.smtp.host"},
		"bad driver":        {[]string{base, "ZEROAUTHY_EMAIL__DRIVER=pigeon"}, "email.driver"},
		"from with newline": {[]string{base, "ZEROAUTHY_EMAIL__FROM=a@x.test\nBcc: b@x.test"}, "email.from"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load("", tc.env)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
