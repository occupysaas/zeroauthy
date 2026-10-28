package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// sysHost satisfies the system host requirement in tests about other settings.
const sysHost = "ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost"

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
	cfg, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost})
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
		"ZEROAUTHY_STORAGE__DSN=memory://", sysHost,
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
		"half tls":         {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost, "ZEROAUTHY_SERVER__TLS_CERT_FILE=/c.pem"}, want: "tls_cert_file and server.tls_key_file"},
		"bad level":        {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost, "ZEROAUTHY_LOG__LEVEL=loud"}, want: "log.level"},
		"bad format":       {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost, "ZEROAUTHY_LOG__FORMAT=xml"}, want: "log.format"},
		"both master keys": {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost, "ZEROAUTHY_SECURITY__MASTER_KEY=x", "ZEROAUTHY_SECURITY__MASTER_KEY_FILE=/k"}, want: "only one of"},
		"unknown env key":  {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost, "ZEROAUTHY_SECURITY__MASTERKEY=x"}, want: "masterkey"},
		"unknown top env":  {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost, "ZEROAUTHY_BOGUS=1"}, want: "bogus"},
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
	cfg, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost})
	if err != nil || cfg.Security.LoginMaxAttempts != 10 || cfg.Security.LoginLockoutSeconds != 900 {
		t.Fatalf("defaults = %+v, %v", cfg.Security, err)
	}
	cfg, err = Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost, "ZEROAUTHY_SECURITY__LOGIN_MAX_ATTEMPTS=5", "ZEROAUTHY_SECURITY__LOGIN_LOCKOUT_SECONDS=60"})
	if err != nil || cfg.Security.LoginMaxAttempts != 5 || cfg.Security.LoginLockoutSeconds != 60 {
		t.Fatalf("overrides = %+v, %v", cfg.Security, err)
	}
	if _, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost, "ZEROAUTHY_SECURITY__LOGIN_MAX_ATTEMPTS=0"}); err == nil {
		t.Fatal("zero attempts accepted")
	}
}

func TestEmailSettings(t *testing.T) {
	base := "ZEROAUTHY_STORAGE__DSN=memory://"
	cfg, err := Load("", []string{base, sysHost})
	if err != nil || cfg.Email.Driver != "log" || cfg.Email.From != "zeroauthy@localhost" || cfg.Email.SMTP.Port != 587 {
		t.Fatalf("defaults = %+v, %v", cfg.Email, err)
	}
	cfg, err = Load("", []string{base, sysHost, "ZEROAUTHY_EMAIL__SMTP__PORT=2525"})
	if err != nil || cfg.Email.SMTP.Port != 2525 {
		t.Fatalf("port override = %+v, %v", cfg.Email, err)
	}
	cfg, err = Load("", []string{base, sysHost, "ZEROAUTHY_EMAIL__ALLOW_LOCAL_SMTP=127.0.0.1:2525"})
	if err != nil || len(cfg.Email.AllowLocalSMTP) != 1 || cfg.Email.AllowLocalSMTP[0] != "127.0.0.1:2525" {
		t.Fatalf("local SMTP allowlist = %+v, %v", cfg.Email.AllowLocalSMTP, err)
	}
	cases := map[string]struct {
		env  []string
		want string
	}{
		"dir without dir":              {[]string{base, sysHost, "ZEROAUTHY_EMAIL__DRIVER=dir"}, "email.dir is required"},
		"smtp without host":            {[]string{base, sysHost, "ZEROAUTHY_EMAIL__DRIVER=smtp"}, "email.smtp.host"},
		"port zero":                    {[]string{base, sysHost, "ZEROAUTHY_EMAIL__DRIVER=smtp", "ZEROAUTHY_EMAIL__SMTP__HOST=h", "ZEROAUTHY_EMAIL__SMTP__PORT=0"}, "email.smtp.port"},
		"port too large":               {[]string{base, sysHost, "ZEROAUTHY_EMAIL__DRIVER=smtp", "ZEROAUTHY_EMAIL__SMTP__HOST=h", "ZEROAUTHY_EMAIL__SMTP__PORT=70000"}, "email.smtp.port"},
		"bad driver":                   {[]string{base, sysHost, "ZEROAUTHY_EMAIL__DRIVER=pigeon"}, "email.driver"},
		"from with newline":            {[]string{base, sysHost, "ZEROAUTHY_EMAIL__FROM=a@x.test\nBcc: b@x.test"}, "email.from"},
		"invalid local SMTP allowlist": {[]string{base, sysHost, "ZEROAUTHY_EMAIL__ALLOW_LOCAL_SMTP=127.0.0.1:nope"}, "email.allow_local_smtp"},
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

func TestStorageAutoMigrate(t *testing.T) {
	cfg, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=sqlite:///tmp/z.db", sysHost})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.AutoMigrate {
		t.Error("auto_migrate defaults to true, want false")
	}
	cfg, err = Load("", []string{"ZEROAUTHY_STORAGE__DSN=sqlite:///tmp/z.db", sysHost, "ZEROAUTHY_STORAGE__AUTO_MIGRATE=true"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Storage.AutoMigrate {
		t.Error("ZEROAUTHY_STORAGE__AUTO_MIGRATE=true not applied")
	}
}

func TestCustomDBSettings(t *testing.T) {
	base := "ZEROAUTHY_STORAGE__DSN=memory://"
	cfg, err := Load("", []string{base, sysHost})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CustomDB.Node != "node" || cfg.CustomDB.MaxMemoryMB != 256 || cfg.CustomDB.IdleTimeout != 5*time.Minute {
		t.Errorf("defaults = %+v", cfg.CustomDB)
	}
	cfg, err = Load("", []string{base, sysHost, "ZEROAUTHY_CUSTOM_DB__IDLE_TIMEOUT=30s", "ZEROAUTHY_CUSTOM_DB__MODULES_DIR=/opt/mods"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CustomDB.IdleTimeout != 30*time.Second || cfg.CustomDB.ModulesDir != "/opt/mods" {
		t.Errorf("env not applied: %+v", cfg.CustomDB)
	}
	_, err = Load("", []string{base, sysHost, "ZEROAUTHY_CUSTOM_DB__MODULES_DIR=mods"})
	if err == nil || !strings.Contains(err.Error(), "custom_db.modules_dir must be an absolute path") {
		t.Errorf("relative modules_dir: err = %v", err)
	}
	if _, err = Load("", []string{base, sysHost, "ZEROAUTHY_CUSTOM_DB__MAX_MEMORY_MB=31"}); err == nil {
		t.Error("max_memory_mb 31 accepted")
	}
}

func TestDeviceActivationSettings(t *testing.T) {
	base := "ZEROAUTHY_STORAGE__DSN=memory://"
	cfg, err := Load("", []string{base, sysHost})
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Security
	if s.DeviceActivationTxnMaxMisses != 5 || s.DeviceActivationIPMaxMisses != 10 || s.DeviceActivationIPLockoutSeconds != 900 ||
		s.DeviceActivationTenantMaxMisses != 1000 || s.DeviceActivationTenantWindowSeconds != 600 || s.DeviceActivationTenantLockoutSeconds != 60 {
		t.Fatalf("defaults = %+v", s)
	}
	if _, err := Load("", []string{base, sysHost, "ZEROAUTHY_SECURITY__DEVICE_ACTIVATION_IP_MAX_MISSES=0", "ZEROAUTHY_SECURITY__DEVICE_ACTIVATION_TENANT_MAX_MISSES=0"}); err != nil {
		t.Fatalf("zero (off) rejected: %v", err)
	}
	for _, bad := range []string{"DEVICE_ACTIVATION_IP_MAX_MISSES=-1", "DEVICE_ACTIVATION_TENANT_MAX_MISSES=-1", "DEVICE_ACTIVATION_TXN_MAX_MISSES=0"} {
		if _, err := Load("", []string{base, sysHost, "ZEROAUTHY_SECURITY__" + bad}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// Without a base domain the system tenant needs an explicit host (Plan 13).
func TestSystemHost(t *testing.T) {
	_, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://"})
	if err == nil || !strings.Contains(err.Error(), "server.system_host is required") {
		t.Fatalf("no base domain, no system host: err = %v", err)
	}
	cfg, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__BASE_DOMAIN=auth.example.test"})
	if err != nil || cfg.Server.SystemHost != "" {
		t.Fatalf("base domain only: %+v, %v", cfg, err)
	}
	cfg, err = Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__SYSTEM_HOST=admin.localhost:8443"})
	if err != nil || cfg.Server.SystemHost != "admin.localhost:8443" {
		t.Fatalf("system host only: %+v, %v", cfg, err)
	}
	if _, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__SYSTEM_HOST=https://admin.test/"}); err == nil {
		t.Fatal("a URL was accepted as system_host")
	}
}

func TestBootstrapAdminEmail(t *testing.T) {
	base := []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost"}
	cfg, err := Load("", append(base, "ZEROAUTHY_BOOTSTRAP__ADMIN_EMAIL=Admin@Example.test"))
	if err != nil || cfg.Bootstrap.AdminEmail != "Admin@Example.test" {
		t.Fatalf("%+v, %v", cfg.Bootstrap, err)
	}
	if _, err := Load("", append(base, "ZEROAUTHY_BOOTSTRAP__ADMIN_EMAIL=not an address")); err == nil {
		t.Fatal("a bad admin email was accepted")
	}
	// The bootstrap never takes a password.
	if _, err := Load("", append(base, "ZEROAUTHY_BOOTSTRAP__ADMIN_PASSWORD=x")); err == nil {
		t.Fatal("bootstrap.admin_password was accepted")
	}
}

// The resolver matches <name>.<base_domain> by tenant name before domains,
// so a system host under the base domain other than system.<base_domain>
// could be captured by a tenant with that name.
func TestSystemHostUnderBaseDomain(t *testing.T) {
	base := []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__BASE_DOMAIN=Example.com"}
	for _, host := range []string{"acme.example.com", "ACME.Example.com.", "acme.example.com:443", "a.b.example.com"} {
		_, err := Load("", append(base, "ZEROAUTHY_SERVER__SYSTEM_HOST="+host))
		if err == nil || !strings.Contains(err.Error(), "system.example.com") {
			t.Errorf("system_host %q: err = %v", host, err)
		}
	}
	for _, host := range []string{"system.example.com", "System.Example.com:443", "admin.other.test", "example.com:8443"} {
		if _, err := Load("", append(base, "ZEROAUTHY_SERVER__SYSTEM_HOST="+host)); err != nil {
			t.Errorf("system_host %q: %v", host, err)
		}
	}
}

func TestSeedMode(t *testing.T) {
	base := []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost}
	cfg, err := Load("", base)
	if err != nil || cfg.SeedMode != "apply" {
		t.Fatalf("default = %q, %v; want apply", cfg.SeedMode, err)
	}
	cfg, err = Load("", append(slices.Clone(base), "ZEROAUTHY_SEED_MODE=create_only"))
	if err != nil || cfg.SeedMode != "create_only" {
		t.Fatalf("env = %q, %v", cfg.SeedMode, err)
	}
	if _, err := Load("", append(slices.Clone(base), "ZEROAUTHY_SEED_MODE=sometimes")); err == nil {
		t.Error("an unknown seed_mode was accepted")
	}
}

func TestJobsSettings(t *testing.T) {
	cfg, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Jobs.Workers != 2 || cfg.Jobs.Lease != time.Minute {
		t.Errorf("defaults = %+v, want 2 workers and a 60s lease", cfg.Jobs)
	}
	cfg, err = Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost, "ZEROAUTHY_JOBS__WORKERS=0", "ZEROAUTHY_JOBS__LEASE=90s"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Jobs.Workers != 0 || cfg.Jobs.Lease != 90*time.Second {
		t.Errorf("jobs = %+v, want 0 workers and 90s", cfg.Jobs)
	}
	for _, env := range []string{"ZEROAUTHY_JOBS__WORKERS=-1", "ZEROAUTHY_JOBS__LEASE=0s", "ZEROAUTHY_JOBS__LEASE=500ms"} {
		if _, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost, env}); err == nil {
			t.Errorf("%s was accepted", env)
		}
	}
}

func TestTrustedProxyCIDRs(t *testing.T) {
	cfg, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost, "ZEROAUTHY_SERVER__TRUSTED_PROXY_CIDRS=10.1.2.3/8, 2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := cfg.Server.TrustedProxies()
	if err != nil || len(got) != 2 || got[0].String() != "10.0.0.0/8" || got[1].String() != "2001:db8::/32" {
		t.Fatalf("prefixes = %v, %v", got, err)
	}
	for _, bad := range []string{"10.0.0.1", "not-a-cidr", "fe80::1%eth0/64"} {
		if _, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", sysHost, "ZEROAUTHY_SERVER__TRUSTED_PROXY_CIDRS=" + bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestACMEConfig(t *testing.T) {
	base := []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__BASE_DOMAIN=auth.example.test"}
	on := append(slices.Clone(base), "ZEROAUTHY_SERVER__ACME__ENABLED=true", "ZEROAUTHY_SERVER__ACME__EMAIL=ops@example.test",
		"ZEROAUTHY_SERVER__ACME__TERMS_ACCEPTED=true", "ZEROAUTHY_SERVER__ACME__DEPLOYMENT_ID=prod-1", "ZEROAUTHY_SERVER__ACME__CHALLENGE=http-01")
	cfg, err := Load("", base)
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.Server.ACME
	if a.Enabled || a.DirectoryURL != "https://acme-v02.api.letsencrypt.org/directory" || a.Workers != 2 || a.HostedWildcard.Enabled {
		t.Fatalf("defaults = %+v", a)
	}
	if got := cfg.Server.OriginDomain(); got != "auth.example.test" {
		t.Fatalf("origin default = %q", got)
	}
	cfg, err = Load("", on)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ACME.HTTPListen != ":80" {
		t.Fatalf("http-01 listen default = %q", cfg.Server.ACME.HTTPListen)
	}
	alpn := append(slices.Clone(on[:len(on)-1]), "ZEROAUTHY_SERVER__ACME__CHALLENGE=tls-alpn-01")
	if cfg, err := Load("", alpn); err != nil || cfg.Server.ACME.HTTPListen != "" {
		t.Fatalf("tls-alpn = %+v, %v", cfg, err)
	}
	wild := append(slices.Clone(on), "ZEROAUTHY_SERVER__ACME__HOSTED_WILDCARD__ENABLED=true",
		"ZEROAUTHY_SERVER__ACME__HOSTED_WILDCARD__ZONE=example.test", "ZEROAUTHY_SERVER__ACME__HOSTED_WILDCARD__TOKEN_FILE=/run/secrets/do")
	if _, err := Load("", wild); err != nil {
		t.Fatalf("hosted wildcard = %v", err)
	}
	for name, env := range map[string][]string{
		"no email":         drop(on, "EMAIL"),
		"bad email":        append(drop(on, "EMAIL"), "ZEROAUTHY_SERVER__ACME__EMAIL=not an address"),
		"terms":            drop(on, "TERMS_ACCEPTED"),
		"deployment":       drop(on, "DEPLOYMENT_ID"),
		"no challenge":     drop(on, "CHALLENGE"),
		"bad challenge":    append(drop(on, "CHALLENGE"), "ZEROAUTHY_SERVER__ACME__CHALLENGE=dns-01"),
		"alpn with http":   append(slices.Clone(alpn), "ZEROAUTHY_SERVER__ACME__HTTP_LISTEN=:80"),
		"http directory":   append(slices.Clone(on), "ZEROAUTHY_SERVER__ACME__DIRECTORY_URL=http://ca.test/dir"),
		"workers 0":        append(slices.Clone(on), "ZEROAUTHY_SERVER__ACME__WORKERS=0"),
		"workers 9":        append(slices.Clone(on), "ZEROAUTHY_SERVER__ACME__WORKERS=9"),
		"wildcard off":     append(slices.Clone(base), "ZEROAUTHY_SERVER__ACME__HOSTED_WILDCARD__ENABLED=true"),
		"wildcard zone":    drop(wild, "ZONE"),
		"wildcard token":   drop(wild, "TOKEN_FILE"),
		"zone mismatch":    append(drop(wild, "ZONE"), "ZEROAUTHY_SERVER__ACME__HOSTED_WILDCARD__ZONE=other.test"),
		"wildcard no base": append(drop(wild, "BASE_DOMAIN"), sysHost),
		"wildcard port":    append(drop(wild, "BASE_DOMAIN"), "ZEROAUTHY_SERVER__BASE_DOMAIN=auth.example.test:8443"),
		"origin url":       append(slices.Clone(base), "ZEROAUTHY_SERVER__CUSTOM_DOMAINS__ORIGIN_DOMAIN=https://o.test"),
		"origin port":      append(slices.Clone(base), "ZEROAUTHY_SERVER__CUSTOM_DOMAINS__ORIGIN_DOMAIN=o.test:8443"),
		"unknown acme key": append(slices.Clone(on), "ZEROAUTHY_SERVER__ACME__INSECURE=true"),
		"resolver host":    append(slices.Clone(base), "ZEROAUTHY_SERVER__CUSTOM_DOMAINS__DNS_RESOLVER=dns.example.test:53"),
	} {
		if _, err := Load("", env); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// drop removes the environment entries whose key contains part.
func drop(env []string, part string) []string {
	out := []string{}
	for _, e := range env {
		if !strings.Contains(strings.SplitN(e, "=", 2)[0], part) {
			out = append(out, e)
		}
	}
	return out
}

func TestActionsSettings(t *testing.T) {
	base := "ZEROAUTHY_STORAGE__DSN=memory://"
	cfg, err := Load("", []string{base, sysHost})
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.Actions
	if a.Node != "node" || a.NPMCLI != "" || a.Registry != "https://registry.npmjs.org/" || a.CacheDir != "" ||
		a.MaxMemoryMB != 256 || a.IdleTimeout != 5*time.Minute || a.BuildTimeout != 2*time.Minute ||
		a.MaxArtifactMB != 50 || a.MaxConcurrentBuilds != 2 {
		t.Errorf("defaults = %+v", a)
	}
	cfg, err = Load("", []string{base, sysHost, "ZEROAUTHY_ACTIONS__CACHE_DIR=/var/cache/za", "ZEROAUTHY_ACTIONS__NPM_CLI=/opt/npm/bin/npm-cli.js",
		"ZEROAUTHY_ACTIONS__REGISTRY=http://mirror.internal:4873/", "ZEROAUTHY_ACTIONS__BUILD_TIMEOUT=30s", "ZEROAUTHY_ACTIONS__MAX_CONCURRENT_BUILDS=4"})
	if err != nil {
		t.Fatal(err)
	}
	if a := cfg.Actions; a.CacheDir != "/var/cache/za" || a.NPMCLI != "/opt/npm/bin/npm-cli.js" || a.Registry != "http://mirror.internal:4873/" ||
		a.BuildTimeout != 30*time.Second || a.MaxConcurrentBuilds != 4 {
		t.Errorf("env not applied: %+v", a)
	}
	for bad, want := range map[string]string{
		"CACHE_DIR=cache":             "actions.cache_dir must be an absolute path",
		"NPM_CLI=npm-cli.js":          "actions.npm_cli must be an absolute path",
		"REGISTRY=ftp://x/":           "actions.registry must be an http or https URL",
		"REGISTRY=registry.npmjs.org": "actions.registry must be an http or https URL",
		"NODE=":                       "actions.node must not be empty",
		"MAX_MEMORY_MB=31":            "actions.max_memory_mb",
		"IDLE_TIMEOUT=0s":             "actions.idle_timeout must be positive",
		"BUILD_TIMEOUT=-1s":           "actions.build_timeout must be positive",
		"MAX_ARTIFACT_MB=0":           "actions.max_artifact_mb",
		"MAX_ARTIFACT_MB=51":          "actions.max_artifact_mb",
		"MAX_CONCURRENT_BUILDS=0":     "actions.max_concurrent_builds",
	} {
		_, err := Load("", []string{base, sysHost, "ZEROAUTHY_ACTIONS__" + bad})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", bad, err, want)
		}
	}
}
