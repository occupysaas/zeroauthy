package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/pkg/storeplugin"
)

// testServer gives the system tenant a host (server.system_host).
var testServer = config.Server{SystemHost: "system.localhost"}

func TestNewSeedsAndServes(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.yaml")
	if err := os.WriteFile(seedPath, []byte("tenants:\n  - name: acme\n    domains: [acme.example.test]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Seed: seedPath}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "https://acme.example.test/.well-known/jwks.json", nil))
	if rec.Code != 200 || len(rec.Body.String()) < 100 {
		t.Fatalf("jwks after startup: %d %s (keys should be ensured for seeded tenants)", rec.Code, rec.Body)
	}
	tn, err := a.store.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := a.store.ResourceServers().GetByIdentifier(context.Background(), tn.ID, "https://acme.example.test/api/v2/")
	if err != nil || rs.Name != "Auth0 Management API" {
		t.Fatalf("Management API after startup: %+v err=%v", rs, err)
	}
}

func TestNewRejectsBadSeed(t *testing.T) {
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Seed: "/nonexistent/seed.yaml"}
	if _, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected error for missing seed file")
	}
}

func TestHTTPServerTimeouts(t *testing.T) {
	a := &App{cfg: &config.Config{Server: config.Server{Listen: ":1234"}}}
	srv := a.httpServer()
	if srv.Addr != ":1234" {
		t.Errorf("Addr = %q", srv.Addr)
	}
	if srv.ReadHeaderTimeout != 10*time.Second || srv.ReadTimeout != 30*time.Second ||
		srv.WriteTimeout != 30*time.Second || srv.IdleTimeout != 120*time.Second {
		t.Errorf("timeouts = header %v read %v write %v idle %v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}

func TestNewWarnsAboutLogEmailDriver(t *testing.T) {
	for driver, want := range map[string]bool{"log": true, "dir": false} {
		var buf strings.Builder
		cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Email: config.Email{Driver: driver, Dir: t.TempDir()}}
		a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(&buf, nil)))
		if err != nil {
			t.Fatal(err)
		}
		a.Close()
		got := strings.Contains(buf.String(), "level=WARN") &&
			strings.Contains(buf.String(), "email.driver is log: emails are written to the server log and not delivered; reset links are redacted unless email.log_links is true")
		if got != want {
			t.Errorf("driver %s: warned = %v, log = %s", driver, got, buf.String())
		}
	}
}

func sqliteConfig(t *testing.T, autoMigrate bool) *config.Config {
	t.Helper()
	return &config.Config{
		Server:   testServer,
		Storage:  config.Storage{DSN: "sqlite://" + filepath.Join(t.TempDir(), "z.db"), AutoMigrate: autoMigrate},
		Security: config.Security{MasterKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="},
	}
}

func TestNewRefusesUnmigratedDatabase(t *testing.T) {
	_, err := New(context.Background(), sqliteConfig(t, false), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "run zeroauthy migrate") {
		t.Fatalf("err = %v, want it to say run zeroauthy migrate", err)
	}
}

func TestNewAutoMigrates(t *testing.T) {
	var buf strings.Builder
	a, err := New(context.Background(), sqliteConfig(t, true), slog.New(slog.NewTextHandler(&buf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("/healthz = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(buf.String(), "schema_version=") {
		t.Errorf("schema version not logged: %s", buf.String())
	}
}

// TestNewNeedsMasterKeyBeforeMigrating: a persistent store without a master
// key is refused before anything touches the database.
func TestNewNeedsMasterKeyBeforeMigrating(t *testing.T) {
	cfg := sqliteConfig(t, true)
	cfg.Security.MasterKey = ""
	path := strings.TrimPrefix(cfg.Storage.DSN, "sqlite://")
	_, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "security.master_key or security.master_key_file is required") {
		t.Fatalf("err = %v, want the master-key error", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("database file %s was created (stat err = %v); want it untouched", path, err)
	}
}

// TestAppOnPluginStorage: the app runs on a gRPC storage plugin; the plugin
// store is not a Migrator, so schema preparation is skipped, and it needs the
// master key like any persistent store.
func TestAppOnPluginStorage(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "zeroauthy-store-memory")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/zeroauthy/zeroauthy/cmd/zeroauthy-store-memory").CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v\n%s", err, out)
	}
	seedPath := filepath.Join(dir, "seed.yaml")
	seed := `
tenants:
  - name: acme
    domains: [acme.example.test]
    resource_servers:
      - {identifier: "https://api.acme.test", skip_consent_for_verifiable_first_party_clients: true, name: API, scopes: [{value: "read:things"}]}
    clients:
      - {client_id: m2m, app_type: non_interactive, client_secret: m2m-secret, grant_types: [client_credentials]}
    client_grants:
      - {client_id: m2m, audience: "https://api.acme.test", scopes: ["read:things"]}
`
	if err := os.WriteFile(seedPath, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Server:   testServer,
		Storage:  config.Storage{DSN: "plugin://" + bin},
		Security: config.Security{MasterKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="},
		Seed:     seedPath,
	}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("/healthz = %d %s", rec.Code, rec.Body)
	}
	// /healthz is liveness only; /readyz pings the store, i.e. the plugin.
	rec = httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 200 {
		t.Fatalf("/readyz = %d %s", rec.Code, rec.Body)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"m2m"}, "client_secret": {"m2m-secret"}, "audience": {"https://api.acme.test"}}
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"access_token"`) {
		t.Fatalf("token = %d %s", rec.Code, rec.Body)
	}

	// A dead plugin makes the app not ready, while it stays alive.
	storeplugin.KillForTest(a.store)
	rec = httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz after the plugin died = %d, want 503", rec.Code)
	}
	rec = httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("/healthz after the plugin died = %d, want 200", rec.Code)
	}
}

// A plugin store is persistent, so it needs the master key like the SQL
// drivers, and nothing is started without it.
func TestPluginStorageNeedsMasterKey(t *testing.T) {
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "plugin:///nonexistent/plugin"}}
	_, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "security.master_key or security.master_key_file is required") {
		t.Fatalf("err = %v, want the master-key error", err)
	}
}

// A customized connection whose scripts cannot run (no Node.js) is a
// warning, not a startup failure.
func TestNewWarnsWhenNodeIsMissing(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.yaml")
	seedYAML := `tenants:
  - name: acme
    domains: [acme.example.test]
    clients:
      - {client_id: app, app_type: spa}
    connections:
      - name: Legacy-DB
        enabled_clients: [app]
        enabledDatabaseCustomization: true
        customScripts: {login: "function login(u, p, cb) { cb(null, null); }"}
`
	if err := os.WriteFile(seedPath, []byte(seedYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Seed: seedPath,
		CustomDB: config.CustomDB{Node: filepath.Join(dir, "no-node")}}
	var logs strings.Builder
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if n := strings.Count(logs.String(), "cannot run their scripts"); n != 1 {
		t.Fatalf("warnings = %d; log:\n%s", n, logs.String())
	}
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "https://acme.example.test/.well-known/jwks.json", nil))
	if rec.Code != 200 {
		t.Fatalf("jwks = %d", rec.Code)
	}
}

// TestDeviceThrottlesFromConfig: the app builds the device activation
// limits from the security settings.
func TestDeviceThrottlesFromConfig(t *testing.T) {
	newApp := func(t *testing.T, sec config.Security) http.Handler {
		t.Helper()
		seedPath := filepath.Join(t.TempDir(), "seed.yaml")
		if err := os.WriteFile(seedPath, []byte("tenants:\n  - name: acme\n    domains: [acme.example.test]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Seed: seedPath, Security: sec}
		a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close() })
		return a.Handler()
	}
	check := func(t *testing.T, h http.Handler, remoteAddr string) int {
		t.Helper()
		req := httptest.NewRequest("GET", "https://acme.example.test/activate?user_code=BCDF-GHJK", nil)
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	t.Run("ip", func(t *testing.T) {
		h := newApp(t, config.Security{DeviceActivationTxnMaxMisses: 5, DeviceActivationIPMaxMisses: 2, DeviceActivationIPLockoutSeconds: 900})
		for i, want := range []int{400, 400, 429} {
			if got := check(t, h, "192.0.2.1:1234"); got != want {
				t.Fatalf("miss %d from one IP = %d, want %d", i+1, got, want)
			}
		}
		if got := check(t, h, "192.0.2.2:1234"); got != 400 {
			t.Fatalf("another IP = %d, want 400", got)
		}
	})
	t.Run("tenant", func(t *testing.T) {
		h := newApp(t, config.Security{DeviceActivationTxnMaxMisses: 5,
			DeviceActivationTenantMaxMisses: 2, DeviceActivationTenantWindowSeconds: 600, DeviceActivationTenantLockoutSeconds: 60})
		for i, want := range []int{400, 400, 429} {
			if got := check(t, h, fmt.Sprintf("192.0.2.%d:1234", i+1)); got != want {
				t.Fatalf("miss %d from another IP = %d, want %d", i+1, got, want)
			}
		}
	})
	t.Run("transaction", func(t *testing.T) {
		h := newApp(t, config.Security{DeviceActivationTxnMaxMisses: 1})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "https://acme.example.test/activate", nil))
		state := regexp.MustCompile(`name="state" value="([^"]+)"`).FindStringSubmatch(rec.Body.String())
		csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(rec.Body.String())
		if rec.Code != 200 || state == nil || csrf == nil {
			t.Fatalf("entry = %d %s", rec.Code, rec.Body)
		}
		cookies := rec.Result().Cookies()
		post := func() (int, string) {
			form := url.Values{"state": {state[1]}, "csrf": {csrf[1]}, "code": {"BCDF-GHJK"}}
			req := httptest.NewRequest("POST", "https://acme.example.test/activate", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for _, c := range cookies {
				req.AddCookie(c)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec.Code, rec.Body.String()
		}
		// The one allowed miss shows the entry form again; the next
		// request finds the transaction used up.
		if got, body := post(); got != 400 || !strings.Contains(body, `action="/activate"`) {
			t.Fatalf("first miss = %d\n%s", got, body)
		}
		if got, body := post(); got != 400 || strings.Contains(body, `action="/activate"`) {
			t.Fatalf("second miss = %d, want the session-expired page\n%s", got, body)
		}
	})
}

// The server creates the system tenant at start and serves it on the
// system host.
func TestNewEnsuresSystemTenant(t *testing.T) {
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "https://system.localhost/.well-known/openid-configuration", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"issuer":"https://system.localhost/"`) {
		t.Fatalf("discovery on the system host = %d %s", rec.Code, rec.Body)
	}
}

func TestNewRefusesSeedOnSystemHost(t *testing.T) {
	seedPath := filepath.Join(t.TempDir(), "seed.yaml")
	if err := os.WriteFile(seedPath, []byte("tenants:\n  - name: acme\n    domains: [System.Localhost]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Seed: seedPath}
	_, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "system host") {
		t.Fatalf("err = %v", err)
	}
}

// bootstrap.admin_email creates the first operator once: a later start
// with an operator present creates nothing and logs no link.
func TestBootstrapAdminEmailOnce(t *testing.T) {
	cfg := sqliteConfig(t, true)
	cfg.Bootstrap.AdminEmail = "root@example.test"
	setupLink := regexp.MustCompile(`setup_url="?https://system\.localhost/u/reset-password\?ticket=\S+`)
	start := func() string {
		t.Helper()
		var buf strings.Builder
		a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(&buf, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if log := start(); len(setupLink.FindAllString(log, -1)) != 1 || !strings.Contains(log, "root@example.test") {
		t.Fatalf("first start log has no single setup link:\n%s", log)
	}
	for range 2 {
		if log := start(); setupLink.MatchString(log) {
			t.Fatalf("a later start logged a setup link again:\n%s", log)
		}
	}
}

func TestNewWiresActionsBuilds(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "actions-cache")
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Actions: config.Actions{CacheDir: cache}}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.builds == nil {
		t.Fatal("no Actions build manager")
	}
	if err := a.builds.Prewarm(context.Background()); err != nil {
		t.Fatalf("Prewarm with nothing deployed: %v", err)
	}
	if root, err := a.builds.TenantRoot("t1"); err != nil || root != filepath.Join(cache, "t1") {
		t.Fatalf("TenantRoot = %s, %v; want under %s", root, err, cache)
	}
}
