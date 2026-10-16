package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/pkg/storeplugin"
)

func TestNewSeedsAndServes(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.yaml")
	if err := os.WriteFile(seedPath, []byte("tenants:\n  - name: acme\n    domains: [acme.example.test]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Storage: config.Storage{DSN: "memory://"}, Seed: seedPath}
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
}

func TestNewRejectsBadSeed(t *testing.T) {
	cfg := &config.Config{Storage: config.Storage{DSN: "memory://"}, Seed: "/nonexistent/seed.yaml"}
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
		cfg := &config.Config{Storage: config.Storage{DSN: "memory://"}, Email: config.Email{Driver: driver, Dir: t.TempDir()}}
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
	cfg := &config.Config{Storage: config.Storage{DSN: "plugin:///nonexistent/plugin"}}
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
	cfg := &config.Config{Storage: config.Storage{DSN: "memory://"}, Seed: seedPath,
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
