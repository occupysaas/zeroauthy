package app

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
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
