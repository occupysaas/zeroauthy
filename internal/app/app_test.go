package app

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
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
