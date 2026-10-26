package app

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestStartupDomainDriftPrecedesSeedRepair(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "a", Name: "acme", Domains: []string{"old.example.test"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.ResourceServers().Create(ctx, &store.ResourceServer{TenantID: "a", ID: "old", Identifier: "https://wrong.example.test/api/v2/", IsSystem: true}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "seed.yaml")
	if err := os.WriteFile(path, []byte("tenants: [{name: acme, domains: [new.example.test]}]"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := build(ctx, &config.Config{Server: config.Server{BaseDomain: "auth.example.test", SystemHost: "admin.example.test"}, Seed: path}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, make([]byte, 32))
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("startup drift = %v", err)
	}
	rows, _ := st.ResourceServers().List(ctx, "a")
	if len(rows) != 1 || rows[0].Identifier != "https://wrong.example.test/api/v2/" {
		t.Fatalf("seed hid drift: %+v", rows)
	}
	a, _ := st.Tenants().Get(ctx, "a")
	if a.CanonicalHost != "" || a.Domains[0] != "old.example.test" {
		t.Fatalf("failed startup mutated tenant: %+v", a)
	}
}

// With ACME on, startup validates that system and canonical identities are
// covered by a static certificate or the hosted wildcard, and serves TLS
// through the certificate manager.
func TestStartupTLSCoverage(t *testing.T) {
	ctx := context.Background()
	acme := config.ACME{Enabled: true, DirectoryURL: "https://ca.test/directory", Email: "ops@example.test", TermsAccepted: true,
		DeploymentID: "prod-1", Challenge: "tls-alpn-01", Workers: 2}
	cfg := &config.Config{Server: config.Server{BaseDomain: "auth.example.test", ACME: acme}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := build(ctx, cfg, log, memory.New(), make([]byte, 32)); err == nil || !strings.Contains(err.Error(), "covered") {
		t.Fatalf("uncovered system host = %v", err)
	}
	cfg.Server.ACME.HostedWildcard = config.HostedWildcard{Enabled: true, Zone: "example.test", TokenFile: "/dev/null"}
	a, err := build(ctx, cfg, log, memory.New(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if a.tls == nil {
		t.Fatal("no certificate manager")
	}
	if tc, err := a.tls.TLSConfig(); err != nil || tc.MinVersion != tls.VersionTLS12 {
		t.Fatalf("tls config = %+v, %v", tc, err)
	}
}
