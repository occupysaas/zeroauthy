package app

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	cfg.Server.CustomDomains.DNSResolver = "127.0.0.1:53"
	cfg.Server.ACME.HostedWildcard = config.HostedWildcard{Enabled: true, Zone: "example.test", TokenFile: "/dev/null"}
	if _, err := build(ctx, cfg, log, memory.New(), make([]byte, 32)); err == nil || !strings.Contains(err.Error(), "token_file") {
		t.Fatalf("empty token file = %v", err)
	}
	cfg.Server.ACME.HostedWildcard.TokenFile = tokenFile(t)
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

// With HTTP-01 ACME, Serve also runs the challenge listener and the
// certificate worker, and stops both on shutdown.
func TestServeACMELifecycle(t *testing.T) {
	acme := config.ACME{Enabled: true, DirectoryURL: "https://127.0.0.1:1/directory", Email: "ops@example.test", TermsAccepted: true,
		DeploymentID: "prod-1", Challenge: "http-01", HTTPListen: "127.0.0.1:0", Workers: 1,
		HostedWildcard: config.HostedWildcard{Enabled: true, Zone: "example.test", TokenFile: tokenFile(t)}}
	cfg := &config.Config{Server: config.Server{Listen: "127.0.0.1:0", BaseDomain: "auth.example.test", ACME: acme,
		CustomDomains: config.CustomDomains{DNSResolver: "127.0.0.1:53"}}}
	a, err := build(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), memory.New(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if a.acme == nil || a.domains == nil {
		t.Fatal("ACME worker or domain service not built")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve = %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func tokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "do-token")
	if err := os.WriteFile(p, []byte("dop_v1_test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The custom domain service is wired without ACME too: self-managed domains
// need origin TLS, managed ones need ACME, and both report 503 otherwise.
func TestStartupDomainServiceWithoutACME(t *testing.T) {
	cfg := &config.Config{Server: config.Server{BaseDomain: "auth.example.test", CustomDomains: config.CustomDomains{DNSResolver: "127.0.0.1:53"}}}
	a, err := build(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), memory.New(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if a.domains == nil || a.acme != nil || a.tls != nil {
		t.Fatalf("domains=%v acme=%v tls=%v", a.domains != nil, a.acme != nil, a.tls != nil)
	}
	if _, err := a.domains.Create(context.Background(), "nobody", customdomain.CreateInput{Domain: "id.example.org", Type: customdomain.TypeManaged}); !errors.Is(err, customdomain.ErrManagedUnavailable) {
		t.Fatalf("managed without ACME = %v", err)
	}
}
