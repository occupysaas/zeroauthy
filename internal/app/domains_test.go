package app

import (
	"context"
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
