package app

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type microsoftPredecessorStore struct{ store.Store }

func TestMicrosoftStartupPreflight(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	defer st.Close()
	_ = st.Tenants().Create(ctx, &store.Tenant{ID: "local", Name: "acme"})
	_ = st.Connections().Create(ctx, &store.Connection{TenantID: "local", ID: "ms", Name: "ms", Strategy: "windowslive"})
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Seed: "/nonexistent/seed.yaml"}
	_, err := build(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), microsoftPredecessorStore{st}, bytes.Repeat([]byte{1}, 32))
	if err == nil || !strings.Contains(err.Error(), "Microsoft federation preflight") {
		t.Fatalf("preflight did not precede seed: %v", err)
	}
}
