package app

import (
	"bytes"
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"io"
	"log/slog"
	"testing"
)

type oldRBACStore struct{ store.Store }

func (oldRBACStore) CheckRBACSupport(context.Context) error { return store.ErrRBACUnavailable }
func TestRBACStartupCapability(t *testing.T) {
	st := memory.New()
	defer st.Close()
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Seed: "/nonexistent/seed.yaml"}
	_, err := build(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), oldRBACStore{st}, bytes.Repeat([]byte{1}, 32))
	if !errors.Is(err, store.ErrRBACUnavailable) {
		t.Fatalf("RBAC capability must fail before seed/listeners: %v", err)
	}
}
