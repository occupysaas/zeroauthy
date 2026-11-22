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
	"strings"
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

type oldActionsStore struct{ store.Store }

func (oldActionsStore) CheckActionsSupport(context.Context) error { return store.ErrActionsUnavailable }
func TestActionsStartupCapability(t *testing.T) {
	st := memory.New()
	defer st.Close()
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Seed: "/nonexistent/seed.yaml"}
	_, err := build(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), oldActionsStore{st}, bytes.Repeat([]byte{1}, 32))
	if !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatalf("Actions capability must fail before seed/listeners: %v", err)
	}
}

type refreshCapabilityStore struct {
	oldRBACStore
	probeError error
}

func (s refreshCapabilityStore) CheckRefreshTokensIISupport(context.Context) error {
	return s.probeError
}
func TestRefreshIIStartupCapability(t *testing.T) {
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}}
	for _, tc := range []struct {
		name        string
		probe, want error
		warnings    int
	}{
		{"legacy", store.ErrRefreshTokensIIUnavailable, store.ErrRBACUnavailable, 1},
		{"transport", context.DeadlineExceeded, context.DeadlineExceeded, 0},
		{"current", nil, store.ErrRBACUnavailable, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := refreshCapabilityStore{oldRBACStore{memory.New()}, tc.probe}
			defer st.Close()
			var buf bytes.Buffer
			_, err := build(context.Background(), cfg, slog.New(slog.NewTextHandler(&buf, nil)), st, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("startup error=%v", err)
			}
			if n := strings.Count(buf.String(), "legacy leeway"); n != tc.warnings {
				t.Fatalf("warnings=%d want %d", n, tc.warnings)
			}
		})
	}
}
