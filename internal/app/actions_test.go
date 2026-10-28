package app

import (
	"context"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/keys"
)

func TestActionsStartupSeed(t *testing.T) {
	actionstest.RequireNode(t)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected registry request %s", r.URL)
		http.NotFound(w, r)
	}))
	defer registry.Close()
	path := filepath.Join(t.TempDir(), "seed.yaml")
	doc := `tenants:
- name: acme
  domains: [acme.example.test]
  actions:
  - name: startup
    code: exports.onExecutePostLogin = async () => {};
    supported_triggers: [{id: post-login}]
    secrets: [{name: KEY, value: value}]
    deploy: true
  triggers:
    post-login:
      bindings: [{ref: {type: action_name, value: startup}}]
`
	if err := os.WriteFile(path, []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Security: config.Security{MasterKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}, Seed: path, Actions: config.Actions{CacheDir: t.TempDir(), Registry: registry.URL}}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	tn, err := a.store.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	bs, err := a.store.Actions().Bindings(context.Background(), tn.ID, "post-login")
	if err != nil || len(bs) != 1 || bs[0].Version.Number != 1 {
		t.Fatalf("startup bindings=%v %v", bs, err)
	}
	master, err := cfg.Security.MasterKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := keys.NewLocalWrapper(master)
	if err != nil {
		t.Fatal(err)
	}
	value, err := keys.OpenActionSecret(wrapper, tn.ID, bs[0].Action.ID, "KEY", bs[0].Version.Secrets[0].Sealed)
	if err != nil || value != "value" {
		t.Fatalf("startup secret=%q %v", value, err)
	}
}

// Serve must drain durable Actions jobs and stop the worker before returning.
func TestActionsJobsServeLifecycle(t *testing.T) {
	actionstest.RequireNode(t)
	delivered := make(chan struct{}, 2)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { delivered <- struct{}{} }))
	defer sink.Close()
	seedPath := filepath.Join(t.TempDir(), "seed.yaml")
	doc := fmt.Sprintf(`tenants:
- name: acme
  domains: [acme.example.test]
  actions:
  - name: queued
    code: exports.onExecutePostUserRegistration = async () => { await fetch(%q); };
    supported_triggers: [{id: post-user-registration}]
    deploy: true
  triggers:
    post-user-registration:
      bindings: [{ref: {type: action_name, value: queued}}]
`, sink.URL)
	if err := os.WriteFile(seedPath, []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Server: config.Server{Listen: "127.0.0.1:0", BaseDomain: "example.test", SystemHost: "system.example.test"}, Storage: config.Storage{DSN: "memory://"}, Security: config.Security{MasterKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}, Seed: seedPath, Actions: config.Actions{CacheDir: t.TempDir(), JobWorkers: 1, JobPollInterval: 10 * time.Millisecond}}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	tn, err := a.store.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	enqueue := func() {
		t.Helper()
		if err := a.store.WithTx(context.Background(), func(tx store.Store) error {
			return a.actionJobs.Engine.Enqueue(context.Background(), tx, actions.AsyncJob{TenantID: tn.ID, Trigger: actions.TriggerPostUserRegistration, Input: map[string]any{}})
		}); err != nil {
			t.Fatal(err)
		}
	}
	enqueue()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx) }()
	select {
	case <-delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not start Actions worker")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop Actions worker")
	}
	enqueue()
	select {
	case <-delivered:
		t.Fatal("worker delivered after Serve returned")
	case <-time.After(50 * time.Millisecond):
	}
}
