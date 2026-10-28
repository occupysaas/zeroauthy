package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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
