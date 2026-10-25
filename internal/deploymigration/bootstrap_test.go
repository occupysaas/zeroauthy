package deploymigration

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestBootstrapPreservesCredentials(t *testing.T) {
	bootstrap, err := seed.Parse([]byte("tenants:\n  - name: destination\n    domains: [dest.example.test]\n    clients:\n      - client_id: local-tool\n        app_type: non_interactive\n        client_secret: local-secret\n        grant_types: [client_credentials]\n    client_grants:\n      - client_id: local-tool\n        audience: https://dest.example.test/api/v2/\n        scopes: [read:clients]\n"))
	if err != nil {
		t.Fatal(err)
	}
	source := Export{Resources: map[string]json.RawMessage{"clients": json.RawMessage(`[{"client_id":"source-id","name":"Web","app_type":"regular_web","token_endpoint_auth_method":"client_secret_post","grant_types":["authorization_code"],"is_first_party":false},{"client_id":"public-id","name":"SPA","app_type":"spa","token_endpoint_auth_method":"none","grant_types":["authorization_code"],"is_first_party":false}]`)}}
	got, err := PrepareBootstrap(source, bootstrap, map[string]string{"source-id": "source-secret"}, BootstrapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tenants) != 1 || len(got.Tenants[0].Clients) != 3 {
		t.Fatalf("prepared clients: %+v", got.Tenants)
	}
	if got.Tenants[0].Clients[2].ClientSecret != "" || got.Tenants[0].Clients[2].TokenEndpointAuthMethod != "none" {
		t.Fatal("public client credentials were not preserved as absent")
	}
}

func TestBootstrapInventoryCollision(t *testing.T) {
	if err := CheckExportInventory([]json.RawMessage{json.RawMessage(`{"name":"Auth0 Management API"}`)}); err == nil {
		t.Fatal("user API with reserved export name was not rejected")
	}
	if err := CheckExportInventory([]json.RawMessage{json.RawMessage(`{"name":"Auth0 Management API","is_system":true}`)}); err != nil {
		t.Fatalf("system API collision rejected: %v", err)
	}
}

func TestBootstrapRerun(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f, err := seed.Parse([]byte("tenants:\n  - name: destination\n    domains: [dest.example.test]\n    clients:\n      - client_id: local-tool\n        app_type: non_interactive\n        client_secret: local-secret\n        grant_types: [client_credentials]\n    client_grants:\n      - client_id: local-tool\n        audience: https://dest.example.test/api/v2/\n        scopes: [read:clients]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.CheckManagementAPI(""); err != nil {
		t.Fatal(err)
	}
	f.Mode = seed.ModeCreateOnly
	first, err := ApplyBootstrap(ctx, st, f, w, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if first.TenantID == "" || first.AlreadyApplied {
		t.Fatalf("first result: %+v", first)
	}
	second, err := ApplyBootstrap(ctx, st, f, w, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if !second.AlreadyApplied || second.TenantID != first.TenantID {
		t.Fatalf("repeat result: %+v", second)
	}
	tn, err := st.Tenants().Get(ctx, first.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	tn.FriendlyName = "edited after import"
	if err := st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBootstrap(ctx, st, f, w); err != nil {
		t.Fatalf("mutable tenant setting blocked rerun: %v", err)
	}
}

func TestBootstrapRedaction(t *testing.T) {
	boot, err := seed.Parse([]byte("tenants:\n  - name: destination\n    domains: [dest.example.test]\n    clients:\n      - client_id: tool\n        app_type: non_interactive\n        client_secret: local-secret\n        grant_types: [client_credentials]\n"))
	if err != nil {
		t.Fatal(err)
	}
	source := Export{Resources: map[string]json.RawMessage{"clients": json.RawMessage(`[{"client_id":"worker","name":"Worker","app_type":"regular_web","token_endpoint_auth_method":"client_secret_post","grant_types":["authorization_code"],"is_first_party":false}]`)}}
	_, err = PrepareBootstrap(source, boot, nil, BootstrapOptions{})
	if err == nil || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("missing secret error was not safely reported: %v", err)
	}
}
