package deploymigration

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store"
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
	if err := got.CheckManagementAPI(""); err != nil {
		t.Fatal(err)
	}
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	defer st.Close()
	result, err := ApplyBootstrap(t.Context(), st, got, w, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	web, err := st.Clients().Get(t.Context(), result.TenantID, "source-id")
	if err != nil || len(web.Secrets) != 1 {
		t.Fatal("confidential web client not applied")
	}
	secret, err := keys.OpenClientSecret(w, web.TenantID, web.ClientID, web.Secrets[0].Sealed)
	if err != nil || subtle.ConstantTimeCompare([]byte(secret), []byte("source-secret")) != 1 {
		t.Fatal("confidential web credential changed")
	}
	public, err := st.Clients().Get(t.Context(), result.TenantID, "public-id")
	if err != nil || len(public.Secrets) != 0 {
		t.Fatal("public client gained a secret")
	}
	if _, err = CheckBootstrap(t.Context(), st, got, w); err != nil {
		t.Fatalf("web client without client_credentials must support bootstrap rerun: %v", err)
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
	api, err := st.ResourceServers().GetByIdentifier(ctx, first.TenantID, "https://dest.example.test/api/v2/")
	if err != nil {
		t.Fatal(err)
	}
	api.TokenLifetime = 1234
	if err = st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
	if err = st.Connections().Create(ctx, &store.Connection{TenantID: first.TenantID, ID: "imported-users", Name: "Imported users", Strategy: store.StrategyDatabase}); err != nil {
		t.Fatal(err)
	}
	if _, err = ApplyBootstrap(ctx, st, f, w, time.Now); err != nil {
		t.Fatal(err)
	}
	saved, err := st.ResourceServers().GetByIdentifier(ctx, first.TenantID, api.Identifier)
	if err != nil || saved.TokenLifetime != 1234 {
		t.Fatal("bootstrap rerun reset edited Management API defaults")
	}
	savedTenant, err := st.Tenants().Get(ctx, first.TenantID)
	if err != nil || savedTenant.FriendlyName != "edited after import" {
		t.Fatal("bootstrap rerun reset imported settings")
	}
	if _, err = st.Connections().Get(ctx, first.TenantID, "imported-users"); err != nil {
		t.Fatal("bootstrap rerun changed imported connections")
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
	source.Resources["clients"] = json.RawMessage(`[{"client_id":"worker","name":"Worker","app_type":"regular_web","token_endpoint_auth_method":"client_secret_post","grant_types":["authorization_code"],"SENTINEL_FIELD":"SENTINEL_SECRET"}]`)
	_, err = PrepareBootstrap(source, boot, map[string]string{"worker": "SENTINEL_SECRET"}, BootstrapOptions{})
	if err == nil || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("unsupported source field leaked input: %v", err)
	}
	source.Resources["clients"] = json.RawMessage(`[]`)
	_, err = PrepareBootstrap(source, boot, map[string]string{"SENTINEL_ID": "SENTINEL_SECRET"}, BootstrapOptions{})
	if err == nil || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("unexpected credential leaked input: %v", err)
	}

}

func TestBootstrapPinnedExportMetadata(t *testing.T) {
	boot, err := seed.Parse([]byte("tenants:\n  - name: destination\n    domains: [dest.example.test]\n"))
	if err != nil {
		t.Fatal(err)
	}
	source := Export{Resources: map[string]json.RawMessage{"clients": json.RawMessage(`[{"client_id":"web","name":"Web","tenant":"source","created_at":"2026-10-20T12:00:00Z","app_type":"regular_web","oidc_conformant":true,"token_endpoint_auth_method":"client_secret_post","grant_types":["authorization_code"],"jwt_configuration":{"alg":"RS256","lifetime_in_seconds":1234,"secret_encoded":false},"refresh_token":{"rotation_type":"non-rotating","expiration_type":"non-expiring","token_lifetime":31557600,"idle_token_lifetime":2592000,"infinite_token_lifetime":true,"infinite_idle_token_lifetime":true}}]`)}}
	prepared, err := PrepareBootstrap(source, boot, map[string]string{"web": "web-secret"}, BootstrapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Tenants[0].Clients[0].IDTokenLifetime != 1234 {
		t.Fatal("exported ID-token lifetime lost")
	}
}

func TestBootstrapRerunRefusesConflictsWithoutMutation(t *testing.T) {
	for _, kind := range []string{"credential", "authentication", "partial", "api-origin", "unrelated-domain", "expired-credential"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			st := memory.New()
			defer st.Close()
			w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{9}, 32))
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte("tenants:\n  - name: destination\n    domains: [dest.example.test]\n    clients:\n      - client_id: web\n        name: Web\n        app_type: regular_web\n        client_secret: web-secret\n        token_endpoint_auth_method: client_secret_post\n        grant_types: [authorization_code]\n")
			f, err := seed.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.CheckManagementAPI(""); err != nil {
				t.Fatal(err)
			}
			first, err := ApplyBootstrap(ctx, st, f, w, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "expired-credential":
				client, _ := st.Clients().Get(ctx, first.TenantID, "web")
				expired := time.Now().Add(-time.Hour)
				for i := range client.Secrets {
					client.Secrets[i].ExpiresAt = &expired
				}
				if err = st.Clients().Update(ctx, client); err != nil {
					t.Fatal(err)
				}
			case "credential":
				f.Tenants[0].Clients[0].ClientSecret = "CHANGED-SENTINEL"
			case "authentication":
				f.Tenants[0].Clients[0].TokenEndpointAuthMethod = "client_secret_basic"
			case "partial":
				f.Tenants[0].Clients = append(f.Tenants[0].Clients, seed.Client{ClientID: "missing", Name: "Missing", AppType: "spa", TokenEndpointAuthMethod: "none", GrantTypes: []string{"authorization_code"}})
			case "api-origin":
				tn, _ := st.Tenants().Get(ctx, first.TenantID)
				tn.Origin = store.OriginAPI
				if err = st.Tenants().Update(ctx, tn); err != nil {
					t.Fatal(err)
				}
			case "unrelated-domain":
				f.Tenants[0].Name = "different"
			}
			before, _ := st.Clients().Get(ctx, first.TenantID, "web")
			beforeJSON, _ := json.Marshal(before)
			_, err = ApplyBootstrap(ctx, st, f, w, time.Now)
			if err == nil || strings.Contains(err.Error(), "CHANGED-SENTINEL") {
				t.Fatalf("conflict was not safely rejected: %v", err)
			}
			after, _ := st.Clients().Get(ctx, first.TenantID, "web")
			afterJSON, _ := json.Marshal(after)
			if !bytes.Equal(beforeJSON, afterJSON) {
				t.Fatal("failed bootstrap mutated existing client")
			}
		})
	}
}
