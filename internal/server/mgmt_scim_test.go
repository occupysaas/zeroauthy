package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/scim"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var scimMgmtScopes = []string{"read:scim_config", "create:scim_config", "update:scim_config", "delete:scim_config", "read:scim_token", "create:scim_token", "delete:scim_token"}

func newSCIMManagement(t *testing.T) (*orgAPI, store.Store, string) {
	t.Helper()
	quoted := `"` + strings.Join(append(slices.Clone(orgMgmtScopes), scimMgmtScopes...), `", "`) + `", `
	seedText := strings.Replace(usersSeed, `"read:connections", "create:connections"`, quoted+`"read:connections", "create:connections"`, 1)
	h, st := newMgmtEnvSeed(t, seedText, nil)
	a := &orgAPI{t: t, h: h, c: newMgmtContract(t), admin: clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")}
	ctx := context.Background()
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	conn := &store.Connection{TenantID: tn.ID, ID: "con_scimMgmt0123", Name: "corp-okta", Strategy: "okta", Extra: map[string]any{"domain": "corp.okta.test"}}
	if err := st.Connections().Create(ctx, conn); err != nil {
		t.Fatal(err)
	}
	return a, st, conn.ID
}

// scimCall calls the connection's SCIM endpoint on the tenant host.
func scimCall(a *orgAPI, conn, method, path, token, body string) (int, map[string]any) {
	req := httptest.NewRequest(method, "https://acme.example.test/scim/v2/connections/"+conn+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", scim.MediaType)
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// TestSCIMManagementRoutes: a SCIM configuration and token made through the
// Management API authorize the connection's SCIM endpoint; the token is
// shown once, scoped, limited to two, and revoked by DELETE.
func TestSCIMManagementRoutes(t *testing.T) {
	a, st, conn := newSCIMManagement(t)
	admin := a.admin
	must := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		code, out, raw := a.call(method, path, admin, body)
		if code != want {
			t.Fatalf("%s %s=%d %s", method, path, code, raw)
		}
		return out
	}
	base := "/connections/" + conn + "/scim-configuration"
	if code, _, _ := a.call("GET", base, admin, nil); code != 404 {
		t.Fatalf("no configuration %d", code)
	}
	if code, _, _ := a.call("POST", base+"/tokens", admin, map[string]any{}); code != 404 {
		t.Fatalf("token without configuration %d", code)
	}
	dm := must("GET", base+"/default-mapping", nil, 200)
	if len(dm["mapping"].([]any)) != len(scim.DefaultMapping()) {
		t.Fatalf("default mapping %v", dm)
	}
	cfg := must("POST", base, nil, 201)
	if cfg["user_id_attribute"] != "externalId" || cfg["strategy"] != "okta" || cfg["connection_name"] != "corp-okta" || len(cfg["mapping"].([]any)) != len(scim.DefaultMapping()) {
		t.Fatalf("created %v", cfg)
	}
	// Auth0 answers 400 "... already exists" (the Deploy CLI 9.1.0
	// scimHandler matches on that message).
	if code, out, _ := a.call("POST", base, admin, nil); code != 400 || !strings.Contains(out["message"].(string), "already exists") {
		t.Fatalf("second configuration %d %v", code, out)
	}
	for name, body := range map[string]any{
		"unknown auth0 field": map[string]any{"user_id_attribute": "externalId", "mapping": []any{map[string]any{"auth0": "password", "scim": "password"}}},
		"bad scim path":       map[string]any{"user_id_attribute": "externalId", "mapping": []any{map[string]any{"auth0": "email", "scim": "a..b"}}},
		"bad uid":             map[string]any{"user_id_attribute": "emails[", "mapping": []any{}},
		"missing mapping":     map[string]any{"user_id_attribute": "externalId"},
	} {
		if code, _, raw := a.call("PATCH", base, admin, body); code != 400 {
			t.Errorf("%s: %d %s", name, code, raw)
		}
	}
	up := must("PATCH", base, map[string]any{"user_id_attribute": "userName", "mapping": []any{map[string]any{"auth0": "email", "scim": "emails[primary eq true].value"}}}, 200)
	if up["user_id_attribute"] != "userName" || len(up["mapping"].([]any)) != 1 {
		t.Fatalf("updated %v", up)
	}
	list := must("GET", "/connections-scim-configurations", nil, 200)
	if len(list["scim_configurations"].([]any)) != 1 {
		t.Fatalf("list %v", list)
	}
	// Tokens.
	for _, body := range []any{map[string]any{"token_lifetime": 900}, map[string]any{"scopes": []string{"get:everything"}}, map[string]any{"scopes": []string{}}} {
		if code, _, raw := a.call("POST", base+"/tokens", admin, body); code != 400 {
			t.Errorf("token %v: %d %s", body, code, raw)
		}
	}
	tok := must("POST", base+"/tokens", map[string]any{"scopes": []string{"get:users", "post:users"}, "token_lifetime": 3600}, 201)
	secret, _ := tok["token"].(string)
	if len(secret) < 32 || tok["valid_until"] == nil {
		t.Fatalf("token %v", tok)
	}
	ctx := context.Background()
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	stored, _ := st.Directory().ListSCIMTokens(ctx, tn.ID, conn)
	if len(stored) != 1 || stored[0].Hash == secret || stored[0].Hash != scim.HashToken(secret) {
		t.Fatal("the token is not stored as its hash")
	}
	if code, _ := scimCall(a, conn, "POST", "/Users", secret, `{"userName":"jdoe","emails":[{"primary":true,"value":"jdoe@corp.test"}]}`); code != 201 {
		t.Fatalf("SCIM create with the Management token: %d", code)
	}
	if code, _ := scimCall(a, conn, "DELETE", "/Users/okta|corp-okta|jdoe", secret, ""); code != 403 {
		t.Fatalf("SCIM delete without delete:users: %d", code)
	}
	code, raw := a.c.do(a.h, "GET", "https://acme.example.test/api/v2"+base+"/tokens", admin, nil)
	var listed []map[string]any
	if err := json.Unmarshal(raw, &listed); code != 200 || err != nil || len(listed) != 1 || listed[0]["token"] != nil || listed[0]["last_used_at"] == nil {
		t.Fatalf("token list %d %s", code, raw)
	}
	must("POST", base+"/tokens", map[string]any{}, 201)
	if code, _, _ := a.call("POST", base+"/tokens", admin, map[string]any{}); code != 409 {
		t.Fatalf("third token %d", code)
	}
	must("DELETE", base+"/tokens/"+tok["token_id"].(string), nil, 204)
	if code, _, _ := a.call("DELETE", base+"/tokens/"+tok["token_id"].(string), admin, nil); code != 404 {
		t.Fatalf("deleted token again %d", code)
	}
	if code, _ := scimCall(a, conn, "GET", "/Users", secret, ""); code != 401 {
		t.Fatalf("revoked token still works: %d", code)
	}
	// SCIM is refused for a database connection.
	db, err := st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	if code, _, _ := a.call("POST", "/connections/"+db.ID+"/scim-configuration", admin, nil); code != 400 {
		t.Fatalf("database connection SCIM %d", code)
	}
	must("DELETE", base, nil, 204)
	if left, _ := st.Directory().ListSCIMTokens(ctx, tn.ID, conn); len(left) != 0 {
		t.Fatalf("tokens survived the configuration: %d", len(left))
	}
}

// TestSCIMManagementScopes is the 401/403 matrix of the SCIM routes.
func TestSCIMManagementScopes(t *testing.T) {
	a, _, conn := newSCIMManagement(t)
	base := "/connections/" + conn + "/scim-configuration"
	cases := []struct{ method, path, scope string }{
		{"GET", base, "read:scim_config"}, {"POST", base, "create:scim_config"}, {"PATCH", base, "update:scim_config"},
		{"DELETE", base, "delete:scim_config"}, {"GET", base + "/default-mapping", "read:scim_config"},
		{"GET", base + "/tokens", "read:scim_token"}, {"POST", base + "/tokens", "create:scim_token"},
		{"DELETE", base + "/tokens/tok_x", "delete:scim_token"}, {"GET", "/connections-scim-configurations", "read:scim_config"},
	}
	all := append(slices.Clone(orgMgmtScopes), scimMgmtScopes...)
	for _, c := range cases {
		t.Run(c.method+c.path, func(t *testing.T) {
			if code, _, raw := a.call(c.method, c.path, "", map[string]any{}); code != 401 {
				t.Fatalf("no token=%d %s", code, raw)
			}
			var others []string
			for _, s := range all {
				if s != c.scope {
					others = append(others, s)
				}
			}
			if code, out, raw := a.call(c.method, c.path, a.token(others), map[string]any{}); code != 403 || out["errorCode"] != "insufficient_scope" {
				t.Fatalf("without %s=%d %s", c.scope, code, raw)
			}
			if code, _, raw := a.call(c.method, c.path, a.token([]string{c.scope}), map[string]any{}); code == 401 || code == 403 {
				t.Fatalf("with only %s=%d %s", c.scope, code, raw)
			}
		})
	}
}
