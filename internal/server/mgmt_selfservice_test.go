package server

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/scim"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var selfServiceMgmtScopes = []string{
	"read:self_service_profiles", "create:self_service_profiles", "update:self_service_profiles", "delete:self_service_profiles",
	"read:self_service_profile_custom_texts", "update:self_service_profile_custom_texts", "create:sso_access_tickets", "delete:sso_access_tickets",
	"read:connection_profiles", "create:connection_profiles", "update:connection_profiles", "delete:connection_profiles",
}

func newSelfServiceManagement(t *testing.T) (*orgAPI, store.Store) {
	t.Helper()
	quoted := `"` + strings.Join(append(slices.Clone(orgMgmtScopes), selfServiceMgmtScopes...), `", "`) + `", `
	seedText := strings.Replace(usersSeed, `"read:connections", "create:connections"`, quoted+`"read:connections", "create:connections"`, 1)
	h, st := newMgmtEnvSeed(t, seedText, nil)
	return &orgAPI{t: t, h: h, c: newMgmtContract(t), admin: clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")}, st
}

// TestSelfServiceRoutes drives the self-service profile, custom text, SSO
// ticket and connection profile routes through the real router against
// api/management.yaml.
func TestSelfServiceRoutes(t *testing.T) {
	a, st := newSelfServiceManagement(t)
	admin := a.admin
	must := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		code, out, raw := a.call(method, path, admin, body)
		if code != want {
			t.Fatalf("%s %s=%d %s", method, path, code, raw)
		}
		return out
	}
	p := must("POST", "/self-service-profiles", map[string]any{"name": "Partners", "description": "Partner SSO",
		"branding":           map[string]any{"logo_url": "https://logo.example.test/a.png", "colors": map[string]any{"primary": "#19aecc"}},
		"allowed_strategies": []string{"samlp", "oidc"}, "user_attributes": []any{map[string]any{"name": "email", "description": "Work email", "is_optional": false}}}, 201)
	id := p["id"].(string)
	if !strings.HasPrefix(id, "ssp_") || p["description"] != "Partner SSO" || p["created_at"] == nil {
		t.Fatalf("created %v", p)
	}
	for name, body := range map[string]any{
		"no name":            map[string]any{},
		"http logo":          map[string]any{"name": "X", "branding": map[string]any{"logo_url": "http://logo.example.test"}},
		"unknown member":     map[string]any{"name": "X", "evil": true},
		"strategy not here":  map[string]any{"name": "X", "allowed_strategies": []string{"pingfederate"}},
		"strategy not known": map[string]any{"name": "X", "allowed_strategies": []string{"ldap"}},
	} {
		if code, _, raw := a.call("POST", "/self-service-profiles", admin, body); code != 400 {
			t.Errorf("%s: %d %s", name, code, raw)
		}
	}
	if code, _, _ := a.call("POST", "/self-service-profiles", admin, map[string]any{"name": "Partners"}); code != 409 {
		t.Fatalf("duplicate name %d", code)
	}
	up := must("PATCH", "/self-service-profiles/"+id, map[string]any{"description": nil, "name": "Partners EU"}, 200)
	if up["description"] != nil || up["name"] != "Partners EU" || up["branding"] == nil {
		t.Fatalf("patched %v", up)
	}
	list := must("GET", "/self-service-profiles?include_totals=true", nil, 200)
	if list["total"].(float64) != 1 {
		t.Fatalf("list %v", list)
	}
	// Custom text.
	base := "/self-service-profiles/" + id + "/custom-text/en/get-started"
	if got := must("GET", base, nil, 200); len(got) != 0 {
		t.Fatalf("unset text %v", got)
	}
	if got := must("PUT", base, map[string]any{"introduction": "Welcome, <b>partner</b>"}, 200); got["introduction"] != "Welcome, <b>partner</b>" {
		t.Fatalf("put text %v", got)
	}
	if code, _, _ := a.call("PUT", base, admin, map[string]any{"introduction": strings.Repeat("x", 2001)}); code != 400 {
		t.Fatalf("long text %d", code)
	}
	// Tickets.
	if code, _, raw := a.call("POST", "/self-service-profiles/"+id+"/sso-ticket", admin, map[string]any{}); code != 400 {
		t.Fatalf("ticket without a connection %d %s", code, raw)
	}
	if code, _, raw := a.call("POST", "/self-service-profiles/"+id+"/sso-ticket", admin, map[string]any{"connection_config": map[string]any{"name": "acme-sso"}, "enabled_clients": []string{"nope"}}); code != 400 {
		t.Fatalf("unknown client %d %s", code, raw)
	}
	if code, _, raw := a.call("POST", "/self-service-profiles/"+id+"/sso-ticket", admin, map[string]any{"connection_config": map[string]any{"name": "acme-sso"}, "ttl_sec": 432001}); code != 400 {
		t.Fatalf("long ttl %d %s", code, raw)
	}
	tk := must("POST", "/self-service-profiles/"+id+"/sso-ticket", map[string]any{"connection_config": map[string]any{"name": "acme-sso"}, "ttl_sec": 3600}, 201)
	u, err := url.Parse(tk["ticket"].(string))
	if err != nil || u.Scheme != "https" || u.Host != "acme.example.test" || u.Path != "/self-service/connections-flow" || len(u.Query().Get("ticket")) < 40 {
		t.Fatalf("ticket %v", tk)
	}
	token := u.Query().Get("ticket")
	ctx := context.Background()
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	stored, err := st.SelfService().GetTicketByHash(ctx, tn.ID, scim.HashToken(token))
	if err != nil || stored.ProfileID != id || stored.ExpiresAt.Sub(stored.CreatedAt).Seconds() != 3600 {
		t.Fatalf("stored ticket %+v %v", stored, err)
	}
	if strings.Contains(string(stored.Doc), token) || stored.Hash == token {
		t.Fatal("the ticket token is stored in the clear")
	}
	if code, _, _ := a.call("POST", "/self-service-profiles/"+id+"/sso-ticket", admin, map[string]any{"connection_config": map[string]any{"name": "Username-Password-Authentication"}}); code != 409 {
		t.Fatalf("existing connection name %d", code)
	}
	db, _ := st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	if code, _, _ := a.call("POST", "/self-service-profiles/"+id+"/sso-ticket", admin, map[string]any{"connection_id": db.ID}); code != 400 {
		t.Fatalf("database connection not allowed by the profile %d", code)
	}
	must("POST", "/self-service-profiles/"+id+"/sso-ticket/"+token+"/revoke", nil, 202)
	stored, _ = st.SelfService().GetTicketByHash(ctx, tn.ID, scim.HashToken(token))
	if stored.RevokedAt == nil {
		t.Fatal("ticket not revoked")
	}
	must("POST", "/self-service-profiles/"+id+"/sso-ticket/unknown/revoke", nil, 202)
	// Connection profiles and templates.
	cp := must("POST", "/connection-profiles", map[string]any{"name": "Partner SAML", "connection_name_prefix_template": "con-{org_name}", "enabled_features": []string{"scim"}}, 201)
	cid := cp["id"].(string)
	if code, _, _ := a.call("POST", "/connection-profiles", admin, map[string]any{"name": "Bad", "connection_name_prefix_template": "-bad"}); code != 400 {
		t.Fatalf("bad prefix template %d", code)
	}
	if code, _, _ := a.call("POST", "/connection-profiles", admin, map[string]any{"name": "Partner SAML"}); code != 409 {
		t.Fatalf("duplicate connection profile %d", code)
	}
	if got := must("PATCH", "/connection-profiles/"+cid, map[string]any{"enabled_features": []string{}}, 200); len(got["enabled_features"].([]any)) != 0 || got["connection_name_prefix_template"] != "con-{org_name}" {
		t.Fatalf("patched connection profile %v", got)
	}
	if got := must("GET", "/connection-profiles?take=10", nil, 200)["connection_profiles"].([]any); len(got) != 1 {
		t.Fatalf("connection profiles %v", got)
	}
	tpls := must("GET", "/connection-profiles/templates", nil, 200)["connection_profile_templates"].([]any)
	if len(tpls) == 0 {
		t.Fatal("no templates")
	}
	must("GET", "/connection-profiles/templates/"+tpls[0].(map[string]any)["id"].(string), nil, 200)
	if code, _, _ := a.call("GET", "/connection-profiles/templates/cpt_nope", admin, nil); code != 404 {
		t.Fatalf("unknown template %d", code)
	}
	must("DELETE", "/connection-profiles/"+cid, nil, 204)
	if code, _, _ := a.call("GET", "/connection-profiles/"+cid, admin, nil); code != 404 {
		t.Fatalf("deleted connection profile %d", code)
	}
	must("DELETE", "/self-service-profiles/"+id, nil, 204)
	if code, _, _ := a.call("GET", "/self-service-profiles/"+id, admin, nil); code != 404 {
		t.Fatalf("deleted profile %d", code)
	}
}

// TestSelfServiceScopes is the 401/403 matrix of the Phase B routes.
func TestSelfServiceScopes(t *testing.T) {
	a, _ := newSelfServiceManagement(t)
	p := "/self-service-profiles/ssp_x"
	cases := []struct{ method, path, scope string }{
		{"GET", "/self-service-profiles", "read:self_service_profiles"}, {"POST", "/self-service-profiles", "create:self_service_profiles"},
		{"GET", p, "read:self_service_profiles"}, {"PATCH", p, "update:self_service_profiles"}, {"DELETE", p, "delete:self_service_profiles"},
		{"GET", p + "/custom-text/en/get-started", "read:self_service_profile_custom_texts"},
		{"PUT", p + "/custom-text/en/get-started", "update:self_service_profile_custom_texts"},
		{"POST", p + "/sso-ticket", "create:sso_access_tickets"}, {"POST", p + "/sso-ticket/x/revoke", "delete:sso_access_tickets"},
		{"GET", "/connection-profiles", "read:connection_profiles"}, {"POST", "/connection-profiles", "create:connection_profiles"},
		{"GET", "/connection-profiles/cop_x", "read:connection_profiles"}, {"PATCH", "/connection-profiles/cop_x", "update:connection_profiles"},
		{"DELETE", "/connection-profiles/cop_x", "delete:connection_profiles"}, {"GET", "/connection-profiles/templates", "read:connection_profiles"},
		{"GET", "/connection-profiles/templates/cpt_sso", "read:connection_profiles"},
	}
	all := append(slices.Clone(orgMgmtScopes), selfServiceMgmtScopes...)
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
