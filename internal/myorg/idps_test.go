package myorg

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const testSecret = "oidc-client-secret-value-1"

// withWrites gives the env the in-process Management API (Phase B writes).
func (e *env) withWrites(t *testing.T) {
	t.Helper()
	e.h.Writes = &mgmt.Handlers{Store: e.st, Wrapper: e.w, Keys: e.km, Now: func() time.Time { return e.now }}
	e.route = e.h.Routes()
}

func oidcIdP(name string) map[string]any {
	return map[string]any{"name": name, "strategy": "oidc", "display_name": "Acme SSO",
		"options": map[string]any{"type": "back_channel", "client_id": "acme-client", "client_secret": testSecret, "discovery_url": "https://idp.acme.example/.well-known/openid-configuration"}}
}

func (e *env) createIdP(t *testing.T, tok string, body map[string]any) map[string]any {
	t.Helper()
	rec, out := e.do(t, tok, "POST", "/identity-providers", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	return out
}

func TestIdPConfig(t *testing.T) {
	e := newEnv(t)
	tok := e.adminToken(t)
	rec, cfg := e.do(t, tok, "GET", "/config/identity-providers", nil)
	if rec.Code != 200 {
		t.Fatalf("config = %d %s", rec.Code, rec.Body)
	}
	org := cfg["organization"].(map[string]any)
	strategies := cfg["strategies"].(map[string]any)
	if org["can_set_show_as_button"] != false || org["can_set_assign_membership_on_login"] != false || len(strategies) != 1 ||
		cfg["domain_aliases_config"].(map[string]any)["domain_verification"] != "optional" {
		t.Fatalf("defaults %v", cfg)
	}
	if s := strategies["oidc"].(map[string]any); len(s["enabled_features"].([]any)) != 0 || len(s["provisioning_methods"].([]any)) != 0 {
		t.Fatalf("oidc defaults %v", s)
	}
	must(t, e.st.SelfService().CreateConnectionProfile(context.Background(), &store.ConnectionProfile{TenantID: e.tn.ID, ID: "cop_1", Name: "SSO",
		Doc: []byte(`{"organization":{"show_as_button":"optional","assign_membership_on_login":"required"},"enabled_features":[],"strategy_overrides":{"okta":{"enabled_features":["scim"]},"google-apps":{"enabled_features":["universal_logout"]}},"provisioning":{"scim":{"tokens":{"scopes":["get:users","post:users"],"default_expiry":3600}}}}`)}))
	e.setConfig(t, `{"connection_profile_id":"cop_1","allowed_strategies":["oidc","okta","google-apps"],"connection_deletion_behavior":"allow","invitation_landing_client_id":"portal"}`)
	_, cfg = e.do(t, e.adminToken(t), "GET", "/config/identity-providers", nil)
	org = cfg["organization"].(map[string]any)
	strategies = cfg["strategies"].(map[string]any)
	if org["can_set_show_as_button"] != true || org["can_set_assign_membership_on_login"] != false || len(strategies) != 3 {
		t.Fatalf("profile config %v", cfg)
	}
	okta := strategies["okta"].(map[string]any)
	if okta["enabled_features"].([]any)[0] != "provisioning" || okta["provisioning_methods"].([]any)[0] != "scim" {
		t.Fatalf("okta %v", okta)
	}
	if tokens := okta["provisioning"].(map[string]any)["scim"].(map[string]any)["tokens"].(map[string]any); tokens["default_expiry"] != float64(3600) || len(tokens["scopes"].([]any)) != 2 {
		t.Fatalf("okta tokens %v", okta)
	}
	if g := strategies["googleapps"].(map[string]any); g["enabled_features"].([]any)[0] != "universal_logout" || len(g["provisioning_methods"].([]any)) != 0 {
		t.Fatalf("google-apps %v", g)
	}
	if o := strategies["oidc"].(map[string]any); len(o["enabled_features"].([]any)) != 0 {
		t.Fatalf("oidc %v", o)
	}
}

func TestIdPCreateRead(t *testing.T) {
	e := newEnv(t)
	e.withWrites(t)
	tok := e.adminToken(t)
	idp := e.createIdP(t, tok, oidcIdP("acme-sso"))
	id, _ := idp["id"].(string)
	if !strings.HasPrefix(id, "con_") || idp["name"] != "acme-sso" || idp["strategy"] != "oidc" || idp["access_level"] != "full" || idp["is_enabled"] != true ||
		idp["display_name"] != "Acme SSO" || idp["options"].(map[string]any)["client_id"] != "acme-client" || len(idp["attributes"].([]any)) != 0 {
		t.Fatalf("created %v", idp)
	}
	ctx := context.Background()
	oc, err := e.st.Organizations().GetConnection(ctx, e.tn.ID, e.orgA.ID, id)
	must(t, err)
	conn, err := e.st.Connections().Get(ctx, e.tn.ID, id)
	must(t, err)
	if oc.OrganizationAccessLevel != "full" || !oc.IsEnabled || len(conn.EnabledClients) != 1 || conn.EnabledClients[0] != "portal" {
		t.Fatalf("stored %+v %v", oc, conn.EnabledClients)
	}
	if rec, g := e.do(t, tok, "GET", "/identity-providers/"+id, nil); rec.Code != 200 || g["id"] != id {
		t.Fatalf("get = %d %v", rec.Code, g)
	}
	// A disabled, limited provider for the filters.
	idp2 := e.createIdP(t, tok, oidcIdP("acme-sso-2"))
	must(t, e.st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: e.tn.ID, OrganizationID: e.orgA.ID, ConnectionID: idp2["id"].(string), OrganizationAccessLevel: "readonly", OrganizationMemberAccessLevel: "full", IsEnabled: false, IsEnabledSet: true}, false))
	count := func(q string) int {
		rec, l := e.do(t, tok, "GET", "/identity-providers"+q, nil)
		if rec.Code != 200 {
			t.Fatalf("list%s = %d %s", q, rec.Code, rec.Body)
		}
		return len(l["identity_providers"].([]any))
	}
	if count("") != 2 || count("?is_enabled=true") != 1 || count("?is_enabled=false") != 1 || count("?member_access_level=full") != 1 || count("?member_access_level=none&member_access_level=limited") != 1 {
		t.Fatal("filters")
	}
	if rec, _ := e.do(t, tok, "GET", "/identity-providers?is_enabled=maybe", nil); rec.Code != 400 {
		t.Fatalf("bad filter = %d", rec.Code)
	}
	// Refusals.
	okta := map[string]any{"name": "acme-okta", "strategy": "okta", "options": map[string]any{"domain": "acme.okta.com", "client_id": "c", "client_secret": "s"}}
	if rec, b := e.do(t, tok, "POST", "/identity-providers", okta); rec.Code != 400 || !strings.Contains(b["detail"].(string), "allowed") {
		t.Fatalf("strategy not allowed = %d %v", rec.Code, b)
	}
	if rec, _ := e.do(t, tok, "POST", "/identity-providers", oidcIdP("acme-sso")); rec.Code != 409 {
		t.Fatalf("duplicate name = %d", rec.Code)
	}
	bad := oidcIdP("acme-bad")
	bad["options"].(map[string]any)["issuer"] = "https://x"
	if rec, _ := e.do(t, tok, "POST", "/identity-providers", bad); rec.Code != 400 {
		t.Fatalf("unknown option = %d", rec.Code)
	}
	cross := oidcIdP("acme-cross")
	cross["cross_app_access_resource_app"] = map[string]any{}
	if rec, _ := e.do(t, tok, "POST", "/identity-providers", cross); rec.Code != 400 {
		t.Fatalf("cross-app access = %d", rec.Code)
	}
	// Nothing half-made remains after a refused create.
	if _, err := e.st.Connections().GetByName(ctx, e.tn.ID, "acme-bad"); err == nil {
		t.Fatal("refused provider stored")
	}
}

// TestIdPIsolation: providers of another organization, unlinked ones and
// access level none are 404 on every provider route.
func TestIdPIsolation(t *testing.T) {
	e := newEnv(t)
	e.withWrites(t)
	carol := e.tokenFor(t, e.carol.UserID, e.orgB.ID)
	theirs := e.createIdP(t, carol, oidcIdP("other-sso"))["id"].(string)
	ctx := context.Background()
	hidden := e.createIdP(t, e.adminToken(t), oidcIdP("hidden-sso"))["id"].(string)
	must(t, e.st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: e.tn.ID, OrganizationID: e.orgA.ID, ConnectionID: hidden, OrganizationAccessLevel: "none", IsEnabled: true, IsEnabledSet: true}, false))
	tok := e.adminToken(t)
	routes := []struct{ method, path string }{
		{"GET", ""}, {"PATCH", ""}, {"DELETE", ""}, {"PUT", "/update-attributes"}, {"POST", "/detach"}, {"POST", "/domains"}, {"DELETE", "/domains/acme.example"},
		{"GET", "/provisioning"}, {"POST", "/provisioning"}, {"DELETE", "/provisioning"}, {"PUT", "/provisioning/update-attributes"},
		{"GET", "/provisioning/scim-tokens"}, {"POST", "/provisioning/scim-tokens"}, {"GET", "/provisioning/scim-tokens/tok"}, {"DELETE", "/provisioning/scim-tokens/tok"},
	}
	for _, id := range []string{theirs, hidden, e.conn.ID, "con_doesnotexist0000"} {
		for _, rt := range routes {
			var body any
			if rt.method != "GET" && rt.method != "DELETE" {
				body = map[string]any{}
			}
			if rt.path == "/domains" {
				body = map[string]any{"domain": "acme.example"}
			}
			rec, _ := e.do(t, tok, rt.method, "/identity-providers/"+id+rt.path, body)
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s%s = %d %s", rt.method, id, rt.path, rec.Code, rec.Body)
			}
		}
	}
	_, l := e.do(t, tok, "GET", "/identity-providers", nil)
	if len(l["identity_providers"].([]any)) != 0 {
		t.Fatalf("list shows %v", l)
	}
	if _, err := e.st.Connections().Get(ctx, e.tn.ID, theirs); err != nil {
		t.Fatal("other organization's provider changed")
	}
}

// TestIdPNoSecrets: no client secret in responses or logs.
func TestIdPNoSecrets(t *testing.T) {
	e := newEnv(t)
	e.withWrites(t)
	tok := e.adminToken(t)
	rec, idp := e.do(t, tok, "POST", "/identity-providers", oidcIdP("acme-sso"))
	bodies := rec.Body.String()
	rec, _ = e.do(t, tok, "GET", "/identity-providers/"+idp["id"].(string), nil)
	bodies += rec.Body.String()
	rec, _ = e.do(t, tok, "GET", "/identity-providers", nil)
	bodies += rec.Body.String()
	if strings.Contains(bodies, testSecret) || strings.Contains(bodies, "client_secret") || strings.Contains(e.logs.String(), testSecret) {
		t.Fatalf("secret exposed: %s / %s", bodies, e.logs)
	}
}
