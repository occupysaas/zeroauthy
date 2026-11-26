package myorg

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (e *env) setAccess(t *testing.T, id, level string) {
	t.Helper()
	oc, err := e.st.Organizations().GetConnection(context.Background(), e.tn.ID, e.orgA.ID, id)
	must(t, err)
	oc.OrganizationAccessLevel = level
	must(t, e.st.Organizations().PutConnection(context.Background(), *oc, false))
}

func TestIdPAccessLevels(t *testing.T) {
	e := newEnv(t)
	e.withWrites(t)
	tok := e.adminToken(t)
	id := e.createIdP(t, tok, oidcIdP("acme-sso"))["id"].(string)
	opts := map[string]any{"type": "front_channel", "client_id": "new", "discovery_url": "https://idp.acme.example/.well-known/openid-configuration"}
	cases := []struct {
		level string
		body  map[string]any
		code  int
	}{
		{"readonly", map[string]any{"is_enabled": false}, 403},
		{"readonly", map[string]any{"display_name": "x"}, 403},
		{"limited", map[string]any{"display_name": "x"}, 403},
		{"limited", map[string]any{"options": opts}, 403},
		{"limited", map[string]any{"use_for_third_party_client_access": false}, 403},
		{"limited", map[string]any{"is_enabled": false}, 200},
		{"full", map[string]any{"display_name": "Acme Login"}, 200},
	}
	for _, c := range cases {
		e.setAccess(t, id, c.level)
		if rec, _ := e.do(t, tok, "PATCH", "/identity-providers/"+id, c.body); rec.Code != c.code {
			t.Errorf("%s %v = %d %s", c.level, c.body, rec.Code, rec.Body)
		}
	}
	e.setAccess(t, id, "readonly")
	for _, rt := range []struct{ method, path string }{{"DELETE", ""}, {"POST", "/domains"}, {"DELETE", "/domains/acme.example"}} {
		if rec, _ := e.do(t, tok, rt.method, "/identity-providers/"+id+rt.path, map[string]any{"domain": "acme.example"}); rec.Code != 403 {
			t.Errorf("readonly %s %s = %d", rt.method, rt.path, rec.Code)
		}
	}
}

func TestIdPUpdate(t *testing.T) {
	e := newEnv(t)
	e.withWrites(t)
	tok := e.adminToken(t)
	id := e.createIdP(t, tok, oidcIdP("acme-sso"))["id"].(string)
	rec, v := e.do(t, tok, "PATCH", "/identity-providers/"+id, map[string]any{"display_name": "Acme Login", "is_enabled": false,
		"options": map[string]any{"type": "back_channel", "client_id": "acme-client", "discovery_url": "https://idp.acme.example/.well-known/openid-configuration"}})
	if rec.Code != 200 || v["display_name"] != "Acme Login" || v["is_enabled"] != false || v["options"].(map[string]any)["type"] != "back_channel" {
		t.Fatalf("patch = %d %v", rec.Code, v)
	}
	// The secret was kept although the update omitted it.
	conn, err := e.st.Connections().Get(context.Background(), e.tn.ID, id)
	must(t, err)
	if len(conn.FederationSecretsSealed) == 0 {
		t.Fatal("client secret dropped")
	}
	// The Management API's refusals come through (client_id is immutable).
	if rec, b := e.do(t, tok, "PATCH", "/identity-providers/"+id, map[string]any{"options": map[string]any{"type": "back_channel", "client_id": "other", "discovery_url": "https://idp.acme.example/.well-known/openid-configuration"}}); rec.Code != 400 || !strings.Contains(b["detail"].(string), "client_id") {
		t.Fatalf("immutable client_id = %d %v", rec.Code, b)
	}
	// Without a connection profile administrators cannot set the flags.
	if rec, _ := e.do(t, tok, "PATCH", "/identity-providers/"+id, map[string]any{"show_as_button": true}); rec.Code != 403 {
		t.Fatalf("show_as_button without profile = %d", rec.Code)
	}
	must(t, e.st.SelfService().CreateConnectionProfile(context.Background(), &store.ConnectionProfile{TenantID: e.tn.ID, ID: "cop_1", Name: "SSO", Doc: []byte(`{"organization":{"show_as_button":"optional","assign_membership_on_login":"none"}}`)}))
	e.setConfig(t, `{"connection_profile_id":"cop_1","allowed_strategies":["oidc"],"connection_deletion_behavior":"allow","invitation_landing_client_id":"portal"}`)
	tok = e.adminToken(t)
	if rec, v := e.do(t, tok, "PATCH", "/identity-providers/"+id, map[string]any{"show_as_button": true}); rec.Code != 200 || v["show_as_button"] != true {
		t.Fatalf("show_as_button optional = %d %v", rec.Code, v)
	}
	if rec, _ := e.do(t, tok, "PATCH", "/identity-providers/"+id, map[string]any{"assign_membership_on_login": true}); rec.Code != 403 {
		t.Fatalf("assign_membership_on_login none = %d", rec.Code)
	}
	if rec, _ := e.do(t, tok, "PATCH", "/identity-providers/"+id, map[string]any{"options": map[string]any{"type": "back_channel"}}); rec.Code != 400 {
		t.Fatalf("incomplete options = %d", rec.Code)
	}
	if rec, _ := e.do(t, tok, "PATCH", "/identity-providers/"+id, map[string]any{"name": "renamed"}); rec.Code != 400 {
		t.Fatalf("name is not updatable = %d", rec.Code)
	}
}

func TestIdPDeleteDetach(t *testing.T) {
	e := newEnv(t)
	e.withWrites(t)
	tok := e.adminToken(t)
	ctx := context.Background()
	a := e.createIdP(t, tok, oidcIdP("acme-a"))["id"].(string)
	b := e.createIdP(t, tok, oidcIdP("acme-b"))["id"].(string)
	if rec, _ := e.do(t, tok, "POST", "/identity-providers/"+a+"/detach", nil); rec.Code != 204 {
		t.Fatalf("detach = %d", rec.Code)
	}
	if _, err := e.st.Organizations().GetConnection(ctx, e.tn.ID, e.orgA.ID, a); err == nil {
		t.Fatal("still linked")
	}
	if _, err := e.st.Connections().Get(ctx, e.tn.ID, a); err != nil {
		t.Fatal("detach deleted the connection")
	}
	e.setAccess(t, b, "limited")
	if rec, _ := e.do(t, tok, "DELETE", "/identity-providers/"+b, nil); rec.Code != 403 {
		t.Fatalf("delete at limited = %d", rec.Code)
	}
	e.setAccess(t, b, "full")
	// allow_if_empty with a user of the connection.
	e.setConfig(t, `{"allowed_strategies":["oidc"],"connection_deletion_behavior":"allow_if_empty","invitation_landing_client_id":"portal"}`)
	tok = e.adminToken(t)
	must(t, e.st.Users().Create(ctx, &store.User{TenantID: e.tn.ID, UserID: "oidc|acme-b|u1", Identities: []store.Identity{{Connection: "acme-b", Provider: "oidc", UserID: "acme-b|u1"}}}))
	if rec, _ := e.do(t, tok, "DELETE", "/identity-providers/"+b, nil); rec.Code != 400 {
		t.Fatalf("delete non-empty with allow_if_empty = %d", rec.Code)
	}
	must(t, e.st.Users().Delete(ctx, e.tn.ID, "oidc|acme-b|u1"))
	if rec, _ := e.do(t, tok, "DELETE", "/identity-providers/"+b, nil); rec.Code != 204 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if _, err := e.st.Connections().Get(ctx, e.tn.ID, b); err == nil {
		t.Fatal("connection remains")
	}
}

func (e *env) verifiedDomain(t *testing.T, org *store.Organization, id, name string) {
	t.Helper()
	must(t, e.st.OrganizationsII().PutDiscoveryDomain(context.Background(), &store.OrganizationDiscoveryDomain{TenantID: e.tn.ID, OrganizationID: org.ID, ID: id, Domain: name, Status: "verified"}, true))
}

func TestIdPDomains(t *testing.T) {
	e := newEnv(t)
	e.withWrites(t)
	tok := e.adminToken(t)
	a := e.createIdP(t, tok, oidcIdP("acme-a"))["id"].(string)
	b := e.createIdP(t, tok, oidcIdP("acme-b"))["id"].(string)
	e.verifiedDomain(t, e.orgA, "ord_aaaaaaaaaaaaaaaaaaaaaa", "acme.example")
	_, pending := e.do(t, tok, "POST", "/domains", map[string]any{"domain": "pending.example"})
	if rec, out := e.do(t, tok, "POST", "/identity-providers/"+a+"/domains", map[string]any{"domain": "ACME.example"}); rec.Code != 201 || out["domain"] != "acme.example" {
		t.Fatalf("link = %d %v", rec.Code, out)
	}
	if _, v := e.do(t, tok, "GET", "/identity-providers/"+a, nil); len(v["domains"].([]any)) != 1 {
		t.Fatalf("provider domains %v", v)
	}
	if _, d := e.do(t, tok, "GET", "/domains/ord_aaaaaaaaaaaaaaaaaaaaaa", nil); d["identity_provider_association"] != "associated" {
		t.Fatalf("association %v", d)
	}
	rec, l := e.do(t, tok, "GET", "/domains/ord_aaaaaaaaaaaaaaaaaaaaaa/identity-providers", nil)
	if items := l["identity_providers"].([]any); rec.Code != 200 || len(items) != 1 || items[0].(map[string]any)["id"] != a || items[0].(map[string]any)["name"] != "acme-a" {
		t.Fatalf("domain providers = %d %v", rec.Code, l)
	}
	if rec, _ := e.do(t, tok, "POST", "/identity-providers/"+a+"/domains", map[string]any{"domain": "acme.example"}); rec.Code != 409 {
		t.Fatalf("relink = %d", rec.Code)
	}
	if rec, _ := e.do(t, tok, "POST", "/identity-providers/"+b+"/domains", map[string]any{"domain": "acme.example"}); rec.Code != 409 {
		t.Fatalf("link held by another provider = %d", rec.Code)
	}
	if rec, _ := e.do(t, tok, "POST", "/identity-providers/"+b+"/domains", map[string]any{"domain": pending["domain"]}); rec.Code != 400 {
		t.Fatalf("unverified = %d", rec.Code)
	}
	e.verifiedDomain(t, e.orgB, "dd_bbbbbbbbbbbbbbbbbbbbbbbb", "other.example")
	if rec, _ := e.do(t, tok, "POST", "/identity-providers/"+b+"/domains", map[string]any{"domain": "other.example"}); rec.Code != 400 {
		t.Fatalf("another organization's domain = %d", rec.Code)
	}
	if rec, _ := e.do(t, tok, "DELETE", "/identity-providers/"+a+"/domains/acme.example", nil); rec.Code != 204 {
		t.Fatalf("unlink = %d", rec.Code)
	}
	if rec, _ := e.do(t, tok, "DELETE", "/identity-providers/"+a+"/domains/acme.example", nil); rec.Code != 404 {
		t.Fatalf("unlink again = %d", rec.Code)
	}
	// Deleting the organization domain removes the link.
	e.do(t, tok, "POST", "/identity-providers/"+b+"/domains", map[string]any{"domain": "acme.example"})
	if rec, _ := e.do(t, tok, "DELETE", "/domains/ord_aaaaaaaaaaaaaaaaaaaaaa", nil); rec.Code != 204 {
		t.Fatalf("delete domain = %d", rec.Code)
	}
	if _, v := e.do(t, tok, "GET", "/identity-providers/"+b, nil); len(v["domains"].([]any)) != 0 {
		t.Fatalf("link survived the domain %v", v)
	}
	// Create with domains.
	e.verifiedDomain(t, e.orgA, "ord_cccccccccccccccccccccc", "c.example")
	withDomains := oidcIdP("acme-c")
	withDomains["domains"] = []any{"c.example"}
	if v := e.createIdP(t, tok, withDomains); len(v["domains"].([]any)) != 1 {
		t.Fatalf("create with domains %v", v)
	}
	withDomains = oidcIdP("acme-d")
	withDomains["domains"] = []any{"c.example"}
	if rec, _ := e.do(t, tok, "POST", "/identity-providers", withDomains); rec.Code != 409 {
		t.Fatalf("create with a held domain = %d", rec.Code)
	}
}

func TestIdPUpdateAttributes(t *testing.T) {
	e := newEnv(t)
	e.withWrites(t)
	tok := e.adminToken(t)
	id := e.createIdP(t, tok, oidcIdP("acme-sso"))["id"].(string)
	rec, v := e.do(t, tok, "PUT", "/identity-providers/"+id+"/update-attributes", map[string]any{})
	if rec.Code != 200 || v["id"] != id || len(v["attributes"].([]any)) != 0 {
		t.Fatalf("refresh = %d %v", rec.Code, v)
	}
	if rec, _ := e.do(t, tok, "PUT", "/identity-providers/"+id+"/update-attributes", map[string]any{"x": 1}); rec.Code != 400 {
		t.Fatalf("refresh with members = %d", rec.Code)
	}
	_ = strings.Contains
	_ = http.StatusOK
}

// TestIdPSharedConnection: a connection also enabled on another
// organization is not one organization's to delete or reconfigure, whatever
// its access level; per-organization settings and detach still work.
func TestIdPSharedConnection(t *testing.T) {
	e := newEnv(t)
	e.withWrites(t)
	tok := e.adminToken(t)
	ctx := context.Background()
	id := e.createIdP(t, tok, oidcIdP("shared-sso"))["id"].(string)
	must(t, e.st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: e.tn.ID, OrganizationID: e.orgB.ID, ConnectionID: id, OrganizationAccessLevel: "full", IsEnabled: true, IsEnabledSet: true}, true))
	e.verifiedDomain(t, e.orgA, "ord_aaaaaaaaaaaaaaaaaaaaaa", "acme.example")
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"DELETE", "", nil},
		{"PATCH", "", map[string]any{"display_name": "Mine"}},
		{"PATCH", "", map[string]any{"options": map[string]any{"type": "back_channel", "client_id": "acme-client", "discovery_url": "https://idp.acme.example/.well-known/openid-configuration"}}},
		{"POST", "/domains", map[string]any{"domain": "acme.example"}},
		{"POST", "/provisioning", nil},
	} {
		if rec, _ := e.do(t, tok, c.method, "/identity-providers/"+id+c.path, c.body); rec.Code != 403 {
			t.Errorf("%s %s on a shared connection = %d %s", c.method, c.path, rec.Code, rec.Body)
		}
	}
	if rec, _ := e.do(t, tok, "PATCH", "/identity-providers/"+id, map[string]any{"is_enabled": false}); rec.Code != 200 {
		t.Fatalf("per-organization flag = %d", rec.Code)
	}
	if rec, _ := e.do(t, tok, "POST", "/identity-providers/"+id+"/detach", nil); rec.Code != 204 {
		t.Fatalf("detach = %d", rec.Code)
	}
	if _, err := e.st.Connections().Get(ctx, e.tn.ID, id); err != nil {
		t.Fatal("shared connection deleted")
	}
}
