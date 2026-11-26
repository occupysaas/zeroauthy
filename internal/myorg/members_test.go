package myorg

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"testing"
)

func TestConfigShape(t *testing.T) {
	e := newEnv(t)
	rec, out := e.do(t, e.adminToken(t), "GET", "/config", nil)
	if rec.Code != 200 || out["connection_deletion_behavior"] != "allow" || out["organization_deletion_behavior"] != "allow_if_empty" {
		t.Fatalf("config = %d %v", rec.Code, out)
	}
	if s, _ := out["allowed_strategies"].([]any); len(s) != 1 || s[0] != "oidc" {
		t.Errorf("strategies %v", out["allowed_strategies"])
	}
	if _, ok := out["third_party_client_access"]; ok {
		t.Errorf("third_party_client_access shown while not configured: %v", out)
	}
	e.setConfig(t, `{"allowed_strategies":[],"connection_deletion_behavior":"allow","third_party_client_access":{"default_value":"block","allowed_values":["block","allow"]}}`)
	_, out = e.do(t, e.adminToken(t), "GET", "/config", nil)
	if tp, _ := out["third_party_client_access"].(map[string]any); tp["default_value"] != "block" {
		t.Errorf("third party %v", out)
	}
}

func TestDetails(t *testing.T) {
	e := newEnv(t)
	rec, out := e.do(t, e.adminToken(t), "GET", "/details", nil)
	if rec.Code != 200 || out["id"] != e.orgA.ID || out["name"] != "acme-org" || out["display_name"] != "ACME-ORG" || out["third_party_client_access"] != "block" {
		t.Fatalf("details = %d %v", rec.Code, out)
	}
	if _, ok := out["metadata"]; ok {
		t.Error("metadata exposed")
	}
	rec, out = e.do(t, e.adminToken(t), "PATCH", "/details", map[string]any{"display_name": "Acme Inc", "branding": map[string]any{"logo_url": "https://acme.test/l.png", "colors": map[string]any{"primary": "#112233", "page_background": "#ffffff"}}})
	if rec.Code != 200 || out["display_name"] != "Acme Inc" || out["branding"].(map[string]any)["logo_url"] != "https://acme.test/l.png" {
		t.Fatalf("patch = %d %v", rec.Code, out)
	}
	got, _ := e.st.Organizations().Get(context.Background(), e.tn.ID, e.orgA.ID)
	if got.DisplayName != "Acme Inc" || got.Name != "acme-org" {
		t.Fatalf("stored %+v", got)
	}
	for name, body := range map[string]any{
		"empty":                  map[string]any{},
		"id":                     map[string]any{"id": "org_x"},
		"metadata":               map[string]any{"metadata": map[string]any{"a": "b"}},
		"bad name":               map[string]any{"name": "Not Valid!"},
		"http logo":              map[string]any{"branding": map[string]any{"logo_url": "http://acme.test/l.png"}},
		"third party disallowed": map[string]any{"third_party_client_access": "allow"},
	} {
		if rec, _ := e.do(t, e.adminToken(t), "PATCH", "/details", body); rec.Code != 400 {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	e.setConfig(t, `{"allowed_strategies":[],"connection_deletion_behavior":"allow","third_party_client_access":{"default_value":"block","allowed_values":["block","allow"]}}`)
	if rec, out := e.do(t, e.adminToken(t), "PATCH", "/details", map[string]any{"third_party_client_access": "allow"}); rec.Code != 200 || out["third_party_client_access"] != "allow" {
		t.Errorf("allowed third party = %d %v", rec.Code, out)
	}
}

func memberIDs(out map[string]any) []string {
	ids := []string{}
	for _, m := range out["members"].([]any) {
		ids = append(ids, m.(map[string]any)["user_id"].(string))
	}
	return ids
}

func TestMembersList(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 5; i++ {
		u := e.user(t, fmt.Sprintf("auth0|m%d", i), fmt.Sprintf("m%d@acme.test", i))
		e.member(t, e.orgA, u)
	}
	rec, out := e.do(t, e.adminToken(t), "GET", "/members?take=3&include_totals=true", nil)
	if rec.Code != 200 || len(out["members"].([]any)) != 3 || out["total"] != float64(7) || out["total_is_capped"] != false || out["next"] == nil {
		t.Fatalf("page 1 = %d %v", rec.Code, out)
	}
	seen := memberIDs(out)
	for out["next"] != nil {
		_, out = e.do(t, e.adminToken(t), "GET", "/members?take=3&from="+url.QueryEscape(out["next"].(string)), nil)
		seen = append(seen, memberIDs(out)...)
	}
	if len(seen) != 7 || slices.Contains(seen, e.carol.UserID) {
		t.Fatalf("members %v", seen)
	}
	m := out["members"].([]any)[0].(map[string]any)
	if _, ok := m["app_metadata"]; ok {
		t.Error("app_metadata exposed")
	}
	if rec, _ := e.do(t, e.adminToken(t), "GET", "/members?take=101", nil); rec.Code != 400 {
		t.Errorf("take 101 = %d", rec.Code)
	}
	// fields
	_, out = e.do(t, e.adminToken(t), "GET", "/members?fields=user_id,email", nil)
	for _, v := range out["members"].([]any) {
		if len(v.(map[string]any)) != 2 {
			t.Fatalf("fields %v", v)
		}
	}
}

// Review Focus 4: roles appear only with read:my_org:member_roles.
func TestMembersRolesScope(t *testing.T) {
	e := newEnv(t)
	roles := func(tok, query string) []any {
		_, out := e.do(t, tok, "GET", "/members"+query, nil)
		for _, v := range out["members"].([]any) {
			m := v.(map[string]any)
			if m["user_id"] == e.admin.UserID {
				r, _ := m["roles"].([]any)
				return r
			}
		}
		t.Fatalf("admin missing: %v", out)
		return nil
	}
	if r := roles(e.adminToken(t), ""); len(r) != 1 || r[0].(map[string]any)["name"] != "Org Admin" {
		t.Errorf("with scope: %v", r)
	}
	if r := roles(e.adminToken(t, "read:my_org:members"), ""); r != nil {
		t.Errorf("without scope: %v", r)
	}
	if r := roles(e.adminToken(t), "?fields=user_id,roles"); len(r) != 1 {
		t.Errorf("requested roles: %v", r)
	}
	if r := roles(e.adminToken(t), "?fields=roles&include_fields=false"); r != nil {
		t.Errorf("excluded roles: %v", r)
	}
}

func TestMemberDetail(t *testing.T) {
	e := newEnv(t)
	rec, out := e.do(t, e.adminToken(t), "GET", "/members/"+url.PathEscape(e.bob.UserID), nil)
	if rec.Code != 200 || out["user_id"] != e.bob.UserID || out["email"] != "bob@acme.test" {
		t.Fatalf("bob = %d %v", rec.Code, out)
	}
	if rec, _ := e.do(t, e.adminToken(t), "GET", "/members/"+url.PathEscape(e.carol.UserID), nil); rec.Code != 404 {
		t.Errorf("carol (other org) = %d", rec.Code)
	}
}

// delete-memberships removes the membership, not the user.
func TestDeleteMemberships(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if rec, _ := e.do(t, e.adminToken(t), "POST", "/delete-memberships", map[string]any{"members": []string{e.bob.UserID}}); rec.Code != 204 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if ok, _ := e.st.Organizations().IsMember(ctx, e.tn.ID, e.orgA.ID, e.bob.UserID); ok {
		t.Fatal("still a member")
	}
	if _, err := e.st.Users().Get(ctx, e.tn.ID, e.bob.UserID); err != nil {
		t.Fatalf("user deleted: %v", err)
	}
	for name, body := range map[string]any{
		"two":       map[string]any{"members": []string{"auth0|a", "auth0|b"}},
		"none":      map[string]any{"members": []string{}},
		"other org": map[string]any{"members": []string{e.carol.UserID}},
	} {
		if rec, _ := e.do(t, e.adminToken(t), "POST", "/delete-memberships", body); rec.Code != 400 && rec.Code != 404 {
			t.Errorf("%s = %d", name, rec.Code)
		}
	}
	if ok, _ := e.st.Organizations().IsMember(ctx, e.tn.ID, e.orgB.ID, e.carol.UserID); !ok {
		t.Fatal("carol removed from her organization")
	}
}

func TestUserStores(t *testing.T) {
	e := newEnv(t)
	rec, out := e.do(t, e.adminToken(t), "GET", "/user-stores", nil)
	if rec.Code != 200 {
		t.Fatalf("user stores = %d %s", rec.Code, rec.Body)
	}
	stores := out["user_stores"].([]any)
	if len(stores) != 1 || stores[0].(map[string]any)["id"] != e.conn.ID || stores[0].(map[string]any)["is_enabled"] != true {
		t.Fatalf("stores %v", stores)
	}
}
