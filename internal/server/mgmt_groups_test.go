package server

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

var groupMgmtScopes = []string{
	"read:groups", "delete:groups", "read:group_members", "read:group_roles", "create:group_roles", "delete:group_roles",
	"read:user_role_source_groups", "read:organization_groups", "read:organization_group_roles", "create:organization_group_roles",
	"delete:organization_group_roles", "read:organization_member_role_source_groups",
}

type groupFixture struct {
	a                          *orgAPI
	st                         store.Store
	org, user, role, group, g2 string
}

// newGroupManagement seeds two groups of the database connection, the
// user as a member of the first, an organization enabling the connection
// with the user as member, and a role.
func newGroupManagement(t *testing.T) *groupFixture {
	t.Helper()
	quoted := `"` + strings.Join(append(slices.Clone(orgMgmtScopes), groupMgmtScopes...), `", "`) + `", `
	seedText := strings.Replace(usersSeed, `"read:connections", "create:connections"`, quoted+`"read:connections", "create:connections"`, 1)
	h, st := newMgmtEnvSeed(t, seedText, nil)
	a := &orgAPI{t: t, h: h, c: newMgmtContract(t), admin: clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")}
	org, user, role := a.memberFixture("grp")
	ctx := context.Background()
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	conn, err := st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	if code, _, raw := a.call("POST", "/organizations/"+org+"/enabled_connections", a.admin, map[string]any{"connection_id": conn.ID}); code != 201 {
		t.Fatalf("enable connection=%d %s", code, raw)
	}
	now := time.Now()
	f := &groupFixture{a: a, st: st, org: org, user: user, role: role, group: "grp_aaaaaaaaaaaaaaaaaaaa", g2: "grp_bbbbbbbbbbbbbbbbbbbb"}
	for i, id := range []string{f.group, f.g2} {
		if err := st.Directory().CreateGroup(ctx, &store.Group{TenantID: tn.ID, ID: id, ConnectionID: conn.ID, Name: []string{"Engineering", "Sales"}[i], ExternalID: "ext-" + id[4:6], CreatedAt: now.Add(time.Duration(i) * time.Second), UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Directory().UpdateGroupMembers(ctx, tn.ID, f.group, []string{user}, nil, false, now); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestGroupsRoutes drives every group route through the real router and
// validates each response against api/management.yaml.
func TestGroupsRoutes(t *testing.T) {
	f := newGroupManagement(t)
	a, admin := f.a, f.a.admin
	must := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		code, out, raw := a.call(method, path, admin, body)
		if code != want {
			t.Fatalf("%s %s=%d %s", method, path, code, raw)
		}
		return out
	}
	list := func(path string) []any {
		t.Helper()
		code, _, raw := a.call("GET", path, admin, nil)
		if code != 200 {
			t.Fatalf("GET %s=%d %s", path, code, raw)
		}
		var arr []any
		if err := json.Unmarshal(raw, &arr); err != nil {
			t.Fatalf("GET %s: not an array: %s", path, raw)
		}
		return arr
	}
	if got := list("/groups"); len(got) != 2 {
		t.Fatalf("groups %v", got)
	}
	if got := list("/groups?search=eng"); len(got) != 1 || got[0].(map[string]any)["name"] != "Engineering" {
		t.Fatalf("search %v", got)
	}
	if got := list("/groups?name=Sales&fields=id&include_fields=true"); len(got) != 1 || len(got[0].(map[string]any)) != 1 {
		t.Fatalf("name filter with fields %v", got)
	}
	totals := must("GET", "/groups?include_totals=true&per_page=1", nil, 200)
	if totals["total"].(float64) != 2 || len(totals["groups"].([]any)) != 1 {
		t.Fatalf("totals %v", totals)
	}
	cp := must("GET", "/groups?take=1", nil, 200)
	next, _ := cp["next"].(string)
	if next == "" || len(cp["groups"].([]any)) != 1 {
		t.Fatalf("checkpoint %v", cp)
	}
	cp2 := must("GET", "/groups?take=1&from="+url.QueryEscape(next), nil, 200)
	if cp2["next"] != nil || cp2["groups"].([]any)[0].(map[string]any)["id"] != f.g2 {
		t.Fatalf("checkpoint page 2 %v", cp2)
	}
	if code, _, _ := a.call("GET", "/groups?from=bogus", admin, nil); code != 400 {
		t.Fatalf("bad cursor %d", code)
	}
	g := must("GET", "/groups/"+f.group, nil, 200)
	if g["tenant_name"] != "acme" || g["external_id"] != "ext-aa" {
		t.Fatalf("group %v", g)
	}
	if code, _, _ := a.call("GET", "/groups/grp_cccccccccccccccccccc", admin, nil); code != 404 {
		t.Fatalf("unknown group %d", code)
	}
	if code, _, _ := a.call("GET", "/groups/not-a-group", admin, nil); code != 400 {
		t.Fatalf("bad group id %d", code)
	}
	members := must("GET", "/groups/"+f.group+"/members", nil, 200)["members"].([]any)
	if len(members) != 1 || members[0].(map[string]any)["id"] != f.user || members[0].(map[string]any)["member_type"] != "user" {
		t.Fatalf("members %v", members)
	}
	// Tenant group roles.
	must("POST", "/groups/"+f.group+"/roles", map[string]any{"roles": []string{f.role}}, 204)
	if code, _, _ := a.call("POST", "/groups/"+f.group+"/roles", admin, map[string]any{"roles": []string{"rol_nope"}}); code != 404 {
		t.Fatalf("unknown role %d", code)
	}
	if code, _, _ := a.call("POST", "/groups/"+f.group+"/roles", admin, map[string]any{"roles": []string{}}); code != 400 {
		t.Fatalf("empty roles %d", code)
	}
	if roles := must("GET", "/groups/"+f.group+"/roles", nil, 200)["roles"].([]any); len(roles) != 1 || roles[0].(map[string]any)["id"] != f.role {
		t.Fatalf("group roles %v", roles)
	}
	must("POST", "/roles/"+f.role+"/groups", map[string]any{"groups": []string{f.g2}}, 204)
	if gs := must("GET", "/roles/"+f.role+"/groups", nil, 200)["groups"].([]any); len(gs) != 2 {
		t.Fatalf("role groups %v", gs)
	}
	must("DELETE", "/roles/"+f.role+"/groups", map[string]any{"groups": []string{f.g2}}, 204)
	uid := url.PathEscape(f.user)
	ug := list("/users/" + uid + "/groups")
	if len(ug) != 1 || ug[0].(map[string]any)["membership_created_at"] == nil {
		t.Fatalf("user groups %v", ug)
	}
	src := must("GET", "/users/"+uid+"/effective-roles/sources/groups?role_id="+f.role, nil, 200)["groups"].([]any)
	if len(src) != 1 || src[0].(map[string]any)["id"] != f.group {
		t.Fatalf("role source groups %v", src)
	}
	if code, _, _ := a.call("GET", "/users/"+uid+"/effective-roles/sources/groups", admin, nil); code != 400 {
		t.Fatalf("missing role_id %d", code)
	}
	must("DELETE", "/groups/"+f.group+"/roles", map[string]any{"roles": []string{f.role}}, 204)
	if roles := must("GET", "/groups/"+f.group+"/roles", nil, 200)["roles"].([]any); len(roles) != 0 {
		t.Fatalf("after removal %v", roles)
	}
	// Organization groups and group roles.
	o := "/organizations/" + f.org
	if gs := must("GET", o+"/groups", nil, 200)["groups"].([]any); len(gs) != 2 {
		t.Fatalf("organization groups %v", gs)
	}
	orgRole := must("POST", "/roles", map[string]any{"name": "org-group-role"}, 200)["id"].(string)
	must("POST", o+"/groups/"+f.group+"/roles", map[string]any{"roles": []string{orgRole}}, 204)
	// A tenant-wide group role is not an organization role.
	tenantRole := must("POST", "/roles", map[string]any{"name": "tenant-group-role"}, 200)["id"].(string)
	must("POST", "/groups/"+f.group+"/roles", map[string]any{"roles": []string{tenantRole}}, 204)
	if roles := must("GET", o+"/groups/"+f.group+"/roles", nil, 200)["roles"].([]any); len(roles) != 1 || roles[0].(map[string]any)["id"] != orgRole {
		t.Fatalf("organization group roles %v", roles)
	}
	if roles := must("GET", "/groups/"+f.group+"/roles", nil, 200)["roles"].([]any); len(roles) != 1 || roles[0].(map[string]any)["id"] != tenantRole {
		t.Fatalf("organization role leaked into tenant group roles %v", roles)
	}
	eff := must("GET", o+"/members/"+uid+"/effective-roles", nil, 200)["roles"].([]any)
	sources := map[string]string{}
	for _, r := range eff {
		m := r.(map[string]any)
		var s []string
		for _, v := range m["sources"].([]any) {
			s = append(s, v.(string))
		}
		sources[m["id"].(string)] = strings.Join(s, ",")
	}
	if _, leaked := sources[tenantRole]; leaked || sources[f.role] != "direct" || sources[orgRole] != "group" {
		t.Fatalf("effective roles %v", eff)
	}
	src = must("GET", o+"/members/"+uid+"/effective-roles/sources/groups?role_id="+orgRole, nil, 200)["groups"].([]any)
	if len(src) != 1 || src[0].(map[string]any)["id"] != f.group {
		t.Fatalf("member role source groups %v", src)
	}
	if src := must("GET", "/users/"+uid+"/effective-roles/sources/groups?role_id="+orgRole, nil, 200)["groups"].([]any); len(src) != 0 {
		t.Fatalf("organization group role counted tenant-wide %v", src)
	}
	must("DELETE", o+"/groups/"+f.group+"/roles", map[string]any{"roles": []string{orgRole}}, 204)
	// A group of a connection not enabled on the organization is refused.
	ctx := context.Background()
	tn, _ := f.st.Tenants().GetByName(ctx, "acme")
	if err := f.st.Directory().CreateGroup(ctx, &store.Group{TenantID: tn.ID, ID: "grp_dddddddddddddddddddd", ConnectionID: "con_other", Name: "Other", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if code, _, raw := a.call("POST", o+"/groups/grp_dddddddddddddddddddd/roles", admin, map[string]any{"roles": []string{orgRole}}); code != 400 {
		t.Fatalf("group of a disabled connection=%d %s", code, raw)
	}
	must("DELETE", "/groups/"+f.group, nil, 204)
	if code, _, _ := a.call("GET", "/groups/"+f.group, admin, nil); code != 404 {
		t.Fatalf("deleted group %d", code)
	}
}

// TestGroupsScopes is the 401/403 matrix of every group route.
func TestGroupsScopes(t *testing.T) {
	f := newGroupManagement(t)
	a := f.a
	g, o, uid := "/groups/"+f.group, "/organizations/"+f.org, url.PathEscape(f.user)
	cases := []struct{ method, path, scope string }{
		{"GET", "/groups", "read:groups"}, {"GET", g, "read:groups"}, {"DELETE", g, "delete:groups"},
		{"GET", g + "/members", "read:group_members"}, {"GET", g + "/roles", "read:group_roles"},
		{"POST", g + "/roles", "create:group_roles"}, {"DELETE", g + "/roles", "delete:group_roles"},
		{"GET", "/roles/" + f.role + "/groups", "read:group_roles"}, {"POST", "/roles/" + f.role + "/groups", "create:group_roles"},
		{"DELETE", "/roles/" + f.role + "/groups", "delete:group_roles"},
		{"GET", "/users/" + uid + "/groups", "read:groups"},
		{"GET", "/users/" + uid + "/effective-roles/sources/groups?role_id=" + f.role, "read:user_role_source_groups"},
		{"GET", o + "/groups", "read:organization_groups"}, {"GET", o + "/groups/" + f.group + "/roles", "read:organization_group_roles"},
		{"POST", o + "/groups/" + f.group + "/roles", "create:organization_group_roles"},
		{"DELETE", o + "/groups/" + f.group + "/roles", "delete:organization_group_roles"},
		{"GET", o + "/members/" + uid + "/effective-roles/sources/groups?role_id=" + f.role, "read:organization_member_role_source_groups"},
	}
	all := append(slices.Clone(orgMgmtScopes), groupMgmtScopes...)
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
