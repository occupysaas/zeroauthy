package mgmt_test

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

var memberScopes = []string{
	"read:organization_members", "create:organization_members", "delete:organization_members",
	"read:organization_member_roles", "create:organization_member_roles", "delete:organization_member_roles",
	"read:organization_member_effective_roles", "read:roles", "read:users", "read:organizations",
}

func memberUser(n int) string { return fmt.Sprintf("auth0|m%02d", n) }

// newMemberEnv is newOrgEnv with users m01..m12 (m12 without email, name or
// picture) and roles rol_1..rol_3 in acme, and one organization.
func newMemberEnv(t *testing.T) (*orgEnv, string) {
	t.Helper()
	e := newOrgEnv(t)
	ctx := context.Background()
	for i := 1; i <= 12; i++ {
		u := &store.User{TenantID: e.tn.ID, UserID: memberUser(i), Identities: []store.Identity{{Connection: "org-db", Provider: store.StrategyDatabase, UserID: fmt.Sprintf("m%02d", i)}}}
		if i < 12 {
			u.Email, u.Name, u.Picture = fmt.Sprintf("m%02d@example.test", i), fmt.Sprintf("Member %d", i), fmt.Sprintf("https://img.example.test/m%02d.png", i)
		}
		if err := e.st.Users().Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= 3; i++ {
		if err := e.st.RBAC().CreateRole(ctx, &store.Role{TenantID: e.tn.ID, ID: fmt.Sprintf("rol_%d", i), Name: fmt.Sprintf("Role %d", i), Description: fmt.Sprintf("Role number %d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	e.caller = m2mCaller(append(slices.Clone(orgScopes), memberScopes...)...)
	return e, e.create(map[string]any{"name": "members"}, 201)["id"].(string)
}

func (e *orgEnv) members(id string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			e.h.ListOrganizationMembers(w, r, id)
		case "POST":
			e.h.AddOrganizationMembers(w, r, id)
		default:
			e.h.RemoveOrganizationMembers(w, r, id)
		}
	}
}

func (e *orgEnv) memberRoles(id, uid string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			e.h.ListOrganizationMemberRoles(w, r, id, uid)
		case "POST":
			e.h.AddOrganizationMemberRoles(w, r, id, uid)
		default:
			e.h.RemoveOrganizationMemberRoles(w, r, id, uid)
		}
	}
}

func (e *orgEnv) effectiveRoles(id, uid string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationMemberEffectiveRoles(w, r, id, uid) }
}

func (e *orgEnv) roleMembers(id, rid string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationRoleMembers(w, r, id, rid) }
}

func (e *orgEnv) userOrgs(uid string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { e.h.ListUserOrganizations(w, r, uid) }
}

func userIDs(items []any) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.(map[string]any)["user_id"].(string))
	}
	return out
}

func TestOrganizationMembersContract(t *testing.T) {
	e, id := newMemberEnv(t)
	m := "/organizations/" + id + "/members"

	// Add: 204, idempotent, all or none for an unknown user, 1 to 10 IDs.
	e.do(e.tn, "POST", m, map[string]any{"members": []string{memberUser(3), memberUser(1), memberUser(2)}}, e.members(id), 204)
	e.do(e.tn, "POST", m, map[string]any{"members": []string{memberUser(1), memberUser(12)}}, e.members(id), 204)
	e.fail("POST", m, map[string]any{"members": []string{memberUser(4), "auth0|ghost"}}, e.members(id), 404, "inexistent_user")
	if in, _ := e.st.Organizations().IsMember(context.Background(), e.tn.ID, id, memberUser(4)); in {
		t.Fatal("a refused batch added a member")
	}
	eleven := make([]string, 11)
	for i := range eleven {
		eleven[i] = memberUser(i + 1)
	}
	for name, body := range map[string]any{
		"empty":            map[string]any{"members": []string{}},
		"not an array":     map[string]any{"members": memberUser(1)},
		"no members":       map[string]any{},
		"unknown property": map[string]any{"members": []string{memberUser(1)}, "roles": []string{}},
		"eleven":           map[string]any{"members": eleven},
		"empty ID":         map[string]any{"members": []string{""}},
	} {
		t.Run("add "+name, func(t *testing.T) {
			e.t = t
			e.fail("POST", m, body, e.members(id), 400, "invalid_body")
			e.fail("DELETE", m, body, e.members(id), 400, "invalid_body")
		})
	}
	e.t = t
	e.fail("POST", "/organizations/org_0000000000000000/members", map[string]any{"members": []string{memberUser(1)}}, e.members("org_0000000000000000"), 404, "")
	e.fail("POST", "/organizations/bad/members", map[string]any{"members": []string{memberUser(1)}}, e.members("bad"), 400, "invalid_uri")

	// List: bare array ordered by user ID with the joined user fields;
	// fields left empty on the user are left out.
	list := e.list(m, e.members(id))
	if got := userIDs(list); !slices.Equal(got, []string{memberUser(1), memberUser(2), memberUser(3), memberUser(12)}) {
		t.Fatalf("members=%v", got)
	}
	if fmt.Sprint(list[0]) != "map[email:m01@example.test name:Member 1 picture:https://img.example.test/m01.png user_id:auth0|m01]" ||
		fmt.Sprint(list[3]) != "map[user_id:auth0|m12]" {
		t.Fatalf("items=%v", list)
	}
	page := e.obj("GET", m+"?include_totals=true&per_page=3&page=1", nil, e.members(id), 200)
	if fmt.Sprint(page["start"], page["limit"], page["total"]) != "3 3 4" || fmt.Sprint(userIDs(page["members"].([]any))) != "["+memberUser(12)+"]" {
		t.Fatalf("offset page=%v", page)
	}
	var walked []string
	from := ""
	for range 4 {
		q := m + "?take=3"
		if from != "" {
			q += "&from=" + from + "&page=7"
		}
		cp := e.obj("GET", q, nil, e.members(id), 200)
		if _, ok := cp["total"]; ok {
			t.Fatalf("checkpoint has totals: %v", cp)
		}
		walked = append(walked, userIDs(cp["members"].([]any))...)
		if from, _ = cp["next"].(string); from == "" {
			break
		}
	}
	if !slices.Equal(walked, []string{memberUser(1), memberUser(2), memberUser(3), memberUser(12)}) {
		t.Fatalf("checkpoint walk=%v", walked)
	}
	e.fail("GET", m+"?from=garbage", nil, e.members(id), 400, "")
	e.fail("GET", m+"?per_page=101", nil, e.members(id), 400, "invalid_query_string")
	e.fail("GET", m+"?take=0", nil, e.members(id), 400, "invalid_query_string")
	e.fail("GET", m+"?page=1001", nil, e.members(id), 400, "invalid_paging")
	e.fail("GET", m+"?fields=user_id,nickname", nil, e.members(id), 400, "invalid_query_string")
	e.fail("GET", m+"?sort=name:1", nil, e.members(id), 400, "invalid_query_string")

	// Member roles: offset only, the user must be a member, roles must exist.
	r1 := "/organizations/" + id + "/members/" + memberUser(1) + "/roles"
	e.do(e.tn, "POST", r1, map[string]any{"roles": []string{"rol_2", "rol_1"}}, e.memberRoles(id, memberUser(1)), 204)
	e.do(e.tn, "POST", r1, map[string]any{"roles": []string{"rol_1"}}, e.memberRoles(id, memberUser(1)), 204)
	roles := e.list(r1, e.memberRoles(id, memberUser(1)))
	if fmt.Sprint(roles) != "[map[description:Role number 1 id:rol_1 name:Role 1] map[description:Role number 2 id:rol_2 name:Role 2]]" {
		t.Fatalf("roles=%v", roles)
	}
	rp := e.obj("GET", r1+"?include_totals=true&per_page=1&page=1", nil, e.memberRoles(id, memberUser(1)), 200)
	if fmt.Sprint(rp["start"], rp["limit"], rp["total"], len(rp["roles"].([]any))) != "1 1 2 1" {
		t.Fatalf("roles page=%v", rp)
	}
	e.fail("GET", r1+"?take=1", nil, e.memberRoles(id, memberUser(1)), 400, "invalid_query_string")
	r5 := "/organizations/" + id + "/members/" + memberUser(5) + "/roles"
	e.fail("GET", r5, nil, e.memberRoles(id, memberUser(5)), 404, "")
	e.fail("POST", r5, map[string]any{"roles": []string{"rol_1"}}, e.memberRoles(id, memberUser(5)), 404, "")
	e.fail("DELETE", r5, map[string]any{"roles": []string{"rol_1"}}, e.memberRoles(id, memberUser(5)), 404, "")
	e.fail("DELETE", "/organizations/"+id+"/members/auth0|ghost/roles", map[string]any{"roles": []string{"rol_1"}}, e.memberRoles(id, "auth0|ghost"), 404, "inexistent_user")
	e.fail("POST", r1, map[string]any{"roles": []string{"rol_3", "rol_ghost"}}, e.memberRoles(id, memberUser(1)), 404, "")
	if l := e.list(r1, e.memberRoles(id, memberUser(1))); len(l) != 2 {
		t.Fatalf("unknown role batch assigned roles: %v", l)
	}
	e.fail("POST", r1, map[string]any{"roles": []string{}}, e.memberRoles(id, memberUser(1)), 400, "invalid_body")
	e.fail("POST", r1, map[string]any{"roles": eleven}, e.memberRoles(id, memberUser(1)), 400, "invalid_body")
	e.fail("POST", r1, map[string]any{"members": []string{"rol_1"}}, e.memberRoles(id, memberUser(1)), 400, "invalid_body")
	e.fail("GET", "/organizations/bad/members/x/roles", nil, e.memberRoles("bad", "x"), 400, "invalid_uri")
	e.fail("GET", "/organizations/org_0000000000000000/members/x/roles", nil, e.memberRoles("org_0000000000000000", "x"), 404, "")
	e.do(e.tn, "POST", "/organizations/"+id+"/members/"+memberUser(2)+"/roles", map[string]any{"roles": []string{"rol_2"}}, e.memberRoles(id, memberUser(2)), 204)

	// fields=roles returns only the listed fields and needs
	// read:organization_member_roles.
	only := e.list(m+"?fields=roles", e.members(id))
	if fmt.Sprint(only) != "[map[roles:[map[id:rol_1 name:Role 1] map[id:rol_2 name:Role 2]]] map[roles:[map[id:rol_2 name:Role 2]]] map[roles:[]] map[roles:[]]]" {
		t.Fatalf("fields=roles: %v", only)
	}
	withID := e.obj("GET", m+"?fields=roles,user_id&take=1", nil, e.members(id), 200)
	if fmt.Sprint(withID["members"]) != "[map[roles:[map[id:rol_1 name:Role 1] map[id:rol_2 name:Role 2]] user_id:auth0|m01]]" {
		t.Fatalf("fields=roles,user_id: %v", withID)
	}
	if got := e.list(m+"?fields=roles,email&include_fields=false", e.members(id)); fmt.Sprint(got[0]) != "map[name:Member 1 picture:https://img.example.test/m01.png user_id:auth0|m01]" {
		t.Fatalf("include_fields=false: %v", got)
	}
	if got := e.list(m+"?fields=email", e.members(id)); fmt.Sprint(got[0]) != "map[email:m01@example.test]" {
		t.Fatalf("fields=email: %v", got)
	}
	e.caller = m2mCaller("read:organization_members")
	e.fail("GET", m+"?fields=roles", nil, e.members(id), 403, "insufficient_scope")
	e.list(m+"?fields=roles&include_fields=false", e.members(id))
	e.caller = m2mCaller("read:organization_member_roles")
	e.list(m+"?fields=roles", e.members(id))
	e.caller = m2mCaller(append(slices.Clone(orgScopes), memberScopes...)...)

	// Effective roles: the direct roles with their source, checkpoint style.
	er := "/organizations/" + id + "/members/" + memberUser(1) + "/effective-roles"
	eff := e.obj("GET", er, nil, e.effectiveRoles(id, memberUser(1)), 200)
	if fmt.Sprint(eff) != "map[roles:[map[description:Role number 1 id:rol_1 name:Role 1 sources:[direct]] map[description:Role number 2 id:rol_2 name:Role 2 sources:[direct]]]]" {
		t.Fatalf("effective=%v", eff)
	}
	first := e.obj("GET", er+"?take=1", nil, e.effectiveRoles(id, memberUser(1)), 200)
	next, _ := first["next"].(string)
	rest := e.obj("GET", er+"?take=1&from="+next, nil, e.effectiveRoles(id, memberUser(1)), 200)
	if next == "" || fmt.Sprint(first["roles"], rest["roles"]) != "[map[description:Role number 1 id:rol_1 name:Role 1 sources:[direct]]] [map[description:Role number 2 id:rol_2 name:Role 2 sources:[direct]]]" || rest["next"] != nil {
		t.Fatalf("effective pages=%v %v", first, rest)
	}
	e.fail("GET", "/organizations/"+id+"/members/"+memberUser(5)+"/effective-roles", nil, e.effectiveRoles(id, memberUser(5)), 404, "")
	e.fail("GET", er+"?page=1", nil, e.effectiveRoles(id, memberUser(1)), 400, "invalid_query_string")

	// Role members: current members holding the role, checkpoint only.
	rm := "/organizations/" + id + "/roles/rol_2/members"
	rms := e.obj("GET", rm+"?page=3&per_page=1&include_totals=true", nil, e.roleMembers(id, "rol_2"), 200)
	if fmt.Sprint(rms) != "map[members:[map[email:m01@example.test name:Member 1 picture:https://img.example.test/m01.png user_id:auth0|m01] map[email:m02@example.test name:Member 2 picture:https://img.example.test/m02.png user_id:auth0|m02]]]" {
		t.Fatalf("role members=%v", rms)
	}
	rm1 := e.obj("GET", rm+"?take=1&fields=user_id", nil, e.roleMembers(id, "rol_2"), 200)
	if fmt.Sprint(rm1["members"]) != "[map[user_id:auth0|m01]]" || rm1["next"] == nil {
		t.Fatalf("role members take=1: %v", rm1)
	}
	e.fail("GET", "/organizations/"+id+"/roles/rol_ghost/members", nil, e.roleMembers(id, "rol_ghost"), 404, "")
	e.fail("GET", rm+"?fields=roles", nil, e.roleMembers(id, "rol_2"), 400, "invalid_query_string")

	// Removing a member keeps the role assignments (observed): they come
	// back when the user is re-added, and the role-member list leaves the
	// removed member out meanwhile.
	e.do(e.tn, "DELETE", m, map[string]any{"members": []string{memberUser(1), memberUser(9)}}, e.members(id), 204)
	if got := userIDs(e.obj("GET", rm, nil, e.roleMembers(id, "rol_2"), 200)["members"].([]any)); !slices.Equal(got, []string{memberUser(2)}) {
		t.Fatalf("role members after removal=%v", got)
	}
	e.fail("GET", r1, nil, e.memberRoles(id, memberUser(1)), 404, "")
	e.do(e.tn, "POST", m, map[string]any{"members": []string{memberUser(1)}}, e.members(id), 204)
	if l := e.list(r1, e.memberRoles(id, memberUser(1))); len(l) != 2 {
		t.Fatalf("roles after re-add=%v", l)
	}
	e.do(e.tn, "DELETE", r1, map[string]any{"roles": []string{"rol_1", "rol_3"}}, e.memberRoles(id, memberUser(1)), 204)
	if l := e.list(r1, e.memberRoles(id, memberUser(1))); fmt.Sprint(l) != "[map[description:Role number 2 id:rol_2 name:Role 2]]" {
		t.Fatalf("roles after delete=%v", l)
	}

	// User organizations: offset and checkpoint, empty for a non-member,
	// 404 for an unknown user.
	other := e.create(map[string]any{"name": "another", "display_name": "Another"}, 201)["id"].(string)
	e.do(e.tn, "POST", "/organizations/"+other+"/members", map[string]any{"members": []string{memberUser(1)}}, e.members(other), 204)
	uo := e.list("/users/"+memberUser(1)+"/organizations", e.userOrgs(memberUser(1)))
	if len(uo) != 2 || uo[0].(map[string]any)["name"] != "another" || uo[1].(map[string]any)["name"] != "members" {
		t.Fatalf("user orgs=%v", uo)
	}
	if keys := keysOf(uo[0].(map[string]any)); !slices.Equal(keys, []string{"display_name", "id", "is_app_entitlement_active", "name", "third_party_client_access"}) {
		t.Fatalf("user org keys=%v", keys)
	}
	uop := e.obj("GET", "/users/"+memberUser(1)+"/organizations?include_totals=true&per_page=1", nil, e.userOrgs(memberUser(1)), 200)
	if fmt.Sprint(uop["start"], uop["limit"], uop["total"], len(uop["organizations"].([]any))) != "0 1 2 1" {
		t.Fatalf("user orgs page=%v", uop)
	}
	uoc := e.obj("GET", "/users/"+memberUser(1)+"/organizations?take=1", nil, e.userOrgs(memberUser(1)), 200)
	if len(uoc["organizations"].([]any)) != 1 || uoc["next"] == nil {
		t.Fatalf("user orgs checkpoint=%v", uoc)
	}
	if l := e.list("/users/"+memberUser(6)+"/organizations", e.userOrgs(memberUser(6))); len(l) != 0 {
		t.Fatalf("non-member orgs=%v", l)
	}
	e.fail("GET", "/users/auth0|ghost/organizations", nil, e.userOrgs("auth0|ghost"), 404, "inexistent_user")
	e.fail("GET", "/users/"+memberUser(1)+"/organizations?per_page=500", nil, e.userOrgs(memberUser(1)), 400, "invalid_query_string")

	// Cross-tenant: another tenant sees none of it.
	tn, err := tenantsetup.UpsertTenant(context.Background(), e.st, "other", time.Now(), func(tn *store.Tenant) error {
		tn.Domains, tn.CanonicalHost = []string{"login.other.test"}, "login.other.test"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e.do(tn, "GET", m, nil, e.members(id), 404)
	e.do(tn, "POST", m, map[string]any{"members": []string{memberUser(1)}}, e.members(id), 404)
	e.do(tn, "DELETE", m, map[string]any{"members": []string{memberUser(1)}}, e.members(id), 404)
	e.do(tn, "GET", r1, nil, e.memberRoles(id, memberUser(1)), 404)
	e.do(tn, "POST", r1, map[string]any{"roles": []string{"rol_1"}}, e.memberRoles(id, memberUser(1)), 404)
	e.do(tn, "DELETE", r1, map[string]any{"roles": []string{"rol_1"}}, e.memberRoles(id, memberUser(1)), 404)
	e.do(tn, "GET", er, nil, e.effectiveRoles(id, memberUser(1)), 404)
	e.do(tn, "GET", rm, nil, e.roleMembers(id, "rol_2"), 404)
	e.do(tn, "GET", "/users/"+memberUser(1)+"/organizations", nil, e.userOrgs(memberUser(1)), 404)

	// Deleting the organization removes its members.
	e.do(e.tn, "DELETE", "/organizations/"+id, nil, e.del(id), 204)
	if l := e.list("/users/"+memberUser(1)+"/organizations", e.userOrgs(memberUser(1))); len(l) != 1 {
		t.Fatalf("user orgs after delete=%v", l)
	}
}

// TestOrganizationMembersRoleLimit: a member holds at most 50 roles in an
// organization (D-0055, local); the batch that would exceed it is 400 and
// assigns nothing.
func TestOrganizationMembersRoleLimit(t *testing.T) {
	e, id := newMemberEnv(t)
	ctx := context.Background()
	for i := 4; i <= orgrules.Limit("roles_per_member_max")+1; i++ {
		if err := e.st.RBAC().CreateRole(ctx, &store.Role{TenantID: e.tn.ID, ID: fmt.Sprintf("rol_%d", i), Name: fmt.Sprintf("Role %d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	e.do(e.tn, "POST", "/organizations/"+id+"/members", map[string]any{"members": []string{memberUser(1)}}, e.members(id), 204)
	path := "/organizations/" + id + "/members/" + memberUser(1) + "/roles"
	for start := 1; start <= 50; start += 10 {
		batch := make([]string, 10)
		for i := range batch {
			batch[i] = fmt.Sprintf("rol_%d", start+i)
		}
		e.do(e.tn, "POST", path, map[string]any{"roles": batch}, e.memberRoles(id, memberUser(1)), 204)
	}
	e.do(e.tn, "POST", path, map[string]any{"roles": []string{"rol_1"}}, e.memberRoles(id, memberUser(1)), 204) // already held
	e.fail("POST", path, map[string]any{"roles": []string{"rol_51"}}, e.memberRoles(id, memberUser(1)), 400, "invalid_body")
	page := e.obj("GET", path+"?include_totals=true", nil, e.memberRoles(id, memberUser(1)), 200)
	if page["total"] != float64(50) {
		t.Fatalf("total=%v", page["total"])
	}
}

// TestOrganizationMembersUnsupportedPlugin: every member route is 501 when
// the storage plugin lacks Organizations.
func TestOrganizationMembersUnsupportedPlugin(t *testing.T) {
	e, id := newMemberEnv(t)
	e.h.Store = noOrgStore{e.st}
	for name, fn := range map[string]http.HandlerFunc{
		"members": e.members(id), "member roles": e.memberRoles(id, memberUser(1)),
		"effective roles": e.effectiveRoles(id, memberUser(1)), "role members": e.roleMembers(id, "rol_1"),
		"user organizations": e.userOrgs(memberUser(1)),
	} {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			t.Run(name+" "+method, func(t *testing.T) {
				rec, _ := e.call(t, e.tn, e.caller, method, "/x", map[string]any{"members": []string{memberUser(1)}, "roles": []string{"rol_1"}}, fn)
				if rec.Code != http.StatusNotImplemented {
					t.Fatalf("status=%d %s", rec.Code, rec.Body)
				}
			})
		}
	}
}
