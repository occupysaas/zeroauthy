package myorg

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func roleIDs(out map[string]any) []string {
	ids := []string{}
	for _, v := range out["roles"].([]any) {
		ids = append(ids, v.(map[string]any)["id"].(string))
	}
	return ids
}

func (e *env) memberRoleIDs(t *testing.T, o *store.Organization, uid string) []string {
	t.Helper()
	res, err := e.st.Organizations().MemberRoles(context.Background(), e.tn.ID, o.ID, uid, store.OrgPage{Take: 50})
	must(t, err)
	return res.Items
}

func TestListRoles(t *testing.T) {
	e := newEnv(t)
	rec, out := e.do(t, e.adminToken(t), "GET", "/roles", nil)
	got := roleIDs(out)
	if rec.Code != 200 || len(got) != 2 || slices.Contains(got, e.roles["Hidden"]) {
		t.Fatalf("roles = %d %v", rec.Code, got)
	}
	_, out = e.do(t, e.adminToken(t), "GET", "/roles?name=MEMB", nil)
	if got := roleIDs(out); len(got) != 1 || got[0] != e.roles["Member"] {
		t.Errorf("filtered %v", got)
	}
	_, out = e.do(t, e.adminToken(t), "GET", "/roles?take=1", nil)
	if len(roleIDs(out)) != 1 || out["next"] == nil {
		t.Errorf("page %v", out)
	}
	_, out = e.do(t, e.adminToken(t), "GET", "/roles?take=1&from="+url.QueryEscape(out["next"].(string)), nil)
	if len(roleIDs(out)) != 1 || out["next"] != nil {
		t.Errorf("page 2 %v", out)
	}
}

func TestAssignAndUnassignRoles(t *testing.T) {
	e := newEnv(t)
	bob := "/members/" + url.PathEscape(e.bob.UserID)
	rec, out := e.do(t, e.adminToken(t), "GET", bob+"/roles", nil)
	if rec.Code != 200 || len(roleIDs(out)) != 1 {
		t.Fatalf("bob roles = %d %v", rec.Code, out)
	}
	if rec, _ := e.do(t, e.adminToken(t), "POST", bob+"/roles", map[string]any{"role_ids": []string{e.roles["Org Admin"]}}); rec.Code != 204 {
		t.Fatalf("assign = %d", rec.Code)
	}
	if got := e.memberRoleIDs(t, e.orgA, e.bob.UserID); len(got) != 2 {
		t.Fatalf("after assign %v", got)
	}
	if rec, _ := e.do(t, e.adminToken(t), "POST", bob+"/unassign-roles", map[string]any{"role_ids": []string{e.roles["Org Admin"]}}); rec.Code != 204 {
		t.Fatalf("unassign = %d", rec.Code)
	}
	if got := e.memberRoleIDs(t, e.orgA, e.bob.UserID); len(got) != 1 {
		t.Fatalf("after unassign %v", got)
	}
	for name, body := range map[string]any{"empty": map[string]any{"role_ids": []string{}}, "eleven": map[string]any{"role_ids": strings.Split("a,b,c,d,e,f,g,h,i,j,k", ",")}} {
		if rec, _ := e.do(t, e.adminToken(t), "POST", bob+"/roles", body); rec.Code != 400 {
			t.Errorf("%s = %d", name, rec.Code)
		}
	}
	if rec, _ := e.do(t, e.adminToken(t), "POST", "/members/"+url.PathEscape(e.carol.UserID)+"/roles", map[string]any{"role_ids": []string{e.roles["Member"]}}); rec.Code != 404 {
		t.Errorf("other org's member = %d", rec.Code)
	}
}

// Review Focus 2: only roles visible to the API, never above the
// administrator's own my_org permissions when the application enforces the
// ceiling, never to themselves when it restricts self-assignment.
func TestMyOrgRoleEscalation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	bob := "/members/" + url.PathEscape(e.bob.UserID) + "/roles"
	if rec, _ := e.do(t, e.adminToken(t), "POST", bob, map[string]any{"role_ids": []string{e.roles["Hidden"]}}); rec.Code != 403 {
		t.Fatalf("hidden role = %d", rec.Code)
	}
	// A sub-admin holding only read:my_org:members and member role writes.
	sub := e.user(t, "auth0|sub", "sub@acme.test")
	must(t, e.st.RBAC().CreateRole(ctx, &store.Role{TenantID: e.tn.ID, ID: "rol_subadmin", Name: "Sub Admin"}))
	api, _ := e.st.ResourceServers().GetByIdentifier(ctx, e.tn.ID, "https://"+host+"/my-org/")
	must(t, e.st.RBAC().ChangeRolePermissions(ctx, e.tn.ID, "rol_subadmin", true, []store.PermissionKey{{ResourceServerIdentifier: api.Identifier, PermissionName: "create:my_org:member_roles"}}))
	e.roles["Sub Admin"] = "rol_subadmin"
	e.member(t, e.orgA, sub, "Sub Admin")
	subTok := e.tokenFor(t, sub.UserID, e.orgA.ID)
	// Without the ceiling (Auth0's default) the sub-admin may grant Org Admin.
	if rec, _ := e.do(t, subTok, "POST", bob, map[string]any{"role_ids": []string{e.roles["Org Admin"]}}); rec.Code != 204 {
		t.Fatalf("no ceiling = %d", rec.Code)
	}
	must(t, e.st.Organizations().ChangeMemberRoles(ctx, e.tn.ID, e.orgA.ID, e.bob.UserID, false, []string{e.roles["Org Admin"]}))
	e.setConfig(t, `{"allowed_strategies":[],"connection_deletion_behavior":"allow","invitation_landing_client_id":"portal","enforce_permission_ceiling":true,"enforce_self_assignment_restriction":true}`)
	if rec, _ := e.do(t, subTok, "POST", bob, map[string]any{"role_ids": []string{e.roles["Org Admin"]}}); rec.Code != 403 {
		t.Fatalf("above the ceiling = %d", rec.Code)
	}
	if rec, _ := e.do(t, subTok, "POST", bob, map[string]any{"role_ids": []string{e.roles["Member"]}}); rec.Code != 204 {
		t.Fatalf("within the ceiling = %d", rec.Code)
	}
	if rec, _ := e.do(t, e.adminToken(t), "POST", "/members/"+url.PathEscape(e.admin.UserID)+"/roles", map[string]any{"role_ids": []string{e.roles["Member"]}}); rec.Code != 403 {
		t.Fatalf("self-assignment = %d", rec.Code)
	}
	if got := e.memberRoleIDs(t, e.orgA, e.bob.UserID); slices.Contains(got, e.roles["Org Admin"]) {
		t.Fatal("escalated")
	}
}

// Review Focus 3: the last administrator cannot lose administration.
func TestMyOrgLastAdmin(t *testing.T) {
	e := newEnv(t)
	self := "/members/" + url.PathEscape(e.admin.UserID)
	if rec, _ := e.do(t, e.adminToken(t), "POST", self+"/unassign-roles", map[string]any{"role_ids": []string{e.roles["Org Admin"]}}); rec.Code != 409 {
		t.Fatalf("unassign last admin = %d", rec.Code)
	}
	if rec, _ := e.do(t, e.adminToken(t), "POST", "/delete-memberships", map[string]any{"members": []string{e.admin.UserID}}); rec.Code != 409 {
		t.Fatalf("remove last admin = %d", rec.Code)
	}
	// With a second administrator, the first may step down.
	if rec, _ := e.do(t, e.adminToken(t), "POST", "/members/"+url.PathEscape(e.bob.UserID)+"/roles", map[string]any{"role_ids": []string{e.roles["Org Admin"]}}); rec.Code != 204 {
		t.Fatalf("promote bob = %d", rec.Code)
	}
	if rec, _ := e.do(t, e.adminToken(t), "POST", self+"/unassign-roles", map[string]any{"role_ids": []string{e.roles["Org Admin"]}}); rec.Code != 204 {
		t.Fatalf("step down = %d", rec.Code)
	}
}
