package myorg

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func problemShape(t *testing.T, code int, out map[string]any) {
	t.Helper()
	for _, k := range []string{"type", "status", "title"} {
		if out[k] == nil {
			t.Errorf("problem %v lacks %s", out, k)
		}
	}
	if out["status"] != float64(code) {
		t.Errorf("status %v vs %d", out["status"], code)
	}
}

// The token must be a user token for this host's audience with an org_id
// whose organization exists and still has the user as a member, from an
// application with a My Organization configuration.
func TestMyOrgAuth(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if rec, _ := e.do(t, e.adminToken(t), "GET", "/details", nil); rec.Code == 401 || rec.Code == 403 {
		t.Fatalf("admin = %d %s", rec.Code, rec.Body)
	}
	cases := map[string]string{
		"no token":       "",
		"garbage":        "x.y.z",
		"no org":         e.tokenFor(t, e.admin.UserID, ""),
		"not a member":   e.tokenFor(t, e.admin.UserID, e.orgB.ID),
		"unknown user":   e.tokenFor(t, "auth0|ghost", e.orgA.ID),
		"client subject": e.tokenFor(t, "portal@clients", e.orgA.ID),
	}
	for name, tok := range cases {
		rec, out := e.do(t, tok, "GET", "/details", nil)
		if rec.Code != 401 && rec.Code != 403 {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
			continue
		}
		problemShape(t, rec.Code, out)
	}
	// An organization that does not exist: the OpenAPI's 404.
	if rec, out := e.do(t, e.tokenFor(t, e.admin.UserID, "org_cccccccccccccccc"), "GET", "/details", nil); rec.Code != 404 {
		t.Errorf("unknown org = %d", rec.Code)
	} else {
		problemShape(t, 404, out)
	}
	// Removed from the organization since the token was issued.
	tok := e.tokenFor(t, e.bob.UserID, e.orgA.ID)
	must(t, e.st.Organizations().RemoveMembers(ctx, e.tn.ID, e.orgA.ID, []string{e.bob.UserID}))
	if rec, _ := e.do(t, tok, "GET", "/details", nil); rec.Code != 403 {
		t.Errorf("removed member = %d", rec.Code)
	}
	// The application lost its configuration (LR42b-4).
	repo, _ := store.MyOrg(ctx, e.st)
	must(t, repo.DeleteMyOrgClientConfig(ctx, e.tn.ID, "portal"))
	if rec, out := e.do(t, e.adminToken(t), "GET", "/details", nil); rec.Code != 403 {
		t.Errorf("no configuration = %d %v", rec.Code, out)
	}
}

func TestMyOrgScopes(t *testing.T) {
	e := newEnv(t)
	tok := e.adminToken(t, "openid")
	for _, c := range []struct{ method, path string }{
		{"GET", "/config"}, {"GET", "/details"}, {"PATCH", "/details"}, {"GET", "/members"}, {"GET", "/members/auth0%7Cbob"},
		{"POST", "/delete-memberships"}, {"GET", "/members/auth0%7Cbob/roles"}, {"POST", "/members/auth0%7Cbob/roles"},
		{"POST", "/members/auth0%7Cbob/unassign-roles"}, {"GET", "/roles"}, {"GET", "/member-invitations"}, {"POST", "/member-invitations"},
		{"GET", "/member-invitations/uinv_x"}, {"GET", "/member-invitations/uinv_x/roles"}, {"POST", "/delete-member-invitations"}, {"GET", "/user-stores"},
	} {
		var body any
		if c.method != "GET" {
			body = map[string]any{}
		}
		rec, out := e.do(t, tok, c.method, c.path, body)
		if rec.Code != 403 {
			t.Errorf("%s %s = %d", c.method, c.path, rec.Code)
			continue
		}
		problemShape(t, 403, out)
	}
}

// Deactivated: the API is gone.
func TestMyOrgInactive(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	api, _ := e.st.ResourceServers().GetByIdentifier(ctx, e.tn.ID, "https://"+host+"/my-org/")
	must(t, e.st.ResourceServers().Delete(ctx, e.tn.ID, api.ID))
	if rec, _ := e.do(t, e.adminToken(t), "GET", "/details", nil); rec.Code != 404 {
		t.Fatalf("inactive = %d", rec.Code)
	}
}
