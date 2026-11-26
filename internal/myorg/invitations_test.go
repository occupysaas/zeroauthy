package myorg

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// disableInvitationEmail keeps tests off the email queue.
func (e *env) disableInvitationEmail(t *testing.T) {
	t.Helper()
	must(t, e.st.EmailTemplates().Put(context.Background(), &store.EmailTemplate{TenantID: e.tn.ID, Name: "user_invitation", Fields: map[string]any{"enabled": false}}, 0))
}

func TestInvitations(t *testing.T) {
	e := newEnv(t)
	e.disableInvitationEmail(t)
	ctx := context.Background()
	body := map[string]any{"invitees": []any{map[string]any{"email": "New@acme.test", "roles": []string{e.roles["Member"]}}, map[string]any{"email": "two@acme.test"}}, "inviter": map[string]any{"name": "Admin"}, "user_store_id": e.conn.ID, "ttl_sec": 3600}
	rec, _ := e.do(t, e.adminToken(t), "POST", "/member-invitations", body)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created []map[string]any
	mustJSON(t, rec.Body.Bytes(), &created)
	if len(created) != 2 || created[0]["organization_id"] != e.orgA.ID || created[0]["user_store_id"] != e.conn.ID || created[0]["invitee"].(map[string]any)["email"] != "new@acme.test" || created[0]["invitation_url"] == nil {
		t.Fatalf("created %v", created)
	}
	id := created[0]["id"].(string)
	// List, get, roles.
	_, out := e.do(t, e.adminToken(t), "GET", "/member-invitations?include_totals=true", nil)
	if len(out["invitations"].([]any)) != 2 || out["total"] != float64(2) {
		t.Fatalf("list %v", out)
	}
	if rec, out := e.do(t, e.adminToken(t), "GET", "/member-invitations/"+id, nil); rec.Code != 200 || out["id"] != id {
		t.Fatalf("get = %d %v", rec.Code, out)
	}
	if _, out := e.do(t, e.adminToken(t), "GET", "/member-invitations/"+id+"/roles", nil); len(roleIDs(out)) != 1 {
		t.Fatalf("roles %v", out)
	}
	// A new invitation for the same email revokes the earlier one.
	rec, _ = e.do(t, e.adminToken(t), "POST", "/member-invitations", map[string]any{"invitees": []any{map[string]any{"email": "new@acme.test"}}, "user_store_id": e.conn.ID})
	if rec.Code != 201 {
		t.Fatalf("again = %d %s", rec.Code, rec.Body)
	}
	if _, err := e.st.OrganizationsII().GetInvitation(ctx, e.tn.ID, e.orgA.ID, id); err != store.ErrNotFound {
		t.Fatalf("earlier invitation kept: %v", err)
	}
	// Refusals.
	for name, b := range map[string]any{
		"no store":      map[string]any{"invitees": []any{map[string]any{"email": "x@acme.test"}}},
		"hidden role":   map[string]any{"invitees": []any{map[string]any{"email": "x@acme.test", "roles": []string{e.roles["Hidden"]}}}, "user_store_id": e.conn.ID},
		"eleven":        map[string]any{"invitees": strings.Split("a,b,c,d,e,f,g,h,i,j,k", ","), "user_store_id": e.conn.ID},
		"bad email":     map[string]any{"invitees": []any{map[string]any{"email": "nope"}}, "user_store_id": e.conn.ID},
		"foreign store": map[string]any{"invitees": []any{map[string]any{"email": "x@acme.test"}}, "user_store_id": "con_notmine0000000"},
		"long ttl":      map[string]any{"invitees": []any{map[string]any{"email": "x@acme.test"}}, "user_store_id": e.conn.ID, "ttl_sec": 2592001},
	} {
		if rec, _ := e.do(t, e.adminToken(t), "POST", "/member-invitations", b); rec.Code != 400 && rec.Code != 403 {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	// No landing application in the configuration.
	e.setConfig(t, `{"allowed_strategies":[],"connection_deletion_behavior":"allow"}`)
	if rec, _ := e.do(t, e.adminToken(t), "POST", "/member-invitations", map[string]any{"invitees": []any{map[string]any{"email": "x@acme.test"}}, "user_store_id": e.conn.ID}); rec.Code != 400 {
		t.Errorf("no landing client = %d", rec.Code)
	}
	// Delete.
	_, out = e.do(t, e.adminToken(t), "GET", "/member-invitations", nil)
	ids := []string{}
	for _, v := range out["invitations"].([]any) {
		ids = append(ids, v.(map[string]any)["id"].(string))
	}
	if rec, _ := e.do(t, e.adminToken(t), "POST", "/delete-member-invitations", map[string]any{"invitations": ids}); rec.Code != 204 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if _, out := e.do(t, e.adminToken(t), "GET", "/member-invitations", nil); len(out["invitations"].([]any)) != 0 {
		t.Fatalf("after delete %v", out)
	}
}

// Review Focus 1: an administrator of organization B reaches nothing of A.
func TestMyOrgIsolation(t *testing.T) {
	e := newEnv(t)
	e.disableInvitationEmail(t)
	rec, _ := e.do(t, e.adminToken(t), "POST", "/member-invitations", map[string]any{"invitees": []any{map[string]any{"email": "a@acme.test"}}, "user_store_id": e.conn.ID})
	var inv []map[string]any
	mustJSON(t, rec.Body.Bytes(), &inv)
	invA := inv[0]["id"].(string)
	carol := e.tokenFor(t, e.carol.UserID, e.orgB.ID)
	bob := url.PathEscape(e.bob.UserID)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/members/" + bob, nil},
		{"GET", "/members/" + bob + "/roles", nil},
		{"POST", "/members/" + bob + "/roles", map[string]any{"role_ids": []string{e.roles["Member"]}}},
		{"POST", "/members/" + bob + "/unassign-roles", map[string]any{"role_ids": []string{e.roles["Member"]}}},
		{"POST", "/delete-memberships", map[string]any{"members": []string{e.bob.UserID}}},
		{"GET", "/member-invitations/" + invA, nil},
		{"GET", "/member-invitations/" + invA + "/roles", nil},
		{"POST", "/delete-member-invitations", map[string]any{"invitations": []string{invA}}},
	} {
		if rec, _ := e.do(t, carol, c.method, c.path, c.body); rec.Code != 404 {
			t.Errorf("%s %s = %d", c.method, c.path, rec.Code)
		}
	}
	// Lists and details show B only.
	_, out := e.do(t, carol, "GET", "/members", nil)
	if ids := memberIDs(out); len(ids) != 1 || ids[0] != e.carol.UserID {
		t.Errorf("members %v", ids)
	}
	if _, out := e.do(t, carol, "GET", "/details", nil); out["id"] != e.orgB.ID {
		t.Errorf("details %v", out)
	}
	if _, out := e.do(t, carol, "GET", "/member-invitations", nil); len(out["invitations"].([]any)) != 0 {
		t.Errorf("invitations %v", out)
	}
	// A's state is unchanged.
	if ok, _ := e.st.Organizations().IsMember(context.Background(), e.tn.ID, e.orgA.ID, e.bob.UserID); !ok {
		t.Fatal("bob removed from A")
	}
	if _, err := e.st.OrganizationsII().GetInvitation(context.Background(), e.tn.ID, e.orgA.ID, invA); err != nil {
		t.Fatal("A's invitation deleted")
	}
}
