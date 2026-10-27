package mgmt_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
	"testing"
)

func TestRBACLinkLifecycle(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	tid := e.tn.ID
	primary := e.mustCreate(t, map[string]any{"email": "rbac-primary@x.test"})["user_id"].(string)
	secondary := e.mustCreate(t, map[string]any{"email": "rbac-secondary@x.test"})["user_id"].(string)
	api := &store.ResourceServer{TenantID: tid, ID: "rbac-api", Identifier: "https://rbac-link.test", Scopes: []store.Scope{{Value: "primary"}, {Value: "secondary"}}, EnforcePolicies: true}
	if err := e.st.ResourceServers().Create(ctx, api); err != nil {
		t.Fatal(err)
	}
	for uid, perm := range map[string]string{primary: "primary", secondary: "secondary"} {
		if err := e.st.RBAC().ChangeUserPermissions(ctx, tid, uid, true, []store.PermissionKey{{ResourceServerIdentifier: api.Identifier, PermissionName: perm}}); err != nil {
			t.Fatal(err)
		}
	}
	e.mustLink(t, primary, secondary)
	snap, err := e.st.RBAC().Snapshot(ctx, tid, primary, api.Identifier)
	if err != nil || len(snap.Permissions) != 1 || snap.Permissions[0] != "primary" {
		t.Fatalf("primary rights merged: %+v %v", snap, err)
	}
	rec, _ := e.unlink(t, primary, "auth0", strings.TrimPrefix(secondary, "auth0|"))
	if rec.Code != 200 {
		t.Fatalf("unlink: %d", rec.Code)
	}
	snap, err = e.st.RBAC().Snapshot(ctx, tid, secondary, api.Identifier)
	if err != nil || len(snap.Permissions) != 0 {
		t.Fatalf("secondary rights copied/restored: %+v %v", snap, err)
	}
}
