package actions

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"testing"
)

func TestInvitationOrganizationRoleSnapshot(t *testing.T) {
	st := memory.New()
	ctx := context.Background()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(st.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "tenant"}))
	must(st.Users().Create(ctx, &store.User{TenantID: "t", UserID: "u"}))
	must(st.RBAC().CreateRole(ctx, &store.Role{TenantID: "t", ID: "role", Name: "role"}))
	must(st.RBAC().ChangeUserRoles(ctx, "t", "u", true, []string{"role"}))
	oid := "org_0000000000000001"
	must(st.Organizations().Create(ctx, &store.Organization{TenantID: "t", ID: oid, Name: "org", DisplayName: "org"}, nil))
	must(st.Organizations().AddMembers(ctx, "t", oid, []string{"u"}))
	must(st.Organizations().ChangeMemberRoles(ctx, "t", oid, "u", true, []string{"role"}))
	eng := &Engine{Store: st}
	roles, err := eng.organizationRoleSnapshot(ctx, "t", "u", oid)
	must(err)
	if len(roles) != 1 {
		t.Fatal(roles)
	}
	must(st.RBAC().CreateRole(ctx, &store.Role{TenantID: "t", ID: "org-only", Name: "org-only"}))
	must(st.Organizations().ChangeMemberRoles(ctx, "t", oid, "u", true, []string{"org-only"}))
	must(st.Organizations().RemoveMembers(ctx, "t", oid, []string{"u"}))
	roles, err = eng.organizationRoleSnapshot(ctx, "t", "u", oid)
	must(err)
	if len(roles) != 1 {
		t.Fatal("removed membership changed tenant snapshot", roles)
	}
	roles, err = eng.organizationRoleSnapshot(ctx, "t", "u", "")
	must(err)
	if len(roles) != 1 {
		t.Fatal("tenant roles changed", roles)
	}
}
