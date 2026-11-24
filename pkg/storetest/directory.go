package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testDirectory is Plan 37c (scim.v1): SCIM configurations and hashed
// tokens, groups unique by name within a connection, members, tenant and
// organization group roles, and the cascades from users, roles,
// connections and organizations.
func testDirectory(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	if !store.DirectoryAvailable(s) {
		t.Fatal("store must support scim.v1")
	}
	d := s.Directory()
	for _, tid := range []string{"dir-a", "dir-b"} {
		mustNoErr(t, s.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}))
		mustNoErr(t, s.Connections().Create(ctx, newConnection(tid, "con1", "corp-saml")))
		mustNoErr(t, s.Connections().Create(ctx, newConnection(tid, "con2", "corp-oidc")))
		for _, uid := range []string{"u1", "u2", "u3"} {
			mustNoErr(t, s.Users().Create(ctx, &store.User{TenantID: tid, UserID: uid}))
		}
	}

	t.Run("scim config", func(t *testing.T) {
		c := &store.SCIMConfig{TenantID: "dir-a", ConnectionID: "con1", UserIDAttribute: "externalId",
			Mapping: []store.SCIMMapping{{Auth0: "email", SCIM: "emails[primary eq true].value"}}, CreatedAt: ts(0), UpdatedAt: ts(0)}
		mustNoErr(t, d.CreateSCIMConfig(ctx, c))
		mustErrIs(t, d.CreateSCIMConfig(ctx, c), store.ErrConflict)
		got, err := d.GetSCIMConfig(ctx, "dir-a", "con1")
		mustNoErr(t, err)
		mustEqual(t, got, c)
		got.Mapping[0].Auth0 = "mutated"
		again, _ := d.GetSCIMConfig(ctx, "dir-a", "con1")
		mustEqual(t, again, c)
		_, err = d.GetSCIMConfig(ctx, "dir-b", "con1")
		mustErrIs(t, err, store.ErrNotFound)
		c.UserIDAttribute, c.UpdatedAt = "userName", ts(time.Hour)
		mustNoErr(t, d.UpdateSCIMConfig(ctx, c))
		got, _ = d.GetSCIMConfig(ctx, "dir-a", "con1")
		mustEqual(t, got, c)
		mustErrIs(t, d.UpdateSCIMConfig(ctx, &store.SCIMConfig{TenantID: "dir-a", ConnectionID: "con2"}), store.ErrNotFound)
		c2 := &store.SCIMConfig{TenantID: "dir-a", ConnectionID: "con2", UserIDAttribute: "externalId", CreatedAt: ts(time.Minute), UpdatedAt: ts(time.Minute)}
		mustNoErr(t, d.CreateSCIMConfig(ctx, c2))
		list, err := d.ListSCIMConfigs(ctx, "dir-a")
		mustNoErr(t, err)
		if len(list) != 2 || list[0].ConnectionID != "con1" || list[1].ConnectionID != "con2" {
			t.Fatalf("list %+v", list)
		}
		if list, _ := d.ListSCIMConfigs(ctx, "dir-b"); len(list) != 0 {
			t.Fatalf("other tenant sees %d configs", len(list))
		}
	})

	t.Run("scim tokens", func(t *testing.T) {
		exp := ts(2 * time.Hour)
		tok := func(id, hash string, created time.Time, expires *time.Time) *store.SCIMToken {
			return &store.SCIMToken{TenantID: "dir-a", ConnectionID: "con1", ID: id, Hash: hash, Scopes: []string{"get:users", "post:users"}, CreatedAt: created, ExpiresAt: expires}
		}
		// An expired token does not count toward the limit.
		old := ts(-time.Hour)
		mustNoErr(t, d.CreateSCIMToken(ctx, tok("tok_old", "h-old", ts(-2*time.Hour), &old)))
		a := tok("tok_a", "h-a", ts(0), &exp)
		mustNoErr(t, d.CreateSCIMToken(ctx, a))
		mustNoErr(t, d.CreateSCIMToken(ctx, tok("tok_b", "h-b", ts(time.Second), nil)))
		mustErrIs(t, d.CreateSCIMToken(ctx, tok("tok_c", "h-c", ts(2*time.Second), nil)), store.ErrSCIMTokenLimit)
		list, err := d.ListSCIMTokens(ctx, "dir-a", "con1")
		mustNoErr(t, err)
		if len(list) != 3 || list[0].ID != "tok_old" || list[2].ID != "tok_b" {
			t.Fatalf("tokens %+v", list)
		}
		used, err := d.UseSCIMToken(ctx, "dir-a", "h-a", ts(time.Minute))
		mustNoErr(t, err)
		if used.ID != "tok_a" || used.LastUsedAt == nil || !used.LastUsedAt.Equal(ts(time.Minute)) || used.ExpiresAt == nil || !used.ExpiresAt.Equal(exp) {
			t.Fatalf("used %+v", used)
		}
		_, err = d.UseSCIMToken(ctx, "dir-b", "h-a", ts(time.Minute))
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, d.DeleteSCIMToken(ctx, "dir-a", "con2", "tok_a"), store.ErrNotFound)
		mustNoErr(t, d.DeleteSCIMToken(ctx, "dir-a", "con1", "tok_a"))
		mustNoErr(t, d.CreateSCIMToken(ctx, tok("tok_c", "h-c", ts(3*time.Second), nil)))
		_, err = d.UseSCIMToken(ctx, "dir-a", "h-a", ts(time.Minute))
		mustErrIs(t, err, store.ErrNotFound)
		// Deleting the configuration deletes the connection's tokens.
		mustNoErr(t, d.DeleteSCIMConfig(ctx, "dir-a", "con1"))
		if list, _ := d.ListSCIMTokens(ctx, "dir-a", "con1"); len(list) != 0 {
			t.Fatalf("tokens survived the configuration: %d", len(list))
		}
		_, err = d.UseSCIMToken(ctx, "dir-a", "h-c", ts(time.Minute))
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, d.DeleteSCIMConfig(ctx, "dir-a", "con1"), store.ErrNotFound)
	})

	group := func(tid, id, conn, name string, created time.Duration) *store.Group {
		return &store.Group{TenantID: tid, ID: id, ConnectionID: conn, Name: name, ExternalID: "ext-" + id, CreatedAt: ts(created), UpdatedAt: ts(created)}
	}
	t.Run("groups", func(t *testing.T) {
		g1 := group("dir-a", "grp_1", "con1", "Engineering", 0)
		mustNoErr(t, d.CreateGroup(ctx, g1))
		mustErrIs(t, d.CreateGroup(ctx, group("dir-a", "grp_x", "con1", "Engineering", time.Second)), store.ErrConflict)
		mustErrIs(t, d.CreateGroup(ctx, group("dir-a", "grp_1", "con2", "Other", time.Second)), store.ErrConflict)
		mustNoErr(t, d.CreateGroup(ctx, group("dir-a", "grp_2", "con2", "Engineering", time.Second)))
		mustNoErr(t, d.CreateGroup(ctx, group("dir-a", "grp_3", "con1", "Sales", 2*time.Second)))
		mustNoErr(t, d.CreateGroup(ctx, group("dir-b", "grp_1", "con1", "Engineering", 0)))
		got, err := d.GetGroup(ctx, "dir-a", "grp_1")
		mustNoErr(t, err)
		mustEqual(t, got, g1)
		g3, _ := d.GetGroup(ctx, "dir-a", "grp_3")
		g3.Name = "Engineering"
		mustErrIs(t, d.UpdateGroup(ctx, g3), store.ErrConflict)
		g3.Name, g3.ExternalID, g3.UpdatedAt = "Sales EMEA", "ext-sales", ts(time.Hour)
		mustNoErr(t, d.UpdateGroup(ctx, g3))
		got, _ = d.GetGroup(ctx, "dir-a", "grp_3")
		mustEqual(t, got, g3)
		mustErrIs(t, d.UpdateGroup(ctx, group("dir-a", "grp_none", "con1", "X", 0)), store.ErrNotFound)
		ids := func(f store.GroupFilter, p store.Page) ([]string, int) {
			t.Helper()
			gs, total, err := d.ListGroups(ctx, "dir-a", f, p)
			mustNoErr(t, err)
			out := []string{}
			for _, g := range gs {
				out = append(out, g.ID)
			}
			return out, total
		}
		check := func(name string, f store.GroupFilter, p store.Page, want []string, wantTotal int) {
			t.Helper()
			got, total := ids(f, p)
			if total != wantTotal {
				t.Errorf("%s: total %d, want %d", name, total, wantTotal)
			}
			mustEqual(t, got, want)
		}
		check("all", store.GroupFilter{}, store.Page{}, []string{"grp_1", "grp_2", "grp_3"}, 3)
		check("connection", store.GroupFilter{ConnectionID: "con1"}, store.Page{}, []string{"grp_1", "grp_3"}, 2)
		check("name", store.GroupFilter{Name: "Engineering"}, store.Page{}, []string{"grp_1", "grp_2"}, 2)
		check("external", store.GroupFilter{ExternalID: "ext-sales"}, store.Page{}, []string{"grp_3"}, 1)
		check("prefix", store.GroupFilter{NamePrefix: "sales"}, store.Page{}, []string{"grp_3"}, 1)
		check("ids", store.GroupFilter{IDs: []string{"grp_3", "grp_1", "grp_9"}}, store.Page{}, []string{"grp_1", "grp_3"}, 2)
		check("page", store.GroupFilter{}, store.Page{Offset: 1, Limit: 1}, []string{"grp_2"}, 3)
	})

	t.Run("members", func(t *testing.T) {
		mustNoErr(t, d.UpdateGroupMembers(ctx, "dir-a", "grp_1", []string{"u1", "u2"}, nil, false, ts(0)))
		mustNoErr(t, d.UpdateGroupMembers(ctx, "dir-a", "grp_1", []string{"u1"}, nil, false, ts(time.Hour)))
		mustErrIs(t, d.UpdateGroupMembers(ctx, "dir-a", "grp_none", []string{"u1"}, nil, false, ts(0)), store.ErrNotFound)
		ms, total, err := d.ListGroupMembers(ctx, "dir-a", "grp_1", store.Page{})
		mustNoErr(t, err)
		if total != 2 || len(ms) != 2 || ms[0].UserID != "u1" || !ms[0].CreatedAt.Equal(ts(0)) || ms[1].UserID != "u2" {
			t.Fatalf("members %+v", ms)
		}
		mustNoErr(t, d.UpdateGroupMembers(ctx, "dir-a", "grp_3", []string{"u1"}, nil, false, ts(time.Minute)))
		ug, err := d.ListUserGroups(ctx, "dir-a", "u1")
		mustNoErr(t, err)
		if len(ug) != 2 || ug[0].GroupID != "grp_1" || ug[1].GroupID != "grp_3" {
			t.Fatalf("user groups %+v", ug)
		}
		mustNoErr(t, d.UpdateGroupMembers(ctx, "dir-a", "grp_1", nil, []string{"u2", "u9"}, false, ts(0)))
		mustNoErr(t, d.UpdateGroupMembers(ctx, "dir-a", "grp_1", []string{"u3"}, nil, true, ts(2*time.Hour)))
		ms, _, _ = d.ListGroupMembers(ctx, "dir-a", "grp_1", store.Page{})
		if len(ms) != 1 || ms[0].UserID != "u3" {
			t.Fatalf("replaced members %+v", ms)
		}
		if ug, _ := d.ListUserGroups(ctx, "dir-b", "u1"); len(ug) != 0 {
			t.Fatalf("other tenant sees memberships %+v", ug)
		}
	})

	t.Run("group roles", func(t *testing.T) {
		r := s.RBAC()
		mustNoErr(t, r.CreateRole(ctx, &store.Role{TenantID: "dir-a", ID: "rol_1", Name: "Reader"}))
		mustNoErr(t, r.CreateRole(ctx, &store.Role{TenantID: "dir-a", ID: "rol_2", Name: "Writer"}))
		mustNoErr(t, d.AddGroupRoles(ctx, "dir-a", "grp_1", "", []string{"rol_1", "rol_2"}))
		mustNoErr(t, d.AddGroupRoles(ctx, "dir-a", "grp_1", "", []string{"rol_1"}))
		mustNoErr(t, d.AddGroupRoles(ctx, "dir-a", "grp_3", "org_1", []string{"rol_1"}))
		roles, err := d.ListGroupRoles(ctx, "dir-a", "grp_1", "", "")
		mustNoErr(t, err)
		mustEqual(t, roles, []store.GroupRole{{GroupID: "grp_1", RoleID: "rol_1"}, {GroupID: "grp_1", RoleID: "rol_2"}})
		byRole, _ := d.ListGroupRoles(ctx, "dir-a", "", "rol_1", "")
		mustEqual(t, byRole, []store.GroupRole{{GroupID: "grp_1", RoleID: "rol_1"}})
		org, _ := d.ListGroupRoles(ctx, "dir-a", "", "", "org_1")
		mustEqual(t, org, []store.GroupRole{{GroupID: "grp_3", RoleID: "rol_1", OrganizationID: "org_1"}})
		mustNoErr(t, d.RemoveGroupRoles(ctx, "dir-a", "grp_1", "", []string{"rol_2", "rol_9"}))
		roles, _ = d.ListGroupRoles(ctx, "dir-a", "grp_1", "", "")
		mustEqual(t, roles, []store.GroupRole{{GroupID: "grp_1", RoleID: "rol_1"}})
		// Deleting a role removes its group assignments.
		mustNoErr(t, r.DeleteRole(ctx, "dir-a", "rol_1"))
		if all, _ := d.ListGroupRoles(ctx, "dir-a", "", "", ""); len(all) != 0 {
			t.Fatalf("role assignments survived the role: %+v", all)
		}
		if all, _ := d.ListGroupRoles(ctx, "dir-a", "", "", "org_1"); len(all) != 0 {
			t.Fatalf("organization assignments survived the role: %+v", all)
		}
	})

	t.Run("cascades", func(t *testing.T) {
		r := s.RBAC()
		mustNoErr(t, r.CreateRole(ctx, &store.Role{TenantID: "dir-a", ID: "rol_3", Name: "Admin"}))
		mustNoErr(t, d.AddGroupRoles(ctx, "dir-a", "grp_1", "", []string{"rol_3"}))
		// Deleting a user removes the user's memberships.
		mustNoErr(t, s.Users().Delete(ctx, "dir-a", "u3"))
		if ms, _, _ := d.ListGroupMembers(ctx, "dir-a", "grp_1", store.Page{}); len(ms) != 0 {
			t.Fatalf("membership survived the user: %+v", ms)
		}
		// Deleting a group removes its members and roles.
		mustNoErr(t, d.UpdateGroupMembers(ctx, "dir-a", "grp_1", []string{"u1"}, nil, false, ts(0)))
		mustNoErr(t, d.DeleteGroup(ctx, "dir-a", "grp_1"))
		mustErrIs(t, d.DeleteGroup(ctx, "dir-a", "grp_1"), store.ErrNotFound)
		if ug, _ := d.ListUserGroups(ctx, "dir-a", "u1"); len(ug) != 1 || ug[0].GroupID != "grp_3" {
			t.Fatalf("memberships after group delete %+v", ug)
		}
		if roles, _ := d.ListGroupRoles(ctx, "dir-a", "", "rol_3", ""); len(roles) != 0 {
			t.Fatalf("role assignments survived the group: %+v", roles)
		}
		// Deleting a connection removes its groups and SCIM state.
		mustNoErr(t, d.CreateSCIMConfig(ctx, &store.SCIMConfig{TenantID: "dir-a", ConnectionID: "con1", UserIDAttribute: "externalId", CreatedAt: ts(0), UpdatedAt: ts(0)}))
		mustNoErr(t, d.CreateSCIMToken(ctx, &store.SCIMToken{TenantID: "dir-a", ConnectionID: "con1", ID: "tok_z", Hash: "h-z", Scopes: []string{"get:users"}, CreatedAt: ts(0)}))
		mustNoErr(t, s.Connections().Delete(ctx, "dir-a", "con1"))
		if gs, _, _ := d.ListGroups(ctx, "dir-a", store.GroupFilter{ConnectionID: "con1"}, store.Page{}); len(gs) != 0 {
			t.Fatalf("groups survived the connection: %d", len(gs))
		}
		if ug, _ := d.ListUserGroups(ctx, "dir-a", "u1"); len(ug) != 0 {
			t.Fatalf("memberships survived the connection: %+v", ug)
		}
		_, err := d.GetSCIMConfig(ctx, "dir-a", "con1")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = d.UseSCIMToken(ctx, "dir-a", "h-z", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		// The other tenant is untouched.
		if _, err := d.GetGroup(ctx, "dir-b", "grp_1"); err != nil {
			t.Fatalf("other tenant's group: %v", err)
		}
		if errors.Is(err, store.ErrDirectoryUnavailable) {
			t.Fatal("unavailable")
		}
	})
}
