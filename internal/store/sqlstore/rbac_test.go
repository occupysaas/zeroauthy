package sqlstore

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestRBACMigration(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			if s.LatestVersion() < 22 {
				t.Fatal("RBAC migration missing")
			}
			if err := s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			api := &store.ResourceServer{TenantID: "t", ID: "api", Identifier: "https://api.test"}
			if err := s.ResourceServers().Create(ctx, api); err != nil {
				t.Fatal(err)
			}
			got, err := s.ResourceServers().Get(ctx, "t", "api")
			if err != nil {
				t.Fatal(err)
			}
			if got.EnforcePolicies || got.TokenDialect != "" {
				t.Fatalf("legacy defaults: %#v", got)
			}
			api.EnforcePolicies = true
			api.TokenDialect = "rfc9068_profile_authz"
			if err := s.ResourceServers().Update(ctx, api); err != nil {
				t.Fatal(err)
			}
			got, err = s.ResourceServers().Get(ctx, "t", "api")
			if err != nil {
				t.Fatal(err)
			}
			if !got.EnforcePolicies || got.TokenDialect != "rfc9068_profile_authz" {
				t.Fatal("RBAC settings lost")
			}
		})
	}
}

func TestRBACSnapshotConcurrency(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			api := &store.ResourceServer{TenantID: "t", ID: "api", Identifier: "https://api.test", EnforcePolicies: true, Scopes: []store.Scope{{Value: "read:x"}}}
			must(s.ResourceServers().Create(ctx, api))
			must(s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "u"}))
			key := store.PermissionKey{ResourceServerIdentifier: api.Identifier, PermissionName: "read:x"}
			var wg sync.WaitGroup
			errs := make(chan error, 2)
			wg.Go(func() {
				for range 20 {
					err := s.WithTx(ctx, func(tx store.Store) error {
						a, e := tx.ResourceServers().Get(ctx, "t", "api")
						if e != nil {
							return e
						}
						a.EnforcePolicies = false
						if e = tx.ResourceServers().Update(ctx, a); e != nil {
							return e
						}
						return tx.RBAC().ChangeUserPermissions(ctx, "t", "u", true, []store.PermissionKey{key})
					})
					if err != nil {
						errs <- err
						return
					}
					err = s.WithTx(ctx, func(tx store.Store) error {
						a, e := tx.ResourceServers().Get(ctx, "t", "api")
						if e != nil {
							return e
						}
						a.EnforcePolicies = true
						if e = tx.ResourceServers().Update(ctx, a); e != nil {
							return e
						}
						return tx.RBAC().ChangeUserPermissions(ctx, "t", "u", false, []store.PermissionKey{key})
					})
					if err != nil {
						errs <- err
						return
					}
				}
			})
			wg.Go(func() {
				for range 40 {
					snap, e := s.RBAC().Snapshot(ctx, "t", "u", api.Identifier)
					if e != nil {
						errs <- e
						return
					}
					if snap.API.EnforcePolicies && len(snap.Permissions) > 0 || !snap.API.EnforcePolicies && !reflect.DeepEqual(snap.Permissions, []string{"read:x"}) {
						t.Errorf("mixed snapshot: %#v permissions %v", snap.API, snap.Permissions)
						return
					}
				}
			})
			wg.Wait()
			close(errs)
			for e := range errs {
				t.Fatal(e)
			}
		})
	}
}

// TestRBACUpgradePreservesLegacy exercises the actual pre-22 schema: a fresh
// migration alone cannot catch defaults that corrupt existing API or user rows.
func TestRBACUpgradePreservesLegacy(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := mustOpenRaw(t, mk(t))
			if err := s.migrateTo(ctx, 21); err != nil {
				t.Fatal(err)
			}
			if _, err := s.exec(ctx, `INSERT INTO resource_servers (tenant_id,id,identifier,name,scopes,signing_alg,token_lifetime,allow_offline_access,created_at,skip_consent_for_verifiable_first_party_clients,user_policy,client_policy,is_system,origin,token_lifetime_for_web) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "old", "api", "https://old.test", "Old API", `[{"Value":"read:old","Description":"old"}]`, "RS256", 3600, false, int64(0), false, "allow_all", "require_client_grant", false, "", 1800); err != nil {
				t.Fatal(err)
			}
			user := &store.User{TenantID: "old", UserID: "old-user", Email: "old@example.test"}
			insertLegacyUser(t, s, user)
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			api, err := s.ResourceServers().Get(ctx, "old", "api")
			if err != nil {
				t.Fatal(err)
			}
			if api.EnforcePolicies || api.TokenDialect != "" || api.Name != "Old API" || api.TokenLifetime != 3600 || len(api.Scopes) != 1 || api.Scopes[0].Value != "read:old" {
				t.Fatalf("legacy API changed: %#v", api)
			}
			got, err := s.Users().Get(ctx, "old", "old-user")
			if err != nil {
				t.Fatal(err)
			}
			if got.Email != user.Email {
				t.Fatalf("legacy user changed: %#v", got)
			}
			roles, err := s.RBAC().ListRoles(ctx, "old", store.RBACPage{})
			if err != nil {
				t.Fatal(err)
			}
			if len(roles.Items) != 0 {
				t.Fatal("migration invented role assignments")
			}
		})
	}
}

func TestRBACCheckpoint(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := mk(t)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			must(s.RBAC().CreateRole(ctx, &store.Role{TenantID: "t", ID: "role", Name: "Member"}))
			for _, id := range []string{"a", "b", "c"} {
				must(s.Users().Create(ctx, &store.User{TenantID: "t", UserID: id}))
				must(s.RBAC().AssignRoleUsers(ctx, "t", "role", []string{id}))
			}
			page, err := s.RBAC().RoleUsers(ctx, "t", "role", store.RBACPage{Take: 2})
			must(err)
			if len(page.Items) != 2 || page.Items[0].UserID != "a" || page.Items[1].UserID != "b" || page.Next == "" {
				t.Fatalf("first page: %#v", page)
			}
			page, err = s.RBAC().RoleUsers(ctx, "t", "role", store.RBACPage{Take: 2, From: page.Next})
			must(err)
			if len(page.Items) != 1 || page.Items[0].UserID != "c" || page.Next != "" {
				t.Fatalf("second page: %#v", page)
			}
		})
	}
}

// A public transaction may have read before taking the authorization lock.
// MySQL's default repeatable snapshot must not let it recreate revoked edges.
func TestRBACNestedTransactionCurrentReads(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		if name != "mysql" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := mk(t)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "nested", Name: "nested"}))
			must(s.Users().Create(ctx, &store.User{TenantID: "nested", UserID: "u"}))
			api := &store.ResourceServer{TenantID: "nested", ID: "api", Identifier: "https://nested.test", Scopes: []store.Scope{{Value: "read:x"}}}
			must(s.ResourceServers().Create(ctx, api))
			must(s.WithTx(ctx, func(tx store.Store) error {
				// Establish an earlier read view without entering the policy-lock
				// boundary. Users.Get is a policy read now: using it would retain
				// the tenant lock and correctly block the independent writer below.
				var userID string
				if err := tx.(*Store).queryRow(ctx, `SELECT user_id FROM users WHERE tenant_id=? AND user_id=?`, "nested", "u").Scan(&userID); err != nil {
					return err
				}
				api.Scopes = nil
				api.EnforcePolicies = true
				if err := s.ResourceServers().Update(ctx, api); err != nil {
					return err
				}
				snap, err := tx.RBAC().Snapshot(ctx, "nested", "u", api.Identifier)
				if err != nil {
					return err
				}
				if !snap.API.EnforcePolicies || len(snap.API.Scopes) != 0 {
					t.Error("authorization snapshot retained pre-lock API settings")
				}
				err = tx.RBAC().ChangeUserPermissions(ctx, "nested", "u", true, []store.PermissionKey{{ResourceServerIdentifier: api.Identifier, PermissionName: "read:x"}})
				if !errors.Is(err, store.ErrInvalid) {
					t.Errorf("removed permission assigned from stale transaction snapshot: %v", err)
				}
				return nil
			}))
		})
	}
}

// Transactional reads used by PATCH must lock before merging omitted fields.
// Otherwise a concurrent name-only update can turn RBAC back off.
func TestRBACResourceServerTransactionReadLocks(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		if name == "sqlite" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := mk(t)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "merge", Name: "merge"}))
			must(s.ResourceServers().Create(ctx, &store.ResourceServer{TenantID: "merge", ID: "api", Identifier: "https://merge.test"}))
			firstRead, release, secondAttempt, secondRead := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			errs := make(chan error, 2)
			go func() {
				errs <- s.WithTx(ctx, func(tx store.Store) error {
					api, err := tx.ResourceServers().Get(ctx, "merge", "api")
					if err != nil {
						return err
					}
					close(firstRead)
					<-release
					api.EnforcePolicies = true
					return tx.ResourceServers().Update(ctx, api)
				})
			}()
			<-firstRead
			go func() {
				errs <- s.WithTx(ctx, func(tx store.Store) error {
					close(secondAttempt)
					api, err := tx.ResourceServers().Get(ctx, "merge", "api")
					if err != nil {
						return err
					}
					close(secondRead)
					api.Name = "renamed"
					return tx.ResourceServers().Update(ctx, api)
				})
			}()
			<-secondAttempt
			select {
			case <-secondRead:
				t.Error("concurrent PATCH read stale RBAC settings before first commit")
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			must(<-errs)
			must(<-errs)
			api, err := s.ResourceServers().Get(ctx, "merge", "api")
			must(err)
			if !api.EnforcePolicies || api.Name != "renamed" {
				t.Fatalf("merged patch lost state: %+v", api)
			}
		})
	}
}

func TestRBACRoleTransactionReadLocks(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		if name == "sqlite" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := mk(t)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "role-merge", Name: "role-merge"}))
			must(s.RBAC().CreateRole(ctx, &store.Role{TenantID: "role-merge", ID: "role", Name: "Original"}))
			firstRead, release, secondAttempt, secondRead := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			errs := make(chan error, 2)
			go func() {
				errs <- s.WithTx(ctx, func(tx store.Store) error {
					role, err := tx.RBAC().GetRole(ctx, "role-merge", "role")
					if err != nil {
						return err
					}
					close(firstRead)
					<-release
					role.Description = "changed"
					return tx.RBAC().UpdateRole(ctx, role)
				})
			}()
			<-firstRead
			go func() {
				errs <- s.WithTx(ctx, func(tx store.Store) error {
					close(secondAttempt)
					role, err := tx.RBAC().GetRole(ctx, "role-merge", "role")
					if err != nil {
						return err
					}
					close(secondRead)
					role.Name = "Renamed"
					return tx.RBAC().UpdateRole(ctx, role)
				})
			}()
			<-secondAttempt
			select {
			case <-secondRead:
				t.Error("concurrent role PATCH read old fields before first commit")
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			must(<-errs)
			must(<-errs)
			role, err := s.RBAC().GetRole(ctx, "role-merge", "role")
			must(err)
			if role.Name != "Renamed" || role.Description != "changed" {
				t.Fatalf("merged role patch lost state: %+v", role)
			}
		})
	}
}
