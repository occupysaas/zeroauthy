package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Catches a migration that loses existing tokens, or leaves upgraded
// databases with different tables from fresh installations.
func TestOrganizationsMigration(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			old := openAtVersion(t, mk(t), 24)
			mustExec(t, old, `INSERT INTO auth_codes (tenant_id,code_hash,client_id,redirect_uri,user_id,session_id,scopes,audience,nonce,code_challenge,code_challenge_method,auth_time,expires_at,created_at) VALUES ('legacy','code','client','https://callback','user','session','["openid"]','aud','nonce','challenge','S256',123,9999999999999999,123)`)
			mustExec(t, old, `INSERT INTO refresh_tokens (tenant_id,id,token_hash,family_id,client_id,user_id,session_id,scopes,audience,auth_time,rotating,expires_at,idle_expires_at,rotated_at,revoked_at,created_at) VALUES ('legacy','refresh','refresh-hash','family','client','user','session','["openid"]','aud',123,true,9999999999999999,9999999999999998,NULL,NULL,123)`)
			if err := old.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			if old.LatestVersion() < 25 {
				t.Fatal("Organizations migration missing")
			}
			code, err := old.AuthCodes().Get(ctx, "legacy", "code")
			if err != nil || code.ClientID != "client" || code.OrganizationID != "" {
				t.Fatalf("legacy code: %+v %v", code, err)
			}
			rt, err := old.RefreshTokens().Get(ctx, "legacy", "refresh")
			if err != nil || rt.FamilyID != "family" || rt.OrganizationID != "" {
				t.Fatalf("legacy refresh token: %+v %v", rt, err)
			}
			fresh := mustOpen(t, mk(t))
			for _, table := range []string{"organizations", "organization_connections", "organization_members", "organization_member_roles", "auth_codes", "refresh_tokens"} {
				got, want := tableShape(t, old, table), tableShape(t, fresh, table)
				if len(want) == 0 || !slices.Equal(got, want) {
					t.Errorf("%s: upgraded %v != fresh %v", table, got, want)
				}
				if got, want := actionsIISchemaDefinition(t, old, table), actionsIISchemaDefinition(t, fresh, table); !slices.Equal(got, want) {
					t.Errorf("%s: upgraded definitions %v != fresh %v", table, got, want)
				}
			}
		})
	}
}

func rowCount(t *testing.T, s *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.queryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Catches duplicate names slipping past a check-then-insert, non-idempotent
// concurrent member adds, and member rows orphaned by a racing delete.
func TestOrganizationsConcurrency(t *testing.T) {
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
			must(s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "auth0|u", Email: "u@example.test"}))
			orgs := s.Organizations()
			newOrg := func(name string) *store.Organization {
				return &store.Organization{TenantID: "t", ID: orgrules.NewID(), Name: name}
			}

			t.Run("same name", func(t *testing.T) {
				const n = 8
				var wg sync.WaitGroup
				errs := make(chan error, n)
				for range n {
					wg.Go(func() { errs <- orgs.Create(ctx, newOrg("race"), nil) })
				}
				wg.Wait()
				close(errs)
				ok, conflicts := 0, 0
				for err := range errs {
					switch {
					case err == nil:
						ok++
					case errors.Is(err, store.ErrConflict):
						conflicts++
					default:
						t.Errorf("unexpected error: %v", err)
					}
				}
				if ok != 1 || conflicts != n-1 {
					t.Fatalf("created %d, conflicts %d", ok, conflicts)
				}
				if c := rowCount(t, s, `SELECT COUNT(*) FROM organizations WHERE tenant_id='t' AND name='race'`); c != 1 {
					t.Fatalf("%d rows", c)
				}
			})

			t.Run("idempotent AddMembers", func(t *testing.T) {
				o := newOrg("members")
				must(orgs.Create(ctx, o, nil))
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(func() {
						if err := orgs.AddMembers(ctx, "t", o.ID, []string{"auth0|u"}); err != nil {
							t.Error(err)
						}
					})
				}
				wg.Wait()
				if c := rowCount(t, s, `SELECT COUNT(*) FROM organization_members WHERE tenant_id='t' AND organization_id=?`, o.ID); c != 1 {
					t.Fatalf("%d member rows", c)
				}
			})

			t.Run("delete versus AddMembers", func(t *testing.T) {
				for i := range 10 {
					o := newOrg(fmt.Sprintf("doomed%d", i))
					must(orgs.Create(ctx, o, nil))
					var wg sync.WaitGroup
					var addErr, delErr error
					wg.Go(func() { addErr = orgs.AddMembers(ctx, "t", o.ID, []string{"auth0|u"}) })
					wg.Go(func() { delErr = orgs.Delete(ctx, "t", o.ID) })
					wg.Wait()
					if delErr != nil || addErr != nil && !errors.Is(addErr, store.ErrNotFound) {
						t.Fatalf("add=%v delete=%v", addErr, delErr)
					}
					for _, table := range []string{"organization_members", "organization_member_roles", "organization_connections"} {
						if c := rowCount(t, s, `SELECT COUNT(*) FROM `+table+` WHERE tenant_id='t' AND organization_id=?`, o.ID); c != 0 {
							t.Fatalf("%s: %d orphan rows", table, c)
						}
					}
				}
			})
		})
	}
}
