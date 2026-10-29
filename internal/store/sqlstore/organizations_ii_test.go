package sqlstore

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	"slices"
	"testing"
	"time"
)

// Run explicitly once the SQL implementation lands; the unavailable stub fails
// these cases rather than silently selecting no conformance tests.
func TestOrganizationsII(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			storetest.RunSuites(t, func(t *testing.T) store.Store { return mk(t) }, "OrganizationsII")
		})
	}
}

// Upgrade real Plan 29 rows rather than recreating them through new codecs.
func TestOrganizationsIIMigrationFrom25(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := openAtVersion(t, mk(t), 25)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			must(s.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "c"}))
			must(s.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "conn", Name: "database", Strategy: "auth0"}))
			must(s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "auth0|u"}))
			must(s.RBAC().CreateRole(ctx, &store.Role{TenantID: "t", ID: "role", Name: "role"}))
			mustExec(t, s, `INSERT INTO organizations (tenant_id,id,name,display_name,third_party_client_access,created_at,updated_at) VALUES ('t','org_legacy','legacy','Legacy','deny',123,456)`)
			mustExec(t, s, `INSERT INTO organization_connections (tenant_id,organization_id,connection_id,assign_membership_on_login,show_as_button,is_signup_enabled) VALUES ('t','org_legacy','conn',true,true,false)`)
			mustExec(t, s, `INSERT INTO organization_members (tenant_id,organization_id,user_id) VALUES ('t','org_legacy','auth0|u')`)
			mustExec(t, s, `INSERT INTO organization_member_roles (tenant_id,organization_id,user_id,role_id) VALUES ('t','org_legacy','auth0|u','role')`)
			mustExec(t, s, `INSERT INTO client_grants (tenant_id,id,client_id,audience,scopes,created_at,subject_type,origin,allow_all_scopes) VALUES ('t','grant','c','aud','["read"]',123,'client','api',false)`)
			must(s.Migrate(ctx))
			o, e := s.Organizations().Get(ctx, "t", "org_legacy")
			must(e)
			if o.IsAppEntitlementActive || o.DisplayName != "Legacy" || micros(o.CreatedAt) != 123 || micros(o.UpdatedAt) != 456 {
				t.Fatalf("organization changed %+v", o)
			}
			c, e := s.Organizations().GetConnection(ctx, "t", o.ID, "conn")
			must(e)
			if !c.IsEnabled || !c.IsEnabledSet || c.ConnectionName != "database" || c.OrganizationAccessLevel != "none" || c.OrganizationMemberAccessLevel != "limited" || !c.AssignMembershipOnLogin || !c.ShowAsButton || c.IsSignupEnabled {
				t.Fatalf("connection upgrade %+v", c)
			}
			member, e := s.Organizations().IsMember(ctx, "t", o.ID, "auth0|u")
			must(e)
			if !member {
				t.Fatal("lost membership")
			}
			roles, e := s.Organizations().MemberRoles(ctx, "t", o.ID, "auth0|u", store.OrgPage{})
			must(e)
			if len(roles.Items) != 1 || roles.Items[0] != "role" {
				t.Fatal("lost roles")
			}
			g, e := s.ClientGrants().Find(ctx, "t", "c", "aud", store.SubjectTypeClient)
			must(e)
			if g.OrganizationUsage != "deny" || g.AllowAnyOrganization || len(g.Scopes) != 1 || g.Scopes[0] != "read" || g.Origin != "api" {
				t.Fatalf("grant upgrade %+v", g)
			}
			fresh := mustOpen(t, mk(t))
			for _, table := range []string{"organizations", "organization_connections", "client_grants", "organization_invitations", "organization_invitation_roles", "organization_invitation_receipts", "organization_clients", "organization_client_grants", "organization_discovery_domains"} {
				if !slices.Equal(tableShape(t, s, table), tableShape(t, fresh, table)) {
					t.Fatalf("upgrade shape differs: %s", table)
				}
			}
		})
	}
}

func orgIIRaceSeed(t *testing.T, s *Store) (*store.Organization, *store.OrganizationInvitation) {
	t.Helper()
	ctx := context.Background()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
	must(s.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "c"}))
	must(s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "auth0|u"}))
	o := &store.Organization{TenantID: "t", ID: orgrules.NewID(), Name: "race", IsAppEntitlementActive: true}
	must(s.Organizations().Create(ctx, o, nil))
	must(s.OrganizationsII().PutClients(ctx, "t", o.ID, []store.OrganizationClient{{ClientID: "c", UseForMemberAccess: true}}))
	in := &store.OrganizationInvitation{TenantID: "t", OrganizationID: o.ID, ID: "uinv_race", ClientID: "c", TicketHash: "hash", WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
	must(s.OrganizationsII().CreateInvitation(ctx, in))
	return o, in
}

// Barriers place the writer transaction before the acceptor's policy read; the
// writer cannot commit until the acceptor has been launched. No sleeps or timing
// assertions decide the outcome, and all goroutine errors reach the test thread.
func orgIIRevokeRace(t *testing.T, deleteInvite bool) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := mk(t)
			o, in := orgIIRaceSeed(t, s)
			held, release, started := make(chan struct{}), make(chan struct{}), make(chan struct{})
			writer := make(chan error, 1)
			accepted := make(chan error, 1)
			go func() {
				writer <- s.WithTx(ctx, func(tx store.Store) error {
					var err error
					if deleteInvite {
						err = tx.OrganizationsII().DeleteInvitation(ctx, "t", o.ID, in.ID)
					} else {
						err = tx.OrganizationsII().PutClients(ctx, "t", o.ID, []store.OrganizationClient{{ClientID: "c", UseForMemberAccess: false}})
					}
					close(held)
					if err != nil {
						return err
					}
					<-release
					return nil
				})
			}()
			<-held
			go func() {
				close(started)
				accepted <- s.WithTx(ctx, func(tx store.Store) error {
					c, err := tx.OrganizationsII().GetClient(ctx, "t", o.ID, "c")
					if err != nil {
						return err
					}
					if !c.UseForMemberAccess {
						return store.ErrPrecondition
					}
					if _, err := tx.OrganizationsII().ConsumeInvitation(ctx, "t", o.ID, in.ID, "accept", "auth0|u", time.Now()); err != nil {
						return err
					}
					return tx.Organizations().AddMembers(ctx, "t", o.ID, []string{"auth0|u"})
				})
			}()
			<-started
			close(release)
			if err := <-writer; err != nil {
				t.Fatal(err)
			}
			if err := <-accepted; !errors.Is(err, store.ErrPrecondition) {
				t.Fatalf("accept after revocation: %v", err)
			}
			if _, err := s.OrganizationsII().GetInvitationReceipt(ctx, "t", "accept"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("receipt survives failure: %v", err)
			}
			member, err := s.Organizations().IsMember(ctx, "t", o.ID, "auth0|u")
			if err != nil || member {
				t.Fatalf("membership survives failure: %v %v", member, err)
			}
		})
	}
}
func TestOrganizationsIIAcceptDeleteRace(t *testing.T)     { orgIIRevokeRace(t, true) }
func TestOrganizationsIIPolicyRevocationRace(t *testing.T) { orgIIRevokeRace(t, false) }

func TestOrganizationsIIResetContext(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			ticket := &store.PasswordResetTicket{TenantID: "t", ID: "reset", TokenHash: "hash", UserID: "u", OrganizationID: "org_bound", ExpiresAt: time.Now().Add(time.Hour)}
			if err := s.PasswordResetTickets().Create(ctx, ticket); err != nil {
				t.Fatal(err)
			}
			got, err := s.PasswordResetTickets().GetByTokenHash(ctx, "t", "hash")
			if err != nil || got.OrganizationID != ticket.OrganizationID {
				t.Fatalf("reset context %+v %v", got, err)
			}
		})
	}
}

func TestOrganizationsIIReadExpiryBoundary(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			o, in := orgIIRaceSeed(t, s)
			ctx := context.Background()
			clock := in.ExpiresAt.Add(-time.Nanosecond)
			s.orgIIClock = func() time.Time { return clock }
			if _, err := s.OrganizationsII().GetInvitation(ctx, "t", o.ID, in.ID); err != nil {
				t.Fatal(err)
			}
			clock = in.ExpiresAt
			if _, err := s.OrganizationsII().GetInvitation(ctx, "t", o.ID, in.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("get exact expiry %v", err)
			}
			if _, err := s.OrganizationsII().FindInvitation(ctx, "t", in.TicketHash); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("find exact expiry %v", err)
			}
			page, err := s.OrganizationsII().ListInvitations(ctx, "t", o.ID, store.OrgPage{})
			if err != nil || len(page.Items) != 0 {
				t.Fatalf("list exact expiry %+v %v", page, err)
			}
			if err := s.WithTx(ctx, func(tx store.Store) error {
				_, err := tx.OrganizationsII().GetInvitation(ctx, "t", o.ID, in.ID)
				return err
			}); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("transaction clock %v", err)
			}
		})
	}
}

func TestOrganizationsIIPolicyReadHoldsWriter(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			for _, kind := range []string{"organization", "association", "organization-connection", "client", "connection", "grant", "user", "invitation-delete", "organization-delete", "client-delete", "user-delete", "tenant-delete"} {
				t.Run(kind, func(t *testing.T) {
					s := mk(t)
					ctx := context.Background()
					o, in := orgIIRaceSeed(t, s)
					conn := &store.Connection{TenantID: "t", ID: "con", Name: "database", Strategy: store.StrategyDatabase, EnabledClients: []string{"c"}}
					if err := s.Connections().Create(ctx, conn); err != nil {
						t.Fatal(err)
					}
					link := store.OrganizationConnection{TenantID: "t", OrganizationID: o.ID, ConnectionID: "con", ShowAsButton: true, IsEnabled: true, IsEnabledSet: true}
					if err := s.Organizations().PutConnection(ctx, link, true); err != nil {
						t.Fatal(err)
					}
					grant := &store.ClientGrant{TenantID: "t", ID: "grant", ClientID: "c", Audience: "aud", OrganizationUsage: "allow"}
					if err := s.ClientGrants().Create(ctx, grant); err != nil {
						t.Fatal(err)
					}
					client, err := s.Clients().Get(ctx, "t", "c")
					if err != nil {
						t.Fatal(err)
					}
					user, err := s.Users().Get(ctx, "t", "auth0|u")
					if err != nil {
						t.Fatal(err)
					}
					var read func(store.Store) error
					var write func(context.Context) error
					switch kind {
					case "organization":
						read = func(tx store.Store) error { _, e := tx.Organizations().Get(ctx, "t", o.ID); return e }
						write = func(c context.Context) error { o.IsAppEntitlementActive = false; return s.Organizations().Update(c, o) }
					case "association":
						read = func(tx store.Store) error { _, e := tx.OrganizationsII().GetClient(ctx, "t", o.ID, "c"); return e }
						write = func(c context.Context) error {
							return s.OrganizationsII().PutClients(c, "t", o.ID, []store.OrganizationClient{{ClientID: "c", UseForMemberAccess: false}})
						}
					case "organization-connection":
						read = func(tx store.Store) error { _, e := tx.Organizations().GetConnection(ctx, "t", o.ID, "con"); return e }
						write = func(c context.Context) error {
							link.IsEnabled = false
							return s.Organizations().PutConnection(c, link, false)
						}
					case "client":
						read = func(tx store.Store) error { _, e := tx.Clients().Get(ctx, "t", "c"); return e }
						write = func(c context.Context) error {
							client.OrganizationUsage = store.OrgUsageDeny
							return s.Clients().Update(c, client)
						}
					case "connection":
						read = func(tx store.Store) error { _, e := tx.Connections().Get(ctx, "t", "con"); return e }
						write = func(c context.Context) error { conn.EnabledClients = nil; return s.Connections().Update(c, conn) }
					case "grant":
						read = func(tx store.Store) error {
							_, e := tx.ClientGrants().Find(ctx, "t", "c", "aud", store.SubjectTypeClient)
							return e
						}
						write = func(c context.Context) error {
							grant.OrganizationUsage = "deny"
							return s.ClientGrants().Update(c, grant)
						}
					case "user":
						read = func(tx store.Store) error { _, e := tx.Users().GetForUpdate(ctx, "t", "auth0|u"); return e }
						write = func(c context.Context) error { user.Blocked = true; return s.Users().Update(c, user) }
					case "invitation-delete":
						read = func(tx store.Store) error {
							_, e := tx.OrganizationsII().GetInvitation(ctx, "t", o.ID, in.ID)
							return e
						}
						write = func(c context.Context) error { return s.OrganizationsII().DeleteInvitation(c, "t", o.ID, in.ID) }
					case "organization-delete":
						read = func(tx store.Store) error { _, e := tx.Organizations().Get(ctx, "t", o.ID); return e }
						write = func(c context.Context) error { return s.Organizations().Delete(c, "t", o.ID) }
					case "client-delete":
						read = func(tx store.Store) error { _, e := tx.Clients().Get(ctx, "t", "c"); return e }
						write = func(c context.Context) error { return s.Clients().Delete(c, "t", "c") }
					case "user-delete":
						read = func(tx store.Store) error { _, e := tx.Users().GetForUpdate(ctx, "t", "auth0|u"); return e }
						write = func(c context.Context) error { return s.Users().Delete(c, "t", "auth0|u") }
					case "tenant-delete":
						read = func(tx store.Store) error {
							_, e := tx.OrganizationsII().GetInvitation(ctx, "t", o.ID, in.ID)
							return e
						}
						write = func(c context.Context) error { return s.Tenants().Delete(c, "t") }
					}
					readDone, release, attempted := make(chan struct{}), make(chan struct{}), make(chan struct{})
					readerErr, writerErr := make(chan error, 1), make(chan error, 1)
					go func() {
						readerErr <- s.WithTx(ctx, func(tx store.Store) error {
							e := read(tx)
							close(readDone)
							<-release
							if e != nil {
								return e
							}
							if _, e := tx.OrganizationsII().ConsumeInvitation(ctx, "t", o.ID, in.ID, "first", "auth0|u", time.Now()); e != nil {
								return e
							}
							return tx.Organizations().AddMembers(ctx, "t", o.ID, []string{"auth0|u"})
						})
					}()
					<-readDone
					writerCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
					defer cancel()
					go func() { close(attempted); writerErr <- write(writerCtx) }()
					<-attempted
					e := <-writerErr
					close(release)
					readerResult := <-readerErr
					if !errors.Is(e, context.DeadlineExceeded) {
						t.Fatalf("writer crossed active policy transaction: %v", e)
					}
					if readerResult != nil {
						t.Fatal(readerResult)
					}
					if _, e := s.OrganizationsII().GetInvitationReceipt(ctx, "t", "first"); e != nil {
						t.Fatal(e)
					}
					if e := write(ctx); e != nil {
						t.Fatalf("writer after commit: %v", e)
					}
				})
			}
		})
	}
}

func TestOrganizationsIICompositeOwners(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			o, _ := orgIIRaceSeed(t, s)
			if err := s.Tenants().Create(ctx, &store.Tenant{ID: "other", Name: "other"}); err != nil {
				t.Fatal(err)
			}
			if err := s.Clients().Create(ctx, &store.Client{TenantID: "other", ClientID: "foreign"}); err != nil {
				t.Fatal(err)
			}
			if err := s.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: "other", ID: "foreign-grant", ClientID: "foreign", Audience: "aud"}); err != nil {
				t.Fatal(err)
			}
			for _, q := range []string{
				`INSERT INTO organization_clients (tenant_id,organization_id,client_id,use_for_member_access) VALUES ('t',?,'foreign',true)`,
				`INSERT INTO organization_client_grants (tenant_id,organization_id,grant_id) VALUES ('t',?,'foreign-grant')`,
				`INSERT INTO organization_invitation_receipts (tenant_id,organization_id,invitation_id,transaction_id,user_id,accepted_at) VALUES ('t',?,'invite','tx','missing',1)`,
				`INSERT INTO organization_invitations (tenant_id,organization_id,id,client_id,ticket_hash,expires_at,created_at,payload) VALUES ('t',?,'bad','foreign','bad',1,1,'{}')`,
			} {
				if _, err := s.exec(ctx, q, o.ID); err == nil {
					t.Fatalf("composite owner not constrained: %s", q)
				}
			}
			if _, err := s.exec(ctx, `INSERT INTO organization_clients (tenant_id,organization_id,client_id,use_for_member_access) VALUES ('other',?,'foreign',true)`, o.ID); err == nil {
				t.Fatal("organization owner not constrained")
			}
		})
	}
}

// II adds owner constraints and a policy lock to established repositories. Keep
// the relevant original contracts in the focused selection so cascade ordering,
// standalone fixtures and transaction behavior remain covered on every driver.
func TestOrganizationsIILegacyRegression(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			storetest.RunSuites(t, func(t *testing.T) store.Store { return mk(t) }, "Organizations", "ClientGrants", "TenantsDelete", "RBAC", "Clients", "Connections", "Users", "UserDelete", "PasswordResetTickets", "AuthTransactions")
		})
	}
}
