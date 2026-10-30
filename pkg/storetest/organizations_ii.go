package storetest

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"sync"
	"testing"
	"time"
)

func testOrganizationsII(t *testing.T, factory Factory) {
	t.Run("OrganizationsIIDeletionReferences", func(t *testing.T) { testOrganizationsIIDeletionReferences(t, factory) })
	ctx := context.Background()
	setup := func(t *testing.T) (store.Store, *store.Organization) {
		s := open(t, factory)
		orgSeed(t, s, true)
		o := newOrg("org-a", "ii", time.Now().UTC())
		mustNoErr(t, s.Organizations().Create(ctx, o, nil))
		mustNoErr(t, s.Clients().Create(ctx, &store.Client{TenantID: "org-a", ClientID: "client", Name: "client"}))
		return s, o
	}
	invite := func(s store.Store, o *store.Organization, id string) *store.OrganizationInvitation {
		return &store.OrganizationInvitation{TenantID: o.TenantID, OrganizationID: o.ID, ID: id, ClientID: "client", InviterName: "Inviter", InviteeEmail: "u@example.test", TicketHash: id, WrappedTicket: []byte("sealed"), Roles: []string{"r1"}, UserMetadata: map[string]any{"nested": map[string]any{"a": "original"}}, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}
	}
	t.Run("OrganizationsIIInvitationAtomicity", func(t *testing.T) {
		s, o := setup(t)
		in := invite(s, o, "uinv_atomic")
		mustNoErr(t, s.OrganizationsII().CreateInvitation(ctx, in))
		// A failed role mutation must undo both consumption and membership.
		err := s.WithTx(ctx, func(tx store.Store) error {
			if _, e := tx.OrganizationsII().ConsumeInvitation(ctx, o.TenantID, o.ID, in.ID, "rollback", "auth0|u1", time.Now()); e != nil {
				return e
			}
			if e := tx.Organizations().AddMembers(ctx, o.TenantID, o.ID, []string{"auth0|u1"}); e != nil {
				return e
			}
			return tx.Organizations().ChangeMemberRoles(ctx, o.TenantID, o.ID, "auth0|u1", true, []string{"missing"})
		})
		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("rollback error %v", err)
		}
		if _, e := s.OrganizationsII().GetInvitation(ctx, o.TenantID, o.ID, in.ID); e != nil {
			t.Fatal(e)
		}
		member, e := s.Organizations().IsMember(ctx, o.TenantID, o.ID, "auth0|u1")
		mustNoErr(t, e)
		if member {
			t.Fatal("membership survived rollback")
		}
		if _, e := s.OrganizationsII().GetInvitationReceipt(ctx, o.TenantID, "rollback"); !errors.Is(e, store.ErrNotFound) {
			t.Fatalf("receipt survived rollback %v", e)
		}
		var wg sync.WaitGroup
		out := make(chan error, 2)
		for _, id := range []string{"one", "two"} {
			wg.Go(func() {
				out <- s.WithTx(ctx, func(tx store.Store) error {
					_, e := tx.OrganizationsII().ConsumeInvitation(ctx, o.TenantID, o.ID, in.ID, id, "auth0|u1", time.Now())
					return e
				})
			})
		}
		wg.Wait()
		close(out)
		successes := 0
		for e := range out {
			if e == nil {
				successes++
			} else if !errors.Is(e, store.ErrPrecondition) {
				t.Fatal(e)
			}
		}
		if successes != 1 {
			t.Fatalf("accepted %d times", successes)
		}
		receipts := 0
		for _, id := range []string{"one", "two"} {
			receipt, e := s.OrganizationsII().GetInvitationReceipt(ctx, o.TenantID, id)
			if errors.Is(e, store.ErrNotFound) {
				continue
			}
			mustNoErr(t, e)
			receipts++
			if receipt.InvitationID != in.ID || receipt.UserID != "auth0|u1" || receipt.TransactionID != id {
				t.Fatalf("wrong receipt %+v", receipt)
			}
		}
		if receipts != 1 {
			t.Fatalf("receipt count %d", receipts)
		}
	})
	t.Run("OrganizationsIIReceiptReplay", func(t *testing.T) {
		s, o := setup(t)
		in := invite(s, o, "uinv_replay")
		mustNoErr(t, s.OrganizationsII().CreateInvitation(ctx, in))
		if _, e := s.OrganizationsII().ConsumeInvitation(ctx, o.TenantID, o.ID, in.ID, "tx", "auth0|u1", time.Now()); !errors.Is(e, store.ErrPrecondition) {
			t.Fatalf("outside transaction %v", e)
		}
		for range 2 {
			mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
				_, e := tx.OrganizationsII().ConsumeInvitation(ctx, o.TenantID, o.ID, in.ID, "tx", "auth0|u1", time.Now())
				return e
			}))
		}
		mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
			for _, v := range [][3]string{{o.ID, in.ID, "auth0|u2"}, {o.ID, "other", "auth0|u1"}, {"other", in.ID, "auth0|u1"}} {
				if _, e := tx.OrganizationsII().ConsumeInvitation(ctx, o.TenantID, v[0], v[1], "tx", v[2], time.Now()); !errors.Is(e, store.ErrPrecondition) {
					t.Fatalf("receipt binding %v", e)
				}
			}
			return nil
		}))
		if _, e := s.OrganizationsII().GetInvitationReceipt(ctx, "org-b", "tx"); !errors.Is(e, store.ErrNotFound) {
			t.Fatalf("receipt leaked %v", e)
		}
	})
	t.Run("OrganizationsIIExpiration", func(t *testing.T) {
		s, o := setup(t)
		in := invite(s, o, "uinv_expired")
		in.ExpiresAt = time.Now().Add(-time.Second)
		mustNoErr(t, s.OrganizationsII().CreateInvitation(ctx, in))
		if _, e := s.OrganizationsII().GetInvitation(ctx, o.TenantID, o.ID, in.ID); !errors.Is(e, store.ErrNotFound) {
			t.Fatalf("expired get %v", e)
		}
		if _, e := s.OrganizationsII().FindInvitation(ctx, o.TenantID, in.TicketHash); !errors.Is(e, store.ErrNotFound) {
			t.Fatalf("expired find %v", e)
		}
		page, e := s.OrganizationsII().ListInvitations(ctx, o.TenantID, o.ID, store.OrgPage{})
		mustNoErr(t, e)
		if len(page.Items) != 0 {
			t.Fatal("expired list")
		}
		fresh := invite(s, o, "uinv_exact")
		mustNoErr(t, s.OrganizationsII().CreateInvitation(ctx, fresh))
		e = s.WithTx(ctx, func(tx store.Store) error {
			_, e := tx.OrganizationsII().ConsumeInvitation(ctx, o.TenantID, o.ID, fresh.ID, "exact", "auth0|u1", fresh.ExpiresAt)
			return e
		})
		if !errors.Is(e, store.ErrPrecondition) {
			t.Fatalf("exact expiry %v", e)
		}
	})
	t.Run("OrganizationsIITenantIsolation", func(t *testing.T) {
		s, o := setup(t)
		in := invite(s, o, "uinv_isolation")
		mustNoErr(t, s.OrganizationsII().CreateInvitation(ctx, in))
		in.Roles[0] = "mutated"
		in.WrappedTicket[0] = 'X'
		in.UserMetadata["nested"].(map[string]any)["a"] = "mutated"
		got, e := s.OrganizationsII().GetInvitation(ctx, o.TenantID, o.ID, in.ID)
		mustNoErr(t, e)
		if got.Roles[0] != "r1" || string(got.WrappedTicket) != "sealed" || got.UserMetadata["nested"].(map[string]any)["a"] != "original" {
			t.Fatal("input aliases persisted")
		}
		got.Roles[0] = "mutated"
		got.UserMetadata["nested"].(map[string]any)["a"] = "mutated"
		got, e = s.OrganizationsII().FindInvitation(ctx, o.TenantID, in.TicketHash)
		mustNoErr(t, e)
		if got.Roles[0] != "r1" || got.UserMetadata["nested"].(map[string]any)["a"] != "original" {
			t.Fatal("read aliases persisted")
		}
		if _, e = s.OrganizationsII().GetInvitation(ctx, "org-b", o.ID, in.ID); !errors.Is(e, store.ErrNotFound) {
			t.Fatalf("cross tenant get %v", e)
		}
		if _, e = s.OrganizationsII().FindInvitation(ctx, "org-b", in.TicketHash); !errors.Is(e, store.ErrNotFound) {
			t.Fatalf("cross tenant hash %v", e)
		}
		bad := invite(s, o, "uinv_bad")
		bad.Roles = []string{"missing"}
		if e = s.OrganizationsII().CreateInvitation(ctx, bad); !errors.Is(e, store.ErrNotFound) {
			t.Fatalf("bad role %v", e)
		}
		if e = s.OrganizationsII().PutClients(ctx, o.TenantID, o.ID, []store.OrganizationClient{{ClientID: "client", UseForMemberAccess: true}, {ClientID: "missing"}}); !errors.Is(e, store.ErrNotFound) {
			t.Fatalf("bad batch %v", e)
		}
		if _, e = s.OrganizationsII().GetClient(ctx, o.TenantID, o.ID, "client"); !errors.Is(e, store.ErrNotFound) {
			t.Fatal("partial batch")
		}
	})
	t.Run("OrganizationsIIPolicyDefaults", func(t *testing.T) {
		s, o := setup(t)
		if o.IsAppEntitlementActive {
			t.Fatal("entitlement default")
		}
		c := dbConn("con1")
		c.TenantID = o.TenantID
		c.OrganizationID = o.ID
		mustNoErr(t, s.Organizations().PutConnection(ctx, c, true))
		got, e := s.Organizations().GetConnection(ctx, o.TenantID, o.ID, "con1")
		mustNoErr(t, e)
		if !got.IsEnabled || !got.IsEnabledSet || got.OrganizationAccessLevel != "none" || got.OrganizationMemberAccessLevel != "limited" {
			t.Fatalf("connection defaults %+v", got)
		}
		got.IsEnabled = false
		got.OrganizationMemberAccessLevel = "none"
		mustNoErr(t, s.Organizations().PutConnection(ctx, *got, false))
		got, e = s.Organizations().GetConnection(ctx, o.TenantID, o.ID, "con1")
		mustNoErr(t, e)
		if got.IsEnabled || got.OrganizationMemberAccessLevel != "none" {
			t.Fatal("explicit disable/none lost")
		}
		// Legacy replacement literals omit the II fields, preserving existing policy.
		mustNoErr(t, s.Organizations().PutConnection(ctx, c, false))
		got, e = s.Organizations().GetConnection(ctx, o.TenantID, o.ID, "con1")
		mustNoErr(t, e)
		if got.IsEnabled || got.OrganizationMemberAccessLevel != "none" {
			t.Fatal("omitted replacement reset policy")
		}
		c2 := store.OrganizationConnection{TenantID: o.TenantID, OrganizationID: o.ID, ConnectionID: "con2", IsEnabled: false, IsEnabledSet: true}
		mustNoErr(t, s.Organizations().PutConnection(ctx, c2, true))
		got, e = s.Organizations().GetConnection(ctx, o.TenantID, o.ID, "con2")
		mustNoErr(t, e)
		if got.IsEnabled || !got.IsEnabledSet {
			t.Fatal("explicit false create reset")
		}
		mustNoErr(t, s.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: o.TenantID, ID: "default", ClientID: "client", Audience: "default"}))
		grant, e := s.ClientGrants().Find(ctx, o.TenantID, "client", "default", store.SubjectTypeClient)
		mustNoErr(t, e)
		if grant.OrganizationUsage != "deny" || grant.AllowAnyOrganization {
			t.Fatalf("old grant policy %+v", grant)
		}
	})
	t.Run("OrganizationsIIReferenceValidation", func(t *testing.T) { testOrganizationsIIReferenceValidation(t, factory) })
	t.Run("OrganizationsIIRepositoryRoundTrips", func(t *testing.T) { testOrganizationsIIRepositoryRoundTrips(t, factory) })
	t.Run("OrganizationsIICascades", func(t *testing.T) { testOrganizationsIICascades(t, setup, invite) })
}

func testOrganizationsIICascades(t *testing.T, setup func(*testing.T) (store.Store, *store.Organization), invite func(store.Store, *store.Organization, string) *store.OrganizationInvitation) {
	ctx := context.Background()
	s, o := setup(t)
	mustNoErr(t, s.ResourceServers().Create(ctx, &store.ResourceServer{TenantID: o.TenantID, ID: "api", Identifier: "https://api.test", Name: "api"}))
	g := &store.ClientGrant{TenantID: o.TenantID, ID: "grant", ClientID: "client", Audience: "https://api.test", SubjectType: store.SubjectTypeClient, Origin: store.OriginAPI}
	mustNoErr(t, s.ClientGrants().Create(ctx, g))
	mustNoErr(t, s.OrganizationsII().PutClientGrant(ctx, o.TenantID, o.ID, g.ID))
	has, e := s.OrganizationsII().HasClientGrant(ctx, o.TenantID, o.ID, g.ID)
	mustNoErr(t, e)
	if !has {
		t.Fatal("missing grant")
	}
	page, e := s.OrganizationsII().ListClientGrants(ctx, o.TenantID, o.ID, store.OrgPage{})
	mustNoErr(t, e)
	if len(page.Items) != 1 || page.Items[0].Origin != store.OriginAPI {
		t.Fatal("grant origin lost")
	}
	reverse, e := s.OrganizationsII().GrantOrganizations(ctx, o.TenantID, g.ID, store.OrgPage{})
	mustNoErr(t, e)
	if len(reverse.Items) != 1 {
		t.Fatal("missing reverse grant")
	}
	mustNoErr(t, s.OrganizationsII().DeleteClientGrant(ctx, o.TenantID, o.ID, g.ID))
	has, e = s.OrganizationsII().HasClientGrant(ctx, o.TenantID, o.ID, g.ID)
	mustNoErr(t, e)
	if has {
		t.Fatal("grant removal left access")
	}
	mustNoErr(t, s.OrganizationsII().PutClientGrant(ctx, o.TenantID, o.ID, g.ID))
	mustNoErr(t, s.ClientGrants().Delete(ctx, o.TenantID, g.ID))
	has, e = s.OrganizationsII().HasClientGrant(ctx, o.TenantID, o.ID, g.ID)
	if e != nil && !errors.Is(e, store.ErrNotFound) {
		t.Fatal(e)
	}
	if has {
		t.Fatal("deleted grant left access")
	}
	in := invite(s, o, "uinv_cascade")
	mustNoErr(t, s.OrganizationsII().CreateInvitation(ctx, in))
	mustNoErr(t, s.OrganizationsII().PutClients(ctx, o.TenantID, o.ID, []store.OrganizationClient{{ClientID: "client", UseForMemberAccess: true}}))
	domain := &store.OrganizationDiscoveryDomain{TenantID: o.TenantID, OrganizationID: o.ID, ID: "dom", Domain: "example.test", Status: "verified", UseForOrganizationDiscovery: true}
	mustNoErr(t, s.OrganizationsII().PutDiscoveryDomain(ctx, domain, true))
	orgs, e := s.OrganizationsII().DiscoverOrganizations(ctx, o.TenantID, "example.test")
	mustNoErr(t, e)
	if len(orgs) != 1 {
		t.Fatal("missing discovery")
	}
	mustNoErr(t, s.OrganizationsII().DeleteDiscoveryDomain(ctx, o.TenantID, o.ID, domain.ID))
	orgs, e = s.OrganizationsII().DiscoverOrganizations(ctx, o.TenantID, "example.test")
	mustNoErr(t, e)
	if len(orgs) != 0 {
		t.Fatal("deleted discovery")
	}
	mustNoErr(t, s.OrganizationsII().PutDiscoveryDomain(ctx, domain, true))
	mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
		_, e := tx.OrganizationsII().ConsumeInvitation(ctx, o.TenantID, o.ID, in.ID, "org-cascade", "auth0|u1", time.Now())
		return e
	}))
	mustNoErr(t, s.Organizations().Delete(ctx, o.TenantID, o.ID))
	if _, e = s.OrganizationsII().GetInvitationReceipt(ctx, o.TenantID, "org-cascade"); !errors.Is(e, store.ErrNotFound) {
		t.Fatalf("orphan receipt %v", e)
	}
	if _, e = s.OrganizationsII().FindInvitation(ctx, o.TenantID, in.TicketHash); !errors.Is(e, store.ErrNotFound) {
		t.Fatalf("orphan invitation %v", e)
	}
	if _, e = s.OrganizationsII().GetClient(ctx, o.TenantID, o.ID, "client"); !errors.Is(e, store.ErrNotFound) {
		t.Fatalf("orphan client %v", e)
	}
	orgs, e = s.OrganizationsII().DiscoverOrganizations(ctx, o.TenantID, "example.test")
	mustNoErr(t, e)
	if len(orgs) != 0 {
		t.Fatal("orphan discovery")
	}
}

// Deleting an accepting user must not resurrect its bearer invitation; removing
// client/role/API references must invalidate or remove dependent access rows.
func testOrganizationsIIDeletionReferences(t *testing.T, factory Factory) {
	ctx := context.Background()
	for _, kind := range []string{"user", "role", "client", "api", "tenant"} {
		t.Run(kind, func(t *testing.T) {
			s := open(t, factory)
			orgSeed(t, s, true)
			o := newOrg("org-a", "cascade", time.Now())
			mustNoErr(t, s.Organizations().Create(ctx, o, nil))
			mustNoErr(t, s.Clients().Create(ctx, &store.Client{TenantID: o.TenantID, ClientID: "c"}))
			mustNoErr(t, s.ResourceServers().Create(ctx, &store.ResourceServer{TenantID: o.TenantID, ID: "api", Identifier: "api"}))
			g := &store.ClientGrant{TenantID: o.TenantID, ID: "g", ClientID: "c", Audience: "api"}
			mustNoErr(t, s.ClientGrants().Create(ctx, g))
			mustNoErr(t, s.OrganizationsII().PutClientGrant(ctx, o.TenantID, o.ID, "g"))
			mustNoErr(t, s.OrganizationsII().PutClients(ctx, o.TenantID, o.ID, []store.OrganizationClient{{ClientID: "c", UseForMemberAccess: true}}))
			in := &store.OrganizationInvitation{TenantID: o.TenantID, OrganizationID: o.ID, ID: "uinv_ref", ClientID: "c", TicketHash: "hash", WrappedTicket: []byte("sealed"), Roles: []string{"r1"}, ExpiresAt: time.Now().Add(time.Hour)}
			mustNoErr(t, s.OrganizationsII().CreateInvitation(ctx, in))
			if kind == "user" {
				mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
					_, e := tx.OrganizationsII().ConsumeInvitation(ctx, o.TenantID, o.ID, in.ID, "accept", "auth0|u1", time.Now())
					return e
				}))
				mustNoErr(t, s.Users().Delete(ctx, o.TenantID, "auth0|u1"))
			}
			if kind == "role" {
				mustNoErr(t, s.RBAC().DeleteRole(ctx, o.TenantID, "r1"))
			}
			if kind == "client" {
				mustNoErr(t, s.Clients().Delete(ctx, o.TenantID, "c"))
			}
			if kind == "api" {
				mustNoErr(t, s.ResourceServers().Delete(ctx, o.TenantID, "api"))
			}
			if kind == "tenant" {
				mustNoErr(t, s.Tenants().Delete(ctx, o.TenantID))
			}
			if kind != "api" {
				if _, e := s.OrganizationsII().FindInvitation(ctx, o.TenantID, "hash"); !errors.Is(e, store.ErrNotFound) {
					t.Fatalf("%s left usable invitation: %v", kind, e)
				}
			}
			if kind == "client" || kind == "api" || kind == "tenant" {
				has, e := s.OrganizationsII().HasClientGrant(ctx, o.TenantID, o.ID, "g")
				if e != nil && !errors.Is(e, store.ErrNotFound) {
					t.Fatal(e)
				}
				if has {
					t.Fatal("deleted owner left access")
				}
				// Reusing an ID must not inherit the deleted grant's old associations.
				if kind == "api" {
					mustNoErr(t, s.ResourceServers().Create(ctx, &store.ResourceServer{TenantID: o.TenantID, ID: "api", Identifier: "api"}))
					mustNoErr(t, s.ClientGrants().Create(ctx, g))
					has, e = s.OrganizationsII().HasClientGrant(ctx, o.TenantID, o.ID, "g")
					mustNoErr(t, e)
					if has {
						t.Fatal("recreated grant inherited old access")
					}
				}
			}
			if kind == "client" || kind == "tenant" {
				if _, e := s.OrganizationsII().GetClient(ctx, o.TenantID, o.ID, "c"); !errors.Is(e, store.ErrNotFound) {
					t.Fatalf("orphan client %v", e)
				}
			}
		})
	}
}

// A user-subject grant cannot become an M2M organization association. Owners
// and complete batches must be checked before any row becomes visible.
func testOrganizationsIIReferenceValidation(t *testing.T, factory Factory) {
	ctx := context.Background()
	s := open(t, factory)
	orgSeed(t, s, true)
	o := newOrg("org-a", "refs", time.Now())
	mustNoErr(t, s.Organizations().Create(ctx, o, nil))
	mustNoErr(t, s.Clients().Create(ctx, &store.Client{TenantID: o.TenantID, ClientID: "c"}))
	mustNoErr(t, s.ResourceServers().Create(ctx, &store.ResourceServer{TenantID: o.TenantID, ID: "api", Identifier: "api"}))
	mustNoErr(t, s.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: o.TenantID, ID: "user-grant", ClientID: "c", Audience: "api", SubjectType: store.SubjectTypeUser}))
	if e := s.OrganizationsII().PutClientGrant(ctx, o.TenantID, o.ID, "user-grant"); !errors.Is(e, store.ErrInvalid) {
		t.Fatalf("user grant associated: %v", e)
	}
	for _, f := range []func() error{
		func() error { return s.OrganizationsII().PutClientGrant(ctx, "org-b", o.ID, "user-grant") },
		func() error {
			return s.OrganizationsII().PutClients(ctx, "org-b", o.ID, []store.OrganizationClient{{ClientID: "c"}})
		},
		func() error {
			return s.OrganizationsII().PutDiscoveryDomain(ctx, &store.OrganizationDiscoveryDomain{TenantID: "org-b", OrganizationID: o.ID, ID: "d", Domain: "x.test"}, true)
		},
	} {
		if e := f(); !errors.Is(e, store.ErrNotFound) {
			t.Fatalf("cross tenant write %v", e)
		}
	}
	if e := s.OrganizationsII().PutClients(ctx, o.TenantID, o.ID, []store.OrganizationClient{{TenantID: "org-b", ClientID: "c"}}); !errors.Is(e, store.ErrNotFound) {
		t.Fatalf("cross tenant batch owner %v", e)
	}
	mustNoErr(t, s.OrganizationsII().PutClients(ctx, o.TenantID, o.ID, []store.OrganizationClient{{ClientID: "c", UseForMemberAccess: true}}))
	if e := s.OrganizationsII().DeleteClients(ctx, o.TenantID, o.ID, []string{"c", "missing"}); !errors.Is(e, store.ErrNotFound) {
		t.Fatalf("invalid delete batch %v", e)
	}
	got, e := s.OrganizationsII().GetClient(ctx, o.TenantID, o.ID, "c")
	mustNoErr(t, e)
	if !got.UseForMemberAccess {
		t.Fatal("partial batch changed association")
	}
}

func testOrganizationsIIRepositoryRoundTrips(t *testing.T, factory Factory) {
	ctx := context.Background()
	s := open(t, factory)
	orgSeed(t, s, true)
	o := newOrg("org-a", "roundtrip", time.Now())
	mustNoErr(t, s.Organizations().Create(ctx, o, nil))
	ii := s.OrganizationsII()
	for _, id := range []string{"a", "b"} {
		mustNoErr(t, s.Clients().Create(ctx, &store.Client{TenantID: o.TenantID, ClientID: id}))
		mustNoErr(t, ii.PutClients(ctx, o.TenantID, o.ID, []store.OrganizationClient{{ClientID: id, UseForMemberAccess: true}}))
	}
	page, e := ii.ListClients(ctx, o.TenantID, o.ID, store.OrgPage{Take: 1})
	mustNoErr(t, e)
	if len(page.Items) != 1 || page.Items[0].ClientID != "a" || page.Next == "" {
		t.Fatalf("client page %+v", page)
	}
	tail, e := ii.ListClients(ctx, o.TenantID, o.ID, store.OrgPage{From: page.Next})
	mustNoErr(t, e)
	if len(tail.Items) != 1 || tail.Items[0].ClientID != "b" || tail.Next != "" {
		t.Fatal("client checkpoint tail")
	}
	if _, e = ii.ListClients(ctx, "org-b", o.ID, store.OrgPage{From: page.Next}); !errors.Is(e, store.ErrNotFound) {
		t.Fatalf("cross tenant parent %v", e)
	}
	mustNoErr(t, ii.PutClients(ctx, o.TenantID, o.ID, []store.OrganizationClient{{ClientID: "a", UseForMemberAccess: false}}))
	v, e := ii.GetClient(ctx, o.TenantID, o.ID, "a")
	mustNoErr(t, e)
	if v.UseForMemberAccess {
		t.Fatal("false association update lost")
	}
	v.UseForMemberAccess = true
	v, e = ii.GetClient(ctx, o.TenantID, o.ID, "a")
	mustNoErr(t, e)
	if v.UseForMemberAccess {
		t.Fatal("association output aliases")
	}
	d := &store.OrganizationDiscoveryDomain{TenantID: o.TenantID, OrganizationID: o.ID, ID: "d", Domain: "x.test", Status: "pending", UseForOrganizationDiscovery: true, VerificationHost: "_verify.x.test", VerificationTXT: "challenge"}
	mustNoErr(t, ii.PutDiscoveryDomain(ctx, d, true))
	d.VerificationTXT = "mutated"
	got, e := ii.GetDiscoveryDomainByName(ctx, o.TenantID, o.ID, "x.test")
	mustNoErr(t, e)
	if got.VerificationTXT != "challenge" {
		t.Fatal("domain input aliases")
	}
	got.Status = "verified"
	mustNoErr(t, ii.PutDiscoveryDomain(ctx, got, false))
	got.Status = "pending"
	found, e := ii.DiscoverOrganizations(ctx, o.TenantID, "x.test")
	mustNoErr(t, e)
	if len(found) != 1 {
		t.Fatal("domain output aliases")
	}
	domains, e := ii.ListDiscoveryDomains(ctx, o.TenantID, o.ID, store.OrgPage{PerPage: 1})
	mustNoErr(t, e)
	if len(domains.Items) != 1 || domains.Total != 1 {
		t.Fatal("domain paging")
	}
	in := &store.OrganizationInvitation{TenantID: o.TenantID, OrganizationID: o.ID, ID: "uinv_roundtrip", ClientID: "a", TicketHash: "roundtrip", WrappedTicket: []byte("sealed"), CreatedAt: ts(0), ExpiresAt: time.Now().Add(time.Hour)}
	mustNoErr(t, ii.CreateInvitation(ctx, in))
	in2 := *in
	in2.ID = "uinv_second"
	in2.TicketHash = "second"
	in2.CreatedAt = ts(1)
	mustNoErr(t, ii.CreateInvitation(ctx, &in2))
	invites, e := ii.ListInvitations(ctx, o.TenantID, o.ID, store.OrgPage{Take: 1})
	mustNoErr(t, e)
	if len(invites.Items) != 1 || invites.Next == "" || invites.Items[0].ID != "uinv_second" {
		t.Fatal("invitation pagination")
	}
	// Every II map participates in rollback, including delete cascades.
	rollback := errors.New("rollback")
	e = s.WithTx(ctx, func(tx store.Store) error {
		if e := tx.Organizations().Delete(ctx, o.TenantID, o.ID); e != nil {
			return e
		}
		return rollback
	})
	if !errors.Is(e, rollback) {
		t.Fatal(e)
	}
	if _, e = ii.GetInvitation(ctx, o.TenantID, o.ID, in.ID); e != nil {
		t.Fatal("invitation cascade rollback", e)
	}
	if _, e = ii.GetClient(ctx, o.TenantID, o.ID, "a"); e != nil {
		t.Fatal("client cascade rollback", e)
	}
	if _, e = ii.GetDiscoveryDomain(ctx, o.TenantID, o.ID, "d"); e != nil {
		t.Fatal("domain cascade rollback", e)
	}
	mustNoErr(t, ii.DeleteInvitation(ctx, o.TenantID, o.ID, in.ID))
	mustNoErr(t, ii.DeleteInvitation(ctx, o.TenantID, o.ID, in.ID))
	if _, e = ii.GetInvitation(ctx, o.TenantID, o.ID, in.ID); !errors.Is(e, store.ErrNotFound) {
		t.Fatalf("deleted invitation %v", e)
	}
	mustNoErr(t, ii.DeleteClients(ctx, o.TenantID, o.ID, []string{"a", "b"}))
	page, e = ii.ListClients(ctx, o.TenantID, o.ID, store.OrgPage{})
	mustNoErr(t, e)
	if len(page.Items) != 0 {
		t.Fatal("delete clients")
	}
}
