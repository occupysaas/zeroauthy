package storetest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newOrg(tenant, name string, created time.Time) *store.Organization {
	return &store.Organization{
		TenantID: tenant, ID: orgrules.NewID(), Name: name, DisplayName: "Display " + name,
		ThirdPartyClientAccess: "block", CreatedAt: created, UpdatedAt: created,
	}
}

func dbConn(id string) store.OrganizationConnection {
	return store.OrganizationConnection{ConnectionID: id, ShowAsButton: true}
}

// orgSeed creates tenant "org-a" (and "org-b" when other is true) with users
// auth0|u1..u5, roles r1..r3 and connections con1 (database), con2 (waad,
// enterprise) and con3 (google, social).
func orgSeed(t *testing.T, s store.Store, other bool) {
	t.Helper()
	ctx := context.Background()
	tenants := []string{"org-a"}
	if other {
		tenants = append(tenants, "org-b")
	}
	for _, tid := range tenants {
		mustNoErr(t, s.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}))
		for i := 1; i <= 5; i++ {
			id := fmt.Sprintf("u%d", i)
			mustNoErr(t, s.Users().Create(ctx, newUser(tid, id, id+"@"+tid+".test", id)))
		}
		for i := 1; i <= 3; i++ {
			mustNoErr(t, s.RBAC().CreateRole(ctx, &store.Role{TenantID: tid, ID: fmt.Sprintf("r%d", i), Name: fmt.Sprintf("Role %d", i)}))
		}
		for _, c := range []struct{ id, name, strategy string }{{"con1", "Database", store.StrategyDatabase}, {"con2", "Entra", "waad"}, {"con3", "Goog", "google"}} {
			conn := newConnection(tid, c.id, c.name)
			conn.Strategy = c.strategy
			mustNoErr(t, s.Connections().Create(ctx, conn))
		}
	}
}

func orgNames(items []store.Organization) []string {
	out := make([]string, len(items))
	for i, o := range items {
		out[i] = o.Name
	}
	return out
}

// testOrganizations pins the Organizations repository: CRUD and uniqueness,
// both pagination styles with every sort, members and member roles, each
// cascade, tenant deletion, transaction rollback and the caps.
func testOrganizations(t *testing.T, newStore Factory) {
	ctx := context.Background()
	const tid = "org-a"
	uid := func(n int) string { return fmt.Sprintf("auth0|u%d", n) }

	t.Run("CRUD", func(t *testing.T) {
		s := open(t, newStore)
		orgSeed(t, s, true)
		o := s.Organizations()
		in := newOrg(tid, "acme", ts(0))
		logo := "https://x.test/logo.png"
		in.Branding = &store.OrgBranding{LogoURL: &logo, Colors: &store.OrgColors{Primary: "#111111", PageBackground: "#ffffff"}}
		in.Metadata = map[string]string{"tier": "gold"}
		mustNoErr(t, o.Create(ctx, in, []store.OrganizationConnection{
			{TenantID: tid, OrganizationID: in.ID, ConnectionID: "con1", ShowAsButton: true, AssignMembershipOnLogin: true, IsSignupEnabled: true},
			{TenantID: tid, OrganizationID: in.ID, ConnectionID: "con2"},
		}))
		got, err := o.Get(ctx, tid, in.ID)
		mustNoErr(t, err)
		mustEqual(t, got, in)
		*in.Branding.LogoURL = "mutated"
		in.Metadata["tier"] = "mutated"
		again, err := o.Get(ctx, tid, in.ID)
		mustNoErr(t, err)
		mustEqual(t, again.Metadata, map[string]string{"tier": "gold"})
		mustEqual(t, *again.Branding.LogoURL, "https://x.test/logo.png")
		again.Metadata["tier"] = "mutated"
		third, _ := o.Get(ctx, tid, in.ID)
		mustEqual(t, third.Metadata, map[string]string{"tier": "gold"})

		byName, err := o.GetByName(ctx, tid, "acme")
		mustNoErr(t, err)
		mustEqual(t, byName.ID, in.ID)
		_, err = o.GetByName(ctx, tid, "ACME")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = o.Get(ctx, "org-b", in.ID)
		mustErrIs(t, err, store.ErrNotFound)
		_, err = o.GetByName(ctx, "org-b", "acme")
		mustErrIs(t, err, store.ErrNotFound)

		conns, err := o.Connections(ctx, tid, in.ID, store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, conns.Total, 2)
		mustEqual(t, conns.Items[0].ConnectionID, "con1")
		mustEqual(t, conns.Items[0].OrganizationID, in.ID)
		mustEqual(t, conns.Items[0].IsSignupEnabled, true)

		dup := newOrg(tid, "acme", ts(1))
		mustErrIs(t, o.Create(ctx, dup, nil), store.ErrConflict)
		mustNoErr(t, o.Create(ctx, newOrg("org-b", "acme", ts(1)), nil))
		bad := newOrg(tid, "Bad Name", ts(1))
		mustErrIs(t, o.Create(ctx, bad, nil), store.ErrInvalid)
		unknownConn := newOrg(tid, "ghost", ts(1))
		mustErrIs(t, o.Create(ctx, unknownConn, []store.OrganizationConnection{dbConn("nope")}), store.ErrNotFound)
		_, err = o.GetByName(ctx, tid, "ghost")
		mustErrIs(t, err, store.ErrNotFound)
		hide := newOrg(tid, "hidden", ts(1))
		mustErrIs(t, o.Create(ctx, hide, []store.OrganizationConnection{{ConnectionID: "con1"}}), store.ErrInvalid)
		twice := newOrg(tid, "twice", ts(1))
		mustErrIs(t, o.Create(ctx, twice, []store.OrganizationConnection{dbConn("con1"), dbConn("con1")}), store.ErrConflict)

		// Update replaces whole: omitted branding and metadata are cleared.
		up := *got
		up.Name, up.DisplayName, up.Branding, up.Metadata, up.ThirdPartyClientAccess = "acme2", "Acme Two", nil, nil, "allow"
		up.CreatedAt = ts(99)
		mustNoErr(t, o.Update(ctx, &up))
		after, err := o.Get(ctx, tid, in.ID)
		mustNoErr(t, err)
		mustEqual(t, after.Name, "acme2")
		mustEqual(t, after.DisplayName, "Acme Two")
		mustEqual(t, after.ThirdPartyClientAccess, "allow")
		if after.Branding != nil || after.Metadata != nil {
			t.Fatalf("branding/metadata survived replacement: %#v", after)
		}
		mustEqual(t, after.CreatedAt, ts(0))
		if !after.UpdatedAt.After(ts(0)) {
			t.Fatalf("UpdatedAt = %v", after.UpdatedAt)
		}
		_, err = o.GetByName(ctx, tid, "acme")
		mustErrIs(t, err, store.ErrNotFound)
		second := newOrg(tid, "second", ts(2))
		mustNoErr(t, o.Create(ctx, second, nil))
		clash := *after
		clash.Name = "second"
		mustErrIs(t, o.Update(ctx, &clash), store.ErrConflict)
		same := *after
		mustNoErr(t, o.Update(ctx, &same))
		ghost := *after
		ghost.ID = orgrules.NewID()
		mustErrIs(t, o.Update(ctx, &ghost), store.ErrNotFound)
		invalid := *after
		invalid.DisplayName = strings.Repeat("x", 256)
		mustErrIs(t, o.Update(ctx, &invalid), store.ErrInvalid)

		mustNoErr(t, o.Delete(ctx, tid, in.ID))
		mustErrIs(t, o.Delete(ctx, tid, in.ID), store.ErrNotFound)
		_, err = o.Get(ctx, tid, in.ID)
		mustErrIs(t, err, store.ErrNotFound)
		// The name is free again.
		mustNoErr(t, o.Create(ctx, newOrg(tid, "acme", ts(3)), nil))
	})

	t.Run("ConcurrentCreate", func(t *testing.T) {
		s := open(t, newStore)
		orgSeed(t, s, false)
		errs := parallel(10, func(int) error { return s.Organizations().Create(ctx, newOrg(tid, "race", ts(0)), nil) })
		wins := 0
		for _, err := range errs {
			switch {
			case err == nil:
				wins++
			case !errors.Is(err, store.ErrConflict):
				t.Fatalf("unexpected error %v", err)
			}
		}
		mustEqual(t, wins, 1)
		res, err := s.Organizations().List(ctx, tid, store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, res.Total, 1)
	})

	t.Run("ConcurrentAddMembers", func(t *testing.T) {
		// Concurrent adds of the same users are idempotent, also inside a
		// caller's transaction that read before the add (Management handlers
		// do), and so are concurrent role assignments.
		s := open(t, newStore)
		orgSeed(t, s, false)
		o := newOrg(tid, "race", ts(0))
		mustNoErr(t, s.Organizations().Create(ctx, o, nil))
		errs := parallel(8, func(int) error {
			return s.WithTx(ctx, func(tx store.Store) error {
				if _, err := tx.Organizations().IsMember(ctx, tid, o.ID, uid(1)); err != nil {
					return err
				}
				return tx.Organizations().AddMembers(ctx, tid, o.ID, []string{uid(1), uid(2)})
			})
		})
		for _, err := range errs {
			mustNoErr(t, err)
		}
		members, err := s.Organizations().Members(ctx, tid, o.ID, store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, members.Items, []string{uid(1), uid(2)})
		errs = parallel(8, func(int) error {
			return s.WithTx(ctx, func(tx store.Store) error {
				if _, err := tx.Organizations().MemberRoles(ctx, tid, o.ID, uid(1), store.OrgPage{}); err != nil {
					return err
				}
				return tx.Organizations().ChangeMemberRoles(ctx, tid, o.ID, uid(1), true, []string{"r1", "r2"})
			})
		})
		for _, err := range errs {
			mustNoErr(t, err)
		}
		roles, err := s.Organizations().MemberRoles(ctx, tid, o.ID, uid(1), store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, roles.Items, []string{"r1", "r2"})
	})

	t.Run("Pagination", func(t *testing.T) {
		s := open(t, newStore)
		orgSeed(t, s, true)
		o := s.Organizations()
		// name order, display_name order and creation order all differ.
		for _, sp := range []struct {
			name, display string
			created       time.Duration
		}{{"delta", "Bravo", 1}, {"alpha", "Echo", 4}, {"echo", "Alpha", 3}, {"bravo", "Delta", 5}, {"charlie", "Charlie", 2}} {
			org := newOrg(tid, sp.name, ts(sp.created*time.Minute))
			org.DisplayName = sp.display
			mustNoErr(t, o.Create(ctx, org, nil))
		}
		mustNoErr(t, o.Create(ctx, newOrg("org-b", "other", ts(0)), nil))
		want := map[string][]string{
			"":                {"alpha", "bravo", "charlie", "delta", "echo"},
			"name:1":          {"alpha", "bravo", "charlie", "delta", "echo"},
			"name:-1":         {"echo", "delta", "charlie", "bravo", "alpha"},
			"display_name:1":  {"echo", "delta", "charlie", "bravo", "alpha"},
			"display_name:-1": {"alpha", "bravo", "charlie", "delta", "echo"},
			"created_at:1":    {"delta", "charlie", "echo", "alpha", "bravo"},
			"created_at:-1":   {"bravo", "alpha", "echo", "charlie", "delta"},
		}
		// Display names: delta=Bravo, alpha=Echo, echo=Alpha, bravo=Delta, charlie=Charlie.
		for sort, names := range want {
			t.Run("offset "+sort, func(t *testing.T) {
				res, err := o.List(ctx, tid, store.OrgPage{Sort: sort})
				mustNoErr(t, err)
				mustEqual(t, orgNames(res.Items), names)
				mustEqual(t, res.Total, 5)
				mustEqual(t, res.Next, "")
				var paged []string
				for page := 0; page < 3; page++ {
					r, err := o.List(ctx, tid, store.OrgPage{Sort: sort, Page: page, PerPage: 2})
					mustNoErr(t, err)
					mustEqual(t, r.Total, 5)
					paged = append(paged, orgNames(r.Items)...)
				}
				mustEqual(t, paged, names)
				past, err := o.List(ctx, tid, store.OrgPage{Sort: sort, Page: 9, PerPage: 2})
				mustNoErr(t, err)
				mustEqual(t, len(past.Items), 0)
			})
			t.Run("checkpoint "+sort, func(t *testing.T) {
				expect := names
				if sort == "" {
					expect = want["created_at:1"] // checkpoint default is creation order
				}
				var got []string
				from, rounds := "", 0
				for {
					r, err := o.List(ctx, tid, store.OrgPage{Sort: sort, Take: 2, From: from})
					mustNoErr(t, err)
					got = append(got, orgNames(r.Items)...)
					if rounds++; rounds > 5 {
						t.Fatal("checkpoint never ended")
					}
					if r.Next == "" {
						mustEqual(t, len(r.Items) > 0, true)
						break
					}
					mustEqual(t, len(r.Items), 2)
					from = r.Next
				}
				mustEqual(t, got, expect)
			})
		}
		// from alone uses the default size; page is ignored beside from.
		first, err := o.List(ctx, tid, store.OrgPage{Take: 1})
		mustNoErr(t, err)
		rest, err := o.List(ctx, tid, store.OrgPage{From: first.Next, Page: 3})
		mustNoErr(t, err)
		mustEqual(t, len(rest.Items), 4)
		mustEqual(t, rest.Next, "")
		// A cursor is bound to its tenant and sort.
		_, err = o.List(ctx, "org-b", store.OrgPage{From: first.Next})
		mustErrIs(t, err, store.ErrInvalid)
		_, err = o.List(ctx, tid, store.OrgPage{From: first.Next, Sort: "name:1"})
		mustErrIs(t, err, store.ErrInvalid)
		_, err = o.List(ctx, tid, store.OrgPage{From: "garbage"})
		mustErrIs(t, err, store.ErrInvalid)
		for _, bad := range []store.OrgPage{{Sort: "id:1"}, {Sort: "name"}, {PerPage: 101}, {Take: 101}, {Page: 1001}, {Page: -1}} {
			_, err = o.List(ctx, tid, bad)
			mustErrIs(t, err, store.ErrInvalid)
		}
		other, err := o.List(ctx, "org-b", store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, orgNames(other.Items), []string{"other"})
		empty, err := o.List(ctx, "nope", store.OrgPage{})
		mustNoErr(t, err)
		if empty.Items == nil || len(empty.Items) != 0 {
			t.Fatalf("empty list should be a non-nil empty slice: %#v", empty.Items)
		}
	})

	t.Run("Connections", func(t *testing.T) {
		s := open(t, newStore)
		orgSeed(t, s, true)
		o := s.Organizations()
		a, b := newOrg(tid, "a", ts(0)), newOrg(tid, "b", ts(1))
		mustNoErr(t, o.Create(ctx, a, nil))
		mustNoErr(t, o.Create(ctx, b, nil))
		put := func(org *store.Organization, c store.OrganizationConnection, create bool) error {
			c.TenantID, c.OrganizationID = tid, org.ID
			return o.PutConnection(ctx, c, create)
		}
		mustNoErr(t, put(a, dbConn("con1"), true))
		mustErrIs(t, put(a, dbConn("con1"), true), store.ErrConflict)
		mustErrIs(t, put(a, dbConn("con2"), false), store.ErrNotFound)
		mustErrIs(t, put(a, dbConn("missing"), true), store.ErrNotFound)
		mustErrIs(t, o.PutConnection(ctx, store.OrganizationConnection{TenantID: tid, OrganizationID: orgrules.NewID(), ConnectionID: "con1", ShowAsButton: true}, true), store.ErrNotFound)
		// Flag rules follow the connection's strategy.
		mustErrIs(t, put(a, store.OrganizationConnection{ConnectionID: "con2", ShowAsButton: true, IsSignupEnabled: true, AssignMembershipOnLogin: true}, true), store.ErrInvalid)
		mustErrIs(t, put(a, store.OrganizationConnection{ConnectionID: "con3"}, true), store.ErrInvalid)
		mustErrIs(t, put(a, store.OrganizationConnection{ConnectionID: "con1", IsSignupEnabled: true, ShowAsButton: true}, false), store.ErrInvalid)
		mustNoErr(t, put(a, store.OrganizationConnection{ConnectionID: "con2"}, true)) // enterprise may hide its button
		mustNoErr(t, put(a, store.OrganizationConnection{ConnectionID: "con1", ShowAsButton: true, AssignMembershipOnLogin: true, IsSignupEnabled: true}, false))
		got, err := o.GetConnection(ctx, tid, a.ID, "con1")
		mustNoErr(t, err)
		mustEqual(t, *got, store.OrganizationConnection{TenantID: tid, OrganizationID: a.ID, ConnectionID: "con1", ShowAsButton: true, AssignMembershipOnLogin: true, IsSignupEnabled: true})
		_, err = o.GetConnection(ctx, tid, a.ID, "con3")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = o.GetConnection(ctx, tid, orgrules.NewID(), "con1")
		mustErrIs(t, err, store.ErrNotFound)

		mustNoErr(t, put(b, dbConn("con1"), true))
		by, err := o.ConnectionsByConnection(ctx, tid, "con1")
		mustNoErr(t, err)
		ids := []string{by[0].OrganizationID, by[1].OrganizationID}
		mustEqual(t, len(by), 2)
		mustEqual(t, ids, []string{min(a.ID, b.ID), max(a.ID, b.ID)})
		none, err := o.ConnectionsByConnection(ctx, tid, "con3")
		mustNoErr(t, err)
		mustEqual(t, len(none), 0)
		cross, err := o.ConnectionsByConnection(ctx, "org-b", "con1")
		mustNoErr(t, err)
		mustEqual(t, len(cross), 0)

		page, err := o.Connections(ctx, tid, a.ID, store.OrgPage{PerPage: 1, Page: 1})
		mustNoErr(t, err)
		mustEqual(t, page.Total, 2)
		mustEqual(t, page.Items[0].ConnectionID, "con2")
		cp, err := o.Connections(ctx, tid, a.ID, store.OrgPage{Take: 1})
		mustNoErr(t, err)
		mustEqual(t, cp.Items[0].ConnectionID, "con1")
		cp, err = o.Connections(ctx, tid, a.ID, store.OrgPage{From: cp.Next})
		mustNoErr(t, err)
		mustEqual(t, cp.Items[0].ConnectionID, "con2")
		mustEqual(t, cp.Next, "")
		_, err = o.Connections(ctx, tid, orgrules.NewID(), store.OrgPage{})
		mustErrIs(t, err, store.ErrNotFound)

		mustNoErr(t, o.DeleteConnection(ctx, tid, a.ID, "con2"))
		mustNoErr(t, o.DeleteConnection(ctx, tid, a.ID, "con2")) // exists, not enabled: idempotent
		mustErrIs(t, o.DeleteConnection(ctx, tid, a.ID, "missing"), store.ErrNotFound)
		mustErrIs(t, o.DeleteConnection(ctx, tid, orgrules.NewID(), "con1"), store.ErrNotFound)
		_, err = o.GetConnection(ctx, tid, a.ID, "con2")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("Members", func(t *testing.T) {
		s := open(t, newStore)
		orgSeed(t, s, true)
		o := s.Organizations()
		a, b := newOrg(tid, "a", ts(0)), newOrg(tid, "b", ts(1))
		mustNoErr(t, o.Create(ctx, a, nil))
		mustNoErr(t, o.Create(ctx, b, nil))
		mustErrIs(t, o.AddMembers(ctx, tid, a.ID, []string{uid(3), "auth0|ghost"}), store.ErrNotFound)
		in, err := o.IsMember(ctx, tid, a.ID, uid(3))
		mustNoErr(t, err)
		mustEqual(t, in, false)
		mustErrIs(t, o.AddMembers(ctx, tid, a.ID, nil), store.ErrInvalid)
		mustErrIs(t, o.AddMembers(ctx, tid, orgrules.NewID(), []string{uid(1)}), store.ErrNotFound)
		mustNoErr(t, o.AddMembers(ctx, tid, a.ID, []string{uid(3), uid(1), uid(5), uid(3)}))
		mustNoErr(t, o.AddMembers(ctx, tid, a.ID, []string{uid(1), uid(2)})) // present members are ignored
		in, err = o.IsMember(ctx, tid, a.ID, uid(3))
		mustNoErr(t, err)
		mustEqual(t, in, true)
		in, err = o.IsMember(ctx, tid, b.ID, uid(3))
		mustNoErr(t, err)
		mustEqual(t, in, false)
		_, err = o.IsMember(ctx, tid, orgrules.NewID(), uid(3))
		mustErrIs(t, err, store.ErrNotFound)

		all, err := o.Members(ctx, tid, a.ID, store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, all.Items, []string{uid(1), uid(2), uid(3), uid(5)})
		mustEqual(t, all.Total, 4)
		pg, err := o.Members(ctx, tid, a.ID, store.OrgPage{Page: 1, PerPage: 3})
		mustNoErr(t, err)
		mustEqual(t, pg.Items, []string{uid(5)})
		var walked []string
		from := ""
		for range 4 {
			r, err := o.Members(ctx, tid, a.ID, store.OrgPage{Take: 3, From: from})
			mustNoErr(t, err)
			walked = append(walked, r.Items...)
			if from = r.Next; from == "" {
				break
			}
		}
		mustEqual(t, walked, []string{uid(1), uid(2), uid(3), uid(5)})
		_, err = o.Members(ctx, tid, orgrules.NewID(), store.OrgPage{})
		mustErrIs(t, err, store.ErrNotFound)
		_, err = o.Members(ctx, tid, a.ID, store.OrgPage{From: "garbage"})
		mustErrIs(t, err, store.ErrInvalid)

		mustNoErr(t, o.AddMembers(ctx, tid, b.ID, []string{uid(3)}))
		orgs, err := o.UserOrganizations(ctx, tid, uid(3), store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, orgNames(orgs.Items), []string{"a", "b"})
		mustEqual(t, orgs.Total, 2)
		cp, err := o.UserOrganizations(ctx, tid, uid(3), store.OrgPage{Take: 1, Sort: "name:-1"})
		mustNoErr(t, err)
		mustEqual(t, orgNames(cp.Items), []string{"b"})
		mustEqual(t, cp.Next != "", true)
		none, err := o.UserOrganizations(ctx, tid, uid(4), store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, len(none.Items), 0)
		_, err = o.UserOrganizations(ctx, tid, "auth0|ghost", store.OrgPage{})
		mustErrIs(t, err, store.ErrNotFound)

		mustNoErr(t, o.RemoveMembers(ctx, tid, a.ID, []string{uid(1), uid(4)})) // a non-member is ignored
		in, err = o.IsMember(ctx, tid, a.ID, uid(1))
		mustNoErr(t, err)
		mustEqual(t, in, false)
		mustErrIs(t, o.RemoveMembers(ctx, tid, orgrules.NewID(), []string{uid(1)}), store.ErrNotFound)
		mustErrIs(t, o.RemoveMembers(ctx, tid, a.ID, nil), store.ErrInvalid)
	})

	t.Run("MemberRoles", func(t *testing.T) {
		s := open(t, newStore)
		orgSeed(t, s, false)
		o := s.Organizations()
		a, b := newOrg(tid, "a", ts(0)), newOrg(tid, "b", ts(1))
		mustNoErr(t, o.Create(ctx, a, nil))
		mustNoErr(t, o.Create(ctx, b, nil))
		mustNoErr(t, o.AddMembers(ctx, tid, a.ID, []string{uid(1), uid(2)}))
		mustNoErr(t, o.AddMembers(ctx, tid, b.ID, []string{uid(1)}))
		// A non-member is not found for every member-role operation.
		_, err := o.MemberRoles(ctx, tid, a.ID, uid(3), store.OrgPage{})
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(3), true, []string{"r1"}), store.ErrNotFound)
		mustErrIs(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(3), false, []string{"r1"}), store.ErrNotFound)
		mustErrIs(t, o.ChangeMemberRoles(ctx, tid, orgrules.NewID(), uid(1), true, []string{"r1"}), store.ErrNotFound)
		mustErrIs(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(1), true, nil), store.ErrInvalid)
		// An unknown role assigns nothing.
		mustErrIs(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(1), true, []string{"r1", "nope"}), store.ErrNotFound)
		got, err := o.MemberRoles(ctx, tid, a.ID, uid(1), store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, len(got.Items), 0)
		mustNoErr(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(1), true, []string{"r2", "r1", "r2"}))
		mustNoErr(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(1), true, []string{"r1"}))
		mustNoErr(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(2), true, []string{"r2"}))
		mustNoErr(t, o.ChangeMemberRoles(ctx, tid, b.ID, uid(1), true, []string{"r3"}))
		got, err = o.MemberRoles(ctx, tid, a.ID, uid(1), store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, got.Items, []string{"r1", "r2"})
		mustEqual(t, got.Total, 2)
		pg, err := o.MemberRoles(ctx, tid, a.ID, uid(1), store.OrgPage{Page: 1, PerPage: 1})
		mustNoErr(t, err)
		mustEqual(t, pg.Items, []string{"r2"})
		inB, err := o.MemberRoles(ctx, tid, b.ID, uid(1), store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, inB.Items, []string{"r3"})

		rm, err := o.RoleMembers(ctx, tid, a.ID, "r2", store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, rm.Items, []string{uid(1), uid(2)})
		rm, err = o.RoleMembers(ctx, tid, a.ID, "r2", store.OrgPage{Take: 1})
		mustNoErr(t, err)
		mustEqual(t, rm.Items, []string{uid(1)})
		rm, err = o.RoleMembers(ctx, tid, a.ID, "r2", store.OrgPage{From: rm.Next})
		mustNoErr(t, err)
		mustEqual(t, rm.Items, []string{uid(2)})
		mustEqual(t, rm.Next, "")
		_, err = o.RoleMembers(ctx, tid, a.ID, "nope", store.OrgPage{})
		mustErrIs(t, err, store.ErrNotFound)
		_, err = o.RoleMembers(ctx, tid, orgrules.NewID(), "r2", store.OrgPage{})
		mustErrIs(t, err, store.ErrNotFound)

		mustNoErr(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(1), false, []string{"r1", "r3"})) // unassigned role is ignored
		got, err = o.MemberRoles(ctx, tid, a.ID, uid(1), store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, got.Items, []string{"r2"})

		// Removing the membership keeps the assignments; re-adding restores them.
		mustNoErr(t, o.RemoveMembers(ctx, tid, a.ID, []string{uid(1)}))
		_, err = o.MemberRoles(ctx, tid, a.ID, uid(1), store.OrgPage{})
		mustErrIs(t, err, store.ErrNotFound)
		rm, err = o.RoleMembers(ctx, tid, a.ID, "r2", store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, rm.Items, []string{uid(2)}) // only current members
		mustNoErr(t, o.AddMembers(ctx, tid, a.ID, []string{uid(1)}))
		got, err = o.MemberRoles(ctx, tid, a.ID, uid(1), store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, got.Items, []string{"r2"})
	})

	t.Run("Cascades", func(t *testing.T) {
		s := open(t, newStore)
		orgSeed(t, s, false)
		o := s.Organizations()
		seed := func(name string) *store.Organization {
			org := newOrg(tid, name, ts(0))
			mustNoErr(t, o.Create(ctx, org, []store.OrganizationConnection{dbConn("con1"), dbConn("con3")}))
			mustNoErr(t, o.AddMembers(ctx, tid, org.ID, []string{uid(1), uid(2)}))
			mustNoErr(t, o.ChangeMemberRoles(ctx, tid, org.ID, uid(1), true, []string{"r1", "r2"}))
			mustNoErr(t, o.ChangeMemberRoles(ctx, tid, org.ID, uid(2), true, []string{"r1"}))
			return org
		}
		keep := seed("keep")

		t.Run("organization", func(t *testing.T) {
			gone := seed("gone")
			mustNoErr(t, o.Delete(ctx, tid, gone.ID))
			mine, err := o.UserOrganizations(ctx, tid, uid(1), store.OrgPage{})
			mustNoErr(t, err)
			mustEqual(t, orgNames(mine.Items), []string{"keep"})
			by, err := o.ConnectionsByConnection(ctx, tid, "con1")
			mustNoErr(t, err)
			mustEqual(t, len(by), 1)
			// Nothing of the deleted organization reappears under a new one.
			again := newOrg(tid, "gone", ts(0))
			mustNoErr(t, o.Create(ctx, again, nil))
			mem, err := o.Members(ctx, tid, again.ID, store.OrgPage{})
			mustNoErr(t, err)
			mustEqual(t, len(mem.Items), 0)
			mustNoErr(t, o.Delete(ctx, tid, again.ID))
			kept, err := o.MemberRoles(ctx, tid, keep.ID, uid(1), store.OrgPage{})
			mustNoErr(t, err)
			mustEqual(t, kept.Items, []string{"r1", "r2"})
		})
		t.Run("role", func(t *testing.T) {
			mustNoErr(t, s.RBAC().DeleteRole(ctx, tid, "r2"))
			got, err := o.MemberRoles(ctx, tid, keep.ID, uid(1), store.OrgPage{})
			mustNoErr(t, err)
			mustEqual(t, got.Items, []string{"r1"})
			mustNoErr(t, s.RBAC().CreateRole(ctx, &store.Role{TenantID: tid, ID: "r2", Name: "Role 2"}))
			got, err = o.MemberRoles(ctx, tid, keep.ID, uid(1), store.OrgPage{})
			mustNoErr(t, err)
			mustEqual(t, got.Items, []string{"r1"})
		})
		t.Run("connection", func(t *testing.T) {
			mustNoErr(t, s.Connections().Delete(ctx, tid, "con3"))
			_, err := o.GetConnection(ctx, tid, keep.ID, "con3")
			mustErrIs(t, err, store.ErrNotFound)
			by, err := o.ConnectionsByConnection(ctx, tid, "con3")
			mustNoErr(t, err)
			mustEqual(t, len(by), 0)
			still, err := o.GetConnection(ctx, tid, keep.ID, "con1")
			mustNoErr(t, err)
			mustEqual(t, still.ConnectionID, "con1")
		})
		t.Run("user", func(t *testing.T) {
			mustNoErr(t, s.Users().Delete(ctx, tid, uid(2)))
			mem, err := o.Members(ctx, tid, keep.ID, store.OrgPage{})
			mustNoErr(t, err)
			mustEqual(t, mem.Items, []string{uid(1)})
			rm, err := o.RoleMembers(ctx, tid, keep.ID, "r1", store.OrgPage{})
			mustNoErr(t, err)
			mustEqual(t, rm.Items, []string{uid(1)})
			// A recreated user starts with no membership and no roles.
			mustNoErr(t, s.Users().Create(ctx, newUser(tid, "u2", "u2@again.test", "u2")))
			mustNoErr(t, o.AddMembers(ctx, tid, keep.ID, []string{uid(2)}))
			roles, err := o.MemberRoles(ctx, tid, keep.ID, uid(2), store.OrgPage{})
			mustNoErr(t, err)
			mustEqual(t, len(roles.Items), 0)
		})
		t.Run("connection delete removes its users", func(t *testing.T) {
			// con1's users go with it (Connections.Delete); their memberships follow.
			mustNoErr(t, s.Connections().Delete(ctx, tid, "con1"))
			mem, err := o.Members(ctx, tid, keep.ID, store.OrgPage{})
			mustNoErr(t, err)
			mustEqual(t, len(mem.Items), 0)
		})
	})

	t.Run("TenantDelete", func(t *testing.T) {
		s := open(t, newStore)
		orgSeed(t, s, true)
		o := s.Organizations()
		for _, tenant := range []string{"org-a", "org-b"} {
			org := newOrg(tenant, "acme", ts(0))
			mustNoErr(t, o.Create(ctx, org, []store.OrganizationConnection{dbConn("con1")}))
			mustNoErr(t, o.AddMembers(ctx, tenant, org.ID, []string{uid(1)}))
			mustNoErr(t, o.ChangeMemberRoles(ctx, tenant, org.ID, uid(1), true, []string{"r1"}))
		}
		mustNoErr(t, s.Tenants().Delete(ctx, "org-a"))
		res, err := o.List(ctx, "org-a", store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, len(res.Items), 0)
		by, err := o.ConnectionsByConnection(ctx, "org-a", "con1")
		mustNoErr(t, err)
		mustEqual(t, len(by), 0)
		left, err := o.List(ctx, "org-b", store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, len(left.Items), 1)
		mustNoErr(t, o.AddMembers(ctx, "org-b", left.Items[0].ID, []string{uid(1)}))
		// A recreated tenant starts empty.
		orgSeed(t, s, false)
		fresh, err := o.List(ctx, "org-a", store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, len(fresh.Items), 0)
	})

	t.Run("TxRollback", func(t *testing.T) {
		s := open(t, newStore)
		orgSeed(t, s, false)
		boom := errors.New("rollback")
		var id string
		err := s.WithTx(ctx, func(tx store.Store) error {
			org := newOrg(tid, "txorg", ts(0))
			id = org.ID
			if err := tx.Organizations().Create(ctx, org, []store.OrganizationConnection{dbConn("con1")}); err != nil {
				return err
			}
			if err := tx.Organizations().AddMembers(ctx, tid, org.ID, []string{uid(1)}); err != nil {
				return err
			}
			if err := tx.Organizations().ChangeMemberRoles(ctx, tid, org.ID, uid(1), true, []string{"r1"}); err != nil {
				return err
			}
			in, err := tx.Organizations().IsMember(ctx, tid, org.ID, uid(1))
			if err != nil || !in {
				return fmt.Errorf("not visible in transaction: %v", err)
			}
			return boom
		})
		mustErrIs(t, err, boom)
		_, err = s.Organizations().Get(ctx, tid, id)
		mustErrIs(t, err, store.ErrNotFound)
		by, err := s.Organizations().ConnectionsByConnection(ctx, tid, "con1")
		mustNoErr(t, err)
		mustEqual(t, len(by), 0)
		mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
			return tx.Organizations().Create(ctx, newOrg(tid, "committed", ts(0)), nil)
		}))
		_, err = s.Organizations().GetByName(ctx, tid, "committed")
		mustNoErr(t, err)
	})

	// The organization an authorization code or refresh token was issued for
	// survives storage, and an unbound one stays empty.
	t.Run("TokenBindings", func(t *testing.T) {
		s := open(t, newStore)
		orgSeed(t, s, false)
		bound := newAuthCode(tid, "bound")
		bound.OrganizationID = "org_abcdefghij012345"
		mustNoErr(t, s.AuthCodes().Create(ctx, bound))
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode(tid, "plain")))
		got, err := s.AuthCodes().Get(ctx, tid, "bound")
		mustNoErr(t, err)
		mustEqual(t, got.OrganizationID, "org_abcdefghij012345")
		used, err := s.AuthCodes().Consume(ctx, tid, "bound", ts(time.Second))
		mustNoErr(t, err)
		mustEqual(t, used.OrganizationID, "org_abcdefghij012345")
		got, err = s.AuthCodes().Get(ctx, tid, "plain")
		mustNoErr(t, err)
		mustEqual(t, got.OrganizationID, "")

		rt := newRefreshToken(tid, "rt1", "h1", "f1")
		rt.OrganizationID = "org_abcdefghij012345"
		mustNoErr(t, s.RefreshTokens().Create(ctx, rt))
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken(tid, "rt2", "h2", "f2")))
		for hash, want := range map[string]string{"h1": "org_abcdefghij012345", "h2": ""} {
			g, err := s.RefreshTokens().GetByTokenHash(ctx, tid, hash)
			mustNoErr(t, err)
			mustEqual(t, g.OrganizationID, want)
		}
		next := newRefreshToken(tid, "rt3", "h3", "f1")
		next.OrganizationID = "org_abcdefghij012345"
		mustNoErr(t, s.RefreshTokens().Rotate(ctx, tid, "rt1", next, ts(time.Second), 0))
		g, err := s.RefreshTokens().Get(ctx, tid, "rt3")
		mustNoErr(t, err)
		mustEqual(t, g.OrganizationID, "org_abcdefghij012345")
	})

	t.Run("Limits", func(t *testing.T) {
		s := open(t, newStore)
		setter, ok := s.(store.OrgLimitSetter)
		if !ok {
			t.Skip("store cannot override Organizations limits")
		}
		orgSeed(t, s, true)
		setter.SetOrgLimits(store.OrgLimits{OrganizationsPerTenant: 2, ConnectionsPerOrganization: 2, RolesPerMember: 2})
		o := s.Organizations()
		a, b := newOrg(tid, "a", ts(0)), newOrg(tid, "b", ts(1))
		mustNoErr(t, o.Create(ctx, a, nil))
		mustNoErr(t, o.Create(ctx, b, nil))
		mustErrIs(t, o.Create(ctx, newOrg(tid, "c", ts(2)), nil), store.ErrPrecondition)
		mustNoErr(t, o.Create(ctx, newOrg("org-b", "c", ts(2)), nil)) // the cap is per tenant
		_, err := o.GetByName(ctx, tid, "c")
		mustErrIs(t, err, store.ErrNotFound)
		mustNoErr(t, o.Delete(ctx, tid, b.ID))
		c := newOrg(tid, "c", ts(2))
		mustNoErr(t, o.Create(ctx, c, nil))

		over := newOrg(tid, "over", ts(3))
		mustNoErr(t, o.Delete(ctx, tid, c.ID))
		mustErrIs(t, o.Create(ctx, over, []store.OrganizationConnection{dbConn("con1"), {ConnectionID: "con2"}, {ConnectionID: "con3", ShowAsButton: true}}), store.ErrPrecondition)
		_, err = o.GetByName(ctx, tid, "over")
		mustErrIs(t, err, store.ErrNotFound)

		put := func(conn string) error {
			return o.PutConnection(ctx, store.OrganizationConnection{TenantID: tid, OrganizationID: a.ID, ConnectionID: conn, ShowAsButton: true}, true)
		}
		mustNoErr(t, put("con1"))
		mustNoErr(t, put("con2"))
		mustErrIs(t, put("con3"), store.ErrPrecondition)
		// Replacing an existing entry is not growth.
		mustNoErr(t, o.PutConnection(ctx, store.OrganizationConnection{TenantID: tid, OrganizationID: a.ID, ConnectionID: "con1", ShowAsButton: true, AssignMembershipOnLogin: true}, false))

		mustNoErr(t, o.AddMembers(ctx, tid, a.ID, []string{uid(1)}))
		mustNoErr(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(1), true, []string{"r1", "r2"}))
		mustErrIs(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(1), true, []string{"r3"}), store.ErrPrecondition)
		mustNoErr(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(1), true, []string{"r1"})) // already assigned
		got, err := o.MemberRoles(ctx, tid, a.ID, uid(1), store.OrgPage{})
		mustNoErr(t, err)
		mustEqual(t, got.Items, []string{"r1", "r2"})
		mustNoErr(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(1), false, []string{"r1"}))
		mustNoErr(t, o.ChangeMemberRoles(ctx, tid, a.ID, uid(1), true, []string{"r3"}))
	})
}
