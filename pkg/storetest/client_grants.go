package storetest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newClientGrant(tenantID, id, clientID, audience string) *store.ClientGrant {
	return &store.ClientGrant{
		OrganizationUsage: "deny",
		TenantID:          tenantID,
		ID:                id,
		ClientID:          clientID,
		Audience:          audience,
		Scopes:            []string{"read:things"},
		SubjectType:       store.SubjectTypeClient,
		CreatedAt:         ts(0),
	}
}

func testClientGrants(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		s := open(t, newStore)
		want := newClientGrant("ten_a", "cg1", "c1", "https://api.test")
		mustNoErr(t, s.ClientGrants().Create(ctx, want))

		got, err := s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		mustEqual(t, got, want)

		want.Scopes = []string{"read:things", "write:things"}
		want.Origin = store.OriginAPI
		mustNoErr(t, s.ClientGrants().Update(ctx, want))
		got, err = s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		mustEqual(t, got, want)

		moved := *want
		moved.Audience = "https://other.test"
		mustErrIs(t, s.ClientGrants().Update(ctx, &moved), store.ErrConflict)

		mustNoErr(t, s.ClientGrants().Delete(ctx, "ten_a", "cg1"))
		_, err = s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test", store.SubjectTypeClient)
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.ClientGrants().Delete(ctx, "ten_a", "cg1"), store.ErrNotFound)
		mustErrIs(t, s.ClientGrants().Update(ctx, want), store.ErrNotFound)
	})

	t.Run("EmptySubjectTypeIsClient", func(t *testing.T) {
		s := open(t, newStore)
		in := newClientGrant("ten_a", "cg1", "c1", "https://api.test")
		in.SubjectType = ""
		mustNoErr(t, s.ClientGrants().Create(ctx, in))

		got, err := s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		if got.SubjectType != store.SubjectTypeClient {
			t.Fatalf("SubjectType = %q, want %q", got.SubjectType, store.SubjectTypeClient)
		}
		// It is the client grant for the pair, so a second one conflicts.
		dup := newClientGrant("ten_a", "cg2", "c1", "https://api.test")
		mustErrIs(t, s.ClientGrants().Create(ctx, dup), store.ErrConflict)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newClientGrant("ten_a", "cg1", "c1", "https://api.test")
		mustNoErr(t, s.ClientGrants().Create(ctx, in))
		in.Scopes[0] = "mutated"

		got, err := s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		mustEqual(t, got, newClientGrant("ten_a", "cg1", "c1", "https://api.test"))
		got.Scopes[0] = "mutated-again"

		again, err := s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		mustEqual(t, again, newClientGrant("ten_a", "cg1", "c1", "https://api.test"))
	})

	t.Run("Uniqueness", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.ClientGrants().Create(ctx, newClientGrant("ten_a", "cg1", "c1", "https://api.test")))
		mustErrIs(t, s.ClientGrants().Create(ctx, newClientGrant("ten_a", "cg2", "c1", "https://api.test")), store.ErrConflict)
		mustErrIs(t, s.ClientGrants().Create(ctx, newClientGrant("ten_a", "cg1", "c2", "https://api.test")), store.ErrConflict)
		mustNoErr(t, s.ClientGrants().Create(ctx, newClientGrant("ten_b", "cg1", "c1", "https://api.test")))
		_, err := s.ClientGrants().Find(ctx, "ten_c", "c1", "https://api.test", store.SubjectTypeClient)
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("SubjectTypes", func(t *testing.T) {
		s := open(t, newStore)
		cg := newClientGrant("ten_a", "cg1", "c1", "https://api.test")
		ug := newClientGrant("ten_a", "cg2", "c1", "https://api.test")
		ug.SubjectType, ug.Scopes = store.SubjectTypeUser, []string{"write:things"}
		mustNoErr(t, s.ClientGrants().Create(ctx, cg))
		mustNoErr(t, s.ClientGrants().Create(ctx, ug)) // same client and API, other subject type
		got, err := s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test", store.SubjectTypeUser)
		mustNoErr(t, err)
		mustEqual(t, got, ug)
		got, err = s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		mustEqual(t, got, cg)
		dup := newClientGrant("ten_a", "cg3", "c1", "https://api.test")
		dup.SubjectType = store.SubjectTypeUser
		mustErrIs(t, s.ClientGrants().Create(ctx, dup), store.ErrConflict)
		moved := *ug
		moved.SubjectType = store.SubjectTypeClient
		mustErrIs(t, s.ClientGrants().Update(ctx, &moved), store.ErrConflict)
	})

	t.Run("OriginRoundTrip", func(t *testing.T) {
		s := open(t, newStore)
		g := newClientGrant("ten_a", "cg1", "c1", "https://api.test")
		g.Origin = store.OriginAPI
		mustNoErr(t, s.ClientGrants().Create(ctx, g))
		mustNoErr(t, s.ClientGrants().Create(ctx, newClientGrant("ten_a", "cg2", "c2", "https://api.test")))
		got, total, err := s.ClientGrants().List(ctx, "ten_a", store.ClientGrantFilter{}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, total, 2)
		mustEqual(t, got[0].Origin, store.OriginAPI)
		mustEqual(t, got[1].Origin, "")
	})

	t.Run("AllowAllScopesRoundTrip", func(t *testing.T) {
		s := open(t, newStore)
		g := newClientGrant("ten_a", "cg1", "c1", "https://api.test")
		g.Scopes, g.AllowAllScopes = nil, true
		mustNoErr(t, s.ClientGrants().Create(ctx, g))
		got, err := s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		mustEqual(t, got.AllowAllScopes, true)
		mustEqual(t, len(got.Scopes), 0)
		got.AllowAllScopes, got.Scopes = false, []string{"a"}
		mustNoErr(t, s.ClientGrants().Update(ctx, got))
		got, err = s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		mustEqual(t, got.AllowAllScopes, false)
		mustEqual(t, got.Scopes, []string{"a"})
	})

	t.Run("List", func(t *testing.T) {
		s := open(t, newStore)
		// Created out of order, with IDs that sort differently by byte
		// order and by case-insensitive collation, and CreatedAt running
		// against the ID order: List orders by ID, byte order.
		type spec struct{ id, client, audience, subject string }
		specs := []spec{
			{"cgr_b", "c1", "https://api1", store.SubjectTypeClient},
			{"cgr_B", "c2", "https://api1", store.SubjectTypeClient},
			{"cgr_a", "c1", "https://api2", store.SubjectTypeClient},
			{"cgr_c", "c1", "https://api1", store.SubjectTypeUser},
			{"cgr_A", "c2", "https://api2", store.SubjectTypeUser},
			{"cgr_1", "c3", "https://api2", store.SubjectTypeClient},
		}
		for i, sp := range specs {
			g := newClientGrant("ten_a", sp.id, sp.client, sp.audience)
			g.SubjectType, g.CreatedAt = sp.subject, ts(time.Duration(len(specs)-i)*time.Second)
			mustNoErr(t, s.ClientGrants().Create(ctx, g))
		}
		other := newClientGrant("ten_b", "cgr_x", "c1", "https://api1")
		mustNoErr(t, s.ClientGrants().Create(ctx, other))

		ids := func(gs []*store.ClientGrant) []string {
			out := []string{}
			for _, g := range gs {
				out = append(out, g.ID)
			}
			return out
		}
		list := func(f store.ClientGrantFilter, p store.Page) ([]string, int) {
			t.Helper()
			got, total, err := s.ClientGrants().List(ctx, "ten_a", f, p)
			mustNoErr(t, err)
			return ids(got), total
		}
		check := func(name string, f store.ClientGrantFilter, p store.Page, wantIDs []string, wantTotal int) {
			t.Run(name, func(t *testing.T) {
				gotIDs, total := list(f, p)
				mustEqual(t, gotIDs, wantIDs)
				mustEqual(t, total, wantTotal)
			})
		}
		all := []string{"cgr_1", "cgr_A", "cgr_B", "cgr_a", "cgr_b", "cgr_c"}
		check("All", store.ClientGrantFilter{}, store.Page{}, all, 6)
		check("ClientID", store.ClientGrantFilter{ClientID: "c1"}, store.Page{}, []string{"cgr_a", "cgr_b", "cgr_c"}, 3)
		check("Audience", store.ClientGrantFilter{Audience: "https://api2"}, store.Page{}, []string{"cgr_1", "cgr_A", "cgr_a"}, 3)
		check("SubjectType", store.ClientGrantFilter{SubjectType: store.SubjectTypeUser}, store.Page{}, []string{"cgr_A", "cgr_c"}, 2)
		check("ClientAndAudience", store.ClientGrantFilter{ClientID: "c1", Audience: "https://api1"}, store.Page{}, []string{"cgr_b", "cgr_c"}, 2)
		check("ClientAndSubject", store.ClientGrantFilter{ClientID: "c2", SubjectType: store.SubjectTypeClient}, store.Page{}, []string{"cgr_B"}, 1)
		check("AudienceAndSubject", store.ClientGrantFilter{Audience: "https://api2", SubjectType: store.SubjectTypeClient}, store.Page{}, []string{"cgr_1", "cgr_a"}, 2)
		check("AllThree", store.ClientGrantFilter{ClientID: "c1", Audience: "https://api2", SubjectType: store.SubjectTypeClient}, store.Page{}, []string{"cgr_a"}, 1)
		check("NoMatch", store.ClientGrantFilter{ClientID: "c1", Audience: "https://api2", SubjectType: store.SubjectTypeUser}, store.Page{}, []string{}, 0)
		check("UnknownClient", store.ClientGrantFilter{ClientID: "nope"}, store.Page{Limit: 5}, []string{}, 0)
		check("FirstPage", store.ClientGrantFilter{}, store.Page{Limit: 4}, all[:4], 6)
		check("SecondPage", store.ClientGrantFilter{}, store.Page{Offset: 4, Limit: 4}, all[4:], 6)
		check("OffsetNoLimit", store.ClientGrantFilter{}, store.Page{Offset: 2}, all[2:], 6)
		check("LimitZeroIsNoLimit", store.ClientGrantFilter{}, store.Page{Offset: 0, Limit: 0}, all, 6)
		check("PageExactEnd", store.ClientGrantFilter{}, store.Page{Offset: 6, Limit: 3}, []string{}, 6)
		check("PagePastEnd", store.ClientGrantFilter{}, store.Page{Offset: 40, Limit: 3}, []string{}, 6)
		check("ByID", store.ClientGrantFilter{ID: "cgr_b"}, store.Page{}, []string{"cgr_b"}, 1)
		check("ByIDNone", store.ClientGrantFilter{ID: "cgr_x"}, store.Page{}, []string{}, 0)
		check("ByIDOtherTenant", store.ClientGrantFilter{ID: "cgr_x", ClientID: "c1"}, store.Page{}, []string{}, 0)
		check("AfterID", store.ClientGrantFilter{AfterID: "cgr_B"}, store.Page{}, all[3:], 3)
		check("AfterIDByteOrder", store.ClientGrantFilter{AfterID: "cgr_A"}, store.Page{Limit: 1}, []string{"cgr_B"}, 4)
		check("AfterLast", store.ClientGrantFilter{AfterID: "cgr_c"}, store.Page{}, []string{}, 0)
		check("AfterIDAndFilter", store.ClientGrantFilter{ClientID: "c1", AfterID: "cgr_a"}, store.Page{}, []string{"cgr_b", "cgr_c"}, 2)
		check("FilteredPage", store.ClientGrantFilter{ClientID: "c1"}, store.Page{Offset: 1, Limit: 1}, []string{"cgr_b"}, 3)
		check("LimitLargerThanRest", store.ClientGrantFilter{ClientID: "c1"}, store.Page{Offset: 2, Limit: 50}, []string{"cgr_c"}, 3)

		t.Run("TenantIsolation", func(t *testing.T) {
			got, total, err := s.ClientGrants().List(ctx, "ten_b", store.ClientGrantFilter{}, store.Page{})
			mustNoErr(t, err)
			mustEqual(t, ids(got), []string{"cgr_x"})
			mustEqual(t, total, 1)
			got, total, err = s.ClientGrants().List(ctx, "ten_none", store.ClientGrantFilter{}, store.Page{})
			mustNoErr(t, err)
			mustEqual(t, len(got), 0)
			mustEqual(t, total, 0)
		})

		t.Run("ReturnsCopies", func(t *testing.T) {
			got, _, err := s.ClientGrants().List(ctx, "ten_a", store.ClientGrantFilter{ClientID: "c3"}, store.Page{})
			mustNoErr(t, err)
			got[0].Scopes[0] = "mutated"
			again, _, err := s.ClientGrants().List(ctx, "ten_a", store.ClientGrantFilter{ClientID: "c3"}, store.Page{})
			mustNoErr(t, err)
			mustEqual(t, again[0].Scopes, []string{"read:things"})
		})
	})

	// Paging by offset through the whole list returns every grant once, in
	// ID order: the checkpoint cursors of the Management API depend on it.
	t.Run("ListWalk", func(t *testing.T) {
		s := open(t, newStore)
		const n = 23
		for i := 0; i < n; i++ {
			g := newClientGrant("ten_a", fmt.Sprintf("cgr_%02d", (i*7)%n), fmt.Sprintf("c%d", i), "https://api.test")
			mustNoErr(t, s.ClientGrants().Create(ctx, g))
		}
		var seen []string
		for off := 0; ; off += 5 {
			got, total, err := s.ClientGrants().List(ctx, "ten_a", store.ClientGrantFilter{}, store.Page{Offset: off, Limit: 5})
			mustNoErr(t, err)
			mustEqual(t, total, n)
			if len(got) == 0 {
				break
			}
			for _, g := range got {
				seen = append(seen, g.ID)
			}
		}
		mustEqual(t, len(seen), n)
		for i, id := range seen {
			mustEqual(t, id, fmt.Sprintf("cgr_%02d", i))
		}
	})
}
