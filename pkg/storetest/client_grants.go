package storetest

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newClientGrant(tenantID, id, clientID, audience string) *store.ClientGrant {
	return &store.ClientGrant{
		TenantID:    tenantID,
		ID:          id,
		ClientID:    clientID,
		Audience:    audience,
		Scopes:      []string{"read:things"},
		SubjectType: store.SubjectTypeClient,
		CreatedAt:   ts(0),
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
}
