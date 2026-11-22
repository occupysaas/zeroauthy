package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testSAMLReplay is Plan 37a (LR37a-3): each SAML assertion ID is single use
// per tenant and connection until it expires, also inside a transaction
// that rolls back, and expired entries are purged.
func testSAMLReplay(t *testing.T, factory Factory) {
	s := open(t, factory)
	ctx := context.Background()
	mustNoErr(t, s.Tenants().Create(ctx, &store.Tenant{ID: "ten_a", Name: "a"}))
	mustNoErr(t, s.Tenants().Create(ctx, &store.Tenant{ID: "ten_b", Name: "b"}))
	repo, ok := s.(store.SAMLReplayStore)
	if !ok {
		t.Fatal("missing SAML replay repository")
	}
	now := time.Now().UTC()
	exp := now.Add(time.Minute)
	mustNoErr(t, repo.UseSAMLAssertion(ctx, "ten_a", "conn", "_assertion1", exp, now))
	mustErrIs(t, repo.UseSAMLAssertion(ctx, "ten_a", "conn", "_assertion1", exp, now), store.ErrConflict)
	mustNoErr(t, repo.UseSAMLAssertion(ctx, "ten_b", "conn", "_assertion1", exp, now))
	mustNoErr(t, repo.UseSAMLAssertion(ctx, "ten_a", "other", "_assertion1", exp, now))
	mustErrIs(t, s.WithTx(ctx, func(tx store.Store) error {
		mustNoErr(t, tx.(store.SAMLReplayStore).UseSAMLAssertion(ctx, "ten_a", "conn", "_rolled_back", exp, now))
		return store.ErrConflict
	}), store.ErrConflict)
	mustNoErr(t, repo.UseSAMLAssertion(ctx, "ten_a", "conn", "_rolled_back", exp, now))
	mustErrIs(t, repo.UseSAMLAssertion(ctx, "ten_a", "conn", "_expired", now, now), store.ErrInvalid)
	mustErrIs(t, repo.UseSAMLAssertion(ctx, "ten_a", "conn", "", exp, now), store.ErrInvalid)
	// After expiry the ID may be recorded again (the assertion itself has
	// expired by then).
	later := exp.Add(time.Second)
	mustNoErr(t, repo.UseSAMLAssertion(ctx, "ten_a", "conn", "_assertion1", later.Add(time.Minute), later))
	n, err := repo.PurgeSAMLAssertions(ctx, exp.Add(time.Second), 100)
	mustNoErr(t, err)
	mustEqual(t, n, 3)
}
