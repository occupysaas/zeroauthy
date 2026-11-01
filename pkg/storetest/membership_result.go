package storetest

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"slices"
	"testing"
)

// MembershipWriteResult checks the optional atomic insertion report without
// requiring a second existence read or changing ordinary AddMembers behavior.
func MembershipWriteResult(t *testing.T, factory Factory) {
	t.Helper()
	ctx := context.Background()
	st := open(t, factory)
	const tid = "member-result"
	mustNoErr(t, st.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}))
	org := newOrg(tid, "members", ts(0))
	mustNoErr(t, st.Organizations().Create(ctx, org, nil))
	for _, id := range []string{"u1", "u2", "u3"} {
		mustNoErr(t, st.Users().Create(ctx, newUser(tid, id, id+"@example.test", id)))
	}
	if _, ok := st.Organizations().(store.OrganizationMembershipWriter); !ok {
		t.Fatal("atomic membership result missing")
	}
	inserted, err := store.AddMembersResult(ctx, st.Organizations(), tid, org.ID, []string{"auth0|u1", "auth0|u2", "auth0|u1"})
	mustNoErr(t, err)
	if !slices.Equal(inserted, []string{"auth0|u1", "auth0|u2"}) {
		t.Fatalf("inserted=%v", inserted)
	}
	inserted, err = store.AddMembersResult(ctx, st.Organizations(), tid, org.ID, []string{"auth0|u1", "auth0|u2"})
	mustNoErr(t, err)
	if len(inserted) != 0 {
		t.Fatalf("noop inserted=%v", inserted)
	}
	inserted, err = store.AddMembersResult(ctx, st.Organizations(), tid, org.ID, []string{"auth0|u3", "auth0|missing"})
	if !errors.Is(err, store.ErrNotFound) || len(inserted) != 0 {
		t.Fatalf("failed batch inserted=%v err=%v", inserted, err)
	}
	fail := errors.New("rollback session creation")
	err = st.WithTx(ctx, func(tx store.Store) error {
		ids, err := store.AddMembersResult(ctx, tx.Organizations(), tid, org.ID, []string{"auth0|u3"})
		if err != nil {
			return err
		}
		if !slices.Equal(ids, []string{"auth0|u3"}) {
			t.Fatalf("tx inserted=%v", ids)
		}
		return fail
	})
	if !errors.Is(err, fail) {
		t.Fatal(err)
	}
	member, err := st.Organizations().IsMember(ctx, tid, org.ID, "auth0|u3")
	mustNoErr(t, err)
	if member {
		t.Fatal("rolled-back insertion survived")
	}
	// An older repository can still add members, without claiming insertion info.
	inserted, err = store.AddMembersResult(ctx, oldMembershipRepository{st.Organizations()}, tid, org.ID, []string{"auth0|u3"})
	mustNoErr(t, err)
	if len(inserted) != 0 {
		t.Fatalf("legacy repository claimed insertion: %v", inserted)
	}
	member, err = st.Organizations().IsMember(ctx, tid, org.ID, "auth0|u3")
	mustNoErr(t, err)
	if !member {
		t.Fatal("legacy fallback changed business behavior")
	}
}

type oldMembershipRepository struct{ store.Organizations }
