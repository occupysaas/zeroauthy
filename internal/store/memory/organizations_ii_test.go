package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// Active reads must use the store clock, and transaction views share that clock.
func TestOrganizationsIIActiveReadClock(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	s := memory.NewWithClock(func() time.Time { return now })
	defer s.Close()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
	must(s.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "c"}))
	o := &store.Organization{TenantID: "t", ID: orgrules.NewID(), Name: "clock"}
	must(s.Organizations().Create(ctx, o, nil))
	in := &store.OrganizationInvitation{TenantID: "t", OrganizationID: o.ID, ID: "uinv_clock", ClientID: "c", TicketHash: "hash", WrappedTicket: []byte("sealed"), ExpiresAt: now.Add(time.Hour)}
	must(s.OrganizationsII().CreateInvitation(ctx, in))
	if !in.CreatedAt.Equal(now) {
		t.Fatalf("creation clock %s", in.CreatedAt)
	}
	must(s.WithTx(ctx, func(tx store.Store) error { _, e := tx.OrganizationsII().FindInvitation(ctx, "t", "hash"); return e }))
	now = in.ExpiresAt.Add(-time.Nanosecond)
	if _, e := s.OrganizationsII().GetInvitation(ctx, "t", o.ID, in.ID); e != nil {
		t.Fatal("early expiry", e)
	}
	now = in.ExpiresAt
	for _, read := range []func(store.Store) error{
		func(st store.Store) error {
			_, e := st.OrganizationsII().GetInvitation(ctx, "t", o.ID, in.ID)
			return e
		},
		func(st store.Store) error { _, e := st.OrganizationsII().FindInvitation(ctx, "t", "hash"); return e },
	} {
		if e := read(s); !errors.Is(e, store.ErrNotFound) {
			t.Fatalf("exact expiry %v", e)
		}
		must(s.WithTx(ctx, func(tx store.Store) error {
			if e := read(tx); !errors.Is(e, store.ErrNotFound) {
				t.Fatalf("transaction expiry %v", e)
			}
			return nil
		}))
	}
	page, e := s.OrganizationsII().ListInvitations(ctx, "t", o.ID, store.OrgPage{})
	must(e)
	if len(page.Items) != 0 {
		t.Fatal("expired active list")
	}
}
