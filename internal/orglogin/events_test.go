package orglogin

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type eventRecorder struct{ events []logs.Event }

func (c *eventRecorder) Record(_ context.Context, e logs.Event) { c.events = append(c.events, e) }
func TestInvitationEvents(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{true: "fi", false: "si"}[failed], func(t *testing.T) {
			st, in := acceptanceFixture(t)
			c := &eventRecorder{}
			in.Recorder = c
			if failed {
				in.UserID = "wrong"
			}
			_, err := AcceptInvitation(context.Background(), st, in)
			if (err != nil) != failed {
				t.Fatal(err)
			}
			if len(c.events) == 0 {
				t.Fatal("no event")
			}
			if !failed {
				if len(c.events) != 2 || c.events[0].Type != "organization_member_added" || c.events[0].ClientID != in.ClientID || c.events[0].UserID != in.UserID || c.events[0].ConnectionID != in.PrimaryConnectionID || c.events[0].Strategy != "auth0" {
					t.Fatalf("actual added member event=%+v", c.events)
				}
			}
			got := c.events[len(c.events)-1]
			want := "si"
			if failed {
				want = "fi"
			}
			if got.Type != want || got.ClientID != in.ClientID || got.OrganizationID != in.OrganizationID || got.UserID != in.UserID || got.Description == "" {
				t.Fatalf("event=%+v", got)
			}
		})
	}
}

func TestMembershipEventsCommitAndRollback(t *testing.T) {
	for _, rollback := range []bool{true, false} {
		t.Run(map[bool]string{true: "rollback", false: "commit"}[rollback], func(t *testing.T) {
			st, in := acceptanceFixture(t)
			capture := &eventRecorder{}
			ctx := logs.WithRecorder(context.Background(), capture)
			org, err := st.Organizations().Get(ctx, in.TenantID, in.OrganizationID)
			if err != nil {
				t.Fatal(err)
			}
			link, err := st.Organizations().GetConnection(ctx, in.TenantID, in.OrganizationID, in.PrimaryConnectionID)
			if err != nil {
				t.Fatal(err)
			}
			link.AssignMembershipOnLogin = true
			if err := st.Organizations().PutConnection(ctx, *link, false); err != nil {
				t.Fatal(err)
			}
			failed := errors.New("later session write failed")
			err = WithMembershipEvents(ctx, st, func(ctx context.Context, tx store.Store) error {
				if err := EnsureMembership(ctx, tx, Context{Org: org}, in.UserID, in.PrimaryConnectionID); err != nil {
					return err
				}
				if len(capture.events) != 0 {
					t.Fatal("event published before transaction commit")
				}
				if rollback {
					return failed
				}
				return nil
			})
			if rollback {
				if !errors.Is(err, failed) || len(capture.events) != 0 {
					t.Fatalf("rollback=%v events=%v", err, capture.events)
				}
				return
			}
			if err != nil || len(capture.events) != 1 {
				t.Fatalf("commit=%v events=%v", err, capture.events)
			}
			got := capture.events[0]
			if got.Type != "organization_member_added" || got.UserID != in.UserID || got.OrganizationID != in.OrganizationID || got.ConnectionID != in.PrimaryConnectionID {
				t.Fatalf("event=%+v", got)
			}
			err = WithMembershipEvents(ctx, st, func(ctx context.Context, tx store.Store) error {
				return EnsureMembership(ctx, tx, Context{Org: org}, in.UserID, in.PrimaryConnectionID)
			})
			if err != nil || len(capture.events) != 1 {
				t.Fatalf("existing membership duplicated event: %v %+v", err, capture.events)
			}
		})
	}
}

func TestExistingInvitationMemberHasNoAddedEvent(t *testing.T) {
	st, in := acceptanceFixture(t)
	capture := &eventRecorder{}
	in.Recorder = capture
	if err := st.Organizations().AddMembers(context.Background(), in.TenantID, in.OrganizationID, []string{in.UserID}); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptInvitation(context.Background(), st, in); err != nil {
		t.Fatal(err)
	}
	if len(capture.events) != 1 || capture.events[0].Type != "si" {
		t.Fatalf("existing member generated addition: %+v", capture.events)
	}
	if _, err := AcceptInvitation(context.Background(), st, in); err != nil {
		t.Fatal(err)
	}
	if len(capture.events) != 1 {
		t.Fatalf("receipt replay generated event: %+v", capture.events)
	}
}
