package storetest

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Every outcome reference resolves within the lease's tenant. Rejection must be
// atomic even when the same outcome includes otherwise valid writes/removals.
func testEventDeliveryReferences(t *testing.T, newStore Factory) {
	for _, kind := range []string{"Failed", "Succeeded"} {
		for _, reference := range []string{"Foreign", "Missing", "Purged"} {
			t.Run(kind+reference+"Atomic", func(t *testing.T) {
				s, ctx := deliveryFixture(t, newStore)
				r := s.Events()
				now := time.Now().Add(2 * time.Second)
				mustNoErr(t, r.AppendEvents(ctx, []store.TenantEvent{{TenantID: "a", ID: "e3", Type: "user.created", Time: now, Body: []byte(`{}`)}, {TenantID: "a", ID: "e4", Type: "user.created", Time: now, Body: []byte(`{}`)}}))
				missingID := "missing"
				switch reference {
				case "Foreign":
					missingID = "foreign"
					mustNoErr(t, r.AppendEvents(ctx, []store.TenantEvent{{TenantID: "b", ID: missingID, Type: "user.created", Time: now, Body: []byte(`{}`)}}))
					if _, err := r.GetEvent(ctx, "b", missingID); err != nil {
						t.Fatal(err)
					}
				case "Purged":
					missingID = "e1"
					event, err := r.GetEvent(ctx, "a", missingID)
					mustNoErr(t, err)
					n, err := r.PurgeEvents(ctx, event.Time.Add(500*time.Millisecond), 100)
					mustNoErr(t, err)
					if n != 1 {
						t.Fatalf("purged %d events, want1", n)
					}
				}
				if _, err := r.GetEvent(ctx, "a", missingID); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("invalid reference fixture %s: %v", reference, err)
				}
				before, err := r.GetEventStream(ctx, "a", "s1")
				mustNoErr(t, err)
				deliveriesBefore, _, err := r.ListDeliveries(ctx, "a", "s1", store.DeliveryFilter{}, "", 100)
				mustNoErr(t, err)
				latest, err := r.LatestEventSeq(ctx, "a")
				mustNoErr(t, err)
				outcome := store.DeliveryOutcome{Checkpoint: latest, ConsecutiveFailures: 7, TotalFailures: 9, Disable: true}
				outcome.Failed = &store.EventDelivery{TenantID: "a", StreamID: "s1", EventID: "e3", EventType: "user.created", Status: "failed", EventTime: now, Attempts: []store.DeliveryAttempt{{Status: "failed", Timestamp: now, ErrorMessage: "new failure"}}}
				if kind == "Failed" {
					outcome.Failed.EventID = missingID
					outcome.Succeeded = []string{"e2"}
				} else {
					outcome.Succeeded = []string{"e2", missingID}
				}
				err = r.RecordEventDelivery(ctx, "a", "s1", "owner", outcome)
				if !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("%s reference %s should be missing: %v", kind, reference, err)
				}
				after, err := r.GetEventStream(ctx, "a", "s1")
				mustNoErr(t, err)
				deliveriesAfter, _, err := r.ListDeliveries(ctx, "a", "s1", store.DeliveryFilter{}, "", 100)
				mustNoErr(t, err)
				if !reflect.DeepEqual(before, after) {
					t.Fatalf("rejected outcome changed stream: before=%+v after=%+v", before, after)
				}
				if !reflect.DeepEqual(deliveriesBefore, deliveriesAfter) {
					t.Fatalf("rejected outcome changed deliveries: before=%+v after=%+v", deliveriesBefore, deliveriesAfter)
				}
			})
		}
	}
	t.Run("RejectedOutcomeCanBeCaughtInsideTransaction", func(t *testing.T) {
		s, ctx := deliveryFixture(t, newStore)
		r := s.Events()
		before, err := r.GetEventStream(ctx, "a", "s1")
		mustNoErr(t, err)
		deliveriesBefore, _, err := r.ListDeliveries(ctx, "a", "s1", store.DeliveryFilter{}, "", 100)
		mustNoErr(t, err)
		mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
			err := tx.Events().RecordEventDelivery(ctx, "a", "s1", "owner", store.DeliveryOutcome{Checkpoint: before.Checkpoint, ConsecutiveFailures: 7, TotalFailures: 9, Disable: true, Succeeded: []string{"e1", "missing"}})
			if !errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("expected missing reference, got %v", err)
			}
			// Commit the caller's transaction after handling the error. A driver
			// cannot rely on its caller rolling back partially applied outcomes.
			return nil
		}))
		after, err := r.GetEventStream(ctx, "a", "s1")
		mustNoErr(t, err)
		deliveriesAfter, _, err := r.ListDeliveries(ctx, "a", "s1", store.DeliveryFilter{}, "", 100)
		mustNoErr(t, err)
		if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(deliveriesBefore, deliveriesAfter) {
			t.Fatal("committing after a rejected outcome persisted partial changes")
		}
	})
	t.Run("SuccessTenantAndStreamIsolation", func(t *testing.T) {
		s, ctx := deliveryFixture(t, newStore)
		r := s.Events()
		now := time.Now()
		mustNoErr(t, r.AppendEvents(ctx, []store.TenantEvent{{TenantID: "b", ID: "e1", Type: "user.created", Time: now, Body: []byte(`{}`)}}))
		mustNoErr(t, r.CreateEventStream(ctx, &store.EventStream{TenantID: "a", ID: "s2", Name: "second", Status: "enabled"}))
		mustNoErr(t, r.CreateEventStream(ctx, &store.EventStream{TenantID: "b", ID: "s1", Name: "other", Status: "enabled"}))
		for _, tenant := range []string{"a", "b"} {
			sid, owner := "s2", "second-owner"
			if tenant == "b" {
				sid, owner = "s1", "other-owner"
			}
			leased, err := r.LeaseEventStream(ctx, owner, now, now.Add(time.Minute))
			mustNoErr(t, err)
			if leased.TenantID != tenant || leased.ID != sid {
				t.Fatalf("unexpected lease: %+v", leased)
			}
			event, err := r.GetEvent(ctx, tenant, "e1")
			mustNoErr(t, err)
			mustNoErr(t, r.RecordEventDelivery(ctx, tenant, sid, owner, store.DeliveryOutcome{Checkpoint: event.Seq, ConsecutiveFailures: 1, TotalFailures: 1, Failed: &store.EventDelivery{TenantID: tenant, StreamID: sid, EventID: "e1", EventType: event.Type, Status: "failed", EventTime: event.Time}}))
		}
		otherTenant, err := r.GetDelivery(ctx, "b", "s1", "e1")
		mustNoErr(t, err)
		otherStream, err := r.GetDelivery(ctx, "a", "s2", "e1")
		mustNoErr(t, err)
		tenantStream, err := r.GetEventStream(ctx, "b", "s1")
		mustNoErr(t, err)
		secondStream, err := r.GetEventStream(ctx, "a", "s2")
		mustNoErr(t, err)
		mustNoErr(t, r.RecordEventDelivery(ctx, "a", "s1", "owner", store.DeliveryOutcome{Checkpoint: 2, Succeeded: []string{"e1", "e2"}}))
		if _, err := r.GetDelivery(ctx, "a", "s1", "e1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("owned failure not removed: %v", err)
		}
		tenantAfter, err := r.GetDelivery(ctx, "b", "s1", "e1")
		mustNoErr(t, err)
		streamAfter, err := r.GetDelivery(ctx, "a", "s2", "e1")
		mustNoErr(t, err)
		if !reflect.DeepEqual(otherTenant, tenantAfter) || !reflect.DeepEqual(otherStream, streamAfter) {
			t.Fatal("successful outcome changed unrelated failure records")
		}
		tenantStreamAfter, err := r.GetEventStream(ctx, "b", "s1")
		mustNoErr(t, err)
		secondStreamAfter, err := r.GetEventStream(ctx, "a", "s2")
		mustNoErr(t, err)
		if !reflect.DeepEqual(tenantStream, tenantStreamAfter) || !reflect.DeepEqual(secondStream, secondStreamAfter) {
			t.Fatal("successful outcome changed unrelated stream counters")
		}
		// Initial successful delivery has an event but no prior failure row.
		mustNoErr(t, r.AppendEvents(ctx, []store.TenantEvent{{TenantID: "a", ID: "success-only", Type: "user.created", Time: now, Body: []byte(`{}`)}}))
		latest, err := r.LatestEventSeq(ctx, "a")
		mustNoErr(t, err)
		mustNoErr(t, r.RecordEventDelivery(ctx, "a", "s1", "owner", store.DeliveryOutcome{Checkpoint: latest, Succeeded: []string{"success-only"}}))
	})
}
