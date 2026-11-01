package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func testEvents(t *testing.T, newStore Factory) {
	t.Run("EventStreamFairLease", func(t *testing.T) { testEventStreamFairLease(t, newStore) })
	t.Run("EventsPurgeFailureCounters", func(t *testing.T) { testEventsPurgeFailureCounters(t, newStore) })
	for name, fn := range map[string]func(*testing.T, Factory){"EventStreamCRUDAndNameConflict": testEventStreamCRUDAndNameConflict, "EventStreamLease": testEventStreamLease, "EventDeliveriesFilterPage": testEventDeliveriesFilterPage, "QueueRedeliveryRules": testQueueRedeliveryRules, "EventsPurge": testEventsPurge, "EventsDeleteTenant": testEventsDeleteTenant, "EventDeliveryReferences": testEventDeliveryReferences} {
		t.Run(name, func(t *testing.T) { fn(t, newStore) })
	}
	t.Run("EventsAppendOrdering", func(t *testing.T) {
		s := eventsStore(t, newStore)
		ctx := context.Background()
		e := []store.TenantEvent{{TenantID: "a", ID: "e1", Type: "user.created", Time: time.Now(), Body: []byte(`{}`)}, {TenantID: "a", ID: "e2", Type: "user.updated", Time: time.Now(), Body: []byte(`{}`)}}
		if err := s.Events().AppendEvents(ctx, e); err != nil {
			t.Fatal(err)
		}
		got, err := s.Events().EventsAfter(ctx, "a", 0, nil, 10, time.Now().Add(time.Hour))
		if err != nil || len(got) != 2 || got[0].Seq >= got[1].Seq {
			t.Fatalf("%v %v", got, err)
		}
		filtered, err := s.Events().EventsAfter(ctx, "a", 0, []string{"user.updated"}, 1, time.Now().Add(time.Hour))
		mustNoErr(t, err)
		if len(filtered) != 1 || filtered[0].ID != "e2" {
			t.Fatalf("type filter: %v", filtered)
		}
		timed, err := s.Events().EventsFromTime(ctx, "a", e[1].Time, []string{"user.updated"}, 1, time.Now().Add(time.Hour))
		mustNoErr(t, err)
		if len(timed) != 1 || timed[0].ID != "e2" {
			t.Fatalf("timestamp read: %v", timed)
		}
		got[0].Body[0] = 'x'
		again, err := s.Events().GetEvent(ctx, "a", "e1")
		mustNoErr(t, err)
		if string(again.Body) != "{}" {
			t.Fatal("aliased body")
		}
	})
	t.Run("EventsTenantIsolation", func(t *testing.T) {
		s := eventsStore(t, newStore)
		ctx := context.Background()
		mustNoErr(t, s.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "a", ID: "e", Type: "user.created", Time: time.Now(), Body: []byte(`{}`)}}))
		if _, err := s.Events().GetEvent(ctx, "b", "e"); !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		got, err := s.Events().EventsAfter(ctx, "b", 0, nil, 10, time.Now().Add(time.Hour))
		if err != nil || len(got) != 0 {
			t.Fatalf("%v %v", got, err)
		}
	})
	t.Run("EventsSettled", func(t *testing.T) {
		s := eventsStore(t, newStore)
		ctx := context.Background()
		cut := time.Now().Add(-time.Second)
		if err := s.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "a", ID: "e", Type: "user.created", Body: []byte(`{}`), Time: cut.Add(-time.Hour)}}); err != nil {
			t.Fatal(err)
		}
		got, err := s.Events().EventsAfter(ctx, "a", 0, nil, 10, cut)
		mustNoErr(t, err)
		if len(got) != 0 {
			t.Fatal("unsettled event visible")
		}
		got, err = s.Events().EventsAfter(ctx, "a", 0, nil, 10, time.Now().Add(time.Hour))
		mustNoErr(t, err)
		if len(got) != 1 {
			t.Fatal(got)
		}
		next, err := s.Events().EventsAfter(ctx, "a", got[0].Seq, nil, 10, time.Now().Add(time.Hour))
		mustNoErr(t, err)
		if len(next) != 0 {
			t.Fatal("duplicate")
		}
	})
	t.Run("EventsRollback", func(t *testing.T) {
		s := eventsStore(t, newStore)
		ctx := context.Background()
		abort := errors.New("abort")
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "a", ID: "e", Type: "user.created", Time: time.Now(), Body: []byte(`{}`)}}); err != nil {
				return err
			}
			return abort
		})
		if !errors.Is(err, abort) {
			t.Fatal(err)
		}
		seq, readErr := s.Events().LatestEventSeq(ctx, "a")
		mustNoErr(t, readErr)
		if seq != 0 {
			t.Fatal(seq)
		}
	})
}

func testEventStreamFairLease(t *testing.T, newStore Factory) {
	s := eventsStore(t, newStore)
	ctx := context.Background()
	r := s.Events()
	now := time.Now().UTC()
	until := now.Add(time.Minute)
	for _, tid := range []string{"a", "b"} {
		mustNoErr(t, r.CreateEventStream(ctx, &store.EventStream{TenantID: tid, ID: "s", Name: "s", Status: "enabled"}))
		mustNoErr(t, r.AppendEvents(ctx, []store.TenantEvent{{TenantID: tid, ID: "e", Type: "user.created", Time: now, Body: []byte(`{}`)}}))
	}
	// No checkpoints advance, so both streams remain due throughout all turns.
	// Identical input times exercise the persisted nanosecond tie breaker.
	for i, tid := range []string{"a", "b", "a", "b", "a", "b"} {
		leased, err := r.LeaseEventStream(ctx, "worker", now, until)
		mustNoErr(t, err)
		if leased.TenantID != tid {
			t.Fatalf("turn %d leased %s, want %s", i, leased.TenantID, tid)
		}
		want := until.Add(time.Duration(i/2) * time.Nanosecond)
		if !leased.LeaseUntil.Equal(want) {
			t.Fatalf("turn %d expiry=%s, want %s", i, leased.LeaseUntil, want)
		}
		persisted, err := r.GetEventStream(ctx, tid, "s")
		mustNoErr(t, err)
		if !persisted.LeaseUntil.Equal(leased.LeaseUntil) {
			t.Fatal("returned expiry differs from stored expiry")
		}
	}
	if _, err := r.LeaseEventStream(ctx, "other", now, until); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("another worker stole a live lease", err)
	}
	// Once expired, the next owner can take over; the prior owner cannot record.
	newNow := now.Add(2 * time.Minute)
	stolen, err := r.LeaseEventStream(ctx, "other", newNow, newNow.Add(time.Minute))
	mustNoErr(t, err)
	if stolen.TenantID != "a" || stolen.LeaseOwner != "other" {
		t.Fatalf("takeover=%+v", stolen)
	}
	if err := r.RecordEventDelivery(ctx, "a", "s", "worker", store.DeliveryOutcome{}); !errors.Is(err, store.ErrPrecondition) {
		t.Fatal("stale owner recorded", err)
	}
	// A never-leased disabled stream is eligible only after redelivery is queued.
	disabled := &store.EventStream{TenantID: "a", ID: "disabled", Name: "disabled", Status: "disabled", LeaseOwner: "seed", LeaseUntil: until}
	mustNoErr(t, r.CreateEventStream(ctx, disabled))
	mustNoErr(t, r.RecordEventDelivery(ctx, "a", "disabled", "seed", store.DeliveryOutcome{TotalFailures: 1, Failed: &store.EventDelivery{TenantID: "a", StreamID: "disabled", EventID: "e", Status: "failed"}}))
	_, err = r.QueueRedelivery(ctx, "a", "disabled", []string{"e"}, nil)
	mustNoErr(t, err)
	disabled, err = r.GetEventStream(ctx, "a", "disabled")
	mustNoErr(t, err)
	disabled.LeaseOwner, disabled.LeaseUntil = "", time.Time{}
	mustNoErr(t, r.UpdateEventStream(ctx, disabled, disabled.Version))
	queued, err := r.LeaseEventStream(ctx, "worker", now, until)
	mustNoErr(t, err)
	if queued.ID != "disabled" || queued.Status != "disabled" {
		t.Fatalf("queued disabled stream did not get its fair turn: %+v", queued)
	}
	mustNoErr(t, r.RecordEventDelivery(ctx, "a", "disabled", "worker", store.DeliveryOutcome{Succeeded: []string{"e"}}))
	eligible, err := r.LeaseEventStream(ctx, "worker", now, until)
	mustNoErr(t, err)
	if eligible.TenantID != "b" || eligible.ID != "s" {
		t.Fatalf("disabled stream without queue remained eligible: %+v", eligible)
	}
	// A maximum representable expiry cannot be advanced; fail without changing
	// ownership/state rather than wrapping or truncating the persisted timestamp.
	for _, tid := range []string{"a", "b"} {
		stream, err := r.GetEventStream(ctx, tid, "s")
		mustNoErr(t, err)
		stream.Status = "disabled"
		mustNoErr(t, r.UpdateEventStream(ctx, stream, stream.Version))
	}
	maximum := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	mustNoErr(t, r.CreateEventStream(ctx, &store.EventStream{TenantID: "b", ID: "maximum", Name: "maximum", Status: "enabled", LeaseOwner: "worker", LeaseUntil: maximum}))
	if _, err := r.LeaseEventStream(ctx, "worker", now, until); !errors.Is(err, store.ErrInvalid) {
		t.Fatal("maximum-time renewal did not fail safely", err)
	}
	unchanged, err := r.GetEventStream(ctx, "b", "maximum")
	mustNoErr(t, err)
	if unchanged.LeaseOwner != "worker" || !unchanged.LeaseUntil.Equal(maximum) {
		t.Fatal("overflow changed stored lease")
	}
}

func testEventsPurgeFailureCounters(t *testing.T, newStore Factory) {
	s := eventsStore(t, newStore)
	ctx := context.Background()
	r := s.Events()
	now := time.Now()
	for _, tid := range []string{"a", "b"} {
		stream := &store.EventStream{TenantID: tid, ID: "s", Name: "s", Status: "enabled"}
		mustNoErr(t, r.CreateEventStream(ctx, stream))
		for _, id := range []string{"old", "new"} {
			at := now
			if tid == "a" && id == "old" {
				at = now.Add(-8 * 24 * time.Hour)
			}
			mustNoErr(t, r.AppendEvents(ctx, []store.TenantEvent{{TenantID: tid, ID: id, Time: at, Body: []byte(`{}`)}}))
		}
	}
	for i, tid := range []string{"a", "b"} {
		leased, err := r.LeaseEventStream(ctx, tid, now, now.Add(time.Minute))
		mustNoErr(t, err)
		if leased.TenantID != tid {
			t.Fatalf("lease %d: %+v", i, leased)
		}
		for j, id := range []string{"old", "new"} {
			mustNoErr(t, r.RecordEventDelivery(ctx, tid, "s", tid, store.DeliveryOutcome{ConsecutiveFailures: j + 1, TotalFailures: j + 1, Failed: &store.EventDelivery{TenantID: tid, StreamID: "s", EventID: id, Status: "failed"}}))
		}
	}
	abort := errors.New("abort purge")
	err := s.WithTx(ctx, func(tx store.Store) error {
		n, err := tx.Events().PurgeEvents(ctx, now.Add(-7*24*time.Hour), 1)
		if err != nil {
			return err
		}
		if n != 1 {
			t.Fatalf("purged=%d", n)
		}
		a, err := tx.Events().GetEventStream(ctx, "a", "s")
		if err != nil {
			return err
		}
		if a.TotalFailures != 1 {
			t.Fatalf("in-tx failure count=%d, want 1", a.TotalFailures)
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	a, err := r.GetEventStream(ctx, "a", "s")
	mustNoErr(t, err)
	if a.TotalFailures != 2 {
		t.Fatalf("rollback count=%d", a.TotalFailures)
	}
	n, err := r.PurgeEvents(ctx, now.Add(-7*24*time.Hour), 1)
	mustNoErr(t, err)
	if n != 1 {
		t.Fatalf("purged=%d", n)
	}
	a, err = r.GetEventStream(ctx, "a", "s")
	mustNoErr(t, err)
	b, err := r.GetEventStream(ctx, "b", "s")
	mustNoErr(t, err)
	if a.TotalFailures != 1 || b.TotalFailures != 2 {
		t.Fatalf("counts a=%d b=%d", a.TotalFailures, b.TotalFailures)
	}
	if a.ConsecutiveFailures != 2 || b.ConsecutiveFailures != 2 || a.Version != 4 || b.Version != 3 {
		t.Fatalf("purge changed streak or failed to fence counters: a=%+v b=%+v", a, b)
	}
	if _, err := r.GetDelivery(ctx, "a", "s", "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("purged failure retained", err)
	}
	if _, err := r.GetDelivery(ctx, "b", "s", "old"); err != nil {
		t.Fatal("foreign tenant failure removed", err)
	}
	n, err = r.PurgeEvents(ctx, now.Add(-7*24*time.Hour), 1)
	mustNoErr(t, err)
	if n != 0 {
		t.Fatal(n)
	}
	a, err = r.GetEventStream(ctx, "a", "s")
	mustNoErr(t, err)
	if a.TotalFailures != 1 {
		t.Fatal("second sweep decremented again")
	}
}

func eventStreamFixture(t *testing.T, newStore Factory) (store.Store, context.Context, *store.EventStream) {
	t.Helper()
	s := eventsStore(t, newStore)
	ctx := context.Background()
	now := time.Now()
	stream := &store.EventStream{TenantID: "a", ID: "s1", Name: "stream", Status: "enabled", Subscriptions: []string{"user.created"}, Config: map[string]any{"nested": map[string]any{"value": "original"}}, SealedSecret: []byte("secret"), CreatedAt: now, UpdatedAt: now}
	if err := s.Events().CreateEventStream(ctx, stream); err != nil {
		t.Fatal(err)
	}
	if err := s.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "a", ID: "e1", Type: "user.created", Time: now, Body: []byte(`{}`)}, {TenantID: "a", ID: "e2", Type: "user.updated", Time: now.Add(time.Second), Body: []byte(`{}`)}}); err != nil {
		t.Fatal(err)
	}
	return s, ctx, stream
}
func testEventStreamCRUDAndNameConflict(t *testing.T, newStore Factory) {
	s, ctx, v := eventStreamFixture(t, newStore)
	r := s.Events()
	dup := *v
	dup.ID = "s2"
	if err := r.CreateEventStream(ctx, &dup); !errors.Is(err, store.ErrConflict) {
		t.Fatal(err)
	}
	dup.TenantID = "b"
	if err := r.CreateEventStream(ctx, &dup); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetEventStream(ctx, "b", "s1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	v.Config["nested"].(map[string]any)["value"] = "mutated"
	v.SealedSecret[0] = 'X'
	got, err := r.GetEventStream(ctx, "a", "s1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Config["nested"].(map[string]any)["value"] != "original" || string(got.SealedSecret) != "secret" {
		t.Fatal("aliased create")
	}
	version := got.Version
	got.Name = "renamed"
	if err := r.UpdateEventStream(ctx, got, version); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateEventStream(ctx, got, version); !errors.Is(err, store.ErrConflict) {
		t.Fatal(err)
	}
	list, next, err := r.ListEventStreams(ctx, "a", "", 1)
	if err != nil || len(list) != 1 || next != "" {
		t.Fatalf("%v %q %v", list, next, err)
	}
	n, err := r.CountEventStreams(ctx, "a")
	if err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	extra := *got
	extra.ID = "s3"
	extra.Name = "second"
	mustNoErr(t, r.CreateEventStream(ctx, &extra))
	first, cursor, err := r.ListEventStreams(ctx, "a", "", 1)
	mustNoErr(t, err)
	second, end, err := r.ListEventStreams(ctx, "a", cursor, 1)
	mustNoErr(t, err)
	if len(first) != 1 || len(second) != 1 || cursor == "" || end != "" || first[0].ID == second[0].ID {
		t.Fatalf("bad stream pages: %v %v %q %q", first, second, cursor, end)
	}
	if err := r.DeleteEventStream(ctx, "a", "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetEventStream(ctx, "a", "s1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
}
func testEventStreamLease(t *testing.T, newStore Factory) {
	s, ctx, _ := eventStreamFixture(t, newStore)
	r := s.Events()
	now := time.Now()
	lease, err := r.LeaseEventStream(ctx, "owner1", now, now.Add(time.Minute))
	if err != nil || lease.LeaseOwner != "owner1" {
		t.Fatalf("%v %v", lease, err)
	}
	if _, err := r.LeaseEventStream(ctx, "owner2", now, now.Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := r.LeaseEventStream(ctx, "owner2", now.Add(2*time.Minute), now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordEventDelivery(ctx, "a", "s1", "owner1", store.DeliveryOutcome{}); !errors.Is(err, store.ErrPrecondition) {
		t.Fatal(err)
	}
	if err := r.RecordEventDelivery(ctx, "a", "s1", "owner2", store.DeliveryOutcome{Checkpoint: 2, ConsecutiveFailures: 1, TotalFailures: 1, Disable: true}); err != nil {
		t.Fatal(err)
	}
	v, readErr := r.GetEventStream(ctx, "a", "s1")
	mustNoErr(t, readErr)
	if v.Status != "disabled" || v.ConsecutiveFailures != 1 || v.TotalFailures != 1 || v.Checkpoint != 2 {
		t.Fatal(v)
	}
}
func deliveryFixture(t *testing.T, newStore Factory) (store.Store, context.Context) {
	t.Helper()
	s, ctx, _ := eventStreamFixture(t, newStore)
	now := time.Now()
	_, err := s.Events().LeaseEventStream(ctx, "owner", now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"e1", "e2"} {
		e, err := s.Events().GetEvent(ctx, "a", id)
		if err != nil {
			t.Fatal(err)
		}
		d := &store.EventDelivery{TenantID: "a", StreamID: "s1", EventID: id, EventType: e.Type, Status: "failed", EventTime: e.Time, Attempts: []store.DeliveryAttempt{{Status: "failed", Timestamp: now, ErrorMessage: "timeout"}}}
		if err := s.Events().RecordEventDelivery(ctx, "a", "s1", "owner", store.DeliveryOutcome{Checkpoint: int64(i + 1), Failed: d, ConsecutiveFailures: i + 1, TotalFailures: i + 1}); err != nil {
			t.Fatal(err)
		}
	}
	return s, ctx
}
func testEventDeliveriesFilterPage(t *testing.T, newStore Factory) {
	s, ctx := deliveryFixture(t, newStore)
	r := s.Events()
	out, next, err := r.ListDeliveries(ctx, "a", "s1", store.DeliveryFilter{}, "", 1)
	if err != nil || len(out) != 1 || next == "" {
		t.Fatalf("%v %q %v", out, next, err)
	}
	out2, next2, err := r.ListDeliveries(ctx, "a", "s1", store.DeliveryFilter{}, next, 1)
	if err != nil || len(out2) != 1 || next2 != "" || out2[0].EventID == out[0].EventID {
		t.Fatalf("%v %q %v", out2, next2, err)
	}
	out[0].Attempts[0].ErrorMessage = "mutated"
	d, readErr := r.GetDelivery(ctx, "a", "s1", out[0].EventID)
	mustNoErr(t, readErr)
	if d.Attempts[0].ErrorMessage != "timeout" {
		t.Fatal("aliased attempts")
	}
	got, _, err := r.ListDeliveries(ctx, "a", "s1", store.DeliveryFilter{EventTypes: []string{"user.created"}, Statuses: []string{"failed"}, From: d.EventTime, To: d.EventTime.Add(time.Second)}, "", 100)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := r.GetDelivery(ctx, "b", "s1", "e1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
}
func testQueueRedeliveryRules(t *testing.T, newStore Factory) {
	s, ctx := deliveryFixture(t, newStore)
	r := s.Events()
	n, err := r.QueueRedelivery(ctx, "a", "s1", []string{"e1", "missing"}, nil)
	if n != 0 || !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("%d %v", n, err)
	}
	queued, err := r.QueuedDeliveries(ctx, "a", "s1", 100)
	if err != nil || len(queued) != 0 {
		t.Fatalf("partial queue: %v %v", queued, err)
	}
	n, err = r.QueueRedelivery(ctx, "a", "s1", []string{"e1"}, nil)
	if err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := r.QueueRedelivery(ctx, "a", "s1", nil, &store.DeliveryFilter{}); !errors.Is(err, store.ErrPrecondition) {
		t.Fatal(err)
	}
	queued, err = r.QueuedDeliveries(ctx, "a", "s1", 100)
	mustNoErr(t, err)
	if len(queued) != 1 || queued[0].EventID != "e1" {
		t.Fatal(queued)
	}
	if err := r.RecordEventDelivery(ctx, "a", "s1", "owner", store.DeliveryOutcome{Checkpoint: 2, Succeeded: []string{"e1"}, TotalFailures: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetDelivery(ctx, "a", "s1", "e1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	v, readErr := r.GetEventStream(ctx, "a", "s1")
	mustNoErr(t, readErr)
	if v.ConsecutiveFailures != 0 || v.TotalFailures != 2 {
		t.Fatal(v)
	}
}
func testEventsPurge(t *testing.T, newStore Factory) {
	s, ctx := deliveryFixture(t, newStore)
	r := s.Events()
	n, err := r.PurgeEvents(ctx, time.Now().Add(time.Hour), 1)
	if err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	got, readErr := r.EventsAfter(ctx, "a", 0, nil, 100, time.Now().Add(time.Hour))
	mustNoErr(t, readErr)
	if len(got) != 1 {
		t.Fatal(got)
	}
	deliveries, _, readErr := r.ListDeliveries(ctx, "a", "s1", store.DeliveryFilter{}, "", 100)
	mustNoErr(t, readErr)
	if len(deliveries) != 1 || deliveries[0].EventID != got[0].ID {
		t.Fatal(deliveries)
	}
}
func testEventsDeleteTenant(t *testing.T, newStore Factory) {
	s, ctx := deliveryFixture(t, newStore)
	r := s.Events()
	if err := r.AppendEvents(ctx, []store.TenantEvent{{TenantID: "b", ID: "e1", Time: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteTenantEvents(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	seq, readErr := r.LatestEventSeq(ctx, "a")
	mustNoErr(t, readErr)
	n, readErr := r.CountEventStreams(ctx, "a")
	mustNoErr(t, readErr)
	if seq != 0 || n != 0 {
		t.Fatalf("seq=%d count=%d", seq, n)
	}
	if _, err := r.GetDelivery(ctx, "a", "s1", "e1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := r.GetEvent(ctx, "b", "e1"); err != nil {
		t.Fatal(err)
	}
}

func eventsStore(t *testing.T, f Factory) store.Store {
	t.Helper()
	s := open(t, f)
	for _, id := range []string{"a", "b"} {
		mustNoErr(t, s.Tenants().Create(context.Background(), &store.Tenant{ID: id, Name: id, CanonicalHost: id + ".example"}))
	}
	return s
}
