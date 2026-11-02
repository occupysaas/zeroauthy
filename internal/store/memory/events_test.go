package memory_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestEvents(t *testing.T) {
	storetest.RunSuites(t, func(*testing.T) store.Store { return memory.New() }, "Events")
}

func TestEventEvictionFailureCount(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := st.Events().CreateEventStream(ctx, &store.EventStream{TenantID: "t", ID: "s", Name: "s", Status: "enabled"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "old", Time: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Events().LeaseEventStream(ctx, "owner", time.Now(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.Events().RecordEventDelivery(ctx, "t", "s", "owner", store.DeliveryOutcome{TotalFailures: 1, Failed: &store.EventDelivery{TenantID: "t", StreamID: "s", EventID: "old", Status: "failed"}}); err != nil {
		t.Fatal(err)
	}
	batch := make([]store.TenantEvent, 10000)
	for i := range batch {
		batch[i] = store.TenantEvent{TenantID: "t", ID: fmt.Sprint(i), Time: time.Now()}
	}
	if err := st.Events().AppendEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}
	s, err := st.Events().GetEventStream(ctx, "t", "s")
	if err != nil {
		t.Fatal(err)
	}
	if s.TotalFailures != 0 {
		t.Fatalf("evicted failure still counted: %d", s.TotalFailures)
	}
	if _, err := st.Events().GetDelivery(ctx, "t", "s", "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestEventsRingAndCommitVisibility(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	s := memory.NewWithClock(func() time.Time { return now })
	cut := now.Add(time.Second)
	if err := s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "first", Time: now}}); err != nil {
			return err
		}
		now = now.Add(2 * time.Second)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Events().EventsAfter(ctx, "t", 0, nil, 100, cut)
	if err != nil || len(got) != 0 {
		t.Fatalf("append timestamp used instead of commit: %v %v", got, err)
	}
	got, err = s.Events().EventsAfter(ctx, "t", 0, nil, 100, now)
	if err != nil || len(got) != 1 {
		t.Fatalf("commit missing: %v %v", got, err)
	}
	es := make([]store.TenantEvent, 10001)
	for i := range es {
		es[i] = store.TenantEvent{TenantID: "t", ID: fmt.Sprint(i), Type: "user.created", Time: now, Body: []byte(`{}`)}
	}
	if err := s.Events().AppendEvents(ctx, es); err != nil {
		t.Fatal(err)
	}
	oldest, _ := s.Events().OldestEventSeq(ctx, "t")
	latest, _ := s.Events().LatestEventSeq(ctx, "t")
	if latest-oldest != 9999 {
		t.Fatalf("ring=%d..%d", oldest, latest)
	}
	if _, err := s.Events().GetEvent(ctx, "t", "first"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	es[1].Body[0] = 'x'
	e, _ := s.Events().GetEvent(ctx, "t", "1")
	if string(e.Body) != "{}" {
		t.Fatal("input body aliased")
	}
	// A clock step backwards cannot make a later sequence visible before an older one.
	now = now.Add(-time.Hour)
	if err := s.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "backwards", Time: now}}); err != nil {
		t.Fatal(err)
	}
	got, err = s.Events().EventsAfter(ctx, "t", latest, nil, 100, now)
	if err != nil || len(got) != 0 {
		t.Fatalf("clock skew bypassed ordering: %v %v", got, err)
	}
}
func TestEventsTenantDeletionCascades(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	for _, tid := range []string{"a", "b"} {
		if err := s.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}); err != nil {
			t.Fatal(err)
		}
		if err := s.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: tid, ID: "e", Time: time.Now()}}); err != nil {
			t.Fatal(err)
		}
		if err := s.Events().CreateEventStream(ctx, &store.EventStream{TenantID: tid, ID: "s", Name: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Tenants().Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Events().GetEvent(ctx, "a", "e"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	n, _ := s.Events().CountEventStreams(ctx, "a")
	if n != 0 {
		t.Fatal(n)
	}
	if _, err := s.Events().GetEvent(ctx, "b", "e"); err != nil {
		t.Fatal(err)
	}
}

func TestEventsRingEvictionRemovesDeliveries(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "first", Time: now}}))
	must(s.Events().CreateEventStream(ctx, &store.EventStream{TenantID: "t", ID: "s", Name: "s", Status: "enabled"}))
	if _, err := s.Events().LeaseEventStream(ctx, "owner", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	must(s.Events().RecordEventDelivery(ctx, "t", "s", "owner", store.DeliveryOutcome{Checkpoint: 1, Failed: &store.EventDelivery{TenantID: "t", StreamID: "s", EventID: "first", Status: "failed"}}))
	es := make([]store.TenantEvent, 10000)
	for i := range es {
		es[i] = store.TenantEvent{TenantID: "t", ID: fmt.Sprint(i), Time: now}
	}
	must(s.Events().AppendEvents(ctx, es))
	if _, err := s.Events().GetDelivery(ctx, "t", "s", "first"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delivery retained without event: %v", err)
	}
}

func TestEventEvictionWatermarkRollback(t *testing.T) {
	st := memory.New()
	ctx := t.Context()
	type purgeFloor interface {
		PurgedEventSeq(context.Context, string) (int64, error)
	}
	floor := func(repo store.Events, want int64) {
		t.Helper()
		f, ok := repo.(purgeFloor)
		if !ok {
			t.Fatal("missing tenant purge watermark")
		}
		got, err := f.PurgedEventSeq(ctx, "t")
		if err != nil || got != want {
			t.Fatalf("floor=%d want=%d err=%v", got, want, err)
		}
	}
	batch := make([]store.TenantEvent, 10000)
	for i := range batch {
		batch[i] = store.TenantEvent{TenantID: "t", ID: fmt.Sprint(i)}
	}
	if err := st.Events().AppendEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}
	floor(st.Events(), 0)
	abort := errors.New("abort")
	if err := st.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "evict"}}); err != nil {
			return err
		}
		floor(tx.Events(), batch[0].Seq)
		return abort
	}); !errors.Is(err, abort) {
		t.Fatal(err)
	}
	floor(st.Events(), 0)
	if err := st.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "evict"}}); err != nil {
		t.Fatal(err)
	}
	floor(st.Events(), batch[0].Seq)
}
