package events_test

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestPurgeRetention(t *testing.T) {
	ctx, st := fixture(t)
	now := time.Now()
	for i, age := range []time.Duration{8 * 24 * time.Hour, 6 * 24 * time.Hour, 23 * time.Hour} {
		if err := st.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "ten", ID: []string{"old", "recent", "today"}[i], Time: now.Add(-age), Body: []byte(`{}`)}}); err != nil {
			t.Fatal(err)
		}
	}
	p := events.NewPurger(st, events.Config{}, nil)
	if err := p.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Events().GetEvent(ctx, "ten", "old"); err == nil {
		t.Fatal("default 7d retention kept 8d event")
	}
	if _, err := st.Events().GetEvent(ctx, "ten", "recent"); err != nil {
		t.Fatal("default removed recent event", err)
	}
	p = events.NewPurger(st, events.Config{Retention: time.Hour}, nil)
	if err := p.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Events().GetEvent(ctx, "ten", "today"); err != nil {
		t.Fatal("minimum 1d not enforced", err)
	}
}

func TestPurgeCancelled(t *testing.T) {
	_, st := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := events.NewPurger(st, events.Config{}, nil).Sweep(ctx); err == nil {
		t.Fatal("cancelled purge succeeded")
	}
}
