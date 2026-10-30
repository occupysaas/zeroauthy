package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestLogsRingRollbackAndCopies(t *testing.T) {
	s := New()
	ctx := context.Background()
	at := time.Now().UTC()
	body := []byte(`{"type":"s"}`)
	events := make([]store.LogEvent, 10000)
	for i := range events {
		events[i] = store.LogEvent{TenantID: "a", Date: at, Body: body}
	}
	if err := s.Logs().AppendLogs(ctx, events, nil); err != nil {
		t.Fatal(err)
	}
	body[0] = 'x'
	events[0].TenantID = "bad"
	first, err := s.Logs().GetLog(ctx, "a", store.FormatLogID(1))
	if err != nil || first.Body[0] != '{' {
		t.Fatalf("input alias: %v %v", first, err)
	}
	rollback := errors.New("rollback")
	err = s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "a", Date: at}}, nil); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if _, err = s.Logs().GetLog(ctx, "a", store.FormatLogID(1)); err != nil {
		t.Fatalf("eviction survived rollback: %v", err)
	}
	if err = s.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "a", Date: at}, {TenantID: "b", Date: at}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Logs().GetLog(ctx, "a", store.FormatLogID(1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("oldest not evicted: %v", err)
	}
	for tid, want := range map[string]int{"a": 10000, "b": 1} {
		_, n, err := s.Logs().SearchLogs(ctx, tid, nil, store.LogPage{PerPage: 100, IncludeTotals: true})
		if err != nil || n != want {
			t.Fatalf("tenant %s count %d err %v", tid, n, err)
		}
	}
	last, err := s.Logs().LatestLogs(ctx, "a", nil, 1, at.Add(time.Hour))
	if err != nil || len(last) != 1 || last[0].Seq != 10001 {
		t.Fatalf("counter rollback: %+v %v", last, err)
	}
}

func TestLogsCommitTimestampAndNestedRollback(t *testing.T) {
	s := New()
	ctx := context.Background()
	at := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	now := at
	s.now = func() time.Time { return now }
	var settled time.Time
	err := s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "a", Date: at}}, []store.DailyStatDelta{{TenantID: "a", Day: at, Logins: 1}}); err != nil {
			return err
		}
		rollback := errors.New("nested")
		if err := tx.WithTx(ctx, func(nested store.Store) error {
			if err := nested.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "a", Date: at}}, []store.DailyStatDelta{{TenantID: "a", Day: at, Logins: 10}}); err != nil {
				return err
			}
			return rollback
		}); !errors.Is(err, rollback) {
			return err
		}
		settled = now
		now = now.Add(time.Minute)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.Logs().LogsAfter(ctx, "a", 0, nil, 100, settled)
	if err != nil || len(rows) != 0 {
		t.Fatalf("event visible before commit: %+v %v", rows, err)
	}
	rows, err = s.Logs().LogsAfter(ctx, "a", 0, nil, 100, now)
	if err != nil || len(rows) != 1 {
		t.Fatalf("committed: %+v %v", rows, err)
	}
	stats, err := s.Logs().DailyStats(ctx, "a", at, at)
	if err != nil || len(stats) != 1 || stats[0].Logins != 1 {
		t.Fatalf("nested stats rollback: %+v %v", stats, err)
	}
}
