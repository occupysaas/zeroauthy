package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

// Stream inputs may contain typed JSON values; compare their JSON meaning rather
// than assuming a particular Go representation after storage normalization.
func typedLogSink() map[string]any {
	return map[string]any{"items": []string{"original"}, "nested": map[string]string{"value": "original"}, "headers": []map[string]string{{"header": "X-Name", "value": "original"}}, "number": json.Number("9007199254740993")}
}
func mutateLogSink(sink map[string]any) {
	switch items := sink["items"].(type) {
	case []string:
		items[0] = "changed"
	case []any:
		items[0] = "changed"
	}
	switch nested := sink["nested"].(type) {
	case map[string]string:
		nested["value"] = "changed"
	case map[string]any:
		nested["value"] = "changed"
	}
	switch headers := sink["headers"].(type) {
	case []map[string]string:
		headers[0]["value"] = "changed"
	case []any:
		headers[0].(map[string]any)["value"] = "changed"
	}
}
func assertOriginalLogSink(t *testing.T, s store.Store) {
	t.Helper()
	got, err := s.Logs().GetLogStream(context.Background(), "a", "s")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := json.Marshal(got.Sink)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(typedLogSink())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("stored sink changed or lost JSON precision:\n got %s\nwant %s", actual, expected)
	}
}
func TestLogsStreamTypedSinkCopies(t *testing.T) {
	for _, boundary := range []string{"create input", "get output", "list output", "lease output", "update input", "snapshot rollback"} {
		t.Run(boundary, func(t *testing.T) {
			s := New()
			ctx := context.Background()
			input := &store.LogStream{TenantID: "a", ID: "s", Type: "http", Status: "active", Sink: typedLogSink()}
			if err := s.Logs().CreateLogStream(ctx, input); err != nil {
				t.Fatal(err)
			}
			switch boundary {
			case "create input":
				mutateLogSink(input.Sink)
			case "get output":
				got, err := s.Logs().GetLogStream(ctx, "a", "s")
				if err != nil {
					t.Fatal(err)
				}
				mutateLogSink(got.Sink)
			case "list output":
				got, err := s.Logs().ListLogStreams(ctx, "a")
				if err != nil {
					t.Fatal(err)
				}
				mutateLogSink(got[0].Sink)
			case "lease output":
				now := time.Now()
				got, err := s.Logs().LeaseLogStream(ctx, "lease", now, now.Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				mutateLogSink(got.Sink)
			case "update input":
				got, err := s.Logs().GetLogStream(ctx, "a", "s")
				if err != nil {
					t.Fatal(err)
				}
				got.Sink = typedLogSink()
				if err := s.Logs().UpdateLogStream(ctx, got, got.Version); err != nil {
					t.Fatal(err)
				}
				mutateLogSink(got.Sink)
			case "snapshot rollback":
				rollback := errors.New("rollback")
				err := s.WithTx(ctx, func(tx store.Store) error {
					got, err := tx.Logs().GetLogStream(ctx, "a", "s")
					if err != nil {
						return err
					}
					mutateLogSink(got.Sink)
					got.Name = "temporary"
					if err := tx.Logs().UpdateLogStream(ctx, got, got.Version); err != nil {
						return err
					}
					return rollback
				})
				if !errors.Is(err, rollback) {
					t.Fatal(err)
				}
			}
			assertOriginalLogSink(t, s)
		})
	}
}

func TestLogsStreamRejectsInvalidSink(t *testing.T) {
	type typedMap map[string]any
	cyclic := typedMap{}
	cyclic["self"] = cyclic
	nativeMap := map[string]any{}
	nativeMap["self"] = nativeMap
	nativeSlice := make([]any, 1)
	nativeSlice[0] = nativeSlice
	for name, value := range map[string]any{"cycle": cyclic, "native map cycle": nativeMap, "native slice cycle": nativeSlice, "channel": make(chan int), "function": func() {}, "nonfinite": math.NaN(), "invalid JSON": json.RawMessage(`{"bad":`), "invalid number": json.Number("invalid")} {
		t.Run(name, func(t *testing.T) {
			s := New()
			ctx := context.Background()
			bad := &store.LogStream{TenantID: "a", ID: "bad", Type: "http", Status: "active", Sink: map[string]any{"bad": value}}
			if err := s.Logs().CreateLogStream(ctx, bad); !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("create invalid sink: %v", err)
			}
			if _, err := s.Logs().GetLogStream(ctx, "a", "bad"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("invalid create persisted: %v", err)
			}
			good := &store.LogStream{TenantID: "a", ID: "s", Type: "http", Status: "active", Sink: typedLogSink()}
			if err := s.Logs().CreateLogStream(ctx, good); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			leased, err := s.Logs().LeaseLogStream(ctx, "owner", now, now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			leased.Sink = bad.Sink
			if err := s.Logs().UpdateLogStream(ctx, leased, leased.Version); !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("update invalid sink: %v", err)
			}
			fresh, err := s.Logs().GetLogStream(ctx, "a", "s")
			if err != nil {
				t.Fatal(err)
			}
			if fresh.Version != leased.Version || fresh.LeaseOwner != "owner" {
				t.Fatal("invalid update changed version/lease")
			}
			assertOriginalLogSink(t, s)
		})
	}
}

func TestLogsBackwardsClockCheckpoint(t *testing.T) {
	for _, transaction := range []bool{false, true} {
		t.Run(fmt.Sprint(transaction), func(t *testing.T) {
			s := New()
			ctx := context.Background()
			base := time.Now().UTC()
			now := base.Add(10 * time.Second)
			s.now = func() time.Time { return now }
			appendBatch := func() error { return s.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "t", Date: base}}, nil) }
			if err := appendBatch(); err != nil {
				t.Fatal(err)
			}
			now = base
			var err error
			if transaction {
				err = s.WithTx(ctx, func(tx store.Store) error {
					return tx.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "t", Date: base}}, nil)
				})
			} else {
				err = appendBatch()
			}
			if err != nil {
				t.Fatal(err)
			}
			rows, err := s.Logs().LogsAfter(ctx, "t", 0, nil, 100, base.Add(time.Second))
			if err != nil || len(rows) != 0 {
				t.Fatalf("clock skew: %v %v", rows, err)
			}
			rows, err = s.Logs().LogsAfter(ctx, "t", 0, nil, 100, base.Add(20*time.Second))
			if err != nil || len(rows) != 2 {
				t.Fatalf("lost events: %v %v", rows, err)
			}
		})
	}
}
