package storetest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func logsFixture(t *testing.T, f Factory) (store.Store, context.Context, time.Time) {
	t.Helper()
	s := open(t, f)
	ctx := context.Background()
	mustNoErr(t, s.Tenants().Create(ctx, newTenant("logs")))
	mustNoErr(t, s.Tenants().Create(ctx, newTenant("other")))
	return s, ctx, time.Now().UTC().Add(-time.Hour)
}
func appendLog(t *testing.T, s store.Store, ctx context.Context, tid string, at time.Time) {
	t.Helper()
	mustNoErr(t, s.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: tid, Date: at, Type: "s", UserID: "auth0|u", Body: []byte(`{"description":"hello","user_name":"Alice"}`)}}, nil))
}
func logStream(tid, id string) *store.LogStream {
	return &store.LogStream{TenantID: tid, ID: id, Name: id, Type: "http", Status: "active", Sink: map[string]any{"nested": map[string]any{"items": []any{"a"}}}, SealedSecrets: []byte("sealed"), Filters: []store.LogStreamFilter{{Type: "category", Name: "auth.login.success"}}, PII: &store.LogStreamPII{LogFields: []string{"email"}, Method: "mask"}}
}
func testLogs(t *testing.T, f Factory) {
	t.Run("LogsAppendOrdering", func(t *testing.T) {
		s, ctx, at := logsFixture(t, f)
		appendLog(t, s, ctx, "ten_logs", at.Add(time.Hour))
		appendLog(t, s, ctx, "ten_logs", at)
		rows, err := s.Logs().LogsAfter(ctx, "ten_logs", 0, nil, 100, time.Now().Add(time.Hour))
		mustNoErr(t, err)
		if len(rows) != 2 || rows[0].Seq >= rows[1].Seq || rows[0].ID >= rows[1].ID {
			t.Fatalf("sequence order: %+v", rows)
		}
		for _, e := range rows {
			if len(e.ID) != 56 || strings.Trim(e.ID, "0123456789") != "" || e.ID != store.FormatLogID(e.Seq) {
				t.Fatalf("invalid ID %q", e.ID)
			}
		}
		page, total, err := s.Logs().SearchLogs(ctx, "ten_logs", nil, store.LogPage{PerPage: 100, Ascending: true, IncludeTotals: true})
		mustNoErr(t, err)
		if total != 2 || page[0].Seq != rows[1].Seq {
			t.Fatalf("page date ordering/total: %+v %d", page, total)
		}
	})
	t.Run("LogsTenantIsolation", func(t *testing.T) {
		s, ctx, at := logsFixture(t, f)
		appendLog(t, s, ctx, "ten_logs", at)
		appendLog(t, s, ctx, "ten_other", at)
		a, _, err := s.Logs().SearchLogs(ctx, "ten_logs", nil, store.LogPage{PerPage: 10})
		mustNoErr(t, err)
		b, _, err := s.Logs().SearchLogs(ctx, "ten_other", nil, store.LogPage{PerPage: 10})
		mustNoErr(t, err)
		if len(a) != 1 || len(b) != 1 {
			t.Fatalf("isolation %d/%d", len(a), len(b))
		}
		_, err = s.Logs().GetLog(ctx, "ten_other", a[0].ID)
		mustErrIs(t, err, store.ErrNotFound)
		for _, id := range []string{"", "1", strings.Repeat("x", 56), strings.Repeat("9", 56)} {
			_, err = s.Logs().GetLog(ctx, "ten_logs", id)
			mustErrIs(t, err, store.ErrNotFound)
		}
		a[0].Body[0] = 'x'
		got, err := s.Logs().GetLog(ctx, "ten_logs", a[0].ID)
		mustNoErr(t, err)
		if got.Body[0] != '{' {
			t.Fatal("body alias")
		}
		q := &store.LogQuery{Op: "eq", Field: "user_name", Value: "Alice"}
		a, _, err = s.Logs().SearchLogs(ctx, "ten_logs", q, store.LogPage{PerPage: 10})
		mustNoErr(t, err)
		if len(a) != 1 {
			t.Fatal("body query missing")
		}
		_, _, err = s.Logs().SearchLogs(ctx, "ten_logs", &store.LogQuery{Op: "wat"}, store.LogPage{PerPage: 10})
		mustErrIs(t, err, store.ErrInvalid)
	})
	t.Run("LogsSettledCheckpoint", func(t *testing.T) {
		s, ctx, at := logsFixture(t, f)
		settled := time.Now().Add(-time.Second)
		appendLog(t, s, ctx, "ten_logs", at)
		rows, err := s.Logs().LogsAfter(ctx, "ten_logs", 0, nil, 10, settled)
		mustNoErr(t, err)
		if len(rows) != 0 {
			t.Fatal("unsettled returned")
		}
		rows, err = s.Logs().LogsAfter(ctx, "ten_logs", 0, nil, 10, time.Now().Add(time.Second))
		mustNoErr(t, err)
		if len(rows) != 1 {
			t.Fatalf("settled rows %d", len(rows))
		}
		again, err := s.Logs().LogsAfter(ctx, "ten_logs", rows[0].Seq, nil, 10, time.Now().Add(time.Second))
		mustNoErr(t, err)
		if len(again) != 0 {
			t.Fatal("checkpoint duplicate")
		}
		last, err := s.Logs().LatestLogs(ctx, "ten_logs", nil, 1, time.Now().Add(time.Second))
		mustNoErr(t, err)
		if len(last) != 1 || last[0].ID != rows[0].ID {
			t.Fatal("latest mismatch")
		}
	})
	t.Run("LogsPageLimits", func(t *testing.T) {
		s, ctx, at := logsFixture(t, f)
		events := make([]store.LogEvent, 105)
		for i := range events {
			events[i] = store.LogEvent{TenantID: "ten_logs", Date: at, Type: "s"}
		}
		mustNoErr(t, s.Logs().AppendLogs(ctx, events, nil))
		for _, p := range []store.LogPage{{Page: -1, PerPage: 10}, {PerPage: 101}, {PerPage: -1}, {Page: 10, PerPage: 100}, {Page: 1000000000000, PerPage: 100}} {
			_, _, err := s.Logs().SearchLogs(ctx, "ten_logs", nil, p)
			mustErrIs(t, err, store.ErrInvalid)
		}
		rows, total, err := s.Logs().SearchLogs(ctx, "ten_logs", nil, store.LogPage{Page: 1, PerPage: 100, IncludeTotals: true})
		mustNoErr(t, err)
		if len(rows) != 5 || total != 105 {
			t.Fatalf("page %d total %d", len(rows), total)
		}
		for _, take := range []int{-1, 0, 101} {
			_, err = s.Logs().LogsAfter(ctx, "ten_logs", 0, nil, take, time.Now())
			mustErrIs(t, err, store.ErrInvalid)
			_, err = s.Logs().LatestLogs(ctx, "ten_logs", nil, take, time.Now())
			mustErrIs(t, err, store.ErrInvalid)
		}
	})
	t.Run("LogsPurgeBatches", func(t *testing.T) {
		s, ctx, at := logsFixture(t, f)
		for range 3 {
			appendLog(t, s, ctx, "ten_logs", at)
		}
		appendLog(t, s, ctx, "ten_other", at.Add(time.Hour))
		n, err := s.Logs().PurgeLogs(ctx, at.Add(time.Minute), 2)
		mustNoErr(t, err)
		if n != 2 {
			t.Fatalf("purged %d", n)
		}
		n, err = s.Logs().PurgeLogs(ctx, at.Add(time.Minute), 2)
		mustNoErr(t, err)
		if n != 1 {
			t.Fatalf("purged %d", n)
		}
		rows, _, err := s.Logs().SearchLogs(ctx, "ten_other", nil, store.LogPage{PerPage: 10})
		mustNoErr(t, err)
		if len(rows) != 1 {
			t.Fatal("purged fresh")
		}
		_, err = s.Logs().PurgeLogs(ctx, at, 0)
		mustErrIs(t, err, store.ErrInvalid)
	})
	t.Run("LogsStatsUpsert", func(t *testing.T) {
		s, ctx, at := logsFixture(t, f)
		local := at.In(time.FixedZone("plus", 3600))
		for range 2 {
			mustNoErr(t, s.Logs().AppendLogs(ctx, nil, []store.DailyStatDelta{{TenantID: "ten_logs", Day: local, Logins: 2, Signups: 1, LeakedPasswords: 3}}))
		}
		stats, err := s.Logs().DailyStats(ctx, "ten_logs", at.Add(-24*time.Hour), at.Add(24*time.Hour))
		mustNoErr(t, err)
		if len(stats) != 1 || stats[0].Logins != 4 || stats[0].Signups != 2 || stats[0].LeakedPasswords != 6 || stats[0].Day.Hour() != 0 || stats[0].Day.Location() != time.UTC || stats[0].CreatedAt.IsZero() || stats[0].UpdatedAt.Before(stats[0].CreatedAt) {
			t.Fatalf("stats %+v", stats)
		}
		rows, err := s.Logs().DailyStats(ctx, "ten_other", at.Add(-24*time.Hour), at.Add(24*time.Hour))
		mustNoErr(t, err)
		if len(rows) != 0 {
			t.Fatal("cross-tenant stats")
		}
		u := newUser("ten_logs", "u", "u@example.test", "")
		u.LastLogin = &at
		mustNoErr(t, s.Users().Create(ctx, u))
		n, err := s.Logs().ActiveUsers(ctx, "ten_logs", at)
		mustNoErr(t, err)
		if n != 1 {
			t.Fatal("inclusive active users")
		}
		n, err = s.Logs().ActiveUsers(ctx, "ten_logs", at.Add(time.Second))
		mustNoErr(t, err)
		if n != 0 {
			t.Fatal("old user active")
		}
	})
	t.Run("LogStreamLease", func(t *testing.T) {
		s, ctx, _ := logsFixture(t, f)
		stream := logStream("ten_logs", "stream")
		mustNoErr(t, s.Logs().CreateLogStream(ctx, stream))
		now := time.Now()
		leased, err := s.Logs().LeaseLogStream(ctx, "owner1", now, now.Add(time.Hour))
		mustNoErr(t, err)
		if leased.LeaseOwner != "owner1" {
			t.Fatal("missing owner")
		}
		_, err = s.Logs().LeaseLogStream(ctx, "owner2", now, now.Add(time.Hour))
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.Logs().RecordDelivery(ctx, "ten_logs", "stream", "owner2", store.LogStreamDelivery{}), store.ErrPrecondition)
		_, err = s.Logs().LeaseLogStream(ctx, "owner2", now.Add(2*time.Hour), now.Add(3*time.Hour))
		mustNoErr(t, err)
		mustErrIs(t, s.Logs().RecordDelivery(ctx, "ten_logs", "stream", "owner1", store.LogStreamDelivery{Checkpoint: 9}), store.ErrPrecondition)
		mustNoErr(t, s.Logs().RecordDelivery(ctx, "ten_logs", "stream", "owner2", store.LogStreamDelivery{Checkpoint: 2, Status: "active", NextAt: now.Add(4 * time.Hour), LastSuccessAt: now}))
		got, err := s.Logs().GetLogStream(ctx, "ten_logs", "stream")
		mustNoErr(t, err)
		if got.Checkpoint != 2 || got.LeaseOwner != "" {
			t.Fatalf("delivery %+v", got)
		}
		_, err = s.Logs().LeaseLogStream(ctx, "owner3", now, now.Add(time.Hour))
		mustErrIs(t, err, store.ErrNotFound)
		mustNoErr(t, s.Logs().CreateLogStream(ctx, logStream("ten_logs", "expired")))
		_, err = s.Logs().LeaseLogStream(ctx, "expired", now.Add(-2*time.Hour), now.Add(-time.Hour))
		mustNoErr(t, err)
		mustErrIs(t, s.Logs().RecordDelivery(ctx, "ten_logs", "expired", "expired", store.LogStreamDelivery{Checkpoint: 10}), store.ErrPrecondition)
	})
	t.Run("LogStreamVersionConflict", func(t *testing.T) {
		s, ctx, at := logsFixture(t, f)
		stream := logStream("ten_logs", "stream")
		stream.StartFrom = at
		mustNoErr(t, s.Logs().CreateLogStream(ctx, stream))
		mustErrIs(t, s.Logs().CreateLogStream(ctx, stream), store.ErrConflict)
		stream.Sink["nested"].(map[string]any)["items"].([]any)[0] = "bad"
		stream.SealedSecrets[0] = 'x'
		stream.Filters[0].Name = "bad"
		stream.PII.LogFields[0] = "bad"
		got, err := s.Logs().GetLogStream(ctx, "ten_logs", "stream")
		mustNoErr(t, err)
		if got.Sink["nested"].(map[string]any)["items"].([]any)[0] != "a" || got.SealedSecrets[0] != 's' || got.Filters[0].Name == "bad" || got.PII.LogFields[0] != "email" || !got.StartFrom.Equal(at) {
			t.Fatal("create aliases")
		}
		stale := *got
		now := time.Now()
		_, err = s.Logs().LeaseLogStream(ctx, "worker", now, now.Add(time.Hour))
		mustNoErr(t, err)
		got.Status = "paused"
		got.StartFrom = at.Add(time.Hour)
		mustNoErr(t, s.Logs().UpdateLogStream(ctx, got, got.Version))
		mustErrIs(t, s.Logs().UpdateLogStream(ctx, &stale, stale.Version), store.ErrConflict)
		mustErrIs(t, s.Logs().RecordDelivery(ctx, "ten_logs", "stream", "worker", store.LogStreamDelivery{Status: "active", Checkpoint: 9}), store.ErrPrecondition)
		fresh, err := s.Logs().GetLogStream(ctx, "ten_logs", "stream")
		mustNoErr(t, err)
		if fresh.Status != "paused" || !fresh.StartFrom.Equal(at) {
			t.Fatal("admin status or create-only startFrom overwritten")
		}
		fresh.PII.LogFields[0] = "bad"
		fresh.Sink["nested"].(map[string]any)["items"].([]any)[0] = "bad"
		list, err := s.Logs().ListLogStreams(ctx, "ten_logs")
		mustNoErr(t, err)
		if len(list) != 1 || list[0].PII.LogFields[0] != "email" || list[0].Sink["nested"].(map[string]any)["items"].([]any)[0] != "a" {
			t.Fatal("read aliases")
		}
		_, err = s.Logs().GetLogStream(ctx, "ten_other", "stream")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.Logs().DeleteLogStream(ctx, "ten_other", "stream"), store.ErrNotFound)
		mustNoErr(t, s.Logs().DeleteLogStream(ctx, "ten_logs", "stream"))
	})
	t.Run("LogsDeleteTenant", func(t *testing.T) {
		s, ctx, at := logsFixture(t, f)
		for _, tid := range []string{"ten_logs", "ten_other"} {
			appendLog(t, s, ctx, tid, at)
			mustNoErr(t, s.Logs().CreateLogStream(ctx, logStream(tid, "s")))
			mustNoErr(t, s.Logs().AppendLogs(ctx, nil, []store.DailyStatDelta{{TenantID: tid, Day: at, Logins: 1}}))
		}
		u := newUser("ten_logs", "u", "u@example.test", "")
		mustNoErr(t, s.Users().Create(ctx, u))
		mustNoErr(t, s.Users().Delete(ctx, "ten_logs", u.UserID))
		rows, _, err := s.Logs().SearchLogs(ctx, "ten_logs", nil, store.LogPage{PerPage: 10})
		mustNoErr(t, err)
		if len(rows) != 1 {
			t.Fatal("user deletion removed log")
		}
		mustNoErr(t, s.Tenants().Delete(ctx, "ten_logs"))
		for _, tid := range []string{"ten_logs", "ten_other"} {
			want := 0
			if tid == "ten_other" {
				want = 1
			}
			rows, _, err = s.Logs().SearchLogs(ctx, tid, nil, store.LogPage{PerPage: 10})
			mustNoErr(t, err)
			streams, err := s.Logs().ListLogStreams(ctx, tid)
			mustNoErr(t, err)
			stats, err := s.Logs().DailyStats(ctx, tid, at.Add(-24*time.Hour), at.Add(24*time.Hour))
			mustNoErr(t, err)
			if len(rows) != want || len(streams) != want || len(stats) != want {
				t.Fatalf("tenant %s lengths %d/%d/%d", tid, len(rows), len(streams), len(stats))
			}
		}
		mustNoErr(t, s.Logs().DeleteTenantLogs(ctx, "ten_other"))
		rows, _, err = s.Logs().SearchLogs(ctx, "ten_other", nil, store.LogPage{PerPage: 10})
		mustNoErr(t, err)
		if len(rows) != 0 {
			t.Fatal("explicit deletion")
		}
	})
	t.Run("LogsTransactionRollback", func(t *testing.T) {
		s, ctx, at := logsFixture(t, f)
		appendLog(t, s, ctx, "ten_logs", at)
		before, _, err := s.Logs().SearchLogs(ctx, "ten_logs", nil, store.LogPage{PerPage: 10})
		mustNoErr(t, err)
		mustNoErr(t, s.Logs().CreateLogStream(ctx, logStream("ten_logs", "persist")))
		mustNoErr(t, s.Logs().AppendLogs(ctx, nil, []store.DailyStatDelta{{TenantID: "ten_logs", Day: at, Logins: 1}}))
		rollback := errors.New("rollback")
		err = s.WithTx(ctx, func(tx store.Store) error {
			appendLog(t, tx, ctx, "ten_logs", at)
			mustNoErr(t, tx.Logs().CreateLogStream(ctx, logStream("ten_logs", "rolled")))
			mustNoErr(t, tx.Logs().AppendLogs(ctx, nil, []store.DailyStatDelta{{TenantID: "ten_logs", Day: at, Logins: 1}}))
			now := time.Now()
			leased, err := tx.Logs().LeaseLogStream(ctx, "rollback-owner", now, now.Add(time.Hour))
			mustNoErr(t, err)
			if leased.ID != "persist" {
				t.Fatalf("leased %s", leased.ID)
			}
			mustNoErr(t, tx.Logs().RecordDelivery(ctx, "ten_logs", "persist", "rollback-owner", store.LogStreamDelivery{Checkpoint: 9, Status: "suspended", Failures: 10}))
			mustNoErr(t, tx.Logs().DeleteTenantLogs(ctx, "ten_logs"))
			return rollback
		})
		mustErrIs(t, err, rollback)
		appendLog(t, s, ctx, "ten_logs", at)
		rows, err := s.Logs().LogsAfter(ctx, "ten_logs", 0, nil, 10, time.Now().Add(time.Hour))
		mustNoErr(t, err)
		if len(rows) != 2 || rows[0].ID != before[0].ID || rows[1].Seq != rows[0].Seq+1 {
			t.Fatalf("rollback sequence/events %+v", rows)
		}
		streams, err := s.Logs().ListLogStreams(ctx, "ten_logs")
		mustNoErr(t, err)
		stats, err := s.Logs().DailyStats(ctx, "ten_logs", at.Add(-24*time.Hour), at.Add(24*time.Hour))
		mustNoErr(t, err)
		if len(streams) != 1 || streams[0].ID != "persist" || streams[0].Checkpoint != before[0].Seq || streams[0].Status != "active" || streams[0].LeaseOwner != "" || streams[0].Failures != 0 || len(stats) != 1 || stats[0].Logins != 1 {
			t.Fatalf("rollback streams/stats %+v %+v", streams, stats)
		}
	})
	t.Run("LogStreamResume", func(t *testing.T) {
		s, ctx, _ := logsFixture(t, f)
		mustNoErr(t, s.Logs().CreateLogStream(ctx, logStream("ten_logs", "s")))
		now := time.Now()
		_, err := s.Logs().LeaseLogStream(ctx, "delivery", now, now.Add(time.Hour))
		mustNoErr(t, err)
		mustNoErr(t, s.Logs().RecordDelivery(ctx, "ten_logs", "s", "delivery", store.LogStreamDelivery{Checkpoint: 5, Status: "suspended", Failures: 10, FailingSince: now.Add(-25 * time.Hour), NextAt: now.Add(time.Hour), LastErrorClass: "timeout", LastSuccessAt: now.Add(-26 * time.Hour)}))
		got, err := s.Logs().GetLogStream(ctx, "ten_logs", "s")
		mustNoErr(t, err)
		success := got.LastSuccessAt
		got.Status = "active"
		mustNoErr(t, s.Logs().UpdateLogStream(ctx, got, got.Version))
		resumed, err := s.Logs().LeaseLogStream(ctx, "resumed", time.Now(), time.Now().Add(time.Hour))
		mustNoErr(t, err)
		if resumed.Checkpoint != 5 || resumed.Failures != 0 || !resumed.FailingSince.IsZero() || resumed.LastErrorClass != "" || !resumed.LastSuccessAt.Equal(success) {
			t.Fatalf("resume state %+v", resumed)
		}
	})
	t.Run("LogStreamAdminMerge", func(t *testing.T) {
		s, ctx, _ := logsFixture(t, f)
		mustNoErr(t, s.Logs().CreateLogStream(ctx, logStream("ten_logs", "s")))
		admin, err := s.Logs().GetLogStream(ctx, "ten_logs", "s")
		mustNoErr(t, err)
		now := time.Now()
		_, err = s.Logs().LeaseLogStream(ctx, "delivery", now, now.Add(time.Hour))
		mustNoErr(t, err)
		mustNoErr(t, s.Logs().RecordDelivery(ctx, "ten_logs", "s", "delivery", store.LogStreamDelivery{Checkpoint: 5, Status: "active", LastSuccessAt: now}))
		admin.Name = "renamed"
		mustNoErr(t, s.Logs().UpdateLogStream(ctx, admin, admin.Version))
		got, err := s.Logs().GetLogStream(ctx, "ten_logs", "s")
		mustNoErr(t, err)
		if got.Name != "renamed" || got.Checkpoint != 5 || !got.LastSuccessAt.Equal(now) {
			t.Fatalf("stale admin lost delivery: %+v", got)
		}
		_, err = s.Logs().LeaseLogStream(ctx, "next", time.Now(), time.Now().Add(time.Hour))
		mustNoErr(t, err)
		mustErrIs(t, s.Logs().RecordDelivery(ctx, "ten_logs", "s", "next", store.LogStreamDelivery{Checkpoint: 4}), store.ErrPrecondition)
	})
	t.Run("LogStreamConcurrentLease", func(t *testing.T) {
		s, ctx, _ := logsFixture(t, f)
		mustNoErr(t, s.Logs().CreateLogStream(ctx, logStream("ten_logs", "s")))
		now := time.Now()
		var winners atomic.Int32
		var wg sync.WaitGroup
		for i := range 10 {
			wg.Go(func() {
				_, err := s.Logs().LeaseLogStream(ctx, fmt.Sprint("owner", i), now, now.Add(time.Hour))
				if err == nil {
					winners.Add(1)
				} else if !errors.Is(err, store.ErrNotFound) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if winners.Load() != 1 {
			t.Fatalf("lease winners %d", winners.Load())
		}
	})
	t.Run("LogStreamStartFrom", func(t *testing.T) {
		s, ctx, at := logsFixture(t, f)
		for _, date := range []time.Time{at.Add(-time.Hour), at.Add(time.Hour), at.Add(-time.Hour), at.Add(2 * time.Hour)} {
			appendLog(t, s, ctx, "ten_logs", date)
		}
		events, err := s.Logs().LogsAfter(ctx, "ten_logs", 0, nil, 100, time.Now().Add(time.Hour))
		mustNoErr(t, err)
		for id, start := range map[string]time.Time{"all": at.Add(-2 * time.Hour), "middle": at, "future": at.Add(3 * time.Hour), "default": {}} {
			stream := logStream("ten_logs", id)
			stream.StartFrom = start
			mustNoErr(t, s.Logs().CreateLogStream(ctx, stream))
			got, err := s.Logs().GetLogStream(ctx, "ten_logs", id)
			mustNoErr(t, err)
			want := events[3].Seq
			if id == "all" {
				want = events[0].Seq - 1
			}
			if id == "middle" {
				want = events[1].Seq - 1
			}
			if got.Checkpoint != want {
				t.Fatalf("%s checkpoint %d want %d", id, got.Checkpoint, want)
			}
		}
	})
	t.Run("LogsQueryBoolean", func(t *testing.T) {
		s, ctx, at := logsFixture(t, f)
		appendLog(t, s, ctx, "ten_logs", at)
		eq := func(field, value string) *store.LogQuery {
			return &store.LogQuery{Op: "eq", Field: field, Value: value}
		}
		queries := []*store.LogQuery{{Op: "and", Left: eq("type", "s"), Right: &store.LogQuery{Op: "not", Left: eq("user_id", "other")}}, {Op: "sw", Field: "description", Value: "hel"}, {Op: "range", Field: "date", Value: at.Add(-time.Second).Format(time.RFC3339Nano), Upper: at.Add(time.Second).Format(time.RFC3339Nano)}}
		for i, q := range queries {
			rows, _, err := s.Logs().SearchLogs(ctx, "ten_logs", q, store.LogPage{PerPage: 10})
			mustNoErr(t, err)
			if len(rows) != 1 {
				t.Fatal(fmt.Sprint("query ", i, " did not match"))
			}
		}
	})
}
