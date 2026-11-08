package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

// Task 4 supplies the implementation; this suite must not be reported passing
// while Logs returns UnimplementedLogs.
func TestLogs(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) { storetest.RunSuites(t, func(t *testing.T) store.Store { return fresh(t) }, "Logs") })
	}
}

func TestLogsMigrationFrom27(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 27)
			ctx := context.Background()
			seedLegacyTenant(t, s, "legacy")
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Tenants().Get(ctx, "legacy"); err != nil {
				t.Fatal(err)
			}
			if err := s.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "legacy", Date: time.Now()}}, nil); err != nil {
				t.Fatal(err)
			}
			fresh := mustOpen(t, mk(t))
			for _, table := range []string{"tenant_logs", "log_streams", "log_stats_daily"} {
				if !slices.Equal(tableShape(t, s, table), tableShape(t, fresh, table)) {
					t.Fatal("shape differs", table)
				}
			}
		})
	}
}

func TestLogsSearchPageBound(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			if err := s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			events := make([]store.LogEvent, 1100)
			for i := range events {
				events[i] = store.LogEvent{TenantID: "t", Date: time.Now(), Body: []byte(`{}`)}
			}
			if err := s.Logs().AppendLogs(ctx, events, nil); err != nil {
				t.Fatal(err)
			}
			spy := &logQuerySpy{querier: s.q}
			s.q = spy
			rows, total, err := s.Logs().SearchLogs(ctx, "t", nil, store.LogPage{Page: 9, PerPage: 100, IncludeTotals: true})
			if err != nil || len(rows) != 100 || total != 1100 {
				t.Fatalf("rows=%d total=%d err=%v", len(rows), total, err)
			}
			if len(spy.queries) != 1 || len(spy.args[0]) != 3 || spy.args[0][1] != 100 || spy.args[0][2] != 900 || !regexp.MustCompile(`LIMIT (?:\?|\$[0-9]+) OFFSET (?:\?|\$[0-9]+)$`).MatchString(spy.queries[0]) {
				t.Fatalf("unbounded rows query: %v", spy.queries)
			}
		})
	}
}

type logQuerySpy struct {
	querier
	queries []string
	args    [][]any
}

func (s *logQuerySpy) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	s.queries = append(s.queries, q)
	s.args = append(s.args, append([]any(nil), args...))
	return s.querier.QueryContext(ctx, q, args...)
}

// Explicitly delay the lower sequence's outer commit, after AppendLogs returns.
// Separate pools guarantee independent connections, including SQLite's writer
// and checkpoint reader. Advancing the clock beyond settlement while the writer
// is blocked would expose a skipped lower sequence without the tenant lock.
func TestLogsConcurrentWritersCheckpoint(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			dsn := mk(t)
			a := mustOpen(t, dsn)
			b := mustOpenRaw(t, dsn)
			reader := mustOpenRaw(t, dsn)
			if err := a.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			base := time.Now().UTC()
			var tick atomic.Int64
			clock := func() time.Time { return base.Add(time.Duration(tick.Load()) * time.Second) }
			a.logsClock = clock
			b.logsClock = clock
			inserted := make(chan struct{})
			release := make(chan struct{})
			first := make(chan error, 1)
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			go func() {
				first <- a.WithTx(ctx, func(tx store.Store) error {
					if err := tx.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "t", Date: base, Body: []byte(`{"writer":1}`)}}, nil); err != nil {
						return err
					}
					close(inserted)
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			}()
			select {
			case <-inserted:
			case err := <-first:
				t.Fatalf("first append: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			secondStarted := make(chan struct{})
			second := make(chan error, 1)
			go func() {
				close(secondStarted)
				second <- b.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "t", Date: base, Body: []byte(`{"writer":2}`)}}, nil)
			}()
			<-secondStarted
			tick.Store(10)
			var checkpoint int64
			seen := map[int64]bool{}
			poll := func() {
				t.Helper()
				rows, err := reader.Logs().LogsAfter(ctx, "t", checkpoint, nil, 1, clock().Add(-2*time.Second))
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range rows {
					if seen[e.Seq] {
						t.Fatalf("duplicate %d", e.Seq)
					}
					seen[e.Seq] = true
					checkpoint = e.Seq
				}
			}
			// Poll while the first transaction remains deliberately uncommitted. Yield
			// enough for the second connection to execute rather than relying on launch order.
			deadline := time.Now().Add(100 * time.Millisecond)
			for time.Now().Before(deadline) {
				poll()
				select {
				case err := <-second:
					t.Fatalf("second committed ahead of locked first: %v", err)
				default:
				}
				runtime.Gosched()
			}
			unblock()
			if err := <-first; err != nil {
				t.Fatal(err)
			}
			if err := <-second; err != nil {
				t.Fatal(err)
			}
			tick.Store(20)
			for range 3 {
				poll()
			}
			if len(seen) != 2 {
				t.Fatalf("checkpoint skipped committed event: %v", seen)
			}
		})
	}
}

func TestLogsLeaseExpiryAndSinkPrecision(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			now := time.Now().UTC()
			s.logsClock = func() time.Time { return now }
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			must(s.Logs().CreateLogStream(ctx, &store.LogStream{TenantID: "t", ID: "s", Type: "http", Status: "active", Sink: map[string]any{"number": json.Number("9007199254740993")}}))
			got, err := s.Logs().GetLogStream(ctx, "t", "s")
			must(err)
			if got.Sink["number"] != json.Number("9007199254740993") {
				t.Fatalf("precision lost: %#v", got.Sink)
			}
			_, err = s.Logs().LeaseLogStream(ctx, "acquisition-1", now, now.Add(time.Second))
			must(err)
			now = now.Add(2 * time.Second)
			if err := s.Logs().RecordDelivery(ctx, "t", "s", "acquisition-1", store.LogStreamDelivery{Checkpoint: 1}); !errors.Is(err, store.ErrPrecondition) {
				t.Fatalf("expired lease: %v", err)
			}
			_, err = s.Logs().LeaseLogStream(ctx, "acquisition-2", now, now.Add(time.Second))
			must(err)
			if err := s.Logs().RecordDelivery(ctx, "t", "s", "acquisition-1", store.LogStreamDelivery{Checkpoint: 2}); !errors.Is(err, store.ErrPrecondition) {
				t.Fatalf("stale acquisition: %v", err)
			}
			must(s.Logs().RecordDelivery(ctx, "t", "s", "acquisition-2", store.LogStreamDelivery{Checkpoint: 1}))
		})
	}
}

func TestLogsTimestampBoundaries(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			dates := []time.Time{time.Date(1600, 1, 1, 0, 0, 0, 123456789, time.UTC), time.Unix(0, 0).UTC(), time.Date(3000, 1, 1, 0, 0, 0, 987654321, time.UTC), {}, time.Date(0, 1, 1, 0, 0, 0, 1, time.UTC)}
			s.logsClock = func() time.Time { return dates[1] }
			for _, date := range dates {
				must(s.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "t", Date: date}}, []store.DailyStatDelta{{TenantID: "t", Day: date, Logins: 1}}))
			}
			rows, err := s.Logs().LogsAfter(ctx, "t", 0, nil, 10, dates[1])
			must(err)
			if len(rows) != len(dates) {
				t.Fatalf("epoch settlement: %v", rows)
			}
			page, _, err := s.Logs().SearchLogs(ctx, "t", nil, store.LogPage{Ascending: true})
			must(err)
			if len(page) != len(dates) || !page[0].Date.Equal(dates[4]) || !page[1].Date.IsZero() {
				t.Fatalf("year0000 and zero date ordering: %v", page)
			}
			for i := range dates {
				if !rows[i].Date.Equal(dates[i]) {
					t.Fatalf("date %d: %v want %v", i, rows[i].Date, dates[i])
				}
			}
			must(s.Logs().CreateLogStream(ctx, &store.LogStream{TenantID: "t", ID: "s", Type: "http", Status: "active", StartFrom: dates[2]}))
			got, err := s.Logs().GetLogStream(ctx, "t", "s")
			must(err)
			if got.Checkpoint != rows[2].Seq-1 || !got.StartFrom.Equal(dates[2]) || !got.CreatedAt.Equal(dates[1]) {
				t.Fatalf("startFrom/epoch: %+v", got)
			}
			s.logsClock = func() time.Time { return dates[2] }
			_, err = s.Logs().LeaseLogStream(ctx, "future", dates[2], dates[2].Add(time.Hour))
			must(err)
			must(s.Logs().RecordDelivery(ctx, "t", "s", "future", store.LogStreamDelivery{Checkpoint: rows[2].Seq, LastSuccessAt: dates[2]}))
			got, err = s.Logs().GetLogStream(ctx, "t", "s")
			must(err)
			if !got.LastSuccessAt.Equal(dates[2]) {
				t.Fatalf("future delivery: %v", got.LastSuccessAt)
			}
			stats, err := s.Logs().DailyStats(ctx, "t", dates[4], dates[2])
			must(err)
			if len(stats) != len(dates) {
				t.Fatalf("stats: %v", stats)
			}
		})
	}
}

// Acquisition can wait for a transaction/savepoint or a competing row lock.
// Expiry must be evaluated after that wait, rather than at method entry.
func TestLogsDeliveryExpiryAfterTransactionWait(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			base := time.Now().UTC()
			var tick atomic.Int64
			s.logsClock = func() time.Time { return base.Add(time.Duration(tick.Load()) * time.Second) }
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			must(s.Logs().CreateLogStream(ctx, &store.LogStream{TenantID: "t", ID: "s", Type: "http", Status: "active"}))
			_, err := s.Logs().LeaseLogStream(ctx, "lease", base, base.Add(time.Second))
			must(err)
			must(s.WithTx(ctx, func(tx store.Store) error {
				st := tx.(*Store)
				entered := make(chan struct{})
				resume := make(chan struct{})
				st.q = &logDeliveryGate{querier: st.q, entered: entered, resume: resume}
				done := make(chan error, 1)
				go func() {
					done <- tx.Logs().RecordDelivery(ctx, "t", "s", "lease", store.LogStreamDelivery{Checkpoint: 7})
				}()
				<-entered
				tick.Store(2)
				close(resume)
				if err := <-done; !errors.Is(err, store.ErrPrecondition) {
					t.Errorf("delivery accepted expired lease after wait: %v", err)
				}
				return nil
			}))
		})
	}
}

type logDeliveryGate struct {
	querier
	once    sync.Once
	entered chan struct{}
	resume  chan struct{}
}

func (g *logDeliveryGate) wait() { g.once.Do(func() { close(g.entered); <-g.resume }) }
func (g *logDeliveryGate) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	g.wait()
	return g.querier.ExecContext(ctx, q, args...)
}
func (g *logDeliveryGate) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	g.wait()
	return g.querier.QueryRowContext(ctx, q, args...)
}

func TestLogsBackwardsClockCheckpoint(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			base := time.Now().UTC()
			now := base.Add(10 * time.Second)
			s.logsClock = func() time.Time { return now }
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			must(s.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "t", Date: base}}, nil))
			now = base
			must(s.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "t", Date: base}, {TenantID: "t", Date: base}}, nil))
			rows, err := s.Logs().LogsAfter(ctx, "t", 0, nil, 100, base.Add(time.Second))
			must(err)
			if len(rows) != 0 {
				t.Fatalf("clock skew exposed later sequence before unsettled earlier event: %v", rows)
			}
			rows, err = s.Logs().LogsAfter(ctx, "t", 0, nil, 100, base.Add(20*time.Second))
			must(err)
			if len(rows) != 3 {
				t.Fatalf("lost events: %v", rows)
			}
		})
	}
}

func TestLogsWideUserID(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			// Federation migration 0021 supports user IDs up to 1280 bytes. Persist a
			// real user first so the log references an ID the existing driver accepts.
			id := "federated|" + strings.Repeat("x", 1270)
			must(s.Users().Create(ctx, &store.User{TenantID: "t", UserID: id}))
			must(s.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "t", UserID: id, Date: time.Now()}}, nil))
			rows, err := s.Logs().LogsAfter(ctx, "t", 0, nil, 10, time.Now().Add(time.Hour))
			must(err)
			if len(rows) != 1 || rows[0].UserID != id {
				t.Fatalf("wide user ID roundtrip: %v", rows)
			}
		})
	}
}
