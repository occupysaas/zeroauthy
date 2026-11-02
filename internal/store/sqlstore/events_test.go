package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestEventsConformance(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			storetest.RunSuites(t, func(t *testing.T) store.Store { return fresh(t) }, "Events")
		})
	}
}

func TestEventsMigrationFrom30(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 30)
			ctx := context.Background()
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "legacy", Name: "legacy"}))
			mustEvent(t, s.Migrate(ctx))
			if s.LatestVersion() != 32 {
				t.Fatalf("latest version=%d", s.LatestVersion())
			}
			_, err := s.Tenants().Get(ctx, "legacy")
			mustEvent(t, err)
			mustEvent(t, s.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "legacy", ID: "e", Time: time.Now()}}))
			fresh := mustOpen(t, mk(t))
			for _, table := range []string{"tenant_events", "event_streams", "event_deliveries", "event_cursor_watermarks"} {
				if !slices.Equal(tableShape(t, s, table), tableShape(t, fresh, table)) {
					t.Fatal("shape differs", table)
				}
			}
		})
	}
}

func mustEvent(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestEventsAppendInBusinessTx(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			abort := errors.New("abort")
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			for _, commit := range []bool{false, true} {
				err := s.WithTx(ctx, func(tx store.Store) error {
					if err := tx.Users().Create(ctx, &store.User{TenantID: "t", UserID: "u"}); err != nil {
						return err
					}
					if err := tx.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "e", Time: time.Now()}}); err != nil {
						return err
					}
					if !commit {
						return abort
					}
					return nil
				})
				if commit {
					mustEvent(t, err)
				} else if !errors.Is(err, abort) {
					t.Fatal(err)
				}
				_, userErr := s.Users().Get(ctx, "t", "u")
				_, eventErr := s.Events().GetEvent(ctx, "t", "e")
				if commit {
					mustEvent(t, userErr)
					mustEvent(t, eventErr)
				} else if !errors.Is(userErr, store.ErrNotFound) || !errors.Is(eventErr, store.ErrNotFound) {
					t.Fatalf("rollback user=%v event=%v", userErr, eventErr)
				}
			}
			// An append that fails after writing its first event is a savepoint: the
			// caller may catch the conflict and still commit an unrelated user.
			mustEvent(t, s.WithTx(ctx, func(tx store.Store) error {
				err := tx.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "new"}, {TenantID: "t", ID: "e"}})
				if !errors.Is(err, store.ErrConflict) {
					t.Fatalf("duplicate: %v", err)
				}
				return tx.Users().Create(ctx, &store.User{TenantID: "t", UserID: "caught"})
			}))
			if _, err := s.Events().GetEvent(ctx, "t", "new"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("partial append", err)
			}
			_, err := s.Users().Get(ctx, "t", "caught")
			mustEvent(t, err)
		})
	}
}

func TestEventsConcurrentWritersSettled(t *testing.T) {
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
			a.eventsClock = clock
			b.eventsClock = clock
			inserted := make(chan struct{})
			release := make(chan struct{})
			first := make(chan error, 1)
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			go func() {
				first <- a.WithTx(ctx, func(tx store.Store) error {
					if err := tx.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "first", Time: base, Body: []byte(`{"writer":1}`)}}); err != nil {
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
				second <- b.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "second", Time: base, Body: []byte(`{"writer":2}`)}})
			}()
			<-secondStarted
			tick.Store(10)
			var checkpoint int64
			seen := map[int64]bool{}
			poll := func() {
				t.Helper()
				rows, err := reader.Events().EventsAfter(ctx, "t", checkpoint, nil, 1, clock().Add(-2*time.Second))
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

func TestEventsBackwardsClock(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			base := time.Now().UTC()
			now := base.Add(10 * time.Second)
			s.eventsClock = func() time.Time { return now }
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			mustEvent(t, s.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "first", Time: base}}))
			now = base
			mustEvent(t, s.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "second", Time: base}, {TenantID: "t", ID: "third", Time: base}}))
			rows, err := s.Events().EventsAfter(ctx, "t", 0, nil, 100, base.Add(time.Second))
			mustEvent(t, err)
			if len(rows) != 0 {
				t.Fatalf("later sequence settled ahead of earlier: %v", rows)
			}
			rows, err = s.Events().EventsAfter(ctx, "t", 0, nil, 100, base.Add(20*time.Second))
			mustEvent(t, err)
			if len(rows) != 3 {
				t.Fatalf("lost events: %v", rows)
			}
		})
	}
}

func TestEventsLeaseAndDeliveryGuards(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			now := time.Now().UTC()
			s.eventsClock = func() time.Time { return now }
			r := s.Events()
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			mustEvent(t, r.CreateEventStream(ctx, &store.EventStream{TenantID: "t", ID: "s", Name: "stream", Status: "enabled", Config: map[string]any{"big": json.Number("9007199254740993")}}))
			if _, err := r.LeaseEventStream(ctx, "owner", now, now.Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("idle stream leased", err)
			}
			es := []store.TenantEvent{{TenantID: "t", ID: "e", Type: "user.created", Time: now}}
			mustEvent(t, r.AppendEvents(ctx, es))
			leased, err := r.LeaseEventStream(ctx, "owner", now, now.Add(time.Minute))
			mustEvent(t, err)
			if leased.Config["big"] != json.Number("9007199254740993") {
				t.Fatalf("lost config precision: %v", leased.Config)
			}
			// Same-owner renewal works while another owner cannot steal an active lease.
			_, err = r.LeaseEventStream(ctx, "owner", now, now.Add(2*time.Minute))
			mustEvent(t, err)
			if _, err := r.LeaseEventStream(ctx, "other", now, now.Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
				t.Fatal(err)
			}
			d := &store.EventDelivery{TenantID: "foreign", StreamID: "s", EventID: "e", Status: "failed"}
			if err := r.RecordEventDelivery(ctx, "t", "s", "owner", store.DeliveryOutcome{Checkpoint: es[0].Seq, Failed: d}); !errors.Is(err, store.ErrInvalid) {
				t.Fatal("foreign failed identity", err)
			}
			d.TenantID = "t"
			d.StreamID = "foreign"
			if err := r.RecordEventDelivery(ctx, "t", "s", "owner", store.DeliveryOutcome{Failed: d}); !errors.Is(err, store.ErrInvalid) {
				t.Fatal(err)
			}
			d.StreamID = "s"
			d.Status = "success"
			if err := r.RecordEventDelivery(ctx, "t", "s", "owner", store.DeliveryOutcome{Failed: d}); !errors.Is(err, store.ErrInvalid) {
				t.Fatal(err)
			}
			d.Status = "failed"
			d.EventType = "user.created"
			d.EventTime = now
			d.Attempts = []store.DeliveryAttempt{{Status: "failed", Timestamp: now}}
			mustEvent(t, r.RecordEventDelivery(ctx, "t", "s", "owner", store.DeliveryOutcome{Checkpoint: es[0].Seq, Failed: d, ConsecutiveFailures: 1, TotalFailures: 1, Disable: true}))
			if err := r.RecordEventDelivery(ctx, "t", "s", "owner", store.DeliveryOutcome{Checkpoint: es[0].Seq - 1}); !errors.Is(err, store.ErrPrecondition) {
				t.Fatal("checkpoint regression", err)
			}
			// Disabled streams ignore fresh events but queued failures remain leasable.
			now = now.Add(3 * time.Minute)
			mustEvent(t, r.AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "new", Time: now}}))
			if _, err := r.LeaseEventStream(ctx, "other", now, now.Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("disabled new event leased", err)
			}
			n, err := r.QueueRedelivery(ctx, "t", "s", []string{"e", "e"}, nil)
			mustEvent(t, err)
			if n != 1 {
				t.Fatal(n)
			}
			_, err = r.LeaseEventStream(ctx, "other", now, now.Add(time.Minute))
			mustEvent(t, err)
			if err := r.RecordEventDelivery(ctx, "t", "s", "owner", store.DeliveryOutcome{Checkpoint: es[0].Seq}); !errors.Is(err, store.ErrPrecondition) {
				t.Fatal("lost owner", err)
			}
			mustEvent(t, r.RecordEventDelivery(ctx, "t", "s", "other", store.DeliveryOutcome{Checkpoint: es[0].Seq, Succeeded: []string{"e"}}))
			v, err := r.GetEventStream(ctx, "t", "s")
			mustEvent(t, err)
			if v.TotalFailures != 0 || v.ConsecutiveFailures != 0 || v.Status != "disabled" {
				t.Fatalf("failure counters after redelivery: %+v", v)
			}
			if _, err := r.GetDelivery(ctx, "t", "s", "e"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal(err)
			}
			now = now.Add(time.Minute)
			if err := r.RecordEventDelivery(ctx, "t", "s", "other", store.DeliveryOutcome{Checkpoint: es[0].Seq}); !errors.Is(err, store.ErrPrecondition) {
				t.Fatal("expired lease", err)
			}
		})
	}
}

func TestEventsTenantDeletionAndBoundedPurge(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			now := time.Now().UTC()
			r := s.Events()
			for _, tid := range []string{"a", "b"} {
				mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}))
				mustEvent(t, r.CreateEventStream(ctx, &store.EventStream{TenantID: tid, ID: "s", Name: "stream", Status: "enabled"}))
				es := []store.TenantEvent{{TenantID: tid, ID: "old", Time: now.Add(-time.Hour)}, {TenantID: tid, ID: "new", Time: now.Add(time.Hour)}}
				mustEvent(t, r.AppendEvents(ctx, es))
				_, err := r.LeaseEventStream(ctx, tid, now, now.Add(time.Minute))
				mustEvent(t, err)
				mustEvent(t, r.RecordEventDelivery(ctx, tid, "s", tid, store.DeliveryOutcome{Checkpoint: es[0].Seq, Failed: &store.EventDelivery{TenantID: tid, StreamID: "s", EventID: "old", EventTime: es[0].Time, Status: "failed"}}))
			}
			n, err := r.PurgeEvents(ctx, now, 1)
			mustEvent(t, err)
			if n != 1 {
				t.Fatal(n)
			}
			var events, deliveries int
			mustEvent(t, s.queryRow(ctx, `SELECT COUNT(*) FROM tenant_events WHERE event_time<?`, logTime(now)).Scan(&events))
			mustEvent(t, s.queryRow(ctx, `SELECT COUNT(*) FROM event_deliveries`).Scan(&deliveries))
			if events != 1 || deliveries != 1 {
				t.Fatalf("batch exceeded or orphaned deliveries events=%d deliveries=%d", events, deliveries)
			}
			mustEvent(t, s.Tenants().Delete(ctx, "a"))
			for _, table := range []string{"tenant_events", "event_streams", "event_deliveries", "event_cursor_watermarks"} {
				var count int
				mustEvent(t, s.queryRow(ctx, `SELECT COUNT(*) FROM `+table+` WHERE tenant_id=?`, "a").Scan(&count))
				if count != 0 {
					t.Fatal("tenant cleanup", table, count)
				}
			}
			_, err = r.GetEvent(ctx, "b", "new")
			mustEvent(t, err)
			n, err = r.PurgeEvents(ctx, now, 100)
			mustEvent(t, err)
			if n < 0 || n > 1 {
				t.Fatal(n)
			}
			_, err = r.GetEvent(ctx, "b", "new")
			mustEvent(t, err)
		})
	}
}

// Expiry is evaluated after tenant/stream locks, rather than before waiting.
func TestEventsDeliveryExpiryAfterTransactionWait(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			base := time.Now().UTC()
			var tick atomic.Int64
			s.eventsClock = func() time.Time { return base.Add(time.Duration(tick.Load()) * time.Second) }
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			mustEvent(t, s.Events().CreateEventStream(ctx, &store.EventStream{TenantID: "t", ID: "s", Name: "stream", Status: "enabled"}))
			mustEvent(t, s.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "e", Time: base}}))
			_, err := s.Events().LeaseEventStream(ctx, "owner", base, base.Add(time.Second))
			mustEvent(t, err)
			mustEvent(t, s.WithTx(ctx, func(tx store.Store) error {
				st := tx.(*Store)
				entered := make(chan struct{})
				resume := make(chan struct{})
				st.q = &logDeliveryGate{querier: st.q, entered: entered, resume: resume}
				done := make(chan error, 1)
				go func() {
					done <- tx.Events().RecordEventDelivery(ctx, "t", "s", "owner", store.DeliveryOutcome{Checkpoint: 1})
				}()
				<-entered
				tick.Store(2)
				close(resume)
				if err := <-done; !errors.Is(err, store.ErrPrecondition) {
					t.Fatalf("accepted expired lease: %v", err)
				}
				return nil
			}))
		})
	}
}

// A purge batch is selected before it obtains tenant locks. Another purge can
// remove a candidate during that gap; a subsequently inserted event with the
// same ID is a different sequence and its deliveries must remain untouched.
func TestEventsPurgeStaleCandidate(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			now := time.Now().UTC()
			r := s.Events()
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			mustEvent(t, r.CreateEventStream(ctx, &store.EventStream{TenantID: "t", ID: "s", Name: "stream", Status: "enabled"}))
			mustEvent(t, r.AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "same", Time: now.Add(-time.Hour)}}))
			mustEvent(t, s.WithTx(ctx, func(tx store.Store) error {
				st := tx.(*Store)
				// Inject the completed competing purge/reinsert at the lock boundary. Using
				// this transaction makes the schedule deterministic on SQLite too, where an
				// IMMEDIATE transaction already excludes a concurrent writer.
				st.q = &eventPurgeReplacement{querier: st.q, t: t, s: st, ctx: ctx, now: now}
				n, err := tx.Events().PurgeEvents(ctx, now, 1)
				if err != nil {
					return err
				}
				if n != 0 {
					t.Fatalf("deleted replacement event: %d", n)
				}
				_, err = tx.Events().GetEvent(ctx, "t", "same")
				if err != nil {
					return err
				}
				_, err = tx.Events().GetDelivery(ctx, "t", "s", "same")
				if err != nil {
					t.Fatalf("stale batch deleted replacement delivery: %v", err)
				}
				return nil
			}))
		})
	}
}

type eventPurgeReplacement struct {
	querier
	once sync.Once
	t    *testing.T
	s    *Store
	ctx  context.Context
	now  time.Time
}

func (g *eventPurgeReplacement) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	if strings.Contains(q, "SELECT id FROM tenants WHERE id=") {
		g.once.Do(func() {
			// Use the underlying querier so the replacement does not recurse through
			// this lock hook. Old candidate rows have already been read and closed.
			exec := func(q string, args ...any) {
				_, err := g.querier.ExecContext(g.ctx, g.s.d.rebind(q), args...)
				mustEvent(g.t, err)
			}
			exec(`DELETE FROM tenant_events WHERE tenant_id=? AND event_id=?`, "t", "same")
			exec(`INSERT INTO tenant_events (tenant_id,event_id,type,event_time,committed_at,body) VALUES (?,?,?,?,?,?)`, "t", "same", "user.created", logTime(g.now.Add(time.Hour)), logTime(g.now), []byte(`{}`))
			exec(`INSERT INTO event_deliveries (`+eventDeliveryCols+`) VALUES (?,?,?,?,?,?,?,?,?)`, "t", "s", "same", "user.created", "failed", "[]", false, logTime(g.now.Add(time.Hour)), logTime(g.now))
		})
	}
	return g.querier.QueryRowContext(ctx, q, args...)
}

// A count used to enforce a tenant stream quota must serialize with other
// transactional quota checks, including while the first stream table is empty.
func TestEventStreamCountSerializesCreateQuota(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := fresh(t)
			ctx := t.Context()
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "quota", Name: "quota"}))
			counted := make(chan struct{})
			release := make(chan struct{})
			first := make(chan error, 1)
			go func() {
				first <- s.WithTx(ctx, func(tx store.Store) error {
					n, err := tx.Events().CountEventStreams(ctx, "quota")
					if err != nil {
						return err
					}
					if n != 0 {
						return store.ErrInvalid
					}
					close(counted)
					<-release
					return tx.Events().CreateEventStream(ctx, &store.EventStream{TenantID: "quota", ID: "one", Name: "one", Status: "enabled", DestType: "action", Config: map[string]any{}})
				})
			}()
			select {
			case <-counted:
			case err := <-first:
				t.Fatal(err)
			case <-time.After(10 * time.Second):
				t.Fatal("first quota check did not start")
			}
			second := make(chan error, 1)
			go func() {
				second <- s.WithTx(ctx, func(tx store.Store) error {
					n, err := tx.Events().CountEventStreams(ctx, "quota")
					if err != nil {
						return err
					}
					if n >= 1 {
						return store.ErrConflict
					}
					return tx.Events().CreateEventStream(ctx, &store.EventStream{TenantID: "quota", ID: "two", Name: "two", Status: "enabled", DestType: "action", Config: map[string]any{}})
				})
			}()
			var early error
			completed := false
			select {
			case early = <-second:
				completed = true
			case <-time.After(150 * time.Millisecond):
			}
			close(release)
			mustEvent(t, <-first)
			if completed {
				t.Fatalf("quota check did not wait for tenant transaction: %v", early)
			}
			if err := <-second; !errors.Is(err, store.ErrConflict) {
				t.Fatalf("quota must reject second create: %v", err)
			}
			n, err := s.Events().CountEventStreams(ctx, "quota")
			mustEvent(t, err)
			if n != 1 {
				t.Fatalf("quota exceeded: %d", n)
			}
		})
	}
}

// Exercise the actual Management handler against an append whose commit is
// delayed. Once enabling succeeds, that disabled-period event must be skipped;
// a later append must still be eligible for delivery.
func TestEventStreamEnableCheckpointSerializesAppend(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := fresh(t)
			ctx := t.Context()
			tn := &store.Tenant{ID: "resume", Name: "resume"}
			mustEvent(t, s.Tenants().Create(ctx, tn))
			id := "est_1234567890123456789012"
			mustEvent(t, s.Events().CreateEventStream(ctx, &store.EventStream{TenantID: tn.ID, ID: id, Name: "Resume", Status: "disabled", DestType: "webhook", Config: map[string]any{"webhook_endpoint": "https://collector.example.test/events", "webhook_authorization": map[string]any{"method": "bearer"}}, ConsecutiveFailures: 8, TotalFailures: 42}))
			appended := make(chan struct{})
			release := make(chan struct{})
			appendDone := make(chan error, 1)
			go func() {
				appendDone <- s.WithTx(ctx, func(tx store.Store) error {
					if err := tx.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: tn.ID, ID: "before-enable", Time: time.Now()}}); err != nil {
						return err
					}
					close(appended)
					<-release
					return nil
				})
			}()
			select {
			case <-appended:
			case err := <-appendDone:
				t.Fatal(err)
			case <-time.After(10 * time.Second):
				t.Fatal("append did not start")
			}
			h := &mgmt.Handlers{Store: s}
			r := httptest.NewRequest("PATCH", "/api/v2/event-streams/"+id, strings.NewReader(`{"status":"enabled"}`))
			r = r.WithContext(tenant.WithResolved(ctx, tenant.Resolved{Tenant: tn, Host: "example.test"}))
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { h.UpdateEventStream(w, r, id); close(done) }()
			select {
			case <-done:
				close(release)
				mustEvent(t, <-appendDone)
				t.Fatal("enable passed uncommitted append", w.Code, w.Body)
			case <-time.After(150 * time.Millisecond):
			}
			close(release)
			mustEvent(t, <-appendDone)
			<-done
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			stream, err := s.Events().GetEventStream(ctx, tn.ID, id)
			mustEvent(t, err)
			if stream.Checkpoint != 1 || stream.ConsecutiveFailures != 0 || stream.TotalFailures != 42 {
				t.Fatalf("disabled history retained: %+v", stream)
			}
			mustEvent(t, s.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: tn.ID, ID: "after-enable", Time: time.Now()}}))
			events, err := s.Events().EventsAfter(ctx, tn.ID, stream.Checkpoint, nil, 10, time.Now().Add(time.Hour))
			mustEvent(t, err)
			if len(events) != 1 || events[0].ID != "after-enable" {
				t.Fatalf("eligibility after enabling: %+v", events)
			}
		})
	}
}

func TestEventsWatermarkUpgradeFrom31(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			dsn := mk(t)
			s := openAtVersion(t, dsn, 31)
			ctx := t.Context()
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "legacy", Name: "legacy"}))
			mustEvent(t, s.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "legacy", ID: "before", Time: time.Now()}}))
			mustEvent(t, s.Migrate(ctx))
			var n int
			err := s.queryRow(ctx, `SELECT COUNT(*) FROM event_cursor_watermarks`).Scan(&n)
			mustEvent(t, err)
			if n != 0 {
				t.Fatal("migration invented missing history")
			}
			type floorRepo interface {
				PurgedEventSeq(context.Context, string) (int64, error)
			}
			f, ok := s.Events().(floorRepo)
			if !ok {
				t.Fatal("missing durable floor")
			}
			seq, err := f.PurgedEventSeq(ctx, "legacy")
			mustEvent(t, err)
			if seq != 0 {
				t.Fatal(seq)
			}
			row, err := s.Events().GetEvent(ctx, "legacy", "before")
			mustEvent(t, err)
			_, err = s.Events().PurgeEvents(ctx, time.Now().Add(time.Hour), 10)
			mustEvent(t, err)
			reopened, err := Open(ctx, dsn)
			mustEvent(t, err)
			defer reopened.Close()
			seq, err = reopened.Events().(floorRepo).PurgedEventSeq(ctx, "legacy")
			mustEvent(t, err)
			if seq != row.Seq {
				t.Fatalf("reopened floor=%d want=%d", seq, row.Seq)
			}
			fresh := mustOpen(t, mk(t))
			if !slices.Equal(tableShape(t, s, "event_cursor_watermarks"), tableShape(t, fresh, "event_cursor_watermarks")) {
				t.Fatal("upgrade table differs")
			}
		})
	}
}

func TestEventsWatermarkMySQLResume32(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		if name != "mysql" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 31)
			ms, err := s.migrations()
			mustEvent(t, err)
			for _, m := range ms {
				if m.version == 32 {
					// MySQL DDL committed, then the process died before the version marker.
					_, err = s.exec(t.Context(), m.statements[0])
					mustEvent(t, err)
				}
			}
			version, err := s.SchemaVersion(t.Context())
			mustEvent(t, err)
			if version != 31 {
				t.Fatal(version)
			}
			mustEvent(t, s.Migrate(t.Context()))
			mustEvent(t, s.Migrate(t.Context()))
			version, err = s.SchemaVersion(t.Context())
			mustEvent(t, err)
			if version != 32 {
				t.Fatal(version)
			}
			n, err := s.Events().PurgedEventSeq(t.Context(), "unknown")
			mustEvent(t, err)
			if n != 0 {
				t.Fatal(n)
			}
		})
	}
}
