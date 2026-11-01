package grpcstore

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// Exercise a real server and transport, selectively making Events methods look
// like an older or restarting plugin without replacing any earlier feature.
type eventsFaults struct {
	appendCode    atomic.Int32
	versionZero   atomic.Bool
	missing       bool
	probeCode     atomic.Int32
	operationCode atomic.Int32
}

func serveEventsFaults(t *testing.T, backing store.Store, faults *eventsFaults) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		name := strings.TrimPrefix(info.FullMethod, "/zeroauthy.store.v1.StoreService/")
		if name == "EventsCapabilities" {
			if faults.versionZero.Load() {
				return &storev1.EventsCapabilitiesResult{}, nil
			}
			if faults.missing {
				return nil, status.Error(codes.Unimplemented, "pre-Events plugin")
			}
			if code := codes.Code(faults.probeCode.Swap(0)); code != codes.OK {
				return nil, status.Error(code, "probe failure")
			}
		}
		if name == "AppendEvents" {
			if code := codes.Code(faults.appendCode.Swap(0)); code != codes.OK {
				return nil, status.Error(code, "append failure")
			}
		}
		if name == "GetEvent" {
			if code := codes.Code(faults.operationCode.Swap(0)); code != codes.OK {
				return nil, status.Error(code, "operation failure")
			}
		}
		return handler(ctx, req)
	}))
	srv := NewServer(backing)
	storev1.RegisterStoreServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(conn, func() error {
		err := conn.Close()
		srv.Close()
		gs.Stop()
		_ = lis.Close()
		_ = backing.Close()
		return err
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func TestEventsCapabilities(t *testing.T) {
	ctx := context.Background()
	for _, missing := range []bool{false, true} {
		name := "v1"
		if missing {
			name = "preEvents"
		}
		t.Run(name, func(t *testing.T) {
			faults := &eventsFaults{missing: missing}
			c := serveEventsFaults(t, memory.New(), faults)
			if got := c.EventsSupported(); got == missing {
				t.Fatalf("EventsSupported=%v, missing=%v", got, missing)
			}
			err := c.CheckEventsSupport(ctx)
			if missing {
				if !errors.Is(err, store.ErrEventsUnavailable) {
					t.Fatal(err)
				}
				for i, call := range eventsUnavailableCalls(ctx) {
					if err := call(c.Events()); !errors.Is(err, store.ErrEventsUnavailable) {
						t.Fatalf("operation %d: %v", i, err)
					}
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := c.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "e", Type: "user.created", Time: time.Now(), Body: []byte(`{}`)}}); err != nil {
					t.Fatal(err)
				}
				if got, err := c.Events().GetEvent(ctx, "t", "e"); err != nil || string(got.Body) != "{}" {
					t.Fatalf("event=%+v err=%v", got, err)
				}
			}
			if err := c.WithTx(ctx, func(tx store.Store) error {
				if tx.(store.EventsSupporter).EventsSupported() == missing {
					return errors.New("transaction capability differs")
				}
				err := tx.Events().AppendEvents(ctx, nil)
				if missing && errors.Is(err, store.ErrEventsUnavailable) {
					return nil
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("transient", func(t *testing.T) {
		faults := &eventsFaults{}
		c := serveEventsFaults(t, memory.New(), faults)
		faults.probeCode.Store(int32(codes.Unavailable))
		if c.EventsSupported() {
			t.Fatal("unreachable plugin reported support")
		}
		if !c.EventsSupported() {
			t.Fatal("transient absence was cached")
		}
		faults.probeCode.Store(int32(codes.Unavailable))
		if err := c.Events().AppendEvents(ctx, nil); err == nil || errors.Is(err, store.ErrEventsUnavailable) {
			t.Fatalf("transient probe: %v", err)
		}
		if err := c.Events().AppendEvents(ctx, nil); err != nil {
			t.Fatalf("probe recovery: %v", err)
		}
		faults.operationCode.Store(int32(codes.Unavailable))
		if _, err := c.Events().GetEvent(ctx, "t", "missing"); err == nil || errors.Is(err, store.ErrEventsUnavailable) {
			t.Fatalf("transient operation: %v", err)
		}
		if _, err := c.Events().GetEvent(ctx, "t", "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("operation recovery: %v", err)
		}
		faults.operationCode.Store(int32(codes.Unimplemented))
		if _, err := c.Events().GetEvent(ctx, "t", "missing"); !errors.Is(err, store.ErrEventsUnavailable) {
			t.Fatalf("unknown method: %v", err)
		}
		if c.EventsSupported() {
			t.Fatal("unknown method not cached as definitive")
		}
		if err := c.CheckEventsSupport(ctx); err != nil || !c.EventsSupported() {
			t.Fatalf("explicit recovery: %v", err)
		}
	})
}
func eventsUnavailableCalls(ctx context.Context) []func(store.Events) error {
	return []func(store.Events) error{
		func(r store.Events) error { return r.AppendEvents(ctx, nil) },
		func(r store.Events) error { _, e := r.GetEvent(ctx, "t", "e"); return e },
		func(r store.Events) error { _, e := r.EventsAfter(ctx, "t", 0, nil, 1, time.Now()); return e },
		func(r store.Events) error {
			_, e := r.EventsFromTime(ctx, "t", time.Now(), nil, 1, time.Now())
			return e
		},
		func(r store.Events) error { _, e := r.LatestEventSeq(ctx, "t"); return e },
		func(r store.Events) error { _, e := r.OldestEventSeq(ctx, "t"); return e },
		func(r store.Events) error { _, e := r.PurgeEvents(ctx, time.Now(), 1); return e },
		func(r store.Events) error { return r.DeleteTenantEvents(ctx, "t") },
		func(r store.Events) error { return r.CreateEventStream(ctx, &store.EventStream{}) },
		func(r store.Events) error { _, e := r.GetEventStream(ctx, "t", "s"); return e },
		func(r store.Events) error { _, _, e := r.ListEventStreams(ctx, "t", "", 1); return e },
		func(r store.Events) error { _, e := r.CountEventStreams(ctx, "t"); return e },
		func(r store.Events) error { return r.UpdateEventStream(ctx, &store.EventStream{}, 1) },
		func(r store.Events) error { return r.DeleteEventStream(ctx, "t", "s") },
		func(r store.Events) error {
			_, e := r.LeaseEventStream(ctx, "owner", time.Now(), time.Now().Add(time.Hour))
			return e
		},
		func(r store.Events) error {
			return r.RecordEventDelivery(ctx, "t", "s", "owner", store.DeliveryOutcome{})
		},
		func(r store.Events) error {
			_, _, e := r.ListDeliveries(ctx, "t", "s", store.DeliveryFilter{}, "", 1)
			return e
		},
		func(r store.Events) error { _, e := r.GetDelivery(ctx, "t", "s", "e"); return e },
		func(r store.Events) error { _, e := r.QueueRedelivery(ctx, "t", "s", nil, nil); return e },
		func(r store.Events) error { _, e := r.QueuedDeliveries(ctx, "t", "s", 1); return e },
	}
}

func TestEventsPrePluginPriorFeatures(t *testing.T) {
	names := make([]string, 0, len(storetest.Suites))
	for name := range storetest.Suites {
		if name != "Events" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	storetest.RunSuites(t, func(t *testing.T) store.Store {
		m := memory.New()
		c := serveEventsFaults(t, m, &eventsFaults{missing: true})
		if !errors.Is(c.CheckEventsSupport(context.Background()), store.ErrEventsUnavailable) {
			t.Fatal("old plugin advertises Events")
		}
		return limitForwarder{c, m}
	}, names...)
}
func TestEventsPluginRoundTrip(t *testing.T) {
	for name, f := range map[string]func(*testing.T) *Client{"memory": inProcess, "sqlite": inProcessSQLite} {
		t.Run(name, func(t *testing.T) { storetest.RunSuites(t, func(t *testing.T) store.Store { return f(t) }, "Events") })
	}
}
func TestEventsRemoteTxRollback(t *testing.T) {
	for name, f := range map[string]func(*testing.T) *Client{"memory": inProcess, "sqlite": inProcessSQLite} {
		t.Run(name, func(t *testing.T) {
			c := f(t)
			defer c.Close()
			ctx := context.Background()
			if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			abort := errors.New("abort business transaction")
			for _, rollback := range []bool{true, false} {
				err := c.WithTx(ctx, func(tx store.Store) error {
					if err := tx.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "c", Name: "business"}); err != nil {
						return err
					}
					if err := tx.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "e", Type: "user.created", Time: time.Now(), Body: []byte(`{}`)}}); err != nil {
						return err
					}
					if _, err := tx.Events().GetEvent(ctx, "t", "e"); err != nil {
						return err
					}
					if rollback {
						return abort
					}
					return nil
				})
				if rollback {
					if !errors.Is(err, abort) {
						t.Fatal(err)
					}
					if _, err := c.Clients().Get(ctx, "t", "c"); !errors.Is(err, store.ErrNotFound) {
						t.Fatalf("business leaked: %v", err)
					}
					if _, err := c.Events().GetEvent(ctx, "t", "e"); !errors.Is(err, store.ErrNotFound) {
						t.Fatalf("event leaked: %v", err)
					}
					if seq, err := c.Events().LatestEventSeq(ctx, "t"); err != nil || seq != 0 {
						t.Fatalf("sequence leaked: %d %v", seq, err)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if _, err := c.Clients().Get(ctx, "t", "c"); err != nil {
						t.Fatal(err)
					}
					if _, err := c.Events().GetEvent(ctx, "t", "e"); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestEventsAssignedFields(t *testing.T) {
	for name, f := range map[string]func(*testing.T) *Client{"memory": inProcess, "sqlite": inProcessSQLite} {
		t.Run(name, func(t *testing.T) {
			c := f(t)
			defer c.Close()
			ctx := context.Background()
			if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			es := []store.TenantEvent{{TenantID: "t", ID: "e", Type: "user.created", Time: time.Now(), Body: []byte(`{}`)}}
			if err := c.Events().AppendEvents(ctx, es); err != nil {
				t.Fatal(err)
			}
			got, err := c.Events().GetEvent(ctx, "t", "e")
			if err != nil || es[0].Seq == 0 || es[0].Seq != got.Seq {
				t.Fatalf("assigned sequence: input=%+v persisted=%+v error=%v", es, got, err)
			}
			s := &store.EventStream{TenantID: "t", ID: "s", Name: "stream", Status: "enabled"}
			if err := c.Events().CreateEventStream(ctx, s); err != nil {
				t.Fatal(err)
			}
			if s.Version != 1 {
				t.Fatalf("create version=%d", s.Version)
			}
			if err := c.Events().UpdateEventStream(ctx, s, s.Version); err != nil {
				t.Fatal(err)
			}
			if s.Version != 2 {
				t.Fatalf("update version=%d", s.Version)
			}
		})
	}
}

func TestEventsCapabilityVersionChanges(t *testing.T) {
	ctx := context.Background()
	faults := &eventsFaults{}
	faults.versionZero.Store(true)
	c := serveEventsFaults(t, memory.New(), faults)
	if c.EventsSupported() {
		t.Fatal("version zero advertised support")
	}
	if err := c.Events().AppendEvents(ctx, nil); !errors.Is(err, store.ErrEventsUnavailable) {
		t.Fatal(err)
	}
	faults.versionZero.Store(false)
	if err := c.Events().AppendEvents(ctx, nil); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if !c.EventsSupported() {
		t.Fatal("upgrade retained cached absence")
	}
	faults.versionZero.Store(true)
	if err := c.Events().AppendEvents(ctx, nil); !errors.Is(err, store.ErrEventsUnavailable) {
		t.Fatalf("downgrade: %v", err)
	}
	if c.EventsSupported() {
		t.Fatal("downgrade retained cached support")
	}
}

type eventsBackend struct {
	store.Store
	repo store.Events
}

func (b eventsBackend) Events() store.Events { return b.repo }

type eventsDeclaredBackend struct {
	eventsBackend
	support  bool
	probeErr error
}

func (b eventsDeclaredBackend) CheckEventsSupport(context.Context) error { return b.probeErr }
func (b eventsDeclaredBackend) EventsSupported() bool                    { return b.support }
func TestEventsBackendCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend store.Store
		want    bool
		wantErr error
	}{
		{"stub", eventsBackend{memory.New(), store.UnimplementedEvents{}}, false, store.ErrEventsUnavailable},
		{"stubPointer", eventsBackend{memory.New(), &store.UnimplementedEvents{}}, false, store.ErrEventsUnavailable},
		{"undeclared", eventsBackend{memory.New(), &eventsEcho{}}, true, nil},
		{"declaredUnavailable", eventsDeclaredBackend{eventsBackend{memory.New(), &eventsEcho{}}, false, store.ErrEventsUnavailable}, false, store.ErrEventsUnavailable},
		{"declaredFalse", eventsDeclaredBackend{eventsBackend{memory.New(), &eventsEcho{}}, false, nil}, false, store.ErrEventsUnavailable},
		{"declaredTransient", eventsDeclaredBackend{eventsBackend{memory.New(), &eventsEcho{}}, true, errors.New("backend transient")}, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := serve(t, tc.backend)
			defer c.Close()
			err := c.CheckEventsSupport(context.Background())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatal(err)
				}
			} else if tc.want && err != nil {
				t.Fatal(err)
			} else if !tc.want && (err == nil || errors.Is(err, store.ErrEventsUnavailable)) {
				t.Fatalf("transient became definitive: %v", err)
			}
			if got := c.EventsSupported(); got != tc.want {
				t.Fatalf("support=%v want=%v", got, tc.want)
			}
		})
	}
	if !errors.Is(errFromPB(errToPB(store.ErrEventsUnavailable)), store.ErrEventsUnavailable) {
		t.Fatal("unavailable sentinel lost")
	}
}

type eventsEcho struct {
	store.UnimplementedEvents
	event   store.TenantEvent
	stream  store.EventStream
	outcome store.DeliveryOutcome
	filter  *store.DeliveryFilter
}

func (r *eventsEcho) AppendEvents(_ context.Context, v []store.TenantEvent) error {
	r.event = v[0]
	return nil
}
func (r *eventsEcho) GetEvent(context.Context, string, string) (*store.TenantEvent, error) {
	return &r.event, nil
}
func (r *eventsEcho) CreateEventStream(_ context.Context, v *store.EventStream) error {
	r.stream = *v
	return nil
}
func (r *eventsEcho) GetEventStream(context.Context, string, string) (*store.EventStream, error) {
	return &r.stream, nil
}
func (r *eventsEcho) RecordEventDelivery(_ context.Context, _, _, _ string, v store.DeliveryOutcome) error {
	r.outcome = v
	return nil
}
func (r *eventsEcho) GetDelivery(context.Context, string, string, string) (*store.EventDelivery, error) {
	return r.outcome.Failed, nil
}
func (r *eventsEcho) QueueRedelivery(_ context.Context, _, _ string, _ []string, f *store.DeliveryFilter) (int, error) {
	r.filter = f
	return 0, nil
}
func TestEventsLosslessRoundTrip(t *testing.T) {
	ctx := context.Background()
	repo := &eventsEcho{}
	c := serve(t, eventsBackend{memory.New(), repo})
	defer c.Close()
	at := time.Date(0, 1, 1, 0, 0, 0, 123, time.UTC)
	for i, b := range [][]byte{nil, {}, []byte(`{"integer":9007199254740993}`)} {
		e := store.TenantEvent{TenantID: "t", ID: "e", Type: "user.created", Seq: math.MaxInt64, Time: at, Body: b}
		if err := c.Events().AppendEvents(ctx, []store.TenantEvent{e}); err != nil {
			t.Fatal(err)
		}
		got, err := c.Events().GetEvent(ctx, "t", "e")
		if err != nil || !reflect.DeepEqual(*got, e) {
			t.Fatalf("event=%#v want=%#v err=%v", got, e, err)
		}
		stream := store.EventStream{TenantID: "t", ID: "s", Name: "n", Status: "enabled", DestType: "webhook", Subscriptions: []string{"user.created", "user.updated"}, Config: map[string]any{"number": json.Number("9007199254740993"), "nested": []any{json.Number("12345678901234567890.123456789")}}, SealedSecret: b, Checkpoint: math.MaxInt64, LeaseOwner: "owner", LeaseUntil: at, ConsecutiveFailures: 123, TotalFailures: 456, Version: 789, CreatedAt: time.Time{}, UpdatedAt: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)}
		if i == 0 {
			stream.Subscriptions = nil
			stream.Config = nil
		}
		if i == 1 {
			stream.Subscriptions = []string{}
			stream.Config = map[string]any{}
		}
		if err := c.Events().CreateEventStream(ctx, &stream); err != nil {
			t.Fatal(err)
		}
		gotStream, err := c.Events().GetEventStream(ctx, "t", "s")
		if err != nil || !reflect.DeepEqual(*gotStream, stream) {
			t.Fatalf("stream=%#v want=%#v err=%v", gotStream, stream, err)
		}
		d := &store.EventDelivery{TenantID: "t", StreamID: "s", EventID: "e", EventType: "user.created", Status: "failed", Attempts: []store.DeliveryAttempt{{Status: "failed", Timestamp: at, ErrorMessage: "timeout", DurationMS: math.Float64frombits(0x400921fb54442d18)}}, Queued: true, EventTime: time.Time{}, UpdatedAt: time.Unix(0, 0).UTC()}
		if i == 0 {
			d.Attempts = nil
		}
		if i == 1 {
			d.Attempts = []store.DeliveryAttempt{}
		}
		outcome := store.DeliveryOutcome{Checkpoint: math.MaxInt64, Failed: d, Succeeded: []string{"e2"}, ConsecutiveFailures: 123, TotalFailures: 456, Disable: true}
		if err := c.Events().RecordEventDelivery(ctx, "t", "s", "owner", outcome); err != nil {
			t.Fatal(err)
		}
		gotDelivery, err := c.Events().GetDelivery(ctx, "t", "s", "e")
		if err != nil || !reflect.DeepEqual(gotDelivery, d) || !reflect.DeepEqual(repo.outcome, outcome) {
			t.Fatalf("delivery=%#v outcome=%#v want=%#v err=%v", gotDelivery, repo.outcome, outcome, err)
		}
	}
	for _, f := range []*store.DeliveryFilter{nil, {}, {Statuses: []string{}, EventTypes: []string{}, From: at, To: time.Unix(0, 0).UTC()}, {Statuses: []string{"failed"}, EventTypes: []string{"user.created"}}} {
		if _, err := c.Events().QueueRedelivery(ctx, "t", "s", nil, f); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(repo.filter, f) {
			t.Fatalf("filter=%#v want=%#v", repo.filter, f)
		}
	}
}
func TestEventsCaptureNegotiation(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "transient", true: "oldPlugin"}[missing], func(t *testing.T) {
			faults := &eventsFaults{missing: missing}
			backing := memory.New()
			c := serveEventsFaults(t, backing, faults)
			ctx := context.Background()
			if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t", CanonicalHost: "t.example"}); err != nil {
				t.Fatal(err)
			}
			wrapped := events.Wrap(c, events.DefaultConfig())
			user := &store.User{TenantID: "t", UserID: "auth0|u", Email: "u@example.test"}
			if !missing {
				faults.probeCode.Store(int32(codes.Unavailable))
				if err := wrapped.Users().Create(ctx, user); err == nil || errors.Is(err, store.ErrEventsUnavailable) {
					t.Fatalf("transient mutation: %v", err)
				}
				if _, err := c.Users().Get(ctx, "t", user.UserID); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("unrecorded user: %v", err)
				}
			}
			if err := wrapped.Users().Create(ctx, user); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Users().Get(ctx, "t", user.UserID); err != nil {
				t.Fatal(err)
			}
			if missing {
				if seq, err := backing.Events().LatestEventSeq(ctx, "t"); err != nil || seq != 0 {
					t.Fatalf("old plugin captured: %d %v", seq, err)
				}
				if _, err := c.Events().LatestEventSeq(ctx, "t"); !errors.Is(err, store.ErrEventsUnavailable) {
					t.Fatal(err)
				}
			} else {
				es, err := c.Events().EventsAfter(ctx, "t", 0, nil, 10, time.Now().Add(time.Hour))
				if err != nil || len(es) != 1 || es[0].Type != "user.created" {
					t.Fatalf("recovery events=%+v err=%v", es, err)
				}
			}
		})
	}
}

func TestEventsCaptureAppendFailure(t *testing.T) {
	for _, code := range []codes.Code{codes.Unavailable, codes.Unimplemented} {
		t.Run(code.String(), func(t *testing.T) {
			faults := &eventsFaults{}
			c := serveEventsFaults(t, memory.New(), faults)
			ctx := context.Background()
			if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t", CanonicalHost: "t.example"}); err != nil {
				t.Fatal(err)
			}
			wrapped := events.Wrap(c, events.DefaultConfig())
			user := &store.User{TenantID: "t", UserID: "auth0|u", Email: "u@example.test"}
			faults.appendCode.Store(int32(code))
			if err := wrapped.Users().Create(ctx, user); err == nil {
				t.Fatal("append failure accepted mutation")
			}
			if _, err := c.Users().Get(ctx, "t", user.UserID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("business write leaked: %v", err)
			}
			if seq, err := c.Events().LatestEventSeq(ctx, "t"); err != nil || seq != 0 {
				t.Fatalf("outbox leaked: %d %v", seq, err)
			}
			if err := wrapped.Users().Create(ctx, user); err != nil {
				t.Fatalf("retry: %v", err)
			}
			if seq, err := c.Events().LatestEventSeq(ctx, "t"); err != nil || seq == 0 {
				t.Fatalf("retry uncaptured: %d %v", seq, err)
			}
		})
	}
}
func TestEventsRemoteNestedRollback(t *testing.T) {
	for name, f := range map[string]func(*testing.T) *Client{"memory": inProcess, "sqlite": inProcessSQLite} {
		t.Run(name, func(t *testing.T) {
			c := f(t)
			defer c.Close()
			ctx := context.Background()
			if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			abort := errors.New("abort child")
			if err := c.WithTx(ctx, func(tx store.Store) error {
				outer := []store.TenantEvent{{TenantID: "t", ID: "outer", Time: time.Now(), Type: "user.created", Body: []byte(`{}`)}}
				if err := tx.Events().AppendEvents(ctx, outer); err != nil {
					return err
				}
				if err := tx.WithTx(ctx, func(child store.Store) error {
					if err := child.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "inner"}); err != nil {
						return err
					}
					if err := child.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: "t", ID: "inner", Time: time.Now(), Type: "user.created", Body: []byte(`{}`)}}); err != nil {
						return err
					}
					return abort
				}); !errors.Is(err, abort) {
					return err
				}
				if _, err := tx.Events().GetEvent(ctx, "t", "inner"); !errors.Is(err, store.ErrNotFound) {
					return errors.New("inner event leaked")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Clients().Get(ctx, "t", "inner"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("nested business leaked: %v", err)
			}
			if _, err := c.Events().GetEvent(ctx, "t", "outer"); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Events().GetEvent(ctx, "t", "inner"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("nested event leaked: %v", err)
			}
		})
	}
}
