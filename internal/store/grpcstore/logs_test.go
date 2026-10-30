package grpcstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Task 5 supplies the transport; these are deliberately real conformance
// wrappers, not skips that could hide an unavailable capability.
func TestLogs(t *testing.T) {
	for name, f := range map[string]func(*testing.T) *Client{"memory": inProcess, "sqlite": inProcessSQLite} {
		t.Run(name, func(t *testing.T) { storetest.RunSuites(t, func(t *testing.T) store.Store { return f(t) }, "Logs") })
	}
}

// Missing negotiation, empty byte coercion and float64 JSON decoding must fail
// these tests even when ordinary log bodies happen to survive transport.
func TestLogsCapabilityProbe(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	probe, ok := any(c).(interface {
		CheckLogsSupport(context.Context) error
		LogsSupported() bool
	})
	if !ok {
		t.Fatal("Logs v1 capability probe missing")
	}
	if err := probe.CheckLogsSupport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !probe.LogsSupported() {
		t.Fatal("Logs v1 unsupported")
	}
}

type logsEchoStore struct {
	store.Store
	repo *logsEcho
}

func (s logsEchoStore) Logs() store.Logs { return s.repo }

type logsEcho struct {
	store.UnimplementedLogs
	event  store.LogEvent
	stream store.LogStream
	query  *store.LogQuery
}

func (s *logsEcho) AppendLogs(_ context.Context, e []store.LogEvent, _ []store.DailyStatDelta) error {
	s.event = e[0]
	return nil
}
func (s *logsEcho) GetLog(context.Context, string, string) (*store.LogEvent, error) {
	return &s.event, nil
}
func (s *logsEcho) CreateLogStream(_ context.Context, v *store.LogStream) error {
	s.stream = *v
	return nil
}
func (s *logsEcho) GetLogStream(context.Context, string, string) (*store.LogStream, error) {
	return &s.stream, nil
}
func (s *logsEcho) SearchLogs(_ context.Context, _ string, q *store.LogQuery, _ store.LogPage) ([]store.LogEvent, int, error) {
	s.query = q
	return []store.LogEvent{s.event}, 1, nil
}
func TestLogsLosslessRoundTrip(t *testing.T) {
	ctx := context.Background()
	repo := &logsEcho{}
	c := serve(t, logsEchoStore{memory.New(), repo})
	defer c.Close()
	for _, body := range [][]byte{nil, {}, []byte(`{"x":9007199254740993}`)} {
		e := store.LogEvent{TenantID: "t", ID: "id", Seq: 19, Date: time.Time{}, Type: "s", UserID: "u", ClientID: "c", ConnectionID: "cn", OrganizationID: "org", IP: "::1", Body: body}
		if err := c.Logs().AppendLogs(ctx, []store.LogEvent{e}, nil); err != nil {
			t.Fatal(err)
		}
		got, err := c.Logs().GetLog(ctx, "t", "id")
		if err != nil || !reflect.DeepEqual(*got, e) {
			t.Fatalf("event: %#v, %v; want %#v", got, err, e)
		}
	}
	for i, secrets := range [][]byte{nil, {}, {0, 1, 255, 128}} {
		s := store.LogStream{
			TenantID: "t", ID: "s", Name: "name", Type: "http", Status: "active",
			Sink:          map[string]any{"large": json.Number("9007199254740993"), "nested": []any{json.Number("12345678901234567890.123456789")}},
			SealedSecrets: secrets,
			Filters:       []store.LogStreamFilter{{Type: "category", Name: "auth"}},
			PII:           &store.LogStreamPII{LogFields: []string{"ip", "user_name"}, Method: "mask", Algorithm: "xxhash"},
			StartFrom:     time.Date(0, 1, 1, 0, 0, 0, 123, time.UTC),
			LeaseUntil:    time.Unix(0, 0).UTC(), IsPriority: true,
			Checkpoint: 9223372036854775806, LeaseOwner: "owner",
			NextAt:        time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC),
			FailingSince:  time.Date(1, 1, 1, 0, 0, 0, 7, time.UTC),
			LastSuccessAt: time.Unix(123456789, 987654321).UTC(),
			Failures:      7, LastErrorClass: "timeout", Version: 18,
			CreatedAt: time.Unix(12, 13).UTC(), UpdatedAt: time.Unix(14, 15).UTC(),
		}
		if i == 0 {
			s.Sink = nil
			s.Filters = nil
			s.PII = nil
		}
		if i == 1 {
			s.Sink = map[string]any{}
			s.Filters = []store.LogStreamFilter{}
			s.PII = &store.LogStreamPII{LogFields: []string{}}
		}
		if err := c.Logs().CreateLogStream(ctx, &s); err != nil {
			t.Fatal(err)
		}
		got, err := c.Logs().GetLogStream(ctx, "t", "s")
		if err != nil || !reflect.DeepEqual(*got, s) {
			t.Fatalf("stream: %#v, %v; want %#v", got, err, s)
		}
	}
	q := &store.LogQuery{Op: "and", Left: &store.LogQuery{Op: "not", Left: &store.LogQuery{Op: "eq", Field: "type", Value: "f"}}, Right: &store.LogQuery{Op: "range", Field: "date", Value: "2026-01-01T00:00:00Z", Upper: "2027-01-01T00:00:00Z", LowerExclusive: true, UpperExclusive: true}}
	_, _, err := c.Logs().SearchLogs(ctx, "t", q, store.LogPage{PerPage: 10})
	if err != nil || !reflect.DeepEqual(repo.query, q) {
		t.Fatalf("AST: %#v %v", repo.query, err)
	}
	if !errors.Is(errFromPB(errToPB(store.ErrLogsUnavailable)), store.ErrLogsUnavailable) {
		t.Fatal("Logs unavailable loses sentinel")
	}
}

// Simulate older and temporarily unreachable plugins without replacing any
// non-Logs RPC, so compatibility assertions exercise the ordinary transport.
type logsCapabilityPlugin struct {
	*Server
	version       atomic.Uint32
	missing       bool
	transient     atomic.Bool
	operationCode atomic.Int32
}

func (p *logsCapabilityPlugin) LogsCapabilities(ctx context.Context, q *storev1.PingRequest) (*storev1.LogsCapabilitiesResult, error) {
	if p.missing {
		return nil, status.Error(codes.Unimplemented, "pre-Logs plugin")
	}
	if p.transient.Swap(false) {
		return nil, status.Error(codes.Unavailable, "restart")
	}
	return &storev1.LogsCapabilitiesResult{Version: p.version.Load()}, nil
}
func (p *logsCapabilityPlugin) GetLog(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	if code := codes.Code(p.operationCode.Swap(0)); code != codes.OK {
		return nil, status.Error(code, "operation failure")
	}
	return p.Server.GetLog(ctx, q)
}
func TestLogsCapabilities(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name      string
		version   uint32
		missing   bool
		transient bool
		want      bool
	}{
		{"v0", 0, false, false, false}, {"preLogs", 0, true, false, false}, {"v1", 1, false, false, true}, {"transient", 1, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &logsCapabilityPlugin{Server: NewServer(memory.New()), missing: tc.missing}
			defer p.Close()
			p.version.Store(tc.version)
			c := serveWith(t, p)
			defer c.Close()
			orgSeed(t, c)
			org := &store.Organization{TenantID: "t", ID: "org_abcdefghijklmnop", Name: "compat"}
			if err := c.Organizations().Create(ctx, org, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Organizations().Get(ctx, "t", org.ID); err != nil {
				t.Fatal(err)
			}
			if err := c.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "c", Name: "compat"}); err != nil {
				t.Fatal(err)
			}
			if err := c.CheckOrganizationsIISupport(ctx); err != nil {
				t.Fatal("earlier capability disabled", err)
			}
			if tc.transient {
				p.transient.Store(true)
				if c.LogsSupported() {
					t.Fatal("unreachable plugin reported support")
				}
			}
			if got := c.LogsSupported(); got != tc.want {
				t.Fatalf("LogsSupported=%v want %v", got, tc.want)
			}
			err := c.CheckLogsSupport(ctx)
			if tc.want && err != nil || !tc.want && !errors.Is(err, store.ErrLogsUnavailable) {
				t.Fatalf("probe: %v", err)
			}
			calls := []func(store.Logs) error{
				func(r store.Logs) error { return r.AppendLogs(ctx, nil, nil) },
				func(r store.Logs) error { _, e := r.GetLog(ctx, "t", "missing"); return e },
				func(r store.Logs) error { _, _, e := r.SearchLogs(ctx, "t", nil, store.LogPage{}); return e },
				func(r store.Logs) error { _, e := r.LogsAfter(ctx, "t", 0, nil, 10, time.Now()); return e },
				func(r store.Logs) error { _, e := r.LatestLogs(ctx, "t", nil, 10, time.Now()); return e },
				func(r store.Logs) error { _, e := r.PurgeLogs(ctx, time.Now(), 10); return e },
				func(r store.Logs) error { return r.DeleteTenantLogs(ctx, "t") },
				func(r store.Logs) error { return r.CreateLogStream(ctx, &store.LogStream{}) },
				func(r store.Logs) error { _, e := r.GetLogStream(ctx, "t", "missing"); return e },
				func(r store.Logs) error { _, e := r.ListLogStreams(ctx, "t"); return e },
				func(r store.Logs) error { return r.UpdateLogStream(ctx, &store.LogStream{}, 1) },
				func(r store.Logs) error { return r.DeleteLogStream(ctx, "t", "missing") },
				func(r store.Logs) error {
					_, e := r.LeaseLogStream(ctx, "owner", time.Now(), time.Now().Add(time.Hour))
					return e
				},
				func(r store.Logs) error {
					return r.RecordDelivery(ctx, "t", "missing", "owner", store.LogStreamDelivery{})
				},
				func(r store.Logs) error { _, e := r.DailyStats(ctx, "t", time.Now(), time.Now()); return e },
				func(r store.Logs) error { _, e := r.ActiveUsers(ctx, "t", time.Now()); return e },
			}
			if !tc.want {
				for i, call := range calls {
					if e := call(c.Logs()); !errors.Is(e, store.ErrLogsUnavailable) {
						t.Fatalf("operation %d: %v", i, e)
					}
				}
			}
			if err := c.WithTx(ctx, func(tx store.Store) error {
				if tx.(store.LogsSupporter).LogsSupported() != tc.want {
					return errors.New("transaction capability differs")
				}
				err := tx.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "t", Date: time.Now(), Body: []byte(`{}`)}}, nil)
				if tc.want {
					return err
				}
				if !errors.Is(err, store.ErrLogsUnavailable) {
					return fmt.Errorf("transaction: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if tc.want {
				p.transient.Store(true)
				if err := c.Logs().AppendLogs(ctx, nil, nil); err == nil || errors.Is(err, store.ErrLogsUnavailable) {
					t.Fatalf("transient probe: %v", err)
				}
				if err := c.Logs().AppendLogs(ctx, nil, nil); err != nil {
					t.Fatalf("probe recovery: %v", err)
				}
				p.operationCode.Store(int32(codes.Unavailable))
				if _, err := c.Logs().GetLog(ctx, "t", "missing"); err == nil || errors.Is(err, store.ErrLogsUnavailable) {
					t.Fatalf("transient operation: %v", err)
				}
				if _, err := c.Logs().GetLog(ctx, "t", "missing"); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("operation recovery: %v", err)
				}
				p.operationCode.Store(int32(codes.Unimplemented))
				if _, err := c.Logs().GetLog(ctx, "t", "missing"); !errors.Is(err, store.ErrLogsUnavailable) {
					t.Fatalf("unknown method: %v", err)
				}
				if c.LogsSupported() {
					t.Fatal("unknown method was not cached as unavailable")
				}
				if err := c.CheckLogsSupport(ctx); err != nil {
					t.Fatalf("explicit recovery: %v", err)
				}
				p.version.Store(0)
				if err := c.Logs().AppendLogs(ctx, nil, nil); !errors.Is(err, store.ErrLogsUnavailable) {
					t.Fatalf("downgrade retained support: %v", err)
				}
				p.version.Store(1)
				if err := c.Logs().AppendLogs(ctx, nil, nil); err != nil {
					t.Fatalf("upgrade retained unavailability: %v", err)
				}
			}
		})
	}
}

type noLogsBackend struct{ store.Store }

func (noLogsBackend) Logs() store.Logs { return store.UnimplementedLogs{} }
func TestLogsUnavailableBackend(t *testing.T) {
	c := serve(t, noLogsBackend{memory.New()})
	defer c.Close()
	if err := c.CheckLogsSupport(context.Background()); !errors.Is(err, store.ErrLogsUnavailable) {
		t.Fatalf("stub advertised support: %v", err)
	}
}
