package logs

import (
	"context"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestPurgeRetention(t *testing.T) {
	st := tenantStore(t)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	events := make([]store.LogEvent, 1003)
	for i := range events {
		events[i] = store.LogEvent{TenantID: "t", Type: "s", Date: now.Add(-31 * 24 * time.Hour), Body: []byte(`{"type":"s"}`)}
	}
	events[1001].Date = now.Add(-30 * 24 * time.Hour)
	events[1002].Date = now
	if err := st.Logs().AppendLogs(bg, events, nil); err != nil {
		t.Fatal(err)
	}
	p := NewPurger(st, Config{Now: func() time.Time { return now }}, quiet())
	if err := p.Sweep(bg); err != nil {
		t.Fatal(err)
	}
	_, total, err := st.Logs().SearchLogs(bg, "t", nil, store.LogPage{PerPage: 100, IncludeTotals: true})
	if err != nil || total != 2 {
		t.Fatalf("remaining %d err %v", total, err)
	}
	// Exactly the cutoff survives. An explicit one-day retention removes it.
	p = NewPurger(st, Config{Retention: 24 * time.Hour, Now: func() time.Time { return now }}, quiet())
	if err := p.Sweep(bg); err != nil {
		t.Fatal(err)
	}
	_, total, _ = st.Logs().SearchLogs(bg, "t", nil, store.LogPage{PerPage: 100, IncludeTotals: true})
	if total != 1 {
		t.Fatalf("one-day retention remaining %d", total)
	}
}
func TestPurgeLease(t *testing.T) {
	st := tenantStore(t)
	p := NewPurger(st, Config{}, quiet())
	lease, err := st.TLSAssets().ClaimLease(bg, purgeLeaseKey, "other", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Sweep(bg); err != nil {
		t.Fatal(err)
	}
	if err := st.TLSAssets().CheckLease(bg, *lease); err != nil {
		t.Fatalf("competing sweeper changed lease: %v", err)
	}
	if err := st.TLSAssets().ReleaseLease(bg, *lease); err != nil {
		t.Fatal(err)
	}
	if err := p.Sweep(bg); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TLSAssets().ClaimLease(bg, purgeLeaseKey, "next", time.Minute); err != nil {
		t.Fatalf("sweeper did not release lease: %v", err)
	}
}

type capabilityStore struct {
	wrappedStore
	err       error
	supported bool
}

func (s *capabilityStore) CheckLogsSupport(context.Context) error { return s.err }
func (s *capabilityStore) LogsSupported() bool                    { return s.supported }
func TestRecorderMissingCapabilityAndTransientRecovery(t *testing.T) {
	st := tenantStore(t)
	output := &safeBuffer{}
	probe := &capabilityStore{wrappedStore: wrappedStore{Store: st, repo: st.Logs()}, err: store.ErrLogsUnavailable}
	r := NewRecorder(probe, Config{}, slog.New(slog.NewJSONHandler(output, nil)))
	r.Record(logscrub.WithValues(bg, "hunter2-secret"), Event{TenantID: "t", Type: "s", Description: "hunter2-secret", Details: map[string]any{"password": "hidden", "body": `{"note":"hunter2-secret"}`}})
	if err := r.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if text := output.String(); !strings.Contains(text, "tenant log event") || strings.Contains(text, "hunter2-secret") || strings.Contains(text, "hidden") {
		t.Fatalf("unsafe/missing fallback %s", text)
	}
	probe.err = errors.New("temporary capability outage")
	r = NewRecorder(probe, Config{}, quiet())
	r.Record(bg, Event{TenantID: "t", Type: "s"})
	if err := r.Flush(bg); err == nil {
		t.Fatal("transient probe error hidden")
	}
	probe.err = nil
	probe.supported = true
	r = NewRecorder(probe, Config{}, quiet())
	r.Record(bg, Event{TenantID: "t", Type: "s"})
	if err := r.Flush(bg); err != nil {
		t.Fatal(err)
	}
	_, total, _ := st.Logs().SearchLogs(bg, "t", nil, store.LogPage{PerPage: 100, IncludeTotals: true})
	if total != 1 {
		t.Fatal(fmt.Sprint("recovery total ", total))
	}
}

func TestPurgeUnavailableWarningRate(t *testing.T) {
	st := tenantStore(t)
	out := &safeBuffer{}
	now := time.Now()
	probe := &capabilityStore{wrappedStore: wrappedStore{Store: st, repo: st.Logs()}, err: store.ErrLogsUnavailable}
	p := NewPurger(probe, Config{Now: func() time.Time { return now }}, slog.New(slog.NewTextHandler(out, nil)))
	for range 3 {
		if err := p.Sweep(bg); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(out.String(), "tenant log retention unavailable"); n != 1 {
		t.Fatalf("warnings %d: %s", n, out.String())
	}
	now = now.Add(time.Hour)
	if err := p.Sweep(bg); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "tenant log retention unavailable"); n != 2 {
		t.Fatalf("warnings after hour %d: %s", n, out.String())
	}
}
