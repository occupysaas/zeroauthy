package protection_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type eventRecorder struct {
	mu     sync.Mutex
	events []logs.Event
}

func (c *eventRecorder) Record(_ context.Context, e logs.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func TestBruteForceLogsLimitWCOnce(t *testing.T) {
	ctx := context.Background()
	s, tn, conn := serviceFixture(t)
	tn.ProtectionSettings.BruteForce.Mode = "count_per_identifier_and_ip"
	tn.ProtectionSettings.SuspiciousIP.Enabled = false
	if err := s.Store.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	capture := &eventRecorder{}
	s.Recorder = capture
	other := &protection.Service{Store: s.Store, Now: s.Now, Recorder: capture}
	a := protection.Attempt{Tenant: tn, Connection: conn, Identifier: "person@example.test", IP: "192.0.2.1", Flow: "login"}
	reserve := func() protection.Decision {
		t.Helper()
		d, err := s.Begin(ctx, a)
		if err != nil || !d.Allowed {
			t.Fatalf("expected admission: %+v, %v", d, err)
		}
		return d
	}
	fail := func(d protection.Decision) {
		t.Helper()
		if err := s.Finish(ctx, d.Receipt, "failure"); err != nil {
			t.Fatal(err)
		}
	}
	deny := func(svc *protection.Service) {
		t.Helper()
		if d, err := svc.Begin(ctx, a); err != nil || d.Allowed {
			t.Errorf("expected denial: %+v, %v", d, err)
		}
	}
	checkEvents := func(stage string, want int) {
		t.Helper()
		if len(capture.events) != want {
			t.Errorf("%s: got %d events, want %d: %+v", stage, len(capture.events), want, capture.events)
		}
		for _, e := range capture.events {
			if e.Type != "limit_wc" || e.TenantID != "t" || e.ConnectionID != "c" || e.IP != "192.0.2.1" || e.Description == "" {
				t.Errorf("%s: unexpected event %+v", stage, e)
			}
		}
	}

	fail(reserve())
	pending := reserve()
	deny(other)
	checkEvents("in-flight reservation denial", 0)
	fail(pending)
	checkEvents("settled failure without denial", 0)
	deny(other)
	checkEvents("first durable denial", 1)
	deny(s)
	deny(other)
	checkEvents("repeat denials", 1)

	filter := store.ProtectionFilter{Kind: store.ProtectionBruteForce, ConnectionID: conn.ID, Identifier: a.Identifier, IP: a.IP}
	if err := s.Store.Protection().Clear(ctx, tn.ID, filter); err != nil {
		t.Fatal(err)
	}
	fail(reserve())
	fail(reserve())
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 8 {
		svc := s
		if i%2 == 0 {
			svc = other
		}
		wg.Go(func() {
			<-start
			deny(svc)
		})
	}
	close(start)
	wg.Wait()
	checkEvents("concurrent first denials after unblock", 2)
}

func TestProtectionDecisionEvents(t *testing.T) {
	for _, tc := range []struct {
		name, mode, flow, code string
		monitor                bool
	}{{"brute-force per ip", "count_per_identifier_and_ip", "login", "limit_wc", false}, {"brute-force account", "count_per_identifier", "login", "limit_wc", false}, {"suspicious login", "", "login", "limit_mu", false}, {"suspicious registration", "", "signup", "limit_mu", false}, {"monitor only", "count_per_identifier", "login", "", true}} {
		t.Run(tc.name, func(t *testing.T) {
			s, tn, conn := serviceFixture(t)
			capture := &eventRecorder{}
			s.Recorder = capture
			if tc.mode == "" {
				tn.ProtectionSettings.BruteForce.Enabled = false
				tn.ProtectionSettings.SuspiciousIP.Stage.PreLogin.MaxAttempts = 1
				tn.ProtectionSettings.SuspiciousIP.Stage.PreUserRegistration.MaxAttempts = 1
			} else {
				tn.ProtectionSettings.BruteForce.Mode = tc.mode
				tn.ProtectionSettings.BruteForce.MaxAttempts = 1
				tn.ProtectionSettings.SuspiciousIP.Enabled = false
			}
			if tc.monitor {
				tn.ProtectionSettings.BruteForce.Shields = []string{"admin_notification"}
			}
			if err := s.Store.Tenants().Update(context.Background(), tn); err != nil {
				t.Fatal(err)
			}
			a := protection.Attempt{Tenant: tn, Connection: conn, Identifier: "person@example.test", IP: "192.0.2.1", Flow: tc.flow}
			first, err := s.Begin(context.Background(), a)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Finish(context.Background(), first.Receipt, "failure"); err != nil {
				t.Fatal(err)
			}
			second, err := s.Begin(context.Background(), a)
			if err != nil {
				t.Fatal(err)
			}
			if tc.monitor {
				if !second.Allowed || len(capture.events) != 0 {
					t.Fatal(second, capture.events)
				}
				return
			}
			if second.Allowed {
				t.Fatal("expected denial")
			}
			want := 1
			if tc.mode == "" {
				if repeated, err := s.Begin(context.Background(), a); err != nil || repeated.Allowed {
					t.Fatal(repeated, err)
				}
				want = 2
			}
			if len(capture.events) != want {
				t.Fatalf("got events %+v; want %d %s events", capture.events, want, tc.code)
			}
			for _, event := range capture.events {
				if event.Type != tc.code || event.ConnectionID != "c" || event.Connection != "db" || event.Strategy != "auth0" || event.StrategyType != "database" || event.Description == "" {
					t.Fatalf("event=%+v", event)
				}
			}
		})
	}
}

type noLogLookupStore struct {
	store.Store
	calls *int
}

func (s noLogLookupStore) Protection() store.Protection {
	return noLogLookupProtection{s.Store.Protection(), s.calls}
}

type noLogLookupProtection struct {
	store.Protection
	calls *int
}

func (p noLogLookupProtection) Blocks(context.Context, string, store.ProtectionFilter, time.Time) ([]store.ProtectionBlock, error) {
	*p.calls++
	return nil, errors.New("logging attribution must not query storage")
}
func TestDeniedEventDoesNotReadForLogging(t *testing.T) {
	s, tn, conn := serviceFixture(t)
	tn.ProtectionSettings.BruteForce.MaxAttempts = 1
	tn.ProtectionSettings.BruteForce.Shields = []string{"block"}
	tn.ProtectionSettings.SuspiciousIP.Enabled = false
	if err := s.Store.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.Store = noLogLookupStore{s.Store, &calls}
	capture := &eventRecorder{}
	s.Recorder = capture
	a := protection.Attempt{Tenant: tn, Connection: conn, Identifier: "person@example.test", IP: "192.0.2.1", Flow: "login"}
	d, err := s.Begin(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Finish(context.Background(), d.Receipt, "failure"); err != nil {
		t.Fatal(err)
	}
	d, err = s.Begin(context.Background(), a)
	if err != nil || d.Allowed || calls != 0 || len(capture.events) == 0 {
		t.Fatalf("decision=%+v err=%v reads=%d events=%+v", d, err, calls, capture.events)
	}
}

type legacyAdmissionStore struct {
	store.Store
	omitDeniedKinds bool
}

func (s legacyAdmissionStore) Protection() store.Protection {
	return legacyAdmissionProtection{s.Store.Protection(), s.omitDeniedKinds}
}

type legacyAdmissionProtection struct {
	store.Protection
	omitDeniedKinds bool
}

func (p legacyAdmissionProtection) Reserve(ctx context.Context, limits []store.ProtectionLimit, now time.Time) (store.ProtectionAdmission, error) {
	decision, err := p.Protection.Reserve(ctx, limits, now)
	decision.FirstBruteForceDenial = false
	if p.omitDeniedKinds {
		decision.DeniedKinds = nil
	}
	return decision, err
}
func TestLegacyAdmissionOmitsUncertainEvent(t *testing.T) {
	for _, tc := range []struct {
		name            string
		omitDeniedKinds bool
		wantEvents      int
	}{
		{name: "no attribution", omitDeniedKinds: true},
		{name: "attribution without a brute-force claim", wantEvents: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, tn, conn := serviceFixture(t)
			tn.ProtectionSettings.SuspiciousIP.Stage.PreLogin.MaxAttempts = 2
			if err := s.Store.Tenants().Update(ctx, tn); err != nil {
				t.Fatal(err)
			}
			s.Store = legacyAdmissionStore{s.Store, tc.omitDeniedKinds}
			capture := &eventRecorder{}
			s.Recorder = capture
			a := protection.Attempt{Tenant: tn, Connection: conn, Identifier: "person@example.test", IP: "192.0.2.1", Flow: "login"}
			for range 2 {
				d, err := s.Begin(ctx, a)
				if err != nil || !d.Allowed {
					t.Fatal(d, err)
				}
				if err = s.Finish(ctx, d.Receipt, "failure"); err != nil {
					t.Fatal(err)
				}
			}
			denied, err := s.Begin(ctx, a)
			if err != nil || denied.Allowed || len(capture.events) != tc.wantEvents {
				t.Fatal(denied, err, capture.events)
			}
			if tc.wantEvents > 0 && capture.events[0].Type != "limit_mu" {
				t.Fatal(capture.events)
			}
		})
	}
}

func TestDiscoveryEventOmitsUnknownStrategy(t *testing.T) {
	s, tn, _ := serviceFixture(t)
	tn.ProtectionSettings.SuspiciousIP.Stage.PreLogin.MaxAttempts = 1
	if err := s.Store.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	capture := &eventRecorder{}
	s.Recorder = capture
	a := protection.Attempt{Tenant: tn, IP: "192.0.2.1", Flow: "organization-discovery"}
	d, err := s.Begin(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Finish(context.Background(), d.Receipt, "failure"); err != nil {
		t.Fatal(err)
	}
	d, err = s.Begin(context.Background(), a)
	if err != nil || d.Allowed || len(capture.events) != 1 {
		t.Fatal(d, err, capture.events)
	}
	event := capture.events[0]
	if event.Type != "limit_mu" || event.Connection != "" || event.ConnectionID != "" || event.Strategy != "" || event.StrategyType != "" {
		t.Fatalf("invented connection or strategy: %+v", event)
	}
}
