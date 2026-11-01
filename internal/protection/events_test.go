package protection_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type eventRecorder struct{ events []logs.Event }

func (c *eventRecorder) Record(_ context.Context, e logs.Event) { c.events = append(c.events, e) }
func TestProtectionEvents(t *testing.T) {
	s, tenant, conn := serviceFixture(t)
	c := &eventRecorder{}
	s.Recorder = c
	a := protection.Attempt{Tenant: tenant, Connection: conn, Identifier: "person@example.test", IP: "192.0.2.1", Flow: "login"}
	for range 2 {
		d, e := s.Begin(context.Background(), a)
		if e != nil {
			t.Fatal(e)
		}
		if e = s.Finish(context.Background(), d.Receipt, "failure"); e != nil {
			t.Fatal(e)
		}
	}
	d, e := s.Begin(context.Background(), a)
	if e != nil || d.Allowed {
		t.Fatal(d, e)
	}
	if len(c.events) == 0 {
		t.Fatal("no blocking event")
	}
	for _, e := range c.events {
		if e.Type != "limit_wc" && e.Type != "limit_sul" {
			t.Fatalf("event=%+v", e)
		}
		if e.TenantID != "t" || e.ConnectionID != "c" || e.IP != "192.0.2.1" || e.Description == "" {
			t.Fatalf("event=%+v", e)
		}
	}
}

func TestProtectionDecisionEvents(t *testing.T) {
	for _, tc := range []struct {
		name, mode, flow, code string
		monitor                bool
	}{{"brute-force per ip", "count_per_identifier_and_ip", "login", "limit_sul", false}, {"brute-force account", "count_per_identifier", "login", "limit_wc", false}, {"suspicious login", "", "login", "limit_mu", false}, {"suspicious registration", "", "signup", "limit_mu", false}, {"monitor only", "count_per_identifier", "login", "", true}} {
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
			found := false
			for _, event := range capture.events {
				if event.Type == tc.code {
					found = true
				}
				if event.ConnectionID != "c" || event.Connection != "db" || event.Strategy != "auth0" || event.StrategyType != "database" || event.Description == "" {
					t.Fatalf("event=%+v", event)
				}
			}
			if !found {
				t.Fatalf("missing %s in %+v", tc.code, capture.events)
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

type legacyAdmissionStore struct{ store.Store }

func (s legacyAdmissionStore) Protection() store.Protection {
	return legacyAdmissionProtection{s.Store.Protection()}
}

type legacyAdmissionProtection struct{ store.Protection }

func (p legacyAdmissionProtection) Reserve(ctx context.Context, limits []store.ProtectionLimit, now time.Time) (store.ProtectionAdmission, error) {
	decision, err := p.Protection.Reserve(ctx, limits, now)
	decision.DeniedKinds = nil
	return decision, err
}
func TestLegacyAdmissionOmitsUncertainEvent(t *testing.T) {
	s, tn, conn := serviceFixture(t)
	s.Store = legacyAdmissionStore{s.Store}
	capture := &eventRecorder{}
	s.Recorder = capture
	a := protection.Attempt{Tenant: tn, Connection: conn, Identifier: "person@example.test", IP: "192.0.2.1", Flow: "login"}
	for range 2 {
		d, err := s.Begin(context.Background(), a)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Finish(context.Background(), d.Receipt, "failure"); err != nil {
			t.Fatal(err)
		}
	}
	denied, err := s.Begin(context.Background(), a)
	if err != nil || denied.Allowed || len(capture.events) != 0 {
		t.Fatal(denied, err, capture.events)
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
