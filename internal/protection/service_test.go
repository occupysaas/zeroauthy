package protection_test

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func serviceFixture(t *testing.T) (*protection.Service, *store.Tenant, *store.Connection) {
	t.Helper()
	st := memory.New()
	tenant := &store.Tenant{ID: "t", Name: "tenant", ProtectionSettings: protectionrules.Defaults(), ProtectionSettingsInitialized: true}
	tenant.ProtectionSettings.BruteForce.MaxAttempts = 2
	conn := &store.Connection{ID: "c", TenantID: "t", Name: "db", Strategy: store.StrategyDatabase, BruteForceProtection: true}
	if err := st.Tenants().Create(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if err := st.Connections().Create(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	return &protection.Service{Store: st, Now: func() time.Time { return time.Unix(1000, 0) }}, tenant, conn
}
func TestServiceSharedLimits(t *testing.T) {
	s, tenant, conn := serviceFixture(t)
	ctx := context.Background()
	other := &protection.Service{Store: s.Store, Now: s.Now}
	a := protection.Attempt{Tenant: tenant, Connection: conn, Identifier: " Alice@Example.test ", IP: "::ffff:192.0.2.1", Flow: "login"}
	for _, svc := range []*protection.Service{s, other} {
		d, err := svc.Begin(ctx, a)
		if err != nil || !d.Allowed {
			t.Fatalf("admit: %+v %v", d, err)
		}
		if err := svc.Finish(ctx, d.Receipt, "failure"); err != nil {
			t.Fatal(err)
		}
	}
	a.Identifier = "alice@example.test"
	a.IP = "192.0.2.1"
	d, err := other.Begin(ctx, a)
	if err != nil || d.Allowed {
		t.Fatalf("shared denial: %+v %v", d, err)
	}
	a.Flow = "signup"
	d, err = other.Begin(ctx, a)
	if err != nil || !d.Allowed {
		t.Fatalf("signup consumed brute force: %+v %v", d, err)
	}
}
func TestServiceOptOutAndResetBudget(t *testing.T) {
	s, tenant, conn := serviceFixture(t)
	ctx := context.Background()
	conn.BruteForceProtection = false
	if err := s.Store.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	tenant.ProtectionSettings.SuspiciousIP.Stage.PreLogin = store.ProtectionRate{MaxAttempts: 1, Rate: 864000}
	if err := s.Store.Tenants().Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	a := protection.Attempt{Tenant: tenant, Connection: conn, Identifier: "a", IP: "192.0.2.1", Flow: "login"}
	d, err := s.Begin(ctx, a)
	if err != nil || !d.Allowed {
		t.Fatal(d, err)
	}
	if err := s.Finish(ctx, d.Receipt, "failure"); err != nil {
		t.Fatal(err)
	}
	d, err = s.Begin(ctx, a)
	if err != nil || d.Allowed {
		t.Fatalf("connection opt-out bypassed IP: %+v %v", d, err)
	}
	a.Flow = "reset-send"
	for range 3 {
		d, err = s.Begin(ctx, a)
		if err != nil || !d.Allowed {
			t.Fatal(d, err)
		}
		if err := s.Finish(ctx, d.Receipt, "failure"); err != nil {
			t.Fatal(err)
		}
	}
	d, err = s.Begin(ctx, a)
	if err != nil || d.Allowed {
		t.Fatalf("reset send budget not shared: %+v %v", d, err)
	}
}

func TestServiceCancellationAndStaleRefund(t *testing.T) {
	s, tenant, conn := serviceFixture(t)
	ctx := context.Background()
	a := protection.Attempt{Tenant: tenant, Connection: conn, Identifier: "a", IP: "192.0.2.1", Flow: "login"}
	old, err := s.Begin(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Finish(cancelled, old.Receipt, "refund"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		d, err := s.Begin(ctx, a)
		if err != nil || !d.Allowed {
			t.Fatal(d, err)
		}
		if err := s.Finish(ctx, d.Receipt, "failure"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Finish(ctx, old.Receipt, "refund"); err != nil {
		t.Fatal(err)
	}
	d, err := s.Begin(ctx, a)
	if err != nil || d.Allowed {
		t.Fatalf("old refund erased failures: %+v %v", d, err)
	}
}
func TestServiceMonitoringAllowlistAndCurrentPolicy(t *testing.T) {
	s, tenant, conn := serviceFixture(t)
	ctx := context.Background()
	tenant.ProtectionSettings.BruteForce.Shields = []string{}
	tenant.ProtectionSettings.SuspiciousIP.Allowlist = []string{"192.0.2.0/24"}
	if err := s.Store.Tenants().Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	a := protection.Attempt{Tenant: tenant, Connection: conn, Identifier: "a", IP: "::ffff:192.0.2.1", Flow: "login"}
	for range 5 {
		d, err := s.Begin(ctx, a)
		if err != nil || !d.Allowed {
			t.Fatal(d, err)
		}
		if err := s.Finish(ctx, d.Receipt, "failure"); err != nil {
			t.Fatal(err)
		}
	}
	tenant.ProtectionSettings.BruteForce.Shields = []string{"block"}
	if err := s.Store.Tenants().Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		d, err := s.Begin(ctx, a)
		if err != nil || !d.Allowed {
			t.Fatal(d, err)
		}
		if err := s.Finish(ctx, d.Receipt, "failure"); err != nil {
			t.Fatal(err)
		}
	}
	d, err := s.Begin(ctx, a)
	if err != nil || d.Allowed {
		t.Fatalf("current blocking policy ignored: %+v %v", d, err)
	}
}
