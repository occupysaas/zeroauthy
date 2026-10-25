package protection

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type testNotifier struct{ calls []string }

func (n *testNotifier) Notify(_ context.Context, tenant, user, purpose string) error {
	n.calls = append(n.calls, fmt.Sprintf("%s:%s:%s", tenant, user, purpose))
	return nil
}

func notificationService(t *testing.T) (*Service, *store.Tenant, *store.Connection, *testNotifier) {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	t.Cleanup(func() { _ = st.Close() })
	tn := &store.Tenant{ID: "t", Name: "t", ProtectionSettings: protectionrules.Defaults(), ProtectionSettingsInitialized: true}
	tn.ProtectionSettings.BruteForce.MaxAttempts = 1
	tn.ProtectionSettings.BruteForce.Shields = []string{"block", "user_notification"}
	conn := &store.Connection{ID: "c", TenantID: "t", Name: "db", Strategy: store.StrategyDatabase, BruteForceProtection: true}
	if err := st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := st.Connections().Create(ctx, conn); err != nil {
		t.Fatal(err)
	}
	user := &store.User{TenantID: "t", UserID: "u", Email: "primary@example.test", EmailVerified: true, Identities: []store.Identity{{Connection: "db", Provider: store.StrategyDatabase, UserID: "u", ProfileData: map[string]any{"email": "alias@example.test"}}}}
	if err := st.Users().Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	n := &testNotifier{}
	s := &Service{Store: st, Notifier: n, Now: func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }, Go: func(f func()) { f() }}
	return s, tn, conn, n
}

func TestNotificationAfterAuthoritativeEvent(t *testing.T) {
	s, tn, conn, n := notificationService(t)
	ctx := context.Background()
	a := Attempt{Tenant: tn, Connection: conn, Identifier: "alias@example.test", IP: "192.0.2.1", Flow: "login"}
	first, err := s.Begin(ctx, a)
	if err != nil || !first.Allowed {
		t.Fatal(first, err)
	}
	if len(n.calls) != 0 {
		t.Fatal("notified at Begin before a block", n.calls)
	}
	if err = s.Finish(ctx, first.Receipt, "failure"); err != nil {
		t.Fatal(err)
	}
	blocked, err := s.Begin(ctx, a)
	if err != nil || blocked.Allowed {
		t.Fatal(blocked, err)
	}
	want := "t:u:blocked_account"
	if len(n.calls) != 1 || n.calls[0] != want {
		t.Fatalf("notifications=%v", n.calls)
	}
}

func TestNoSuspiciousIPUserNotification(t *testing.T) {
	s, tn, conn, n := notificationService(t)
	ctx := context.Background()
	tn.ProtectionSettings.BruteForce.Shields = nil
	tn.ProtectionSettings.SuspiciousIP.Shields = []string{"block", "user_notification"}
	tn.ProtectionSettings.SuspiciousIP.Stage.PreLogin = store.ProtectionRate{MaxAttempts: 1, Rate: 1000}
	if err := s.Store.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	a := Attempt{Tenant: tn, Connection: conn, Identifier: "alias@example.test", IP: "192.0.2.2", Flow: "login"}
	d, e := s.Begin(ctx, a)
	if e != nil || !d.Allowed {
		t.Fatal(d, e)
	}
	if e = s.Finish(ctx, d.Receipt, "failure"); e != nil {
		t.Fatal(e)
	}
	d, e = s.Begin(ctx, a)
	if e != nil || d.Allowed {
		t.Fatal(d, e)
	}
	if len(n.calls) != 0 {
		t.Fatal("suspicious IP sent a user notice", n.calls)
	}
}

func TestStolenCredentialsNotifiesVerifiedLoginSubject(t *testing.T) {
	s, tn, _, n := notificationService(t)
	tn.ProtectionSettings.BreachedPassword.Enabled = true
	tn.ProtectionSettings.BreachedPassword.Shields = []string{"block", "user_notification"}
	if err := s.Store.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	s.BreachChecker = hitChecker{}
	err := s.CheckPasswordForUser(context.Background(), tn, "login", "compromised-password", "u")
	if err != ErrPasswordLeaked {
		t.Fatalf("check error=%v", err)
	}
	if len(n.calls) != 1 || n.calls[0] != "t:u:stolen_credentials" {
		t.Fatalf("notifications=%v", n.calls)
	}
}

func TestAdminNotificationStillDeferred(t *testing.T) {
	s, tn, _, n := notificationService(t)
	ctx := context.Background()
	tn.ProtectionSettings.BreachedPassword.Enabled = true
	tn.ProtectionSettings.BreachedPassword.Shields = []string{"admin_notification"}
	if err := s.Store.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	s.Log = slog.New(slog.NewTextHandler(&logs, nil))
	s.Now = func() time.Time { return time.Now().UTC().Add(2 * time.Hour) }
	s.BreachChecker = hitChecker{}
	if err := s.CheckPasswordForUser(ctx, tn, "login", "secret", "u"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "protection admin notification deferred") || len(n.calls) != 0 {
		t.Fatalf("admin notification behavior logs=%q user=%v", logs.String(), n.calls)
	}
}

type hitChecker struct{}

func (hitChecker) Check(context.Context, string) (bool, error) { return true, nil }
