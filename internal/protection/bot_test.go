package protection_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/protection"
)

func TestBotRollingRisk(t *testing.T) {
	for level, threshold := range map[string]int{"low": 10, "medium": 5, "high": 1} {
		t.Run(level, func(t *testing.T) {
			s, tenant, conn := serviceFixture(t)
			ctx := context.Background()
			tenant.ProtectionSettings.Bot.ChallengePasswordPolicy = "when_risky"
			tenant.ProtectionSettings.Bot.BotDetectionLevel = level
			if err := s.Store.Tenants().Update(ctx, tenant); err != nil {
				t.Fatal(err)
			}
			other := &protection.Service{Store: s.Store, Now: s.Now}
			a := protection.Attempt{Tenant: tenant, Connection: conn, IP: "::ffff:192.0.2.1", Flow: "login"}
			for i := 0; i < threshold; i++ {
				required, err := other.RequireChallenge(ctx, a)
				if err != nil || required {
					t.Fatalf("early %v %v", required, err)
				}
				for range 2 {
					if err := s.RecordFailure(ctx, a, fmt.Sprint(i)); err != nil {
						t.Fatal(err)
					}
				}
			}
			required, err := other.RequireChallenge(ctx, a)
			if err != nil || !required {
				t.Fatalf("missing challenge %v %v", required, err)
			}
			d, err := s.Begin(ctx, a)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Finish(ctx, d.Receipt, "success"); err != nil {
				t.Fatal(err)
			}
			if required, err := other.RequireChallenge(ctx, a); err != nil || !required {
				t.Fatal("success erased history", required, err)
			}
			other.Now = func() time.Time { return s.Now().Add(15 * time.Minute) }
			required, err = other.RequireChallenge(ctx, a)
			if err != nil || required {
				t.Fatalf("expiry %v %v", required, err)
			}
		})
	}
}
func TestBotPolicies(t *testing.T) {
	s, tenant, conn := serviceFixture(t)
	ctx := context.Background()
	a := protection.Attempt{Tenant: tenant, Connection: conn, IP: "192.0.2.1", Flow: "login"}
	for _, tc := range []struct {
		mode, flow           string
		monitor, allow, want bool
	}{{"never", "login", false, false, false}, {"always", "login", false, false, true}, {"always", "signup", false, false, true}, {"always", "login", true, false, false}, {"always", "login", false, true, false}, {"always", "refresh", false, false, false}, {"always", "reset-send", false, false, true}} {
		tenant.ProtectionSettings.Bot.ChallengePasswordPolicy = tc.mode
		tenant.ProtectionSettings.Bot.ChallengePasswordResetPolicy = tc.mode
		tenant.ProtectionSettings.Bot.MonitoringModeEnabled = tc.monitor
		tenant.ProtectionSettings.Bot.Allowlist = nil
		if tc.allow {
			tenant.ProtectionSettings.Bot.Allowlist = []string{"192.0.2.0/24"}
		}
		if err := s.Store.Tenants().Update(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		a.Flow = tc.flow
		got, err := s.RequireChallenge(ctx, a)
		if err != nil || got != tc.want {
			t.Fatalf("%+v: %v %v", tc, got, err)
		}
	}
}
func TestBotQualifyingFailures(t *testing.T) {
	for _, tc := range []struct {
		flow string
		err  error
		want bool
	}{
		{"login", identity.ErrInvalidCredentials, true}, {"login", protection.ErrPasswordLeaked, true}, {"login", protection.ErrBreachUnavailable, false}, {"login", identity.ErrUserBlocked, false}, {"signup", identity.ErrUserExists, true}, {"signup", &identity.PolicyError{Key: "zeroauthy.signup.email-invalid"}, false}, {"signup", &identity.PolicyError{Key: "zeroauthy.signup.password-too-short"}, true}, {"reset", &identity.PolicyError{Key: "zeroauthy.signup.password-history"}, true}, {"reset-send", nil, false},
	} {
		if got := protection.QualifyingFailure(tc.flow, tc.err); got != tc.want {
			t.Fatalf("%s %v: %v", tc.flow, tc.err, got)
		}
	}
}
