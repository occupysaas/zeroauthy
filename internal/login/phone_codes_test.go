package login

import (
	"context"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
	"time"
)

func TestSignupWithPhoneVerification(t *testing.T) {
	f, r := newPhoneMFAFixture(t, "sms")
	ctx := context.Background()
	c, _ := f.st.Connections().GetByName(ctx, f.tn.ID, "Username-Password-Authentication")
	connID := c.ID
	if err := f.h.sendIdentifierCode(ctx, f.tn.ID, connID, "+14155550100", "signup", ""); err != nil {
		t.Fatal(err)
	}
	in := r.last(t)
	if in.Message.Type != "otp_verify" || in.Message.To != "+14155550100" {
		t.Fatal(in.Message.Type)
	}
	if _, err := f.h.consumeIdentifierCode(ctx, f.tn.ID, connID, "+14155550100", "signup", "000"); err == nil {
		t.Fatal("wrong code accepted")
	}
	if _, err := f.h.consumeIdentifierCode(ctx, f.tn.ID, connID, "+14155550100", "signup", in.Message.Code); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.consumeIdentifierCode(ctx, f.tn.ID, connID, "+14155550100", "signup", in.Message.Code); err == nil {
		t.Fatal("code reused")
	}
	for i := 1; i < 10; i++ {
		if err := f.h.sendIdentifierCode(ctx, f.tn.ID, connID, "+14155550100", "signup", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.h.sendIdentifierCode(ctx, f.tn.ID, connID, "+14155550100", "signup", ""); err == nil {
		t.Fatal("send budget bypassed")
	}
}
func TestResetByPhone(t *testing.T) {
	f, r := newPhoneMFAFixture(t, "sms")
	ctx := context.Background()
	c, _ := f.st.Connections().GetByName(ctx, f.tn.ID, "Username-Password-Authentication")
	connID := c.ID
	if err := f.h.sendIdentifierCode(ctx, f.tn.ID, connID, "+14155550100", "reset", "secret-ticket"); err != nil {
		t.Fatal(err)
	}
	in := r.last(t)
	if in.Message.Type != "change_password" {
		t.Fatal(in.Message.Type)
	}
	// Delivery and merely looking at a page cannot spend the code. Only the
	// code submit opens the bound ticket, once.
	raw, err := f.h.consumeIdentifierCode(ctx, f.tn.ID, connID, "+14155550100", "reset", in.Message.Code)
	if err != nil || raw != "secret-ticket" {
		t.Fatalf("%s %v", raw, err)
	}
	if _, err = f.h.consumeIdentifierCode(ctx, f.tn.ID, connID, "+14155550100", "reset", in.Message.Code); err == nil {
		t.Fatal("reset proof replayed")
	}
}

func TestPhoneIdentifierSendsShareIPBudget(t *testing.T) {
	f, _ := newPhoneMFAFixture(t, "sms")
	ctx := logs.WithEvent(t.Context(), logs.Event{IP: "198.51.100.8"})
	c, _ := f.st.Connections().GetByName(ctx, f.tn.ID, "Username-Password-Authentication")
	// Pre-spend the durable IP budget as other requests/instances would.
	for i := 0; i < 50; i++ {
		a, err := f.st.Protection().Reserve(ctx, []store.ProtectionLimit{{Key: store.ProtectionKey{TenantID: f.tn.ID, Kind: "identifier-phone-ip", IP: "198.51.100.8"}, Algorithm: "fixed-window", Capacity: 50, Window: time.Hour}}, f.h.now())
		if err != nil {
			t.Fatal(err)
		}
		if err = f.st.Protection().Complete(ctx, a.Receipt, "failure", f.h.now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.h.sendIdentifierCode(ctx, f.tn.ID, c.ID, "+14155550111", "signup", ""); err == nil {
		t.Fatal("IP budget bypassed")
	}
}

func TestSignupCodeLifetime900(t *testing.T) {
	for _, tc := range []struct {
		kind  string
		age   time.Duration
		valid bool
	}{
		{"signup", 899 * time.Second, true},
		{"signup", 900 * time.Second, false},
		{"signup", 901 * time.Second, false},
		{"reset", 299 * time.Second, true},
		{"reset", 300 * time.Second, false},
	} {
		t.Run(fmt.Sprintf("%s/%s", tc.kind, tc.age), func(t *testing.T) {
			f, runner := newPhoneMFAFixture(t, "sms")
			ctx := t.Context()
			conn, err := f.st.Connections().GetByName(ctx, f.tn.ID, "Username-Password-Authentication")
			if err != nil {
				t.Fatal(err)
			}
			if err := f.h.sendIdentifierCode(ctx, f.tn.ID, conn.ID, "+14155550100", tc.kind, ""); err != nil {
				t.Fatal(err)
			}
			code := runner.last(t).Message.Code
			*f.clock = f.clock.Add(tc.age)
			_, err = f.h.consumeIdentifierCode(ctx, f.tn.ID, conn.ID, "+14155550100", tc.kind, code)
			if (err == nil) != tc.valid {
				t.Fatalf("code at %s: err=%v, want valid=%v", tc.age, err, tc.valid)
			}
		})
	}
}

func TestCodeBudgetPerConnectionAndKind(t *testing.T) {
	for _, dimension := range []string{"connection", "kind", "identifier"} {
		t.Run(dimension, func(t *testing.T) {
			f, runner := newPhoneMFAFixture(t, "sms")
			ctx := t.Context()
			conn, err := f.st.Connections().GetByName(ctx, f.tn.ID, "Username-Password-Authentication")
			if err != nil {
				t.Fatal(err)
			}
			const number = "+14155550100"
			for range 10 {
				if err := f.h.sendIdentifierCode(ctx, f.tn.ID, conn.ID, number, "signup", ""); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.h.sendIdentifierCode(ctx, f.tn.ID, conn.ID, number, "signup", ""); err == nil {
				t.Fatal("exhausted signup budget accepted")
			}
			if runner.count() != 10 {
				t.Fatalf("denied send reached provider: %d sends", runner.count())
			}
			otherConn, otherKind, otherNumber := conn.ID, "signup", number
			switch dimension {
			case "connection":
				other, err := f.st.Connections().GetByName(ctx, f.tn.ID, "Invite-Only")
				if err != nil {
					t.Fatal(err)
				}
				otherConn = other.ID
			case "kind":
				otherKind = "reset"
			case "identifier":
				otherNumber = "+14155550101"
			}
			if err := f.h.sendIdentifierCode(ctx, f.tn.ID, otherConn, otherNumber, otherKind, ""); err != nil {
				t.Fatalf("independent %s budget denied: %v", dimension, err)
			}
			if runner.count() != 11 {
				t.Fatalf("independent send missing: %d sends", runner.count())
			}
			// Alternate formatting must still hit the original identifier's budget.
			if err := f.h.sendIdentifierCode(ctx, f.tn.ID, conn.ID, "+1 415 555 0100", "signup", ""); err == nil {
				t.Fatal("normalization bypassed exhausted budget")
			}
			*f.clock = f.clock.Add(time.Hour)
			if err := f.h.sendIdentifierCode(ctx, f.tn.ID, conn.ID, number, "signup", ""); err != nil {
				t.Fatalf("budget did not reset: %v", err)
			}
		})
	}
}
