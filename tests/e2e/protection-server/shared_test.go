package main

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"path/filepath"
	"testing"
	"time"
)

// Database-backed: DO NOT run before Plan 19 Task 12.
func TestM19TwoInstancesRestart(t *testing.T) {
	ctx := context.Background()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "shared.db")
	open := func() store.Store {
		s, e := storage.Open(ctx, dsn)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	a := open()
	defer a.Close()
	if err := a.(storage.Migrator).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	b := open()
	defer func() { b.Close() }()
	w, e := keys.NewLocalWrapper(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	p := protectionrules.Defaults()
	p.BruteForce.Enabled = true
	p.BruteForce.MaxAttempts = 2
	p.BruteForce.Shields = []string{"block"}
	p.SuspiciousIP.Enabled = false
	p, e = keys.PatchCAPTCHA(w, "m19", p, map[string]any{"active_provider_id": "recaptcha_v2", "recaptcha_v2": map[string]any{"site_key": "m19-site", "secret": "local-only"}})
	if e != nil {
		t.Fatal(e)
	}
	tn := &store.Tenant{ID: "m19", Name: "m19", ProtectionSettings: p, ProtectionSettingsInitialized: true}
	if e = a.Tenants().Create(ctx, tn); e != nil {
		t.Fatal(e)
	}
	c := &store.Connection{ID: "db", TenantID: tn.ID, Name: "db", Strategy: store.StrategyDatabase, BruteForceProtection: true}
	if e = a.Connections().Create(ctx, c); e != nil {
		t.Fatal(e)
	}
	service := func(st store.Store) *protection.Service {
		return &protection.Service{Store: st, Wrapper: w, CaptchaVerifier: verifier{}, Now: func() time.Time { return time.Unix(1000, 0) }}
	}
	s1, s2 := service(a), service(b)
	attempt := protection.Attempt{Tenant: tn, Connection: c, Identifier: "alice@example.test", IP: "192.0.2.1", Flow: "login"}
	admit := func(s *protection.Service, want bool) {
		t.Helper()
		d, err := s.Begin(ctx, attempt)
		if err != nil || d.Allowed != want {
			t.Fatalf("admission=%+v err=%v want=%v", d, err, want)
		}
		if want {
			if err = s.Finish(ctx, d.Receipt, "failure"); err != nil {
				t.Fatal(err)
			}
		}
	}
	admit(s1, true)
	admit(s2, true)
	admit(s1, false)
	attempt.Flow = "reset-send"
	admit(s1, true)
	admit(s2, true)
	admit(s1, true)
	challenge, err := s1.Challenge(ctx, tn.ID, "login", "txn-1", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if err = s1.VerifyChallenge(ctx, challenge, "m19-valid-shared"); err != nil {
		t.Fatal(err)
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	b = open()
	s2 = service(b)
	admit(s2, false) // send budget survives independent connection/service restart
	attempt.Flow = "login"
	admit(s2, false)
	if err = s2.VerifyChallenge(ctx, challenge, "m19-valid-shared"); !errors.Is(err, protection.ErrCaptchaInvalid) {
		t.Fatalf("replay after restart: %v", err)
	}
	if err = b.Protection().Clear(ctx, tn.ID, store.ProtectionFilter{Kind: store.ProtectionBruteForce, ConnectionID: c.ID, Identifier: attempt.Identifier}); err != nil {
		t.Fatal(err)
	}
	admit(s1, true) // other instance sees unblock without restart/cache refresh
	attempt.Flow = "reset-send"
	admit(s1, false) // unblock cannot reset mail budget
	challenge.TransactionID = "txn-2"
	if err = s2.VerifyChallenge(ctx, challenge, "m19-valid-fresh"); err != nil {
		t.Fatal(err)
	}
	if err = s1.VerifyChallenge(ctx, challenge, "m19-valid-fresh"); !errors.Is(err, protection.ErrCaptchaInvalid) {
		t.Fatalf("cross-instance replay: %v", err)
	}
}
func TestM19LocalFixtures(t *testing.T) {
	c := protection.NewRangeChecker(rangeTransport{})
	for _, tc := range []struct {
		password string
		want     bool
	}{{"M19-Breached-Password!", true}, {"clean-password", false}} {
		got, err := c.Check(context.Background(), tc.password)
		if err != nil || got != tc.want {
			t.Fatalf("range fixture: %v %v", got, err)
		}
	}
	v := verifier{}
	challenge := protection.CaptchaChallenge{ProviderID: "recaptcha_v2", SiteKey: "m19-site"}
	if err := v.Verify(context.Background(), challenge, "m19-valid-proof"); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), challenge, "bad"); !errors.Is(err, protection.ErrCaptchaInvalid) {
		t.Fatal(err)
	}
}
