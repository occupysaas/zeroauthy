package memory_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	"testing"
	"time"
)

func TestMFAGuardianDefaults(t *testing.T) {
	s := memory.New()
	if err := s.Tenants().Create(context.Background(), &store.Tenant{ID: "tenant", Name: "tenant"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.MFA().GetGuardian(context.Background(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Factors) != 8 || len(got.Policies) != 0 {
		t.Fatalf("unexpected defaults: %#v", got)
	}
	for name, enabled := range got.Factors {
		if enabled {
			t.Errorf("%s enabled by default", name)
		}
	}
}

func TestMFAConformance(t *testing.T) {
	storetest.MFA(t, func(*testing.T) store.Store { return memory.New() })
}

func TestMFATransactionRollback(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	sentinel := errors.New("rollback")
	if err := s.Tenants().Create(ctx, &store.Tenant{ID: "tenant", Name: "tenant"}); err != nil {
		t.Fatal(err)
	}
	err := s.WithTx(ctx, func(tx store.Store) error {
		g, err := tx.MFA().GetGuardian(ctx, "tenant")
		if err != nil {
			return err
		}
		g.Factors["otp"] = true
		if err := tx.MFA().PutGuardian(ctx, g, 0); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	g, err := s.MFA().GetGuardian(ctx, "tenant")
	if err != nil || g.Factors["otp"] || g.Version != 0 {
		t.Fatalf("rollback: %+v, %v", g, err)
	}
}

func TestMFATransactionRollbackAllRecords(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
	must(s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "u"}))
	g, err := s.MFA().GetGuardian(ctx, "t")
	must(err)
	g.Stored = map[string]json.RawMessage{"route": json.RawMessage(`{"v":1}`)}
	g.SealedSecrets = map[string][]byte{"route": []byte("sealed")}
	must(s.MFA().PutGuardian(ctx, g, 0))
	must(s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "t", UserID: "u", ID: "id", Type: "totp", SealedSecret: []byte("secret")}))
	must(s.MFA().CreateMFAToken(ctx, &store.MFAToken{TenantID: "t", UserID: "u", Hash: "token", Request: json.RawMessage(`{"v":1}`), ExpiresAt: expiry}))
	must(s.MFA().CreateChallenge(ctx, &store.MFAChallenge{TenantID: "t", UserID: "u", ID: "challenge", Challenge: []byte("challenge"), ExpiresAt: expiry}))
	must(s.MFA().CreateTicket(ctx, &store.EnrollmentTicket{TenantID: "t", UserID: "u", Hash: "ticket", ExpiresAt: expiry}))
	must(s.MFA().PutBrowser(ctx, &store.MFABrowser{TenantID: "t", UserID: "u", Hash: "browser", Kind: "remember", ExpiresAt: expiry}))
	sentinel := errors.New("rollback")
	err = s.WithTx(ctx, func(tx store.Store) error {
		g, e := tx.MFA().GetGuardian(ctx, "t")
		if e != nil {
			return e
		}
		g.Stored["route"][2] = 'x'
		g.SealedSecrets["route"][0] = 'x'
		if e = tx.MFA().PutGuardian(ctx, g, 1); e != nil {
			return e
		}
		if e = tx.MFA().AcceptTOTPStep(ctx, "t", "u", "id", 10, now); e != nil {
			return e
		}
		if _, e = tx.MFA().ConsumeMFAToken(ctx, "t", "token", "", now); e != nil {
			return e
		}
		if _, e = tx.MFA().FailChallenge(ctx, "t", "challenge"); e != nil {
			return e
		}
		if _, e = tx.MFA().ConsumeTicket(ctx, "t", "ticket", now); e != nil {
			return e
		}
		if e = tx.MFA().PutBrowser(ctx, &store.MFABrowser{TenantID: "t", UserID: "u", Hash: "browser", Kind: "device", ExpiresAt: expiry}); e != nil {
			return e
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	g, err = s.MFA().GetGuardian(ctx, "t")
	must(err)
	if string(g.Stored["route"]) != `{"v":1}` || string(g.SealedSecrets["route"]) != "sealed" {
		t.Fatal(g)
	}
	a, err := s.MFA().GetAuthenticator(ctx, "t", "u", "id")
	must(err)
	if a.LastStep != 0 || string(a.SealedSecret) != "secret" {
		t.Fatal(a)
	}
	tok, err := s.MFA().PeekMFAToken(ctx, "t", "token", now)
	must(err)
	if string(tok.Request) != `{"v":1}` {
		t.Fatal(tok)
	}
	challenge, err := s.MFA().GetChallenge(ctx, "t", "challenge", now)
	must(err)
	if challenge.Attempts != 0 || string(challenge.Challenge) != "challenge" {
		t.Fatal(challenge)
	}
	_, err = s.MFA().ConsumeTicket(ctx, "t", "ticket", now)
	must(err)
	browser, err := s.MFA().GetBrowser(ctx, "t", "browser", now)
	must(err)
	if browser.Kind != "remember" {
		t.Fatal(browser)
	}
}
