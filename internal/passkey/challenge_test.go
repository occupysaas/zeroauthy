package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

var testTime = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T) (*Service, *store.User) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	must(t, st.Tenants().Create(ctx, &store.Tenant{ID: "tenant", Name: "tenant", CanonicalHost: "login.example.test"}))
	must(t, st.HostedLogins().Put(ctx, &store.HostedLoginConfig{TenantID: "tenant", Prompts: map[string]any{"universal_login_experience": "new", "identifier_first": true}}, 0))
	must(t, st.Connections().Create(ctx, &store.Connection{TenantID: "tenant", ID: "db", Name: "Database", Strategy: store.StrategyDatabase, EnabledClients: []string{"client"}, Extra: map[string]any{"authentication_methods": map[string]any{"passkey": map[string]any{"enabled": true}}}}))
	u := &store.User{TenantID: "tenant", UserID: "auth0|user", Email: "alice@example.test", Identities: []store.Identity{{Connection: "Database", Provider: "auth0", UserID: "user", PasswordHash: "untouched"}}}
	must(t, st.Users().Create(ctx, u))
	return &Service{Store: st, Now: func() time.Time { return testTime }}, u
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func hostedBinding() Binding {
	return Binding{Purpose: PasskeyLogin, RPID: "login.example.test", Origins: []string{"https://login.example.test"}, TxnID: "txn", CookieHash: "cookie"}
}
func TestIssueTakeSingleUse(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	b := hostedBinding()
	i, err := s.Issue(ctx, "tenant", b, 5*time.Minute)
	must(t, err)
	if len(i.Challenge) != 32 || i.Session != "" || !i.ExpiresAt.Equal(testTime.Add(5*time.Minute)) {
		t.Fatal("wrong hosted parameters")
	}
	ch, err := s.Take(ctx, "tenant", i.ID, b)
	must(t, err)
	if !bytes.Equal(ch.Challenge, i.Challenge) {
		t.Fatal("challenge changed")
	}
	if _, err = s.Take(ctx, "tenant", i.ID, b); !errors.Is(err, ErrCeremony) {
		t.Fatalf("replay: %v", err)
	}
	i, err = s.Issue(ctx, "tenant", b, 5*time.Minute)
	must(t, err)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			ch, err := s.Take(ctx, "tenant", i.ID, b)
			if err == nil && bytes.Equal(ch.Challenge, i.Challenge) {
				winners.Add(1)
			} else if !errors.Is(err, ErrCeremony) {
				t.Errorf("take: %v", err)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners = %d", winners.Load())
	}
}
func TestTakeBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Binding)
	}{
		{"purpose", func(b *Binding) { b.Purpose = PasskeyRegister }},
		{"rp", func(b *Binding) { b.RPID = "example.test" }},
		{"origins", func(b *Binding) { b.Origins = []string{"https://other.example.test"} }},
		{"origin_port", func(b *Binding) { b.Origins = []string{"https://login.example.test:443"} }},
		{"transaction", func(b *Binding) { b.TxnID = "other" }},
		{"cookie", func(b *Binding) { b.CookieHash = "other" }},
		{"client", func(b *Binding) { b.ClientID = "other" }},
		{"realm", func(b *Binding) { b.Realm = "other" }},
		{"organization", func(b *Binding) { b.Organization = "other" }},
		{"user", func(b *Binding) { b.UserID = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := fixture(t)
			ctx := context.Background()
			b := hostedBinding()
			i, err := s.Issue(ctx, "tenant", b, 5*time.Minute)
			must(t, err)
			wrong := b
			tc.change(&wrong)
			if _, err = s.Take(ctx, "tenant", i.ID, wrong); !errors.Is(err, ErrCeremony) {
				t.Fatalf("binding accepted: %v", err)
			}
			if _, err = s.Take(ctx, "tenant", i.ID, b); !errors.Is(err, ErrCeremony) {
				t.Fatal("mismatch did not consume")
			}
		})
	}
	t.Run("tenant", func(t *testing.T) {
		s, _ := fixture(t)
		ctx := context.Background()
		b := hostedBinding()
		i, err := s.Issue(ctx, "tenant", b, time.Minute)
		must(t, err)
		if _, err = s.Take(ctx, "other", i.ID, b); !errors.Is(err, ErrCeremony) {
			t.Fatal(err)
		}
		_, err = s.Take(ctx, "tenant", i.ID, b)
		must(t, err)
	})
	t.Run("expiry", func(t *testing.T) {
		s, _ := fixture(t)
		ctx := context.Background()
		b := hostedBinding()
		i, err := s.Issue(ctx, "tenant", b, time.Minute)
		must(t, err)
		s.Now = func() time.Time { return i.ExpiresAt }
		if _, err = s.Take(ctx, "tenant", i.ID, b); !errors.Is(err, ErrCeremony) {
			t.Fatal(err)
		}
	})
	t.Run("verification_consumes", func(t *testing.T) {
		s, _ := fixture(t)
		ctx := context.Background()
		b := hostedBinding()
		i, err := s.Issue(ctx, "tenant", b, time.Minute)
		must(t, err)
		ch, err := s.Take(ctx, "tenant", i.ID, b)
		must(t, err)
		if _, err = s.Login(ctx, "tenant", []byte(`{}`), ch.Challenge, b); !errors.Is(err, ErrCeremony) {
			t.Fatal(err)
		}
		if _, err = s.Take(ctx, "tenant", i.ID, b); !errors.Is(err, ErrCeremony) {
			t.Fatal(err)
		}
	})
}
func TestNativeSessionHashed(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	b := Binding{Purpose: PasskeyLogin, RPID: "login.example.test", Origins: []string{"https://app.example.test"}, ClientID: "client", Realm: "Database", Organization: "org"}
	i, err := s.Issue(ctx, "tenant", b, time.Minute)
	must(t, err)
	if i.Session == "" || i.ID != secrets.HashToken(i.Session) || !i.ExpiresAt.Equal(testTime.Add(70*time.Second)) {
		t.Fatal("wrong native parameters")
	}
	row, err := s.Store.MFA().GetChallenge(ctx, "tenant", i.ID, testTime)
	must(t, err)
	doc, _ := json.Marshal(row)
	if bytes.Contains(doc, []byte(i.Session)) {
		t.Fatal("raw session stored")
	}
	if _, err = s.Store.MFA().GetChallenge(ctx, "tenant", i.Session, testTime); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("session used as storage key")
	}
	_, err = s.Take(ctx, "tenant", secrets.HashToken(i.Session), b)
	must(t, err)
}
