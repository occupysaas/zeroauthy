package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func testEmail(t *testing.T, newStore Factory) {
	ctx := context.Background()
	t.Run("provider CAS and monotonic revisions", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("email")))
		p := &store.EmailProvider{TenantID: "ten_email", Name: "smtp", Enabled: true, DefaultFrom: "a@example.test", PublicConfig: map[string]any{"smtp_host": "smtp.example.test", "headers": map[string]any{"X-Test": "y"}}, SealedCredentials: []byte{1, 2, 3}}
		if _, err := s.EmailProviders().Get(ctx, "ten_email"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("absent provider: %v", err)
		}
		mustNoErr(t, s.EmailProviders().Put(ctx, p, 0))
		got, err := s.EmailProviders().Get(ctx, "ten_email")
		mustNoErr(t, err)
		if got.Revision != 1 {
			t.Fatalf("revision=%d", got.Revision)
		}
		got.PublicConfig["headers"].(map[string]any)["X-Test"] = "mutated"
		got.SealedCredentials[0] = 9
		again, err := s.EmailProviders().Get(ctx, "ten_email")
		mustNoErr(t, err)
		if again.PublicConfig["headers"].(map[string]any)["X-Test"] != "y" || again.SealedCredentials[0] != 1 {
			t.Fatal("provider values are not deeply copied")
		}
		if err := s.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "ten_email", Name: "smtp", Enabled: false}, 0); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("duplicate create: %v", err)
		}
		if err := s.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "ten_email", Name: "smtp", Enabled: false}, 1); err != nil {
			t.Fatal(err)
		}
		updated, err := s.EmailProviders().Get(ctx, "ten_email")
		mustNoErr(t, err)
		if updated.Revision != 2 {
			t.Fatalf("updated revision=%d", updated.Revision)
		}
		if err := s.EmailProviders().Put(ctx, updated, 1); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("stale update: %v", err)
		}
		if err := s.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "ten_email", Name: "sendgrid"}, 2); err != nil {
			t.Fatalf("provider-kind replacement: %v", err)
		}
		if err := s.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "ten_email", Name: "smtp", PublicConfig: map[string]any{"headers": map[string]any{"X-Test": map[string]any{"api_token": "SENTINEL"}}}}, 3); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("secret-looking config accepted: %v", err)
		}
		if err := s.EmailProviders().Delete(ctx, "ten_email", 3); err != nil {
			t.Fatal(err)
		}
		if err := s.EmailProviders().Delete(ctx, "ten_email", 3); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("delete absent: %v", err)
		}
		if err := s.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "ten_email", Name: "sendgrid"}, 0); err != nil {
			t.Fatal(err)
		}
		recreated, err := s.EmailProviders().Get(ctx, "ten_email")
		mustNoErr(t, err)
		if recreated.Revision != 4 {
			t.Fatalf("recreated revision=%d, want 4", recreated.Revision)
		}
		if err := s.EmailProviders().Delete(ctx, "ten_email", 3); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("stale delete: %v", err)
		}
	})
	t.Run("templates CAS and deep copies", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("email")))
		tmpl := &store.EmailTemplate{TenantID: "ten_email", Name: "welcome_email", Fields: map[string]any{"body": "hello", "nested": map[string]any{"enabled": true}}}
		if _, err := s.EmailTemplates().Get(ctx, "ten_email", "welcome_email"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("absent template: %v", err)
		}
		mustNoErr(t, s.EmailTemplates().Put(ctx, tmpl, 0))
		got, err := s.EmailTemplates().Get(ctx, "ten_email", "welcome_email")
		mustNoErr(t, err)
		if got.Revision != 1 {
			t.Fatalf("revision=%d", got.Revision)
		}
		got.Fields["nested"].(map[string]any)["enabled"] = false
		again, err := s.EmailTemplates().Get(ctx, "ten_email", "welcome_email")
		mustNoErr(t, err)
		if again.Fields["nested"].(map[string]any)["enabled"] != true {
			t.Fatal("template is not deeply copied")
		}
		if err := s.EmailTemplates().Put(ctx, got, 0); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("duplicate template: %v", err)
		}
		if err := s.EmailTemplates().Put(ctx, got, 1); err != nil {
			t.Fatal(err)
		}
		next, err := s.EmailTemplates().Get(ctx, "ten_email", "welcome_email")
		mustNoErr(t, err)
		if next.Revision != 2 {
			t.Fatalf("revision=%d", next.Revision)
		}
	})
	t.Run("tenant isolation", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("email")))
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("other")))
		mustNoErr(t, s.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "ten_email", Name: "sendgrid", DefaultFrom: "a@example.test"}, 0))
		mustNoErr(t, s.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "ten_other", Name: "sendgrid", DefaultFrom: "b@example.test"}, 0))
		a, err := s.EmailProviders().Get(ctx, "ten_email")
		mustNoErr(t, err)
		b, err := s.EmailProviders().Get(ctx, "ten_other")
		mustNoErr(t, err)
		if a.DefaultFrom == b.DefaultFrom {
			t.Fatal("tenant provider records crossed")
		}
		if _, err := s.EmailTemplates().Get(ctx, "ten_other", "welcome_email"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross-tenant template read: %v", err)
		}
	})
	t.Run("claims windows concurrency and cleanup", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("email")))
		now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
		expires := now.Add(time.Minute)
		const n = 40
		var wg sync.WaitGroup
		var mu sync.Mutex
		granted := 0
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := s.EmailNotifications().Claim(ctx, "ten_email", "subject", "preview", "2026-10-25T12:00Z", now, expires, 3)
				if err != nil {
					t.Error(err)
					return
				}
				if ok {
					mu.Lock()
					granted++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if granted != 3 {
			t.Fatalf("granted=%d, want 3", granted)
		}
		ok, err := s.EmailNotifications().Claim(ctx, "ten_email", "subject", "welcome", "", now, time.Time{}, 1)
		mustNoErr(t, err)
		if !ok {
			t.Fatal("permanent first claim denied")
		}
		ok, err = s.EmailNotifications().Claim(ctx, "ten_email", "subject", "welcome", "", now, time.Time{}, 1)
		mustNoErr(t, err)
		if ok {
			t.Fatal("permanent claim repeated")
		}
		if ok, err := s.EmailNotifications().Claim(ctx, "ten_email", "subject", "reset", "", now, now, 1); !errors.Is(err, store.ErrInvalid) || ok {
			t.Fatalf("invalid expiry = %v, %v", ok, err)
		}
		if ok, err := s.EmailNotifications().Claim(ctx, "ten_email", "subject", "other", "", now, expires, 0); !errors.Is(err, store.ErrInvalid) || ok {
			t.Fatalf("invalid limit = %v, %v", ok, err)
		}
		if _, err := s.EmailNotifications().Claim(ctx, "missing", "s", "p", "e", now, expires, 1); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("missing tenant: %v", err)
		}
		next := now.Add(time.Minute)
		ok, err = s.EmailNotifications().Claim(ctx, "ten_email", "subject", "preview", "2026-10-25T12:01Z", next, next.Add(time.Minute), 3)
		mustNoErr(t, err)
		if !ok {
			t.Fatal("new window claim denied")
		}
		ok, err = s.EmailNotifications().Claim(ctx, "ten_email", "subject", "preview", "2026-10-25T12:00Z", next, next.Add(time.Minute), 3)
		mustNoErr(t, err)
		if !ok {
			t.Fatal("expired claim did not open a new window")
		}
		removed, err := s.EmailNotifications().Sweep(ctx, next.Add(2*time.Minute), 100)
		mustNoErr(t, err)
		if removed < 2 {
			t.Fatalf("swept=%d", removed)
		}
	})
	t.Run("transaction rollback and tenant deletion", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("email")))
		now := time.Now().UTC()
		boom := fmt.Errorf("rollback")
		err := s.WithTx(ctx, func(tx store.Store) error {
			mustNoErr(t, tx.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "ten_email", Name: "smtp"}, 0))
			mustNoErr(t, tx.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "ten_email", Name: "welcome_email", Fields: map[string]any{"body": "x"}}, 0))
			_, err := tx.EmailNotifications().Claim(ctx, "ten_email", "u", "welcome", "", now, time.Time{}, 1)
			mustNoErr(t, err)
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("tx error=%v", err)
		}
		if _, err := s.EmailProviders().Get(ctx, "ten_email"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("provider survived rollback: %v", err)
		}
		mustNoErr(t, s.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "ten_email", Name: "smtp"}, 0))
		rolledBackCounter, err := s.EmailProviders().Get(ctx, "ten_email")
		mustNoErr(t, err)
		if rolledBackCounter.Revision != 1 {
			t.Fatalf("provider revision after rollback=%d, want 1", rolledBackCounter.Revision)
		}
		if _, err := s.EmailTemplates().Get(ctx, "ten_email", "welcome_email"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("template survived rollback: %v", err)
		}
		_, err = s.EmailNotifications().Claim(ctx, "ten_email", "u", "welcome", "", now, time.Time{}, 1)
		mustNoErr(t, err)
		if err := s.Tenants().Delete(ctx, "ten_email"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.EmailNotifications().Claim(ctx, "ten_email", "u", "welcome", "", now, time.Time{}, 1); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("claim after tenant deletion: %v", err)
		}
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("email")))
		mustNoErr(t, s.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "ten_email", Name: "smtp"}, 0))
		recreated, err := s.EmailProviders().Get(ctx, "ten_email")
		mustNoErr(t, err)
		if recreated.Revision != 1 {
			t.Fatalf("provider revision after tenant recreation=%d, want 1", recreated.Revision)
		}
	})
	t.Run("user and system operator claim deletion", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("email")))
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("system")))
		now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
		user := newUser("ten_email", "claim-user", "claim@example.test", "claim")
		mustNoErr(t, s.Users().Create(ctx, user))
		ok, err := s.EmailNotifications().Claim(ctx, "ten_email", user.UserID, "welcome", "", now, time.Time{}, 1)
		mustNoErr(t, err)
		if !ok {
			t.Fatal("initial welcome claim denied")
		}
		mustNoErr(t, s.Users().Delete(ctx, "ten_email", user.UserID))
		ok, err = s.EmailNotifications().Claim(ctx, "ten_email", user.UserID, "welcome", "", now, time.Time{}, 1)
		mustNoErr(t, err)
		if !ok {
			t.Fatal("user deletion retained welcome claim")
		}

		operator := newOperator("ten_system", "auth0|operator", "email")
		mustNoErr(t, s.Operators().Upsert(ctx, operator))
		for _, purpose := range []string{"preview", "test"} {
			ok, err = s.EmailNotifications().Claim(ctx, "ten_email", operator.UserID, purpose, "minute", now, now.Add(time.Minute), 3)
			mustNoErr(t, err)
			if !ok {
				t.Fatalf("initial %s claim denied", purpose)
			}
		}
		mustNoErr(t, s.Operators().Delete(ctx, operator.TenantID, operator.UserID))
		for _, purpose := range []string{"preview", "test"} {
			ok, err = s.EmailNotifications().Claim(ctx, "ten_email", operator.UserID, purpose, "minute", now, now.Add(time.Minute), 3)
			mustNoErr(t, err)
			if !ok {
				t.Fatalf("operator deletion retained %s claim", purpose)
			}
		}
	})
}
