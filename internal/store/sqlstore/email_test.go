package sqlstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func openEmailSQLite(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), "sqlite://"+path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		_ = s.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func emailTenant(id string) *store.Tenant {
	return &store.Tenant{ID: id, Name: id, FriendlyName: id, DefaultAudience: "https://api.example.test", DefaultDirectory: "Database", SessionLifetime: 3600, IdleSessionLifetime: 600}
}

func TestEmailRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "email.db")
	s := openEmailSQLite(t, path)
	if err := s.Tenants().Create(ctx, emailTenant("tenant-email")); err != nil {
		t.Fatal(err)
	}
	p := &store.EmailProvider{TenantID: "tenant-email", Name: "mailgun", Enabled: true, DefaultFrom: "mail@example.test", SealedCredentials: []byte{1, 2, 3}, PublicConfig: map[string]any{"domain": "mail.example.test"}}
	if err := s.EmailProviders().Put(ctx, p, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-email", Name: "welcome_email", Fields: map[string]any{"body": "Hello"}}, 0); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.EmailNotifications().Claim(ctx, "tenant-email", "user-1", "welcome", "", time.Now().UTC(), time.Time{}, 1); err != nil || !ok {
		t.Fatalf("claim=%v, %v", ok, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := openEmailSQLite(t, path)
	got, err := s2.EmailProviders().Get(ctx, "tenant-email")
	if err != nil || got.Revision != 1 || !bytes.Equal(got.SealedCredentials, []byte{1, 2, 3}) {
		t.Fatalf("provider after restart=%+v, %v", got, err)
	}
	if _, err := s2.EmailTemplates().Get(ctx, "tenant-email", "welcome_email"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s2.EmailNotifications().Claim(ctx, "tenant-email", "user-1", "welcome", "", time.Now().UTC(), time.Time{}, 1); err != nil || ok {
		t.Fatalf("duplicate claim after restart=%v, %v", ok, err)
	}
}

func TestEmailConcurrentHandles(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "email-concurrent.db")
	a := openEmailSQLite(t, path)
	b, err := Open(ctx, "sqlite://"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := a.Tenants().Create(ctx, emailTenant("tenant-email")); err != nil {
		t.Fatal(err)
	}
	if err := a.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "tenant-email", Name: "smtp"}, 0); err != nil {
		t.Fatal(err)
	}
	const contenders = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	won, conflicts := 0, 0
	errs := []error{}
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			db := a
			if i%2 != 0 {
				db = b
			}
			err := db.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "tenant-email", Name: "sendgrid"}, 1)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				won++
			} else if errors.Is(err, store.ErrConflict) {
				conflicts++
			} else {
				errs = append(errs, err)
			}
		}(i)
	}
	wg.Wait()
	if won != 1 || conflicts != contenders-1 || len(errs) > 0 {
		t.Fatalf("provider CAS outcomes: won=%d conflicts=%d errs=%v", won, conflicts, errs)
	}
	const claimLimit = 4
	won = 0
	errs = nil
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			db := a
			if i%2 != 0 {
				db = b
			}
			ok, err := db.EmailNotifications().Claim(ctx, "tenant-email", "op", "test", "window", time.Now().UTC(), time.Now().UTC().Add(time.Minute), claimLimit)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			} else if ok {
				won++
			}
		}(i)
	}
	wg.Wait()
	if won != claimLimit || len(errs) > 0 {
		t.Fatalf("notification claims: won=%d errors=%v", won, errs)
	}
}

func TestEmailUpgradeWithoutRecords(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "email-upgrade.db")
	s, err := Open(ctx, "sqlite://"+path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.migrateTo(ctx, 17); err != nil {
		t.Fatal(err)
	}
	if err := s.Tenants().Create(ctx, emailTenant("legacy")); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateTo(ctx, 18); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EmailProviders().Get(ctx, "legacy"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("legacy provider=%v", err)
	}
	if _, err := s.EmailTemplates().Get(ctx, "legacy", "verify_email"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("legacy template=%v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEmailCredentialsAtRest(t *testing.T) {
	ctx := context.Background()
	s := openEmailSQLite(t, filepath.Join(t.TempDir(), "email-at-rest.db"))
	if err := s.Tenants().Create(ctx, emailTenant("tenant-email")); err != nil {
		t.Fatal(err)
	}
	secret := []byte("SENTINEL_EMAIL_SECRET")
	wrapper, err := keys.NewLocalWrapper(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keys.SealEmailProvider(wrapper, "tenant-email", "smtp", secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "tenant-email", Name: "smtp", SealedCredentials: sealed}, 0); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := s.queryRow(ctx, "SELECT sealed_credentials FROM email_providers WHERE tenant_id = ?", "tenant-email").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, secret) {
		t.Fatal("cleartext credential stored in sealed column")
	}
	var config string
	if err := s.queryRow(ctx, "SELECT public_config FROM email_providers WHERE tenant_id = ?", "tenant-email").Scan(&config); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(config), secret) {
		t.Fatal("cleartext credential stored in public config")
	}
}

func TestEmailRollbackRestoresRevisionAndCiphertext(t *testing.T) {
	ctx := context.Background()
	s := openEmailSQLite(t, filepath.Join(t.TempDir(), "email-rollback.db"))
	if err := s.Tenants().Create(ctx, emailTenant("tenant-email")); err != nil {
		t.Fatal(err)
	}
	original := []byte{1, 2, 3}
	if err := s.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "tenant-email", Name: "smtp", SealedCredentials: original}, 0); err != nil {
		t.Fatal(err)
	}
	boom := fmt.Errorf("forced rollback")
	err := s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "tenant-email", Name: "sendgrid", SealedCredentials: []byte{4, 5, 6}}, 1); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("transaction error=%v", err)
	}
	got, err := s.EmailProviders().Get(ctx, "tenant-email")
	if err != nil || got.Revision != 1 || !bytes.Equal(got.SealedCredentials, original) {
		t.Fatalf("after rollback=%+v, %v", got, err)
	}
}
