package sqlstore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestMFAConformance(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) { storetest.MFA(t, func(t *testing.T) store.Store { return fresh(t) }) })
	}
}

func TestMFAMigrationFrom32(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 32)
			ctx := context.Background()
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			u := &store.User{TenantID: "t", UserID: "u"}
			args, err := userArgs(u)
			mustEvent(t, err)
			_, err = s.exec(ctx, `INSERT INTO users (`+userColsBeforeActionsII+`, last_password_reset) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args[:23]...)
			mustEvent(t, err)
			_, err = s.exec(ctx, `INSERT INTO sessions (tenant_id,id,token_hash,user_id,connection,authenticated_at,client_ids,expires_at,idle_expires_at,created_at,updated_at,last_interacted_at,initial_ip,initial_user_agent,last_ip,last_user_agent,cookie_mode,origin) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "t", "s", "h", "u", "", 0, "[]", 0, 0, 0, 0, 0, "", "", "", "", "", "")
			mustEvent(t, err)
			mustEvent(t, s.Migrate(ctx))
			var epoch int
			var mfa any
			mustEvent(t, s.queryRow(ctx, `SELECT remember_browser_epoch FROM users WHERE tenant_id=? AND user_id=?`, "t", "u").Scan(&epoch))
			mustEvent(t, s.queryRow(ctx, `SELECT mfa_at FROM sessions WHERE tenant_id=? AND id=?`, "t", "s").Scan(&mfa))
			if epoch != 0 || mfa != nil {
				t.Fatalf("epoch=%d mfa=%v", epoch, mfa)
			}
		})
	}
}

func TestMFAConditionalUpdatesConcurrent(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			dsn := mk(t)
			s := mustOpen(t, dsn)
			other := mustOpenRaw(t, dsn)
			ctx := context.Background()
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			mustEvent(t, s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "u"}))
			mustEvent(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "t", UserID: "u", ID: "totp", Type: "totp"}))
			mustEvent(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "t", UserID: "u", ID: "recovery", Type: "recovery-code", CodeHash: "old"}))
			for _, op := range []func(store.MFA) error{func(m store.MFA) error { return m.AcceptTOTPStep(ctx, "t", "u", "totp", 1, time.Now()) }, func(m store.MFA) error { return m.ReplaceRecoveryCode(ctx, "t", "u", "old", "new", time.Now()) }} {
				var wg sync.WaitGroup
				errs := make([]error, 2)
				for i, m := range []store.MFA{s.MFA(), other.MFA()} {
					wg.Add(1)
					go func(i int, m store.MFA) { defer wg.Done(); errs[i] = op(m) }(i, m)
				}
				wg.Wait()
				wins := 0
				for _, err := range errs {
					if err == nil {
						wins++
					} else if !errors.Is(err, store.ErrPrecondition) {
						t.Fatal(err)
					}
				}
				if wins != 1 {
					t.Fatalf("wins=%d errors=%v", wins, errs)
				}
			}
		})
	}
}

func TestMFAMySQLMigrationResume33(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		if name != "mysql" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 32)
			ms, err := s.migrations()
			mustEvent(t, err)
			for _, m := range ms {
				if m.version == 33 {
					for _, stmt := range m.statements[:5] {
						_, err = s.exec(t.Context(), stmt)
						mustEvent(t, err)
					}
				}
			}
			version, err := s.SchemaVersion(t.Context())
			mustEvent(t, err)
			if version != 32 {
				t.Fatal(version)
			}
			mustEvent(t, s.Migrate(t.Context()))
			mustEvent(t, s.Migrate(t.Context()))
			version, err = s.SchemaVersion(t.Context())
			mustEvent(t, err)
			if version != 33 {
				t.Fatal(version)
			}
			mustEvent(t, s.Tenants().Create(t.Context(), &store.Tenant{ID: "t", Name: "t"}))
			mustEvent(t, s.Users().Create(t.Context(), &store.User{TenantID: "t", UserID: "u"}))
			mustEvent(t, s.MFA().CreateAuthenticator(t.Context(), &store.Authenticator{TenantID: "t", UserID: "u", ID: "a"}))
		})
	}
}

func TestMFATokenClientDeletionConcurrent(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			dsn := mk(t)
			s := mustOpen(t, dsn)
			other := mustOpenRaw(t, dsn)
			ctx := context.Background()
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			mustEvent(t, s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "u"}))
			mustEvent(t, s.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "c"}))
			deleted := make(chan struct{})
			release := make(chan struct{})
			deleteDone := make(chan error, 1)
			go func() {
				deleteDone <- s.WithTx(ctx, func(tx store.Store) error {
					if err := tx.Clients().Delete(ctx, "t", "c"); err != nil {
						return err
					}
					close(deleted)
					<-release
					return nil
				})
			}()
			<-deleted
			created := make(chan error, 1)
			go func() {
				created <- other.MFA().CreateMFAToken(ctx, &store.MFAToken{TenantID: "t", UserID: "u", ClientID: "c", Hash: "h", ExpiresAt: time.Now().Add(time.Hour)})
			}()
			var createErr error
			returned := false
			select {
			case createErr = <-created:
				returned = true
			case <-time.After(250 * time.Millisecond):
			}
			close(release)
			mustEvent(t, <-deleteDone)
			if !returned {
				createErr = <-created
			}
			if createErr != nil && !errors.Is(createErr, store.ErrNotFound) {
				t.Fatal(createErr)
			}
			mustEvent(t, s.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "c"}))
			_, err := s.MFA().PeekMFAToken(ctx, "t", "h", time.Now())
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("token survived client deletion: %v (create=%v)", err, createErr)
			}
		})
	}
}

// Review I1: per-user MFA cleanup (DeleteUserMFA) and lookups use indexed
// (tenant_id,user_id) access on every ephemeral MFA table.
func TestMFAUserIndexes(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := fresh(t)
			for _, table := range []string{"mfa_tokens", "mfa_challenges", "mfa_tickets", "mfa_browsers"} {
				found := false
				for _, d := range actionsIISchemaDefinition(t, s, table) {
					d = strings.ToLower(strings.Join(strings.Fields(strings.NewReplacer("`", "", `"`, "").Replace(d)), " "))
					if strings.Contains(d, table+"_user") && (strings.Contains(d, "(tenant_id,user_id)") || strings.Contains(d, "(tenant_id, user_id)")) {
						found = true
					}
				}
				if !found {
					t.Errorf("%s lacks a (tenant_id,user_id) index: %v", table, actionsIISchemaDefinition(t, s, table))
				}
			}
		})
	}
}
