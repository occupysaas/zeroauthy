package login

import (
	"context"
	"database/sql"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// This local fixture follows the server-DSN convention used by sqlstore tests.
// Each case gets its own database, so it never writes another suite's fixtures.
func organizationSQLStores(t *testing.T) map[string]func(*testing.T) *sqlstore.Store {
	makers := map[string]func(*testing.T) *sqlstore.Store{}
	open := func(t *testing.T, dsn string) *sqlstore.Store {
		t.Helper()
		st, err := sqlstore.Open(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if err = st.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
		return st
	}
	makers["sqlite"] = func(t *testing.T) *sqlstore.Store {
		return open(t, "sqlite://"+filepath.Join(t.TempDir(), "organization.db"))
	}
	for kind, key := range map[string]string{"postgres": "ZA_TEST_POSTGRES_DSN", "mysql": "ZA_TEST_MYSQL_DSN"} {
		dsn := os.Getenv(key)
		if dsn == "" {
			continue
		}
		makers[kind] = func(t *testing.T) *sqlstore.Store {
			t.Helper()
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatal(err)
			}
			driver, native, drop := "pgx", dsn, " WITH (FORCE)"
			if kind == "mysql" {
				cfg := mysql.NewConfig()
				cfg.User = u.User.Username()
				cfg.Passwd, _ = u.User.Password()
				cfg.Net, cfg.Addr = "tcp", u.Host
				driver, native, drop = "mysql", cfg.FormatDSN(), ""
			}
			admin, err := sql.Open(driver, native)
			if err != nil {
				t.Fatal(err)
			}
			name := "zt8_" + strings.ToLower(secrets.RandomString(12))
			if _, err = admin.Exec("CREATE DATABASE " + name); err != nil {
				_ = admin.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + name + drop); _ = admin.Close() })
			u.Path = "/" + name
			return open(t, u.String())
		}
	}
	return makers
}

type organizationReadBarrier struct {
	store.Store
	afterGet func()
}

func (s organizationReadBarrier) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(organizationReadBarrier{Store: tx, afterGet: s.afterGet}) })
}
func (s organizationReadBarrier) AuthTransactions() store.AuthTransactions {
	return organizationTxnBarrier{AuthTransactions: s.Store.AuthTransactions(), afterGet: s.afterGet}
}

type organizationTxnBarrier struct {
	store.AuthTransactions
	afterGet func()
}

func (s organizationTxnBarrier) Get(ctx context.Context, tid, id string) (*store.AuthTransaction, error) {
	txn, err := s.AuthTransactions.Get(ctx, tid, id)
	if err == nil {
		s.afterGet()
	}
	return txn, err
}

// B reads the pending transaction first, A commits its choice, and only then
// B continues. B must fail rather than delete A's bound choice. The barrier
// preserves the real SQL read and every subsequent repository operation.
func TestOrganizationBindingSQLConcurrentChoice(t *testing.T) {
	for name, mk := range organizationSQLStores(t) {
		t.Run(name, func(t *testing.T) {
			st := mk(t)
			e := newEnvWithStore(t, st)
			a, _, _ := organizationFixture(t, e, store.OrgBehaviorPreLoginPrompt, true, false)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			b := &store.Organization{TenantID: a.TenantID, ID: "org_0000000000000002", Name: "second", DisplayName: "Second"}
			if err := st.Organizations().Create(ctx, b, nil); err != nil {
				t.Fatal(err)
			}
			txn := &store.AuthTransaction{TenantID: a.TenantID, ID: "pending-org", ClientID: "spa", Params: map[string]string{store.TxnParamOrgMode: string(authz.OrgPromptBefore)}, ExpiresAt: fixedNow().Add(time.Hour)}
			if err := st.AuthTransactions().Create(ctx, txn); err != nil {
				t.Fatal(err)
			}
			first, err := st.AuthTransactions().Get(ctx, a.TenantID, txn.ID)
			if err != nil {
				t.Fatal(err)
			}
			second, err := st.AuthTransactions().Get(ctx, a.TenantID, txn.ID)
			if err != nil {
				t.Fatal(err)
			}
			res := tenant.Resolved{Tenant: mustTenant(t, e, "acme")}
			fa, fb := &flow{res: res, txn: first}, &flow{res: res, txn: second}
			r := httptest.NewRequest("POST", "https://acme.example.test/u/login", nil).WithContext(ctx)
			if name == "sqlite" {
				// SQLite BEGIN IMMEDIATE serializes transactions before their first read.
				if err := e.h.bindOrg(r, fa, a); err != nil {
					t.Fatal(err)
				}
				if err := e.h.bindOrg(r, fb, b); err == nil {
					t.Fatal("stale second choice accepted")
				}
			} else {
				read, release := make(chan struct{}), make(chan struct{})
				defer close(release)
				paused := *e.h
				paused.Store = organizationReadBarrier{Store: st, afterGet: func() {
					close(read)
					select {
					case <-release:
					case <-ctx.Done():
					}
				}}
				done := make(chan error, 1)
				go func() { done <- paused.bindOrg(r, fb, b) }()
				select {
				case <-read:
				case err := <-done:
					t.Fatalf("B failed before reading: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if err := e.h.bindOrg(r, fa, a); err != nil {
					t.Fatal(err)
				}
				release <- struct{}{}
				select {
				case err := <-done:
					if err == nil {
						t.Error("concurrent loser overwrote the bound organization")
					} else if !errors.Is(err, store.ErrConflict) && !errors.Is(err, errTxn) {
						t.Errorf("loser error: %v", err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			saved, err := st.AuthTransactions().Get(ctx, a.TenantID, txn.ID)
			if err != nil {
				t.Fatal(err)
			}
			if saved.Params[store.TxnParamOrgID] != a.ID || saved.HostedState.Revision != 1 {
				t.Fatalf("winning binding was replaced: %+v", saved)
			}
		})
	}
}
