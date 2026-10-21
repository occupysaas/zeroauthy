package jobs

import (
	"context"
	"database/sql"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
)

// forEachStore runs fn against a fresh store of every driver under test:
// memory and SQLite always, PostgreSQL and MySQL when scripts/test-sql.sh
// sets ZA_TEST_POSTGRES_DSN and ZA_TEST_MYSQL_DSN.
func forEachStore(t *testing.T, fn func(t *testing.T, st store.Store)) {
	makers := map[string]func(t *testing.T) store.Store{
		"memory": func(*testing.T) store.Store { return memory.New() },
		"sqlite": func(t *testing.T) store.Store { return openSQL(t, "sqlite://"+filepath.Join(t.TempDir(), "z.db")) },
	}
	if dsn := os.Getenv("ZA_TEST_POSTGRES_DSN"); dsn != "" {
		makers["postgres"] = func(t *testing.T) store.Store { return openSQL(t, freshDatabase(t, "postgres", dsn)) }
	}
	if dsn := os.Getenv("ZA_TEST_MYSQL_DSN"); dsn != "" {
		makers["mysql"] = func(t *testing.T) store.Store { return openSQL(t, freshDatabase(t, "mysql", dsn)) }
	}
	for _, name := range slices.Sorted(maps.Keys(makers)) {
		t.Run(name, func(t *testing.T) { fn(t, makers[name](t)) })
	}
}

func openSQL(t *testing.T, dsn string) store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := sqlstore.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return st
}

// freshDatabase creates an empty database on the server of adminDSN (a
// URL DSN), drops it at cleanup and returns its URL DSN.
func freshDatabase(t *testing.T, kind, adminDSN string) string {
	t.Helper()
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	driver, native, drop := "pgx", adminDSN, " WITH (FORCE)"
	if kind == "mysql" {
		cfg := mysql.NewConfig()
		cfg.User = u.User.Username()
		cfg.Passwd, _ = u.User.Password()
		cfg.Net, cfg.Addr = "tcp", u.Host
		driver, native, drop = "mysql", cfg.FormatDSN(), ""
	}
	name := "zj_" + strings.ToLower(secrets.RandomString(12))
	admin, err := sql.Open(driver, native)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if a, err := sql.Open(driver, native); err == nil {
			_, _ = a.Exec("DROP DATABASE IF EXISTS " + name + drop)
			_ = a.Close()
		}
	})
	u.Path = "/" + name
	return u.String()
}
