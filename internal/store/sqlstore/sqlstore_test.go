package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Environment for the server dialects; scripts/test-sql.sh sets them.
const (
	envPostgres = "ZEROAUTHY_TEST_POSTGRES_DSN" // postgres://…/postgres (an admin database)
	envMySQL    = "ZEROAUTHY_TEST_MYSQL_DSN"    // mysql://root:…@host:port/ (no database)
)

// dsnsUnderTest returns a constructor per dialect that yields the DSN of a
// fresh, empty, unmigrated database for one test, dropped at cleanup.
func dsnsUnderTest(t *testing.T) map[string]func(t *testing.T) string {
	out := map[string]func(t *testing.T) string{
		"sqlite": func(t *testing.T) string {
			return "sqlite://" + filepath.Join(t.TempDir(), "z.db")
		},
	}
	if dsn := os.Getenv(envPostgres); dsn != "" {
		out["postgres"] = func(t *testing.T) string { return freshServerDSN(t, "postgres", dsn) }
	}
	if dsn := os.Getenv(envMySQL); dsn != "" {
		out["mysql"] = func(t *testing.T) string { return freshServerDSN(t, "mysql", dsn) }
	}
	return out
}

// dialectsUnderTest returns a constructor per dialect that yields a fresh,
// empty, migrated database for one test, dropped at cleanup.
func dialectsUnderTest(t *testing.T) map[string]func(t *testing.T) *Store {
	out := map[string]func(t *testing.T) *Store{}
	for name, mk := range dsnsUnderTest(t) {
		out[name] = func(t *testing.T) *Store { return mustOpen(t, mk(t)) }
	}
	return out
}

func mustOpenRaw(t *testing.T, dsn string) *Store {
	t.Helper()
	s, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustOpen(t *testing.T, dsn string) *Store {
	t.Helper()
	s := mustOpenRaw(t, dsn)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

// freshServerDSN creates database z_<random> on the server and drops it at
// cleanup. It returns the DSN of the new database.
func freshServerDSN(t *testing.T, kind, adminDSN string) string {
	t.Helper()
	name := "z_" + strings.ToLower(secrets.RandomString(12))
	admin, err := Open(context.Background(), adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.db.ExecContext(context.Background(), "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a, err := Open(context.Background(), adminDSN)
		if err == nil {
			_, _ = a.db.ExecContext(context.Background(), dropDatabase(kind, name))
			_ = a.Close()
		}
	})
	return withDatabase(adminDSN, name)
}

func dropDatabase(kind, name string) string {
	if kind == "postgres" {
		return "DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"
	}
	return "DROP DATABASE IF EXISTS " + name
}

// withDatabase replaces the path of a URL DSN with /name.
func withDatabase(dsn, name string) string {
	i := strings.Index(dsn, "://")
	rest := dsn[i+3:]
	q := ""
	if j := strings.IndexByte(rest, '?'); j >= 0 {
		rest, q = rest[:j], rest[j:]
	}
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return fmt.Sprintf("%s://%s/%s%s", dsn[:i], rest, name, q)
}

func TestParseDSN(t *testing.T) {
	for _, dsn := range []string{"memory://", "http://x", "nonsense"} {
		if _, _, err := parseDSN(dsn); err == nil {
			t.Errorf("parseDSN(%q) = nil error", dsn)
		}
	}
	if _, _, err := parseDSN("oracle://x"); err == nil || !strings.Contains(err.Error(), `"oracle"`) {
		t.Errorf("want error naming scheme, got %v", err)
	}
	d, native, err := parseDSN("mysql://u%40x:p%3Aw@h:1234/db?foo=bar")
	if err != nil || d.name != "mysql" {
		t.Fatal(d, err)
	}
	for _, want := range []string{"u@x:p:w@tcp(h:1234)/db", "foo=bar", "STRICT_ALL_TABLES", "time_zone=%27%2B00%3A00%27"} {
		if !strings.Contains(native, want) {
			t.Errorf("mysql DSN %q missing %q", native, want)
		}
	}
	if _, native, _ = parseDSN("postgresql://u@h/db"); native != "postgresql://u@h/db" {
		t.Errorf("postgres DSN altered: %q", native)
	}
	if _, native, _ = parseDSN("sqlite:///abs/z.db"); !strings.HasPrefix(native, "file:/abs/z.db?_pragma=busy_timeout(5000)") || !strings.Contains(native, "_txlock=immediate") {
		t.Errorf("sqlite DSN: %q", native)
	}
}

func TestRebind(t *testing.T) {
	if got := dPostgres.rebind("a=? AND b=?"); got != "a=$1 AND b=$2" {
		t.Error(got)
	}
	if got := dSQLite.rebind("a=?"); got != "a=?" {
		t.Error(got)
	}
}

func TestAtomic(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := mk(t)
			count := func() (n int) {
				if err := s.queryRow(ctx, "SELECT COUNT(*) FROM tenants").Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			ins := func(t *Store, id string) error {
				_, err := t.exec(ctx, "INSERT INTO tenants (id, name, friendly_name, default_audience, allowed_logout_urls, enabled_locales, custom_text, session_lifetime, idle_session_lifetime, logo_url, primary_color, default_directory, created_at) VALUES (?, ?, '', '', '[]', '[]', '{}', 0, 0, '', '', '', 0)", id, id)
				return err
			}
			// Commit, with a nested call joining the outer transaction.
			err := s.atomic(ctx, func(tx *Store) error {
				if err := ins(tx, "a"); err != nil {
					return err
				}
				return tx.atomic(ctx, func(in *Store) error {
					if in != tx {
						return fmt.Errorf("nested atomic did not run inline")
					}
					return ins(in, "b")
				})
			})
			if err != nil || count() != 2 {
				t.Fatalf("commit: err=%v count=%d", err, count())
			}
			// Error in the outer function rolls back the nested work too.
			err = s.atomic(ctx, func(tx *Store) error {
				if err := tx.atomic(ctx, func(in *Store) error { return ins(in, "c") }); err != nil {
					return err
				}
				return fmt.Errorf("boom")
			})
			if err == nil || count() != 2 {
				t.Fatalf("rollback: err=%v count=%d", err, count())
			}
			// A panic rolls back and propagates; the store stays usable.
			func() {
				defer func() {
					if recover() == nil {
						t.Error("panic was swallowed")
					}
				}()
				_ = s.atomic(ctx, func(tx *Store) error {
					_ = ins(tx, "d")
					panic("boom")
				})
			}()
			if count() != 2 {
				t.Fatalf("panic rollback: count=%d", count())
			}
			// Unique violations map to store.ErrConflict.
			err = s.atomic(ctx, func(tx *Store) error { return tx.conflict(ins(tx, "a")) })
			if !errors.Is(err, store.ErrConflict) {
				t.Fatalf("want ErrConflict, got %v", err)
			}
		})
	}
}

// atomicRetry gives up after three deadlocks with a wrapped error, and stops
// with ctx.Err() when the context ends during the backoff.
func TestAtomicRetry(t *testing.T) {
	s := mustOpen(t, "sqlite://"+filepath.Join(t.TempDir(), "z.db"))
	deadlock := &mysql.MySQLError{Number: 1213, Message: "Deadlock found"}

	calls := 0
	err := s.atomicRetry(context.Background(), func(*Store) error { calls++; return deadlock })
	if calls != 3 || !errors.Is(err, deadlock) || !strings.HasPrefix(err.Error(), "after 3 attempts: ") {
		t.Fatalf("calls=%d err=%v", calls, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	err = s.atomicRetry(ctx, func(*Store) error { calls++; cancel(); return deadlock })
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("calls=%d err=%v", calls, err)
	}

	calls = 0
	boom := errors.New("boom")
	err = s.atomicRetry(context.Background(), func(*Store) error { calls++; return boom })
	if calls != 1 || err != boom {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
