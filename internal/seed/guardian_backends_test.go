package seed

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/grpcstore"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// forEachGuardianStore runs fn against a fresh store of every driver under test:
// memory and SQLite always, PostgreSQL and MySQL when scripts/test-sql.sh
// sets ZA_TEST_POSTGRES_DSN and ZA_TEST_MYSQL_DSN.
func forEachGuardianStore(t *testing.T, fn func(t *testing.T, st store.Store)) {
	makers := map[string]func(t *testing.T) store.Store{
		"memory":      func(*testing.T) store.Store { return memory.New() },
		"grpc-memory": func(t *testing.T) store.Store { return guardianGRPC(t, memory.New()) },
		"grpc-sqlite": func(t *testing.T) store.Store {
			return guardianGRPC(t, openGuardianSQL(t, "sqlite://"+filepath.Join(t.TempDir(), "g.db")))
		},
		"sqlite": func(t *testing.T) store.Store {
			return openGuardianSQL(t, "sqlite://"+filepath.Join(t.TempDir(), "z.db"))
		},
	}
	if dsn := os.Getenv("ZA_TEST_POSTGRES_DSN"); dsn != "" {
		makers["postgres"] = func(t *testing.T) store.Store { return openGuardianSQL(t, freshGuardianDatabase(t, "postgres", dsn)) }
	}
	if dsn := os.Getenv("ZA_TEST_MYSQL_DSN"); dsn != "" {
		makers["mysql"] = func(t *testing.T) store.Store { return openGuardianSQL(t, freshGuardianDatabase(t, "mysql", dsn)) }
	}
	for _, name := range slices.Sorted(maps.Keys(makers)) {
		t.Run(name, func(t *testing.T) { fn(t, makers[name](t)) })
	}
}

func openGuardianSQL(t *testing.T, dsn string) store.Store {
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

// freshGuardianDatabase creates an empty database on the server of adminDSN (a
// URL DSN), drops it at cleanup and returns its URL DSN.
func freshGuardianDatabase(t *testing.T, kind, adminDSN string) string {
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
	name := "zseed_" + strings.ToLower(secrets.RandomString(12))
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

func TestSeedGuardianBackends(t *testing.T) {
	forEachGuardianStore(t, func(t *testing.T, st store.Store) {
		t.Run("configuration", func(t *testing.T) { testSeedGuardian(t, st) })
		// Independent tenant name keeps rollback separate from the seeded tenant.
		t.Run("rollback", func(t *testing.T) {
			ctx := context.Background()
			f, err := Parse([]byte(`tenants: [{name: rollback, guardian: {factors: {otp: true}, policies: [all-applications]}, clients: [{client_id: boom, app_type: spa}]}]`))
			if err != nil {
				t.Fatal(err)
			}
			if err = Apply(ctx, failingStore{st}, f, fixedNow, testWrapper(t)); err == nil {
				t.Fatal("want injected failure")
			}
			if _, err = st.Tenants().GetByName(ctx, "rollback"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("tenant survived rollback")
			}
		})
	})
}

func guardianGRPC(t *testing.T, backing store.Store) store.Store {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	srv := grpcstore.NewServer(backing)
	storev1.RegisterStoreServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client := grpcstore.NewClient(conn, func() error { srv.Close(); gs.Stop(); return conn.Close() })
	t.Cleanup(func() { _ = client.Close() })
	return client
}
