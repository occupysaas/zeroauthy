package storage

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpen(t *testing.T) {
	st, err := Open(context.Background(), "memory://")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	for dsn, want := range map[string]string{
		"oracle://localhost/db": `driver "oracle" is not available`,
		"nonsense":              "scheme",
		"":                      "scheme",
	} {
		if _, err := Open(context.Background(), dsn); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Open(%q) err = %v, want it to contain %q", dsn, err, want)
		}
	}
}

func TestOpenSQLite(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, "sqlite://"+filepath.Join(t.TempDir(), "z.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	m, ok := st.(Migrator)
	if !ok {
		t.Fatalf("sqlite store %T does not implement Migrator", st)
	}
	if err := m.CheckSchema(ctx); err == nil || !strings.Contains(err.Error(), "run zeroauthy migrate") {
		t.Fatalf("CheckSchema on a fresh database: err = %v", err)
	}
	if err := m.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema after Migrate: %v", err)
	}
}

// TestOpenPostgresSchemes checks that both PostgreSQL schemes reach the SQL
// driver: the error is a connection failure, not "driver not available".
func TestOpenPostgresSchemes(t *testing.T) {
	for _, scheme := range []string{"postgres", "postgresql"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := Open(ctx, scheme+"://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=2")
		cancel()
		if err == nil || !strings.Contains(err.Error(), "connect postgres") {
			t.Errorf("Open(%s://unreachable) err = %v, want a postgres connection error", scheme, err)
		}
	}
}

func TestMemoryIsNotMigrator(t *testing.T) {
	st, err := Open(context.Background(), "memory://")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, ok := st.(Migrator); ok {
		t.Error("memory store should have no schema")
	}
}
