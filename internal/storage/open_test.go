package storage

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var pluginBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "zeroauthy-storage")
	if err != nil {
		panic(err)
	}
	pluginBin = filepath.Join(dir, "zeroauthy-store-memory")
	out, err := exec.Command("go", "build", "-o", pluginBin, "github.com/zeroauthy/zeroauthy/cmd/zeroauthy-store-memory").CombinedOutput()
	if err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestOpenPlugin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// The sample plugin ignores argv, so ?arg=... only proves Open accepts it.
	for _, dsn := range []string{"plugin://" + pluginBin, "plugin://" + pluginBin + "?arg=--ignored&arg=b"} {
		st, err := Open(ctx, dsn)
		if err != nil {
			t.Fatalf("Open(%q): %v", dsn, err)
		}
		if err := st.Ping(ctx); err != nil {
			t.Errorf("Ping: %v", err)
		}
		st.Close()
	}
}

func TestOpenPluginDSNErrors(t *testing.T) {
	ctx := context.Background()
	for dsn, want := range map[string]string{
		"plugin://relative":                    "absolute",
		"plugin://host/abs":                    "absolute",
		"plugin://":                            "absolute",
		"plugin://" + pluginBin + "?other=xx":  `"other"`,
		"plugin://" + pluginBin + "?arg=%zzxx": "malformed",
	} {
		_, err := Open(ctx, dsn)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Open(%q) err = %v, want it to contain %q", dsn, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "xx") {
			t.Errorf("error quotes the parameter value: %v", err)
		}
	}
}

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
