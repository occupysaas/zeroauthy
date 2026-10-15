package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*/*.sql
var migrationFiles embed.FS

type migration struct {
	version    int64
	name       string
	statements []string
}

// migrations returns the dialect's migrations in version order.
func (s *Store) migrations() ([]migration, error) {
	dir := "migrations/" + s.d.name
	entries, err := migrationFiles.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		prefix, _, ok := strings.Cut(e.Name(), "_")
		v, perr := strconv.ParseInt(prefix, 10, 64)
		if !ok || perr != nil {
			return nil, fmt.Errorf("sqlstore: bad migration file name %q", e.Name())
		}
		b, err := migrationFiles.ReadFile(dir + "/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: e.Name(), statements: splitStatements(string(b))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// splitStatements splits on a ';' at the end of a line, ignoring blank lines
// and lines starting with "--".
func splitStatements(src string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		cur.WriteString(line)
		cur.WriteByte('\n')
		if strings.HasSuffix(t, ";") {
			out = append(out, strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(cur.String()), ";")))
			cur.Reset()
		}
	}
	if rest := strings.TrimSpace(cur.String()); rest != "" {
		out = append(out, rest)
	}
	return out
}

// LatestVersion is the newest schema version this binary knows.
func (s *Store) LatestVersion() int64 {
	ms, err := s.migrations()
	if err != nil {
		panic(err) // migrations are embedded; this is a build defect
	}
	if len(ms) == 0 {
		return 0
	}
	return ms[len(ms)-1].version
}

func (s *Store) hasMigrationsTable(ctx context.Context) (bool, error) {
	var q string
	switch s.d.name {
	case "sqlite":
		q = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
	case "postgres":
		q = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'schema_migrations'"
	default:
		q = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'schema_migrations'"
	}
	var n int
	if err := s.queryRow(ctx, q).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// SchemaVersion returns the highest applied migration, or 0 when
// schema_migrations does not exist.
func (s *Store) SchemaVersion(ctx context.Context) (int64, error) {
	ok, err := s.hasMigrationsTable(ctx)
	if err != nil || !ok {
		return 0, err
	}
	var v int64
	err = s.queryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&v)
	return v, err
}

func errNewer(have, latest int64) error {
	return fmt.Errorf("database schema version %d is newer than this binary (%d); upgrade zeroauthy", have, latest)
}

// CheckSchema returns nil only when the database is exactly at LatestVersion.
func (s *Store) CheckSchema(ctx context.Context) error {
	v, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	latest := s.LatestVersion()
	switch {
	case v > latest:
		return errNewer(v, latest)
	case v < latest:
		return fmt.Errorf("database schema is at version %d but this binary needs %d; run zeroauthy migrate", v, latest)
	}
	return nil
}

// lock serializes concurrent migrators and returns the unlock function. The
// lock is held on a dedicated connection. SQLite needs none: _txlock=immediate
// serializes writers.
func (s *Store) lock(ctx context.Context) (func(), error) {
	if s.d.name == "sqlite" {
		return func() {}, nil
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	release := func(q string) func() {
		return func() {
			if _, err := conn.ExecContext(context.WithoutCancel(ctx), q); err != nil {
				// The lock may still be held: discard the connection so
				// closing it releases the lock server-side.
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			}
			_ = conn.Close()
		}
	}
	if s.d.name == "postgres" {
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock(7347209)"); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return release("SELECT pg_advisory_unlock(7347209)"), nil
	}
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK('zeroauthy_migrate', 60)").Scan(&got); err != nil || got.Int64 != 1 {
		_ = conn.Close()
		if err == nil {
			err = fmt.Errorf("sqlstore: timed out waiting for the migration lock")
		}
		return nil, err
	}
	return release("SELECT RELEASE_LOCK('zeroauthy_migrate')"), nil
}

// Migrate applies pending migrations. It refuses a database that is ahead of
// this binary.
func (s *Store) Migrate(ctx context.Context) error {
	ms, err := s.migrations()
	if err != nil {
		return err
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	if _, err := s.db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, applied_at BIGINT NOT NULL)"); err != nil {
		return err
	}
	cur, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if latest := s.LatestVersion(); cur > latest {
		return errNewer(cur, latest)
	}
	for _, m := range ms {
		if m.version <= cur {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			return fmt.Errorf("sqlstore: migration %s: %w", m.name, err)
		}
	}
	return nil
}

// applyMigration runs one migration in a transaction. MySQL commits DDL
// implicitly, so there the version check is what keeps a re-run safe.
func (s *Store) applyMigration(ctx context.Context, m migration) error {
	return s.atomic(ctx, nil, func(t *Store) error {
		var n int
		if err := t.queryRow(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", m.version).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		for _, stmt := range m.statements {
			if _, err := t.exec(ctx, stmt); err != nil {
				return err
			}
		}
		_, err := t.exec(ctx, "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", m.version, micros(time.Now()))
		return err
	})
}
