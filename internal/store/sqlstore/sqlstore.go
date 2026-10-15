// Package sqlstore implements store.Store over database/sql for SQLite,
// PostgreSQL and MySQL.
package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
	_ "modernc.org/sqlite"             // registers the "sqlite" driver

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type querier interface {
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

// Store implements store.Store over database/sql. A Store either wraps the
// pool or, inside atomic/WithTx, one transaction.
type Store struct {
	db *sql.DB
	q  querier
	tx *sql.Tx
	d  dialect
}

// Open connects to the database named by dsn (sqlite://, postgres(ql)://,
// mysql://) and verifies the connection. It does not migrate.
func Open(ctx context.Context, dsn string) (*Store, error) {
	d, native, err := parseDSN(dsn)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(d.driver, native)
	if err != nil {
		return nil, err
	}
	if d.name == "sqlite" {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(20)
		db.SetConnMaxIdleTime(5 * time.Minute)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlstore: connect %s: %w", d.name, err)
	}
	return &Store{db: db, q: db, d: d}, nil
}

// parseDSN maps a zeroauthy storage DSN to a dialect and a driver DSN.
func parseDSN(dsn string) (dialect, string, error) {
	scheme, rest, ok := strings.Cut(dsn, "://")
	if !ok {
		return dialect{}, "", fmt.Errorf("sqlstore: unsupported storage DSN (no scheme)")
	}
	switch scheme {
	case "sqlite":
		const pragmas = "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate"
		sep := "?"
		if strings.Contains(rest, "?") {
			sep = "&"
		}
		return dSQLite, "file:" + rest + sep + pragmas, nil
	case "postgres", "postgresql":
		return dPostgres, dsn, nil
	case "mysql":
		u, err := url.Parse(dsn)
		if err != nil {
			return dialect{}, "", fmt.Errorf("sqlstore: parse mysql DSN: %w", err)
		}
		cfg := mysql.NewConfig()
		cfg.User = u.User.Username()
		cfg.Passwd, _ = u.User.Password()
		cfg.Net = "tcp"
		port := u.Port()
		if port == "" {
			port = "3306"
		}
		cfg.Addr = net.JoinHostPort(u.Hostname(), port)
		cfg.DBName = strings.TrimPrefix(u.Path, "/")
		cfg.Loc = time.UTC
		cfg.Params = map[string]string{}
		for k, v := range u.Query() {
			cfg.Params[k] = v[len(v)-1]
		}
		cfg.ParseTime = false // never let the DSN override: times are BIGINT
		cfg.Params["sql_mode"] = "'STRICT_ALL_TABLES,NO_ZERO_DATE'"
		cfg.Params["time_zone"] = "'+00:00'"
		return dMySQL, cfg.FormatDSN(), nil
	default:
		return dialect{}, "", fmt.Errorf("sqlstore: unsupported storage DSN scheme %q", scheme)
	}
}

func (s *Store) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return s.q.ExecContext(ctx, s.d.rebind(q), args...)
}

func (s *Store) query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return s.q.QueryContext(ctx, s.d.rebind(q), args...)
}

func (s *Store) queryRow(ctx context.Context, q string, args ...any) *sql.Row {
	return s.q.QueryRowContext(ctx, s.d.rebind(q), args...)
}

// atomic runs fn in one transaction, or inline when s is already inside one
// (the nested call joins the outer transaction). fn must use t, never s: with
// SQLite's single connection, touching the pool from inside a transaction
// would deadlock. An error or panic from fn rolls the transaction back.
func (s *Store) atomic(ctx context.Context, fn func(t *Store) error) error {
	if s.tx != nil {
		return fn(s)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		if !finished {
			_ = tx.Rollback()
		}
	}()
	t := &Store{db: s.db, q: tx, tx: tx, d: s.d}
	if err := fn(t); err != nil {
		return err
	}
	finished = true
	return tx.Commit()
}

func (s *Store) conflict(err error) error {
	if err != nil && s.d.isUniqueViolation(err) {
		return store.ErrConflict
	}
	return err
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *Store) Close() error                   { return s.db.Close() }
