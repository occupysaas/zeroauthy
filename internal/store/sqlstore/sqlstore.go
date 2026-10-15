// Package sqlstore implements store.Store over database/sql for SQLite,
// PostgreSQL and MySQL.
package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand/v2"
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
	st *txState // shared by every Store bound to tx; nil outside one
}

// txState is the state of one transaction shared by its nested calls.
type txState struct {
	depth  int   // savepoints currently open
	broken error // set when a ROLLBACK TO SAVEPOINT failed; see savepoint
}

// usable returns the error that broke s's transaction, if any.
func (s *Store) usable() error {
	if s.st != nil {
		return s.st.broken
	}
	return nil
}

// row is a *sql.Row, or the error that broke the transaction.
type row struct {
	r   *sql.Row
	err error
}

func (r row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	return r.r.Scan(dest...)
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
		cfg.ParseTime = false      // never let the DSN override: times are BIGINT
		cfg.ClientFoundRows = true // RowsAffected counts matched rows, so an unchanged UPDATE is not "not found"
		cfg.Params["sql_mode"] = "'STRICT_ALL_TABLES,NO_ZERO_DATE'"
		cfg.Params["time_zone"] = "'+00:00'"
		return dMySQL, cfg.FormatDSN(), nil
	default:
		return dialect{}, "", fmt.Errorf("sqlstore: unsupported storage DSN scheme %q", scheme)
	}
}

func (s *Store) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if err := s.usable(); err != nil {
		return nil, err
	}
	return s.q.ExecContext(ctx, s.d.rebind(q), args...)
}

func (s *Store) query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	if err := s.usable(); err != nil {
		return nil, err
	}
	return s.q.QueryContext(ctx, s.d.rebind(q), args...)
}

func (s *Store) queryRow(ctx context.Context, q string, args ...any) row {
	if err := s.usable(); err != nil {
		return row{err: err}
	}
	return row{r: s.q.QueryRowContext(ctx, s.d.rebind(q), args...)}
}

// atomic runs fn in one transaction begun with opts (nil for the defaults).
// Inside a transaction, fn runs inline on the same Store, within a savepoint:
// opts are ignored, and an error or panic from fn rolls back to the savepoint
// only, so the enclosing transaction stays usable (on PostgreSQL a failed
// statement would otherwise abort it) and every nested call is
// all-or-nothing. fn must use t, never s: with SQLite's single connection,
// touching the pool from inside a transaction would deadlock. An error or
// panic from fn rolls the transaction back. atomic never retries: fn may
// have side effects, so the public WithTx (which is built on it) does not
// retry either. Repository writes use atomicRetry.
func (s *Store) atomic(ctx context.Context, opts *sql.TxOptions, fn func(t *Store) error) error {
	if s.tx != nil {
		return s.savepoint(ctx, fn)
	}
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		if !finished {
			_ = tx.Rollback()
		}
	}()
	t := &Store{db: s.db, q: tx, tx: tx, d: s.d, st: &txState{}}
	if err := fn(t); err != nil {
		return err
	}
	if err := t.st.broken; err != nil { // fn carried on after a failed rollback
		return err
	}
	finished = true
	return tx.Commit()
}

// savepoint runs fn inside SAVEPOINT sp_<depth> of the current transaction,
// rolling back to it when fn fails or panics. If that rollback fails (MySQL
// has already rolled the whole transaction back after a deadlock, say), the
// transaction is marked broken: every later statement through it returns
// the error, and the outermost atomic rolls back and returns it instead of
// committing, so a caller that handles fn's error cannot carry on unaware.
func (s *Store) savepoint(ctx context.Context, fn func(t *Store) error) (err error) {
	if err := s.usable(); err != nil {
		return err
	}
	s.st.depth++
	name := fmt.Sprintf("sp_%d", s.st.depth)
	defer func() { s.st.depth-- }()
	if _, err := s.q.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
		return err
	}
	ok := false
	var fnErr error
	defer func() {
		if ok {
			return
		}
		if _, rbErr := s.q.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+name); rbErr != nil {
			cause := rbErr
			if fnErr != nil && s.d.isDeadlock(fnErr) {
				cause = fnErr // let the outermost atomicRetry retry
			}
			s.st.broken = fmt.Errorf("sqlstore: transaction unusable: rollback to savepoint failed (%v) after: %v: %w", rbErr, fnErr, cause)
			return
		}
		_, _ = s.q.ExecContext(ctx, "RELEASE SAVEPOINT "+name)
	}()
	if fnErr = fn(s); fnErr != nil {
		return fnErr
	}
	ok = true
	_, err = s.q.ExecContext(ctx, "RELEASE SAVEPOINT "+name)
	return err
}

func (s *Store) conflict(err error) error {
	if err != nil && s.d.isUniqueViolation(err) {
		return store.ErrConflict
	}
	return err
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *Store) Close() error                   { return s.db.Close() }

// sweep returns the transaction options for set-based DELETEs: READ
// COMMITTED on MySQL, where REPEATABLE READ's gap locks make a range DELETE
// deadlock with concurrent INSERTs; the defaults elsewhere.
func (s *Store) sweep() *sql.TxOptions {
	if s.d.name == "mysql" {
		return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	return nil
}

// write runs one statement as a repository write, retried on deadlock.
// Outside a transaction and without opts it runs directly on the pool (one
// statement is atomic by itself); with opts it gets its own transaction (the
// isolation level), and inside a transaction a savepoint.
func (s *Store) write(ctx context.Context, opts *sql.TxOptions, q string, args ...any) (sql.Result, error) {
	var res sql.Result
	if s.tx == nil && opts == nil {
		err := s.retry(ctx, func() (err error) {
			res, err = s.exec(ctx, q, args...)
			return err
		})
		return res, err
	}
	err := s.atomicRetry(ctx, opts, func(t *Store) (err error) {
		res, err = t.exec(ctx, q, args...)
		return err
	})
	return res, err
}

// atomicRetry is atomic for repository write methods: the outermost call
// retries up to 3 attempts when the database aborts the transaction as a
// deadlock or serialization failure, with a short jittered backoff. fn must
// be safe to re-run (repository methods only touch the database). A nested
// call, already inside a transaction, never retries; it just propagates.
// After the last attempt the error is wrapped ("after 3 attempts: …"); a
// context that ends during the backoff returns ctx.Err().
func (s *Store) atomicRetry(ctx context.Context, opts *sql.TxOptions, fn func(t *Store) error) error {
	if s.tx != nil {
		return s.atomic(ctx, nil, fn)
	}
	return s.retry(ctx, func() error { return s.atomic(ctx, opts, fn) })
}

// retry runs op up to 3 times while it fails as a deadlock or serialization
// failure, with a short jittered backoff. After the last attempt the error is
// wrapped ("after 3 attempts: …"); a context that ends during the backoff
// returns ctx.Err().
func (s *Store) retry(ctx context.Context, op func() error) error {
	const attempts = 3
	for i := 1; ; i++ {
		err := op()
		if err == nil || !s.d.isDeadlock(err) {
			return err
		}
		if i == attempts {
			return fmt.Errorf("after %d attempts: %w", attempts, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(5+rand.IntN(20*i)) * time.Millisecond):
		}
	}
}
