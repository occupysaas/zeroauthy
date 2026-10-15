# zeroauthy Plan 6: SQL Storage Drivers (Milestone 7)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** zeroauthy can persist all of its data in SQLite, PostgreSQL or MySQL, selected by DSN. Every driver passes the same `pkg/storetest` conformance suite as the memory driver, including the concurrency tests for the atomic operations. The full E2E suite runs against SQLite.

**Architecture:**
- **One shared package, `internal/store/sqlstore`,** implements `store.Store` on `database/sql`:
  - Hand-written SQL uses `?` placeholders, which are rebound to `$n` for PostgreSQL.
  - A small `dialect` value supplies: placeholders, a row-lock suffix, conflict detection, and the advisory lock used by migrations.
  - Migrations are embedded per dialect under `migrations/<dialect>/NNNN_name.sql`.
- **Atomic store methods** (`Consume`, `Rotate`, `AddClient`, the signing-key `Rotate`, …) each run in one transaction with row locks. Correctness therefore never depends on callers.
- **Before the drivers,** this plan clears the prerequisites in `docs/superpowers/plan-1-followups.md`:
  - the gaps in the conformance suite;
  - the signing-key invariants and the `keys.Manager.Ensure` repair;
  - `Store.WithTx`;
  - a transactional seed.

**Tech Stack:**
- Go 1.26+.
- SQL drivers:
  - `modernc.org/sqlite`: pure Go, so the binary stays CGO-free (spec §5.1).
  - `github.com/jackc/pgx/v5/stdlib`.
  - `github.com/go-sql-driver/mysql`.
- Test databases run in podman containers started by a CLI script; there is no testcontainers (user decision, 2026-10-15).
- MySQL 8.0.17+ only; MariaDB is not supported (user decision, 2026-10-15).

**Spec:** `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md` §5.1, §5.2 (plugin authors reuse `storetest`), §3 (`zeroauthy migrate`), §9 (`storage.dsn`, `storage.auto_migrate`), §12 (storage conformance), §13 milestone 7.

## Global Constraints

- **Earlier constraints still apply:**
  - Storage is tenant-scoped.
  - Drivers return copies.
  - Every atomic operation is one store method.
  - `go test -race ./...`, `go vet` and `gofmt` stay clean.
  - Databases run only in containers, never installed on the host (memory `databases-via-containers`). `docker` on this machine is Podman's emulation, so scripts prefer `podman`.
- **Storage DSNs** (spec §5.1):

  | DSN | Driver |
  |---|---|
  | `memory://` | memory |
  | `sqlite:///absolute/path.db` | SQLite. `sqlite://relative.db` is also accepted, relative to the working directory. |
  | `postgres://user:pass@host:port/db?sslmode=…` | PostgreSQL. `postgresql://` is accepted too. |
  | `mysql://user:pass@host:port/db` | MySQL. Converted to the go-sql-driver form `user:pass@tcp(host:port)/db`. |

  Any other scheme is an error naming the scheme.
- **Supported versions:** PostgreSQL 14+ (tested on 17), MySQL 8.0.17+ (tested on 8.4), SQLite through modernc.
- **Storage encoding** (D-0020):
  - **Times:** `BIGINT` microseconds since the Unix epoch, in UTC. A zero `time.Time` is stored as `0`, and a nil `*time.Time` as `NULL`. Values read back are `time.UnixMicro(v).UTC()`.
  - **Slices, maps and structs without their own table:** JSON text. Use `TEXT` in SQLite and PostgreSQL, and `LONGTEXT` in MySQL. JSON `null` decodes to a nil slice or map.
  - **Booleans:** `BOOLEAN` in PostgreSQL and MySQL, `INTEGER` 0/1 in SQLite.
  - **Opaque bytes** (signing keys): `BYTEA`, `LONGBLOB` or `BLOB`.
- **Uniqueness and locking:**
  - Uniqueness rules are enforced by the database (unique indexes), not only by a check-then-insert.
  - A unique violation maps to `store.ErrConflict` (PostgreSQL `23505`, MySQL `1062`, SQLite extended codes `2067` and `1555`).
- **SQLite:**
  - Open with `_pragma=busy_timeout(5000)`, `_pragma=journal_mode(WAL)` and `_pragma=foreign_keys(1)`.
  - Use `db.SetMaxOpenConns(1)`, so every statement and transaction is serialized.
- **PostgreSQL and MySQL:** atomic methods use `SELECT … FOR UPDATE` inside a transaction.
- **Migrations:**
  - Each dialect has an embedded, ordered set of migrations.
  - The table `schema_migrations(version BIGINT PRIMARY KEY, applied_at BIGINT NOT NULL)` records which have run.
  - `zeroauthy migrate` applies pending migrations.
  - `serve` applies them at start when `storage.auto_migrate: true`. Otherwise `serve` refuses to start against a database whose schema is behind or ahead, naming the versions.
  - Concurrent migrators are serialized: PostgreSQL `pg_advisory_lock(7347209)`, MySQL `GET_LOCK('zeroauthy_migrate', 60)`, SQLite `BEGIN IMMEDIATE`.
- **The memory driver stays the reference.** Every behaviour the SQL drivers must have is first pinned by a `storetest` case that the memory driver passes.

## Review Focus

1. **Two concurrent `Consume`, `Rotate` or `AddClient` calls on PostgreSQL and MySQL** must behave exactly like the memory driver: one winner, reuse detected, no lost update. (Tasks 1 and 5: storetest concurrency cases run against every dialect.)
2. **A unique violation inside a multi-row write** (a user with conflicting logins, a tenant with a taken domain) rolls the whole write back and returns `ErrConflict`. No half-written rows remain. (Tasks 3 and 4.)
3. **A time round-trip that loses precision or timezone** (for example nanoseconds, or `time.Local`) must still compare equal after a store round-trip of storetest's second-precision values. Values are always read back as UTC. (Task 2 encoding tests.)
4. **A database at a newer schema version than the binary** must make `serve` and `migrate` refuse to run, with a clear message, rather than corrupting data. (Task 2.)
5. **`seed.Apply` failing halfway** must leave nothing behind on SQL, because it runs in `WithTx`. (Tasks 1 and 6.)

## Out of Scope

- MariaDB.
- The gRPC plugin host (milestone 8).
- Online schema changes and down-migrations.
- Read replicas.
- Connection-pool tuning beyond sane defaults: PostgreSQL and MySQL use `SetMaxOpenConns(20)` and `SetConnMaxIdleTime(5m)`.
- Moving the in-process throttles into the store (recorded follow-up).

## File Map

```
pkg/storetest/*.go                                  gap cases; Run gains exported per-suite helpers
internal/store/store.go, memory/*.go                WithTx; SigningKeys invariants; Users.Update keeps login stats
internal/keys/manager.go                            Ensure repairs partial key sets
internal/seed/apply.go                              Apply runs in WithTx
internal/store/sqlstore/{sqlstore.go,dialect.go,codec.go,migrate.go,tx.go}
internal/store/sqlstore/{tenants.go,clients.go,resource_servers.go,client_grants.go,signing_keys.go,connections.go}
internal/store/sqlstore/{users.go,sessions.go,auth_transactions.go}
internal/store/sqlstore/{auth_codes.go,refresh_tokens.go,password_reset_tickets.go}
internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0001_init.sql
internal/store/sqlstore/sqlstore_test.go            conformance per dialect (sqlite always; pg/mysql via env DSN)
internal/storage/open.go                            DSN dispatch
internal/config/config.go                           storage.auto_migrate
cmd/zeroauthy/migrate.go, root.go                   `zeroauthy migrate`
internal/app/app.go                                 migrate-or-check at start
scripts/test-sql.sh, Makefile                       podman-backed pg/mysql test run
.github/workflows/ci.yml                            service containers for pg/mysql
tests/e2e/run-*.sh                                  E2E on SQLite
docs/compat/decisions.md (D-0020), README.md, docs/superpowers/plan-1-followups.md
```

---

### Task 1: Harden the store contract before SQL (prerequisites)

Every gap listed for milestone 7 in `docs/superpowers/plan-1-followups.md` becomes a `storetest` case that the memory driver passes. That gives the SQL drivers an exact target. This task also adds `Store.WithTx`, enforces the signing-key invariants, repairs `keys.Manager.Ensure`, and makes `seed.Apply` transactional.

**Files:**
- Modify: `internal/store/store.go`, `internal/store/memory/{memory.go,signing_keys.go,users.go,clone.go}` and add `internal/store/memory/tx.go`
- Modify: `pkg/storetest/{storetest.go,tenants.go,client_grants.go,clients.go,signing_keys.go,auth_codes.go,sessions.go,users.go,password_reset_tickets.go}` and add `pkg/storetest/tx.go`
- Modify: `internal/keys/manager.go`, `internal/keys/manager_test.go`
- Modify: `internal/seed/apply.go`, `internal/seed/seed_test.go`

**Interfaces (produced):**

```go
// store.Store gains:
WithTx(ctx context.Context, fn func(tx Store) error) error
// SigningKeys contract additions:
//   Create returns ErrConflict if k.Status is current or next and the tenant
//   already has a key with that status.
//   Rotate returns an error (and changes nothing) if next.Status != KeyNext.
// Users.Update contract change:
//   Update never changes LastLogin or LoginsCount; only RecordLogin does.
// pkg/storetest:
var Suites map[string]func(t *testing.T, newStore Factory) // keyed "Tenants", "Clients", …, "Tx"
func RunSuites(t *testing.T, newStore Factory, names ...string)
```

- [ ] **Step 1: Write the failing conformance cases**

`pkg/storetest/storetest.go`:
- Replace the body of `Run` with an ordered list of suite names that iterates `Suites`.
- Export `Suites`, a map from name to test function, covering every existing suite plus `"Tx"`.
- Add `RunSuites`. It runs only the named suites and fails the test on an unknown name. The SQL tasks use it to run suites incrementally.

Add these cases. All of them use the existing helpers in this package.

`tenants.go`:

```go
	t.Run("UpdateConflictsAndStaleDomains", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("globex")))
		rename := newTenant("acme")
		rename.Name = "globex"
		mustErrIs(t, s.Tenants().Update(ctx, rename), store.ErrConflict)
		missing := newTenant("nobody")
		mustErrIs(t, s.Tenants().Update(ctx, missing), store.ErrNotFound)

		moved := newTenant("acme")
		moved.Domains = []string{"login.acme.test"}
		mustNoErr(t, s.Tenants().Update(ctx, moved))
		_, err := s.Tenants().GetByDomain(ctx, "acme.example.test")
		mustErrIs(t, err, store.ErrNotFound) // the dropped domain is released
		claim := newTenant("globex")
		claim.Domains = []string{"globex.example.test", "acme.example.test"}
		mustNoErr(t, s.Tenants().Update(ctx, claim))
	})
```

In `newTenant`, also set `SessionLifetime: 3600`, `IdleSessionLifetime: 600` and `Branding: store.Branding{LogoURL: "https://cdn.test/" + name + ".png", PrimaryColor: "#112233"}`. The existing round-trip asserts then cover them.

`client_grants.go`: add a `ReturnsCopies` case, modelled on the clients one. Mutate `Scopes` on the input after `Create`, and on a value returned by `Find`. Then assert that the stored scopes are unchanged.

`clients.go`: in `newClient`, set `IDTokenLifetime: 600`.

`signing_keys.go`:

```go
	t.Run("SingleCurrentAndNext", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k2", store.KeyNext, 0)))
		mustErrIs(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k3", store.KeyCurrent, 0)), store.ErrConflict)
		mustErrIs(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k4", store.KeyNext, 0)), store.ErrConflict)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k5", store.KeyPrevious, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k6", store.KeyPrevious, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_b", "k1", store.KeyCurrent, 0))) // other tenant
	})

	t.Run("RotateRequiresNextStatus", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k2", store.KeyNext, time.Hour)))
		if err := s.SigningKeys().Rotate(ctx, "ten_a", newSigningKey("ten_a", "k3", store.KeyCurrent, 2*time.Hour)); err == nil {
			t.Fatal("Rotate accepted a successor without status next")
		}
		mustEqual(t, statuses(t, s, "ten_a"), map[string]store.KeyStatus{"k1": store.KeyCurrent, "k2": store.KeyNext})
	})
```

`auth_codes.go`:

```go
	t.Run("ConcurrentConsume", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")))
		const n = 10
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(time.Second))
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrAlreadyUsed):
			default:
				t.Fatalf("unexpected %v", err)
			}
		}
		mustEqual(t, ok, 1)
		got, err := s.AuthCodes().Get(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got.ReplayedAt != nil, true)
	})
```

`sessions.go`:

```go
	t.Run("SameHashAndIDAcrossTenants", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_a", "s1", "hash1")))
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_b", "s1", "hash1")))
		a, _ := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		b, _ := s.Sessions().GetByTokenHash(ctx, "ten_b", "hash1")
		mustEqual(t, a.TenantID, "ten_a")
		mustEqual(t, b.TenantID, "ten_b")
	})
```

`users.go`:

```go
	t.Run("UpdateUsernameConflictAndKeepsLoginStats", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u1", "alice@example.test", "alice")))
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u2", "bob@example.test", "bob")))
		taken := newUser("ten_a", "u2", "bob@example.test", "alice")
		mustErrIs(t, s.Users().Update(ctx, taken), store.ErrConflict)

		mustNoErr(t, s.Users().RecordLogin(ctx, "ten_a", "auth0|u1", ts(time.Hour)))
		stale := newUser("ten_a", "u1", "alice@example.test", "alice") // LoginsCount 0, LastLogin nil
		stale.Name = "Alice Renamed"
		mustNoErr(t, s.Users().Update(ctx, stale))
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, got.Name, "Alice Renamed")
		mustEqual(t, got.LoginsCount, 1)
		mustEqual(t, got.LastLogin != nil && got.LastLogin.Equal(ts(time.Hour)), true)
	})
```

`password_reset_tickets.go`: add a `ReturnsCopies` case. Consume a ticket, set the returned record's `*UsedAt` to a different time, and re-read: the stored `UsedAt` is unchanged.

Create `pkg/storetest/tx.go`:

```go
package storetest

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func testTx(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CommitApplies", func(t *testing.T) {
		s := open(t, newStore)
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Tenants().Create(ctx, newTenant("acme")); err != nil {
				return err
			}
			_, err := tx.Tenants().GetByName(ctx, "acme") // reads see the transaction's writes
			return err
		})
		mustNoErr(t, err)
		_, err = s.Tenants().GetByName(ctx, "acme")
		mustNoErr(t, err)
	})

	t.Run("ErrorRollsBack", func(t *testing.T) {
		s := open(t, newStore)
		boom := errors.New("boom")
		err := s.WithTx(ctx, func(tx store.Store) error {
			mustNoErr(t, tx.Tenants().Create(ctx, newTenant("acme")))
			mustNoErr(t, tx.Clients().Create(ctx, newClient("ten_acme", "c1")))
			return boom
		})
		mustErrIs(t, err, boom)
		_, err = s.Tenants().GetByName(ctx, "acme")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Clients().Get(ctx, "ten_acme", "c1")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("ConflictInsideRollsBack", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))
		err := s.WithTx(ctx, func(tx store.Store) error {
			mustNoErr(t, tx.Tenants().Create(ctx, newTenant("globex")))
			return tx.Tenants().Create(ctx, newTenant("acme")) // conflict
		})
		mustErrIs(t, err, store.ErrConflict)
		_, err = s.Tenants().GetByName(ctx, "globex")
		mustErrIs(t, err, store.ErrNotFound)
	})
}
```

Run: `go test ./internal/store/memory/`
Expected: FAIL. `WithTx` is undefined, and the new cases fail against the current memory driver.

- [ ] **Step 2: Memory driver**

`store.go`:
- Add `WithTx` to `Store`, with this doc comment: "runs fn against a transactional view of the store. If fn returns an error, none of its writes persist. Drivers serialize transactions; the memory driver's isolation from concurrent non-transactional writers is best effort (tests and demos only)."
- Update the `SigningKeys` and `Users.Update` doc comments as in the Interfaces block.

`memory/tx.go`:

```go
package memory

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// WithTx snapshots every map, runs fn against the same store, and restores
// the snapshot if fn fails. Transactions are serialized by txMu. Writers that
// are not inside a transaction are not isolated (memory is for tests/demos).
func (s *Store) WithTx(ctx context.Context, fn func(store.Store) error) error {
	s.txMu.Lock()
	defer s.txMu.Unlock()
	snap := s.snapshot()
	if err := fn(s); err != nil {
		s.restore(snap)
		return err
	}
	return nil
}
```

- `snapshot` and `restore` take `s.mu` for writing. `snapshot` deep-copies every map, using the existing `clone*` functions. `restore` reassigns the maps.
- Add `txMu sync.Mutex` to `Store`.
- `signing_keys.go`:
  - `Create` rejects a second current or next key per tenant, with `ErrConflict`.
  - `Rotate` returns `errors.New("store: the new key must have status next")` before changing anything, if `next.Status != store.KeyNext`.
- `users.go` `Update`: copy the stored `LastLogin` and `LoginsCount` onto the new value before saving.

Run: `go test -race ./internal/store/memory/`
Expected: PASS.

- [ ] **Step 3: `keys.Manager.Ensure` repairs partial key sets**

Replace `Ensure` with:

```go
// Ensure makes sure the tenant has one current and one next key, creating
// whichever is missing. Concurrent callers (other processes) may race; the
// store rejects a second current/next key with ErrConflict, which Ensure
// treats as "someone else created it".
func (m *Manager) Ensure(ctx context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ks, err := m.store.List(ctx, tenantID)
	if err != nil {
		return err
	}
	have := map[store.KeyStatus]bool{}
	for _, k := range ks {
		have[k.Status] = true
	}
	for _, status := range []store.KeyStatus{store.KeyCurrent, store.KeyNext} {
		if have[status] {
			continue
		}
		k, err := m.generate(tenantID, status)
		if err != nil {
			return err
		}
		if err := m.store.Create(ctx, k); err != nil && !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return nil
}
```

Add tests to `manager_test.go`:
- A tenant with only a current key gains a next key. Afterwards there is exactly one key of each status.
- A tenant with only a next key gains a current key.
- `Ensure` on a complete set changes nothing.

- [ ] **Step 4: Transactional seed**

`internal/seed/apply.go`: wrap the whole loop in `Apply` in `st.WithTx(ctx, func(tx store.Store) error { … })`, using `tx` for every call.

Add a test to `seed_test.go`. The seed file is valid, but the second tenant's client fails at apply time. Provoke it with a store wrapper whose `Clients().Create` returns an error for client ID `boom`. After the failed `Apply`, the first tenant must not exist.

- [ ] **Step 5: Run and commit**

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: PASS. Every test double that embeds `store.Store` keeps compiling, because `WithTx` is promoted from the embedded store. If a double wraps the store and returns its own `Store` from accessors, its `WithTx` must pass the wrapper. Fix such doubles, and report which ones you changed.

```bash
git add internal pkg
git commit -m "feat(store): WithTx, signing-key invariants, conformance gaps; Ensure repairs partial key sets"
```

---

### Task 2: `sqlstore` foundation — dialects, encoding, migrations, schema, test harness

**Files:**
- Create: `internal/store/sqlstore/{sqlstore.go,dialect.go,codec.go,migrate.go,sqlstore_test.go,codec_test.go,migrate_test.go}`
- Create: `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0001_init.sql`
- Create: `scripts/test-sql.sh`
- Modify: `Makefile` (`test-sql` target), `go.mod`/`go.sum` (`modernc.org/sqlite`, `github.com/jackc/pgx/v5`, `github.com/go-sql-driver/mysql`)

**Interfaces (produced):**

```go
package sqlstore
func Open(ctx context.Context, dsn string) (*Store, error)        // sqlite://, postgres(ql)://, mysql://
func (s *Store) Migrate(ctx context.Context) error
func (s *Store) SchemaVersion(ctx context.Context) (int64, error)  // 0 when schema_migrations is absent
func (s *Store) LatestVersion() int64
func (s *Store) CheckSchema(ctx context.Context) error             // nil only when SchemaVersion == LatestVersion
func (s *Store) Ping(ctx context.Context) error
func (s *Store) Close() error
// unexported, used by every repository:
func (s *Store) exec(ctx, q string, args ...any) (sql.Result, error)
func (s *Store) query(ctx, q string, args ...any) (*sql.Rows, error)
func (s *Store) queryRow(ctx, q string, args ...any) *sql.Row
func (s *Store) atomic(ctx context.Context, fn func(t *Store) error) error // one transaction; inline when already inside one
func (s *Store) conflict(err error) error                                // maps unique violations to store.ErrConflict
// codec.go
func micros(t time.Time) int64; func fromMicros(v int64) time.Time
func nullMicros(t *time.Time) any; func fromNullMicros(v sql.NullInt64) *time.Time
func toJSON(v any) (string, error); func fromJSON(s string, v any) error
// test harness (sqlstore_test.go, package sqlstore)
func dialectsUnderTest(t *testing.T) map[string]func(t *testing.T) *Store // "sqlite" always; "postgres"/"mysql" when env DSNs are set
```

- [ ] **Step 1: Dependencies**

```bash
go get modernc.org/sqlite@latest github.com/jackc/pgx/v5@latest github.com/go-sql-driver/mysql@latest
```

Record the resolved versions in the report.

- [ ] **Step 2: Failing tests**

`codec_test.go`:
- **Round trip:** `fromMicros(micros(x))` equals `x.Truncate(time.Microsecond).UTC()` for:
  - a UTC time;
  - a time in `time.FixedZone("x", 3*3600)`;
  - a time with nanoseconds, which are truncated.
- **Zero values:** `micros(time.Time{}) == 0` and `fromMicros(0).IsZero()`.
- **Nullable times:** `nullMicros(nil)` returns `nil`, and `fromNullMicros(sql.NullInt64{})` returns `nil`.
- **JSON:**
  - a nil slice round-trips through `toJSON` to `"null"` and back to a nil slice;
  - a nil map does the same;
  - `map[string]any{"a": []any{"x"}}` round-trips.

`migrate_test.go`, run for every dialect from `dialectsUnderTest`:
- `SchemaVersion` is 0 on an empty database.
- After `Migrate` it equals `LatestVersion()`, and a second `Migrate` is a no-op.
- `CheckSchema` passes after migrating.
- **Database ahead of the binary:**
  1. Insert a row `(LatestVersion()+1, 0)` into `schema_migrations`.
  2. `CheckSchema` must return an error containing "newer than this binary".
  3. `Migrate` must also refuse, with the same message.
- **Fresh database not yet migrated:** `CheckSchema` returns an error containing "run zeroauthy migrate".
- Ten goroutines call `Migrate` concurrently on separate `Open`s of the same database (PostgreSQL and MySQL only), and all succeed.

`sqlstore_test.go` holds the harness. For each test it yields a fresh, empty, migrated database:

```go
package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
)

// Environment for the server dialects; scripts/test-sql.sh sets them.
const (
	envPostgres = "ZA_TEST_POSTGRES_DSN" // postgres://…/postgres (an admin database)
	envMySQL    = "ZA_TEST_MYSQL_DSN"    // mysql://root:…@host:port/ (no database)
)

// dialectsUnderTest returns a constructor per dialect that yields a fresh,
// empty, migrated database for one test, dropped at cleanup.
func dialectsUnderTest(t *testing.T) map[string]func(t *testing.T) *Store {
	out := map[string]func(t *testing.T) *Store{
		"sqlite": func(t *testing.T) *Store {
			return mustOpen(t, "sqlite://"+filepath.Join(t.TempDir(), "z.db"))
		},
	}
	if dsn := os.Getenv(envPostgres); dsn != "" {
		out["postgres"] = func(t *testing.T) *Store { return freshServerDB(t, "postgres", dsn) }
	}
	if dsn := os.Getenv(envMySQL); dsn != "" {
		out["mysql"] = func(t *testing.T) *Store { return freshServerDB(t, "mysql", dsn) }
	}
	return out
}

func mustOpen(t *testing.T, dsn string) *Store {
	t.Helper()
	s, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

// freshServerDB creates database z_<random> on the server, opens it, and
// drops it at cleanup.
func freshServerDB(t *testing.T, kind, adminDSN string) *Store {
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
	return mustOpen(t, withDatabase(adminDSN, name))
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

var _ = sql.ErrNoRows
```

Run: `go test ./internal/store/sqlstore/`
Expected: FAIL (the package is not implemented).

- [ ] **Step 3: Dialects and the core**

`dialect.go`:

```go
package sqlstore

import (
	"errors"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

type dialect struct {
	name      string // "sqlite", "postgres", "mysql"
	driver    string // database/sql driver name
	numbered  bool   // $1-style placeholders
	forUpdate string // row-lock suffix for SELECT inside a transaction
}

var (
	dSQLite   = dialect{name: "sqlite", driver: "sqlite"}
	dPostgres = dialect{name: "postgres", driver: "pgx", numbered: true, forUpdate: " FOR UPDATE"}
	dMySQL    = dialect{name: "mysql", driver: "mysql", forUpdate: " FOR UPDATE"}
)

// rebind turns ? placeholders into $1, $2, … for PostgreSQL. Queries in this
// package never contain a literal '?'.
func (d dialect) rebind(q string) string {
	if !d.numbered {
		return q
	}
	var b strings.Builder
	n := 0
	for _, r := range q {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isUniqueViolation reports whether err is a unique/primary-key violation.
func (d dialect) isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "23505"
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return my.Number == 1062
	}
	var sq *sqlite.Error
	if errors.As(err, &sq) {
		c := sq.Code()
		return c == sqlite3.SQLITE_CONSTRAINT_UNIQUE || c == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
	}
	return false
}
```

`sqlstore.go` covers four things:
- **DSN parsing:**
  - `sqlite://` (the path is everything after the scheme; three slashes means absolute) becomes `file:<path>?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate`.
  - `postgres://` and `postgresql://` are passed through to pgx.
  - `mysql://user:pass@host:port/db?params` becomes `user:pass@tcp(host:port)/db?params&parseTime=false&loc=UTC`. Percent-decode the user and password.
  - Anything else is an error naming the scheme.
- **Opening:** use `sql.Open(d.driver, …)`, then `PingContext`.
- **Pool settings:** SQLite gets `SetMaxOpenConns(1)`. PostgreSQL and MySQL get `SetMaxOpenConns(20)` and `SetConnMaxIdleTime(5*time.Minute)`.
- **MySQL session settings:** every connection must run with `sql_mode` including `STRICT_ALL_TABLES` and with `time_zone='+00:00'`. Set them in the DSN params: `sql_mode='STRICT_ALL_TABLES,NO_ZERO_DATE'` and `time_zone='%2B00%3A00'`.

The `Store` type:

```go
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

func (s *Store) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return s.q.ExecContext(ctx, s.d.rebind(q), args...)
}

func (s *Store) query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return s.q.QueryContext(ctx, s.d.rebind(q), args...)
}

func (s *Store) queryRow(ctx context.Context, q string, args ...any) *sql.Row {
	return s.q.QueryRowContext(ctx, s.d.rebind(q), args...)
}

// atomic runs fn in one transaction, or inline when s is already inside one.
// fn must use t, never s: with SQLite's single connection, touching the pool
// from inside a transaction would deadlock.
func (s *Store) atomic(ctx context.Context, fn func(t *Store) error) error {
	if s.tx != nil {
		return fn(s)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	t := &Store{db: s.db, q: tx, tx: tx, d: s.d}
	if err := fn(t); err != nil {
		_ = tx.Rollback()
		return err
	}
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
```

`codec.go` implements the helpers listed in Interfaces. `fromMicros(0)` returns `time.Time{}`. Everything else returns `time.UnixMicro(v).UTC()`. JSON uses `encoding/json`. `fromJSON` decodes `"null"` or `""` to the zero value.

- [ ] **Step 4: Migrations and the schema**

`migrate.go`:
- Embed `migrations/*/*.sql`.
- Files are named `NNNN_name.sql`; the numeric prefix is the version.
- **Splitting:** split statements on a `;` at the end of a line. Ignore blank lines and lines that start with `--`.
- **`Migrate` steps:**
  1. Take the dialect lock on a dedicated `*sql.Conn` (PostgreSQL and MySQL; SQLite needs none, because `_txlock=immediate` serializes).
  2. Create `schema_migrations` if absent.
  3. Read the current version and refuse if it is greater than `LatestVersion()`.
  4. For each pending migration, open a transaction, check again that the version row is absent, run the statements, and insert `(version, now micros)`. MySQL DDL commits implicitly; that is acceptable, because each migration file is idempotent only through the version check.
- **Error messages, verbatim:**
  - "database schema version %d is newer than this binary (%d); upgrade zeroauthy"
  - "database schema is at version %d but this binary needs %d; run zeroauthy migrate"

Create `migrations/postgres/0001_init.sql`:

```sql
CREATE TABLE tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  friendly_name TEXT NOT NULL,
  default_audience TEXT NOT NULL,
  allowed_logout_urls TEXT NOT NULL,
  enabled_locales TEXT NOT NULL,
  custom_text TEXT NOT NULL,
  session_lifetime INTEGER NOT NULL,
  idle_session_lifetime INTEGER NOT NULL,
  logo_url TEXT NOT NULL,
  primary_color TEXT NOT NULL,
  default_directory TEXT NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE TABLE tenant_domains (
  domain TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  position INTEGER NOT NULL
);
CREATE INDEX tenant_domains_tenant ON tenant_domains (tenant_id);
CREATE TABLE clients (
  tenant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  name TEXT NOT NULL,
  app_type TEXT NOT NULL,
  secrets TEXT NOT NULL,
  token_endpoint_auth_method TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  callbacks TEXT NOT NULL,
  allowed_logout_urls TEXT NOT NULL,
  web_origins TEXT NOT NULL,
  allowed_origins TEXT NOT NULL,
  id_token_lifetime INTEGER NOT NULL,
  refresh_token TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, client_id)
);
CREATE TABLE resource_servers (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  identifier TEXT NOT NULL,
  name TEXT NOT NULL,
  scopes TEXT NOT NULL,
  signing_alg TEXT NOT NULL,
  token_lifetime INTEGER NOT NULL,
  allow_offline_access BOOLEAN NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, identifier)
);
CREATE TABLE client_grants (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  audience TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, client_id, audience)
);
CREATE TABLE signing_keys (
  tenant_id TEXT NOT NULL,
  kid TEXT NOT NULL,
  alg TEXT NOT NULL,
  status TEXT NOT NULL,
  private_key BYTEA NOT NULL,
  public_jwk BYTEA NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, kid)
);
CREATE UNIQUE INDEX signing_keys_active ON signing_keys (tenant_id, status) WHERE status IN ('current', 'next');
CREATE TABLE connections (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  strategy TEXT NOT NULL,
  enabled_clients TEXT NOT NULL,
  disable_signup BOOLEAN NOT NULL,
  requires_username BOOLEAN NOT NULL,
  password_min_length INTEGER NOT NULL,
  password_character_classes INTEGER NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, name)
);
CREATE TABLE users (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  email_verified BOOLEAN NOT NULL,
  username TEXT NOT NULL,
  name TEXT NOT NULL,
  nickname TEXT NOT NULL,
  picture TEXT NOT NULL,
  given_name TEXT NOT NULL,
  family_name TEXT NOT NULL,
  user_metadata TEXT NOT NULL,
  blocked BOOLEAN NOT NULL,
  identities TEXT NOT NULL,
  last_login BIGINT NULL,
  logins_count INTEGER NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, user_id)
);
CREATE TABLE user_logins (
  tenant_id TEXT NOT NULL,
  connection TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  user_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, connection, kind, value)
);
CREATE INDEX user_logins_user ON user_logins (tenant_id, user_id);
CREATE TABLE sessions (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  user_id TEXT NOT NULL,
  connection TEXT NOT NULL,
  authenticated_at BIGINT NOT NULL,
  client_ids TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  idle_expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, token_hash)
);
CREATE INDEX sessions_user ON sessions (tenant_id, user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);
CREATE INDEX sessions_idle ON sessions (idle_expires_at);
CREATE TABLE auth_transactions (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  cookie_hash TEXT NOT NULL,
  csrf_token TEXT NOT NULL,
  client_id TEXT NOT NULL,
  params TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX auth_transactions_expires ON auth_transactions (expires_at);
CREATE TABLE auth_codes (
  tenant_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  audience TEXT NOT NULL,
  nonce TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  auth_time BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  replayed_at BIGINT NULL,
  PRIMARY KEY (tenant_id, code_hash)
);
CREATE INDEX auth_codes_expires ON auth_codes (expires_at);
CREATE TABLE refresh_tokens (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  family_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  audience TEXT NOT NULL,
  auth_time BIGINT NOT NULL,
  rotating BOOLEAN NOT NULL,
  expires_at BIGINT NOT NULL,
  idle_expires_at BIGINT NOT NULL,
  rotated_at BIGINT NULL,
  revoked_at BIGINT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, token_hash)
);
CREATE INDEX refresh_tokens_family ON refresh_tokens (tenant_id, family_id);
CREATE INDEX refresh_tokens_user ON refresh_tokens (tenant_id, user_id);
CREATE INDEX refresh_tokens_expires ON refresh_tokens (expires_at);
CREATE INDEX refresh_tokens_idle ON refresh_tokens (idle_expires_at);
CREATE TABLE password_reset_tickets (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  user_id TEXT NOT NULL,
  connection TEXT NOT NULL,
  client_id TEXT NOT NULL,
  lang TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, token_hash)
);
CREATE INDEX password_reset_tickets_user ON password_reset_tickets (tenant_id, user_id);
CREATE INDEX password_reset_tickets_expires ON password_reset_tickets (expires_at);
```

Create `migrations/sqlite/0001_init.sql`. It is identical to the PostgreSQL file except:
- `BOOLEAN` becomes `INTEGER`;
- `BYTEA` becomes `BLOB`.

SQLite supports the partial index `WHERE status IN ('current', 'next')` as written. Write the file out in full; do not generate it.

Create `migrations/mysql/0001_init.sql` with these rules:
- **Table options:** every table ends with `) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;`. The binary collation keeps comparisons case-sensitive, matching the other drivers.
- **Column types:**
  - `tenant_id` is `VARCHAR(64)`.
  - Every other key or indexed text column is `VARCHAR(255)`.
  - `user_logins.kind` is `VARCHAR(16)`.
  - JSON columns are `LONGTEXT`.
  - `redirect_uri`, `nonce`, `picture` and the user's name fields are `TEXT`.
  - `private_key` and `public_jwk` are `LONGBLOB`.
  - Booleans are `BOOLEAN`.
- **Constraints:** primary keys, unique keys and indexes are the same as the PostgreSQL file. Declare them inside `CREATE TABLE` as `UNIQUE KEY`/`KEY`.
- **`tenant_domains.tenant_id` foreign key:** `FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE`.
- **Single current/next key:** use a generated column:

```sql
  active_status VARCHAR(16) GENERATED ALWAYS AS (CASE WHEN status IN ('current', 'next') THEN status END) STORED,
  UNIQUE KEY signing_keys_active (tenant_id, active_status),
```

Write all three files out in full.

`scripts/test-sql.sh`:

```bash
#!/usr/bin/env bash
# scripts/test-sql.sh: start PostgreSQL and MySQL in containers (podman,
# falling back to docker), run the SQL driver tests against them, and remove
# the containers. SQLite tests need no containers and always run.
set -euo pipefail
cd "$(dirname "$0")/.."
rt="$(command -v podman || command -v docker)"
pg="zeroauthy-test-pg-$$" my="zeroauthy-test-my-$$"
cleanup() { "$rt" rm -f "$pg" "$my" >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$rt" run -d --rm --name "$pg" -e POSTGRES_PASSWORD=zeroauthy -p 127.0.0.1:55432:5432 docker.io/library/postgres:17 >/dev/null
"$rt" run -d --rm --name "$my" -e MYSQL_ROOT_PASSWORD=zeroauthy -p 127.0.0.1:53306:3306 docker.io/library/mysql:8.4 >/dev/null

for _ in $(seq 1 120); do "$rt" exec "$pg" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
for _ in $(seq 1 120); do "$rt" exec "$my" mysqladmin ping -h 127.0.0.1 -pzeroauthy --silent >/dev/null 2>&1 && break; sleep 1; done

export ZA_TEST_POSTGRES_DSN="postgres://postgres:zeroauthy@127.0.0.1:55432/postgres?sslmode=disable"
export ZA_TEST_MYSQL_DSN="mysql://root:zeroauthy@127.0.0.1:53306/"
go test -race -count=1 "${@:-./internal/store/sqlstore/...}"
```

Add a `test-sql:` target to the `Makefile` that runs `./scripts/test-sql.sh`.

- [ ] **Step 5: Run and commit**

Run: `go test -race ./internal/store/sqlstore/`
Expected: PASS for SQLite. The PostgreSQL and MySQL entries are absent without their environment variables.

Run: `./scripts/test-sql.sh`
Expected: PASS for all three dialects. The first run pulls the images.

Run: `go vet ./... && gofmt -l .`
Expected: clean.

```bash
git add internal/store/sqlstore scripts/test-sql.sh Makefile go.mod go.sum
git commit -m "feat(sqlstore): dialects, encoding, embedded migrations and schema for sqlite, postgres, mysql"
```

---

### Task 3: Repositories — tenants, clients, resource servers, client grants, signing keys, connections

**Files:**
- Create: `internal/store/sqlstore/{tenants.go,clients.go,resource_servers.go,client_grants.go,signing_keys.go,connections.go}`
- Create: `internal/store/sqlstore/conformance_test.go`

**Interfaces (produced):** the six accessors on `*sqlstore.Store` (`Tenants()`, `Clients()`, `ResourceServers()`, `ClientGrants()`, `SigningKeys()`, `Connections()`), each returning the matching `store.*` interface.

**Testing with a partial driver.** The SQL store does not implement all of `store.Store` until Task 5. Until then the conformance test builds a hybrid from a memory store and the SQL accessors. It is test-only, and Task 5 deletes it.

```go
package sqlstore

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

// hybrid serves the aggregates implemented so far from SQL and the rest from
// memory. Task 5 replaces it with the full driver.
type hybrid struct {
	*memory.Store
	s *Store
}

func (h hybrid) Tenants() store.Tenants                 { return h.s.Tenants() }
func (h hybrid) Clients() store.Clients                 { return h.s.Clients() }
func (h hybrid) ResourceServers() store.ResourceServers { return h.s.ResourceServers() }
func (h hybrid) ClientGrants() store.ClientGrants       { return h.s.ClientGrants() }
func (h hybrid) SigningKeys() store.SigningKeys         { return h.s.SigningKeys() }
func (h hybrid) Connections() store.Connections         { return h.s.Connections() }

func TestConformance(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			storetest.RunSuites(t, func(t *testing.T) store.Store {
				return hybrid{Store: memory.New(), s: fresh(t)}
			}, "Tenants", "Clients", "ResourceServers", "ClientGrants", "SigningKeys", "Connections")
		})
	}
}
```

`Close` and `Ping` on the hybrid come from memory. That is fine, because `mustOpen` closes the SQL store at cleanup.

- [ ] **Step 1: Run the failing conformance test**

Run: `go test ./internal/store/sqlstore/ -run TestConformance`
Expected: FAIL to compile (the accessors are missing).

- [ ] **Step 2: Implement**

Each repository is a small struct `{ s *Store }`. Follow the `tenants.go` pattern below exactly:
- Scan through one `scanX` helper per type, so column order lives in one place.
- Map `sql.ErrNoRows` to `store.ErrNotFound`.
- Wrap writes with `s.conflict(err)`.
- Use `atomic` whenever a write touches more than one row.

```go
package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type tenants struct{ s *Store }

func (s *Store) Tenants() store.Tenants { return tenants{s} }

const tenantCols = `id, name, friendly_name, default_audience, allowed_logout_urls, enabled_locales, custom_text,
 session_lifetime, idle_session_lifetime, logo_url, primary_color, default_directory, created_at`

func (r tenants) Create(ctx context.Context, t *store.Tenant) error {
	return r.s.atomic(ctx, func(tx *Store) error {
		args, err := tenantArgs(t)
		if err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `INSERT INTO tenants (`+tenantCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...); err != nil {
			return tx.conflict(err)
		}
		return tx.Tenants().(tenants).putDomains(ctx, t.ID, t.Domains)
	})
}

func (r tenants) putDomains(ctx context.Context, id string, domains []string) error {
	if _, err := r.s.exec(ctx, `DELETE FROM tenant_domains WHERE tenant_id = ?`, id); err != nil {
		return err
	}
	for i, d := range domains {
		if _, err := r.s.exec(ctx, `INSERT INTO tenant_domains (domain, tenant_id, position) VALUES (?, ?, ?)`, d, id, i); err != nil {
			return r.s.conflict(err)
		}
	}
	return nil
}

func (r tenants) Update(ctx context.Context, t *store.Tenant) error {
	return r.s.atomic(ctx, func(tx *Store) error {
		args, err := tenantArgs(t)
		if err != nil {
			return err
		}
		res, err := tx.exec(ctx, `UPDATE tenants SET name=?, friendly_name=?, default_audience=?, allowed_logout_urls=?,
 enabled_locales=?, custom_text=?, session_lifetime=?, idle_session_lifetime=?, logo_url=?, primary_color=?,
 default_directory=?, created_at=? WHERE id=?`, append(args[1:], t.ID)...)
		if err != nil {
			return tx.conflict(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return store.ErrNotFound
		}
		return tx.Tenants().(tenants).putDomains(ctx, t.ID, t.Domains)
	})
}

func (r tenants) Get(ctx context.Context, id string) (*store.Tenant, error) {
	return r.one(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id = ?`, id)
}

func (r tenants) GetByName(ctx context.Context, name string) (*store.Tenant, error) {
	return r.one(ctx, `SELECT `+tenantCols+` FROM tenants WHERE name = ?`, name)
}

func (r tenants) GetByDomain(ctx context.Context, domain string) (*store.Tenant, error) {
	return r.one(ctx, `SELECT `+prefixed("t.", tenantCols)+` FROM tenants t JOIN tenant_domains d ON d.tenant_id = t.id WHERE d.domain = ?`, domain)
}

func (r tenants) List(ctx context.Context) ([]*store.Tenant, error) {
	rows, err := r.s.query(ctx, `SELECT `+tenantCols+` FROM tenants ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, t := range out {
		if t.Domains, err = r.domains(ctx, t.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r tenants) one(ctx context.Context, q string, args ...any) (*store.Tenant, error) {
	t, err := scanTenant(r.s.queryRow(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.Domains, err = r.domains(ctx, t.ID)
	return t, err
}

// domains returns a tenant's domains in the order they were given.
func (r tenants) domains(ctx context.Context, id string) ([]string, error) {
	rows, err := r.s.query(ctx, `SELECT domain FROM tenant_domains WHERE tenant_id = ? ORDER BY position`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
```

**Domain order.** `tenant_domains.position` records the slice index, so domains read back in the order they were given. The memory driver preserves that order and storetest asserts it.

`scanTenant(row interface{ Scan(...any) error })` scans the 13 columns:
- decodes the JSON columns with `fromJSON` (`allowed_logout_urls`, `enabled_locales`, `custom_text`);
- sets `Branding{LogoURL, PrimaryColor}`;
- converts `created_at` with `fromMicros`.

`tenantArgs` is its inverse: 13 values in `tenantCols` order. `prefixed(p, cols)` prefixes each comma-separated column name.

**The other repositories.** Use the same pattern. The SQL for each method:

| Repository | Method | SQL / rule |
|---|---|---|
| clients | Create | `INSERT INTO clients (…14 cols…) VALUES (…)`, with `conflict` mapping. JSON: `secrets` (a slice of `{hash, created_at micros, expires_at micros or null}` structs, **not** `store.ClientSecret`, so times use the micros encoding), `grant_types`, `callbacks`, `allowed_logout_urls`, `web_origins`, `allowed_origins`, `refresh_token` (`RefreshTokenPolicy` as JSON). |
| clients | Get | `SELECT … WHERE tenant_id=? AND client_id=?` |
| clients | Update | `UPDATE … WHERE tenant_id=? AND client_id=?`. Zero rows gives `ErrNotFound`. |
| clients | Delete | `DELETE … WHERE tenant_id=? AND client_id=?`. Zero rows gives `ErrNotFound`. |
| clients | List | `… WHERE tenant_id=? ORDER BY client_id` |
| resource_servers | Create, Get, GetByIdentifier, Update, Delete | Same shape, with keys `(tenant_id,id)` and the unique `identifier`. `scopes` is JSON. `Update` maps a unique violation to `ErrConflict`. |
| client_grants | Create | Insert. A duplicate ID or `(client_id, audience)` gives `ErrConflict`. |
| client_grants | Find | `WHERE tenant_id=? AND client_id=? AND audience=?` |
| client_grants | Update | First `SELECT client_id, audience … WHERE tenant_id=? AND id=?` (absent gives `ErrNotFound`). If either differs from `g`, return `ErrConflict`. Otherwise update `scopes`. Run all of this in `atomic`. |
| client_grants | Delete | Zero rows gives `ErrNotFound`. |
| signing_keys | Create | Insert. A unique violation (duplicate KID, or a second current/next key through the active index) gives `ErrConflict`. |
| signing_keys | List | `WHERE tenant_id=? ORDER BY created_at, kid` |
| signing_keys | Rotate | In `atomic`, in this order:<br>1. If `next.Status != KeyNext`, return the same error text as memory.<br>2. `SELECT kid FROM signing_keys WHERE tenant_id=? AND status='next'` + `forUpdate`. If absent, return `ErrNotFound`.<br>3. Update the statuses in order: previous→revoked, current→previous, next→current.<br>4. Insert `next`. A unique violation gives `ErrConflict`, and the transaction rolls back. |
| connections | Create, Get, GetByName, Update, List | Keys `(tenant_id,id)`, unique `name`. `enabled_clients` is JSON. `PasswordPolicy` maps to the two integer columns. `List` is `ORDER BY name`. |

Each repository returns fresh values on every read, so there is no aliasing. Copy semantics come for free.

- [ ] **Step 3: Run**

Run: `go test -race ./internal/store/sqlstore/ && ./scripts/test-sql.sh`
Expected: the six suites PASS on SQLite, PostgreSQL and MySQL. Fix any per-dialect difference in the repository, never in storetest.

- [ ] **Step 4: Commit**

```bash
git add internal/store/sqlstore
git commit -m "feat(sqlstore): tenants, clients, resource servers, client grants, signing keys, connections"
```

---

### Task 4: Repositories — users, sessions, auth transactions

**Files:**
- Create: `internal/store/sqlstore/{users.go,sessions.go,auth_transactions.go}`
- Modify: `internal/store/sqlstore/conformance_test.go`. Add the three accessors to `hybrid` and the suites `"Users"`, `"Sessions"` and `"AuthTransactions"` to `RunSuites`.

**Interfaces (produced):** `Users()`, `Sessions()` and `AuthTransactions()` on `*sqlstore.Store`.

- [ ] **Step 1: Failing test**

Extend the hybrid and the suite list as above.

Run: `go test ./internal/store/sqlstore/`
Expected: FAIL to compile.

- [ ] **Step 2: Users**

Uniqueness rule (from `store.Users`): among users with an identity on the same connection, a non-empty `Email` and a non-empty `Username` must each be unique. The database enforces this through `user_logins`. Each row records one login value of one user on one connection, and its primary key `(tenant_id, connection, kind, value)` makes duplicates impossible.

```go
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type users struct{ s *Store }

func (s *Store) Users() store.Users { return users{s} }

const userCols = `tenant_id, user_id, email, email_verified, username, name, nickname, picture, given_name, family_name,
 user_metadata, blocked, identities, last_login, logins_count, created_at, updated_at`

func (r users) Create(ctx context.Context, u *store.User) error {
	return r.s.atomic(ctx, func(tx *Store) error {
		args, err := userArgs(u)
		if err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `INSERT INTO users (`+userCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...); err != nil {
			return tx.conflict(err)
		}
		return putLogins(ctx, tx, u)
	})
}

// putLogins replaces the user's rows in user_logins. A duplicate value on
// the same connection is a unique violation, mapped to ErrConflict.
func putLogins(ctx context.Context, tx *Store, u *store.User) error {
	if _, err := tx.exec(ctx, `DELETE FROM user_logins WHERE tenant_id = ? AND user_id = ?`, u.TenantID, u.UserID); err != nil {
		return err
	}
	for _, id := range u.Identities {
		for kind, v := range map[string]string{"email": u.Email, "username": u.Username} {
			if v == "" {
				continue
			}
			if _, err := tx.exec(ctx, `INSERT INTO user_logins (tenant_id, connection, kind, value, user_id) VALUES (?,?,?,?,?)`,
				u.TenantID, id.Connection, kind, v, u.UserID); err != nil {
				return tx.conflict(err)
			}
		}
	}
	return nil
}

func (r users) Update(ctx context.Context, u *store.User) error {
	return r.s.atomic(ctx, func(tx *Store) error {
		args, err := userArgs(u)
		if err != nil {
			return err
		}
		// Login stats are owned by RecordLogin; Update never changes them.
		res, err := tx.exec(ctx, `UPDATE users SET email=?, email_verified=?, username=?, name=?, nickname=?, picture=?,
 given_name=?, family_name=?, user_metadata=?, blocked=?, identities=?, created_at=?, updated_at=?
 WHERE tenant_id=? AND user_id=?`,
			args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12],
			args[15], args[16], u.TenantID, u.UserID)
		if err != nil {
			return tx.conflict(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return store.ErrNotFound
		}
		return putLogins(ctx, tx, u)
	})
}

func (r users) FindByLogin(ctx context.Context, tenantID, connection, login string) (*store.User, error) {
	if login == "" {
		return nil, store.ErrNotFound
	}
	var userID string
	err := r.s.queryRow(ctx, `SELECT user_id FROM user_logins WHERE tenant_id=? AND connection=? AND value=? ORDER BY kind LIMIT 1`,
		tenantID, connection, login).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return r.Get(ctx, tenantID, userID)
}

func (r users) RecordLogin(ctx context.Context, tenantID, userID string, at time.Time) error {
	res, err := r.s.exec(ctx, `UPDATE users SET last_login=?, logins_count=logins_count+1 WHERE tenant_id=? AND user_id=?`,
		micros(at), tenantID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}
```

`Get` reads by `(tenant_id, user_id)` through `scanUser`, which reverses `userArgs`:
- 17 values in `userCols` order;
- `user_metadata` and `identities` are JSON;
- `last_login` uses the nullable micros encoding.

`SetPasswordHash` works as follows:
1. In `atomic`, `SELECT identities FROM users WHERE tenant_id=? AND user_id=?` + `forUpdate`. If the user is absent, return `ErrNotFound`.
2. Decode the identities and find the one with `Connection == connection`. If there is none, return `ErrNotFound`.
3. Set its `PasswordHash`, and `UPDATE users SET identities=?, updated_at=? …`.

**MySQL quirk.** `RowsAffected` reports *changed* rows by default. An `UPDATE` that writes identical values therefore reports 0, which would be misread as `ErrNotFound`. Add `clientFoundRows=true` to the MySQL DSN in `Open`, so it reports matched rows. Add a regression test: `Update` the same unchanged user twice on every dialect.

- [ ] **Step 3: Sessions and auth transactions**

| Method | SQL / rule |
|---|---|
| Sessions.Create | Insert. A duplicate `(tenant_id,id)` or `(tenant_id,token_hash)` gives `ErrConflict`. `client_ids` is JSON. |
| Sessions.GetByTokenHash | `WHERE tenant_id=? AND token_hash=?` |
| Sessions.Touch | `UPDATE sessions SET idle_expires_at=? WHERE tenant_id=? AND id=?`. Zero rows gives `ErrNotFound`. |
| Sessions.AddClient | In `atomic`: `SELECT client_ids … WHERE tenant_id=? AND id=?` + `forUpdate` (absent gives `ErrNotFound`). If `clientID` is not in the list, append it and `UPDATE`. |
| Sessions.Delete | Zero rows gives `ErrNotFound`. |
| Sessions.DeleteByUser | `DELETE … WHERE tenant_id=? AND user_id=?`, returning `RowsAffected`. |
| Sessions.DeleteExpired | `DELETE FROM sessions WHERE expires_at <= ? OR idle_expires_at <= ?`, both arguments `micros(before)`. Return `RowsAffected`. |
| AuthTransactions.Create / Get / Delete | Keys `(tenant_id,id)`. `params` is JSON. `Delete` with zero rows gives `ErrNotFound`. |
| AuthTransactions.DeleteExpired | `DELETE … WHERE expires_at <= ?` |

- [ ] **Step 4: Run and commit**

Run: `go test -race ./internal/store/sqlstore/ && ./scripts/test-sql.sh`
Expected: PASS on all three dialects, including `Sessions/ConcurrentAddClient` and `Users/UpdateUsernameConflictAndKeepsLoginStats`.

```bash
git add internal/store/sqlstore
git commit -m "feat(sqlstore): users, sessions, auth transactions"
```

---

### Task 5: Repositories — auth codes, refresh tokens, reset tickets; `WithTx`; the complete driver

**Files:**
- Create: `internal/store/sqlstore/{auth_codes.go,refresh_tokens.go,password_reset_tickets.go,tx.go}`
- Modify: `internal/store/sqlstore/conformance_test.go`: delete `hybrid` and run the **full** `storetest.Run` against the SQL store.

**Interfaces (produced):**
- `AuthCodes()`, `RefreshTokens()`, `PasswordResetTickets()` and `WithTx` on `*sqlstore.Store`;
- the compile-time assertion `var _ store.Store = (*Store)(nil)`.

- [ ] **Step 1: Failing test**

Replace `conformance_test.go` with:

```go
package sqlstore

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

var _ store.Store = (*Store)(nil)

func TestConformance(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T) store.Store { return fresh(t) })
		})
	}
}
```

Run: `go test ./internal/store/sqlstore/`
Expected: FAIL to compile.

- [ ] **Step 2: The atomic repositories**

`auth_codes.go`, with `Consume`:

```go
// Consume marks the code used, or on a later presentation records the first
// replay; one transaction with the row locked makes concurrent callers see
// exactly one success.
func (r authCodes) Consume(ctx context.Context, tenantID, codeHash string, at time.Time) (*store.AuthCode, error) {
	var out *store.AuthCode
	var replay bool
	err := r.s.atomic(ctx, func(tx *Store) error {
		c, err := scanAuthCode(tx.queryRow(ctx, `SELECT `+authCodeCols+` FROM auth_codes WHERE tenant_id=? AND code_hash=?`+tx.d.forUpdate, tenantID, codeHash))
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		switch {
		case c.UsedAt == nil:
			if _, err := tx.exec(ctx, `UPDATE auth_codes SET used_at=? WHERE tenant_id=? AND code_hash=?`, micros(at), tenantID, codeHash); err != nil {
				return err
			}
			t := at.UTC().Truncate(time.Microsecond)
			c.UsedAt = &t
		case c.ReplayedAt == nil:
			if _, err := tx.exec(ctx, `UPDATE auth_codes SET replayed_at=? WHERE tenant_id=? AND code_hash=?`, micros(at), tenantID, codeHash); err != nil {
				return err
			}
			t := at.UTC().Truncate(time.Microsecond)
			c.ReplayedAt = &t
			replay = true
		default:
			replay = true
		}
		out = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	if replay {
		return out, store.ErrAlreadyUsed
	}
	return out, nil
}
```

The replay case still **commits**, because recording `replayed_at` is part of the contract. That is why `ErrAlreadyUsed` is returned only after `atomic` has returned nil.

The other `AuthCodes` methods:
- `Create`: insert. A duplicate `(tenant_id, code_hash)` gives `ErrConflict`.
- `Get`: by key.
- `DeleteExpired`: `DELETE … WHERE expires_at <= ?`.

`refresh_tokens.go`, with `Rotate`. It mirrors the memory driver's rules, including the Task 2 (Plan 3) rule that a rotated-then-revoked token is reuse:

```go
func (r refreshTokens) Rotate(ctx context.Context, tenantID, oldID string, next *store.RefreshToken, at time.Time, leeway time.Duration) error {
	var reused bool
	err := r.s.atomic(ctx, func(tx *Store) error {
		old, err := scanRefreshToken(tx.queryRow(ctx, `SELECT `+refreshCols+` FROM refresh_tokens WHERE tenant_id=? AND id=?`+tx.d.forUpdate, tenantID, oldID))
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if old.RevokedAt != nil {
			if old.RotatedAt != nil {
				reused = true
				return nil
			}
			return store.ErrNotFound
		}
		if next.TenantID != tenantID || next.FamilyID != old.FamilyID {
			return store.ErrConflict
		}
		if old.RotatedAt != nil {
			if leeway <= 0 || !at.Before(old.RotatedAt.Add(leeway)) {
				if _, err := tx.exec(ctx, `UPDATE refresh_tokens SET revoked_at=? WHERE tenant_id=? AND family_id=? AND revoked_at IS NULL`,
					micros(at), tenantID, old.FamilyID); err != nil {
					return err
				}
				reused = true
				return nil
			}
		} else if _, err := tx.exec(ctx, `UPDATE refresh_tokens SET rotated_at=? WHERE tenant_id=? AND id=?`, micros(at), tenantID, oldID); err != nil {
			return err
		}
		return tx.RefreshTokens().(refreshTokens).insert(ctx, next)
	})
	if err != nil {
		return err
	}
	if reused {
		return store.ErrAlreadyUsed
	}
	return nil
}
```

Before writing this, read `internal/store/memory/refresh_tokens.go` and match it exactly. That includes the order of the conflict check relative to the reuse check, and what "nothing changes" means for each error. The storetest cases `RotateAndReuse`, `RotateAfterFamilyRevoked`, `RotateWithinLeeway`, `RotateUnknownAndConflict` and `ConcurrentRotate` are the oracle.

If the successor's insert conflicts, the transaction rolls back, so `rotated_at` is not set. That is exactly "nothing changes".

Remaining refresh-token methods:

| Method | SQL / rule |
|---|---|
| Create | Insert. A duplicate ID or `(tenant_id, token_hash)` gives `ErrConflict`. `expires_at` and `idle_expires_at` store 0 for a zero time. |
| GetByTokenHash | `WHERE tenant_id=? AND token_hash=?` |
| Touch | `UPDATE … SET idle_expires_at=? WHERE tenant_id=? AND id=? AND revoked_at IS NULL AND rotated_at IS NULL`. Zero rows gives `ErrNotFound`. |
| RevokeFamily | `UPDATE … SET revoked_at=? WHERE tenant_id=? AND family_id=? AND revoked_at IS NULL` |
| RevokeByUser | The same with `user_id`, returning `RowsAffected`. |
| DeleteExpired | `DELETE FROM refresh_tokens WHERE (expires_at > 0 AND expires_at <= ?) OR (idle_expires_at > 0 AND idle_expires_at <= ?)` |

Password reset tickets:

| Method | SQL / rule |
|---|---|
| Create | Insert. A duplicate ID or `(tenant_id, token_hash)` gives `ErrConflict`. |
| GetByTokenHash | `WHERE tenant_id=? AND token_hash=?` |
| Consume | In `atomic`, select the row by token hash with `forUpdate`. If absent, return `ErrNotFound`. If `used_at` is set, return the record together with `ErrAlreadyUsed`. Otherwise `UPDATE … SET used_at=? WHERE … AND used_at IS NULL` and return the updated record. |
| DeleteByUser | `DELETE … WHERE tenant_id=? AND user_id=? AND used_at IS NULL`. It deletes only unused tickets, matching memory (Plan 5 ruling). Return `RowsAffected`. |
| DeleteExpired | `DELETE … WHERE expires_at <= ?` |

`tx.go`:

```go
package sqlstore

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// WithTx runs fn in one database transaction. fn must use the store it is
// given, not the outer one (with SQLite the outer one would block).
func (s *Store) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.atomic(ctx, func(t *Store) error { return fn(t) })
}
```

- [ ] **Step 3: Run**

Run: `go test -race ./internal/store/sqlstore/ && ./scripts/test-sql.sh`
Expected: the **entire** conformance suite passes on SQLite, PostgreSQL and MySQL. That includes every `Concurrent*` case and the `Tx` suite.

Also run `./scripts/test-sql.sh -count=3 -run 'TestConformance/.*/(AuthCodes|RefreshTokens|Sessions|PasswordResetTickets)/Concurrent' ./internal/store/sqlstore/` to shake out races. It must pass every time.

- [ ] **Step 4: Commit**

```bash
git add internal/store/sqlstore
git commit -m "feat(sqlstore): auth codes, refresh tokens, reset tickets, WithTx; full conformance on all dialects"
```

---

### Task 6: Wiring — DSN dispatch, `zeroauthy migrate`, `auto_migrate`, CI, E2E on SQLite, docs

**Files:**
- Modify: `internal/storage/open.go`, `internal/storage/open_test.go`
- Modify: `internal/config/config.go`, `internal/config/config_test.go` (`storage.auto_migrate`)
- Create: `cmd/zeroauthy/migrate.go`; modify `cmd/zeroauthy/root.go` and `cmd/zeroauthy/seed.go`
- Modify: `internal/app/app.go`, `internal/app/app_test.go`
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/e2e/run-m3.sh`, `tests/e2e/run-browser.sh`
- Modify: `docs/compat/decisions.md` (D-0020), `docs/compat/matrix.md`, `README.md`, `docs/superpowers/plan-1-followups.md`, spec §5.1

**Interfaces (produced):**
- `storage.Open(ctx, dsn) (store.Store, error)` now dispatches to `sqlstore.Open` for SQL schemes.
- `storage.Migrator`: an optional interface `{ Migrate(ctx) error; CheckSchema(ctx) error }`, implemented by `*sqlstore.Store`.
- `config.Storage.AutoMigrate bool` (koanf `auto_migrate`, default `false`).
- The `zeroauthy migrate [--config]` command.

- [ ] **Step 1: Failing tests**

`internal/storage/open_test.go`:
- `sqlite://<tempdir>/z.db` opens and pings, and `Ping` succeeds.
- `postgresql://` and `postgres://` are both recognised. Assert the error for an unreachable host; do not require a server.
- An unknown scheme's error names the scheme.

`internal/app/app_test.go`:
- **Unmigrated database:** with `storage.dsn: sqlite://<tmp>` and `auto_migrate: false` against a fresh file, `app.New` fails with "run zeroauthy migrate".
- **Auto-migrate:** with `auto_migrate: true`, `app.New` migrates and the handler serves `/healthz`.
- **Master key:** a master key is required for SQLite. The existing rule covers this, and the test sets `security.master_key`.

`cmd/zeroauthy`:
- A test runs `migrate` against a temp SQLite DSN and checks that the output names the version.
- A second run says "up to date".

Run: `go test ./internal/storage/ ./internal/app/ ./cmd/zeroauthy/`
Expected: FAIL.

- [ ] **Step 2: Implement**

`internal/storage/open.go`:

```go
// Open returns the driver named by the DSN scheme: memory://, sqlite://,
// postgres:// (or postgresql://), mysql://. plugin:// comes with the gRPC
// plugin host.
func Open(ctx context.Context, dsn string) (store.Store, error) {
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" {
		return nil, fmt.Errorf("storage: DSN %q has no scheme (e.g. memory://, sqlite:///path.db)", dsn)
	}
	switch u.Scheme {
	case "memory":
		return memory.New(), nil
	case "sqlite", "postgres", "postgresql", "mysql":
		return sqlstore.Open(ctx, dsn)
	default:
		return nil, fmt.Errorf("storage: driver %q is not available in this build", u.Scheme)
	}
}

// Migrator is implemented by drivers with a schema (the SQL drivers).
type Migrator interface {
	Migrate(ctx context.Context) error
	CheckSchema(ctx context.Context) error
}
```

`internal/app/app.go` `New`: after `storage.Open`, if the store implements `storage.Migrator`, then:
- with `cfg.Storage.AutoMigrate`, call `Migrate`;
- otherwise call `CheckSchema`.

On error, close the store and return the error. Log the schema version at Info.

`cmd/zeroauthy/migrate.go`:

```go
func newMigrateCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply pending storage migrations for the configured driver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath, os.Environ())
			if err != nil {
				return err
			}
			st, err := storage.Open(cmd.Context(), cfg.Storage.DSN)
			if err != nil {
				return err
			}
			defer st.Close()
			m, ok := st.(interface {
				storage.Migrator
				SchemaVersion(context.Context) (int64, error)
				LatestVersion() int64
			})
			if !ok {
				fmt.Fprintln(cmd.OutOrStdout(), "this storage driver has no schema; nothing to migrate")
				return nil
			}
			before, err := m.SchemaVersion(cmd.Context())
			if err != nil {
				return err
			}
			if err := m.Migrate(cmd.Context()); err != nil {
				return err
			}
			if before == m.LatestVersion() {
				fmt.Fprintf(cmd.OutOrStdout(), "schema is up to date (version %d)\n", before)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "migrated schema from version %d to %d\n", before, m.LatestVersion())
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", os.Getenv("ZEROAUTHY_CONFIG"), "path to the YAML config file")
	return cmd
}
```

- Register the command in `root.go`.
- `seed.go`: after `storage.Open`, call `CheckSchema` when the store is a `Migrator`. That way seeding never writes into an unmigrated database.

- [ ] **Step 3: CI**

In `.github/workflows/ci.yml`, add a job `sql`:
- `services: postgres` (`postgres:17`, env `POSTGRES_PASSWORD: zeroauthy`, port `55432:5432`, health check `pg_isready`);
- `services: mysql` (`mysql:8.4`, env `MYSQL_ROOT_PASSWORD: zeroauthy`, port `53306:3306`, health check `mysqladmin ping -pzeroauthy`).

It sets the same two `ZA_TEST_*` environment variables as `scripts/test-sql.sh`, then runs `go test -race -count=1 ./internal/store/sqlstore/...`.

- [ ] **Step 4: E2E on SQLite**

In both `tests/e2e/run-m3.sh` and `tests/e2e/run-browser.sh`, start zeroauthy with these environment overrides:
- `ZEROAUTHY_STORAGE__DSN="sqlite://$work/e2e.db"`
- `ZEROAUTHY_STORAGE__AUTO_MIGRATE=true`
- `ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)"`

The E2E suite then exercises the SQLite driver end to end. `tests/e2e/config.yaml` keeps `memory://` as its default for manual runs.

Run: `make e2e`
Expected: run-m3 prints both OK lines, and run-browser reports `6 passed`. Both now run on SQLite.

- [ ] **Step 5: Docs**

Append to `docs/compat/decisions.md`:

```markdown
## D-0020: SQL storage encoding and isolation

- **Context:** The spec requires SQLite, PostgreSQL and MySQL drivers that pass the same conformance suite as the memory driver, with atomic single-method operations.
- **Sources:** spec §5.1; the database vendors' documentation for unique-violation codes and row locking.
- **Decision:**
  - **Times:** stored as BIGINT microseconds since the Unix epoch (UTC). Zero time is 0 and a nil time is NULL, so every dialect compares and sorts times the same way, with no timezone or precision differences.
  - **Values without their own table:** lists and maps are stored as JSON text.
  - **Uniqueness:** enforced by unique indexes; a violation maps to `ErrConflict`. This includes:
    - per-connection user logins, through `user_logins`;
    - one current and one next signing key per tenant, through a partial or generated-column unique index.
  - **Atomic operations:** each runs in one transaction. PostgreSQL and MySQL use `SELECT … FOR UPDATE`. SQLite uses a single connection and immediate transactions.
  - **MySQL:**
    - **Collation:** `utf8mb4_bin`, so comparisons are case-sensitive like the other drivers.
    - **Session settings:** strict SQL mode, a UTC session time zone, and `clientFoundRows`.
  - **Migrations:** embedded and ordered. `serve` refuses to start against an older or newer schema unless `storage.auto_migrate` is true.
- **Rationale:** One encoding for all dialects keeps the shared SQL simple and the conformance results identical.
```

In `docs/compat/matrix.md`, add a "Storage drivers" row:

```markdown
| Storage drivers: memory, SQLite, PostgreSQL 14+, MySQL 8.0.17+ | Implemented | All pass `pkg/storetest` (SQLite in every test run; PostgreSQL 17 and MySQL 8.4 via `make test-sql` and CI); E2E runs on SQLite |
```

`README.md`:
- Add a "Storage" section showing the four DSN forms, `zeroauthy migrate`, `storage.auto_migrate` and `make test-sql`.
- Note that PostgreSQL and MySQL tests need podman or docker.

`docs/superpowers/plan-1-followups.md`:
- Delete the two milestone-7 Prerequisites rows.
- Delete the SQL-driver items that this plan closed:
  - the storage conformance gaps;
  - `Users.Update` overwriting login stats;
  - the `RefreshTokens.Rotate` transaction requirement;
  - `DeleteExpired` needing indexes;
  - the `ReplayedAt` and ticket `Consume` atomicity notes.
- Add a `## Plan 6 follow-ups` section listing:
  - the gRPC plugin host (milestone 8) must run `storetest` against a sample plugin;
  - MariaDB support;
  - down-migrations;
  - moving the throttles and the reset send limit into the store, for multi-instance deployments.

Spec §5.1: add the `storage.auto_migrate` behaviour sentence and the supported versions.

- [ ] **Step 6: Verify and commit**

Run: `go test -race ./... && go vet ./... && gofmt -l . && ./scripts/test-sql.sh && make e2e`
Expected: everything passes.

```bash
git add internal cmd .github tests/e2e docs README.md
git commit -m "feat(storage): sql drivers selectable by DSN, zeroauthy migrate, auto_migrate; CI and E2E on SQLite; docs"
```

---

## Plan Self-Review (completed by the planner)

**Spec coverage:**
- §5.1 DSN table: sqlite, postgres and mysql in Tasks 2 and 6. The plugin is milestone 8.
- §5.1 `sqlstore` with dialects and embedded migrations: Task 2.
- `zeroauthy migrate` and `auto_migrate`: Task 6.
- Atomic single-method operations: Tasks 3–5.
- `WithTx`: Tasks 1 and 5.
- §12 storage conformance against memory, SQLite, PostgreSQL and MySQL: Tasks 1–5, with the plugin in milestone 8.

**Prerequisites from `plan-1-followups.md` (all in Task 1, with storetest cases the SQL drivers must also pass):**
- the `keys.Manager.Ensure` repair;
- one current and one next key, enforced by the store;
- the storetest gaps;
- `WithTx`;
- a transactional seed.

**Rulings made while planning:**
1. Times are microsecond BIGINTs on every dialect (D-0020).
2. SQLite runs on a single connection.
3. MySQL uses `utf8mb4_bin` and `clientFoundRows`.
4. The memory `WithTx` is best-effort isolated and documented as for tests and demos.
5. A test-only hybrid store lets Tasks 3–4 run partial conformance; Task 5 removes it.
6. `user_logins` is a separate table that enforces per-connection login uniqueness.

**Type consistency:**
- `sqlstore.Open`, `Migrate`, `CheckSchema`, `SchemaVersion` and `LatestVersion` are the same in Tasks 2 and 6.
- `storetest.RunSuites` and `Suites` are the same in Tasks 1, 3 and 4.
- `atomic`, `conflict` and `forUpdate` are used identically across Tasks 3–5.

**Review Focus mapping:**
1. The `Concurrent*` cases on every dialect: Tasks 1 and 5.
2. `Users.Create`/`Update` through `putLogins` in `atomic`, and `Tenants.Create`/`Update` through `putDomains` in `atomic`: Tasks 3 and 4, plus `Tx/ConflictInsideRollsBack`.
3. The codec tests: Task 2.
4. The migrate test for a newer schema version: Task 2.
5. The seed rollback test (Task 1) and E2E on SQLite (Task 6).
