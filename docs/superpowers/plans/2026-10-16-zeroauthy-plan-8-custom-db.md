# zeroauthy Plan 8: Custom Database Connections with Import Mode (Milestone 9)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a database connection can delegate its users to a legacy user store through Auth0-shaped custom database action scripts. Operators paste their existing Auth0 scripts (`login`, `get_user`, `create`, `change_password`, …) into the seed file, unchanged. With `import_mode` on, each user is copied into zeroauthy on their first successful login (trickle migration), and the legacy store is never consulted for them again. Hosted login, the password grants, `/dbconnections/signup`, `/dbconnections/change_password` and the hosted password reset all work on such connections.

**Architecture:**
- **Auth0's connection shape** (user decision, 2026-10-16). A custom database is still strategy `auth0`. The options are Auth0's: `enabledDatabaseCustomization`, `import_mode`, `customScripts` (a map from script name to source), `configuration` (a map of secrets the scripts read) and `set_user_root_attributes`. This replaces spec §5.3's separate `custom-db` strategy and its HMAC webhooks.
- **Execution in real Node.js** (D-0022). zeroauthy launches one Node.js process per tenant, running `runner.mjs`, which is embedded in the binary. The process is started lazily and stopped when idle.
  - **Protocol:** requests and responses are newline-delimited JSON over stdin and stdout.
  - **Script context:** each connection's scripts run in their own `vm` context, with Auth0's globals: `configuration`, `global`, `WrongUsernameOrPasswordError`, `ValidationError`, `UnauthorizedError`, `require`, `fetch`, `console`, timers and `Buffer`.
- **Environment isolation** (the user's hard requirement: scripts must not read the system's environment variables):
  - The process starts with an **empty environment** (`exec.Cmd.Env = []string{}`).
  - Configuration travels only inside requests on stdin.
  - Node runs with `--permission`, granting file reads only for the runner directory and the operator's modules directory. It grants no child processes, workers, addons or WASI. So neither `/proc/<ppid>/environ` nor any host file is readable, and nothing can be spawned.
  - Network access is granted (`--allow-net` on Node versions that have it), because scripts must reach their databases.
- **`internal/customdb`:**
  - `NodeRunner` manages the processes and implements `Executor`.
  - `Client` wraps an `Executor` with typed calls (`Login`, `GetUser`, `Create`, `ChangePassword`) and decodes and validates profiles.
  - `FuncExecutor` is an in-Go fake for unit tests.
- **`internal/identity`:** `Database` gains a `Scripts *customdb.Client`. `Login`, `Signup` and two new methods (`FindForReset` and `ChangeLegacyPassword`) branch on the connection's mode. The HTTP handlers keep calling the same `identity` API.

**Tech Stack:**
- Go 1.26+ and Node.js ≥ 22.13 at runtime, needed only when a tenant uses custom database scripts. Node 22.13 is the first 22.x release where `--permission` is stable.
- No new Go dependencies. The runner uses only Node built-ins.

**Spec:** `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md`:
- §4: the Connection and User rows;
- §5.3: legacy user store bridge (rewritten for this plan);
- §9: the `custom_db` configuration;
- §13: milestone 9;
- §14: the script-runtime risk.

**Auth0 sources** (public docs; read them, never copy them):
- https://auth0.com/docs/authenticate/database-connections/custom-db
- https://auth0.com/docs/authenticate/database-connections/custom-db/templates (and its `login`, `get-user`, `create`, `change-password` subpages)
- https://auth0.com/docs/authenticate/database-connections/custom-db/error-handling
- https://auth0.com/docs/manage-users/user-migration/configure-automatic-migration-from-your-database
- https://auth0.com/docs/best-practices/custom-database-connection-and-action-script-best-practices/custom-database-action-script-execution-best-practices (the 20 s limit and the 100 kB script size)

## Global Constraints

- **Earlier constraints still apply:**
  - Drivers return copies; every atomic operation is one store method.
  - `go test -race ./...`, `go vet` and `gofmt` stay clean; `go generate ./...` produces no diff.
  - `CGO_ENABLED=0 go build` works.
  - Errors never quote a DSN.
- **Clean room:**
  - Script names, signatures, error class names and option names are Auth0's public contract, and we match them exactly.
  - All sample scripts, docs and UI text are original. Never paste Auth0's template code into the repository, tests or docs.
- **Script names** (the seven `customScripts` keys): `login`, `get_user`, `create`, `verify`, `change_password`, `delete`, `change_email`. Any other key is a seed error.
- **Limits:**
  - Each script source is at most **100 kB** (102400 bytes).
  - One execution may take at most **20 s**, enforced by the host; when it is exceeded, the tenant's runner process is killed.
  - `configuration` holds at most 64 keys; each key is 1–128 bytes of `[A-Za-z0-9_]` and each value at most 4096 bytes.
- **User IDs:** a custom-database user's `UserID` is `auth0|<profile.user_id>`, and its identity is `{Connection: conn.Name, Provider: "auth0", UserID: profile.user_id}`. A `profile.user_id` must be a non-empty string or an integer JSON number, at most 200 bytes, with no control characters and no `|`.
- **Environment isolation is a tested invariant:**
  - The runner's `exec.Cmd.Env` is always the empty, non-nil slice `[]string{}`.
  - No secret is ever passed in argv.
  - A test (Task 3) proves that a sentinel environment variable of the host is not visible to scripts through `process.env`, `/proc/self/environ` or `/proc/<ppid>/environ`, and that `child_process` cannot run.
- **Configuration secrets are encrypted at rest:**
  - `store.Connection.ConfigurationSealed` holds the envelope-sealed JSON of the `configuration` map, with AAD `"connection-config|" + tenantID + "|" + connectionID`.
  - Only `customdb.Client` opens it.
  - It never appears in logs or errors.
- **Passwords never leave the request:** plaintext passwords go only to the runner's stdin, and are never logged on either side. The runner never echoes request arguments into logs or error messages.
- **The Node floor is 22.13.** On 22.x, `--permission` is stable from 22.13. Any major version 23 or later passes the check. The runner probes `--allow-net` once (`node --permission --allow-net -e 0`) and adds it when the probe succeeds; Node 25 and later deny network access under `--permission` without it.

## Review Focus

1. **A script that never calls back or loops forever:** the request fails after 20 s with a server error, the tenant's runner is killed and restarted on the next call, and other tenants are unaffected. Pinned in Task 3 (`TestRunnerTimeoutKillsTenantProcess`).
2. **A script that calls back twice, or throws after calling back:** the first result wins, and later calls are ignored and logged. Pinned in Task 3 (`TestRunnerCallbackOnce`).
3. **A login profile with a missing, empty, non-string or oversized `user_id`, or a malformed email:** the login fails closed (server error, logged), and no user is created. Pinned in Task 4 (`TestLegacyLoginRejectsBadProfile`).
4. **A legacy profile whose email or user_id already belongs to a different local user on the connection:** the login fails closed and nothing is overwritten (D-0024). Pinned in Task 4 (`TestLegacyLoginCollision`).
5. **Two first logins of the same user at once in import mode:** both succeed, one local user exists, and the second login verifies against the stored hash. Pinned in Task 5 (`TestImportConcurrentFirstLogin`).

---

## Out of Scope

These are recorded in `plan-1-followups.md` under "Plan 8 follow-ups" in Task 7:
- **Callers not built yet:**
  - `verify` needs verification emails.
  - `delete` and `change_email` are called by the Management API (sub-project 3).
  - The runner and `Client.Run` already execute any of the seven scripts.
- **Profile fields and prompts:**
  - `mfa_factors` in profiles (MFA, sub-project 2).
  - Custom signup prompt fields passed to `create` (changelog 2026-04-02, sub-project 2).
- **Other features:**
  - Custom user IDs at signup (changelog 2026-09-17, EA).
  - Passkeys on custom databases.
  - Bcrypt hashes from bulk import.
- **Runtime:**
  - An egress allowlist for scripts. Network access is open; operators firewall it.
  - Pinning the Node version through a config option; today any Node ≥ 22.13 is accepted.

## File Map

| File | Responsibility |
|---|---|
| `internal/store/types.go` | `Connection` custom-DB fields; `User.AppMetadata`; script-name constants |
| `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0002_custom_db.sql` | New columns |
| `internal/store/sqlstore/connections.go`, `users.go` | Read and write the new columns |
| `internal/store/memory/clone.go` | Deep-copy the new maps and bytes |
| `proto/store/v1/store.proto`, `internal/store/grpcstore/codec.go` | New fields over the plugin protocol |
| `pkg/storetest/connections.go`, `users.go` | Round-trip cases for the new fields |
| `internal/keys/config.go` | `SealConnectionConfig` / `OpenConnectionConfig` |
| `internal/config/config.go` | `custom_db` section |
| `internal/seed/seed.go`, `validate.go`, `apply.go` | Auth0-named options; sealing on apply |
| `internal/app/app.go`, `cmd/zeroauthy/seed.go` | Wire the runner; the seed command seals with the master key |
| `internal/customdb/runner.mjs` | Node side: protocol, vm contexts, Auth0 globals, error mapping |
| `internal/customdb/node.go` | `NodeRunner`: per-tenant processes, version probe, timeouts, idle reaper |
| `internal/customdb/client.go`, `profile.go`, `errors.go` | Typed calls, profile validation, error kinds |
| `internal/customdb/fake.go` | `FuncExecutor` for unit tests |
| `internal/identity/custom.go` | Legacy and import-mode logic |
| `internal/identity/database.go` | Dispatch from `Login` and `Signup` |
| `internal/login/login.go`, `reset.go`; `internal/oauth/grant_password.go`; `internal/dbconn/*.go` | Map the new errors; route reset lookups through `identity` |
| `internal/server/server.go` | One shared `identity.Database` with `Scripts` |
| `tests/e2e/legacy-store.mjs`, `m9-custom-db.mjs`, `m9-import.spec.mjs`, `seed.yaml`, `run-m3.sh`, `run-browser.sh` | E2E |
| `.github/workflows/ci.yml` | Node in the `test` job; `ZA_REQUIRE_NODE=1` |
| `docs/custom-db.md`, `docs/compat/*`, README, spec | Docs |

---

### Task 1: Store fields, migration 0002, plugin protocol, conformance

**Files:**
- Modify: `internal/store/types.go`
- Create: `internal/store/sqlstore/migrations/sqlite/0002_custom_db.sql`, `.../postgres/0002_custom_db.sql`, `.../mysql/0002_custom_db.sql`
- Modify: `internal/store/sqlstore/connections.go`, `internal/store/sqlstore/users.go`
- Modify: `internal/store/memory/clone.go`
- Modify: `proto/store/v1/store.proto` (regenerate with `go generate ./...`), `internal/store/grpcstore/codec.go`, `internal/store/grpcstore/codec_test.go`
- Modify: `pkg/storetest/connections.go`, `pkg/storetest/users.go`

**Interfaces:**
- Produces:

```go
// internal/store/types.go
const (
	ScriptLogin          = "login"
	ScriptGetUser        = "get_user"
	ScriptCreate         = "create"
	ScriptVerify         = "verify"
	ScriptChangePassword = "change_password"
	ScriptDelete         = "delete"
	ScriptChangeEmail    = "change_email"
)

// ScriptNames lists every custom database script name Auth0 defines.
var ScriptNames = []string{ScriptLogin, ScriptGetUser, ScriptCreate, ScriptVerify,
	ScriptChangePassword, ScriptDelete, ScriptChangeEmail}

const (
	RootAttributesOnEachLogin  = "on_each_login" // default (empty means this)
	RootAttributesOnFirstLogin = "on_first_login"
)

type Connection struct {
	// … existing fields …

	// EnabledDatabaseCustomization makes the connection use CustomScripts
	// (Auth0's custom database). ImportMode copies users into zeroauthy on
	// their first successful login.
	EnabledDatabaseCustomization bool
	ImportMode                   bool
	CustomScripts                map[string]string // ScriptNames → JS source
	// ConfigurationSealed is the envelope-sealed JSON object of the
	// connection's configuration settings (keys.SealConnectionConfig).
	ConfigurationSealed   []byte
	SetUserRootAttributes string
}

type User struct {
	// … existing fields …
	// AppMetadata is free-form JSON that users cannot edit.
	AppMetadata map[string]any
}
```

- [ ] **Step 1: Write failing storetest cases.**
  - In `pkg/storetest/connections.go`, extend `newConnection` so the CRUD case covers the new fields:

```go
		EnabledDatabaseCustomization: true,
		ImportMode:                   true,
		CustomScripts:                map[string]string{store.ScriptLogin: "function login(e, p, cb) { cb(null, null) }"},
		ConfigurationSealed:          []byte{0x01, 0x02, 0xff},
		SetUserRootAttributes:        store.RootAttributesOnFirstLogin,
```

  - Add a case for a plain connection, so a nil map and nil bytes round-trip as nil:

```go
	t.Run("PlainConnectionHasNoScripts", func(t *testing.T) {
		s := open(t, newStore)
		c := newConnection("ten_a", "con1", "Database")
		c.EnabledDatabaseCustomization, c.ImportMode = false, false
		c.CustomScripts, c.ConfigurationSealed, c.SetUserRootAttributes = nil, nil, ""
		mustNoErr(t, s.Connections().Create(ctx, c))
		got, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustNoErr(t, err)
		mustEqual(t, got, c)
	})
```

  - Add a copy test: mutating `got.CustomScripts["login"]` and `got.ConfigurationSealed[0]` after a `Get` must not change a second `Get`. Model it on the existing copy tests in `pkg/storetest/users.go`.
  - In `pkg/storetest/users.go`, set `AppMetadata: map[string]any{"plan": "gold", "n": float64(3)}` in `newUser`. The existing CRUD and copy cases then cover it. Add `u.AppMetadata = nil` to one case to pin nil round-tripping.

- [ ] **Step 2: Run them and watch them fail.**

Run: `go test ./internal/store/memory/... ./internal/store/sqlstore/... ./internal/store/grpcstore/...`
Expected: compile errors for the unknown fields.

- [ ] **Step 3: Add the type fields and constants shown under Interfaces to `internal/store/types.go`.**

- [ ] **Step 4: Memory driver.** In `internal/store/memory/clone.go`, `cloneConnection` copies `CustomScripts` with `maps.Clone` and `ConfigurationSealed` with `bytes.Clone`. Both keep nil as nil. `cloneUser` deep-copies `AppMetadata` the same way it copies `UserMetadata`, through `cloneJSON`.

- [ ] **Step 5: Migrations.** These are new files. Columns get defaults, so existing rows read as plain connections and nil metadata.

`sqlite/0002_custom_db.sql`:

```sql
ALTER TABLE connections ADD COLUMN enabled_database_customization BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE connections ADD COLUMN import_mode BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE connections ADD COLUMN custom_scripts TEXT NOT NULL DEFAULT 'null';
ALTER TABLE connections ADD COLUMN configuration_sealed BLOB NULL;
ALTER TABLE connections ADD COLUMN set_user_root_attributes TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN app_metadata TEXT NOT NULL DEFAULT 'null';
```

`postgres/0002_custom_db.sql`: the same, with `BYTEA NULL` for `configuration_sealed`.

`mysql/0002_custom_db.sql` (MySQL 8.0.13+ accepts expression defaults on TEXT columns; the floor is 8.0.17):

```sql
ALTER TABLE connections
  ADD COLUMN enabled_database_customization BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN import_mode BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN custom_scripts LONGTEXT NOT NULL DEFAULT ('null'),
  ADD COLUMN configuration_sealed LONGBLOB NULL,
  ADD COLUMN set_user_root_attributes VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN app_metadata LONGTEXT NOT NULL DEFAULT ('null');
```

Check how `internal/store/sqlstore/migrate.go` discovers files (`//go:embed migrations/*/*.sql`, ordered by numeric prefix) and splits statements. If MySQL migrations are applied statement by statement, the two statements above are already separate. `LatestVersion` becomes 2 with no code change. Add a `migrate_test.go` case asserting `LatestVersion() == 2`.

- [ ] **Step 6: sqlstore reads and writes.** Extend `connectionCols`, `scanConnection` and `connectionArgs` in `internal/store/sqlstore/connections.go`, and the `UPDATE` statement:

```go
const connectionCols = `tenant_id, id, name, strategy, enabled_clients, disable_signup, requires_username,
 password_min_length, password_character_classes, created_at,
 enabled_database_customization, import_mode, custom_scripts, configuration_sealed, set_user_root_attributes`
```

```go
	var scripts string
	var sealed []byte
	if err := row.Scan(&c.TenantID, &c.ID, &c.Name, &c.Strategy, &enabled, &c.DisableSignup, &c.RequiresUsername,
		&c.PasswordPolicy.MinLength, &c.PasswordPolicy.RequireCharacterClasses, &created,
		&c.EnabledDatabaseCustomization, &c.ImportMode, &scripts, &sealed, &c.SetUserRootAttributes); err != nil {
		return nil, err
	}
	if err := fromJSON(scripts, &c.CustomScripts); err != nil {
		return nil, err
	}
	if len(sealed) > 0 {
		c.ConfigurationSealed = sealed
	}
```

`connectionArgs` appends `c.EnabledDatabaseCustomization, c.ImportMode, scriptsJSON, sealedArg, c.SetUserRootAttributes`. `sealedArg` is `nil` (SQL NULL) when `len(c.ConfigurationSealed) == 0`. The INSERT gets 15 placeholders. The UPDATE sets the five new columns too. Because the WHERE arguments come last, rebuild its argument slice explicitly rather than with `args[2:]`.

Do the same for `app_metadata` in `internal/store/sqlstore/users.go`, encoded with `toJSON` and `fromJSON` like `user_metadata`.

- [ ] **Step 7: Protocol and codec.** In `proto/store/v1/store.proto`:

```proto
message Connection {
  string tenant_id = 1; string id = 2; string name = 3; string strategy = 4;
  StringList enabled_clients = 5; bool disable_signup = 6; bool requires_username = 7;
  PasswordPolicy password_policy = 8; google.protobuf.Timestamp created_at = 9;
  bool enabled_database_customization = 10; bool import_mode = 11;
  StringMap custom_scripts = 12;            // absent = nil map
  optional bytes configuration_sealed = 13; // absent = nil
  string set_user_root_attributes = 14;
}
```

Add `optional bytes app_metadata_json = 18; // absent = nil map` to `User`. Run `go generate ./...`. In `codec.go`:
- use the existing `stringMap…PB` helpers, in the style used for tenant `custom_text`;
- copy `optional bytes` only when non-nil;
- encode `AppMetadata` exactly as `UserMetadata` is encoded.

Add codec round-trip cases in `codec_test.go`: nil versus empty map, and nil versus empty bytes. Empty bytes may normalize to nil; assert that and document it in a comment.

- [ ] **Step 8: Run all drivers.**

Run: `go test -race ./internal/store/... ./pkg/... && ./scripts/test-sql.sh ./internal/store/sqlstore/...`
Expected: PASS on memory, sqlite, the gRPC plugin, postgres 17 and mysql 8.4.

- [ ] **Step 9: Commit.**

```bash
git add internal/store pkg/storetest proto
git commit -m "feat(store): custom database connection options and app_metadata; migration 0002"
```

---

### Task 2: Sealed configuration, `custom_db` config, seed options

**Files:**
- Create: `internal/keys/config.go`, `internal/keys/config_test.go`
- Modify: `internal/config/config.go`, `internal/config/config_test.go`
- Modify: `internal/seed/seed.go`, `internal/seed/validate.go`, `internal/seed/apply.go`, `internal/seed/seed_test.go`
- Modify: `internal/app/app.go` (export `MasterKey`), `cmd/zeroauthy/seed.go`

**Interfaces:**
- Consumes: the `store.Connection` fields from Task 1.
- Produces:

```go
// internal/keys/config.go
func SealConnectionConfig(w Wrapper, tenantID, connectionID string, cfg map[string]string) ([]byte, error) // nil, nil for an empty map
func OpenConnectionConfig(w Wrapper, tenantID, connectionID string, sealed []byte) (map[string]string, error) // empty map for nil
// internal/config
type CustomDB struct {
	Node        string        `koanf:"node"`          // default "node"
	ModulesDir  string        `koanf:"modules_dir"`   // optional absolute path
	MaxMemoryMB int           `koanf:"max_memory_mb"` // default 256
	IdleTimeout time.Duration `koanf:"idle_timeout"`  // default 5m
}
// Config gains: CustomDB CustomDB `koanf:"custom_db"`
// internal/seed
func Apply(ctx context.Context, st store.Store, f *File, now func() time.Time, w keys.Wrapper) error
// internal/app
func MasterKey(cfg *config.Config, log *slog.Logger) ([]byte, error) // was loadMasterKey
```

- [ ] **Step 1: Failing tests for sealing.** `internal/keys/config_test.go`:
  - A round trip returns the same map.
  - Opening with another tenant or connection ID fails (AAD binding).
  - An empty map seals to nil, and nil opens to an empty map.
  - The sealed bytes do not contain the plaintext value (`bytes.Contains(sealed, []byte("s3cret"))` is false).

- [ ] **Step 2: Implement `internal/keys/config.go`.** Wrap the existing `seal` and `unseal` with `aad := []byte("connection-config|" + tenantID + "|" + connectionID)` and the JSON of the map. Error messages never include values.

- [ ] **Step 3: Failing config tests** in `internal/config/config_test.go`:
  - Defaults are `Node == "node"`, `MaxMemoryMB == 256` and `IdleTimeout == 5*time.Minute`.
  - `ZEROAUTHY_CUSTOM_DB__IDLE_TIMEOUT=30s` is applied.
  - A relative `modules_dir` is rejected with `custom_db.modules_dir must be an absolute path`.
  - `max_memory_mb` below 32 is rejected.

- [ ] **Step 4: Implement the config section, defaults and validation.**

- [ ] **Step 5: Failing seed tests** (`internal/seed/seed_test.go`). The YAML uses Auth0's option names at the connection level:

```yaml
connections:
  - name: legacy
    enabled_clients: [app]
    enabledDatabaseCustomization: true
    import_mode: true
    set_user_root_attributes: on_first_login
    customScripts:
      login: |
        function login(email, password, callback) { callback(null, null); }
      get_user: |
        function getUser(email, callback) { callback(null, null); }
    configuration:
      API_URL: https://legacy.example
      API_TOKEN: s3cret
```

The cases are:
- (a) After applying, the stored connection has the scripts, the flags and a non-nil `ConfigurationSealed` that `keys.OpenConnectionConfig` opens to the map.
- (b) Re-applying with a changed `API_TOKEN` re-seals; opening returns the new value.
- (c) Validation errors are aggregated like the existing ones:
  - an unknown script key (`fail("connection %q: unknown customScripts key %q", …)`);
  - a script over 102400 bytes;
  - `customScripts` or `configuration` without `enabledDatabaseCustomization`;
  - `enabledDatabaseCustomization` without a `login` script;
  - a bad `set_user_root_attributes` value;
  - a configuration key that is not `[A-Za-z0-9_]{1,128}`, or a value over 4096 bytes, or more than 64 keys.
- (d) Seeded `users` on a customized connection are allowed only with `import_mode: true`. Legacy-mode users live in the legacy store (`fail("users[%d]: connection %q is a legacy custom database; users live in the legacy store", …)`).

- [ ] **Step 6: Implement it.**
  - Add the fields to `seed.Connection`:

```go
	EnabledDatabaseCustomization bool              `yaml:"enabledDatabaseCustomization"`
	ImportMode                   bool              `yaml:"import_mode"`
	CustomScripts                map[string]string `yaml:"customScripts"`
	Configuration                map[string]string `yaml:"configuration"`
	SetUserRootAttributes        string            `yaml:"set_user_root_attributes"`
```

  - `applyConnection` copies them. It seals `Configuration` with `keys.SealConnectionConfig(w, tenantID, c.ID, in.Configuration)` after the ID is known: generated for new connections, existing for updates. Thread `w keys.Wrapper` through `Apply`.
  - Rename `loadMasterKey` to the exported `MasterKey` in `internal/app/app.go` and pass a `keys.NewLocalWrapper(masterKey)` to `seed.Apply`.
  - In `cmd/zeroauthy/seed.go`, load the master key with `app.MasterKey(cfg, slog.Default())` before opening the store, and pass the wrapper.

- [ ] **Step 7: Run the tests.**

Run: `go test -race ./internal/keys/... ./internal/config/... ./internal/seed/... ./internal/app/... ./cmd/...`
Expected: PASS.

- [ ] **Step 8: Commit.**

```bash
git add internal/keys internal/config internal/seed internal/app cmd
git commit -m "feat(seed): Auth0 custom database options; sealed connection configuration; custom_db config"
```

---

### Task 3: The Node.js runner

**Files:**
- Create: `internal/customdb/runner.mjs`
- Create: `internal/customdb/errors.go`, `internal/customdb/node.go`, `internal/customdb/fake.go`
- Create: `internal/customdb/node_test.go`, `internal/customdb/testmain_test.go`
- Modify: `.github/workflows/ci.yml` (setup-node 22 in the `test` job; `ZA_REQUIRE_NODE: "1"`)

**Interfaces:**
- Consumes: `config.CustomDB` (Task 2).
- Produces:

```go
package customdb

// Request is one script execution.
type Request struct {
	TenantID     string
	ConnectionID string            // vm context key, with ScriptHash
	Script       string            // one of store.ScriptNames
	Source       string
	Config       map[string]string // plaintext configuration
	Args         []any             // JSON-encodable, without the callback
}

// Executor runs custom database scripts. Result is the JSON value passed
// to the callback as its second argument ("null" when absent).
type Executor interface {
	Execute(ctx context.Context, req Request) (json.RawMessage, error)
	Close() error
}

// ScriptError is an error the script passed to its callback (or threw).
type ScriptError struct {
	Kind    string // KindWrongCredentials | KindValidation | KindUnauthorized | KindError
	Code    string // ValidationError code; WrongUsernameOrPasswordError identifier
	Message string // the script's message; safe to log, shown to users only for KindUnauthorized
}
func (e *ScriptError) Error() string

const (
	KindWrongCredentials = "wrong_credentials"
	KindValidation       = "validation"
	KindUnauthorized     = "unauthorized"
	KindError            = "error"
)

var (
	ErrTimeout     = errors.New("customdb: script timed out")
	ErrUnavailable = errors.New("customdb: script runtime unavailable") // node missing, too old, crashed
	ErrNoScript    = errors.New("customdb: script not configured")
)

const MaxDuration = 20 * time.Second

func NewNodeRunner(cfg config.CustomDB, log *slog.Logger) (*NodeRunner, error) // writes runner.mjs to a 0700 temp dir; starts nothing
func (r *NodeRunner) Execute(ctx context.Context, req Request) (json.RawMessage, error)
func (r *NodeRunner) Close() error // kills processes, removes the temp dir

// FuncExecutor is an Executor for tests: Funcs[script](args) returns the
// callback value or an error (a *ScriptError, ErrTimeout, …).
type FuncExecutor struct {
	Funcs map[string]func(args []any) (any, error)
	Calls []Request // recorded under a mutex; read with Requests()
}
```

**Wire protocol:**
- **Request**, one line on stdin:

```json
{"id":1,"conn":"<connection id>","hash":"<sha256 hex of source>","name":"login","source":"…","config":{…},"args":[…]}
```

  `source` and `config` are sent on every request; the runner caches compiled scripts by `conn+hash` and contexts by `conn+sha256(config)`.
- **Response**, one line on stdout: `{"id":1,"ok":true,"result":<json>}` or `{"id":1,"ok":false,"error":{"kind":"…","code":"…","message":"…"}}`.
- **Logs:** script `console.*` output goes to stderr as JSON lines `{"conn":"…","level":"info","msg":"…"}`, with each `msg` truncated to 2048 bytes.

- [ ] **Step 1: Test helpers.** In `testmain_test.go`, `requireNode(t)` looks up `node` with `exec.LookPath` and checks the version (see Step 4).
  - When Node is missing or too old, the test skips with the reason.
  - When `ZA_REQUIRE_NODE=1` is set, a missing or old Node fails the test instead. CI sets it.
  - Also add `newRunner(t, cfg)`, which builds a `NodeRunner` and closes it in `t.Cleanup`.

- [ ] **Step 2: Failing runner tests** in `node_test.go`. Every script below is original test code.

```go
func TestRunnerLoginProfile(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	src := `function login(email, password, callback) {
	  if (password !== "pw") return callback(new WrongUsernameOrPasswordError(email, "bad password"));
	  callback(null, { user_id: "42", email: email, app_metadata: { k: configuration.K } });
	}`
	res, err := r.Execute(ctx, Request{TenantID: "t1", ConnectionID: "c1", Script: "login", Source: src,
		Config: map[string]string{"K": "v"}, Args: []any{"a@x.test", "pw"}})
	// assert JSON {"user_id":"42","email":"a@x.test","app_metadata":{"k":"v"}}
	_, err = r.Execute(ctx, /* same with "nope" */)
	// assert errors.As(err, &se) && se.Kind == KindWrongCredentials && se.Code == "a@x.test"
}
```

The full list of tests:
- `TestRunnerLoginProfile` (above).
- `TestRunnerErrorKinds`:
  - `ValidationError("user_exists", "m")` gives `KindValidation` with code `user_exists`.
  - `UnauthorizedError("blocked here")` gives `KindUnauthorized` with that message.
  - `new Error("db down")` gives `KindError`.
  - A thrown exception gives `KindError`.
  - A rejected promise from an `async function` gives `KindError`.
- `TestRunnerFunctionForms`:
  - an `async function login(…)` that calls back;
  - a get_user script declared as `function getByEmail(email, callback)`, evaluated as an expression;
  - a script with a leading comment and a trailing semicolon.
- `TestRunnerGlobalPersists`: `global.n = (global.n || 0) + 1` returns 1 and then 2 on the same connection; another connection starts at 1.
- `TestRunnerConfigIsolation`: two connections in one tenant see their own `configuration`; `configuration` is frozen, and assigning to it does not change a later call.
- `TestRunnerCallbackOnce`: a script that calls back twice gets the first value; a script that calls back and then throws gets the callback value.
- `TestRunnerTimeoutKillsTenantProcess`:
  - The test uses a `MaxDuration` override field on `NodeRunner` (`r.maxDuration = 300 * time.Millisecond`).
  - `function login(e,p,cb){ while(true){} }` returns `ErrTimeout`.
  - The next call on the same tenant succeeds in a fresh process.
  - A call for tenant `t2` started in parallel succeeds.
- `TestRunnerRequireAllowlist`:
  - `require("crypto").createHash("sha256")` works;
  - `require("child_process")` and `require("node:worker_threads")` give `KindError`;
  - `require("left-pad")` without `modules_dir` gives `KindError`.
- `TestRunnerModulesDir`: write `<tmp>/node_modules/zz-test/index.js` (`module.exports = () => 7`), set `ModulesDir: tmp`, and `require("zz-test")()` returns 7.
- `TestRunnerFetch`: an `httptest.Server` returns `{"id":"9"}`, and a login script fetches it from `configuration.URL`. This proves network access works under `--permission`.
- `TestRunnerConsoleLogged`: `console.log("hello", 1)` appears in a captured `slog` handler with attributes `tenant=t1` and `connection=c1`. The request's password argument never appears in any log record.

- [ ] **Step 3: The environment isolation tests** (the user's requirement), in `TestRunnerCannotReadHostEnvironment`:

```go
	t.Setenv("ZA_SENTINEL_SECRET", "sentinel-7f3a")
	r := newRunner(t, config.CustomDB{})
	src := `function login(e, p, callback) {
	  const out = { env: JSON.stringify(process.env) };
	  const fs = require("fs");
	  for (const f of ["/proc/self/environ", "/proc/" + process.ppid + "/environ", "/etc/hostname"]) {
	    try { out[f] = fs.readFileSync(f, "utf8"); } catch (e) { out[f] = "denied:" + e.code; }
	  }
	  try { require("child_process"); out.cp = "loaded"; } catch (e) { out.cp = "denied"; }
	  try { process.binding("spawn_sync"); out.binding = "loaded"; } catch (e) { out.binding = "denied"; }
	  callback(null, { user_id: "1", app_metadata: out });
	}`
```

Assert:
- The raw result does not contain `sentinel-7f3a` (`!bytes.Contains`).
- `env` is `{}`.
- The two `/proc` entries and `/etc/hostname` are each either `denied:ERR_ACCESS_DENIED` or empty. Never non-empty content.
- `cp` and `binding` are `denied`.

A second test, `TestRunnerEscapedContextStillIsolated`, runs the same checks after escaping the vm with `this.constructor.constructor("return process")()`. This proves that the process boundary, not `vm`, enforces the guarantee.

- [ ] **Step 4: Run them and watch them fail** (the package does not exist yet).

Run: `ZA_REQUIRE_NODE=1 go test ./internal/customdb/...`
Expected: FAIL (build errors).

- [ ] **Step 5: Implement `runner.mjs`.** It is ESM and uses only `node:` built-ins. Key parts:

```js
// zeroauthy custom database script runner. One process serves one tenant.
// Protocol: one JSON request per stdin line, one JSON response per stdout line.
import vm from 'node:vm';
import readline from 'node:readline';
import { createRequire, builtinModules } from 'node:module';
import { createHash } from 'node:crypto';
import path from 'node:path';

const modulesDir = process.argv[2] || '';
const denied = new Set(['child_process', 'cluster', 'worker_threads', 'inspector', 'vm', 'v8', 'module', 'repl', 'wasi', 'trace_events']);
const hostRequire = createRequire(modulesDir ? path.join(modulesDir, 'noop.js') : import.meta.url);

function sandboxRequire(name) {
  const bare = String(name).replace(/^node:/, '');
  if (denied.has(bare)) throw new Error(`module "${bare}" is not available to custom database scripts`);
  if (builtinModules.includes(bare)) return hostRequire('node:' + bare);
  if (!modulesDir) throw new Error(`module "${bare}" is not installed (set custom_db.modules_dir)`);
  return hostRequire(name);
}

class WrongUsernameOrPasswordError extends Error {
  constructor(identifier, message) { super(message || 'Wrong email or password.'); this.name = 'WrongUsernameOrPasswordError'; this.identifier = identifier ?? null; }
}
class ValidationError extends Error {
  constructor(code, message) { super(message || code); this.name = 'ValidationError'; this.code = code; }
}
class UnauthorizedError extends Error {
  constructor(message) { super(message); this.name = 'UnauthorizedError'; }
}

const contexts = new Map(); // conn + config hash → vm context
const compiled = new Map(); // conn + config hash + source hash → function

function contextFor(conn, config) {
  const key = conn + ':' + createHash('sha256').update(JSON.stringify(config ?? {})).digest('hex');
  let ctx = contexts.get(key);
  if (!ctx) {
    const logger = (level) => (...a) => log(conn, level, a);
    ctx = vm.createContext({
      configuration: Object.freeze({ ...(config ?? {}) }),
      global: {},
      WrongUsernameOrPasswordError, ValidationError, UnauthorizedError,
      require: sandboxRequire,
      console: { log: logger('info'), info: logger('info'), warn: logger('warn'), error: logger('error'), debug: logger('debug') },
      setTimeout, clearTimeout, setInterval, clearInterval, setImmediate, clearImmediate,
      Buffer, URL, URLSearchParams, TextEncoder, TextDecoder, AbortController,
      fetch, Headers, Request, Response, crypto: globalThis.crypto,
    }, { name: 'customdb:' + conn });
    contexts.set(key, ctx);
  }
  return { key, ctx };
}

const aliases = {
  login: ['login'], get_user: ['getUser', 'getByEmail', 'get_user'], create: ['create'],
  verify: ['verify'], change_password: ['changePassword', 'change_password'],
  delete: ['remove', 'deleteUser', 'del'], change_email: ['changeEmail', 'change_email'],
};

function compile(req) {
  const { key, ctx } = contextFor(req.conn, req.config);
  const ckey = key + ':' + req.hash;
  let fn = compiled.get(ckey);
  if (fn) return fn;
  const filename = `${req.name}.js`;
  try {
    // Auth0 scripts are one function; read as an expression it evaluates to that function.
    fn = new vm.Script('(' + req.source.trim().replace(/;\s*$/, '') + '\n)', { filename }).runInContext(ctx, { timeout: 1000 });
  } catch {
    new vm.Script(req.source, { filename }).runInContext(ctx, { timeout: 1000 });
    fn = aliases[req.name].map((n) => ctx[n]).find((f) => typeof f === 'function');
  }
  if (typeof fn !== 'function') throw new Error(`the ${req.name} script does not define a function`);
  compiled.set(ckey, fn);
  return fn;
}

function toWireError(err) {
  const name = err && err.name;
  if (name === 'WrongUsernameOrPasswordError') return { kind: 'wrong_credentials', code: err.identifier == null ? '' : String(err.identifier), message: String(err.message ?? '') };
  if (name === 'ValidationError') return { kind: 'validation', code: String(err.code ?? ''), message: String(err.message ?? '') };
  if (name === 'UnauthorizedError') return { kind: 'unauthorized', code: '', message: String(err.message ?? '') };
  return { kind: 'error', code: '', message: String((err && err.message) ?? err ?? 'error').slice(0, 1024) };
}

function respond(obj) { process.stdout.write(JSON.stringify(obj) + '\n'); }

function run(req) {
  let done = false;
  const finish = (err, value) => {
    if (done) { log(req.conn, 'warn', [`${req.name}: callback called more than once; ignored`]); return; }
    done = true;
    if (err) respond({ id: req.id, ok: false, error: toWireError(err) });
    else respond({ id: req.id, ok: true, result: value === undefined ? null : value });
  };
  try {
    const fn = compile(req);
    const out = fn(...req.args, finish);
    if (out && typeof out.then === 'function') out.then(undefined, (e) => finish(e));
  } catch (e) { finish(e); }
}

function log(conn, level, args) {
  const msg = args.map((a) => (typeof a === 'string' ? a : safeJSON(a))).join(' ').slice(0, 2048);
  process.stderr.write(JSON.stringify({ conn, level, msg }) + '\n');
}
function safeJSON(v) { try { return JSON.stringify(v); } catch { return String(v); } }

process.on('uncaughtException', (e) => log('', 'error', ['uncaught: ' + (e && e.message)]));
process.on('unhandledRejection', (e) => log('', 'error', ['unhandled rejection: ' + (e && e.message)]));
readline.createInterface({ input: process.stdin }).on('line', (line) => {
  let req;
  try { req = JSON.parse(line); } catch { return; }
  run(req);
}).on('close', () => process.exit(0));
```

Notes:
- `vm`'s `timeout` covers only synchronous compilation; the host's 20 s deadline covers everything else.
- An uncaught exception from a script's timer cannot be traced back to its request. That request then times out, which is the documented consequence of not calling back.

- [ ] **Step 6: Implement `node.go`.**
  - **`NodeRunner` fields:** `cfg`, `log`, `dir` (from `os.MkdirTemp("", "zeroauthy-customdb-")`, with `runner.mjs` written at 0600 and the directory at 0700), `maxDuration` (default `MaxDuration`), `mu`, `procs map[string]*proc`, and the probe results `probeOnce sync.Once`, `probeErr`, `allowNet bool`.
  - **`probe()`:**
    - Run `node --version` with `Env: []string{}`.
    - Parse `vMAJOR.MINOR.PATCH`. Require major > 22, or major == 22 with minor ≥ 13. Otherwise return `ErrUnavailable` wrapped with `"node %s is too old; custom database scripts need 22.13 or later"`.
    - Then run `node --permission --allow-net -e 0`; exit status 0 sets `allowNet`.
  - **`start(tenantID)`** builds the command:

```go
	args := []string{"--permission", "--allow-fs-read=" + r.dir}
	if r.cfg.ModulesDir != "" {
		args = append(args, "--allow-fs-read="+r.cfg.ModulesDir)
	}
	if r.allowNet {
		args = append(args, "--allow-net", "--disable-warning=ExperimentalWarning")
	}
	args = append(args, fmt.Sprintf("--max-old-space-size=%d", r.cfg.MaxMemoryMB), filepath.Join(r.dir, "runner.mjs"), r.cfg.ModulesDir)
	cmd := exec.Command(r.cfg.Node, args...)
	cmd.Env = []string{} // never inherit the host environment (D-0022)
	cmd.Dir = r.dir
```

  - **`proc`:** holds stdin (with a write mutex), `pending map[int64]chan response`, `nextID`, `done chan struct{}`, `lastUsed`, and a semaphore of 64 in-flight requests.
    - **stdout goroutine:** decodes response lines and delivers them by id. Unknown ids are dropped. Lines over 1 MiB fail every pending request with `ErrUnavailable` and kill the process (`bufio.Scanner` with a 1 MiB buffer).
    - **stderr goroutine:** decodes log lines and calls `r.log.Log(ctx, level, "custom database script", "tenant", tenantID, "connection", line.Conn, "msg", line.Msg)`. Non-JSON lines are logged at warn, truncated to 2048 bytes.
    - **On exit:** every pending request fails with `ErrUnavailable`, and the `procs` entry is removed so the next call starts a fresh process.
  - **`Execute`:**
    - Validate `req.Script ∈ store.ScriptNames`. If `req.Source == ""`, return `ErrNoScript`.
    - Get or start the tenant's process and write the request line.
    - Wait for the first of: the response, `ctx.Done()` or `time.After(r.maxDuration)`.
      - **Timeout:** kill the process (`cmd.Process.Kill`) and return `ErrTimeout`.
      - **Context cancelled:** return `ctx.Err()` without killing; the late response is dropped.
    - **Mapping the response:** `ok` returns `result`; otherwise return `&ScriptError{…}`, with `kind` validated against the four constants (unknown kinds become `KindError`).
  - **Idle reaper:** `NewNodeRunner` starts a goroutine with a ticker at `IdleTimeout/2` that closes the stdin of processes idle past `IdleTimeout` with no pending requests. The runner then exits on stdin close.
  - **`Close`:** kills every process, waits for them, and runs `os.RemoveAll(r.dir)`.

- [ ] **Step 7: Implement `errors.go` and `fake.go`** as shown under Interfaces. `FuncExecutor.Execute` returns `ErrNoScript` when `Funcs[req.Script]` is nil, and `json.Marshal`s the returned value.

- [ ] **Step 8: Run the tests.**

Run: `ZA_REQUIRE_NODE=1 go test -race -count=1 ./internal/customdb/...`
Expected: PASS. Test locally on Node 26 (this machine), and in CI on Node 22.

- [ ] **Step 9: CI.** In `.github/workflows/ci.yml`, add to the `test` job, before `go test`:

```yaml
      - uses: actions/setup-node@v4
        with:
          node-version: 22
```

Then set `env: { ZA_REQUIRE_NODE: "1" }` on the `go test -race ./...` step.

- [ ] **Step 10: Commit.**

```bash
git add internal/customdb .github/workflows/ci.yml
git commit -m "feat(customdb): Node.js script runner with empty environment and permission sandbox"
```

---

### Task 4: Legacy mode (scripts are the source of truth)

**Files:**
- Create: `internal/customdb/client.go`, `internal/customdb/profile.go`, `internal/customdb/client_test.go`
- Create: `internal/identity/custom.go`, `internal/identity/custom_test.go`
- Modify: `internal/identity/database.go`, `internal/identity/identity.go` (new errors)
- Modify: `internal/server/server.go` (`Deps.Scripts`; one shared `identity.Database`), `internal/app/app.go` (build `NodeRunner` and `customdb.Client`; close on shutdown)
- Modify: `internal/login/login.go`, `internal/login/reset.go`, `internal/oauth/grant_password.go`, `internal/dbconn/signup.go`, `internal/dbconn/change_password.go`
- Modify tests: `internal/login/login_test.go`, `internal/login/reset_test.go`, `internal/oauth/grant_password_test.go`, `internal/dbconn/*_test.go`
- Modify: `docs/compat/decisions.md` (D-0023, D-0024)

**Interfaces:**
- Consumes: `Executor`, `ScriptError`, `ErrNoScript` (Task 3); `keys.OpenConnectionConfig` (Task 2); the Task 1 fields.
- Produces:

```go
// internal/customdb/client.go
type Client struct {
	Exec    Executor
	Wrapper keys.Wrapper
}
type Profile struct {
	UserID                                string // as returned (no "auth0|")
	Email, Username                       string // normalized lowercase
	EmailVerified                         bool
	Name, Nickname, GivenName, FamilyName string
	Picture                               string
	UserMetadata, AppMetadata             map[string]any
}
// Login: profile, or *ScriptError, ErrTimeout, ErrUnavailable, ErrNoScript, ErrBadProfile.
func (c *Client) Login(ctx context.Context, conn *store.Connection, identifier, password string) (*Profile, error)
// GetUser returns nil, nil when the script reports no user.
func (c *Client) GetUser(ctx context.Context, conn *store.Connection, identifier string) (*Profile, error)
type CreateUser struct {
	Tenant, ClientID, Connection, Email, Password, Username string
	UserMetadata, AppMetadata                               map[string]any
}
func (c *Client) Create(ctx context.Context, conn *store.Connection, u CreateUser) error
// ChangePassword returns false when the script reports the password was not changed.
func (c *Client) ChangePassword(ctx context.Context, conn *store.Connection, identifier, newPassword string) (bool, error)
var ErrBadProfile = errors.New("customdb: script returned an invalid profile")

// internal/identity
var (
	ErrScript              = errors.New("identity: custom database script failed") // wraps the cause
	ErrPasswordNotChanged  = errors.New("identity: the legacy store did not change the password")
)
// UnauthorizedError carries a script's UnauthorizedError message, which is shown to the user.
type UnauthorizedError struct{ Message string }
func (e *UnauthorizedError) Error() string
func IsCustom(conn *store.Connection) bool // conn.EnabledDatabaseCustomization
func IsLegacy(conn *store.Connection) bool // IsCustom && !conn.ImportMode
func (d *Database) FindForReset(ctx context.Context, conn *store.Connection, email string) (*store.User, error) // store.ErrNotFound when unknown
func (d *Database) ChangeLegacyPassword(ctx context.Context, conn *store.Connection, user *store.User, newPassword string) error
// identity.Database gains: Scripts *customdb.Client (nil: customized connections fail with ErrScript)
// SignupInput gains: ClientID string
```

**Behavior** (Auth0 docs; D-0023 and D-0024 record what the docs leave open):
- **Legacy `Login`:**
  1. Bound the inputs exactly as today (`maxPasswordBytes`, `maxLoginLength`).
  2. Run `Scripts.Login(identifier as typed, trimmed only, password)`.
  3. `KindWrongCredentials` maps to `ErrInvalidCredentials`. `KindUnauthorized` maps to `*UnauthorizedError`. Every other failure maps to `fmt.Errorf("%w: %w", ErrScript, cause)`.
  4. On success, `upsertProfile(conn, profile, onLogin=true)`:
     - It looks up `auth0|<id>` with `Users().Get`.
     - **Missing:** create the user with identity `{conn.Name, "auth0", id, PasswordHash: ""}`, both metadata maps from the profile, and the same name and nickname defaults as `Signup`.
     - **Present:** the user must have an identity on `conn.Name`; otherwise fail with `ErrScript` and log a collision (D-0024). Email, username and email_verified always update from the profile. Name, nickname, given and family name, and picture update only when `SetUserRootAttributes` is not `on_first_login`. Metadata is never overwritten after creation (D-0024).
     - A `store.ErrConflict` from `Create` or `Update` (another user on the connection holds the email or username) becomes `ErrScript` with a logged collision.
  5. A blocked local user gets `ErrUserBlocked`, after the script has accepted the password.
- **Legacy `Signup`:**
  1. Run the same input validation as today: email, username rules, profile fields and the connection's password policy.
  2. `GetUser(email)`, then `GetUser(username)` when one is required; a profile means `ErrUserExists`.
  3. `Create(CreateUser{Tenant: <tenant name from Store.Tenants().Get>, ClientID, Connection: conn.Name, Email, Password, Username, UserMetadata})`. A `KindValidation` error with code `user_exists` means `ErrUserExists`. Any other `KindValidation` becomes `&PolicyError{Reason: message}`. Anything else is `ErrScript`.
  4. `Login(email, password)` confirms the account (Auth0 does the same). A failure here is `ErrScript`.
  5. `upsertProfile` with the confirmed profile; the user is returned, so `_id` is `profile.user_id`.
- **Legacy `FindForReset(email)`:**
  - Run `GetUser(email)`; nil means `store.ErrNotFound`.
  - Otherwise `upsertProfile(onLogin=false)`, which updates email, username and email_verified only, and return the local user (needed to key the ticket).
- **Legacy `ChangeLegacyPassword`:** run `ChangePassword(user.Email, pw)`. `false` maps to `ErrPasswordNotChanged`. `KindUnauthorized` maps to `*UnauthorizedError`. Errors map to `ErrScript`.
- **`Client`:**
  - It opens `conn.ConfigurationSealed` with `keys.OpenConnectionConfig(c.Wrapper, conn.TenantID, conn.ID, …)` for every call; it is cheap, so there is no cache.
  - It sends `Request{TenantID, ConnectionID: conn.ID, Script, Source: conn.CustomScripts[name], Config, Args}`. An empty source returns `ErrNoScript` without calling `Exec`.
- **`decodeProfile`:**
  - Requires a JSON object. `user_id` follows the Global Constraints (an integer JSON number is formatted with `strconv.FormatInt`).
  - The email, when present, is `NormalizeLogin`ed and passes `identity.CheckEmail`; a username, when present, passes `identity.CheckUsername`. At least one of email and username is required.
  - String fields are capped at 300 runes; `picture` must pass the same https check as signup.
  - Metadata must be a JSON object.
  - Any violation is `ErrBadProfile`, with the offending field name only and never the value.

**Handler mapping** (D-0023):

| Surface | `*UnauthorizedError` | `ErrScript` / `ErrNoScript` | `ErrPasswordNotChanged` |
|---|---|---|---|
| Hosted login `/u/login` | 401; re-render login with the script's message (HTML-escaped by `html/template`); no throttle refund | refund throttles; `h.fail` (generic error page, logged) | n/a |
| Password grants | 401 `{"error":"unauthorized","error_description":<message>}`; no refund | refund; 500 `server_error` | n/a |
| `/dbconnections/signup`, `/u/signup` | 401 `unauthorized` + message (API) / re-render with message (hosted) | 500 `server_error` / error page | n/a |
| `/dbconnections/change_password` | same 200 answer, no email (never reveals anything) | same 200 answer, logged | n/a |
| Hosted reset completion | re-render form with message; ticket not spent | error page; ticket not spent | re-render form with a new catalog key `zeroauthy.reset.not-changed`; ticket not spent |

**Reset completion on a legacy connection** (`internal/login/reset.go`):
- After step 4 (user still exists), call `h.Database.ChangeLegacyPassword(ctx, conn, user, pw)` *before* consuming the ticket, so a failed script leaves the link usable.
- Then skip step 5 (hashing) and step 8 (`SetPasswordHash`); steps 6, 7, 9 and 10 run unchanged.

**Wiring changes:**
- `dbconn.Handlers.FindByEmail` becomes a thin wrapper over `h.Database.FindForReset`. The local path keeps today's exact behaviour, including the username-match rule, so both reset entry points use it.
- `server.Deps` gains `Scripts *customdb.Client`, and `server.New` builds one `db := &identity.Database{Store: d.Store, Scripts: d.Scripts}` shared by all three handler sets.
- `app.build` creates the runner with `customdb.NewNodeRunner(cfg.CustomDB, log)`, which starts no process. It sets `Scripts: &customdb.Client{Exec: runner, Wrapper: wrapper}`, and `App.Close` closes the runner.
- At startup the app logs one warning when a tenant has a customized connection and the Node probe fails, but it still starts: other tenants and connections keep working.

- [ ] **Step 1: Failing `customdb.Client` tests** (`client_test.go`, using `FuncExecutor` and a `keys.NewLocalWrapper` over a fixed 32-byte key):
  - `TestLoginDecodesProfile`: a numeric `user_id` of 42 decodes to "42", and the email is lowercased.
  - `TestLoginRejectsBadProfile` is table-driven. Each of these gives `ErrBadProfile`, and the error string does not contain the bad value:
    - no `user_id`, `""`, `1.5`, `"a|b"`, or 201 bytes;
    - email `"not-an-email"`;
    - neither email nor username;
    - metadata as an array;
    - picture `http://…`.
  - `TestGetUserNull`: null gives `nil, nil`.
  - `TestChangePasswordBool`: true, false, and `{"last_password_reset": "…"}` (treated as true).
  - `TestConfigOpenedPerConnection`: the `Config` that reaches `Exec` equals the sealed map.
  - `TestMissingScript`: an empty `CustomScripts["create"]` gives `ErrNoScript`, and `Exec` is not called.

- [ ] **Step 2: Failing identity tests** (`custom_test.go`). Use the memory store plus `FuncExecutor`, with a helper `legacyConn(scripts map[string]func([]any)(any, error))`.
  - `TestLegacyLoginCreatesLocalUser`: the user is created as `auth0|42` with an empty password hash, `AppMetadata` set from the profile, and `FindByLogin` working afterwards.
  - `TestLegacyLoginAlwaysCallsScript`: after a first login, a second login with a *wrong* password still goes to the script, which rejects it, giving `ErrInvalidCredentials`. The local record is never used to authenticate.
  - `TestLegacyLoginSyncsRootAttributes`: the default updates the name on the second login; `on_first_login` keeps the first name; metadata is never overwritten.
  - `TestLegacyLoginRejectsBadProfile` (Review Focus 3): the error is `ErrScript`, and no user is created.
  - `TestLegacyLoginCollision` (Review Focus 4). Each of these gives `ErrScript`, and the existing user is unchanged:
    - (a) `auth0|42` already exists with an identity on another connection;
    - (b) a different local user on the connection already has the profile's email.
  - `TestLegacyLoginBlocked`: a locally blocked user gives `ErrUserBlocked` after the script accepted the password.
  - `TestLegacyLoginUnauthorized`: an `UnauthorizedError` from the script gives `*UnauthorizedError` with the message.
  - `TestLegacySignup`. The executor records the order of its calls.
    - (a) `get_user` returning null, then `create` receiving the `CreateUser` fields (tenant *name*, client_id, connection, email, password, username, user_metadata), then `login` gives a user with id `auth0|<id>`.
    - (b) `get_user` finds the user, giving `ErrUserExists`, and `create` is not called.
    - (c) `ValidationError("user_exists")` from `create` gives `ErrUserExists`.
    - (d) A password-policy violation gives `PolicyError`, and no script is called.
  - `TestLegacyFindForReset`: an unknown user gives `store.ErrNotFound`; a known user gets a local record created with no hash; email is matched exactly, not by username.
  - `TestChangeLegacyPassword`: true gives nil, false gives `ErrPasswordNotChanged`, and an error gives `ErrScript`.

- [ ] **Step 3: Failing handler tests**, extending the existing fixtures:
  - **`login_test.go`:**
    - On a legacy connection, a POST to `/u/login` with good credentials completes (302 to the callback).
    - A wrong password shows the wrong-credentials message with 401.
    - An `UnauthorizedError` renders its message, HTML-escaped. Test with `<b>x</b>`.
    - A failing script gives the error page, with throttles refunded.
  - **`grant_password_test.go`:** a legacy realm login issues tokens; a script `UnauthorizedError` gives 401 `unauthorized` with the message; a script error gives 500 `server_error`.
  - **`signup_test.go` (dbconn):** a legacy signup returns `_id` equal to the legacy id; `get_user` finding the user gives 409 `user_exists`.
  - **`change_password_test.go`:** a legacy user known only to `get_user` gets a reset email; an unknown user gets the identical 200 and no email; a failing `get_user` gets the identical 200, no email, and a log line.
  - **`reset_test.go`:**
    - On a legacy connection, completing a reset calls `change_password` with the user's email and the new password, revokes sessions, and does not store a hash.
    - `change_password` returning `false` re-renders the form, and the same ticket still works afterwards.
    - A script error leaves the ticket unspent.

- [ ] **Step 4: Run them and watch them fail.**

Run: `go test ./internal/customdb/... ./internal/identity/... ./internal/login/... ./internal/oauth/... ./internal/dbconn/...`

- [ ] **Step 5: Implement `client.go` and `profile.go`, then `identity/custom.go`.**
  - `Database.Login` and `Database.Signup` start with:

```go
	if IsCustom(conn) {
		return d.customLogin(ctx, conn, login, password)
	}
```

  - `customLogin` handles legacy mode here. Task 5 adds the import branch. Until then, `ImportMode` connections follow the legacy path, guarded by a `// Task 5` branch that returns `ErrScript` so the gap is never silent.
  - Script failures are logged once, in `identity`, with `tenant`, `connection`, `script`, `kind` and the script's message. Never log passwords or configuration.

- [ ] **Step 6: Map the errors in the handlers** following the table above. Add `i18n.KeyResetNotChanged` = `zeroauthy.reset.not-changed` to `internal/i18n/keys.go` and the English catalog, with original wording: "Your password could not be changed. Try again or contact support."

- [ ] **Step 7: Wire `server.go` and `app.go`.**

- [ ] **Step 8: Write D-0023 and D-0024** in `docs/compat/decisions.md`. Use the existing entry format: context, decision, sources.
  - **D-0023, "Custom database script errors on the wire":** the table above. The docs name the error classes and their log events but not the HTTP responses. Our choices follow RFC 6749 §5.2 for the token endpoint, and use the script's message only for `UnauthorizedError`, which Auth0 documents as the way to send a message to the front end.
  - **D-0024, "Custom database profiles: identity, collisions, sync":**
    - `user_id` is `auth0|<profile.user_id>`.
    - A collision with another connection or another local user fails closed.
    - `set_user_root_attributes` governs the name fields and picture.
    - Email, username and email_verified always follow the legacy store in legacy mode.
    - Metadata is set once, at creation.

- [ ] **Step 9: Run the tests.**

Run: `go test -race ./...`
Expected: PASS.

- [ ] **Step 10: Commit.**

```bash
git add internal docs/compat/decisions.md
git commit -m "feat(identity): legacy custom database connections: login, signup, reset through scripts; D-0023, D-0024"
```

---

### Task 5: Import mode (trickle migration)

**Files:**
- Modify: `internal/identity/custom.go`, `internal/identity/custom_test.go`
- Modify tests: `internal/login/login_test.go`, `internal/login/reset_test.go`, `internal/oauth/grant_password_test.go`, `internal/dbconn/signup_test.go`, `internal/dbconn/change_password_test.go`

**Interfaces:**
- Consumes: everything from Task 4.
- Produces: no new exported names. The behaviour of `Login`, `Signup` and `FindForReset` changes for `ImportMode` connections, and `ChangeLegacyPassword` is never called for them (`IsLegacy` is false).

**Behavior** (Auth0's automatic migration docs):
- **Import `Login`:**
  1. `FindByLogin` on the connection.
  2. **Found, with a password hash on this connection's identity:** take today's local path (`Database.Login` logic, including `dummyHash` timing). The script is never called. A wrong password is `ErrInvalidCredentials`.
  3. **Not found, or found with an empty hash** (created by a reset lookup): run the `login` script.
     - On success, hash the password with `secrets.Hash`.
     - **User missing:** `Users().Create` with identity `{conn.Name, "auth0", id, PasswordHash: hash}` and the profile fields.
     - **User present without a hash:** check it is the same `auth0|<id>`, then `SetPasswordHash`; a different id is a D-0024 collision.
  4. **`store.ErrConflict` on `Create`** (a concurrent first login won the race; Review Focus 5): re-read with `FindByLogin` and verify the password against the stored hash locally. Return `ErrInvalidCredentials` on a mismatch.
  5. Script `KindWrongCredentials` is `ErrInvalidCredentials`. Other failures map as in Task 4.
- **Import `Signup`:**
  - Local validation, then `GetUser(email)` (and the username when required).
  - `ErrNoScript` from `GetUser` is treated as "not found": in import mode `get_user` is optional, and the local store is authoritative (D-0023 addendum).
  - A profile means `ErrUserExists`. Otherwise run today's local `Signup` with a fresh random id; `create` is never called.
- **Import `FindForReset`:**
  - A local `FindByLogin` hit wins.
  - Otherwise `GetUser(email)` (`ErrNoScript` means not found). A profile is migrated into a local user with **no** password hash, which is the "created by a reset lookup" state above.
  - The reset then completes through today's local path: `SetPasswordHash` sets the hash, and the user is fully migrated.

- [ ] **Step 1: Failing identity tests:**
  - `TestImportFirstLoginMigrates`: the script is called once. Then the user exists with an argon2id hash, and a second login with the same password does *not* call the script. Assert the `FuncExecutor` request count stays at 1.
  - `TestImportWrongPasswordAfterMigration`: gives `ErrInvalidCredentials`, and the script is not called.
  - `TestImportUnknownUser`: the script's `WrongUsernameOrPasswordError` gives `ErrInvalidCredentials`, and no user is created.
  - `TestImportConcurrentFirstLogin` (Review Focus 5):
    - Ten goroutines log in at once, released together by a `sync.WaitGroup` barrier.
    - The script sleeps 20 ms and accepts.
    - Expect all ten to succeed and exactly one user to exist. Run under `-race`.
    - Repeat with a SQLite store from `sqlstore` (`t.TempDir()`), so a real unique constraint is exercised.
  - `TestImportSignup`:
    - (a) `get_user` finds the user, giving `ErrUserExists`.
    - (b) `get_user` returns null, and the user is created locally with a hash; `create` is not called.
    - (c) With no `get_user` script, the signup succeeds locally.
  - `TestImportResetMigrates`: `FindForReset` creates a user with no hash. A login before the reset completes still goes through the `login` script and stores a hash.
  - `TestImportSeededUserIsLocal`: a user from the seed (Task 2 allows seed users in import mode) logs in without the script.

- [ ] **Step 2: Failing handler tests:**
  - Hosted login and the password grant on an import connection: the first login migrates, and the second does not call the script.
  - `/dbconnections/signup` on an import connection: a user found by `get_user` gives 409.
  - The hosted reset flow for a user known only to the legacy store ends with a local hash, and a login with the new password works without the script.

- [ ] **Step 3: Run them and watch them fail.**

- [ ] **Step 4: Implement it**, replacing the Task 4 guard branch.

- [ ] **Step 5: Run the tests.**

Run: `go test -race ./...`
Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
git add internal
git commit -m "feat(identity): custom database import mode: migrate users on first login and on reset"
```

---

### Task 6: End-to-end with real SDKs, a real browser and a legacy store

**Files:**
- Create: `tests/e2e/legacy-store.mjs` (an HTTP server standing in for a legacy user database)
- Create: `tests/e2e/m9-custom-db.mjs` (node-auth0 / auth0-auth-js)
- Create: `tests/e2e/m9-import.spec.mjs` (Playwright, auth0-spa-js login on an import connection)
- Modify: `tests/e2e/seed.yaml`, `tests/e2e/run-m3.sh`, `tests/e2e/run-browser.sh`, `tests/e2e/playwright.config.mjs` (if specs are listed)

**Interfaces:**
- Consumes: the full server from Tasks 1–5.
- Produces:
  - `legacy-store.mjs` listens on `127.0.0.1:${LEGACY_PORT:-8099}`.
  - Routes:
    - `POST /login` with `{email, password}` returns 200 with a profile, or 401.
    - `GET /users?email=` returns 200 with a profile, or 404.
    - `POST /users` creates a user (409 if one exists).
    - `POST /password` with `{email, password}` returns 200 `{changed:true}`.
    - `GET /stats` returns `{login: n, get_user: n, create: n, password: n}`.
  - Every route requires `Authorization: Bearer ${LEGACY_TOKEN}`.
  - It starts with one user, `legacy-user@e2e.local` / `Legacy-Password-1`, with id `L-1001`. Passwords are compared with `crypto.timingSafeEqual` on SHA-256 digests; this is test code, but keep it tidy.

- [ ] **Step 1: Seed.** Add two connections to `tests/e2e/seed.yaml`, both enabled for `e2e-node` and the SPA client:
  - `legacy-users`: `enabledDatabaseCustomization: true`, `import_mode: false`.
  - `import-users`: `enabledDatabaseCustomization: true`, `import_mode: true`.

  Both get `configuration: { API: "http://127.0.0.1:8099", TOKEN: "e2e-legacy-token" }`. The scripts are original and use `fetch`:

```js
// login
async function login(email, password, callback) {
  const res = await fetch(configuration.API + "/login", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + configuration.TOKEN },
    body: JSON.stringify({ email, password }),
    signal: AbortSignal.timeout(5000),
  });
  if (res.status === 401) return callback(new WrongUsernameOrPasswordError(email));
  if (!res.ok) return callback(new Error("legacy store answered " + res.status));
  callback(null, await res.json());
}
```

`get_user`, `create` and `change_password` follow the same pattern against `/users` and `/password`. Note that `AbortSignal` must be in the runner's context globals: add `AbortSignal` next to `AbortController` in Task 3's `contextFor`, and cover it with a line in `TestRunnerFetch`.

- [ ] **Step 2: `m9-custom-db.mjs`:**
  1. `auth.oauth.passwordGrant({username: 'legacy-user@e2e.local', password: 'Legacy-Password-1', realm: 'legacy-users', …})` returns tokens. Decode the ID token (no verification needed) and assert `sub === 'auth0|L-1001'`.
  2. A wrong password rejects with `invalid_grant`.
  3. `import-users`: two password grants for the same user. Read `/stats` before and after; `login` is called exactly once.
  4. `auth.database.signUp({email: 'legacy-user@e2e.local', …, connection: 'import-users'})` rejects with status 409.
  5. `@auth0/auth0-auth-js` `getTokenByPassword` with `realm: 'legacy-users'` returns an access token.

- [ ] **Step 3: `m9-import.spec.mjs`.** Follow the structure of `m4-spa-login.spec.mjs`; read it first and reuse its SPA page and selectors.
  - Log in through the hosted page with `connection=import-users` as the legacy user, and assert the SPA shows the user.
  - Log out, then log in again.
  - Assert through `/stats` (fetched with `page.request`) that the legacy `login` count rose by exactly one across the two logins.

- [ ] **Step 4: Runners.** In `run-m3.sh` and `run-browser.sh`:
  - Start `node tests/e2e/legacy-store.mjs &` before zeroauthy, with `LEGACY_TOKEN=e2e-legacy-token`.
  - Wait for it with the same curl loop as the server.
  - Kill it in `cleanup`.
  - Add `node m9-custom-db.mjs` to the run-m3 test chain. Add the spec to the browser run, in the same way as the existing specs.

- [ ] **Step 5: Run.**

Run: `make e2e`
Expected: all existing E2E steps plus m9 pass. If one fails, read the server log the runner prints; script logs appear there tagged `custom database script`.

- [ ] **Step 6: Commit.**

```bash
git add tests/e2e
git commit -m "test(e2e): custom database connections with node-auth0, auth0-auth-js and Chromium import-mode login"
```

---

### Task 7: Documentation, matrix, follow-ups

**Files:**
- Create: `docs/custom-db.md`
- Modify: `README.md`, `docs/compat/matrix.md`, `docs/superpowers/plan-1-followups.md`, `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md` (only if Tasks 1–6 changed anything §5.3 states)

- [ ] **Step 1: `docs/custom-db.md`**, an operator guide written in our own words. It covers:
  - What legacy mode and import mode do, and which scripts each operation calls (the Behavior lists from Tasks 4 and 5, as a table).
  - The seed syntax (the Task 2 example).
  - The script contract: the signatures, the callback, the three error classes, `configuration`, `global`, the profile fields, and how `user_id` becomes `auth0|…`.
  - **Runtime:**
    - Node ≥ 22.13 on the host's PATH, or `custom_db.node`.
    - `custom_db.modules_dir`: install npm packages with `npm install --prefix <dir> pg`. Native addons do not load under the permission model; prefer pure-JS packages, such as `bcryptjs` instead of `bcrypt`.
    - The 20 s limit and the 100 kB size.
  - **Security:**
    - Scripts run with an empty environment and cannot read host files or start processes.
    - Each tenant gets its own process.
    - `configuration` is encrypted at rest.
    - Scripts *can* reach the network, including internal addresses, so firewall the host's egress if tenants are untrusted.
  - Migrating off a legacy store: keep `import_mode` on and switch `login` and `get_user` to call back with no user once every user has migrated, as Auth0's migration guide describes.

- [ ] **Step 2: Matrix row.**

| Surface | Status | Notes |
|---|---|---|
| Custom database connections (`enabledDatabaseCustomization`, `import_mode`, `customScripts`, `configuration`) | Implemented | Scripts run in Node.js ≥ 22.13 (D-0022). `login`, `get_user`, `create` and `change_password` are called by hosted login, the password grants, `/dbconnections/*` and the reset flow. `verify`, `delete` and `change_email` are stored but have no caller until verification email and the Management API exist. Error responses: D-0023. Profiles: D-0024. Verified with auth0/legacy 7.4.0, @auth0/auth0-auth-js 1.16.1 and Chromium (m9). |

Also add the refresh-token length note from the changelog review to the refresh-token row: "Opaque, stored hashed; no fixed length is promised (Auth0 lengthened its tokens in 2026-10)".

- [ ] **Step 3: README.** Add a short "Custom databases" section linking to `docs/custom-db.md`.

- [ ] **Step 4: Follow-ups.** Add a "Plan 8 follow-ups" section to `plan-1-followups.md` with the Out of Scope list above, plus any review findings deferred while executing.

- [ ] **Step 5: Final verification.**

Run: `gofmt -l . ; go vet ./... ; ZA_REQUIRE_NODE=1 go test -race ./... ; go generate ./... && git diff --exit-code ; CGO_ENABLED=0 go build ./cmd/zeroauthy ; ./scripts/test-sql.sh ./internal/store/sqlstore/... ; make e2e`
Expected: everything is clean and passes.

- [ ] **Step 6: Commit.**

```bash
git add docs README.md
git commit -m "docs: custom database connections guide, matrix, follow-ups"
```

---

## Plan Self-Review (completed by the planner)

- **Spec coverage.** §5.3 as revised maps to the tasks as follows:
  - connection shape → Tasks 1–2;
  - Node runner and env isolation → Task 3;
  - legacy operations → Task 4;
  - import mode → Task 5;
  - config §9 → Task 2;
  - risk §14 → Task 7 docs.
  
  The changelog review was completed before this plan; its plan-relevant items are refresh-token length (Task 7 matrix) and custom-DB items, which are out of scope with backlog entries.
- **Placeholders:** none. Every behavior, error mapping and file is named. The two decisions are written in Task 4 with their content fixed in this plan.
- **Type consistency** across tasks:
  - `Request`, `Executor.Execute`, `ScriptError.Kind` constants, `ErrTimeout`, `ErrUnavailable` and `ErrNoScript` (Task 3) are used by `Client` (Task 4).
  - `Client.Login`, `GetUser`, `Create` and `ChangePassword` are used by `identity` (Tasks 4–5).
  - `keys.SealConnectionConfig` and `OpenConnectionConfig` (Task 2) are used by the seed (Task 2) and `Client` (Task 4).
  - The `store.Script*` constants (Task 1) are used by the seed validation (Task 2) and `Execute` (Task 3).
- **Review Focus:** each of the five lines has a named test in its owning task: lines 1 and 2 in Task 3, lines 3 and 4 in Task 4, and line 5 in Task 5.
