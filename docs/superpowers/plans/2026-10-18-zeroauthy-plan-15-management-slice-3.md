# zeroauthy Plan 15: Management API and console, slice 3 (connections)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** an operator creates a database connection in the console, picks its password policy and sign-up settings (each one explained), enables applications on it, and a user signs up and logs in through it. A newly created application can log users in without further setup. A custom database connection's scripts and configuration are edited and tried from the console. The same works through Auth0's Management API at `/api/v2/connections`, and `auth0 connections …` and `auth0 connections enabled-clients …` work unchanged.

**Architecture:**
- **Storage:** typed fields for the options zeroauthy enforces, plus `OptionsStored`, an allowlisted JSON object of the known Auth0 options zeroauthy only stores and returns, so `auth0-deploy-cli` exports round-trip (approach A, decided with the maintainer). Connections gain `Origin`, `Delete` (cascading to the connection's users) and `SetEnabledClients`. Tenants gain `EnableClientConnections`. Identities gain a password history.
- **`internal/connrules` (new):** the connection rules the seed has today (`internal/seed/validate.go`), plus the mapping between Auth0's wire `options` and the store, shared by the seed and the API, as `clientrules` and `apirules` are.
- **`internal/identity`:** the password policy grows to Auth0's named policies, history, no-personal-info and dictionary, enforced on every path that sets a password.
- **`internal/mgmt`:** `connections.go`, generated from `api/management.yaml` as in Plans 13 and 14.
- **Console:** an Authentication › Database section (list, create, detail with Settings, Password policy, Custom database and Applications tabs), and a Connections tab on application detail.
- **Task 1 settles undocumented Auth0 behaviour first,** by observation (CLEAN_ROOM.md), option A.

**Tech stack:** as Plan 14. No new Go or npm dependencies; the script editor is a plain monospace `<textarea>` (no CodeMirror). The built-in password dictionary is a vendored data file (Task 4), not a dependency.

**Spec:** `docs/superpowers/specs/2026-10-18-zeroauthy-management-design.md` §2 (slice 3), §4, §5 (patterns from slice 1). This plan is slice 3's short design.

**Decided with the maintainer (2026-10-18):**
- **Options: enforce the core, store the rest.** Enforced: Auth0's named password policy and `password_complexity_options.min_length`, `password_history`, `password_no_personal_info`, `password_dictionary`, `disable_signup`, `requires_username`, the custom-database options, `is_domain_connection`. Stored and returned but not enforced (the console labels them "not enforced by zeroauthy"): the other keys on the `connrules` allowlist (Task 3).
- **Storage shape:** approach A (typed enforced fields plus an allowlisted stored object), not the raw `options` blob or a column per option.
- **Custom database in the console:** a plain editor per script, write-only configuration values, the import-mode switch and a "try" button that runs the login script.
- **New applications:** as Auth0, with the tenant flag `enable_client_connections` (default per Task 1): a new first-party application is enabled on every connection of the tenant when the flag is on. Slice 5 exposes the flag through tenant settings; until then it is a seed and system-API setting.
- **Strategies:** only `auth0` (database) connections can be created; social connections are slice 6.

## Global Constraints

- **Wire shape is Auth0's.**
  - Paths: `/api/v2/connections`, `/api/v2/connections/{id}`, `/api/v2/connections/{id}/clients` (if Task 1 shows auth0-cli v1.37.0 uses it), `/api/v2/connections/{id}/status` only if Task 1 shows a client needs it.
  - Field names as in Auth0's Management API (`name`, `display_name`, `strategy`, `options`, `enabled_clients`, `is_domain_connection`, `realms`, `metadata`); error body, pagination and `fields` as in D-0039.
  - Scopes `read:connections`, `create:connections`, `update:connections`, `delete:connections`, `read:connections_options`, `update:connections_options` (the last two added to `tenantsetup.ManagementAPIScopes`); which operations need the `_options` scopes comes from Task 1.
  - Exact defaults, statuses and error codes come from Task 1 and go in D-0042.
- **Secrets never leave sealed:** custom-database `configuration` values are write-only through the API and the console; reads return what Task 1 shows Auth0 returns, but never a plaintext value.
- **Name and strategy are fixed after creation** (`Identity.Connection` stores the name), unless Task 1 shows Auth0 allows a rename; a rename would then need a store migration and is a follow-up instead.
- **Protected connections:** the `system` tenant's operator connection cannot be deleted, disabled for `zeroauthy-console`, or have sign-up turned on by the API (sign-up stays off for operators).
- **One set of rules:** the seed, the API and the console enforce the same connection validation, through `connrules`.
- **Seed coexistence:** connections created through the API are never touched by the seed; enabled clients set through the API on a seeded connection are kept by `seed_mode: create_only` and replaced by `apply` (documented).
- **Console:** as Plan 13 (original look, light and dark, keyboard accessible, its own CSP, tokens in memory, strings in the catalog). Every setting has a one-sentence explanation in the catalog (the "advanced settings explained" goal, design §2).
- **Earlier constraints still apply:** `go test -race ./...`, `go vet ./...`, gofmt, `go generate ./...` with no diff, the SQL suite (Postgres and MySQL; Docker is present in this environment, so run `scripts/test-sql.sh`), `make console` with no diff in `console/dist`, `make e2e`, `make check-sources`, and `make conformance` at exit 0 once at the end.

## Review Focus

1. **Tightening the password policy does not lock anyone out:** a user whose existing password breaks the new policy still logs in; only new passwords (sign-up, change, reset, import with a password) are checked. Pinned in Task 4 (`TestPolicyNotAppliedAtLogin`).
2. **Disabling an application on a connection:** the next `/authorize`, `/oauth/token` password grant, `/dbconnections/signup` and `/dbconnections/change_password` for that client and connection are refused; existing refresh tokens behave per Task 1 (C9). Pinned in Task 5 (`TestDisableClientOnConnection`).
3. **Deleting a connection in use:** its users, their refresh tokens and login sessions go with it; a tenant's `default_directory` naming it is cleared (or the delete refused, per Task 1 C7); the operator connection of the `system` tenant is refused. Pinned in Task 2 (`TestDeleteConnectionCascades`, storetest) and Task 5 (`TestDeleteProtectedConnection`).
4. **Custom-database secrets:** no read through the API, the console or the server log returns a configuration value; a `PATCH` that omits `configuration` keeps it, one that sends a key with an empty value per Task 1 C6. Pinned in Task 5 (`TestConnectionConfigurationWriteOnly`).
5. **Unknown and out-of-range options:** an unknown `options` key, an oversized `OptionsStored` (over 16 KB), `password_history.size` over 24 and `min_length` over `identity.MaxPasswordBytes` are refused with Auth0's error, not silently stored. Pinned in Task 3 (`TestNormalizeOptionsLimits`).

---

### Task 1: Observe Auth0's Management API for connections

Run by the controller session as the observer; implementers see only the notes. **Option A:** the `OBS_AUTH0_*` environment secrets hold an M2M application on the maintainer's non-live dev tenant with the connection scopes and `read/update:tenant_settings`. The observer runs the pinned `auth0-cli` v1.37.0 with `AUTH0_CLI_AUTH_MODE=env` and `curl`. Pace requests (one every two seconds; a burst gave `429` in Plan 14), create only connections named `obs-*`, delete them afterwards and restore any setting changed. Notes record statuses, `errorCode`s and field names, never values, IDs, secrets or tenant names.

**Files:** `docs/compat/observations/management-connections.md` (new), `docs/compat/decisions.md` (D-0042), this plan's Observed column.

| # | Question | Observed |
|---|---|---|
| C1 | `POST /connections` with only `name` and `strategy: auth0`: the full response (field names, `options` keys and defaults, `enabled_clients`, `is_domain_connection`, `realms`) | |
| C2 | Name rules (characters, length), duplicate name, unknown strategy, unknown `options` key: statuses and `errorCode`s | |
| C3 | `PATCH`: may `name` or `strategy` change? Is `options` replaced whole or merged? Which fields are immutable? | |
| C4 | Named password policies: the minimum length and rules of `none`, `low`, `fair`, `good`, `excellent` (from the docs, then one signup per policy against an `obs-*` connection to confirm the error); `password_complexity_options.min_length` range; how `/dbconnections/signup` reports each failure (`code`, `description`, `policy` text) | |
| C5 | `password_history` (`enable`, `size` range), `password_no_personal_info` (which fields count), `password_dictionary` (`enable`, `dictionary` list limits): defaults and errors | |
| C6 | Custom database: does `GET` return `options.configuration` values (plaintext, encrypted, or omitted)? `PATCH` with a missing `configuration`, an empty value; `customScripts` keys and size limits; which operations require `read/update:connections_options` | |
| C7 | `DELETE`: status, a second `DELETE`, unknown ID; are the users deleted? Deleting the connection a tenant's `default_directory` names | |
| C8 | Enabled clients: how auth0-cli v1.37.0 `connections enabled-clients show/update` calls the API (`GET/PATCH /connections/{id}/clients` with `{client_id, status}` items, or `enabled_clients` on the connection); paging of `/clients`; enabling a third-party client | |
| C9 | After disabling a client on a connection: does `/oauth/token` with an existing refresh token for a user of that connection still work? (Docs first; observe only if a test user can be created and removed on an `obs-*` connection.) | |
| C10 | `GET /connections`: order, paging shape (`connections` key), filters (`strategy`, `name`), checkpoint paging (`from`/`take`) | |
| C11 | Tenant `flags.enable_client_connections`: default on a new tenant, and whether a new application is enabled on every connection or only database ones (read-only: `GET /tenants/settings`, then create and delete an `obs-*` application) | |
| C12 | Which connection fields `auth0-deploy-cli` exports and sends (field names only, from its source), and which `options` keys appear in a real export of a database connection (the allowlist for `OptionsStored`) | |

- [ ] **Step 1:** Check the secrets resolve (`auth0 tenants list` in env mode); run C1–C12.
- [ ] **Step 2:** Write the observation note (facts in our own words), then D-0042.
- [ ] **Step 3:** Fill the Observed column. Commit with `docs(compat): observe the Management API for connections`.

---

### Task 2: Storage

**Files:** `internal/store/{store,types}.go`, `internal/store/memory`, `internal/store/sqlstore` (migration 0013 for postgres, mysql and sqlite: connection `origin`, `display_name`, `metadata`, `realms`, `options_stored`, the new password-policy columns; `tenants.enable_client_connections`; identity `password_history`), `internal/store/grpcstore` and `proto` (new RPCs `ConnectionsDelete`, `ConnectionsSetEnabledClients`; fields on `Connection`, `Tenant`, `Identity`; plugins without the RPCs answer Unimplemented, reported as "plugin too old"), `pkg/store`, `pkg/storetest`.

**Interfaces:**
- Produces, in `store`:
  - `PasswordPolicy{Name string; MinLength int; RequireCharacterClasses int; NoRepeatedChars bool; HistorySize int; NoPersonalInfo bool; Dictionary bool; DictionaryWords []string}`. `Name` is one of the `PolicyNone…PolicyExcellent` constants or empty (today's behaviour); `RequireCharacterClasses` and `NoRepeatedChars` are what `connrules` derives from `Name`, so enforcement reads only typed fields.
  - `Connection.Origin`, `DisplayName string`, `Metadata map[string]string`, `Realms []string`, `OptionsStored []byte` (a JSON object, opaque to drivers).
  - `Tenant.EnableClientConnections bool`.
  - `Identity.PasswordHistory []string` (argon2id PHC strings, newest first).
  - `Connections.Delete(ctx, tenantID, id string) error`: deletes the connection, the users whose only identity is on it (a user with other identities loses that identity), their refresh tokens and login sessions, and removes it from the tenant's `DefaultDirectory`; returns `ErrNotFound` if absent; atomic.
  - `Connections.SetEnabledClients(ctx, tenantID, id string, enable, disable []string) error`: adds and removes in one statement-level transaction; unknown client IDs are the caller's check.
  - `Clients.Create` is unchanged; auto-enabling lives in `mgmt` (Task 5) so the seed keeps explicit control.

- [ ] **Step 1: Tests** (storetest): round trip of every new field; `TestDeleteConnectionCascades` (users with only that identity gone, multi-identity user keeps the other, refresh tokens and sessions gone, `DefaultDirectory` cleared, other tenant untouched); `SetEnabledClients` add, remove, both, idempotent; `Delete` unknown ID; gRPC codec round trips; migration 0013 defaults on existing rows (empty policy name, flag false, empty history).
- [ ] **Step 2: Implement** in every driver. **Step 3: Run** `go test -race ./internal/store/... ./pkg/...` and `scripts/test-sql.sh` (both pass). **Step 4: Commit** with `feat(store): connection options, delete and enabled clients`.

---

### Task 3: `internal/connrules` and the seed

**Files:** `internal/connrules/{connrules,options}.go` and tests (new), `internal/seed/{seed,validate,apply}.go`, tests.

**Interfaces:**
- Produces:
  - `connrules.Spec`: the wire shape (`Name`, `DisplayName`, `Strategy`, `Options` as `map[string]json.RawMessage`, `EnabledClients`, `IsDomainConnection`, `Realms`, `Metadata`) plus the decoded enforced options.
  - `connrules.Normalize(s *Spec, c Context) []error` with `Context{Clients map[string]bool; ThirdParty map[string]bool}`: defaults (C1), name rules (C2), strategy `auth0` only, unknown options keys refused, `OptionsStored` at most 16 KB, the third-party restriction, policy ranges (C4, C5), and the custom-DB checks moved from `seed.validateCustomDB` unchanged.
  - `connrules.CheckImmutable(c *store.Connection, s *Spec) error` (C3).
  - `connrules.Apply(c *store.Connection, s *Spec, w keys.Wrapper) error`: sets the typed fields and `OptionsStored`, derives `RequireCharacterClasses`/`NoRepeatedChars` from the policy name, seals `configuration` (a missing key keeps the stored value per C6).
  - `connrules.FromConnection(c *store.Connection) Spec`: the wire shape for reads, with `configuration` as C6 dictates and never plaintext.
  - `connrules.StoredOptionKeys`: the allowlist from C12.
- The seed's `Connection` gains `display_name`, `password_policy.name`, `password_policy.history_size`, `password_policy.no_personal_info`, `password_policy.dictionary` and `dictionary_words`; existing seed files keep working unchanged; `apply` skips `Origin == api`.

- [ ] **Step 1: Tests:** each C1–C5 and C12 rule as a table; `TestNormalizeOptionsLimits` (Review Focus 5); `FromConnection(Apply(spec))` round-trips every stored option; the existing seed tests pass against `connrules` unchanged; the seed skips an API-created connection.
- [ ] **Step 2: Implement. Step 3: Run** `go test -race ./internal/connrules/... ./internal/seed/...`. **Step 4: Commit** with `feat(connrules): shared connection rules and options mapping`.

---

### Task 4: Password policy enforcement

**Files:** `internal/identity/{identity,policy,dictionary}.go`, `internal/identity/data/common-passwords.txt` (new, vendored), `NOTICE`, `scripts/check-sources` input, `internal/dbconn/{signup,change_password}.go`, `internal/login/reset.go`, `internal/i18n/keys.go` and the English catalog, tests.

**Interfaces:**
- Produces:
  - `identity.CheckPassword(p store.PasswordPolicy, password string, who PersonalInfo) error` with `PersonalInfo{Email, Username, Name, Nickname, GivenName, FamilyName string}` (C5 decides the list); returns `*PolicyError` with a `Key` per rule.
  - `identity.CheckHistory(p store.PasswordPolicy, history []string, password string) error` and `identity.PushHistory(p store.PasswordPolicy, history []string, newHash string) []string` (keeps at most `HistorySize`).
- Rules by policy name from C4 (lengths and character classes), `NoRepeatedChars` (no more than two identical characters in a row), dictionary (custom words, case-insensitive, plus the built-in list when `Dictionary` is on), no-personal-info (the password contains none of the listed values of 3+ characters, case-insensitive, per C5).
- **Built-in list:** a common-password list under a permissive licence (SecLists, MIT, is the first candidate), at most 10,000 entries, with provenance in NOTICE and checked by `make check-sources`. If the licence does not pass review, ship only the custom list, and note it in D-0042 and the follow-ups.
- `/dbconnections/signup`, change password and the reset page answer with Auth0's error shapes from C4.

- [ ] **Step 1: Tests:** one table row per named policy at its boundary length (C4 values as literals); repeated characters; dictionary hit on a built-in and a custom word, case-insensitive; personal info; history refusing a reused password and keeping exactly `HistorySize` hashes; `TestPolicyNotAppliedAtLogin` (Review Focus 1); signup, change password and reset each refuse a policy failure with the C4 error.
- [ ] **Step 2: Implement. Step 3: Run** `go test -race ./internal/identity/... ./internal/dbconn/... ./internal/login/...` and `make check-sources`. **Step 4: Commit** with `feat(identity): Auth0 password policies, history and dictionary`.

---

### Task 5: `/api/v2/connections`

**Files:** `api/management.yaml` (schemas and operations), `internal/mgmt/connections.go`, `internal/mgmt/clients.go` (auto-enable on create), `internal/tenantsetup/management.go` (the `_options` scopes), `internal/system/system.go` (`enable_client_connections` on the system tenant API, default per C11), `internal/customdb` (a `TryLogin` entry point for the console's "try" button, if the existing runner has none), tests.

**Interfaces:**
- Consumes: `connrules.*` (Task 3), `Connections.Delete` and `SetEnabledClients` (Task 2).
- `GET /connections` (paging, `fields`, filters per C10), `POST`, `GET /{id}`, `PATCH /{id}`, `DELETE /{id}`, and the enabled-clients form per C8 (`GET/PATCH /connections/{id}/clients`, `enabled_clients` on `PATCH /{id}`, or both).
- `POST /api/v2/connections/{id}/try` is **not** an Auth0 endpoint: the console's "try login" goes through zeroauthy's system API instead, as `POST /api/system/tenants/{tenant}/connections/{id}/try-login` (operator tokens only, body `{email, password}`, answers the script's profile or error, never the configuration), so `/api/v2/` stays Auth0's shape.
- `POST /clients`: when the tenant's `EnableClientConnections` is on, a new non-third-party client is enabled on every connection (C11 decides "every" or "database only").
- Rules: name and strategy fixed (C3); the `system` tenant's operator connection protected (Global Constraints); delete cascades (Review Focus 3); `configuration` write-only (Review Focus 4).

- [ ] **Step 1: Tests:** per operation and field from C1–C11; `TestDisableClientOnConnection` (Review Focus 2) across `/authorize`, the password grant and `/dbconnections/*`; `TestDeleteProtectedConnection`; `TestConnectionConfigurationWriteOnly`; `TestCreateClientEnablesConnections` (flag on and off, third-party skipped); try-login with a good and a bad password and with the configuration absent from the answer; scope checks for each operation; the contract test extended to the new operations.
- [ ] **Step 2: Implement. Step 3: Run** `go test -race ./...` and `go generate ./...` (no diff). **Step 4: Commit** with `feat(mgmt): /api/v2/connections and enabled clients`.

---

### Task 6: Console: database connections

**Files:** `console/src/pages/connections/{List,Create,Detail,SettingsTab,PolicyTab,CustomDbTab,ClientsTab,DangerZone}.vue` and tests, `console/src/pages/applications/ConnectionsTab.vue` and test, `console/src/pages/applications/QuickStart.vue` (drop the slice-3 note; name the connections the application is enabled on), `console/src/api/client.ts` (regenerated), router, sidebar (Authentication › Database), strings, `console/dist`.

**Screens:**
- **List:** server-paginated; name, display name, user count only if C10 shows a cheap source (otherwise omitted), "Custom database" and "Domain" badges.
- **Create:** name (fixed after creation, said so), display name, "requires username", "disable sign-ups". Opens the detail page.
- **Detail:**
  - **Settings:** display name, disable sign-ups, requires username, promote to domain level (with the third-party explanation from Plan 9), then a collapsed "Stored, not enforced by zeroauthy" list of the `OptionsStored` keys present, read-only.
  - **Password policy:** the five named policies as a radio group, each with its rules spelled out; minimum length; history size; no personal info; dictionary with custom words.
  - **Custom database:** the switch, import mode, one monospace textarea per script (tab inserts spaces, size counter against the limit), configuration as key and write-only value rows ("set" or "unchanged"), and "Try login" (email and password, shows the returned profile or the script's error).
  - **Applications:** every application of the tenant with a switch; third-party applications disabled with the domain-level explanation; the console's own client on the `system` tenant locked on.
  - **Danger zone:** delete by typing the name, warning that the connection's users are deleted with it; hidden for the protected connection.
- **Application detail** gains a **Connections** tab: a switch per connection.

- [ ] **Step 1: Tests** (Vitest): each screen's loading, empty, error, validation and success states; the policy radio group sends the right `options`; configuration values never rendered from a read; try-login success and error; the protected connection's locked switch and hidden danger zone.
- [ ] **Step 2: Implement.** Rebuild `dist/`. **Step 3: Run** `make console` (no diff after build). **Step 4: Commit** with `feat(console): database connections and enabled applications`.

---

### Task 7: E2E

**Files:** `tests/e2e/seed.yaml` (the `e2ecli` admin client gains the connection scopes), `tests/e2e/m15-mgmt-cli.mjs` (new), `tests/e2e/m15-console.spec.mjs` (new), `tests/e2e/run-m3.sh`, `docs/compat/blackbox-clients.md`.

- [ ] **Step 1: `auth0-cli`** (v1.37.0, through `connect-proxy.mjs`): `connections create/list/show/update/delete`, `connections enabled-clients show/update`, and `auth0 api` for the password-policy options. Then sign a user up on the new connection through `/dbconnections/signup` and get a token with the password grant; a password breaking the policy is refused; after `enabled-clients update` disables the client the password grant is refused.
- [ ] **Step 2: Playwright:** sign in; create an application and see it enabled on the tenant's connections (flag on); create a database connection with the "good" policy; enable the application; sign up through the hosted pages with a weak and then a good password; turn on custom database, paste the `m9` legacy login script and its configuration, "Try login" against the legacy store; delete the connection and see its user gone.
- [ ] **Step 3: Run** `make e2e`. **Step 4: Commit** with `test(e2e): connections with auth0-cli and the console`.

---

### Task 8: Documentation and final verification

**Files:** `docs/management-api.md` (connections, enabled clients, `enable_client_connections`), `docs/console.md` (database connections), `docs/custom-db.md` (editing and trying scripts from the console), `docs/compat/matrix.md`, `docs/superpowers/plan-1-followups.md` ("Plan 15 follow-ups"; close the slice-3 items in the Plan 13 and 14 sections), README.

- [ ] **Step 1: Write the docs.**
- [ ] **Step 2: Verify:** gofmt, vet, `go test -race ./...`, `go generate` with no diff, `make console` with no diff, `scripts/test-sql.sh` (Postgres and MySQL), `make e2e`, `make check-sources`, `make conformance` (exit 0). Record anything that could not run in a completion note here.
- [ ] **Step 3: Commit** with `docs: connections; Plan 15 records`.
