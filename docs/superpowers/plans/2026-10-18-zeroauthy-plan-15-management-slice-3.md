# zeroauthy Plan 15: Management API and console, slice 3 (database connections)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** everything configurable on an Auth0 database connection is configurable in zeroauthy through `/api/v2/connections` (and `auth0 connections …` unchanged) and through the console; the password rules Auth0 offers are enforced; an application created in the console can finally log users in.

**Architecture:**
- **Storage:** `store.Connection` gains typed fields for the newly enforced settings and an `Extra` JSON object for stored-but-inert options; `Connections.Delete` cascades; a `password_history` table. Migration 0013, proto, every driver, storetest.
- **`internal/connrules` (new):** the connection rules shared by the seed, the API and the console (pattern of `clientrules`, `apirules`).
- **`internal/identity`:** one password check covering length, classes, history, dictionary, personal info; username length.
- **`internal/mgmt/connections.go`:** the endpoints, generated from `api/management.yaml`.
- **System API:** a "try script" extension for operators.
- **Console:** Connections section and an application Connections tab.
- **Task 1 settles undocumented Auth0 behaviour by observation** (CLEAN_ROOM.md), run by the controller session as the observer; implementers see only the notes.

**Tech stack:** as Plans 13–14. One new embedded data file (the common-password list) under a permissive licence recorded in NOTICE; no new Go or npm dependencies.

**Spec:** `docs/superpowers/specs/2026-10-18-zeroauthy-connections-design.md` (this plan argues from it; read both).

## Global Constraints

- **Wire shape is Auth0's:** paths `/api/v2/connections`, `/api/v2/connections/{id}`, `/api/v2/connections/{id}/clients`; field names, defaults, statuses and error codes from Task 1; error body, paging (`page`, `per_page`, `include_totals`) and `fields` per D-0039, plus whatever list filters and checkpoint paging Task 1 observes.
- **Scopes:** `read:connections`, `create:connections`, `update:connections`, `delete:connections` (already in `tenantsetup.ManagementAPIScopes`; add any Task 1 shows `auth0 connections` needs, such as `read:connections_options`).
- **Strategy `auth0` only;** any other strategy on create is `400 invalid_body`.
- **Every Auth0 database-connection option is accepted, stored and returned.** Enforced options live in typed fields; the rest in `Extra`, listed in D-0042 as "stored, not enforced".
- **Configuration secrets never leave the server in plaintext.**
- **One set of rules** (`connrules`) for seed, API and console.
- **Seed coexistence:** API-created connections carry `origin: api`; the seed never touches them; `seed_mode: create_only` keeps working.
- **Console:** original look and wording (CLEAN_ROOM.md "Prohibited"), light and dark, keyboard accessible, its own CSP, tokens in memory, strings in the catalog, every setting with a one-line explanation.
- **Earlier constraints still apply:** `go test -race ./...`, `go vet ./...`, gofmt, `go generate ./...` with no diff, `make console` with no diff in `console/dist`, `make check-sources`, `make e2e` (with `E2E_CHROMIUM` where Playwright's Chromium is absent), the SQL suite where it can run, `make conformance` at exit 0 once at the end.

## Review Focus

1. **Deleting the tenant's default directory:** deleting the connection named by the tenant's `default_directory` clears it (or is refused, per Task 1), so the password grant and `/dbconnections/*` never point at a missing connection. Pinned in Task 5 (`TestDeleteConnectionDefaultDirectory`).
2. **PATCH without `options.configuration`:** a PATCH that omits `configuration`, or sends `options` without it, keeps the stored sealed values (Auth0 replaces `options` whole, per Task 1: then the console must send the merged object and the API test pins whichever rule applies). Pinned in Task 5 (`TestPatchConnectionKeepsConfiguration`).
3. **Enabled clients that do not exist or belong to another tenant:** `enabled_clients` and `PATCH /connections/{id}/clients` refuse unknown client IDs with Task 1's error; deleting a client already removes it (Plan 13). Pinned in Task 5.
4. **Shrinking password history:** lowering `password_history.size` trims stored history on the next password set and never blocks a password older than the new size; size 0 deletes nothing but checks nothing. Pinned in Task 4 (`TestHistoryShrink`).
5. **Personal info and dictionary edge cases:** comparisons are case-insensitive and Unicode-aware; email local parts and name parts shorter than 3 characters are ignored (so a user named "Al" can still use passwords containing "al"); custom words are trimmed and deduplicated. Pinned in Task 4.

---

### Task 1: Observe Auth0's Management API for database connections

Run by the controller session as the observer (option A of Plan 14: the observer M2M application holds the connection and tenant-settings scopes; `OBS_AUTH0_*` secrets). Pace requests (about one per second), restore anything changed, delete every test connection and user.

**Files:** `docs/compat/observations/management-connections.md` (new), `docs/compat/decisions.md` (D-0042), this plan's Observed column, NOTICE (dictionary source).

| # | Question | Observed |
|---|---|---|
| C1 | Defaults of `POST /connections` with only `name` and `strategy: auth0`: every `options` field returned, `enabled_clients`, `realms`, `is_domain_connection`, `display_name` || see note: `password_options` (min 15, history size 3 off, dictionary `en_100k` off, profile data off), `brute_force_protection: true`, `realms:[name]`, IDs `con_`+16 |
| C2 | Name rules (pattern, length), duplicate name error, strategies refused || pattern `^[a-zA-Z0-9](-[a-zA-Z0-9]|[a-zA-Z0-9])*$`, ≤128; `409 connection_conflict`; unknown strategy `400 invalid_body`; unknown `options` keys kept |
| C3 | `options` on PATCH: replaced whole or merged? `configuration` returned or hidden? `strategy`/`name` immutable? || `options` replaced whole; `name`/`strategy`/`enabled_clients` unknown on PATCH; configuration returned as encrypted blobs, a blob sent back keeps the value |
| C4 | Password options: `passwordPolicy` values, `password_complexity_options`, `password_history` (size range), `password_dictionary` (custom list limits), `password_no_personal_info`, `validation.username` min/max ranges || `password_options` (complexity, history 1–24, dictionary `en_10k`/`en_100k`, profile_data) vs legacy fields, never both; history/dictionary/profile data need an entitlement the dev tenant lacks |
| C5 | Custom DB: `enabledDatabaseCustomization`, `customScripts` names and size limits, `import_mode`, `configuration` key/value limits || script names enforced, no size limit hit (1.1 MB); `import_mode` needs custom DB; configuration string|null |
| C6 | `attributes`, `authentication_methods` (passkeys), `precedence`, `non_persistent_attrs`, `disable_self_service_change_password`, `brute_force_protection` (here or tenant-level?), and every other key C1 shows || `brute_force_protection` is a connection boolean (thresholds tenant-level); `validation.username` 1–128; `precedence` ≥3; attributes/passkeys stored |
| C7 | `GET/PATCH /connections/{id}/clients`: body shape, paging, unknown client IDs, limits; `enabled_clients` field still accepted? || `{clients:[{client_id}]}` with checkpoint paging; PATCH `[{client_id,status}]` → 204; `400 inexistent_client`; `enabled_clients` only on POST |
| C8 | `GET /connections`: order, paging shape, filters (`strategy`, `name`), checkpoint paging || case-insensitive name order; D-0039 paging + checkpoint; filters `name`, `strategy` |
| C9 | `DELETE`: status; are the connection's users deleted (create one first)? unknown ID; the tenant's `default_directory` afterwards || `202 {deleted_at}`, then `204`; users deleted; `default_directory` cleared; malformed ID `400 invalid_uri` |
| C10 | Errors: unknown ID, malformed ID, missing scope, unknown property || `404 inexistent_connection`, `400 invalid_uri`, `400 invalid_body`; missing scope per D-0039 (not re-observed) |
| C11 | Which fields `auth0-cli` v1.37.0 `connections create/update` and `auth0-deploy-cli` 9.1.0 send and strip for connections (field names only, from source) || cli: name, strategy, `--data`; deploy-cli: strips name/strategy on update, merges current options, clients via `/clients` |
| C12 | A permissively licensed common-password list for the dictionary (source, licence, size) || SecLists (MIT) `10k-most-common.txt`; `100k-most-used-passwords-NCSC.txt` (NCSC licence, verify for NOTICE) |

- [x] **Step 1:** Run C1–C12 (one connection at a time, cleaned up).
- [x] **Step 2:** Write the observation note (facts in our own words, no secrets, IDs or tenant names) and D-0042, including the "stored, not enforced" option list and the "try script" extension.
- [x] **Step 3:** Fill the Observed column. Commit with `docs(compat): observe the Management API for connections`.

---

### Task 2: Store: connection settings, delete cascade, password history

**Files:** `internal/store/{types,store}.go`, memory, sqlstore (migration 0013 in sqlite, postgres, mysql), grpcstore and proto, `pkg/store`, `pkg/storetest`.

**Interfaces:**
- Produces (as built, after the D-0042 password model):
  - `store.Connection` fields `PasswordOptions store.PasswordOptions{Complexity, History, Dictionary, ProfileData}` (replacing `PasswordPolicy`), `BruteForceProtection bool`, `UsernameMin, UsernameMax int`, `Origin string`, `Extra map[string]any` (JSON object; nil means none). `PasswordComplexity{MinLength, CharacterTypes, CharacterTypeRule, IdenticalCharacters, SequentialCharacters, MaxLengthExceeded, MinCharacterClasses}`; `MinCharacterClasses` keeps the seed's `require_character_classes` 1 and 2; `store.LegacyComplexity(minLength, classes)` maps the seed's policy (4 = all four types, 3 = `three_of_four`).
  - `Connections.Delete(ctx, tenantID, id string) error`: `ErrNotFound` if absent; deletes the users with an identity on the connection and their sessions, refresh tokens, user grants, reset tickets, password history; clears the tenant's `DefaultDirectory` if it names the connection (C9). The enabled-clients list lives on the connection, so it goes with the row.
  - `PasswordHistories` repository (`Store.PasswordHistories()`): `Add(ctx, tenantID, userID string, hash []byte, keep int) error` (appends, then trims to the newest `keep`; `keep <= 0` stores nothing), `List(ctx, tenantID, userID string) ([][]byte, error)` (newest first); removed with the connection's users and with the tenant.
  - `ConnectionFilter{Name string; Strategies []string}` and `Connections.List(ctx, tenantID, f ConnectionFilter, p Page) ([]*Connection, int, error)` replacing the unfiltered list (callers that want all pass zero values), ordered by name case-insensitively, then ID (C8).

- [x] **Step 1: Tests** (storetest): field and `Extra` round trips (nested objects, arrays); `Delete` cascade (users, sessions, refresh tokens, grants, history, enabled lists, default directory); unknown ID; history add/trim/list order; history deleted with the user; list filters and paging; tenant isolation; gRPC codec round trips.
- [x] **Step 2: Implement** in every driver; regenerate with `go generate ./...`. Plugins without the new RPCs answer Unimplemented, reported as "plugin too old".
- [x] **Step 3: Run** the Go suite and the SQL suite (Postgres from installed binaries if containers are unavailable). **Step 4: Commit** with `feat(store): connection settings, delete cascade and password history`.

---

### Task 3: `internal/connrules`

**Files:** `internal/connrules/` (new), `internal/seed/validate.go`, `internal/seed/apply.go`, tests.

**Interfaces:**
- Produces: `connrules.Spec` (the API/seed view of a connection: name, strategy, options typed and extra, enabled clients), `connrules.Normalize(*Spec) []error` (defaults from C1, every limit from C2–C6), `connrules.Apply(*Spec, *store.Connection)`, `connrules.FromConnection(*store.Connection) *Spec`, and `connrules.ExtraSchema` (option name → JSON type, from C6) used to validate `Extra`.

- [ ] **Step 1: Tests:** each limit and default; unknown `options` keys refused (or kept in `Extra`, per C6); the existing seed tests unchanged; a seed with the new password options round-trips.
- [ ] **Step 2: Implement;** move the seed's connection checks here. **Step 3: Run. Step 4: Commit** with `feat(connrules): shared connection rules`.

---

### Task 4: Password rules

**Files:** `internal/identity/` (password check, username check), `internal/identity/dictionary/` (embedded list + loader), `internal/i18n` catalog keys, callers: `internal/login` (signup, reset), `internal/dbconn` (`/dbconnections/signup`, change password), `internal/customdb` (create path), import paths; NOTICE.

**Interfaces:**
- Consumes: Task 2 fields and `PasswordHistory`.
- Produces: `identity.CheckPassword(c *store.Connection, u identity.Person, candidate string, history [][]byte) error` where `identity.Person{Email, Username, Name, GivenName, FamilyName, Nickname string}`; returns `*identity.PolicyError{Reason, Key}` with new keys `KeyPasswordInHistory`, `KeyPasswordInDictionary`, `KeyPasswordHasPersonalInfo`; `identity.CheckUsername(c *store.Connection, username string) error` with `KeyUsernameTooShort`/`KeyUsernameTooLong`; `identity.RecordPassword(ctx, st, c, userID, hash)` writing history with `keep = c.PasswordHistorySize`.

- [ ] **Step 1: Tests:** each rule alone and combined; Review Focus 4 (`TestHistoryShrink`) and 5 (case-insensitive and Unicode comparisons, parts under 3 characters ignored, custom words trimmed and deduplicated); a reused password refused through signup → reset; dictionary hit from the embedded list and from custom words; username limits at signup; localized messages render.
- [ ] **Step 2: Implement;** every password set goes through `CheckPassword` then `RecordPassword`. **Step 3: Run. Step 4: Commit** with `feat(identity): password history, dictionary, personal info and username rules`.

---

### Task 5: `/api/v2/connections`

**Files:** `api/management.yaml` (schemas and operations with `x-source`), `internal/mgmt/connections.go` (new), `internal/server/mgmtapi.go` (scopes), tests.

**Interfaces:**
- Consumes: Tasks 2–3.
- Operations: `GET /connections` (filters, paging, `fields` per C8), `POST`, `GET /{id}`, `PATCH /{id}` (per C3), `DELETE /{id}` (per C9), `GET /{id}/clients`, `PATCH /{id}/clients` (per C7).

- [ ] **Step 1: Tests:** per operation and field from C1–C10; Review Focus 1 (`TestDeleteConnectionDefaultDirectory`), 2 (`TestPatchConnectionKeepsConfiguration`), 3 (unknown and foreign client IDs); `configuration` never in a response; API-created connections carry `origin: api` and the seed skips them; the contract test extended; an application enabled through the API can log a user in through hosted login.
- [ ] **Step 2: Implement. Step 3: Run** the Go suite, `go generate` with no diff, `make check-sources`. **Step 4: Commit** with `feat(mgmt): /api/v2/connections`.

---

### Task 6: Try a custom-database script

**Files:** `api/system.yaml` (or wherever the system API is described), `internal/mgmt/system.go` (or a new `system_scripts.go`), `internal/customdb` (a dry-run entry point), tests.

**Interfaces:**
- Produces: `POST /api/system/tenants/{tenant}/connections/{id}/scripts/{name}/try` with body `{"args": [...]}` (the script's arguments as JSON, matching the runner's signature for that script name), response `{"result": <value>|null, "error": {"name","message"}|null, "logs": [string], "duration_ms": int}`. Operators only, system host only; rate limit 10 per minute per operator (`429 too_many_requests`); logged without arguments or result.
- Consumes: the existing runner (`customdb.Executor.Execute`) with the connection's sealed configuration.

- [ ] **Step 1: Tests:** each script name with a stub script; a thrown error and a timeout; non-operator and M2M tokens refused; rate limit; arguments and results absent from the log.
- [ ] **Step 2: Implement. Step 3: Run. Step 4: Commit** with `feat(system): try a custom database script`.

---

### Task 7: Console: connections

**Files:** `console/src/pages/connections/{List,Create,Detail}.vue` and tabs (`SettingsTab`, `PasswordTab`, `CustomDbTab`, `ClientsTab`, `DangerZone`), `console/src/pages/applications/ConnectionsTab.vue`, `console/src/api/client.ts`, router, sidebar, strings, tests, `console/dist`.

**Screens** (spec §5.5): list (paged, strategy, enabled-application count); create; detail with Settings (stored-not-enforced options in their own labelled group, marked "saved, not enforced yet"), Password policy (with the live checker computed in the browser from the same rules: a TypeScript port of the length, class, dictionary-custom-words and personal-info checks, the embedded list excepted), Custom database (script editor textarea with line numbers, configuration key/values write-only after save, "Try" per script calling Task 6), Applications (switch per application), Danger zone (type the name; shows the user count); application detail gains Connections.

- [ ] **Step 1: Tests** (Vitest): each screen's loading, empty, error, validation and success states; the live checker per rule; configuration values never rendered after save; Try success, error and rate-limit states; PATCH sends the merged `options` if C3 shows Auth0 replaces it whole.
- [ ] **Step 2: Implement.** Rebuild `dist/`. **Step 3: Run** `make console`. **Step 4: Commit** with `feat(console): database connections`.

---

### Task 8: E2E

**Files:** `tests/e2e/m15-mgmt-cli.mjs`, `tests/e2e/m15-console.spec.mjs`, `tests/e2e/run-m3.sh`, `tests/e2e/seed.yaml`.

- [ ] **Step 1: `auth0-cli`** (v1.37.0): `connections create/list/show/update/delete`, `connections enabled-clients show/update`; then a user signs up through `/dbconnections/signup` on the new connection, with a refused and an accepted password.
- [ ] **Step 2: Playwright:** sign in; create a connection; enable an application; set history 2, dictionary on with a custom word, no personal info; sign up through hosted login with a dictionary word (refused, rule named), then a good password (accepted); try a custom-DB `login` script with a stub (result shown); delete the connection (its user is gone).
- [ ] **Step 3: Run** `make e2e`. **Step 4: Commit** with `test(e2e): connections with auth0-cli and the console`.

---

### Task 9: Documentation and final verification

**Files:** `docs/management-api.md`, `docs/console.md`, `docs/compat/matrix.md`, `docs/superpowers/plan-1-followups.md` ("Plan 15 follow-ups": each stored-not-enforced option, slice 5 for attack protection if C6 says tenant-level), README.

- [ ] **Step 1: Write the docs.**
- [ ] **Step 2: Verify:** gofmt, vet, `go test -race ./...`, `go generate` no diff, `make console` no diff, the SQL suite, `make e2e`, `make check-sources`, `make conformance` (exit 0, or say exactly why it cannot run).
- [ ] **Step 3: Commit** with `docs: database connections; Plan 15 records`.
