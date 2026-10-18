# zeroauthy — Design: Management API and console, slice 3 (database connections)

- **Status:** Approved design (2026-10-18), input for Plan 15
- **Date:** 2026-10-18
- **Scope:** slice 3 of the management program (`docs/superpowers/specs/2026-10-18-zeroauthy-management-design.md` §2). Slices 1 (applications) and 2 (APIs and client grants) are done.

## 1. Goal

Everything an operator can configure on an Auth0 database connection can be configured in zeroauthy, through Auth0's Management API and through zeroauthy's console. The console is similar in purpose to Auth0's dashboard but original in look and wording (CLEAN_ROOM.md).

**Success:**
- `auth0 connections list/show/create/update/delete` and `auth0 connections enabled-clients show/update` (auth0-cli v1.37.0) work against zeroauthy unchanged.
- An operator creates a database connection in the console, enables an application on it, sets a strict password policy, and a user signs up through hosted login: a password that breaks a rule is refused with the rule named, a good one succeeds.
- An application created in the console can finally log users in (closing the slice 1 gap).
- Every database-connection setting Auth0 offers is accepted, stored and returned. The ones zeroauthy enforces work; the others are visibly marked as not enforced yet.

## 2. Sources (clean room)

- Auth0's public Management API docs for `/api/v2/connections` and `/api/v2/connections/{id}/clients`, and the public docs on database connections, password policies (strength, history, dictionary, personal data), username settings and custom databases.
- The Apache-2.0 OpenAPI description (NOTICE).
- `auth0-cli` v1.37.0, `auth0-deploy-cli` 9.1.0 and `go-auth0` sources (MIT): which fields they send and read.
- **Observation** on the maintainer's dev tenant (Plan 15 Task 1, option A: the observer M2M application already holds the connection and tenant-settings scopes). The observer and the implementers are different sessions.

## 3. Scope

**In:**
- Management API: `GET/POST /api/v2/connections`, `GET/PATCH/DELETE /api/v2/connections/{id}`, `GET/PATCH /api/v2/connections/{id}/clients`, and the `enabled_clients` field. Scopes `read/create/update/delete:connections`.
- Strategy `auth0` (database) only. Any other strategy on create is `400 invalid_body` until its slice (social: slice 6).
- **Enforced** settings:
  - already working: password length and character classes, `disable_signup`, `requires_username`, `is_domain_connection`, custom database (`enabledDatabaseCustomization`, scripts, `configuration`), `import_mode`, `set_user_root_attributes`, enabled clients;
  - **new in this slice:** password history (no reuse of the last N passwords), password dictionary (a built-in common-password list plus custom words), no personal info in the password (email, username, name parts), username length limits.
- **Stored, returned and shown, not enforced yet:** passkeys and `authentication_methods`, flexible identifiers (`attributes`, phone), non-unique emails, `display_name`, `show_as_button`, `metadata`, `realms` and any other option Task 1 finds. The console marks each "saved, not enforced yet"; each becomes a follow-up.
- **Brute-force protection:** on Auth0 this is tenant-level attack protection. If Task 1 confirms it is not a connection option, it moves to slice 5 (tenant settings).
- **Delete:** a connection's users go with it (and their sessions, refresh tokens, grants and password history); it leaves every client's enabled list. Task 1 confirms Auth0's cascade; differences are logged.
- **Console:** connections list and create; connection detail (Settings, Password policy, Custom database, Applications, Danger zone); a Connections tab on application detail.
- **"Try" a custom-database script:** a zeroauthy extension on the system API (§5.4).

**Out:** social and enterprise connections, passwordless, MFA, organizations, the tenant-level attack protection settings, actually enforcing the "stored" options above.

## 4. Data model

- **`store.Connection`** gains typed fields for the new enforced settings:
  - `PasswordHistorySize int` (0 off; Auth0's limit from Task 1),
  - `PasswordDictionary {Enable bool; Words []string}`,
  - `PasswordNoPersonalInfo bool`,
  - `UsernameMin, UsernameMax int`,
  - `Origin` (`store.OriginAPI` or empty), as on clients and resource servers;
  - `Extra` (a JSON object): the stored-but-inert options, validated against a schema of their names and types, and merged back into `options` on read. When an option becomes enforced it moves out of `Extra` into a typed field, with a migration.
- **`Connections.Delete(ctx, tenantID, id)`** (new): cascades to the connection's users and everything that hangs off them, and removes the connection from clients' enabled lists. Part of the store contract (storetest), implemented by memory, SQL and gRPC; third-party plugins must implement it.
- **Password history:** a `password_history` table (tenant, user, created_at, hash), keeping the last `PasswordHistorySize` hashes per user; written on every password set (signup, reset, change, import, custom-DB create); deleted with the user.
- **Migration 0013** for the new columns and table; new proto fields and RPCs (`ConnectionsDelete`, history RPCs); plugins without them answer Unimplemented ("plugin too old").

## 5. Behaviour

### 5.1 Shared rules

`internal/connrules` (new), the pattern of `clientrules` and `apirules`: name format and uniqueness, strategy, `options` schema (typed and `Extra`), password-policy ranges, script names and size limits, `configuration` limits. The seed's connection checks move there; the seed, the API and the console agree.

### 5.2 Passwords

`identity.CheckPassword(policy, user, candidate, history)` is the single check, called by signup, change-password, password reset, the custom-DB create path and, later, user creation through the Management API (slice 4). Failures name the rule; hosted login shows localized messages (new keys for history, dictionary and personal info). The dictionary is an embedded list of common passwords from a permissively licensed source chosen in Task 1 (recorded in NOTICE), plus the connection's custom words, compared case-insensitively.

### 5.3 Management API

Auth0's shape, statuses and error codes as observed in Task 1 (`inexistent_connection`, conflicts, `invalid_body`, paging and `fields` per D-0039, the connection list's `strategy` and `name` filters). `options.configuration` values are sealed as today and never returned in plaintext (Auth0's behaviour observed and matched). API-created connections carry `origin: api`; the seed never touches them. Enabling clients through `PATCH /connections/{id}/clients` and through `enabled_clients` changes the same data.

### 5.4 Trying a script

`POST /api/system/tenants/{tenant}/connections/{id}/scripts/{name}/try` (operators only, on the system host): runs the connection's script through the existing runner with the operator's test input and the connection's real configuration, and returns the result or the error and console output. Rate-limited per operator, logged to the server log, never stored. Auth0 has no Management API for this; it is a documented zeroauthy extension (decision log).

### 5.5 Console

Original look and wording, the Plan 13/14 patterns:
- **List:** server-paged; name, strategy, number of enabled applications.
- **Create:** name, then the observed defaults.
- **Detail:**
  - **Settings:** display name, disable sign-ups, requires username and its length limits, domain connection, root-attribute sync; the stored-not-enforced options in their own labelled group.
  - **Password policy:** length, character classes, history size, dictionary (on/off, custom words), no personal info; a live checker shows which rules a sample password breaks, computed in the browser from the same rules, never sent.
  - **Custom database:** on/off, import mode, a code editor per script (a monospace textarea with line numbers; no new dependency), configuration key/values (values write-only after save), and "Try" per script (§5.4).
  - **Applications:** a switch per application.
  - **Danger zone:** delete by typing the name; the warning states how many users go with it.
- **Application detail** gains a **Connections** tab.
- Every setting carries a one-line explanation in zeroauthy's words.

## 6. Security

- Configuration secrets never leave the server in plaintext.
- Editing scripts needs `update:connections`; trying them needs an operator token.
- Deleting a connection deletes users: the console asks for the typed name and shows the user count.
- The dictionary check and history comparison run on the server; history keeps hashes only.

## 7. Testing

- storetest: delete cascade, password history, `Extra` round trip, in every driver.
- Unit tests for `connrules` and `CheckPassword` (each rule, combinations, localized messages).
- Management API tests per operation and field from Task 1; the contract test extended.
- Vitest per console screen (loading, empty, error, validation, success; the live checker; system read-only cases).
- E2E: the `auth0 connections` commands and `enabled-clients`; a Playwright flow creating a connection, enabling an application, setting a strict policy, then signing up (refused, then accepted) and trying a custom-DB script.
- `make conformance` stays at exit 0.

## 8. Documentation

`docs/management-api.md`, `docs/console.md`, `docs/compat/matrix.md`, a decision (D-0042 onward) for the observed behaviour and the differences, the "Try" extension and the stored-not-enforced list; Plan 15 follow-ups.
