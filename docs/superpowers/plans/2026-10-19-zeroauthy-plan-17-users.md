# zeroauthy Plan 17: Management API and console, slice 4a (users)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auth0's Management API user surface works against zeroauthy with only the domain changed: `/api/v2/users` (with v3 search), `/users-by-email`, identity linking, sessions, refresh tokens, `/grants` and tickets. Verification emails finally go out. Operators find, edit, block and manage users in the console. Jobs (import, export, `jobs/verification-email`) are Plan 18.

**Architecture:**
- **Storage:** `store.User` gains Auth0's missing profile fields and a `Version` counter. `Users` gains `List` over a parsed query tree, `Delete` with cascade, `FindByEmail` and `SetPasswordHashIfEmpty`. Sessions, refresh tokens and user grants gain per-ID reads and lists. There is a new `EmailVerificationTickets` repository, and `Clients.List` takes a filter and a page. Migration 0014, proto, every driver, storetest.
- **`internal/usersearch` (new):** the Auth0 v3 query parser. It produces `store.UserQuery`, and every driver evaluates that tree the same way.
- **`internal/userrules` (new):** the field rules for create, update and signup (pattern of `clientrules`, `apirules`, `connrules`).
- **`internal/mgmt/{users,user_identities,user_sessions,grants,tickets}.go`:** the endpoints, generated from `api/management.yaml`.
- **Hosted pages:** an email-verification page and email template next to the reset ones.
- **Console:** the Users section turns live (list, create, detail).
- **Task 1 settles undocumented Auth0 behaviour by observation** (CLEAN_ROOM.md). The controller session runs it as the observer, and implementers see only the notes.

**Tech stack:** as Plans 13–15. No new Go or npm dependencies.

**Spec:** `docs/superpowers/specs/2026-10-19-zeroauthy-users-design.md`. This plan argues from it, so read both. Background: `2026-10-18-zeroauthy-management-design.md`, D-0039 (error, paging and `fields` rules), D-0042.

## Global Constraints

- **Parity first.** Auth0 wins where this plan and Auth0 differ. Every deviation is a logged decision (D-0043 onward).
- **Wire shape is Auth0's:** paths, field names, defaults, statuses and error codes come from the reference and Task 1. The error body, offset paging (`page`, `per_page`, `include_totals`) and `fields`/`include_fields` follow D-0039. Checkpoint paging (`from`, `take`) is used where Auth0 offers it (U8).
- **Scopes per endpoint as Auth0's reference lists them:** `read:users`, `create:users`, `update:users`, `delete:users`, `read:users_app_metadata`, `update:users_app_metadata`, `create:user_tickets`, `read:grants`, `delete:grants`, `read:sessions`, `delete:sessions`, `read:refresh_tokens`, `delete:refresh_tokens`. Add any that are missing to `tenantsetup.ManagementAPIScopes`.
- **Search is `search_engine=v3` only.** `v1`/`v2` get Auth0's error (U4). Search is immediately consistent, which is a logged decision.
- **One query tree, one set of semantics:** memory evaluates `store.UserQuery`, and SQL drivers translate it. storetest runs the same query table against every driver.
- **One set of field rules** (`userrules`) for the Management API, `/dbconnections/signup` and hosted signup.
- **No password or hash ever leaves the server.** Every response, log line and console screen is free of `PasswordHash`.
- **Every Management API write is logged with the actor**, as in slices 1–3.
- **Store compatibility:** plugins without the new RPCs answer Unimplemented, reported as "plugin too old".
- **Console:** original look and wording (CLEAN_ROOM.md "Prohibited"), light and dark, keyboard accessible, its own CSP, tokens in memory, strings in the catalog.
- **Earlier constraints still apply:** `go test -race ./...`, `go vet ./...`, gofmt, `go generate ./...` with no diff, `make console` with no diff in `console/dist`, `make check-sources`, `make e2e` (with `E2E_CHROMIUM` where Playwright's Chromium is absent), the SQL suite where it can run, and `make conformance` at exit 0 once at the end.

## Review Focus

1. **Metadata search on values of mixed types:** `app_metadata.plan:pro` must match the same users on memory, SQLite, Postgres and MySQL, including users whose `plan` is a number, a boolean, an array containing `"pro"` or absent. JSON path quirks differ by driver. Pinned in Task 3 (`storetest` `TestUserQueryMetadataTypes`).
2. **Unlinking restores a usable user:** after link and then unlink, the secondary user can log in with its own password, keeps its metadata and gets a fresh `Version`. Its sessions and refresh tokens from before the link are gone. Pinned in Task 8 (`TestUnlinkRestoresLogin`).
3. **PATCH with an email change on a connection where another user has that email:** `409 user_exists` (or U3's code). Nothing is half-applied: no custom-DB `change_email` runs, and the password is not changed in the same request. Pinned in Task 7 (`TestPatchUserEmailConflictAtomic`).
4. **Deleting a user who is mid-login or mid-reset:** an open reset ticket, a verification ticket, an auth code and a device code for the user all stop working (`invalid_grant` or the expired-link page), and a later refresh fails. Pinned in Task 2 (storetest cascade) and Task 7 (`TestDeleteUserMidFlow`).
5. **Search input users type in a console box:** a bare word (`alice`), an email with `+` or `@`, a trailing space, unbalanced quotes or parentheses. Each gives either Auth0's result for that input (U4) or `400 invalid_query_string`, never a 500, and never a SQL error text in the message. Pinned in Task 5 (parser fuzz test `FuzzParse`, no panics) and Task 7 (`TestSearchBadInputIs400`).

---

### Task 1: Observe Auth0's Management API for users

The controller session runs this as the observer, with the observer M2M application from Plans 13–15 (`OBS_AUTH0_*` secrets) on the maintainer's dev tenant. The application needs the scopes in spec §2, and the maintainer adds any it lacks. Pace requests at about one per second, use only throwaway users, and delete every test user, grant and session afterwards. U10 and U11 feed Plan 18, but they are observed now while the observer session is set up.

**Files:** `docs/compat/observations/management-users.md` (new), `docs/compat/decisions.md` (D-0043 and on), this plan's Observed column.

| # | Question | Observed |
|---|---|---|
| U1 | Full `GET /users/{id}` for a database user: every field, defaults for `picture`, `nickname`, `name`, `identities[]` shape, `last_ip`, `phone_*` presence | |
| U2 | `POST /users`: defaults; errors for duplicate email, weak password, missing `connection`, bad email, supplied `user_id` (prefixing, allowed characters, length), `email_verified` + `verify_email` combinations, unknown properties | |
| U3 | `PATCH`: metadata merge (top level, `null` deletes, nested objects replaced?), fields that need `connection`, fields refused together (email + password), whether password change or `blocked: true` revokes sessions or refresh tokens, `app_metadata` without `update:users_app_metadata` | |
| U4 | v3 search: bare words, bare space, wildcard rules and minimum length, unknown field, `v1`/`v2`, `sort` syntax, the paging depth limit and its error, metadata value types, case sensitivity per field, `fields` with `q` | |
| U5 | `users-by-email`: case sensitivity, order, `fields`, unknown email (empty array?) | |
| U6 | Tickets: `ttl_sec` default and maximum, ticket URL path and query names, `result_url` and `includeEmailInRedirect` after success, `mark_email_as_verified`, `email` + `connection_id` form, the email-verification page path and its success screen | |
| U7 | Link and unlink: request forms (`provider`+`user_id`+`connection_id`, `link_with`), response bodies, errors (self link, already linked, other connection types), what happens to the secondary's metadata | |
| U8 | Sessions and refresh tokens: response shapes (`device`, `clients`, `authentication`, timestamps), offset vs checkpoint paging, errors for unknown IDs, status codes of the DELETEs | |
| U9 | `GET /grants` after a first-party login with no consent screen (Plan 9 open point); the grant shape and filters | |
| U10 | (Plan 18) Import limits (file size, concurrent jobs), job and error shapes, upsert field rules, hash algorithm parameter names | |
| U11 | (Plan 18) Export file shape, `location` lifetime | |
| U12 | Delete: status, cascade visible through the API (sessions, grants, refresh tokens of the user), unknown/malformed ID errors | |
| O1 | Re-check of the Plan 9 Management API defaults with a client-credentials token | |

- [ ] **Step 1:** Run U1–U12 and O1 (one user at a time, cleaned up).
- [ ] **Step 2:** Write the observation note and the decisions. Facts go in our own words, with no secrets, IDs or tenant names. The decisions cover the observed behaviour, immediate-consistency search, and anything that changes the "need" lists below.
- [ ] **Step 3:** Fill the Observed column. Commit with `docs(compat): observe the Management API for users`.

---

### Task 2: Store: user fields, delete cascade, user version, set-if-empty

**Files:** `internal/store/{types,store}.go`, memory, sqlstore (migration `0014_users.sql` in sqlite, postgres, mysql), grpcstore and `proto/store/v1/store.proto`, `pkg/store`, `pkg/storetest/users.go`, `pkg/storetest/user_delete.go` (new).

**Interfaces:**
- Produces:
  - `store.User` gains `PhoneNumber string`, `PhoneVerified bool`, `LastIP string`, `Version int64`, plus any profile field U1 shows is missing. `Version` is store-maintained: callers never set it, and `Update` ignores the caller's value.
  - `Users.RecordLogin(ctx, tenantID, userID string, at time.Time, ip string) error` replaces the old signature and sets `LastIP`. Update every caller.
  - `Users.SetPasswordHash` bumps `Version`.
  - `Users.SetPasswordHashIfEmpty(ctx, tenantID, userID, connection, hash string, at time.Time) error`: it returns `ErrConflict` when the identity already has a non-empty hash and changes nothing. On success it bumps `Version`.
  - `Users.Update` bumps `Version` when `Blocked` goes from false to true or `Email` changes.
  - `Users.BumpVersion(ctx, tenantID, userID string) (int64, error)` returns the new value, or `ErrNotFound`.
  - `Users.FindByEmail(ctx, tenantID, email string) ([]*User, error)` searches across connections, ordered by `UserID`. Callers pass the email lowercase.
  - `Users.Delete(ctx, tenantID, userID string) error`, all in one step: the user, sessions, refresh tokens, user grants, password reset tickets, email verification tickets (Task 4; add the clause when Task 4 lands), password history, unconsumed auth codes, and device codes that name the user. It returns `ErrNotFound` if absent. `Connections.Delete` now calls the same per-user cascade.

- [ ] **Step 1: Tests** (storetest): round trips of the new fields; `RecordLogin` IP; `Version` bumps on each of the four triggers and stays the same on other updates; `SetPasswordHashIfEmpty` racing `SetPasswordHash` (20 goroutines, exactly one outcome per call, final hash never overwritten by the if-empty write); `FindByEmail` across two connections; `Delete` cascade (Review Focus 4: each dependent record is gone, other users' records stay); tenant isolation; gRPC codec round trips.
- [ ] **Step 2: Implement** in every driver. Regenerate with `go generate ./...`.
- [ ] **Step 3: Run** the Go suite and `./scripts/test-sql.sh ./internal/store/... ./pkg/storetest/...`. Expected: PASS on sqlite, postgres, mysql.
- [ ] **Step 4: Commit** with `feat(store): user fields, delete cascade, user version and set-if-empty hash`.

---

### Task 3: Store: user list over a query tree

**Files:** `internal/store/userquery.go` (new: types and the in-memory evaluator, shared by memory and tests), `internal/store/store.go`, memory, `internal/store/sqlstore/userquery.go` (new: SQL translation per dialect), grpcstore and proto (`UserQuery` message), `pkg/storetest/user_list.go` (new).

**Interfaces:**
- Produces:
  ```go
  type QueryOp int // QueryAll, QueryAnd, QueryOr, QueryNot, QueryTerm, QueryPrefix, QueryRange, QueryExists
  type ValueKind int // KindString, KindBool, KindNumber, KindDate
  type UserQuery struct {
      Op     QueryOp
      Kids   []*UserQuery // And, Or (2+); Not (1)
      Field  string       // "email", "identities.connection", "app_metadata.plan", …
      Kind   ValueKind
      Value  string       // Term, Prefix (without the "*")
      Lo, Hi *string      // Range; nil = open
      LoIncl, HiIncl bool
  }
  type UserSort struct { Field string; Desc bool } // zero = Auth0's default order from U4
  ```
  `Users.List(ctx, tenantID string, q *UserQuery, s UserSort, p Page) ([]*User, int, error)`. A nil `q` means all users. The int is the match count before paging.
- Semantics (copy them into the doc comment): a term on a string field compares case-insensitively unless U4 says a field is case-sensitive. A term on a metadata path matches a scalar equal to the value, or an array containing it (Review Focus 1). `Exists` is true when the field is present and not null. `identities.*` matches if any identity matches. Ranges compare numbers as numbers and dates as RFC 3339 instants.

- [ ] **Step 1: Tests** (storetest `TestUserList*`): a shared table of about 40 query trees over a fixed set of 12 users, including every documented searchable field (spec §5.2), And/Or/Not nesting, prefix, open and closed ranges on `logins_count` and `created_at`, `_exists_`, and `TestUserQueryMetadataTypes` (Review Focus 1). Also cover sort on each sortable field in both directions, with ties broken by `user_id`; paging and totals; and tenant isolation.
- [ ] **Step 2: Implement.** SQL indexing of metadata is the builder's choice, as long as every driver passes the same table.
- [ ] **Step 3: Run** the Go and SQL suites. **Step 4: Commit** with `feat(store): user list over a query tree`.

---

### Task 4: Store: sessions, refresh tokens, grants, verification tickets, client paging

**Files:** `internal/store/{types,store}.go`, memory, sqlstore (append to migration 0014), grpcstore and proto, `pkg/storetest/{sessions,refresh_tokens,user_grants,clients}.go`, `pkg/storetest/email_verification_tickets.go` (new), `internal/mgmt/clients.go` (stop paging in memory), and every `Clients.List` caller.

**Interfaces:**
- Produces:
  - `LoginSession` gains the fields U8 shows Auth0 returns that we can fill. At least `UpdatedAt`, `LastInteractedAt`, `InitialIP`, `InitialUserAgent`, `LastIP`, `LastUserAgent`, set at create and at `Touch` (`Touch` gains `ip, userAgent string`).
  - `Sessions.Get(ctx, tenantID, id) (*LoginSession, error)` and `Sessions.ListByUser(ctx, tenantID, userID string) ([]*LoginSession, error)`, ordered by `CreatedAt`, then ID.
  - `RefreshTokens.Get(ctx, tenantID, id)`, `RefreshTokens.ListByUser(ctx, tenantID, userID string) ([]*RefreshToken, error)` (unrevoked and unrotated tokens only, ordered by `CreatedAt`, then ID), and `RefreshTokens.Revoke(ctx, tenantID, id string, at time.Time) error` (`ErrNotFound` if absent).
  - `UserGrantFilter{UserID, ClientID, Audience string}` and `UserGrants.List(ctx, tenantID string, f UserGrantFilter, p Page) ([]*UserGrant, int, error)`, ordered by ID.
  - `EmailVerificationTicket{TenantID, ID, TokenHash, UserID, Connection, ClientID, ResultURL, IncludeEmailInRedirect, Lang, ExpiresAt, UsedAt, CreatedAt}` and `Store.EmailVerificationTickets()` with `Create`, `GetByTokenHash`, `Consume`, `DeleteByUser`, `DeleteExpired`. These have the same contracts as `PasswordResetTickets`, and the sweeper covers them.
  - `PasswordResetTicket` gains `ResultURL string`, `IncludeEmailInRedirect bool` and `MarkEmailVerified bool`.
  - `ClientFilter{AppTypes []string; IsFirstParty *bool}` (the filters `GET /clients` applies today) and `Clients.List(ctx, tenantID string, f ClientFilter, p Page) ([]*Client, int, error)`, ordered by `CreatedAt`, then `ClientID` (today's handler order). A zero filter and zero page return everything, for the other callers.

- [ ] **Step 1: Tests** (storetest): each new method; ordering and filters; `Revoke` on rotated and revoked tokens; the ticket contract (copy the reset-ticket cases); `Users.Delete` and `Connections.Delete` now remove verification tickets; `Clients.List` filters and paging; the existing `GET /clients` tests unchanged.
- [ ] **Step 2: Implement. Step 3: Run** the Go and SQL suites. **Step 4: Commit** with `feat(store): sessions, refresh tokens, grants and verification tickets by user; client paging`.

---

### Task 5: `internal/usersearch`: the v3 query parser

**Files:** `internal/usersearch/{lex,parse,fields}.go`, `internal/usersearch/parse_test.go`, `internal/usersearch/fuzz_test.go`.

**Interfaces:**
- Consumes: `store.UserQuery`, `store.UserSort` (Task 3).
- Produces: `usersearch.Parse(q string) (*store.UserQuery, error)` and `usersearch.ParseSort(s string) (store.UserSort, error)`. Errors are `*usersearch.Error{Message string}` carrying Auth0's message text from U4. The handler maps them to `400 invalid_query_string`. `usersearch.Fields` maps each searchable field (spec §5.2) to its `ValueKind`, and to whether it is sortable and whether it allows a prefix.

- [ ] **Step 1: Tests:** a table of Auth0's documented query examples, each with its expected tree; every U4 edge case (bare words, bare space, wildcard minimum, unknown field, quoted phrases with escaped quotes, `NOT` precedence, `[a TO *]`); sort strings `field:1` and `field:-1`; `FuzzParse` (no panic, and every error is a `*usersearch.Error`) with a seed corpus of the Review Focus 5 inputs.
- [ ] **Step 2: Implement** a recursive-descent parser. Precedence: `NOT` > `AND` > `OR`, with bare juxtaposition as U4 decides. **Step 3: Run** `go test ./internal/usersearch/ -fuzz=FuzzParse -fuzztime=30s` plus the unit tests. **Step 4: Commit** with `feat(usersearch): Auth0 v3 user query parser`.

---

### Task 6: `internal/userrules`

**Files:** `internal/userrules/` (new), `internal/identity/database.go` (signup moves to the rules), `internal/dbconn/signup.go`, `internal/login/login.go` (hosted signup), tests.

**Interfaces:**
- Consumes: `identity.CheckPassword`, `identity.CheckUsername`, `identity.CheckEmail`.
- Produces:
  - `userrules.Create{Connection, Email, Username, Password, PhoneNumber, UserID, Name, GivenName, FamilyName, Nickname, Picture string; EmailVerified, PhoneVerified, Blocked *bool; VerifyEmail *bool; UserMetadata, AppMetadata map[string]any}`.
  - `userrules.CheckCreate(c *store.Connection, in *Create) []error`, which normalizes (lowercase email and username, default name and nickname per U1) and returns every problem.
  - `userrules.Patch` (the same fields as pointers, with metadata as `map[string]any` where a nil value deletes).
  - `userrules.CheckPatch(c *store.Connection, u *store.User, in *Patch) []error` and `userrules.ApplyPatch(u *store.User, in *Patch)` (top-level metadata merge per U3).
  - `userrules.MetadataLimits` holds Auth0's size and key rules.
  - The errors are `*userrules.FieldError{Code, Message string}` with U2's codes and messages.

- [ ] **Step 1: Tests:** each rule and limit from U2 and U3; the metadata merge (`null` deletes, nested objects replaced per U3); a `user_id` the caller supplies; a username on a connection without usernames; the existing signup tests (`internal/dbconn`, `internal/login`) unchanged.
- [ ] **Step 2: Implement.** Signup paths call `CheckCreate`. **Step 3: Run. Step 4: Commit** with `feat(userrules): shared user field rules`.

---

### Task 7: `/api/v2/users`, `/users-by-email`, custom-DB callers

**Files:** `api/management.yaml` (schemas and operations with `x-source`), `internal/mgmt/users.go` (new), `internal/mgmt/users_test.go`, `internal/server/mgmtapi.go`, `internal/customdb/client.go`, `internal/server/mgmt_users_test.go`, `internal/server/mgmt_contract_test.go`.

**Interfaces:**
- Consumes: Tasks 2–6.
- Produces:
  - Operations: `GET /users` (`q`, `search_engine`, `sort`, `connection`, paging, `fields`; depth limit per U4), `POST /users`, `GET/PATCH/DELETE /users/{id}`, and `GET /users-by-email`.
  - `mgmt.UserJSON(u *store.User) map[string]any` is the one response renderer (U1 shape, never a hash). Tasks 8–10 reuse it.
  - `customdb.Client` gains `Delete(ctx, conn, userID string) error`, `ChangeEmail(ctx, conn, email, newEmail string, verified bool) (bool, error)` and `Verify(ctx, conn, email string) (bool, error)`. Their argument order is Auth0's, as the runner already defines for these scripts.
- Rules: `app_metadata` is left out of reads without `read:users_app_metadata`, unless U3/U4 shows otherwise, and writes to it need `update:users_app_metadata`. `PATCH`'s password change goes through `CheckPassword` and `RecordPassword`. Revocation on password change or block follows U3. On a custom-DB connection that is not in import mode, create, delete, email change and password change call their scripts before the store write, and script failures map to Auth0's errors (U2/U3). `verify_email: true` sends the verification email (Task 10 provides the sender; until then the handler takes it through an interface `VerificationSender` that Task 10 implements).

- [ ] **Step 1: Tests:** each operation and field from U1–U5 and U12; `TestPatchUserEmailConflictAtomic` (Review Focus 3); `TestDeleteUserMidFlow` (Review Focus 4: a reset link, an auth code, a device code and a refresh token taken before the delete all fail after it); `TestSearchBadInputIs400` (Review Focus 5); the scope split for `app_metadata`; custom-DB create, delete, change email and change password with a stub script, including a thrown error; and the contract test extended.
- [ ] **Step 2: Implement. Step 3: Run** the Go suite, `go generate` with no diff, `make check-sources`. **Step 4: Commit** with `feat(mgmt): /api/v2/users and users-by-email`.

---

### Task 8: Identity linking

**Files:** `internal/mgmt/user_identities.go` (new), tests, `internal/identity/database.go` (login resolves linked identities), `internal/store` (only if the U7 model needs a new method; see below).

**Interfaces:**
- Consumes: Task 7's `UserJSON`.
- Produces: `POST /users/{id}/identities` (`provider` + `user_id` (+ `connection_id`), or `link_with`, which is an ID token verified against the tenant's keys and audience per U7) and `DELETE /users/{id}/identities/{provider}/{user_id}`, both with U7's response bodies (the primary's `identities` array).
- Model: linking moves the secondary's `Identity` (with its `PasswordHash`) into the primary's `Identities`, keeps the secondary's profile and metadata in that identity's `ProfileData map[string]any` (a new `Identity` field, stored as JSON), and deletes the secondary user row with the Task 2 cascade. Unlink recreates the secondary user from `ProfileData`. `Users.FindByLogin` already searches identities by connection, so a linked identity resolves to the primary. Bump both users' `Version`.

- [ ] **Step 1: Tests:** link by `user_id` and by `link_with`; U7's errors (self link, already linked, unknown secondary, a token from another tenant); login through the linked identity returns the primary; `TestUnlinkRestoresLogin` (Review Focus 2); storetest round trip of `ProfileData`.
- [ ] **Step 2: Implement. Step 3: Run** the Go and SQL suites. **Step 4: Commit** with `feat(mgmt): link and unlink user identities`.

---

### Task 9: Sessions, refresh tokens, grants

**Files:** `internal/mgmt/user_sessions.go` (new: sessions and refresh tokens), `internal/mgmt/grants.go` (new), tests, `internal/server/mgmtapi.go`, `internal/login` / `internal/session` (fill the new session fields on create and touch).

**Interfaces:**
- Consumes: Task 4's store methods.
- Produces: `GET/DELETE /users/{id}/sessions`, `GET/DELETE /sessions/{id}`, `GET/DELETE /users/{id}/refresh-tokens`, `GET/DELETE /refresh-tokens/{id}`, `GET /grants` (`user_id`, `client_id`, `audience`, paging), `DELETE /grants/{id}` and `DELETE /grants?user_id=`. Response shapes, paging and status codes come from U8 and U9. `DELETE /users/{id}/sessions` also calls `Users.BumpVersion`.

- [ ] **Step 1: Tests:** each operation from U8 and U9, including checkpoint paging over three pages; deleting a session ends the browser's SSO (the next `/authorize` with `prompt=none` returns `login_required`); deleting a refresh token makes the refresh grant return `invalid_grant`; IP and user agent recorded at login and at touch.
- [ ] **Step 2: Implement.** Align the Plan 9 grant recording with U9, or log a decision. **Step 3: Run. Step 4: Commit** with `feat(mgmt): user sessions, refresh tokens and grants`.

---

### Task 10: Tickets, verification email and page

**Files:** `internal/mgmt/tickets.go` (new), `internal/email/verify.go` and `internal/email/templates/verify_email.{html,txt}`, `internal/login/verify.go` (new page), `internal/login/reset.go` (ticket `result_url`, `includeEmailInRedirect`, `mark_email_as_verified`), `internal/ui` templates, the `internal/i18n` catalog (English plus every shipped locale with the English fallback marker the catalog test expects), `internal/dbconn/signup.go` and `internal/login/login.go` (send on signup per the connection and tenant settings Auth0 uses), tests.

**Interfaces:**
- Consumes: Task 4's `EmailVerificationTickets`, Task 7's `VerificationSender` and `customdb.Client.Verify`.
- Produces:
  - `POST /tickets/password-change` and `POST /tickets/email-verification`, which return `{"ticket": "<url>"}` with U6's TTL default and maximum.
  - The verification page at U6's path: GET shows a confirm button or consumes directly (per U6), sets `email_verified`, runs `verify` on custom-DB connections, then redirects to `result_url` (with `email`/`success`/`message` query parameters per U6) or shows the success page.
  - `email.Sender.SendVerifyEmail(ctx, msg email.VerifyEmail) error`.
  - `login.VerificationMailer` implementing `mgmt.VerificationSender`. Plan 18's `jobs/verification-email` reuses it.

- [ ] **Step 1: Tests:** each ticket field from U6; `user_id` form and `email` + `connection_id` form; a used ticket and an expired ticket show the localized error page; `result_url` redirect parameters; `mark_email_as_verified` on a password-change ticket; signup sends the email once; the email renders in two locales; `verify` script failure leaves `email_verified` false and shows the error page.
- [ ] **Step 2: Implement. Step 3: Run. Step 4: Commit** with `feat: email verification tickets, page and email; password-change tickets`.

---

### Task 11: User version in the grants

**Files:** `internal/oauth` (password grant, refresh grant, authorization-code grant, device-code grant), `internal/identity/database.go` and `internal/identity/custom.go` (import-mode login uses `SetPasswordHashIfEmpty`), `internal/login/reset.go`, `internal/dbconn/change_password.go`, tests.

**Interfaces:**
- Consumes: Task 2's `Version`, `BumpVersion`, `SetPasswordHashIfEmpty`.
- Produces: every grant that mints a refresh token or tokens for a user records `u.Version` when it loads the user. It then mints inside `store.WithTx`, which re-reads the user and returns `invalid_grant` (the error text the grant already uses for a blocked user) when `Version` changed or the user is blocked or gone. An import-mode first login that loses `SetPasswordHashIfEmpty` (`ErrConflict`) re-reads the user and verifies the password against the stored hash. Two concurrent submits of one reset ticket run `change_password` at most once, through `PasswordResetTickets.Consume` before the script call.

- [ ] **Step 1: Tests:** a password grant whose password check finishes before a reset completes, with the mint after it, gets `invalid_grant` (use a store wrapper that blocks between the user read and the tx); the same for `blocked: true` via PATCH; a refresh rotation racing `DELETE /users/{id}/sessions`; an import-mode login racing a reset (the reset hash wins, and the login fails with the old password); two concurrent reset submits call the stub `change_password` script once. Close the matching entries in `plan-1-followups.md`.
- [ ] **Step 2: Implement. Step 3: Run** with `-race -count=20` on the new tests. **Step 4: Commit** with `fix: user version closes the reset, block and import-login races`.

---

### Task 12: Console: users list and create

**Files:** `console/src/pages/users/{List,Create,SearchHelp}.vue` with tests, `console/src/api/client.ts` and `schema.d.ts` (regenerated), `console/src/router.ts`, the sidebar (Users turns live), `console/src/locales/*`, `console/dist`. Remove `console/src/pages/planned/Users.vue` and its entries.

**Screens** (spec §6): a list with a search box that sends the text as `q` with `search_engine=v3`, a link to the query guide (Task 15), a connection filter, server paging, sort, and the columns name/email, connection, logins count, last login and a blocked tag. Create takes the connection (database connections only), email, password with the Plan 15 live checker (`pages/connections/checker.ts`), username when the connection requires one, and "send verification email".

- [ ] **Step 1: Tests** (Vitest): loading, empty, error (a `400 invalid_query_string` shows the server message under the box), and paging states; the search text is sent unchanged and URL-encoded; create validation and success (it navigates to detail); the username field appears only when the connection requires it.
- [ ] **Step 2: Implement.** Rebuild `dist/`. **Step 3: Run** `make console`. **Step 4: Commit** with `feat(console): users list and create`.

---

### Task 13: Console: user detail

**Files:** `console/src/pages/users/{Detail,DetailsTab,MetadataTab,IdentitiesTab,SessionsTab,AppsTab,RawTab,ActionsMenu}.vue` with tests, strings, `console/dist`.

**Screens** (spec §6): Details (editable profile through `PATCH`, phone shown as stored-only), Metadata (two JSON editors reusing `pages/connections/CodeEditor.vue`, validated before save, with a top-level merge shown as a diff before saving), Identities (list, link another database user by search, unlink), Sessions and devices (sessions and refresh tokens, revoke one or all), Authorized applications (grants, revoke), and Raw JSON. The actions menu has block/unblock, change password, change email, create password-change link (shows the URL with a copy button and the TTL), send verification email, and delete (type the email to confirm; it shows what the cascade removes).

- [ ] **Step 1: Tests** (Vitest): each tab's loading, empty, error and success states; invalid JSON blocks save; deleting a metadata key sends `null`; the ticket URL is shown once and never stored in the Pinia store; delete stays disabled until the email matches; `app_metadata` editing is hidden for a caller without the scope.
- [ ] **Step 2: Implement.** Rebuild `dist/`. **Step 3: Run** `make console`. **Step 4: Commit** with `feat(console): user detail`.

---

### Task 14: E2E

**Files:** `tests/e2e/m17-mgmt-cli.mjs`, `tests/e2e/m17-node-auth0.mjs`, `tests/e2e/m17-console.spec.mjs`, `tests/e2e/run-m3.sh`, `tests/e2e/run-browser.sh`, `tests/e2e/seed.yaml`, `tests/e2e/package.json` (node-auth0 is already pinned for m3; reuse that version).

- [ ] **Step 1: auth0-cli v1.37.0:** `users create/search/show/update/delete` (search by email and by `app_metadata`), plus a Plan 15 follow-up check: deleting a connection removes its users, as seen through `users search`.
- [ ] **Step 2: node-auth0:** the `users` manager (create, getAll with `q`, get, update metadata, delete), `usersByEmail`, `tickets.changePassword`, `tickets.verifyEmail`, `grants.getAll`/`delete`, and `users.getSessions`/`deleteSessions`.
- [ ] **Step 3: Playwright:** sign in; create a user; find them by a search query; edit metadata; block them (their password login fails); unblock; revoke sessions; create a password-change link, open it in a fresh context and set a new password, then sign in with it; send a verification ticket and open it (`email_verified` shows true).
- [ ] **Step 4: Run** `make e2e`. **Step 5: Commit** with `test(e2e): users with auth0-cli, node-auth0 and the console`.

---

### Task 15: Documentation and final verification

**Files:** `docs/management-api.md`, `docs/console.md`, `docs/user-search.md` (new: the query guide the console links to, written from our own tests), `docs/compat/matrix.md`, `docs/superpowers/plan-1-followups.md` (close the folded-in items from spec §7 that this plan covers; add "Plan 17 follow-ups"), README roadmap status.

- [ ] **Step 1: Write the docs.**
- [ ] **Step 2: Verify:** gofmt, vet, `go test -race ./...`, `go generate` no diff, `make console` no diff, the SQL suite, `make e2e`, `make check-sources`, and `make conformance` (exit 0, or say exactly why it cannot run).
- [ ] **Step 3: Commit** with `docs: users; Plan 17 records`.
