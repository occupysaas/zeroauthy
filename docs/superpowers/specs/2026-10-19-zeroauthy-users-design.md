# zeroauthy — Design: Management API and console, slice 4 (users)

- **Status:** Draft for maintainer review (2026-10-19), input for Plans 17 and 18
- **Date:** 2026-10-19
- **Scope:** slice 4 of the management program (`2026-10-18-zeroauthy-management-design.md` §2). Slices 1–3 (applications, APIs and client grants, database connections) and the console frame (Plan 16) are done.

## 1. Goal and maintainer rulings

**Goal:** a 1:1, drop-in replacement for Auth0's Management API user surface. A script, SDK or tool written against Auth0's `/api/v2/` user endpoints works against zeroauthy with only the domain changed.

Rulings from the 2026-10-19 conversation:
- **Parity first.** Where this design and Auth0 differ, Auth0 wins; every deviation is a logged decision (see [auth0-parity-first]).
- **Password hashes are imported, the way Auth0 does it.** This reverses the 2026-10-18 ruling "no password-hash import; forced reset" (management design §1 anti-goals, §2 slice 4). The import accepts Auth0's `password_hash` and `custom_password_hash` formats. Plaintext passwords are never accepted in an import file.
- **No zeroauthy-only "bulk send reset emails" action.** Auth0 has none; the console uses Auth0's own endpoints (§5.6).
- **Branding and custom domains are next, not now.** Auth0-compatible page templates (`/api/v2/branding/templates/universal-login`), theme settings, `/api/v2/prompts` custom text, and `/api/v2/custom-domains` with automatic certificates get their own designs after this slice. They matter for the maintainer's own use (login stays on the brand's domain, with the brand's look) and for a later hosting offer.
- Follow-ups that this slice makes doable are folded in (§7).

**Success:**
- `auth0 users search/create/show/update/delete` and `auth0 users import` (auth0-cli, pinned version from Plans 13–15) work against zeroauthy unchanged.
- node-auth0's `users`, `usersByEmail`, `tickets`, `jobs` and `grants` managers work unchanged (E2E).
- An Auth0 user export with bcrypt hashes is imported, and an imported user signs in with their old password; the stored hash is upgraded to zeroauthy's argon2id on that first sign-in.
- An operator finds a user in the console by a search query, edits the profile and metadata, blocks them, ends their sessions, and creates a password-change link.

## 2. Sources (clean room)

- Auth0's public Management API reference for every endpoint in §3, and the public docs on user search (query syntax, searchable fields), bulk user import (the import schema, `custom_password_hash` algorithms), bulk user export, and user profile structure.
- The Apache-2.0 OpenAPI description (NOTICE).
- `auth0-cli`, `go-auth0` and `node-auth0` sources (MIT): which fields they send and read.
- **Observation** on the maintainer's dev tenant (Plan 17 Task 1; the tenant is not live, so test users can be created and deleted). The observer M2M application needs `read/create/update/delete:users`, `read/update:users_app_metadata`, `create:user_tickets`, `read/delete:grants`, `read/delete:sessions` and `read/delete:refresh_tokens` (the jobs endpoints use the user scopes, per Auth0's reference); the maintainer adds any it lacks. Pace requests, clean up, and keep the observer separate from the implementers (CLEAN_ROOM.md).

## 3. Scope

### 3.1 In

**Users** (`read:users`, `create:users`, `update:users`, `delete:users`, plus `read:users_app_metadata` and `update:users_app_metadata` where Auth0 enforces them):
- `GET /api/v2/users`: `q` with `search_engine=v3` (§5.2), `page`, `per_page`, `include_totals`, `sort`, `connection`, `fields`, `include_fields`; Auth0's limit on how deep paging can go.
- `POST /api/v2/users`, `GET/PATCH/DELETE /api/v2/users/{id}`.
- `GET /api/v2/users-by-email`.
- `POST /api/v2/users/{id}/identities` (link) and `DELETE /api/v2/users/{id}/identities/{provider}/{user_id}` (unlink). Only database identities exist until slice 6, but database-to-database linking is real on Auth0 and is in.
- `GET/DELETE /api/v2/users/{id}/sessions`, `GET /api/v2/sessions/{id}`, `DELETE /api/v2/sessions/{id}`.
- `GET/DELETE /api/v2/users/{id}/refresh-tokens`, `GET/DELETE /api/v2/refresh-tokens/{id}`.

**Grants:** `GET /api/v2/grants` (filters `user_id`, `client_id`, `audience`, paging), `DELETE /api/v2/grants/{id}`, `DELETE /api/v2/grants?user_id=`. These read and delete the user grants from Plan 9.

**Tickets** (`create:user_tickets`):
- `POST /api/v2/tickets/password-change` (`user_id`, or `email` plus `connection_id`; `result_url`, `ttl_sec`, `mark_email_as_verified`, `includeEmailInRedirect`, `client_id`). Reuses the existing reset ticket flow and page.
- `POST /api/v2/tickets/email-verification` (`user_id`, `result_url`, `ttl_sec`, `includeEmailInRedirect`, `identity`, `client_id`). New: an email-verification ticket and the page that consumes it (§5.5).

**Jobs** (Plan 18; scopes as Auth0's reference lists them per endpoint):
- `POST /api/v2/jobs/users-imports` (multipart: `users` file, `connection_id`, `upsert`, `external_id`, `send_completion_email`).
- `POST /api/v2/jobs/users-exports` (`connection_id`, `format` `json` or `csv`, `limit`, `fields`).
- `POST /api/v2/jobs/verification-email` (`user_id`, `client_id`, `identity`).
- `GET /api/v2/jobs/{id}` and `GET /api/v2/jobs/{id}/errors`.

**Verification emails**, the long-standing Plan 5 follow-up: the email template, sending on `verify_email`, and the Plan 8 `verify` custom-DB script call.

**Console:** Users list with search; create user; user detail; Import and export (§6).

### 3.2 Out (each to a later slice or design)

- Roles, permissions and organizations on users (`/users/{id}/roles|permissions|organizations`): RBAC and organizations designs.
- MFA endpoints (`enrollments`, `multifactor`, `authentication-methods`, `recovery-code-regeneration`, `invalidate-remember-browser`).
- `/users/{id}/logs`: logs design.
- `/user-blocks`: belongs with brute-force protection in slice 5 (attack protection).
- Phone numbers as login identifiers, and SMS. `phone_number` and `phone_verified` are stored and returned (as Auth0 allows on database users with flexible identifiers), not used for login.
- `federated-connections-tokensets`, social identities (slice 6).

## 4. Data model

- **`store.User`** gains `PhoneNumber`, `PhoneVerified`, `LastIP`, and any profile field Task 1 shows Auth0 returning for database users that is missing today. `RecordLogin` records the IP.
- **`store.Identity`** gains the imported hash: `PasswordHash` keeps argon2id PHC strings for native hashes; a new `ImportedHash` (JSON: algorithm and parameters as in Auth0's `custom_password_hash`, or a bcrypt string from `password_hash`) holds an imported hash until first sign-in. Only one of the two is set.
- **`Users.List(ctx, tenantID, q UserQuery, sort UserSort, p Page) ([]*User, int, error)`**: `UserQuery` is a parsed query tree (§5.2), not a string, so every driver gets the same semantics. Memory evaluates the tree; SQL drivers translate it, with JSON paths for `app_metadata` and `user_metadata`; the gRPC protocol carries the tree as a proto message.
- **`Users.Delete(ctx, tenantID, userID)`**: cascades as `Connections.Delete` does per user (sessions, refresh tokens, user grants, reset and verification tickets, password history, auth codes and device codes for the user).
- **`Users.FindByEmail(ctx, tenantID, email)`** across connections, for `users-by-email`.
- **Store-level user version** (Plan 5 finding): a counter bumped on password change, block, and delete-sessions; refresh and password grants check it in the same transaction that mints, closing the reset race.
- **`SetPasswordHashIfEmpty`** (Plan 8 finding): the import-login versus reset race; a set-if-empty write so a reset that lands first wins.
- **Email verification tickets:** a table alongside password reset tickets (token hash, user, identity, result URL, expiry, used at).
- **Jobs:** a `jobs` table (id, tenant, type, status `pending|processing|completed|failed`, connection, parameters, summary counts, created/updated, export location and expiry) and `job_errors` (job, user record, errors). Workers claim jobs atomically (`Jobs.Claim` with a lease), so several `serve` processes can share the queue. Export files are stored as blobs in the store with a TTL and served by a signed, expiring URL.
- **Store-level client pagination and filtering** (Plan 13 follow-up): `Clients.List` takes the filter and `Page` as `Connections.List` does; `GET /api/v2/clients` stops paging in memory.
- **Migration 0014** (and following) on SQLite, PostgreSQL and MySQL; new proto fields and RPCs; plugins without them answer Unimplemented ("plugin too old"). storetest covers everything in every driver.

## 5. Behaviour

### 5.1 Shared rules

`internal/userrules` (new), in the pattern of `clientrules`, `apirules` and `connrules`: the field rules for create and update (email, username against the connection's username settings, password through `identity.CheckPassword`, picture URL, metadata size and key limits, `user_id` format when supplied), and which fields may change on which connection type. Signup (`/dbconnections/signup`, hosted signup) moves to these rules too, so every path agrees.

### 5.2 Search (`search_engine=v3`)

A parser for Auth0's documented v3 query syntax produces `UserQuery`:
- `field:value`, quoted phrases, `AND`/`OR`/`NOT` and parentheses, an implicit `AND`/`OR` exactly as Auth0 treats a bare space (Task 1);
- wildcards where Auth0 allows them (trailing `*`, Auth0's minimum length);
- ranges `[a TO b]`, `{a TO b}` for dates and numbers;
- `_exists_:field`;
- the documented searchable fields: `user_id`, `email`, `email_verified`, `name`, `given_name`, `family_name`, `nickname`, `username`, `phone_number`, `phone_verified`, `blocked`, `created_at`, `updated_at`, `last_login`, `logins_count`, `last_ip`, `identities.connection`, `identities.provider`, `identities.user_id`, `app_metadata.*`, `user_metadata.*` (Auth0's metadata search rules).

Errors and edge cases (unknown field, bad syntax, `search_engine=v1`/`v2`, the paging depth limit) match Auth0's codes and messages from Task 1. Search is immediately consistent; Auth0's is eventually consistent. That difference only makes zeroauthy return newer results and is logged as a decision, not imitated.

### 5.3 Create, update, delete

As Auth0 documents and Task 1 confirms:
- **Create** needs `connection`; password is checked by the connection's policy; `verify_email` sends the verification email; `email_verified` may be set; `user_id` may be supplied (Auth0 prefixes it with `auth0|`).
- **Update:** `user_metadata` and `app_metadata` merge at the top level, with `null` deleting a key; `password`, `email`, `username` changes need `connection` where Auth0 needs it; `blocked: true` ends nothing by itself unless Task 1 shows otherwise, but the user version bump stops new tokens; whether a password change revokes refresh tokens or sessions follows Task 1.
- **Custom databases** (Plan 8 follow-up): on a connection with database customization and not in import mode, create calls the `create` script, delete calls `delete`, an email change calls `change_email`, a password change calls `change_password`, and verification calls `verify`. Failures map to Auth0's errors.
- **Delete** cascades (§4). Deleting the last identity deletes the user.

### 5.4 Linking

`POST /users/{id}/identities` with `provider` plus `user_id` (or `link_with` token, which needs ID-token verification from the tenant), as Auth0: the secondary user's profile is folded into the primary's `identities` and the secondary user stops existing as its own record. Unlink restores it. Login through a linked identity resolves to the primary user.

### 5.5 Tickets and verification

- **Password change ticket:** returns `{"ticket": "<url>"}` pointing at the existing reset page; `ttl_sec` default and maximum per Auth0 (Task 1); `result_url` and `includeEmailInRedirect` honoured after success.
- **Email verification:** a new hosted page at Auth0's path (Task 1 records it) consumes the ticket, sets `email_verified`, runs the `verify` script on custom databases, then redirects to `result_url` or shows a success page. Localized through the existing catalog. The "verify email" template uses the existing email driver and catalog.
- **`jobs/verification-email`** sends the same email asynchronously and returns a job.

### 5.6 Import and export (Plan 18)

**Import**
- The file is Auth0's import schema (JSON array), with Auth0's size limit and per-tenant concurrent-job limit (Task 1).
- Each user is validated by `userrules`; a failing record goes to `job_errors` with Auth0's error codes, and the rest continue.
- `upsert: false` refuses existing users (by email in the connection); `upsert: true` updates them as Auth0 documents (which fields upsert may change).
- **Hashes:** `password_hash` (bcrypt) and `custom_password_hash` with Auth0's documented algorithms (argon2, bcrypt, hmac, ldap, md4, md5, sha1, sha256, sha512, pbkdf2, scrypt, and any others in the docs at build time), including salt position, encodings, key and digest parameters. A scheme that carries the password in clear (for example an LDAP `{CLEARTEXT}` value) is refused for that record. A user with neither hash is created without a password and gets one through reset.
- **First sign-in** verifies against the imported hash in constant time, then stores an argon2id hash and clears the imported one (Auth0 rehashes to bcrypt; zeroauthy uses its own native hash, a logged decision). The password policy is not applied to imported passwords, as on Auth0.
- `send_completion_email` emails the operators whose tenant list covers the tenant (zeroauthy has no tenant admins otherwise; a logged decision).
- `mfa_factors` in the file are refused or ignored as Task 1 shows Auth0 does on a tenant without MFA; zeroauthy has no MFA yet.

**Export**
- `format` `json` writes newline-delimited JSON, `csv` writes CSV, both gzipped, with `fields` and `export_as` as Auth0. No password hashes are ever exported (as on Auth0).
- The job's `location` is a signed URL on the tenant host, valid for Auth0's lifetime (Task 1), served without a token. Auth0's points at its file storage; the path is zeroauthy's own, the behaviour (a plain GET that downloads the file) is the same.

**Workers:** a pool in each `serve` process claims jobs from the store; a crashed worker's lease expires and the job is retried once, then marked failed.

### 5.7 Errors, scopes and paging

Auth0's management error shape and codes (`inexistent_user`, `invalid_query_string`, `invalid_body`, `user_exists`, `operation_not_supported`, …) from the reference and Task 1. Scopes per endpoint as Auth0's reference lists them. Page/offset paging and `include_totals` as D-0039; checkpoint paging (`from`, `take`) on sessions, refresh tokens and grants where Auth0 offers it.

## 6. Console

Original look and wording on the Plan 16 frame; the Users preview page becomes live. Patterns of Plans 13–15.

- **Users list:** a search box that sends the text as a v3 query (with a link to the query help in `docs/`), connection filter, server paging, sort; columns name/email, connection, logins count, last login, blocked tag. Buttons: Create user, Import and export.
- **Create user:** connection (database connections only), email, password with the connection's live password checker (from Plan 15), username when the connection requires one, "send verification email".
- **User detail:**
  - **Details:** profile fields, email and verification state, phone (stored only), created, last login and IP, logins count; editing through `PATCH`.
  - **Metadata:** `user_metadata` and `app_metadata` as JSON editors (the Plan 15 monospace editor) with validation before save.
  - **Identities:** list; link another database user; unlink.
  - **Sessions and devices:** sessions and refresh tokens, revoke one or all.
  - **Authorized applications:** user grants, revoke.
  - **Raw JSON:** the `GET` response.
  - **Actions menu:** block/unblock, change password, change email, create password-change link (shows the ticket URL to copy), send verification email, delete (type the email to confirm).
- **Import and export:** upload a file, choose the connection, upsert and completion-email switches; the jobs list with status, summary and errors; export with connection, format and field picker, and a download link while it is valid.
- The sidebar's Users item turns live.

## 7. Follow-ups folded in

| From | Item |
|---|---|
| Plan 5 | Email verification emails (§5.5). |
| Plan 5 finding | Store-level user version, so a grant racing a reset or block cannot mint (§4). |
| Plan 8 | Callers for the `delete`, `change_email` and `verify` scripts (§5.3, §5.5). |
| Plan 8 finding | Import-login versus reset race: set-if-empty hash write (§4). |
| Plan 9 | Auth0 stored a user grant after a first-party login with no screen: re-check with `GET /grants` in Task 1 and align or log. |
| Plan 9 | Re-check Management API defaults (O1) with a client-credentials login; done in Task 1 with the observer M2M app. |
| Plan 13 | Store-level client pagination and filtering (§4). |
| Plan 15 | E2E confirms through `/api/v2/users` that deleting a connection deleted its users. |
| Plan 2 | "bcrypt hash verification and upgrade for imported users" (§5.6). |

Not folded in: the change-password send limit and login throttles in the store (multi-instance work), `/user-blocks` (slice 5), the prompts custom-text API (branding design).

## 8. Plans

The slice is big, so it is split:
- **Plan 17 — users:** Task 1 observation (U-points, below); store changes (user fields, list with query tree, delete cascade, user version, set-if-empty, verification tickets, client paging); the v3 parser; `/users`, `/users-by-email`, identities, sessions, refresh tokens, `/grants`, tickets; verification email and page; custom-DB script callers; console Users list, create and detail.
- **Plan 18 — jobs:** the jobs store and workers; imports with every Auth0 hash algorithm and first-sign-in upgrade; exports and the signed download; `jobs/verification-email`; console Import and export; `auth0 users import` and node-auth0 jobs E2E.

**Task 1 observation points (Plan 17)**, recorded in `docs/compat/observations/management-users.md` in our own words:
U1 user response shape for a database user (every field, defaults for `picture`, `nickname`, `name`); U2 create defaults and errors (duplicate email, bad password, missing connection, supplied `user_id`); U3 PATCH merge rules for metadata, which fields need `connection`, and whether a password change or block revokes sessions or refresh tokens; U4 v3 query edge cases (bare spaces, wildcard minimums, unknown fields, paging depth limit and its error); U5 `users-by-email` case sensitivity; U6 ticket TTL defaults and maxima, ticket URL paths, `result_url` behaviour; U7 link/unlink responses; U8 sessions and refresh-token response shapes and checkpoint paging; U9 `/grants` after a no-screen first-party login (Plan 9); U10 import limits (file size, concurrent jobs), job and error shapes, upsert field rules, hash algorithm parameter names; U11 export file shape and `location` lifetime; U12 delete cascade visible through the API.

## 9. Security

- Imported hashes are never returned by any endpoint or export, and are replaced on first sign-in.
- Weak imported algorithms (md4, md5, sha1 without salt) are accepted for parity but flagged: the console's import screen and the job summary say how many users carry a weak hash, and the docs recommend a forced reset for them.
- Export download URLs are unguessable, signed, expiring, and logged.
- `app_metadata` reads and writes respect Auth0's split scopes.
- Every Management API write is logged with the actor, as in slices 1–3.

## 10. Testing

- storetest for every new store method in every driver, including the query tree over metadata.
- Unit tests for the v3 parser (a table of Auth0's documented examples and the Task 1 edge cases), `userrules`, each hash algorithm (vectors generated with independent tools and recorded in the test, never taken from Auth0), and the rehash.
- Management API tests per endpoint and the contract test.
- Vitest per console screen.
- E2E: `auth0 users ...` and `auth0 users import`; node-auth0 users, tickets, jobs and grants; Playwright: create a user, search, edit metadata, block, revoke sessions, create a reset link and use it; import a file with bcrypt and PBKDF2 users and sign in as each; verify an email through the ticket.
- `make conformance` stays at exit 0.

## 11. Documentation

`docs/management-api.md`, `docs/console.md`, `docs/compat/matrix.md`; a user-search query guide; an import guide (formats, hash algorithms, weak-hash advice); decisions D-0043 onward (observed behaviour, immediate-consistency search, argon2id upgrade, completion-email recipients, export URL path); Plans 17 and 18 follow-ups.

## 12. Left to the builder

- Package layout below `internal/mgmt` and the shape of `UserQuery` and its proto message.
- How the SQL drivers index metadata for search (generated columns, JSON indexes), as long as results agree across drivers.
- Job worker pool size and lease length.
- Console component breakdown and layout within the Plan 16 frame.
