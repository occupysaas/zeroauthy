# zeroauthy Plan 18: Management API and console, slice 4b (jobs)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auth0's jobs endpoints work against zeroauthy with only the domain changed: bulk user import with every Auth0 password-hash format (and an upgrade to argon2id at first sign-in), bulk user export with a short-lived download link, and `jobs/verification-email`. Operators import and export from the console. `auth0 users import` and node-auth0's `jobs` manager work unchanged.

**Architecture:**
- **Storage:** a new `Jobs` repository (jobs, per-record errors, export file chunks) with an atomic, leased `Claim`, so several `serve` processes share one queue. `store.Identity` gains `ImportedHash`; `Users.UpgradeImportedHash` swaps it for an argon2id hash with compare-and-swap. Migration 0015, proto, every driver, storetest.
- **`internal/passhash` (new):** parses Auth0's `password_hash` and `custom_password_hash` into a `Spec` and verifies a password against it. Argon2d, Whirlpool and MDC-2 have no Go standard implementation: argon2 is vendored from `golang.org/x/crypto` (BSD-3, NOTICE) with the `d` mode exported, Whirlpool and MDC-2 are written in-tree from their published specifications.
- **`internal/jobs` (new):** the worker pool (one per `serve` process), and the three processors: import, export, verification email. The import processor works in batches, each in one transaction with its checkpoint, so a retried job resumes where the lost worker stopped.
- **`internal/mgmt/jobs.go`:** the endpoints, generated from `api/management.yaml`. Export files are downloaded from a signed, expiring URL on the tenant host.
- **Console:** an Import and export page under Users, and the "Send verification email" action on user detail.
- **Task 1 settles what U10 and U11 left open, by observation** (CLEAN_ROOM.md). The controller session runs it as the observer, and implementers see only the notes.

**Tech stack:** as Plan 17. Go: `golang.org/x/crypto` (already a dependency: `bcrypt`, `scrypt`, `md4`, `ripemd160`), the standard `crypto/pbkdf2`, `crypto/hmac`, `crypto/des`, `compress/gzip`, `encoding/csv`, `mime/multipart`. No new modules. E2E: Python 3 `hashlib`/`hmac` and `openssl` in podman generate the hash vectors (never Auth0's examples).

**Spec:** `docs/superpowers/specs/2026-10-19-zeroauthy-users-design.md` (§3.1 Jobs, §4 Jobs and `ImportedHash`, §5.6, §6 Import and export, §9). This plan argues from it, so read both. Background: D-0039 (errors, paging), D-0043 (users), `docs/compat/observations/management-users.md` (U10, U11).

**Sources read for this plan (2026-10-20):** Auth0's reference pages for `POST /jobs/users-imports`, `POST /jobs/users-exports`, `GET /jobs/{id}`, `POST /jobs/verification-email`; the docs pages "Bulk user imports", "Bulk user import database schema and examples", "Bulk user exports"; the changelog through 2026-10-20 (no entry changes jobs; the 2026-09-17 entry confirms custom user IDs at signup do not apply to bulk import). Facts below are in our own words.

## Global Constraints

- **Parity first.** Auth0 wins where this plan and Auth0 differ; where Auth0's own sources disagree, observation (U10, U11, Task 1) wins, and each such case is a line in D-0044.
- **Wire shapes:** `POST /jobs/users-imports` → `202`; `POST /jobs/users-exports` → `200`; `POST /jobs/verification-email` → `201`; `GET /jobs/{id}/errors` → `200 []` for a completed import without errors, `204` with no body for an export, and `200` with the job object for a failed job (J9, which corrects U10). Job IDs match `^job_[A-Za-z0-9]{16}$`, anything else is `400 invalid_uri`. Connection IDs match `^con_[A-Za-z0-9]{16}$`.
- **Scopes (Auth0's reference):** import `create:users`; export `read:users`; verification email `update:users`; `GET /jobs/{id}` and `/errors` accept `create:users` or `read:users`.
- **Import limits (reference):** request body (multipart framing included) at most 512000 bytes (`413` above, J1), file not empty; JSON array; connection must exist, be a database connection, be enabled for at least one client, and on a custom database be in import mode; 2 concurrent import jobs per tenant; a job not finished 2 hours after its first claim is `failed`; job data (job, errors, files) deleted 24 hours after creation.
- **Import schema (docs):** the top-level properties are exactly `email` (required), `email_verified`, `phone_number`, `phone_verified`, `user_id`, `username`, `given_name`, `family_name`, `name`, `nickname`, `picture`, `blocked`, `password_hash`, `custom_password_hash`, `app_metadata`, `user_metadata`, `mfa_factors`; unknown top-level properties are ignored (U10, which wins over the schema's `additionalProperties: false`). `password_hash` and `custom_password_hash` are mutually exclusive. `app_metadata` may not hold `__tenant`, `_id`, `blocked`, `clientID`, `created_at`, `email_verified`, `email`, `globalClientID`, `global_client_id`, `identities`, `lastIP`, `lastLogin`, `loginsCount`, `metadata`, `multifactor_last_modified`, `multifactor`, `updated_at`, `user_id`.
- **Hash formats (docs):** algorithms `argon2`, `bcrypt`, `hmac`, `ldap`, `md4`, `md5`, `sha1`, `sha256`, `sha512`, `pbkdf2`, `scrypt`; `hash.encoding` `base64|hex|utf8`; `salt.encoding` `base64|hex|utf8` (default `utf8`), `salt.position` `prefix|suffix` (default `prefix`); `password.encoding` `ascii|utf8|utf16le|ucs2|latin1|binary` (default `utf8`); HMAC digests `md4, md5, ripemd160, sha1, sha224, sha256, sha384, sha512, whirlpool` with `hash.key.value` and `key.encoding` (default `utf8`); scrypt `keylen` required, `cost` default 16384 (power of two > 1), `blockSize` default 8, `parallelization` default 1; pbkdf2 PHC `$pbkdf2-<digest>$i=…,l=…$salt$hash` with defaults `i=100000`, `l=64` and the documented digest list (including the `RSA-*`, `*WithRSAEncryption`, `ssl3-*` aliases, `mdc2`, `ripemd*`, `rmd160`, `whirlpool`); argon2 PHC strings (`argon2i`, `argon2d`, `argon2id`), no `salt`; ldap RFC 2307 with `{MD5}`, `{SMD5}`, `{SHA}`, `{SSHA}` and the `{SHA256|384|512}`/`{SSHA…}` forms, `{CRYPT}` refused; bcrypt `$2a$|$2b$|$2y$`, optional `salt`, the 72-byte input limit includes the salt. `password_hash` matches `^\$2[ab]?\$10+\$[./A-Za-z0-9]{53}$` (U10).
- **Never plaintext, never out.** A record whose hash carries the password in clear is refused. No endpoint, export, job error, log line or console screen shows a hash: job errors mask `password_hash` and `custom_password_hash.hash.value` as `*****` (U10).
- **Export (reference + U11):** body `connection_id`, `format` (`json|csv`), `limit` (≥1), `fields[]` of `{name (≤100), export_as (≤100)}`; no `connection_id` exports every connection (U11, wins over the reference's default); gzipped NDJSON or CSV; CSV at most 30 fields, metadata only by subfield, default columns as U11 lists, strings quoted with a leading `'` and doubled inner quotes, numbers, booleans and our own ISO dates bare; `location` valid 60 seconds; no password hash ever exported.
- **Every Management API write is logged with the actor**; every export download is logged with the job and tenant.
- **Store compatibility:** plugins without the new RPCs answer Unimplemented, reported as "plugin too old".
- **Console:** original look and wording (CLEAN_ROOM.md "Prohibited"), light and dark, keyboard accessible, tokens in memory, strings in the catalog.
- **Earlier constraints still apply:** `go test -race ./...`, `go vet ./...`, gofmt, `go generate ./...` with no diff, `make console` with no diff in `console/dist`, `make check-sources`, `make e2e` (with `E2E_CHROMIUM` where Playwright's Chromium is absent), the SQL suite (`./scripts/test-sql.sh`; use the 55999/53999 copy if the default ports are taken), and `make conformance` at exit 0 once at the end.

## Review Focus

1. **First sign-in racing an upsert that replaces the imported hash:** exactly one wins. If the sign-in's upgrade commits first, the upsert record fails with Task 1's code (Auth0: the hash can only be replaced before the user signed in with it). If the upsert commits first, the sign-in's compare-and-swap fails, it re-reads the user and verifies against the new imported hash. The user never ends up with no hash. Pinned in Task 5 (`TestUpgradeRacesUpsert`, `-race -count=20`).
2. **A worker dies mid-import:** the lease expires, a second worker claims the job and resumes at the last checkpoint. Users from committed batches are neither inserted twice nor reported as `DUPLICATED_USER`; summary totals equal the file's record count. A second loss marks the job `failed`. Pinned in Task 6 (`TestJobLeaseRetryOnce`) and Task 7 (`TestImportResumesAfterLeaseExpiry`).
3. **Passwords that are not plain ASCII under a non-UTF-8 `password.encoding`:** `latin1`/`binary` with a character above U+00FF, `ascii` with any non-ASCII character, `utf16le` with a character outside the BMP. Each is converted the way Node's `Buffer.from(password, encoding)` converts it (Auth0's documented encodings are Node's), so the verify gives the answer the original system gave, never a panic. Pinned in Task 3 (`TestPasswordEncodings`, vectors from Python's codecs that mirror Node's lossy rules, recorded in the test).
4. **Hostile values in a CSV export:** `=cmd|…`, `+`, `-`, `@` leading characters, embedded quotes, commas, newlines, and non-string metadata subfields (number, boolean, object, array). Strings get Auth0's `'` prefix and quoting, numbers and booleans are bare, object and array subfields are written as empty values (J8), and every row parses back with `encoding/csv` to the same number of columns. Pinned in Task 8 (`TestExportCSVHostileValues`).
5. **A malformed import file:** not JSON, a JSON object instead of an array, a UTF-8 BOM, NDJSON, an empty array, exactly 512000 and 512001 bytes. The create request answers `202` for every malformed file (only the empty file is `400` and only a body over 512000 bytes is `413`, J1); the job then ends `failed` with J2's `status_details`, or `completed` with `INVALID_TYPE` record errors for non-object entries. Never a 500 or a stuck `processing` job. Pinned in Task 7 (`TestImportBadFiles`).

---

### Task 1: Observe Auth0's jobs

The controller session runs this as the observer, with the observer M2M application (`OBS_AUTH0_*` fish variables, read via `fish -c`; they point at the maintainer's staging tenant, which is not live). The application already holds the user scopes from Plan 17. Pace requests at about one per second, use only throwaway users and a throwaway database connection, and delete every test user and the connection afterwards. Hash vectors for J5 are generated locally with Python and `openssl`, never copied from Auth0's docs.

**Files:** `docs/compat/observations/management-jobs.md` (new), `docs/compat/decisions.md` (D-0044), `docs/compat/changelog-review.md` (log the 2026-10-20 review: entries through 2026-10-20, none on jobs; the Plan 12–17 reviews were not logged, so note that this one covers 2026-10-16 to 2026-10-20), this plan's Observed column.

| # | Question | Observed |
|---|---|---|
| J1 | Import create errors: missing `users`, empty file, `connection_id` malformed / unknown / not a database / custom DB without import mode / no enabled clients, 512001 bytes; exact statuses, codes, messages | J1 table in the note; the limit is the whole body ≤512000 (`413`, no errorCode); loose `upsert` and unknown parts accepted |
| J2 | Malformed files (not JSON, object, BOM, NDJSON, `[]`): rejected at create or a `failed` job; the failed job's shape (`status_details`, `summary`) | all `202`; job `failed` with two `status_details` texts; `[]` completed; non-objects `INVALID_TYPE` |
| J3 | Concurrency: a third import while two are pending (status, code, message); `external_id` echo; `send_completion_email` default; `percentage_done`/`time_left_seconds` presence while pending and after | third active import `429` (no errorCode, Auth0's message); running jobs read `pending`, no progress fields; `external_id` echoed; email default not observable |
| J4 | Upsert `true`: which fields change (profile, `blocked`, `email_verified`, metadata overwrite, `username`, `user_id`), a new `custom_password_hash` before and after the user signed in, `password_hash` on an existing user; duplicates within one file; `user_id` in a record (prefix, conflict) | by email; names, `email_verified`, whole metadata replaced; `blocked`, `user_id`, `password_hash` ignored; `custom_password_hash` only before first sign-in, else `CONFLICT`; file duplicate `NON_UNIQUE_PROPERTY_VALUE`; `user_id` prefixed `auth0|` |
| J5 | Per-record errors for hash mistakes: unknown algorithm, wrong `hash.encoding` for the algorithm, scrypt without `keylen`, `salt` on argon2/pbkdf2/ldap, `{CRYPT}` and `{CLEARTEXT}` ldap, both hash fields; error `code`, `message`, `path`; masking | J5 table; `{CRYPT}` refused, `{CLEARTEXT}` and broken argon2 accepted; `PATTERN` message repeats the hash (we mask, D-0044) |
| J6 | Sign in after import with one bcrypt, one PBKDF2-SHA256 and one salted SHA-256 user (vectors generated locally); the user's `GET` afterwards; a weak password the connection's policy would refuse | bcrypt, PBKDF2, salted SHA-256, argon2id, MD5 all sign in, policy not applied; unusable hash → `invalid_grant` "Password change required." |
| J7 | `mfa_factors` in a record on a tenant without MFA: accepted, ignored or a record error | accepted and stored as enrollments (we ignore, D-0044) |
| J8 | Export: `limit` default and maximum, unknown `fields[].name`, more than 30 CSV fields, whole `user_metadata` in CSV, a metadata subfield holding an object/array/number in CSV and JSON, JSON default keys without `fields`, `export_as` in JSON | no default limit; `{}` = CSV of all connections; 30-field cap; unknown fields empty; CSV objects/arrays empty; `'`-prefixed strings; JSON dotted keys |
| J9 | `GET /jobs/{id}` of a completed export twice: a new `location` each time; `GET` after the 60 s; job `GET` after 24 h (or the documented answer if waiting is impractical: record which); an unknown well-formed ID | new `location` per read, 60 s; `404 inexistent_job`; errors `200 []` / `204` / job object |
| J10 | `POST /jobs/verification-email`: status in the response and on `GET` later, an already verified user, a user without email, an unknown user, `identity` for the primary identity, unknown properties | `201` pending for every valid case; J10 error table; fails without an email provider |

- [x] **Step 1:** Run J1–J10.
- [x] **Step 2:** Write the observation note and D-0044 (the observed behaviour; the conflicts it settles: `upsert: false` reports `DUPLICATED_USER` (U10) where the docs say "skipped", and no `connection_id` exports every connection (U11) where the reference names a default; the argon2id upgrade where Auth0 rehashes to bcrypt; completion-email recipients; the download URL path; the vendored argon2 and in-tree Whirlpool and MDC-2).
- [x] **Step 3:** Fill the Observed column. Commit with `docs(compat): observe the Management API jobs`.

---

### Task 2: Store: jobs, job errors, export files, imported hashes

**Files:** `internal/store/{types,store}.go`, memory (`jobs.go`), sqlstore (`jobs.go`; migration `0015_jobs.sql` in sqlite, postgres, mysql), grpcstore and `proto/store/v1/store.proto` (next free field numbers; `Jobs` RPCs), `pkg/store`, `pkg/storetest/jobs.go` (new), `pkg/storetest/users.go`, `internal/app/sweeper.go`.

**Interfaces:**
- Produces:
  ```go
  type JobType string   // JobUsersImport "users_import", JobUsersExport "users_export", JobVerificationEmail "verification_email"
  type JobStatus string // JobPending "pending", JobProcessing "processing", JobCompleted "completed", JobFailed "failed"
  type JobSummary struct{ Failed, Updated, Inserted, Total int }
  type Job struct {
      TenantID, ID string
      Type   JobType
      Status JobStatus
      ConnectionID, Connection, ExternalID string
      Params   map[string]any // the request's options, as the handler stored them
      Input    []byte         // the import file (≤512000 bytes); nil for other types
      Progress int            // records committed so far
      Summary  JobSummary
      StatusDetails string
      Attempts int
      LeaseOwner string
      LeaseUntil, FirstClaimedAt, CreatedAt, UpdatedAt, ExpiresAt time.Time
      FileSize int64 // bytes of the export file; 0 until written
  }
  type JobErrorItem struct{ Code, Message, Path string }
  type JobError struct{ Index int; User map[string]any; Errors []JobErrorItem } // User already masked
  ```
  `Store.Jobs() Jobs` with:
  - `Create(ctx, j *Job) error` (`ErrConflict` on the ID).
  - `Get(ctx, tenantID, id) (*Job, error)` (`ErrNotFound`, also once expired).
  - `List(ctx, tenantID string, p Page) ([]*Job, int, error)`, newest first (the console's list, Task 9).
  - `CountActive(ctx, tenantID string, t JobType) (int, error)`: pending plus processing.
  - `Claim(ctx, owner string, now time.Time, lease time.Duration) (*Job, error)`: across tenants, the oldest job that is pending, or processing with `LeaseUntil < now`; sets processing, owner, lease, `Attempts++`, `FirstClaimedAt` if zero. `ErrNotFound` when none. Two concurrent claims never return the same job.
  - `Renew(ctx, tenantID, id, owner string, until time.Time) error`: `ErrConflict` when `owner` no longer holds the lease.
  - `Checkpoint(ctx, tenantID, id, owner string, progress int, s JobSummary, errs []JobError) error`: lease-checked (`ErrConflict`), appends errors; callers run it in the same `WithTx` as the batch's user writes.
  - `Finish(ctx, tenantID, id, owner string, st JobStatus, details string, at time.Time) error`: lease-checked; clears the lease and `Input`.
  - `Errors(ctx, tenantID, id) ([]JobError, error)` in `Index` order.
  - `AppendFile(ctx, tenantID, id, owner string, seq int, chunk []byte) error` (chunks ≤1 MiB, so gRPC messages stay small) and `ReadFile(ctx, tenantID, id string, fn func(chunk []byte) error) error` in `seq` order.
  - `DeleteExpired(ctx, before time.Time) (int, error)`: jobs with `ExpiresAt < before`, their errors and chunks; jobs still processing past `FirstClaimedAt + 2h` are set `failed` with `status_details` from Task 1 (or "Job timed out" if Task 1 saw none), and processing jobs whose lease expired after their second attempt are set `failed`. The sweeper calls it.
  - `store.Identity` gains `ImportedHash string` (`json:",omitempty"`): canonical JSON of a `passhash.Spec` (Task 3), opaque to the store. Only one of `PasswordHash` and `ImportedHash` is non-empty.
  - `Users.UpgradeImportedHash(ctx, tenantID, userID, connection, imported, hash string, at time.Time) error`: on that identity, if `ImportedHash == imported`, sets `PasswordHash = hash`, clears `ImportedHash`, bumps `Version`; else `ErrConflict`, nothing changed.

- [ ] **Step 1: Tests** (storetest `TestJobs*`): create/get/list round trips (every field, `Params` with nested values); `CountActive`; `Claim` by 20 goroutines over 5 jobs (each job claimed once); a stale lease reclaimed with `Attempts == 2`; `Renew`, `Checkpoint`, `Finish`, `AppendFile` refused for a lost lease; `Checkpoint` rolled back with its transaction; chunks read in order; `DeleteExpired` removes errors and chunks, fails timed-out and twice-lost jobs, leaves others; tenant isolation; `ImportedHash` round trip; `UpgradeImportedHash` success, wrong `imported`, racing itself (one winner); gRPC codec round trips.
- [ ] **Step 2: Implement** in every driver; add `Jobs().DeleteExpired` to `sweep`. Regenerate with `go generate ./...`.
- [ ] **Step 3: Run** the Go suite and `./scripts/test-sql.sh ./internal/store/... ./pkg/storetest/...`. Expected: PASS on sqlite, postgres, mysql.
- [ ] **Step 4: Commit** with `feat(store): jobs with leased claims, job errors, export files, imported hashes`.

---

### Task 3: `internal/passhash`: parsing and the digest family

**Files:** `internal/passhash/{spec,parse,encoding,digest,hmac,ldap,bcrypt}.go`, `internal/passhash/*_test.go`, `internal/passhash/testdata/vectors.json` (generated by `scripts/gen-hash-vectors.py`, new, run in a podman Python image; the script and its output are committed).

**Interfaces:**
- Produces:
  ```go
  type Spec struct { // json tags are Auth0's custom_password_hash names
      Algorithm string    `json:"algorithm"`
      Hash      HashPart  `json:"hash"`      // Value, Encoding, Digest, Key *KeyPart
      Salt      *SaltPart `json:"salt,omitempty"` // Value, Encoding, Position
      Password  *PassPart `json:"password,omitempty"` // Encoding
      KeyLen, Cost, BlockSize, Parallelization int `json:",omitempty"` // keylen, cost, blockSize, parallelization
  }
  type FieldError struct{ Code, Message, Path string } // import error codes (Task 1 J5)
  func ParseCustom(raw json.RawMessage) (*Spec, []FieldError)
  func FromBcrypt(passwordHash string) (*Spec, []FieldError) // the U10 PATTERN rule, path "passwordHash"
  func (s *Spec) Verify(password string) (bool, error)          // constant-time compare; ErrUnusable for a value that cannot be parsed
  var ErrUnusable error // an accepted argon2 or pbkdf2 value that is not a valid PHC string (D-0044)
  func (s *Spec) Weak() bool  // md4, md5, sha1 without salt; ldap {MD5}/{SHA}
  func (s *Spec) Marshal() string; func Unmarshal(string) (*Spec, error)
  func (s *Spec) Masked(raw map[string]any) map[string]any // replaces hash values with "*****"
  ```
  `ParseCustom` applies every per-algorithm rule in Global Constraints and Task 1 J5 (which encodings, which parts are allowed or required) and refuses `{CRYPT}` and `{CLEARTEXT}` ldap values with `ONE_OF_MISSING` (path `custom_password_hash`; D-0044 for `{CLEARTEXT}`). Argon2 and pbkdf2 values are checked only for their `$argon2`/`$pbkdf2-` prefix at parse, as Auth0 accepts unparsable ones; `Verify` returns `ErrUnusable` for them. `FromBcrypt`'s `PATTERN` message ends in `*****` instead of the hash (D-0044). This task implements `md4`, `md5`, `sha1`, `sha256`, `sha512` (digest of salt and password in `position` order), `hmac` (key from `hash.key`, message is salt and password in order, every documented digest), `ldap`, `bcrypt` (salt joined in `position` order, then cut at 72 bytes as Auth0's bcrypt does, since `x/crypto/bcrypt` refuses longer input), and `password.encoding`. `ripemd160` comes from `x/crypto`; Whirlpool is Task 4's, so `hmac` with `whirlpool` lands there.
- `password.encoding` follows Node's `Buffer.from(s, enc)`: `utf8`; `ascii`, `latin1`, `binary` keep the low 8 bits of each UTF-16 code unit; `utf16le`, `ucs2` write UTF-16LE code units (surrogate pairs for non-BMP). Lone surrogates in a Go string cannot occur (the password arrives as UTF-8), so no other case exists.

- [ ] **Step 1: Write `scripts/gen-hash-vectors.py`** (stdlib `hashlib`, `hmac`, `base64`, `codecs`; `openssl passwd`/`openssl dgst` only where Python lacks an algorithm) producing, per algorithm and option, `{spec, password, match: true}` and a wrong-password `{…, match: false}`. Include the `TestPasswordEncodings` cases (Review Focus 3). Run it in podman; commit the output.
- [ ] **Step 2: Tests:** `TestVectors` over `testdata/vectors.json` for this task's algorithms; `TestParseCustomErrors` (each J5 case: code, message, path); `TestFromBcryptPattern` (`$2a$10$…` ok; `$2y$10$`, `$2a$12$`, 52 characters refused with `PATTERN`); `TestBcryptLongInput` (a 70-byte password with a 10-byte suffix salt matches the hash of the first 72 bytes); `TestPasswordEncodings`; `TestMarshalRoundTrip`; `TestMasked`; `TestWeak`.
- [ ] **Step 3: Implement. Step 4: Run** `go test ./internal/passhash/`. **Step 5: Commit** with `feat(passhash): Auth0 import hash formats (digests, hmac, ldap, bcrypt)`.

---

### Task 4: `internal/passhash`: KDFs, Whirlpool, MDC-2

**Files:** `internal/passhash/{pbkdf2,scrypt,argon2,whirlpool,mdc2}.go`, `internal/third_party/argon2/` (copied from `golang.org/x/crypto/argon2` at the version in `go.mod`, with `argon2d` exported as `DKey`; its LICENSE beside it), `NOTICE`, `make check-sources` allowlist if it flags the directory, tests, regenerated `testdata/vectors.json`.

**Interfaces:**
- Consumes: Task 3's `Spec` and dispatch.
- Produces: `pbkdf2` (PHC `$pbkdf2-<digest>$i=<n>,l=<bytes>$<b64 salt>$<b64 key>`, unpadded base64, defaults `i=100000`, `l=64`; every documented digest name, aliases mapped to the hash: `RSA-SHA256`, `sha256WithRSAEncryption` → SHA-256, `ssl3-md5` → MD5, `ssl3-sha1` and `RSA-SHA1-2` → SHA-1, `rmd160`/`ripemd`/`RSA-RIPEMD160`/`ripemd160WithRSA` → RIPEMD-160, `mdc2`/`RSA-MDC2`/`mdc2WithRSA` → MDC-2, `whirlpool`); `scrypt` (`keylen`, `cost`, `blockSize`, `parallelization` with the documented defaults and rules, salt per `salt`); `argon2` (PHC `$argon2i|argon2d|argon2id$v=19$m=…,t=…,p=…$salt$hash`, and the `v=16` form if Task 1 or the argon2 library docs accept it); `whirlpool` (ISO/IEC 10118-3, written from the specification) and `mdc2` (ISO/IEC 10118-2 with DES, OpenSSL's padding: zero-pad to 8 bytes, as `openssl dgst -mdc2` does) as `hash.Hash` implementations for `hmac` and `pbkdf2`. A cost that would exhaust memory (scrypt `N·r·128` or argon2 `m` above 256 MiB) is refused at parse with `MAXIMUM` (path `custom_password_hash`, D-0044), so a hostile file cannot stall a worker.

- [ ] **Step 1: Extend the vector script** (Python `hashlib.pbkdf2_hmac`, `hashlib.scrypt`; `argon2` vectors from the `argon2` CLI in the podman image; Whirlpool and MDC-2 from `openssl dgst -provider legacy`). Regenerate and commit.
- [ ] **Step 2: Tests:** `TestVectors` now covers every algorithm and every pbkdf2 digest alias; Whirlpool against the published ISO test strings (empty, "a", "abc", the 1-million-"a" vector); MDC-2 against `openssl` output; `TestKDFCostLimits`; argon2d through the vendored package matches the CLI.
- [ ] **Step 3: Implement. Step 4: Run** `go test ./internal/passhash/ ./internal/third_party/...` and `make check-sources`. **Step 5: Commit** with `feat(passhash): pbkdf2, scrypt, argon2, whirlpool and mdc2`.

---

### Task 5: Sign in with an imported hash, then upgrade

**Files:** `internal/identity/database.go` (`passwordHash`, `verifyLocal`), `internal/identity/custom.go` (import mode: an identity with `ImportedHash` is verified locally, never by the login script), `internal/oauth` and `internal/login` only if they read `PasswordHash` directly, `internal/mgmt/users.go` (a `PATCH` password or a reset clears `ImportedHash`; `UserJSON` never shows it), `internal/login/reset.go`, `internal/dbconn/change_password.go`, tests.

**Interfaces:**
- Consumes: Task 2's `ImportedHash`, `UpgradeImportedHash`; Task 3's `Unmarshal`, `Verify`.
- Produces: `Database.Login` verifies a user whose identity has `ImportedHash` with `Spec.Verify` (the password as `EffectivePassword` gives it), then on success hashes with `secrets.Hash` and calls `UpgradeImportedHash`. `ErrConflict` makes it re-read the user once and verify against what is now stored (Review Focus 1). The password policy and history are not applied (as Auth0); the upgrade does not add a history entry. A failed verify costs the same as a native one (the dummy-hash rule). `passhash.ErrUnusable` maps to a new `identity.ErrPasswordChangeRequired`: the password grant answers `403 invalid_grant` "Password change required." for any password (J6), and the hosted login shows a localized message saying the password must be reset, with the reset link. `Users.SetPasswordHash` (reset, PATCH) also clears `ImportedHash`.

- [ ] **Step 1: Tests:** an unusable imported argon2 value gives `Password change required.` on the password grant and the hosted message; a bcrypt-imported and a PBKDF2-imported user sign in with the password grant and the hosted login; afterwards `PasswordHash` is argon2id and `ImportedHash` empty; a wrong password leaves the imported hash; a reset replaces the imported hash; `TestUpgradeRacesUpsert` (Review Focus 1, a store wrapper that blocks between verify and upgrade while an upsert-style `Users.Update` replaces `ImportedHash`); a custom DB in import mode never calls the login script for an imported user; `UserJSON` and the console's raw JSON have no hash.
- [ ] **Step 2: Implement. Step 3: Run** with `-race -count=20` on the race test. **Step 4: Commit** with `feat(identity): sign in with imported hashes and upgrade them to argon2id`.

---

### Task 6: `internal/jobs`: worker pool, job reads, verification-email jobs

**Files:** `internal/jobs/{runner,verify}.go` (new) with tests, `internal/app/app.go` (start the pool next to the sweeper), `internal/config` (`jobs.workers`, default 2; `jobs.lease`, default 60s; 0 workers disables the pool on that process), `api/management.yaml` (`GET /jobs/{id}`, `GET /jobs/{id}/errors`, `POST /jobs/verification-email`, with `x-source`), `internal/mgmt/jobs.go` (new), `internal/server/mgmtapi.go`, `internal/server/mgmt_contract_test.go`, `internal/mgmt/jobs_test.go`.

**Interfaces:**
- Consumes: Task 2's `Jobs`; Plan 17's `login.VerificationMailer` (`mgmt.VerificationSender`).
- Produces:
  - `jobs.Processor interface { Run(ctx context.Context, st store.Store, j *store.Job, lease Lease) (store.JobStatus, string, error) }` and `jobs.Lease` (owner, `Renew(ctx) error`, `Lost() bool`). `jobs.Runner{Store, Processors map[store.JobType]Processor, Workers int, LeaseFor time.Duration, Log, Now}` with `Run(ctx)`: each worker loops `Claim` → processor → `Finish`; it renews the lease every `LeaseFor/3`; when idle it polls every 2 s and wakes at once on `Runner.Notify()`, which the create handlers call. A processor error that is not a lost lease finishes the job `failed` with a generic `status_details` (the error goes to the log, not the job).
  - `mgmt.JobJSON(j *store.Job, location string) map[string]any`: Auth0's job shape (`id`, `type`, `status`, `created_at`, `connection_id`, `connection`, `external_id`, `format`, `limit`, `fields`, `summary` once completed, `location` for a completed export, `percentage_done`/`time_left_seconds`/`status_details` per Task 1 J3, J2). `processing` is shown as `pending` unless Task 1 saw Auth0 report another value.
  - `GET /jobs/{id}` (U10 ID rule, `404` per Task 1 J9 for unknown or expired) and `GET /jobs/{id}/errors` (`200` array, `204` empty; export and verification jobs `204`).
  - `POST /jobs/verification-email` (`user_id`, `client_id`, `identity{user_id, provider, connection_id}`, `organization_id` refused as an unknown property as D-0043 does for tickets): synchronous checks and errors per J10 and the reference (no email, unknown user, identity not on the user, not a database connection); `201` with the job; the processor sends through `VerificationSender`.

- [ ] **Step 1: Tests:** `TestJobLeaseRetryOnce` (Review Focus 2: a processor that blocks and whose worker is cancelled; a second runner reclaims after the lease, a third loss fails the job via `DeleteExpired`); two runners on one store never run a job twice; `Notify` wakes an idle worker; each verification-email case from J10; the email is sent once; `GET /jobs/{id}` shapes for each type and status; ID format errors; scopes; the contract test extended.
- [ ] **Step 2: Implement. Step 3: Run** the Go suite, `go generate` with no diff. **Step 4: Commit** with `feat(jobs): worker pool, GET /jobs and verification-email jobs`.

---

### Task 7: User import

**Files:** `internal/jobs/importer.go` (new) with tests, `internal/mgmt/jobs.go` (`POST /jobs/users-imports`), `api/management.yaml`, `internal/email/import_done.go` and templates `import_done.{html,txt}`, `internal/i18n` catalog, `internal/server/mgmtapi.go`, tests.

**Interfaces:**
- Consumes: Tasks 2, 3, 6; `userrules.CheckCreate`/`CheckPatch`/`ApplyPatch` (Plan 17).
- Produces:
  - `POST /jobs/users-imports` (multipart: `users` file, `connection_id`, `upsert`, `external_id`, `send_completion_email` default `true`): the synchronous checks of J1 and the reference (413 above 512000 bytes, read with a `http.MaxBytesReader` of 512000 + the form overhead; the concurrency limit of 2 with J3's answer), then `Jobs.Create` with the file as `Input` and `202`.
  - `jobs.Importer` (Processor): parses `Input` as a JSON array (J2 decides which malformed files reach it and their `status_details`); processes records from `Progress` in batches of 50, each batch and its `Checkpoint` in one `WithTx`, renewing the lease between batches. Per record: unknown top-level properties ignored; schema and `userrules` checks produce `JobError` items with Auth0's codes (J5's observed `ENUM_MISMATCH`, `ONE_OF_MISSING`, `OBJECT_MISSING_REQUIRED_PROPERTY`, `OBJECT_ADDITIONAL_PROPERTIES`, `NOT_PASSED`, `NON_UNIQUE_PROPERTY_VALUE`, `CONFLICT`, `INVALID_TYPE`, plus the documented `ANY_OF_MISSING`, `ARRAY_LENGTH_LONG`, `ARRAY_LENGTH_SHORT`, `CONFLICT`, `CONFLICT_EMAIL`, `CONFLICT_USERNAME`, `CONNECTION_NOT_FOUND`, `DUPLICATED_USER`, `ENUM_MISMATCH`, `FORMAT`, `INVALID_FORMAT`, `INVALID_TYPE`, `MAX_LENGTH`, `MAXIMUM`, `MFA_FACTORS_FAILED`, `MIN_LENGTH`, `MINIMUM`, `NOT_PASSED`, `OBJECT_REQUIRED`, `PATTERN`, with U10's and J4/J5's paths and messages); hashes through `passhash` into `Identity.ImportedHash`; no hash leaves an identity without a password (reset later); `mfa_factors` accepted and ignored (D-0044); reserved `app_metadata` keys refused; duplicates within the file per J4. `upsert: false` and an existing user (by email on the connection) is `DUPLICATED_USER` (U10). `upsert: true` applies J4's field rules: names and `email_verified` replaced when present, metadata objects replaced whole, `blocked`, `user_id` and `password_hash` ignored on an existing user, `custom_password_hash` replaced only while `ImportedHash` is set, else `CONFLICT` "A custom_password_hash was provided, but the user already has password hash defined." (ledger ruling R1: the batch re-reads the user with `Users.GetForUpdate`, and the login's compare-and-swap decides the race, Review Focus 1). Custom-DB connections in import mode never call scripts.
  - The summary counts `inserted`, `updated`, `failed`, `total`; the job summary and the log line count weak hashes (`Spec.Weak`, spec §9) in `Params["weak_hashes"]`, shown by the console.
  - Completion email when `send_completion_email` is true and the job ends (completed or failed): to the email of every operator whose `Tenants` contains the tenant's name or `*` (spec §5.6, D-0044), localized in English (operators have no locale).

- [ ] **Step 1: Tests:** a file mixing valid users, each documented error code the importer can raise, upserts and hashes from every algorithm family, with exact `summary` and `/errors` bodies (masked); `TestImportResumesAfterLeaseExpiry` (Review Focus 2, the worker killed after the second batch); `TestImportBadFiles` (Review Focus 5); the concurrency limit; the 413 boundary; a user imported with bcrypt signs in (via Task 5) and is upgraded; the completion email goes to two operators of the tenant and not to an operator of another tenant; custom-DB import mode with a stub script that fails if called.
- [ ] **Step 2: Implement. Step 3: Run** the Go suite and the SQL suite on `./internal/jobs/...`. **Step 4: Commit** with `feat(jobs): bulk user import with Auth0 hash formats`.

---

### Task 8: User export and the signed download

**Files:** `internal/jobs/exporter.go` (new) with tests, `internal/mgmt/jobs.go` (`POST /jobs/users-exports`, `location` in `GET /jobs/{id}`), `internal/mgmt/exportlink.go` (new), `api/management.yaml`, `internal/server/server.go` (the download route on tenant hosts), `internal/secrets` (a derived key), tests.

**Interfaces:**
- Consumes: Tasks 2, 6; `Users.List` with an `identities.connection` term (Plan 17); `mgmt.UserJSON`.
- Produces:
  - `POST /jobs/users-exports` (JSON or form body; unknown properties `400 invalid_body`; the J8 checks on `limit` and `fields`): `200` with the job (U11 echo).
  - `jobs.Exporter` (Processor): pages through `Users.List` 500 at a time (ordered by `user_id` for a stable walk), up to `limit` (no limit when absent, J8), writing gzip into 1 MiB chunks with `AppendFile`. JSON: one object per line built from `UserJSON`, keys `export_as` or `name`, absent values left out, whole metadata objects allowed. CSV: header from `export_as`/`name` (the U11 default columns without `fields`), at most 30 fields, metadata by subfield only, values per Global Constraints and Review Focus 4. Never a hash (`UserJSON` has none, and `password_hash`/`custom_password_hash` are refused as field names with J8's error or an empty column, as J8 shows).
  - `mgmt.ExportLink{Key []byte; Now func() time.Time}` with `Sign(host, tenantID, jobID, format string) string` and `Check(tenantID, jobID string, expires int64, sig string) bool`: URL `https://<tenant host>/export/<job id>/<tenant name>.<json|csv>.gz?expires=<unix>&sig=<base64url HMAC-SHA256>`, 60 s lifetime, the key derived from the master key with HKDF-SHA256 (info `zeroauthy export link v1`), constant-time compare. Every completed-export `GET /jobs/{id}` signs a fresh URL (J9).
  - `GET /export/{job}/{file}` on tenant hosts, no token: checks the signature, expiry and that the job is a completed export of this tenant; streams `ReadFile` with `Content-Type: application/gzip`, `Content-Disposition: attachment; filename="<tenant>.<fmt>.gz"`, `Cache-Control: no-store`; anything else `403` with a plain body (the path and its answers are zeroauthy's own, D-0044); logs job, tenant and remote IP.

- [ ] **Step 1: Tests:** JSON and CSV exports with and without `fields`, `export_as`, metadata subfields and whole objects, `limit`, all connections versus one; `TestExportCSVHostileValues` (Review Focus 4); no hash in any output (search the decompressed bytes for `$argon2id$` and the imported vector values); an export of 1200 users spans three chunks and reads back intact; the link: valid, expired at 61 s, tampered signature, other tenant's host, job not completed; a second `GET /jobs/{id}` gives a new URL.
- [ ] **Step 2: Implement. Step 3: Run** the Go and SQL suites. **Step 4: Commit** with `feat(jobs): user export and signed download links`.

---

### Task 9: Console: Import and export

**Files:** `console/src/pages/users/{ImportExport,ImportForm,ExportForm,JobsList,JobErrors}.vue` with tests, `console/src/api/client.ts` and `schema.d.ts` (regenerated), `console/src/router.ts`, `console/src/pages/users/List.vue` (the Import and export button), `console/src/pages/users/ActionsMenu.vue` ("Send verification email" calls `POST /jobs/verification-email`; closes the Plan 17 follow-up), `console/src/locales/*`, `console/dist`; `api/management.yaml` + `internal/mgmt/system.go` for `GET /api/system/tenants/{tenant}/jobs` (operators only, `Jobs.List`; Auth0 has no job list, so this is on the zeroauthy system API, not `/api/v2`).

**Screens** (spec §6): Import: a file picker (refuses files above 512000 bytes before upload, with the limit in the message), connection (database connections; custom DB only in import mode), upsert and completion-email switches, then the job appears in the list. Jobs list: type, status, created, connection, summary, the weak-hash count with a link to the import guide's reset advice, an Errors view (masked records, codes, messages, paths). Export: connection (or all), format, a field picker (default fields, metadata subfield entry, `export_as`, the 30-field CSV limit enforced), then a Download button on the completed job that fetches a fresh `location` and follows it.

- [ ] **Step 1: Tests** (Vitest): each form's validation and success; the list's loading, empty, error and polling states (it polls pending jobs every 3 s and stops when none are pending or the page is hidden); the errors view never shows a hash value; the download asks for a fresh job read each time; the actions menu sends the verification job and shows the result.
- [ ] **Step 2: Implement.** Rebuild `dist/`. **Step 3: Run** `make console` and the system API test. **Step 4: Commit** with `feat(console): user import and export`.

---

### Task 10: E2E

**Files:** `tests/e2e/m18-mgmt-cli.mjs`, `tests/e2e/m18-node-auth0.mjs`, `tests/e2e/m18-console.spec.mjs`, `tests/e2e/fixtures/import-users.json` (generated by `scripts/gen-hash-vectors.py --fixture`: a bcrypt user, a PBKDF2-SHA256 user, a salted SHA-256 user, an argon2id user, and one invalid record), `tests/e2e/run-m3.sh`, `tests/e2e/run-browser.sh`, `tests/e2e/seed.yaml`.

- [ ] **Step 1: auth0-cli v1.37.0:** `auth0 users import --connection-name … --users "$(cat fixture)" --upsert` waits for and reports the job; then `users search` finds the imported users; a password grant signs in each one with its original password.
- [ ] **Step 2: node-auth0** (the pinned m3 version): `jobs.importUsers` (file stream), `jobs.get`, `jobs.getErrors` (the invalid record, masked), `jobs.exportUsers` (CSV and JSON), download the `location`, gunzip and parse; `jobs.verifyEmail` and the email in the dir mailer.
- [ ] **Step 3: Playwright:** sign in to the console; import the fixture; the job completes with the expected summary and one error; open the errors view; sign in to the sample app as the bcrypt user and the PBKDF2 user; export CSV with two fields and download it; send a verification email from user detail.
- [ ] **Step 4: Run** `make e2e`. **Step 5: Commit** with `test(e2e): user import and export with auth0-cli, node-auth0 and the console`.

---

### Task 11: Documentation and final verification

**Files:** `docs/user-import.md` (new: the file format, every hash algorithm with an example generated by our script, the weak-hash advice and a forced-reset recipe with Auth0's own endpoints, limits, upsert rules), `docs/management-api.md`, `docs/console.md`, `docs/configuration` section for `jobs.*` where config is documented, `docs/compat/matrix.md`, `docs/superpowers/plan-1-followups.md` (close "bcrypt hash verification and upgrade for imported users" and the Plan 17 jobs line; add "Plan 18 follow-ups"), `NOTICE`, README roadmap status, `docs/superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md` (Plan 18 done).

- [ ] **Step 1: Write the docs.**
- [ ] **Step 2: Verify:** gofmt, vet, `go test -race ./...`, `go generate` no diff, `make console` no diff, the SQL suite, `make e2e`, `make check-sources`, and `make conformance` (exit 0, or say exactly why it cannot run).
- [ ] **Step 3: Commit** with `docs: jobs and user import; Plan 18 records`.
