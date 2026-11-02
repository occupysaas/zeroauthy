# Plan 33 implementation record

Base: `5d1c30c1ac7c90d88307c1958af7d7fd20ef0d54`; branch `plan-33-mfa`.
Toolchain: Go 1.26.7 and Node v26.8.1. Work proceeds task by task; the
contract freeze does not imply runtime implementation.

## Task 1 — contracts

Public documentation and OpenAPI only; no upstream tenant observation.
M1–M9 remain open as described in D-0059 and the follow-ups. Go's shared type
and function namespace requires `Route(op string) RouteSchema`; the controller
approved this name. API generation produced `internal/gen/authapi/authapi.gen.go`
and `internal/gen/mgmtapi/mgmtapi.gen.go`. Published invalid device-name
constraints were omitted from the management schema.

The inherited RED log `/tmp/plan33-task1/red.log` records `go test
./internal/mfarules -count=1` failing because there were no non-test Go files.
`/tmp/plan33-task1/api-red.log` records the missing MFA create schema test.
The first combined green attempt exposed duplicate authentication YAML keys;
these were corrected, followed by the invalid upstream device-name schema.
See the Task 1 report for final commands and results. `TestPlan33LogCodes`
is explicitly skipped until Task 14, when runtime tasks have added emitters.

Verification (2026-11-02): `GOTOOLCHAIN=go1.26.7 make generate` exited 0;
`GOTOOLCHAIN=go1.26.7 go test ./internal/mfarules ./internal/logrules ./api
-count=1` exited 0; generated API packages compiled via `go test
./internal/gen/authapi ./internal/gen/mgmtapi -count=1` (no test files).
`TestPlan33LogCodes` was explicitly confirmed skipped. `git diff --check`
exited 0. Optional `make check-sources` was interrupted (exit 130) while checking
network URLs, so no result is claimed. Full suites remain Task 14 work.

### Task 1 review fixes

The first review identified an overlapping OAuth 403 union, unrestricted policy
array, omitted enrollment 404s, unsupported discovery conclusion, and missing
FCM v1 write-only annotations. The response now uses `anyOf`, policy requests
allow at most one entry, both enrollment operations describe 404 in the API and
inventory, and both FCM v1 requests mark credentials write-only. Discovery is
unresolved; the local rule does not advertise MFA grants until verification,
without claiming what a public document says. No discovery document or tenant
was contacted for this ruling.

Review tests failed for all of those cases before the fixes (exit 1,
`/tmp/plan33-task1/review-red.log`), then passed (exit 0,
`/tmp/plan33-task1/review-green.log`). `GOTOOLCHAIN=go1.26.7 make generate`
exited 0 (`/tmp/plan33-task1/review-generate.log`). Final focused verification
and generated package compilation are recorded in the task report.

## Task 2 — MFA primitives

- Implementation: `4f0b0f6` adds RFC 6238 verification, random recovery/email codes and IDs, escaped provisioning URI, and in-tree QR byte-mode M encoder (versions 1–10). Oversize QR input returns nil. The SVG golden was independently decoded with ZBar.
- RED: `GOTOOLCHAIN=go1.26.7 go test ./internal/mfa -run 'TOTP|Recovery|IDFormats|QR' -count=1` exited 1 because the primitive APIs did not yet exist; `/tmp/plan33-task2-red.log`.
- Initial GREEN attempt exited 1: a negative-time window and version-10 QR alignment issue; both addressed and rechecked. The QR test covers all ten versions using ImageMagick and ZBar when available, with the committed golden always checked.
- Final focused command above exited 0 (`ok .../internal/mfa 2.154s`); `/tmp/plan33-task2-green.log`. `GOTOOLCHAIN=go1.26.7 go test ./internal/mfa -count=1` exited 0 (`2.153s`). Independent golden decoding using `convert -density 300` and `zbarimg --quiet --raw` exited 0 and returned the expected URI (ImageMagick printed a deprecation warning for `convert`). Comprehensive suites remain Task 14.

## Task 3 — MFA storage contract and memory driver

- Introduced the public and internal MFA interfaces and unavailable stubs for SQL and gRPC, memory storage with transaction snapshots, tenant/user cascades, and session MFA timestamps. MFA writes verify tenant-local users, supplied clients, and challenge authenticator ownership.
- RED: `GOTOOLCHAIN=go1.26.7 go test ./internal/store/memory -run 'MFA|SessionMarkMFA' -count=1` exited 1 because the repository did not exist (`/tmp/plan33-task3-red.log`). Cross-tenant reference regression exited 1 before validation (`/tmp/plan33-task3-reference-red.log`). Only the default and reference tests were observed red; remaining conformance cases were added during implementation.
- Focused memory MFA command exited 0 (`/tmp/plan33-task3-focused-final.log`); bridge test exited 0 (`/tmp/plan33-task3-bridge-green.log`). No full or SQL/gRPC MFA suite was run; those drivers remain unavailable until Tasks 4–5.
- Task 1's generated auth interface required four temporary server adapters; they return 501 `mfa_unavailable`, pending Task 9. Initial internal compile failed on those missing methods; final compile outcome is recorded in the task report.
- Final `GOTOOLCHAIN=go1.26.7 go test ./internal/... -run '^$'` exited 0 (`/tmp/plan33-task3-compile-final.log`).

### Task 3 review fix round 1

- Guardian get/put now return `ErrNotFound` for missing tenants. Recovery authenticators are unique per tenant and user; atomic empty-old initialization creates a confirmed recovery record with the agreed ID and timestamp. Empty new hashes return `ErrInvalid` and stale or absent non-empty old hashes return `ErrPrecondition`.
- Three regressions failed before the fixes (exit 1, `/tmp/plan33-task3-review-red.log`) and passed after (exit 0, `/tmp/plan33-task3-review-green.log`). Factor names, non-nil policies, all MFA record cascades across tenants, and transaction rollback of mutable state were also strengthened.
- `GOTOOLCHAIN=go1.26.7 go test ./internal/store/memory -run 'MFA|SessionMarkMFA' -count=1` exited 0 (`/tmp/plan33-task3-review-focused-final.log`). `GOTOOLCHAIN=go1.26.7 go test ./internal/... -run '^$'` exited 0 (`/tmp/plan33-task3-review-compile.log`). No full suite run; SQL and gRPC conformance remain deferred.

## Task 4 — SQL MFA storage

- Added migration 0033 for the six MFA tables, user epoch and session timestamp; tenant-scoped methods, atomic conditional updates and database-enforced recovery uniqueness; SQL user/tenant deletion cascades and transaction views. MySQL migration 0033 is resumable, and the v21 federation backfill supplies a default for the later user column.
- RED: `GOTOOLCHAIN=go1.26.7 go test ./internal/store/sqlstore -run 'MFA' -count=1` exited 1 (session 38148, `/tmp/plan33-task4-red.log`): SQLite methods returned MFA unavailable and the migration column was missing. Named migration and concurrent-update tests and reusable MFA conformance were present before implementation.
- Focused SQLite: `GOTOOLCHAIN=go1.26.7 go test ./internal/store/sqlstore -run 'MFA|SessionMarkMFA|Migration0021|EventsMigrationFrom30|MigrationSetsMatch' -count=1` exited 0 (`/tmp/plan33-task4-recheck.log`).
- Cross-driver: `GOTOOLCHAIN=go1.26.7 ./scripts/test-sql.sh -v -run 'MFA|SessionMarkMFA' -count=1 ./internal/store/sqlstore/...` exited 0 (session 90713, `/tmp/plan33-task4-cross-driver-final.log`): MFA conformance, v32 migration, and two-connection conditional updates passed on SQLite, PostgreSQL and MySQL, with no skipped drivers. The required nonverbose command also exited 0 (session 99665, `/tmp/plan33-task4-cross-driver.log`), before subsequent migration compatibility fixes; the verbose rerun verified those fixes.
- Repository-wide `GOTOOLCHAIN=go1.26.7 go test ./...` exited 1 (session 38872, `/tmp/plan33-task4-go-test-all.log`, implementation snapshot after the final cross-driver run and before the legacy test-seed fix). `TestOrganizationsIIMigrationFrom25/sqlite` failed because its v25 fixture called the current user codec; it now seeds the v25 columns explicitly. Focused `GOTOOLCHAIN=go1.26.7 go test ./internal/store/sqlstore -run 'TestOrganizationsIIMigrationFrom25|MFA|SessionMarkMFA' -count=1` exited 0 (`/tmp/plan33-task4-regression-fix.log`). The full suite was not rerun.
- Remaining full-run failures belong to Task 5: grpcstore `TestUserRoundTrip/full` and `TestSessionRoundTrip/full` lack transport for the new fields; grpcstore `TestConformance/MFA`, `TestConformanceSQLite/MFA`, `TestEventsPrePluginPriorFeatures/MFA`, and storeplugin `TestConformanceThroughPluginProcess/MFA` fail because the gRPC MFA capability is unavailable. Full-suite output was nonverbose, so individual skipped tests are not visible; no skip count is claimed.
