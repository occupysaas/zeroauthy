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
