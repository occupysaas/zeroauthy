# Plan 45b implementation record

Started 2026-11-16 from `7691b15d92bcfef3a2d48908b29de112bb74f08b`.
Worktree: `/mnt/nvme2/code/zeroauthy-plan45b`.
Branch: `plan-45b-flow-api-fixes`.

Initial scope: Task 1 (decisions) and Task 3 (signup code lifetime and budget).
Task 3 is independent of the pending Task 2 MFA side-effect changes, so it is taken first.

- Task 1: contracts in D-0270 and optional B1–B4 follow-ups recorded.
- Task 3: implemented signup code lifetime from `phonerules.Limits.SignupOTPLifetimeSeconds` (900 s), plus send-budget isolation by connection and purpose. The normalized identifier and tenant remain part of the key; the shared IP budget and reset code lifetime remain unchanged.

Verification (Go 1.26.11, short tmpfs paths):

- RED: `go test ./internal/login -run '^(TestSignupCodeLifetime900|TestCodeBudgetPerConnectionAndKind)$' -count=1`, exit 1: signup rejected at 899 s; alternate connection and reset denied after exhausting signup.
- GREEN: same tests plus `TestSignupWithPhoneVerification`, `TestResetByPhone`, `TestPhoneIdentifierSendsShareIPBudget`, exit 0.
- Final focused check: `GOTOOLCHAIN=go1.26.11 TMPDIR=/dev/shm/za45b GOTMPDIR=/dev/shm/za45b go test ./internal/login ./internal/phonerules -run 'Phone|Identifier|Code|Limits' -count=1`, exit 0 (login 1.859 s, phonerules 0.082 s), at `51dd8844`; log `task-3-tests.log`.
- Logs retained in `.superpowers/sdd/2026-11-16-zeroauthy-plan-45b-flow-api-fixes/task3-{red,green}.log`.

The newly scoped identifier-budget keys start fresh on upgrade; the shared IP
budget retains its keys and enforcement. Existing codes retain their stored
expiry; newly issued signup codes use 900 seconds.

- Task 2 implemented MFA completion effects and authority binding in `7fd0d0c4`, `a7d79213` and `3c8d0e35`.
- Task 4 implemented the durable first-denial `limit_wc` claim and resumable MySQL migration in `e8e3c0f5` and `f9173b5e`.
- Task 5 moved passwordless test sends to the operator-only system route. Its route and console call-site regressions cover tenant grants, delivery through a provider fixture, an empty success response and system-host authorization.
- Task 6 made the console CSP independent of tenant data. For custom-host tenants, console Management requests go through the canonical system host, which checks the signed and current operator grants before dispatching to the existing handlers.
- Task 10 made `GET /api/v2/users` validate and ignore the v1-only `connection` parameter on supported engines. The console sends its selection separately through the private, operator-only `console_connection` parameter. The server parses the original search text before adding an exact `identities.connection` term.
- Tasks 11–13 implemented the email-provider public credentials (`573e3c10`, `605cbc3b`), ordered protection bucket locks (`98687fc6`) and Plan 33 minors M3, M6 and M7 (`3f4439d7`), each reviewed clean after at most one fix round.
- Task 14 updated the changelog, upgrade guide and status docs (`3149e28a`).

Final verification (Go 1.26.11, `TMPDIR`/`GOTMPDIR=/dev/shm/za45b`):

- Fast tier: `go test ./...` (no `-race`) exit 0 at `3f4439d7`. After the review fix, `go test ./internal/login ./internal/authz` exit 0.
- E2E, with work directories on tmpfs (`E2E_ARTIFACT_DIR=/dev/shm/za45b-e2e`): `make e2e-passwordless` exit 0 (8 passed plus SQLite and memory lanes) and `make e2e-email` exit 0 at `0b8f21e7`; `make e2e-mfa` exit 0 (2 browser tests plus SQLite and memory lanes) and `make e2e-organizations-ii` exit 0 (7 passed) at `c9133181`.
- An earlier attempt kept the E2E work directories on btrfs. A goroutine dump showed SQLite's single connection blocked in WAL `fsync`, which made the MFA, passwordless and Organizations II suites time out. The tmpfs reruns above replace those results. Two real test defects surfaced and were fixed in `c9133181`: the MFA privacy allowlist now accepts the proxied console path (Task 6), and the organization verification E2E uses tickets because the Organizations II harness runs no job worker.
- Whole-branch review (74752598..3149e28a): no Critical or Important findings. Minor 6 (social login session binding) was fixed in `0b8f21e7`; the rest are recorded as R1–R7 in the [follow-ups](plan-1-followups.md), with R1 and R2 marked for fixing before 1.0.
- PostgreSQL/MySQL, race and remaining suites run in plan-branch CI (below).

The plan's Go 1.26.10 reference predates main's Go 1.26.11 minimum;
repository toolchain and dependency pins are retained.
