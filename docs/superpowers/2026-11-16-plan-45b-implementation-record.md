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
- Tasks 6–14, full fast-tier and E2E verification, and CI for the resumed branch are pending.

The plan's Go 1.26.10 reference predates main's Go 1.26.11 minimum;
repository toolchain and dependency pins are retained.
