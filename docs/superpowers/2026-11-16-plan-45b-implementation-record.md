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

- Tasks 2 and 4–14: pending; full plan verification and CI have not run.

The plan's Go 1.26.10 reference predates main's Go 1.26.11 minimum;
repository toolchain and dependency pins are retained.
