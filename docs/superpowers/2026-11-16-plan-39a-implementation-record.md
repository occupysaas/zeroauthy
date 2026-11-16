# Plan 39a implementation record

Started 2026-11-16 from `7691b15d92bcfef3a2d48908b29de112bb74f08b`.
Worktree: `/mnt/nvme2/code/zeroauthy-plan39a`.
Branch: `plan-39a-apple`.

Initial scope: Task 3, the internal ES256 client-secret signer and cache,
while the independent Plan 45b branch is in CI. This task consumes existing
`CacheKey`, `Providers` and go-jose interfaces, so it can precede strategy/API
activation. If later provider work needs a different signature, adapt the
internal helper there. Main's Go 1.26.11 minimum and dependency pins are
retained rather than downgrading to the design's stale Go 1.26.10 reference.

- Task 3: signed JWT uses Key ID header and Team ID issuer, Services ID or
  bundle ID subject, Apple's fixed audience, integer issue time and a
  five-minute lifetime. Four-minute cache is bounded and isolated by tenant,
  connection, revision, signing identifiers and subject; concurrent calls
  share one signature. Cache holds no private key.
- Task 1: D-0170 and optional A1–A7 observation points recorded; API and
  inventory edits still pending.
- Tasks 2 and 4–8: pending. Apple login is not operational yet. Full plan
  verification, E2E and the whole-plan review have not run.

Verification uses `GOTOOLCHAIN=go1.26.11 TMPDIR=/dev/shm/za39a GOTMPDIR=/dev/shm/za39a`:

- RED: `go test ./internal/federation -run '^TestApple(ClientSecret|SecretCache)' -count=1`, exit 1: missing signer and cache methods (build failure).
- GREEN: same command, exit 0 (0.121 s). Tests verify signatures with the
  public key, required claims/headers, wrong-key rejection, invalid keys,
  cache expiry at exactly four minutes, revision/key rotation, isolation
  across tenant/connection/subject/Team ID/Key ID, and 32 concurrent calls.
- Package check: `go test -race ./internal/federation -count=1`, exit 0 (10.143 s); log `task3-package.log`.
- Logs retained in `.superpowers/sdd/2026-11-16-zeroauthy-plan-39a-apple/task3-{red,green}.log`.
