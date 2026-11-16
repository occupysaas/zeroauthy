# Plan 45a — Security hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Versioned envelopes with per-tenant master keys, root-key
rotation, Auth0's customer-managed keys API, a Linux sandbox and shared
prelude for the Node runners with retirement on spent budgets, HSTS,
database TLS checks and plugin stderr scrubbing.

**Architecture:**
- **Part A** — `internal/keys`: envelope v2, `TenantWrapper` resolving the
  tenant master key, rotation and rewrap service; `internal/store`
  `KeyHierarchy` repository; `internal/mgmt/encryption_keys.go`;
  `cmd/zeroauthy keys status|rewrap`.
- **Part B** — `internal/noderunner/sandbox_linux.go` (re-exec helper:
  no-new-privs, Landlock, seccomp, rlimits), `internal/runnerprelude`
  (shared `.mjs`), retirement in `noderunner.Pool`.
- **Part C** — `internal/httpx` (HSTS), `internal/store/sqlstore` (DSN
  check), `internal/store/grpcstore` (stderr scrubber).

**Tech Stack:** Go 1.26.10 with `golang.org/x/sys` v0.49.0 (already a
dependency; **no new module**), Node 25 (existing), Vue/TypeScript console.

**Spec:** [Plan 45a design](../specs/2026-11-16-zeroauthy-security-hardening-design.md). § refers to it.

**Gates:** Part A Tasks 2–6 wait for ruling §9.1; Part B Task 8 for §9.2;
Task 11 for §9.3. Tasks 1, 7, 9, 10 and 12 may start at once. Parts are
independent and may land as separate PRs from the same branch.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin; no new module.
- **Clean room.** Own words; the Auth0 OpenAPI is the API contract.
- **Parity.** LR45a-1…7 and K1–K4 in **D-0260**; K points in
  `docs/superpowers/plan-1-followups.md`; amend D-0022 and D-0053 (sandbox)
  and the `SECURITY.md` threat-model section.
- **Never logged or returned:** root keys, TMKs, imported key material,
  wrapping private keys.
- **Online safety:** every migration of sealed data is online, batched,
  idempotent and CAS-guarded; previous roots stay readable.
- **Migration.** One forward-only migration in three dialects written as
  `0044_key_hierarchy.sql`; renamed to main's latest + 1 at merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za45a GOTMPDIR=/dev/shm/za45a go test -p 4 ./...` plus
  `make e2e-actions` and `make e2e` (custom DB); push
  `plan-45a-security-hardening`; report CI (Linux sandbox tests run there).
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan45a`, branch
  `plan-45a-security-hardening`; record in
  `docs/superpowers/2026-11-16-plan-45a-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Mixed envelopes under concurrency:** two replicas rewrapping the same
   rows → every row readable afterwards, each wrapped once. Task 4
   `TestRewrapConcurrent`.
2. **Missing previous root:** start with a v2 TMK wrapped by a root that is
   not configured → refusal naming the kid, no partial start. Task 4
   `TestMissingRootRefuses`.
3. **Customer key delete** while values exist → everything still readable
   under the native root. Task 6 `TestDeleteCustomerKeyFallsBack`.
4. **Sandbox escape probes:** read `/etc/passwd`, another tenant's script
   directory, `/proc/1/environ`; open a raw socket; `execve`; connect to
   `127.0.0.1` — all fail. Task 8 `TestSandboxProbes` (Linux).
5. **Retirement:** after the mask budget is spent, the next call runs in a
   new process with masking working. Task 9 `TestRetireOnMaskBudget`.

---

### Task 1: Inventory and decisions

**Files:** `docs/compat/decisions.md` (D-0260 with §9 open);
`docs/superpowers/plan-1-followups.md` (K1–K4);
`internal/keys/inventory_test.go` (a test that lists every function calling
`Wrapper.Wrap`/`seal` and fails when a new sealing path appears without
being registered — the inventory of spec §3).

- [ ] **Step 1:** Inventory test listing today's 40-odd sealing helpers and any direct `Wrap` users.
- [ ] **Step 2:** D-0260; follow-ups.
- [ ] **Step 3:** Commit `docs: freeze Plan 45a contracts and D-0260`. Ask for the §9 rulings.

### Task 2: Envelope v2 and the tenant wrapper (Part A, gated §9.1)

**Files:** `internal/keys/envelope.go`, `tenantwrapper.go`, tests;
`internal/store/key_hierarchy.go` + memory driver + storetest.

- [ ] **Step 1: Failing tests**: v1 still opens; v2 seal/open; wrong tenant TMK fails; AAD binding unchanged per helper (table over the inventory); TMK created lazily once per tenant under concurrency (one winner).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(keys): versioned envelopes with tenant master keys`.

### Task 3: SQL and gRPC drivers

**Files:** migration `0044_key_hierarchy.sql`, sqlstore, grpcstore + proto
(capability `key_hierarchy.v1`), storetest runs.

- [ ] **Step 1:** Drivers with CAS updates for rewrap.
- [ ] **Step 2:** Capability off → v1 envelopes, keys API `501`.
- [ ] **Step 3:** Commit `feat(store): key hierarchy in SQL and gRPC drivers`.

### Task 4: Root rotation and rewrap

**Files:** `internal/config` (`PREVIOUS_MASTER_KEYS_FILE`),
`internal/keys/rotation.go`, `cmd/zeroauthy` (`keys status`, `keys rewrap`),
`internal/app` startup, tests.

- [ ] **Step 1: Failing tests**: rotation keeps everything readable; startup rewraps TMKs; CLI converts v1 rows and reports counts per root kid; `TestRewrapConcurrent` (Review Focus 1); `TestMissingRootRefuses` (Review Focus 2).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(keys): root key rotation and online rewrap`.

### Task 5: Encryption keys API — read, create, wrapping key, import

**Files:** `api/management.yaml` (seven operations), `make generate`,
`internal/mgmt/encryption_keys.go`, tests.

- [ ] **Step 1: Failing tests**: GET hierarchy shape; create pre-activation (`409` second); wrapping key PEM + algorithm; import a test-wrapped 32-byte key (wrap in the test with the returned public key per K1's algorithm) → active, TMK rewrapped, server root can no longer unwrap that tenant's TMK alone; malformed `wrapped_key` → `400`; scopes.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(mgmt): customer-managed root key import`.

### Task 6: Rekey and delete

**Files:** `internal/mgmt/encryption_keys.go`, `internal/keys/rotation.go`, tests.

- [ ] **Step 1: Failing tests**: rekey creates a TMK, rewrap moves DEKs, old TMK `deactivated` then `destroyed`; `TestDeleteCustomerKeyFallsBack` (Review Focus 3); delete of other types `400`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(mgmt): rekey and customer key removal`.

### Task 7: Shared runner prelude (Part B)

**Files:** create `internal/runnerprelude/prelude.mjs` (+ Go embed),
modify `internal/noderunner/guard.mjs`, `internal/customdb/runner.mjs` to
load it; a probe suite in `internal/runnerprelude/probe_test.go` run
against both runners.

- [ ] **Step 1:** Probe suite first (env scrub, `require` allowlist, fetch guard, masking, log capture) green on today's runners.
- [ ] **Step 2:** Move the shared code; probe suite still green on both.
- [ ] **Step 3:** Commit `refactor(runners): one shared prelude for Actions and custom database scripts`.

### Task 8: Linux sandbox (gated §9.2)

**Files:** `internal/noderunner/sandbox_linux.go`, `sandbox_helper_linux.go`
(re-exec entry `zeroauthy __runner-sandbox`), `seccomp_linux.go`,
`landlock_linux.go`, tests with `//go:build linux`; startup self-test;
config opt-out.

- [ ] **Step 1: Failing tests** `TestSandboxProbes` (Review Focus 4); `TestSandboxSelfTest` refuses or warns per the ruling; Actions and custom DB suites still pass under the sandbox.
- [ ] **Step 2–4:** FAIL → implement → PASS (CI Linux runners).
- [ ] **Step 5:** Commit `feat(runners): Landlock, seccomp and rlimit sandbox on Linux`.

### Task 9: Retirement on spent budgets

**Files:** `internal/noderunner/runner.go` (retire instead of mute),
`internal/customdb` same path, tests.

- [ ] **Step 1: Failing tests**: `TestRetireOnMaskBudget` (Review Focus 5); log-window exhaustion retires; in-flight calls finish.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `fix(runners): retire a tenant process when its log or mask budget is spent`.

### Task 10: HSTS and plugin stderr (Part C)

**Files:** `internal/httpx/hsts.go`, server listeners, config
`ZEROAUTHY_SERVER__HSTS`; `internal/store/grpcstore` stderr pipe through
`internal/logscrub`, tests.

- [ ] **Step 1: Failing tests**: HSTS on the ACME/TLS listeners, absent behind proxy unless configured; stderr lines with `password=…` and secret-looking values scrubbed; 8 KiB cap; rate limit.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat: HSTS on terminated TLS and scrubbed plugin stderr`.

### Task 11: Database TLS checks (gated §9.3)

**Files:** `internal/store/sqlstore/dsn_check.go`, config
`ZEROAUTHY_STORAGE__REQUIRE_TLS`, tests.

- [ ] **Step 1: Failing tests**: DSN table (postgres sslmode variants, mysql tls variants, loopback, unix socket) → warn/refuse/OK.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(store): warn or refuse on unencrypted database connections`.

### Task 12: Console, docs, final verification

- [ ] **Step 1:** Console encryption keys page and sandbox status; Vitest; `console/dist`.
- [ ] **Step 2:** Docs: new `docs/encryption-keys.md` (hierarchy, rotation runbook, BYOK, recovery warnings); `docs/actions.md` and `docs/custom-db.md` (sandbox); `docs/deployment.md` (HSTS, DB TLS); `SECURITY.md`; `docs/upgrading.md` (rotation procedure); `CHANGELOG.md`; roadmap; implementation record.
- [ ] **Step 3:** Fast tier + `make e2e-actions` + `make e2e`; push `plan-45a-security-hardening`; record CI.
- [ ] **Step 4:** Whole-branch review (security focus), fix wave, green CI, maintainer approval.
