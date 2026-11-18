# Plan 37b — WS-Federation and ADFS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The `wsfed` client addon (passive requestor IdP with SAML 1.1
RSTR tokens, metadata, sign-out) and `adfs` connections (WS-Fed RP).

**Architecture:** `internal/wsfedidp` (new) for the IdP side; an `adfs`
provider in `internal/federation`; both on `internal/samlcore` (Plan 37a)
plus a SAML 1.1 builder/parser added there.

**Tech Stack:** Go 1.26.10 (no new module beyond Plan 37a's ruling),
Vue/TypeScript console, Playwright 1.64.0.

**Spec:** [Plan 37b design](../specs/2026-11-16-zeroauthy-ws-federation-design.md). § refers to it.

**Depends on:** Plan 37a merged (samlcore, replay store, session
participants).

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Clean room.** `node-wsfed` provenance per default in D-0140.
- **Parity.** LR37b-1…3 and W1–W5 in **D-0140**; follow-ups.
- **Security:** Plan 37a XML limits apply; `wreply` allowlist exact.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za37b GOTMPDIR=/dev/shm/za37b go test -p 4 ./...` plus
  `make e2e-wsfed`; push `plan-37b-wsfed`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan37b`, branch `plan-37b-wsfed`;
  record in `docs/superpowers/2026-11-16-plan-37b-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **`wreply` outside callbacks** → error page, no token posted. Task 3
   `TestWReplyAllowlist`.
2. **Alias collision** between two clients → refused at write. Task 2
   `TestClientAliasesUnique`.
3. **ADFS token with an unknown thumbprint or wrong audience** → refused.
   Task 5 `TestADFSValidation`.

---

### Task 1: Contracts and decisions
- [ ] `api/management.yaml` (`addons.wsfed`, `client_aliases`, `adfs` options), `api/authentication.yaml` (WS-Fed routes), inventory `adfs` block, D-0140, follow-ups (W1 check of `use_wsfed`) → commit `docs: freeze Plan 37b contracts and D-0140`.

### Task 2: Client rules
**Files:** `internal/clientrules` (`client_aliases`, addon), `internal/mgmt/clients.go`, storage unique index (migration if needed), tests.
- [ ] `TestClientAliasesUnique` (Review Focus 2) and round trips → implement → commit `feat(clients): WS-Fed addon and realm aliases`.

### Task 3: WS-Fed IdP sign-in
**Files:** `internal/samlcore/saml11.go`, `internal/wsfedidp/signin.go`, routes, tests.
- [ ] Tests: realm resolution; `TestWReplyAllowlist` (Review Focus 1); `wctx` echo; `whr` connection hint; RSTR shape; signature verifies; lifetime 8 h default; claims as Plan 37a mapper; `api.samlResponse` options apply → implement → commit `feat(wsfedidp): WS-Federation sign-in`.

### Task 4: Metadata and sign-out
**Files:** `internal/wsfedidp/metadata.go`, `signout.go`, tests.
- [ ] Tests: both metadata paths; `wsignout1.0` ends the session and redirects to an allowed `wreply`; `wsignoutcleanup1.0` → implement → commit `feat(wsfedidp): federation metadata and sign-out`.

### Task 5: ADFS connections
**Files:** `internal/federation/rules/adfs.go`, `internal/federation/adfs.go`, ACS branch for `wresult`, tests.
- [ ] Tests: rules (xor sources, thumbprints computed, `entityId` default); login via fixture with SAML 1.1 and 2.0 tokens; `TestADFSValidation` (Review Focus 3); replay; `user_id_attribute`; email-verified policy; HRD; sign-out redirect → implement → commit `feat(federation): ADFS connections`.

### Task 6: Console, seed, Deploy CLI, E2E, docs, final verification
- [ ] Console addon/ADFS pages; seed; Deploy CLI round trip; `make e2e-wsfed`; docs (`docs/ws-federation.md`, compatibility files, `CHANGELOG.md`, roadmap, implementation record); fast tier + E2E; push; review; maintainer approval.
