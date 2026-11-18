# Plan 45c — Infrastructure hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the nine operational gaps of the spec: durable certificate
retries, more DNS providers and challenge delegation, custom JWKS
publication, a CORS origin index, the orphaned-token sweep, Try limiting,
enforced phone backoff, the Plan 27 MySQL freshness closure and a console
accessibility audit.

**Architecture:** items are independent; each task owns its package
(`internal/certificates`, new `internal/dnsprovider`, `internal/keys` +
`internal/oidc` for JWKS, `internal/server/cors.go` + store index,
`internal/app/sweeper.go`, `internal/mgmt` Try routes,
`internal/phone`/`internal/mfa` backoff, `internal/store/sqlstore` actions,
`console/e2e` axe run).

**Tech Stack:** Go 1.26.10 (no new Go module; Route 53 via
`internal/awssig`; RFC 2136/TSIG through the DNS code the custom-domain
tests already use — if that needs a new module, stop and ask), Playwright
1.64.0; `@axe-core/playwright` is a new dev pin — **needs maintainer
approval** (Task 10 gate).

**Spec:** [Plan 45c design](../specs/2026-11-16-zeroauthy-infrastructure-hardening-design.md). Item numbers refer to its table.

**Gates:** Task 3 waits for ruling §6.1; Task 8 for §6.2 if the maintainer
wants different values; Task 10 for the axe pin.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin; no new Go
  module; one new dev npm pin only if approved.
- **Parity.** LR45c-1…3 and I1–I5 in **D-0280**; I points in
  `docs/superpowers/plan-1-followups.md`; mark the closed follow-ups.
- **Never logged:** DNS provider tokens, TSIG secrets.
- **Migration.** One forward-only migration in three dialects written as
  `0046_infrastructure.sql`; renamed to main's latest + 1 at merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za45c GOTMPDIR=/dev/shm/za45c go test -p 4 ./...` plus
  `make e2e-domains e2e-mfa e2e-actions`; push `plan-45c-infrastructure`;
  report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan45c`, branch
  `plan-45c-infrastructure`; record in
  `docs/superpowers/2026-11-16-plan-45c-implementation-record.md`.
- **Commits** signed off, one per task.

## Review Focus

1. **CORS index equivalence:** random client sets and writes → index
   answer equals the scan for every origin. Task 5 `TestOriginIndexMatchesScan`.
2. **Retry schedule across replicas:** exactly one attempt per due time.
   Task 2 `TestCertificateRetryOneAttempt`.
3. **Backoff never exceeds 32 min** and resets after idle. Task 8
   `TestPhoneBackoffSchedule`.
4. **Actions deploy races on MySQL:** two concurrent deploys get distinct
   version numbers or one clear conflict; deploy-vs-delete never leaves a
   version of a deleted action. Task 9 `TestActionsDeployRaces`.

---

### Task 1: Decisions

- [ ] D-0280, follow-ups, mark closed entries; commit `docs: D-0280 for Plan 45c`. Ask for the §6 rulings and the axe pin.

### Task 2: Durable certificate retries (item 1)

**Files:** `internal/certificates` (or `internal/customdomain`) worker, store
columns, tests.
- [ ] Tests `TestCertificateRetrySchedule` (1 min → 6 h cap, jitter bounds, `Retry-After` honoured), `TestCertificateRetryOneAttempt` (Review Focus 2), restart keeps the schedule → implement → commit `feat(certificates): durable retry schedule for hosted certificates`.

### Task 3: DNS providers and delegation (item 2, gated §6.1)

**Files:** create `internal/dnsprovider` (`Provider` interface:
`Present(ctx, fqdn, value)`, `CleanUp`), move DigitalOcean onto it, add
Cloudflare, Route 53, RFC 2136; config; delegation (follow
`_acme-challenge` CNAME to the configured zone); tests with HTTP and DNS
fakes.
- [ ] Tests per provider (create, cleanup, auth failure, timeout) and `TestDNS01Delegation` → implement → `docs/custom-domains.md` → commit `feat(certificates): Cloudflare, Route 53 and RFC 2136 DNS-01 with CNAME delegation`.

### Task 4: Custom JWKS publication (item 3)

**Files:** `internal/keys` (custom key read), `internal/oidc` JWKS handler,
custom-domain flag (`publish_custom_jwks` on the tenant's custom-domain
settings, LR45c-2), tests.
- [ ] Tests `TestCustomJWKSPublishedOnMarkedHost`, `TestCustomJWKSNotTrusted` (a token signed by a custom key is still refused by `/userinfo` and the Management API) → implement → commit `feat(keys): publish custom public signing keys on marked custom domains`.

### Task 5: CORS origin index (item 4)

**Files:** `internal/store` (`OriginIndex` methods on clients), drivers,
storetest, `internal/server/cors.go`, tests and benchmark.
- [ ] Tests `TestOriginIndexMatchesScan` (Review Focus 1), `BenchmarkOriginAllowed` (10 000 clients), capability fallback → implement → commit `perf(cors): per-tenant origin index`.

### Task 6: Orphaned token sweep (item 5)

**Files:** `internal/app/sweeper.go`, `store.Federation` (`DeleteOrphanTokens(ctx, before, limit)`), drivers, storetest.
- [ ] Tests (orphan removed, owned token kept, batch limit) → implement → commit `feat(federation): sweep orphaned upstream token records`.

### Task 7: Try limiting (item 6)

**Files:** `internal/mgmt` Try routes for custom DB scripts and Actions test
runs, limiter keyed by operator and tenant, tests.
- [ ] Tests (11th call in a minute → 429 with `Retry-After`; other operator unaffected) → implement → commit `feat(mgmt): limit custom script and Action test runs`.

### Task 8: Phone exponential backoff (item 7)

**Files:** `internal/phone` or `internal/mfa` send path, store
`phone_backoff`, hosted MFA message, `/mfa/challenge` answer, logs
(`limit_phone`), tests; `docs/attack-protection.md`.
- [ ] Tests `TestPhoneBackoffSchedule` (Review Focus 3), `TestPhoneBackoffDefaultMode` (fixed budgets only), `TestPhoneBackoffMessages` → implement → commit `feat(mfa): enforce exponential phone send backoff`.

### Task 9: MySQL Actions freshness (item 8)

**Files:** `internal/store/sqlstore/actions.go`, storetest race cases,
store error mapping.
- [ ] Tests `TestActionsDeployRaces` (Review Focus 4) on all three dialects in CI → implement → check the Plan 17 gap-lock case (I2) and fix it the same way if it applies → commit `fix(store): serialize Actions deploy and delete on MySQL`.

### Task 10: Console accessibility audit (item 9, gated pin)

**Files:** `tests/e2e/m45c-a11y.spec.mjs`, allowlist file, fixes in
`console/src`, `console/dist`; `Makefile` (`e2e-a11y`), CI matrix.
- [ ] Run axe over every console route; fix violations; allowlist only with a reason; commit `test(console): accessibility audit with axe`.

### Task 11: Docs and final verification

- [ ] **Step 1:** `docs/custom-domains.md`, `docs/signing-keys.md`, `docs/attack-protection.md`, `docs/deployment.md`, `CHANGELOG.md`, roadmap; implementation record.
- [ ] **Step 2:** Fast tier + E2E targets; push `plan-45c-infrastructure`; record CI.
- [ ] **Step 3:** Whole-branch review, fix wave, green CI, maintainer approval.
