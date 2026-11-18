# Plan 41b — Dynamic Client Registration and CIMD Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Open RFC 7591 registration at `/oidc/register`, Client ID
Metadata Document clients (Management preview/register and resolution at
the authorization endpoints), the related tenant settings and client
fields, and the OIDF Dynamic OP conformance plan.

**Architecture:**
- **`internal/dcr`** (new): request validation and mapping to a
  `clientrules.Spec`, used by `/oidc/register`.
- **`internal/cimd`** (new): fetcher (federation outbound policy), cache,
  validator, mapper (shared by Management routes and the authorization
  endpoints).
- **`internal/oauth` / `internal/authz`**: client lookup gains a CIMD
  resolver step for URL `client_id`s.
- **Storage:** client columns and `cimd_documents`.

**Tech Stack:** Go 1.26.10 (no new module), Vue/TypeScript console,
`@auth0/auth0-spa-js` 2.28.3, OIDF suite `release-v5.3.3`.

**Spec:** [Plan 41b design](../specs/2026-11-16-zeroauthy-dynamic-client-registration-design.md). § refers to it.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Parity.** LR41b-1…3 and R41-1…8 in **D-0090**; R41 points in
  `docs/superpowers/plan-1-followups.md`; amend D-0025 (DCR clients) and
  D-0063 (CIMD credentials).
- **Limits.** `redirect_uris` ≤ 20; `client_name` ≤ 255; CIMD document ≤
  64 KiB, fetch 10 s, cache 5 min–24 h; DCR 5 req/s per tenant.
- **Security.** Third-party rules of D-0025 apply unchanged to every DCR and
  CIMD client.
- **Migration.** One forward-only migration in three dialects written as
  `0047_dcr_cimd.sql`; renamed to main's latest + 1 at merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za41b GOTMPDIR=/dev/shm/za41b go test -p 4 ./...` plus
  `make e2e-dcr` and the conformance Dynamic OP plan; push
  `plan-41b-dcr`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan41b`, branch `plan-41b-dcr`;
  record in `docs/superpowers/2026-11-16-plan-41b-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **DCR cannot escalate:** a registration asking for `client_credentials`,
   `password` or `implicit` gets only `authorization_code`/`refresh_token`;
   the client cannot use non-domain connections. Task 2 `TestRegisterFiltersGrants`.
2. **CIMD identity binding:** a document whose `client_id` differs from its
   URL is refused; a redirect to another origin is refused. Task 4
   `TestCIMDBinding`.
3. **SSRF table:** private IPs, loopback, `http://`, oversize, slow body →
   refused before any data leaves. Task 4 `TestCIMDFetchPolicy`.
4. **Register idempotency:** two concurrent `register` calls for one URL →
   one client. Task 5 `TestCIMDRegisterConcurrent`.

---

### Task 1: Contracts and decisions

**Files:** `api/authentication.yaml` (`POST /oidc/register`),
`api/management.yaml` (two CIMD routes, client fields, tenant settings),
`make generate`, stubs; `internal/tenantrules/inventory.go` (flags active);
D-0090; follow-ups.
- [ ] Edits → `go build ./...` → commit `docs: freeze Plan 41b contracts and D-0090`.

### Task 2: `/oidc/register`

**Files:** `internal/dcr/*.go`, tests; `internal/server/server.go` route;
discovery `registration_endpoint`; rate limiter group; logs.
- [ ] Tests: field table, `TestRegisterFiltersGrants` (Review Focus 1), `tpc_` IDs, strict vs permissive from the tenant setting, secret absent for `none`, `client_secret_expires_at: 0`, RFC 7591 errors, off → `404`, rate limit `429`, ACL scope (if O1 merged) → implement → commit `feat(oidc): dynamic client registration`.

### Task 3: Storage

**Files:** migration, client codecs (memory/sql/grpc), `cimd_documents`
repository + storetest, capability `cimd.v1`.
- [ ] storetest (unique `external_client_id`, document cache CRUD) → implement → commit `feat(store): CIMD documents and external client IDs`.

### Task 4: CIMD fetcher and validator

**Files:** `internal/cimd/fetch.go`, `validate.go`, `map.go`, tests.
- [ ] Tests `TestCIMDFetchPolicy` (Review Focus 3), `TestCIMDBinding` (Review Focus 2), cache bounds from `Cache-Control`, mapping table, `jwks`/`jwks_uri` → credential set → implement → commit `feat(cimd): fetch, validate and map client metadata documents`.

### Task 5: Management preview and register

**Files:** `internal/mgmt/clients_cimd.go`, tests.
- [ ] Tests: preview response shape and no side effect; register create `201`/update `200` with the right scope each; `409` for a DCR client; `TestCIMDRegisterConcurrent` (Review Focus 4); credential rotation follows the document → implement → commit `feat(mgmt): CIMD client preview and registration`.

### Task 6: Resolution at the authorization server

**Files:** `internal/authz` and `internal/oauth` client lookup, PAR, token
endpoint (`private_key_jwt` with CIMD credentials), discovery flag, tests.
- [ ] Tests: known CIMD client by URL; unknown URL with/without dynamic registration; unavailable document past hard expiry → `invalid_client`; refreshed document changes callbacks only after refetch → implement → commit `feat(oauth): resolve CIMD client IDs`.

### Task 7: Default third-party permissions

**Files:** tenant settings (`default_third_party_grants` or Auth0's name per
R41-8), applied at DCR/CIMD creation, tests, docs marking a local
extension if needed.
- [ ] Tests: created client gets the default user grants; changing the default does not touch existing clients → implement → commit `feat: default API grants for dynamically registered clients`.

### Task 8: Console, seed, conformance, E2E, docs, final verification

- [ ] **Step 1:** Console settings and CIMD preview; Vitest; `console/dist`.
- [ ] **Step 2:** Seed flags and `cimd_clients`.
- [ ] **Step 3:** Conformance: add the Dynamic OP plan to `tests/conformance/run.sh`, run, triage per `docs/conformance.md`.
- [ ] **Step 4:** E2E lane `make e2e-dcr`; CI matrix.
- [ ] **Step 5:** Docs: new `docs/dynamic-client-registration.md`; `docs/consent.md` (third-party), `docs/conformance.md`, compatibility files, `CHANGELOG.md`, roadmap; implementation record.
- [ ] **Step 6:** Fast tier + E2E + conformance; push `plan-41b-dcr`; record CI; review; maintainer approval.
