# Plan 45c — Infrastructure hardening (certificates, DNS, custom JWKS, CORS index, sweeps, Try limits, phone backoff)

**Date:** 2026-11-16. **Status:** design; not implemented.

**Roadmap entry:** [management roadmap, Plan 45](2026-10-19-zeroauthy-management-roadmap-design.md);
[parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md) item **O4**
(track O, independent). Sources: the Plan 19, 23, 24 and 27 follow-ups in
`docs/superpowers/plan-1-followups.md`, the Plan 27 implementation record
(Task 4 row), the [attack protection guide](../../attack-protection.md)
("Phone-provider protection"), the [custom domains guide](../../custom-domains.md)
and the [signing keys guide](../../signing-keys.md). Read
[clean-room policy](../../../CLEAN_ROOM.md) and `AGENTS.md`.

## 1. Outcome and scope

Nine operational gaps close. Local rulings **LR45c-n** and observation
points **I1–In** go in **D-0280** (O4 block D-0280–0289).

| # | Item | Today | After |
|---|---|---|---|
| 1 | Hosted wildcard certificate retries (Plan 23) | per-worker backoff, restarts early | durable per-resource retry schedule in the store (next attempt, attempt count, last error class), shared by replicas, exponential 1 min → 6 h cap with jitter; Let's Encrypt rate-limit answers honour `Retry-After` |
| 2 | DNS providers and challenge delegation (Plan 23) | DigitalOcean only for deployment DNS-01 | a small `dnsprovider` interface with DigitalOcean (existing), **Cloudflare**, **Route 53** (SigV4 via the existing `internal/awssig`) and **RFC 2136** (TSIG dynamic update); **CNAME delegation** of `_acme-challenge.<domain>` to a zone zeroauthy controls (decision §6.1) |
| 3 | Custom public signing JWKS (Plans 20, 23) | stored only | published: `/.well-known/jwks.json` on the custom domains the tenant marks, merging the custom public keys after the managed ones; never used to verify zeroauthy-issued tokens (Plan 20 anti-goal kept); Auth0's documented use is for customer-managed signing when a custom domain is in front (I1) |
| 4 | CORS origin lookup | scans every client per request (`originAllowed` in `internal/server/cors.go`) | per-tenant origin index (set of normalized origins → client count) maintained on client writes, cached per replica with the tenant's client revision, falling back to the scan when the cache is cold |
| 5 | Orphaned sealed upstream-token records (Plan 24) | kept until connection deletion | sweeper removes token records whose identity no longer exists (batched, tenant by tenant) |
| 6 | Custom-script **Try** limiting (Plan 19 follow-up) | unlimited | operator-scoped limiter on the console/system "Try" routes for custom database scripts and Actions test runs: 10 per minute per operator and tenant, 429 with `Retry-After` (LR45c-1) |
| 7 | Phone-provider protection `exponential` (stored only in 1.0) | fixed budgets only | enforced backoff per user identifier on SMS/voice MFA sends (§3) |
| 8 | Plan 27 MySQL deploy/delete freshness | `MAX(number)` / `COUNT` reads inside caller transactions may be stale on MySQL REPEATABLE READ | locking reads (`FOR UPDATE`) or a per-action version row; a dedicated race test for deploy-vs-deploy, deploy-vs-delete and bind-vs-delete; specific store error for duplicate version numbers |
| 9 | Console accessibility audit | none | Playwright + axe-core run over every console route in CI with an allowlist file for accepted issues (empty at the end of the plan) |

Plus the Plan 17 MySQL gap-lock note (`Connections.Delete` vs a mint for
another user) is handled with item 8's pattern if the same fix applies (I2).

### Not in scope

- New certificate authorities beyond ACME (existing).
- DNS providers beyond the four (more through the interface later).
- A web-based accessibility fix campaign beyond what the audit finds in
  this plan (fixes for findings are in scope; redesigns are not).

### Anti-goals

- **DNS credentials leaking.** Provider tokens are file references or
  sealed values, never logged, never returned.
- **Custom keys verifying our tokens.** Item 3 publishes keys; the
  verifier set used by zeroauthy is unchanged.
- **CORS widening.** The index must answer exactly what the scan answers
  (property test over random client sets).
- **Backoff lockouts.** Item 7 never locks a user out permanently; waits
  cap at 32 minutes (documented).

## 2. Evidence

- Auth0 "Exponential backoff for SMS" (`/docs/secure/multi-factor-authentication/multi-factor-authentication-factors/exponential-backoff-for-sms`,
  read 2026-11-16): a set number of immediate retries, then waits growing
  from 1 to 32 minutes, jitter, waits shrink when the user stops, long
  inactivity resets; per user identifier; MFA SMS; `limit_phone` log with
  the remaining wait; enabled with `PATCH /api/v2/attack-protection/phone-provider-protection
  {type: exponential}`; MFA prompt tells the user to wait.
- Plan 23/24/19/27 follow-ups and records (above).
- Cloudflare DNS API, Route 53 `ChangeResourceRecordSets`, RFC 2136/RFC 8945
  (TSIG) for item 2; ACME RFC 8555 §8.4 for DNS-01 and CNAME following.

## 3. Phone exponential backoff

- Applies when `phone-provider-protection.type` is `exponential`, to SMS and
  voice sends for MFA (challenge and enrollment) keyed by tenant and user
  (or phone number before the user exists, I3).
- Schedule (local values, I4): 3 immediate sends; then waits of 1, 2, 4, 8,
  16, 32 minutes (cap) before each further send, with ±10 % jitter; each
  full idle period equal to the current wait steps the level down by one;
  24 h without sends resets.
- A refused send answers the MFA prompt with a localized "wait N minutes"
  message and the Authentication API (`/mfa/challenge`) with `429
  too_many_requests` (I5) and `Retry-After`; logs `limit_phone` with the
  remaining wait.
- The fixed budgets stay in force in both modes.
- Passwordless and signup phone sends keep the fixed budgets only (the
  Auth0 page names MFA; I3).

## 4. Storage

- `certificate_retry` columns on the custom-domain / deployment-domain
  rows (or a small table) for item 1.
- `dns_providers` configuration in the server config (deployment DNS) and,
  for delegation, a `_acme-challenge` CNAME target zone setting.
- `tenant_origin_index(tenant_id, origin, refs)` for item 4, maintained in
  the client write transactions; plugins without the capability
  `origin_index.v1` use the scan.
- `phone_backoff(tenant_id, key, level, next_allowed_at, last_send_at)`
  for item 7.
- One migration numbered at merge.

## 5. Tests

Per item: retry schedule with an injected clock and two replicas (one
attempt per due time); provider adapters against local fakes (Cloudflare
and Route 53 HTTP fakes, an RFC 2136 test server built on the existing DNS
test helpers); delegation following the CNAME; JWKS publication per host;
CORS index ≡ scan property test and a benchmark (10 000 clients); sweeper
batches; Try limiter; backoff schedule table and jitter bounds; MySQL race
tests in CI; axe run with zero unaccepted violations.

## 6. Decisions needed from the maintainer

1. **DNS providers:** confirm Cloudflare, Route 53 and RFC 2136 (the
   parallel-paths brief asks "which DNS providers"), and CNAME delegation.
2. **Backoff values** (I4) until Auth0's table is observed.

## 7. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR45c-1 | Try routes: 10 per minute per operator and tenant. |
| LR45c-2 | Custom JWKS published only on hosts the tenant marks. |
| LR45c-3 | Backoff schedule as §3 until observed. |

Observe later (`docs/superpowers/plan-1-followups.md`):

- **I1** Where Auth0 publishes custom signing keys.
- **I2** Whether the Plan 17 gap-lock case shares item 8's fix.
- **I3** Backoff key before a user exists; passwordless/signup coverage.
- **I4** Auth0's retry count and wait steps.
- **I5** `/mfa/challenge` answer when backed off.
