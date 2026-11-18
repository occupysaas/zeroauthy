# Plan 38c — Tenant network ACLs

**Date:** 2026-11-16. **Status:** design; not implemented.

**Roadmap entry:** [management roadmap, Plan 38](2026-10-19-zeroauthy-management-roadmap-design.md)
(network ACLs); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **O1** (track O, independent). Read the [clean-room policy](../../../CLEAN_ROOM.md),
`AGENTS.md`, the [attack protection guide](../../attack-protection.md)
(suspicious-IP state, allowlists), `internal/httpx/clientip.go` (client IP
and proxy boundary) and D-0044/D-0045 (attack protection decisions).

## 1. Outcome and scope

An operator creates tenant access control lists through
`/api/v2/network-acls`. Each ACL has a priority, an active flag and one
rule: an action (`block`, `allow`, `log`, `redirect`), a scope
(`management`, `authentication`, `tenant`, `dynamic_client_registration`)
and `match` / `not_match` signal sets (or `match_all`). zeroauthy evaluates
the active ACLs on every request to the tenant, before any other handler,
in ascending priority, and applies the first match.

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first). Local rulings **LR38c-n** and observation points **N1–Nn** go in
**D-0250** (O1 block D-0250–0259).

### In scope

1. `GET/POST /api/v2/network-acls`, `GET/PUT/PATCH/DELETE /api/v2/network-acls/{id}`
   (scopes `read:`, `create:`, `update:`, `delete:network_acls`), schema per
   the OpenAPI (§2).
2. Enforcement middleware for every tenant host (canonical and custom
   domains) and every scope.
3. Signals zeroauthy can evaluate: `ipv4_cidrs`, `ipv6_cidrs` (client IP
   after the trusted proxy boundary), `connecting_ipv4_cidrs`,
   `connecting_ipv6_cidrs` (the TCP peer), `hostnames`, `user_agents`,
   `ja3_fingerprints`, `ja4_fingerprints` (from the operator-trusted headers
   introduced by Plan 40 / A1).
4. `acls_summary` tenant logs every 10 minutes per rule.
5. Console page and seed support.

### Not in scope

- **`geo_country_codes`, `geo_subdivision_codes`, `asns`:** zeroauthy has no
  GeoIP or ASN data (D-0053). Accepted and stored; a rule that contains
  any of them never matches, and the console and the write response's
  warning header say so (LR38c-1; decision §8.1).
- **`auth0_managed`** curated lists: Auth0's own threat feeds; accepted,
  never match (LR38c-2).
- **HTTP message signatures** (`match.http_message_signature`,
  `/api/v2/keys/network-acls`): Early Access; refused with `400` until GA
  (LR38c-3).
- Plan limits (1 ACL, or 10 with the add-on): zeroauthy has no plans; the
  limit is 10 ACLs per tenant for everyone (LR38c-4).

### Anti-goals

- **Locking the operator out.** The system tenant (console and system API)
  is never subject to tenant ACLs; a `management` block on a tenant blocks
  that tenant's Management API tokens, not the console's system API
  (LR38c-5).
- **Spoofed client IPs.** IP signals use the client IP only through the
  existing trusted-proxy boundary; `X-Forwarded-For` from untrusted peers is
  ignored, exactly as rate limiting does.
- **Open redirects.** `redirect_uri` must be an absolute HTTPS URL; the
  redirect never carries the original query (N1).
- **Slow requests.** Evaluation is in memory over a per-tenant compiled
  rule set (CIDR tries, hash sets), refreshed within 10 s of a change on
  every replica.

## 2. Evidence

- Management OpenAPI (read 2026-11-16): `CreateNetworkAclRequestContent`
  (`description` ≤ 255 required, `active` required, `priority` 1–100
  default 50, `rule` required), `NetworkAclRule` (`action`, `scope`
  required; `match`, `not_match`, `match_all` — "mutually exclusive with
  `match` and `not_match`"), `NetworkAclAction` (`block` | `allow` | `log` |
  `redirect` each `true`, `redirect_uri` 1–2000), `NetworkAclMatch` (signal
  arrays, each `minItems: 1`), `NetworkAclRuleScopeEnum` (`management`,
  `authentication`, `tenant`, `dynamic_client_registration`).
- `/docs/secure/tenant-access-control-list` (limits 1 or 10 ACLs, up to 20
  entries per source identifier; user-agent signal unsupported with
  self-managed custom domains; `hostnames` can restrict the canonical
  domain while allowing custom domains; monitoring mode; `acls_summary`
  every 10 minutes per rule).
- `.../rule-evaluation` (ascending priority, lowest first; values within a
  signal OR'd; different signals AND'd, except IPv4 and IPv6 CIDRs, of
  which one suffices; first match applies and stops evaluation unless the
  rule is in monitoring mode, which records and continues).

## 3. Evaluation

1. Collect the tenant's active ACLs, sorted by `priority` then `id`
   (LR38c-6: ties).
2. For each rule whose scope covers the request (§4):
   - `match_all: true` → matches.
   - Otherwise the request matches when `match` (if present) matches and
     `not_match` (if present) does not match (LR38c-7, N2).
   - A signal set matches when every signal type present matches (AND),
     each type matching if any value matches (OR), with IPv4 and IPv6 CIDR
     types together counting as one type (documented exception).
   - Rules containing unevaluable signals (geo, ASN, `auth0_managed`) never
     match (LR38c-1/2).
3. First match:
   - `block` → `403` (N3: Auth0's body; local: the Authentication API error
     shape `{"error":"access_denied","error_description":"Request blocked"}`
     on API scopes and a plain error page on hosted pages).
   - `allow` → stop evaluating, continue to the handler.
   - `redirect` → `302` to `redirect_uri`.
   - `log` → monitoring mode: record, continue to the next rule (LR38c-8,
     N4: whether `log` is Auth0's monitoring mode).
4. No match → continue (default allow, N5).
5. Every match (any action) increments the rule's counters for
   `acls_summary`.

## 4. Scopes

| Scope | Routes |
|---|---|
| `management` | `/api/v2/*` on the tenant host |
| `authentication` | `/authorize`, `/oauth/*`, `/u/*`, `/login/*`, `/passwordless/*`, `/mfa/*`, `/co/*`, `/userinfo`, `/oidc/logout`, `/v2/logout`, `/.well-known/*`, `/bc-authorize`, `/me/*` (N6) |
| `dynamic_client_registration` | `/oidc/register` (Plan 41b) |
| `tenant` | every request to the tenant's hosts |

## 5. Logs

- `acls_summary` every 10 minutes per rule that matched at least once in the
  window: rule ID, description, action, match count, sample of up to 5
  client IPs (N7: the summary's fields; read the logs schema at build time).
- Blocked requests are not logged individually (documented summary model);
  the server log has a rate-limited debug line.

## 6. Storage and propagation

- Table `network_acls(tenant_id, id, description, active, priority, rule
  JSON, created_at, updated_at)`; tenant `acl_revision` counter bumped in
  the same transaction as any write; one migration numbered at merge.
- Each replica keeps a compiled set per tenant and re-reads it when the
  revision differs, checking at most every 10 s (LR38c-9); writes on the
  same replica apply at once.
- gRPC capability `network_acls.v1`; without it the API answers `501` and
  nothing is enforced.
- Counters for `acls_summary` are per replica and flushed as one log per
  rule per replica per window (N7 notes the difference).

## 7. Console, seed, Deploy CLI, tests

- **Console:** Security → Network ACLs: list by priority, editor with signal
  chips, monitoring toggle, warning badges for unevaluable signals, a
  "test request" panel evaluating a sample IP/host/user agent locally.
- **Seed:** `network_acls` list.
- **Deploy CLI:** 9.1.0 has `networkACLs` and `networkACLKeys` handlers;
  the four-cell round trip includes ACLs; `networkACLKeys` stays excluded
  (Early Access, LR38c-3).
- **Tests:** rule validation table (20-entry limit per signal type, CIDR
  syntax, `match_all` exclusivity, redirect URL rules); evaluation table
  (priority, AND/OR, IPv4/IPv6 exception, `not_match`, monitoring);
  middleware tests for every scope including custom domains and the system
  tenant exemption; propagation test with two store-sharing servers;
  benchmark (10 ACLs × 20 entries, < 5 µs per request).
- **E2E:** extend `make e2e` with node-auth0 `networkAcls` CRUD (if 7.4.0
  has it, else raw) and a curl suite: block by IP, allow overriding a later
  block, redirect, monitoring, hostname restriction of the canonical host.

## 8. Decisions needed from the maintainer

1. **Geo and ASN signals:** store-and-never-match (proposed), or add an
   optional operator-supplied MaxMind-format database later (needs a reader;
   no module exists in `go.mod`).
2. **System tenant exemption** (LR38c-5): confirm.

## 9. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR38c-1 | Geo/ASN signals stored, never match, with warnings. |
| LR38c-2 | `auth0_managed` stored, never matches. |
| LR38c-3 | HTTP message signatures refused while Early Access. |
| LR38c-4 | 10 ACLs per tenant; 20 entries per signal type. |
| LR38c-5 | The system tenant is never subject to ACLs. |
| LR38c-6 | Equal priorities ordered by ID. |
| LR38c-7 | `match` AND NOT `not_match`. |
| LR38c-8 | `log` is monitoring mode: record and continue. |
| LR38c-9 | Changes reach every replica within 10 s. |

Observe later (`docs/superpowers/plan-1-followups.md`):

- **N1** Redirect query handling.
- **N2** `match` with `not_match` semantics.
- **N3** Blocked response body.
- **N4** Monitoring mode vs the `log` action.
- **N5** Default when nothing matches.
- **N6** Routes covered by the `authentication` scope.
- **N7** `acls_summary` fields.
