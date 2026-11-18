# Plan 45b — Flow and API correctness fixes (pre-1.0 review deferrals)

**Date:** 2026-11-16. **Status:** Tasks 1–13 implemented on the plan branch. See the [verification and integration record](../2026-11-16-plan-45b-implementation-record.md).

**Roadmap entry:** [management roadmap, Plan 45](2026-10-19-zeroauthy-management-roadmap-design.md)
("Pre-1.0 review … Deferred here"); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **O3** (track O, independent). Sources: the
[pre-1.0 review](../reviews/2026-11-03-pre-1.0/) findings cited per item,
and the Plan 33 review minors in `docs/superpowers/plan-1-followups.md`.
Read the [clean-room policy](../../../CLEAN_ROOM.md) and `AGENTS.md`.

## 1. Outcome and scope

Eleven small defects and parity gaps found by the pre-1.0 review are fixed,
each with a regression test. None adds a resource; each is local to one
flow or handler. Local rulings **LR45b-n** and observation points
**B1–Bn** go in **D-0270** (O3 block D-0270–0279).

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first). Where the review's verdict was only "plausible", the fix follows
the documented schema and the point is listed for observation.

### In scope

| # | Finding | Fix |
|---|---|---|
| 1 | Side effects before MFA: invitation acceptance, organization auto-membership, `last_login`/`logins_count`, session creation, and the consent step (Plan 33 M1) run before MFA completes (hosted-login-mfa F7) | §3 |
| 2 | Signup verification codes live 5 min instead of the frozen 900 s; the send budget is not scoped by connection or purpose (hosted-login-mfa F6) | use `phonerules.Limits.SignupOTPLifetimeSeconds` for signup; key the budget by tenant, identifier, connection and kind |
| 3 | Brute-force denials log `limit_wc` and `limit_sul`, on every refused attempt (mgmt-config F4) | emit only `limit_wc`, once per block transition (B1) |
| 4 | Console passwordless "send test" calls `/passwordless/start` cross-origin with the operator token (console-docs F7) | new operator-only system route `POST /api/system/tenants/{t}/connections/{id}/passwordless/try` running the start service server-side; the console uses it; the operator token never reaches Authentication API routes |
| 5 | Unauthenticated `/admin/` CSP lists every tenant's domains (console-docs F8) | `connect-src 'self' https://*.<base_domain>` plus the system host; explicit custom domains are reached through the system host proxy for Management calls (LR45b-1) |
| 6 | `PATCH /users/{id}` refuses `null` for nullable attributes and refuses `verify_phone_number` (mgmt-resources F3) | accept `null` on `email`, `phone_number`, `given_name`, `family_name`, `name`, `nickname`, `picture`, `username` with Auth0's clearing rules (a required identifier cannot be cleared: `400`, B2); accept `verify_phone_number: true` by sending the Plan 34 phone verification code (B3) |
| 7 | `organization_id` refused on `POST /jobs/verification-email` and `POST /tickets/email-verification` (mgmt-resources F4) | accept it, check membership like the password-change ticket, carry it into the email and ticket context; fix the stale comment |
| 8 | `GET /users/{id}/organizations` and `GET /organizations/{id}/members` accept scopes the OpenAPI does not list (mgmt-resources F5) | require `read:organizations` and `read:organization_members` respectively (keeping the `fields=roles` check); amend D-0055 (LR45b-2) |
| 9 | `GET /users?connection=` filters under search engine v2/v3 (mgmt-resources F6) | ignore `connection` under v2/v3 (documented v1-only), still validating its text; record in D-0043 and `docs/user-search.md` |
| 10 | `GET /emails/provider` hides the non-secret credential members and ignores `fields`/`include_fields` (mgmt-config F6) | return `api_user`, `region`, `smtp_host`, `smtp_port`, `smtp_user` (moved to the public part of the provider config by an online migration of the sealed blob); apply field projection; amend D-0047 (LR45b-3) |
| 11 | Attack-protection counters lock the tenant row on every attempt (storage-ops-security F8) | lock the bucket rows instead (`INSERT … ON CONFLICT DO NOTHING` then `SELECT … FOR UPDATE` per bucket, ordered keys to avoid deadlocks) on PostgreSQL/MySQL; SQLite unchanged (single writer) |

Plus, from the Plan 33 review minors list (follow-ups file), the ones that
need no ruling: **M3** purge abandoned pending authenticators, **M6**
`multifactor` on `GET /users` computed without one authenticator list per
user (batched), **M7** `amr` read at code issue (stored with the code), not
at exchange.

### Not in scope

- **Actions MFA ordering** (a later `api.multifactor.enable('none')` after
  an earlier challenge): the maintainer ruled on 2026-11-08 to leave it as
  is. This plan does not change Action execution order; §3 moves only
  non-Action side effects (LR45b-4).
- Items owned by O2 (sandbox, keys) or O4 (infrastructure).

### Anti-goals

- **Moving tokens or Actions.** §3 never issues tokens earlier or later
  than today and never moves post-login Actions relative to MFA.
- **Breaking stored data.** Item 10's migration keeps the sealed secret
  members sealed and is reversible by keeping the old blob until the new
  form is read successfully.
- **Lock-order deadlocks** in item 11: buckets are always locked in sorted
  key order.

## 2. Evidence

- The review files and lines cited in the table (`hosted-login-mfa.md`
  F6–F7, `mgmt-config.md` F4/F6, `console-docs.md` F7–F8,
  `mgmt-resources.md` F3–F6, `storage-ops-security.md` F8).
- Auth0 logs schema (`limit_wc`, `limit_sul` descriptions), Management
  OpenAPI (`UpdateUserRequestContent` nullable fields and
  `verify_phone_number`; the `organization_id` members; the scopes of
  `get_user_organizations` and `get_members`; `connection` "only applies
  when using search_engine=v1"; `EmailProviderCredentials`), D-0060
  (signup code lifetime), D-0047, D-0055, D-0043.

## 3. Side effects after MFA

Today (`internal/authz/handlers.go` `Resume`, `internal/login/login.go`
password commit and `complete`) these happen after the first factor:
invitation acceptance and its completion claim, `EnsureMembership`,
`RecordLogin` (`last_login`, `logins_count`), login-session creation, and
the consent page and its persistence.

New order, matching Auth0's documented flow (first factor → MFA → consent →
redirect) and the review's suggestion:

1. First factor succeeds → transaction records the authenticated identity
   (as today) but no durable side effect.
2. MFA (Plan 33 `requireMFA`) completes, or is not required.
3. Consent (Plan 9) — shown only now.
4. In one transaction before the code (or token) is issued: invitation
   acceptance and membership, session creation, `RecordLogin`.
5. Post-login Actions keep their current position (LR45b-4) and therefore
   see `stats.logins_count` already incremented as today (B4: Auth0's
   value at that point).

A login abandoned at MFA leaves no invitation consumed, no membership, no
session and unchanged counters.

## 4. Tests

Each table row gets at least one failing test first, named after the
finding (`TestNoSideEffectsBeforeMFA`, `TestSignupCodeLifetime900`,
`TestBruteForceLogsLimitWCOnce`, `TestPasswordlessTryRoute`,
`TestAdminCSPNoTenantDomains`, `TestPatchUserNulls`,
`TestVerifyPhoneNumber`, `TestVerificationOrganizationID`,
`TestOrganizationReadScopes`, `TestUsersConnectionV1Only`,
`TestEmailProviderPublicCredentials`, `TestProtectionBucketLocks` (with a
contention test showing two tenants no longer serialize and one tenant's
different identifiers proceed in parallel), and the M3/M6/M7 tests.
`make e2e-mfa`, `make e2e-organizations-ii`, `make e2e-passwordless` and
`make e2e-email` cover the flows end to end.

## 5. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR45b-1 | The admin CSP uses the base-domain wildcard; custom domains go through the system host. |
| LR45b-2 | Organization reads require exactly the OpenAPI scopes. |
| LR45b-3 | SMTP host/port/user, `api_user` and `region` are not secrets. |
| LR45b-4 | Actions keep their position relative to MFA (2026-11-08 ruling). |

Observe later (`docs/superpowers/plan-1-followups.md`):

- **B1** Whether Auth0 logs `limit_wc` once per block or per attempt.
- **B2** Clearing a connection's required identifier with `null`.
- **B3** What `verify_phone_number` triggers on Auth0.
- **B4** `stats.logins_count` seen by post-login Actions.
