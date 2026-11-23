# Plan 37c implementation record

Status: **Phase A (inbound SCIM and directory groups) implemented and
verified locally; phases B and C pending.** Started from `main` commit
`953ee03e`. Branch: `plan-37c-scim`; worktree:
`/mnt/nvme2/code/zeroauthy-plan37c`. Not pushed yet: AGENTS.md forbids
pushing a partial plan to start CI, so the branch goes to plan-branch CI
when all three phases are done. Maintainer approval governs integration.

Spec: [SCIM and self-service design](specs/2026-11-16-zeroauthy-scim-self-service-design.md).
Plan: [Plan 37c](plans/2026-11-16-zeroauthy-plan-37c-scim-self-service.md).
Decisions: D-0150 (LR37c-1…9). Operator guide: [SCIM](../scim.md).
Observation points: Q1–Q15 in
[plan-1-followups.md](plan-1-followups.md#plan-37c-observation-points).

Maintainer rulings (2026-11-22): phases A → B → C; Phase C with fixture
coverage of the Google Directory API only.

## Progress

### Phase A

1. A1 `30994aa9`: contracts frozen (Management OpenAPI SCIM and group
   operations, `api/scim.yaml`), D-0150 LR37c-1…5.
2. A2 `8ad7a2a4`: `store.Directory` (`scim.v1` capability) on memory,
   SQLite, PostgreSQL and MySQL (migration 0046), gRPC plugins and the
   events decorator; cascades on user, role, organization, connection and
   tenant deletion; conformance suite `Directory`.
3. A3 `9b4c7e69`: SCIM filter and path parser (fuzzed), mapping, PATCH,
   and the Users endpoint with isolation and deactivation (sessions,
   refresh tokens, back-channel logout).
4. A4 `ba84a705`: SCIM Groups and discovery.
5. A5 `d664be49`: Groups Management API (17 routes, own scopes), group
   roles in the authorization snapshot every token path uses,
   organization group roles, effective-role `group` source, Actions
   `api.groups` and group roles in `event.authorization.roles`.
6. A6 `b25e693b`, `67fa9410`, `4786f411`, `7c4a6b49`, `f9553422`: SCIM
   configuration and token Management routes; console Provisioning tab,
   Groups pages and role/user Groups tabs; `make e2e-scim`; this record and
   [SCIM](../scim.md).

## Verification (Phase A)

| Check | Result |
|---|---|
| `go test ./internal/scim ./internal/store ./internal/mgmt ./internal/actions ./internal/actionsrules ./internal/tenantsetup ./api/...` | ok |
| `go test ./internal/server` (after the final snapshot change) | ok (593 s) |
| `go test ./internal/oauth ./internal/authz ./internal/actions` (after the snapshot fix) | ok |
| SQL dialects and gRPC conformance for `Directory` (A2) | ok (SQLite, PostgreSQL, MySQL containers; `-timeout` raised under load) |
| Console `npm test` | 96 files, 750 tests passed |
| Console typecheck, lint, `make console` | clean; `console/dist` rebuilt |
| `make e2e-scim` | passed, no skips: node-auth0 7.4.0 configuration, tokens, groups and group roles; RFC 7644 Entra/Okta provisioning; isolation; deprovisioning; revocation; log audit; Deploy CLI 9.1.0 four cells |
| Fast tier `go test ./...` | see below |
| zizmor | not run locally (no `uvx`); the only workflow change adds `e2e-scim` to the E2E matrix; CI runs zizmor |

Mutation checks: discovery without a token (401), cross-connection reads,
organization connection eligibility for group roles, tenant group roles
excluded from organization effective roles, and token hashing were each
broken on purpose and caught by a test.

## Findings during Phase A

- The first group-roles snapshot change opened a transaction for every
  non-organization token and broke `internal/oauth` tests that wrap
  `RBAC()`; the tenant path is again the plain RBAC snapshot, with group
  roles added after it.
- `UserGroup` was `allOf: [Group]` with `additionalProperties: false`, so
  `membership_created_at` could never validate; `fields` projection also
  conflicted with required properties. Both schemas fixed.
- A duplicate SCIM configuration answered 409; Auth0 answers 400 "already
  exists", which the Deploy CLI `scimHandler` relies on (LR37c-8).
- Path-less PATCH values with attribute-path keys (Entra ID) were lost
  (LR37c-9); found by `make e2e-scim`.
- The Deploy CLI export omits `client_secret`, so an exported `okta`
  connection cannot be re-imported without keyword replacement; the round
  trip uses `samlp` connections (unrelated to SCIM).

## Rulings

Recorded in the ledger and D-0150: discovery needs a connection token
(LR37c-6); group roles in tokens and organization effective roles
(LR37c-7); 400 "already exists", offset cursors, `hasGroupMembership`
semantics (LR37c-8); path-less PATCH paths (LR37c-9); `Group` and
`UserGroup` have no required properties because `fields` can project any
away.

## Phase B (self-service SSO)

1. B1 `e9af1acc`, `70658145`, `35e1c891`: contracts imported from Auth0's
   Management OpenAPI (16 operations, 75 schemas; one lookahead pattern
   restated for RE2); `store.SelfService` on memory, SQLite, PostgreSQL,
   MySQL (migration 0047) and gRPC (scim.v1 version 2 over DirectoryCall);
   tickets bound to their one connection.
2. B2 `fc1f39b9`: Management routes, validated against the contract's
   schemas at runtime.
3. B3 `f9482ccc`: the hosted assistant (`internal/selfservice`) with a
   fuzzed allowlist sanitizer for custom text.
4. B4 `9bfa8c42`, `f1613494` and this update: console, `make
   e2e-self-service`, [Self-service SSO](../self-service-sso.md).

Findings: Chrome posts with `Origin: null` under `Referrer-Policy:
no-referrer`, which the assistant's origin check refused (now
`same-origin`); SPA applications need PKCE on the test sign-in link; the
connection list omits `enabled_clients` (the E2E reads
`/connections/{id}/clients`).

Mutation checks: ticket hashing, version-2 capability gating, the domain
allowlist, the fixed strategy after creation and the edit ticket's `sso`
switch were each broken on purpose and caught.
