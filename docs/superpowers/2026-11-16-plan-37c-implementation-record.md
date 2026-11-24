# Plan 37c implementation record

Status: **Phases A, B and C implemented and verified locally; plan-branch
CI pending.** Started from `main` commit `953ee03e`. Branch:
`plan-37c-scim`; worktree: `/mnt/nvme2/code/zeroauthy-plan37c`.
Maintainer approval governs integration.

Spec: [SCIM and self-service design](specs/2026-11-16-zeroauthy-scim-self-service-design.md).
Plan: [Plan 37c](plans/2026-11-16-zeroauthy-plan-37c-scim-self-service.md).
Decisions: D-0150 (LR37c-1…16). Operator guides: [SCIM](../scim.md), [Self-service SSO](../self-service-sso.md), [Directory provisioning](../directory-provisioning.md).
Observation points: Q1–Q19 in
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

## Phase C (Google Workspace directory provisioning)

1. C1 `94a46574`, `96044481`, `b0dc70ff`: contracts (11 operations, 17
   schemas, four scopes); the `google-apps` strategy (LR37c-14) on the
   Google OIDC adapter with the `hd` binding; `store.DirectorySync` on
   memory, SQLite, PostgreSQL, MySQL (migration 0048) and gRPC (`scim.v1`
   version 3), cascading with the connection and tenant.
2. C2 `3e8882fd`: `internal/dirsync`: administrator consent (LR37c-15) and
   the syncer (LR37c-16), started with the server like the Actions worker.
3. C3 `6b1fbfb2`, `3c0d5b0e` and this update: Management routes and the
   system API consent link, console (Google Workspace setup and the
   Provisioning tab), [Directory provisioning](../directory-provisioning.md).

Coverage is a fixture Google (maintainer ruling); there is no Phase C E2E
suite because no Auth0 SDK or Deploy CLI release in the pins calls the
directory provisioning routes, and a browser run of the consent would only
replay the fixture the Go tests already drive.

Mutation checks: the `hd` comparison, the consent's state binding and
administrator probe, blocking of removed users, unblocking only
synchronization's own blocks, and the connection cascade of the new tables
were each broken on purpose and caught.

Findings: `go test` passes `GOTMPDIR` to tests as `TMPDIR`; with
`GOTMPDIR` on the btrfs disk (stalled `btrfs-transaction`), every SQLite
fsync waited seconds and the store suites ran past 2.5 hours on main and on
the branch alike. With both on tmpfs they take 25 s (sqlstore) and 77 s
(grpcstore). A forged-state consent test first passed for the wrong reason
(the code exchange failed first); it now presents a valid code.

## Verification (Phases B and C)

| Check | Result |
|---|---|
| `./scripts/test-sql.sh -timeout 60m ./internal/store/sqlstore` (race; SQLite, PostgreSQL, MySQL) at `94a46574` | ok, 3349 s, 0 skips |
| `go test ./internal/store/sqlstore ./internal/store/grpcstore` at `94a46574` | ok (25 s, 77 s) |
| DirectorySync conformance on PostgreSQL and MySQL at `b0dc70ff` | ok |
| `go test ./api/... ./internal/mgmt/... ./internal/dirsync/... ./internal/federation/... ./internal/login/... ./internal/app/...` | ok |
| `go test ./internal/server -run 'DirectoryProvisioning|GoogleApps|SocialConnections|MicrosoftConnections'` | ok |
| Console `npm test`, lint, typecheck; `make console` | 98 files, 754 tests passed; clean; `console/dist` rebuilt |
| Fast tier `go test -p 4 ./...` (tmpfs) at `4acd22a2` | 112 packages ok; 2 failed: `internal/server` `TestEveryAuthenticationRouteIsRateLimited` (CONNECT on the Phase B assistant route answered 404 before the limiter) and `internal/store/sqlstore` `TestEventsMigrationFrom30` (expected migration 47); both fixed in `3f4d09b1` |
| `go test ./internal/server ./internal/store/sqlstore ./internal/dirsync` at `3f4d09b1` | ok (49 s, 25 s, 1 s) |
| `make e2e-self-service` at `3f4d09b1` | passed, no skips |

## Final review

Reviewed the Phase C diff (federation `hd` binding, consent flow, syncer,
Management routes, operator target). One finding fixed in `46a40c4b`: a
transient failure reading one selected group deleted the local group and
its role assignments. The run lease is now one hour. A user whose update
fails is still counted as present (regression test).
