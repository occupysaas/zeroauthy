# Plan 26 — Roles and Permissions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Ship tenant roles and direct permissions that govern custom-API user tokens, with management, console and migration support.

**Architecture:** Add a tenant-scoped RBAC store with atomic authorization snapshots across memory, SQL and gRPC. Shared rules serve seed and management; one OAuth authorization evaluator feeds every existing user grant, while the minter implements the four token profiles. Existing client-access, consent and operator boundaries stay in force.

**Tech Stack:** Go 1.26.7, existing JOSE and protobuf generators, SQLite/PostgreSQL/MySQL, Vue/TypeScript, Vitest/Playwright, pinned Auth0 tools.

**Spec:** [Roles and permissions design](../specs/2026-10-27-zeroauthy-roles-permissions-design.md). Status: implemented, reviewed and locally verified. Actual results are recorded in [the implementation record](../2026-10-27-plan-26-implementation-record.md).

## Global Constraints

- Preserve Go 1.26.7 and the existing Vue/TypeScript, JOSE, SQL and protobuf stack; no new runtime service or dependency is required.
- All role and permission references are tenant-scoped; custom API assignments never confer operator or Management API authority.
- Defaults remain `enforce_policies=false` and `token_dialect=access_token`; system APIs retain their current restrictions.
- SQL migrations are additive; use the next free migration number, currently 0022. Never edit historical migrations.
- RBAC lookup or capability failures fail closed; no cached or empty-success fallback.
- Tests use local fixtures. Live Auth0 evidence is optional and reported separately.
- Plan 19's database-test hold remains specific to Plan 19; this plan does not alter it.

## Review Focus

1. Removing one permission source must retain other sources; deleting/recreating an API permission must not restore old assignments (Tasks 2–4).
2. Role revocation after code/device approval and before refresh must affect the next snapshot, with no refresh scope expansion (Task 7).
3. Same permission text in another API/tenant and account linking must not confer unintended rights (Tasks 2–4, 7).
4. An old plugin or failing store must not drop enforcement flags or mint permissive tokens; system authority must remain separate (Tasks 4–7).
5. RFC token headers/client claims and unrequested permissions can expose consumer assumptions; `/userinfo` and real scope middleware must behave correctly (Tasks 6–9).

## Files, interfaces and execution order

New focused files: `internal/store/rbac.go`, driver `rbac.go` files,
`internal/rbacrules/{rules,inventory}.go`, `internal/oauth/rbac.go`,
`internal/mgmt/{roles,user_rbac}.go`, console role/user components, and Plan 26
local E2E fixtures. Extend existing API/store/seed/tenant bootstrap modules,
protobuf/OpenAPI sources and their generated outputs. Avoid hand-editing generated
code or restructuring unrelated modules.

Order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10. Each task includes its own
verification and commit. Test names below are new tests to create, not evidence
that they already exist. Confirm focused selections actually execute tests and
inspect their helpers before claiming a memory-only run. Commit named files and
generated outputs only; preserve unrelated changes. The maintainer authorized implementation on 2026-10-27.

## Task 1: Freeze public compatibility and local decisions

**Files:** Create `internal/rbacrules/inventory.json`, `internal/rbacrules/inventory.go`, `internal/rbacrules/inventory_test.go`, `docs/compat/observations/roles-permissions.md`; modify `docs/compat/{changelog-review,decisions,matrix}.md` and these draft documents for evidence-backed corrections.

**Interfaces:** `rbacrules.Inventory() []OperationContract`, embedded from JSON. Define `OperationContract` with method, path, required scopes, request/response shape, pagination, status/error codes, limits, source URL and evidence classification. Separate documented, observed and local-decision values.

- [x] Write `TestRBACInventory`: assert exactly the 16 scoped operations in spec §3, all four dialects, direct versus inherited permission semantics, explicit deferred group/organization/EA entries, and a source or named local decision for every validation rule.
- [x] Run `go test ./internal/rbacrules -run '^TestRBACInventory$' -count=1`; expect a missing inventory/implementation failure.
- [x] Read the public sources linked in spec §2 and each operation reference; review RFC 9068 and the changelog since its actual recorded coverage. Review pinned SDK/CLI/Deploy CLI contracts under CLEAN_ROOM.md. Freeze route scope requirements, batch/name limits, source object shape, role-user checkpoint wrapper and exact empty/totals behavior. Confirm relevant SDK-only hints publicly before implementing them.
- [x] Arrange the separate observer session only if available/authorized; record unknowns without invented observation. For unresolved behavior retain spec's explicit local decisions, including case-sensitive names, cleanup, RBAC-off `_authz`, and snapshot revocation timing. Add a compatibility decision for each material difference. Do not advance changelog coverage past unavailable sources.
- [x] Populate inventory and notes. Repeat the test; expect PASS. Commit `docs: freeze roles and permissions compatibility contracts`.

## Task 2: Domain rules and memory store

**Files:** Create `internal/store/rbac.go`, `internal/rbacrules/rules.go`, `internal/rbacrules/rules_test.go`, `internal/store/memory/rbac.go`, `pkg/storetest/rbac.go`; modify `internal/store/{store,types}.go`, `pkg/store/store.go`, `internal/store/memory/{memory,tx,resource_servers,users,tenants}.go`, `pkg/storetest/storetest.go` and memory tests as required by existing layout.

**Interfaces:** Add `Store.RBAC() RBAC`, `ResourceServer.EnforcePolicies bool`, `ResourceServer.TokenDialect string`, and the following types/contracts in `internal/store/rbac.go` (export public aliases):

- `Role{TenantID, ID, Name, Description string}`.
- `PermissionKey{ResourceServerIdentifier, PermissionName string}`.
- `PermissionSource{Type, ID, Name string}`; internal type values `direct` and `role`; HTTP projection follows Task 1's frozen sources shape.
- `PermissionGrant{Key PermissionKey; ResourceServerName, Description string; Sources []PermissionSource}`.
- `RBACPage{Page, PerPage int; NameFilter, From string; Take int}`; zero values normalized by rules to spec defaults. `RBACResult[T]{Items []T; Total int; Next string}`.
- `AuthorizationSnapshot{API *ResourceServer; Permissions []string}`; contains a current custom API and sorted unique effective names from one consistent read. Missing user/API returns `ErrNotFound`.

`RBAC` methods, all with `ctx context.Context` first:

```go
CreateRole(ctx context.Context, role *Role) error
GetRole(ctx context.Context, tenantID, roleID string) (*Role, error)
UpdateRole(ctx context.Context, role *Role) error
DeleteRole(ctx context.Context, tenantID, roleID string) error
ListRoles(ctx context.Context, tenantID string, page RBACPage) (RBACResult[Role], error)
RolePermissions(ctx context.Context, tenantID, roleID string, page RBACPage) (RBACResult[PermissionGrant], error)
ChangeRolePermissions(ctx context.Context, tenantID, roleID string, add bool, keys []PermissionKey) error
RoleUsers(ctx context.Context, tenantID, roleID string, page RBACPage) (RBACResult[User], error)
AssignRoleUsers(ctx context.Context, tenantID, roleID string, userIDs []string) error
UserRoles(ctx context.Context, tenantID, userID string, page RBACPage) (RBACResult[Role], error)
ChangeUserRoles(ctx context.Context, tenantID, userID string, add bool, roleIDs []string) error
UserPermissions(ctx context.Context, tenantID, userID string, page RBACPage) (RBACResult[PermissionGrant], error)
ChangeUserPermissions(ctx context.Context, tenantID, userID string, add bool, keys []PermissionKey) error
Snapshot(ctx context.Context, tenantID, userID, audience string) (*AuthorizationSnapshot, error)
```

Rules: `NormalizeRole(role *store.Role) []error`, `ValidatePermissionKeys(keys []store.PermissionKey) []error`, `NormalizePage(page *store.RBACPage) error`. Source and batch validation live inside store transactions too; API validation alone cannot protect races.

- [x] Add shared `RBAC` conformance subtests for CRUD/case-sensitive uniqueness, copies, page boundaries/totals/filter, source union, duplicate/idempotent mutations, atomic invalid batches, rollback and missing resources. Define two tenants with identical API permission names and prove isolation; assert system/protocol-scope assignment rejection.
- [x] Run `go test ./internal/rbacrules ./internal/store/memory -run 'Test(RBAC|Conformance)' -count=1`; expect interface/conformance failure.
- [x] Implement models, rules and the memory repository. Normalize legacy empty dialect to `access_token` at read boundaries. Snapshot uses the transaction's repositories without reacquiring the outer memory store lock. Add all new maps to transaction cloning/rollback.
- [x] Extend cleanup conformance: delete one role/direct source, delete and recreate a scope, delete API/user/tenant, and rollback a failed scope update; assert no stale rights or cross-API deletion. API scope update and edge cleanup form one atomic operation.
- [x] Repeat focused tests and `go build ./...`; expect PASS after adapting every Store implementation to compile (temporary unsupported implementations must return an explicit error, never success). Commit `feat: add RBAC domain and memory persistence`.

## Task 3: Durable SQL storage and migration

**Files:** Create `internal/store/sqlstore/rbac.go`, `internal/store/sqlstore/rbac_test.go`, `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0022_rbac.sql`; modify `internal/store/sqlstore/{sqlstore,tx,resource_servers,users,tenants,codec}.go`, migration tests and `pkg/storetest/rbac.go`.

**Interfaces:** Implement Task 2's complete `RBAC` interface, API fields and atomic cleanup. Use the next free migration number if 0022 has been allocated. SQL table keys/indexes include tenant and entity identity; edge uniqueness prevents duplicate assignments.

- [x] Add `TestRBACMigration` from pre-26 data: existing APIs stay false/`access_token`, users/grants unchanged, fresh and upgraded schemas agree. Add `TestRBACSnapshotConcurrency`: assignments/settings change concurrently and snapshots match a committed state, not a mix; include mutation-versus-delete and rollback cases.
- [x] Run `go test ./internal/store/sqlstore -run 'Test(RBAC|Conformance)' -count=1`; expect missing-table/behavior failure. These are database-backed tests and are allowed for Plan 26.
- [x] Implement additive migrations, transactional batch validation, query indexes, source projection and sorted snapshots. Make API update/delete and user/tenant cascades atomic with edge cleanup. Cover both direct repository writes and management transaction callers. Do not rely on SQL foreign-key enforcement being identical across dialects.
- [x] Run `./scripts/test-sql.sh ./internal/store/sqlstore/...`; require actual SQLite/PostgreSQL/MySQL results. If a service is unavailable, record it as not run and retain final verification work; never relabel SQLite evidence as cross-dialect evidence.
- [x] Commit `feat: persist RBAC assignments across SQL drivers`.

## Task 4: Plugin protocol and lifecycle boundaries

**Files:** Modify `proto/store/v1/store.proto`, generated protobuf outputs, `internal/store/grpcstore/{client,server,client_repos,server_repos,codec}.go`, `internal/app/app.go`, `internal/mgmt/user_identities.go`; create `internal/store/grpcstore/rbac.go`, `internal/store/grpcstore/rbac_test.go`, `internal/mgmt/user_rbac_link_test.go`; extend public store tests.

**Interfaces:** Add typed additive RBAC request/response messages and RPCs matching Task 2. Add `RBACCapabilities` RPC returning version 1 and an internal `ErrRBACUnavailable` mapped consistently across plugin boundaries. Startup requires version ≥1 before exposing listeners. Snapshot is one RPC executed atomically on the server; no client-side pagination assembly.

- [x] Add `TestRBACPluginRoundTrip`, `TestRBACOldPlugin`, and `TestRBACStartupCapability`: all fields/empty sources survive transport; unknown capability returns explicit startup failure, and no API setting can silently disappear. Add shared conformance selection for RBAC, rollback and cleanup over gRPC.
- [x] Run `go test ./internal/store/grpcstore -run 'Test(RBAC|Conformance)' -count=1`; expect missing RPC/capability failure.
- [x] Implement transport/error mapping, transactional repository binding and startup negotiation. Persist both new resource-server fields in the codec. Extend `TestRBACLinkLifecycle`: primary rights survive, secondary rights never transfer, secondary deletion cleans edges, unlink does not copy rights, other tenants stay untouched.
- [x] Run `go generate ./...` twice and compare generated outputs for stability; then `go test ./internal/store/grpcstore ./internal/mgmt ./internal/app -run 'Test(RBAC|Conformance)' -count=1` and `go build ./...`; expect PASS. Record that gRPC conformance can select SQLite-backed tests.
- [x] Commit `feat: expose RBAC plugin capability and lifecycle cleanup`.

## Task 5: Management API, resource-server rules and seed

**Files:** Create `internal/mgmt/{roles,user_rbac}.go`, `internal/server/mgmt_rbac_test.go`, `internal/seed/rbac_test.go`; modify `api/management.yaml`, generated Go/TypeScript contracts, `internal/server/mgmtapi.go`, `internal/mgmt/resource_servers.go`, `internal/apirules/apirules.go`, `internal/tenantsetup/management.go`, bootstrap upgrade tests, `internal/seed/{seed,validate,apply}.go`.

**Interfaces:** Generated handlers expose Task 1's 16 operations through `mgmt.Handlers` and Task 2 repositories. Extend `apirules.Spec` with `EnforcePolicies bool`, `TokenDialect string`; Normalize/Apply/FromResourceServer round-trip all four dialects. Seed roles carry `name`, `description`, `permissions` with API identifier/name keys; apply create-only after APIs. Assignment seed syntax is not added.

- [x] Add `TestRBACManagementContract` covering every route's success, 401/403, cross-tenant 404, malformed/oversized/null/duplicate bodies, totals, checkpoints, redacted role-user summaries and sources. Assert PATCH omission preserves state and empty description clears it. Add `TestRBACSystemBoundary` for reserved APIs and operator isolation.
- [x] Run `go test ./internal/server ./internal/apirules ./internal/seed -run '^TestRBAC' -count=1`; expect unimplemented route/rule failures.
- [x] Implement the schema with `x-source` entries, generated handlers, scope middleware and shared rules. Replace hardcoded false/legacy response values and validators. Register scopes in tenant bootstrap without enlarging existing restricted grants. Handle unknown/deferred role/group queries explicitly according to the inventory.
- [x] Add `TestRBACSeed` and `TestRBACManagementUpgrade`: validation parity, API-before-role ordering, missing API/scope refusal, defaults, create-only restart preservation, and existing tenant scope inventory upgrade without client privilege expansion. Add API scope-delete/role-assignment race integration coverage against the transactional store.
- [x] Regenerate contracts; repeat focused tests and `make check-sources`; expect PASS. Commit `feat: manage roles permissions and API RBAC settings`.

## Task 6: JWT profile support and consumers

**Files:** Modify `internal/oauth/{minter,minter_test,grant_client_credentials}.go`, `internal/keys/{manager,manager_test}.go`; create `internal/oauth/token_profiles_test.go`, `internal/oidc/rbac_test.go`; inspect and modify `internal/oidc/userinfo.go` and token consumers under `internal/claims` as needed.

**Interfaces:** Extend `AccessTokenParams` with `TokenDialect string`, `Permissions []string`, `IncludePermissions bool`. Add `(*keys.Manager).SignWithType(ctx context.Context, tenantID string, claims any, tokenType string) (string, error)` restricted to `JWT`/`at+jwt`; existing `Sign` keeps `JWT`. A token dialect defaults to legacy and unknown values fail rather than downgrade.

- [x] Add `TestRBACTokenProfiles`: real signed JWT assertions for all four dialects, typ, azp/client_id, gty omission, required claims, unique jti, sorted permissions, absent versus empty permissions, signature/key rotation, and unchanged ID tokens. Assert invalid dialect/type refuses signing.
- [x] Run `go test ./internal/oauth ./internal/keys -run '^TestRBACTokenProfiles' -count=1`; expect profile assertion failures.
- [x] Implement spec §5's matrix without changing algorithm/key trust. Pass API dialect to M2M minter while preserving client-grant scopes and omitting user permissions. Ensure signer cache identity cannot reuse a JWT signer with the wrong type.
- [x] Add `TestRBACProfileUserinfo`: RFC access token with openid and userinfo audience succeeds; wrong audience/type/issuer and ID token substitution fail; legacy still works. Audit azp readers and adapt only custom-API access-token paths. System APIs cannot select RFC profiles through management.
- [x] Run `go test ./internal/oauth ./internal/oidc ./internal/keys ./internal/claims -run 'Test(RBAC|AccessToken|IDToken|Sign)' -count=1`; expect PASS. Commit `feat: issue and consume supported access token profiles`.

## Task 7: Enforce current permissions in every user grant

**Files:** Create `internal/oauth/rbac.go`, `internal/oauth/rbac_test.go`; modify `internal/oauth/{user_tokens,grant_authorization_code,grant_password,grant_device_code,grant_refresh_token}.go` and their tests; extend `internal/server/flow_test.go` for federated/custom-domain regressions.

**Interfaces:** `(*Handlers).authorizeUserToken(ctx context.Context, tenantID, userID string, rs *store.ResourceServer, scopes []string) (userAuthorization, *Error)` with `userAuthorization{API *store.ResourceServer; Scopes, Permissions []string; IncludePermissions bool}`. For custom APIs consume Task 2 Snapshot, including its current enforcement settings and definitions. For nil/system API retain existing protections. `mintUserTokens` uses this result to populate Task 6 params and actual response scope. Keep the pre-RBAC authorized scope ceiling separate when creating/rotating refresh tokens.

- [x] Add table-driven `TestRBACUserGrants` for code, password, password-realm, device and refresh, with RBAC on/off × four dialects. Example: API defines `read:x,write:x`; user owns only `read:x`; request both plus `openid`; enabled output is `openid read:x`, permissions only `read:x` for `_authz`. Unrequested owned permission appears only in permissions. OIDC/offline rules and no-audience behavior remain intact.
- [x] Run `go test ./internal/oauth -run '^TestRBAC' -count=1`; expect scope/claim failures.
- [x] Implement the single evaluator at issuance. Never load permission lists through paginated API methods. Use the snapshot's current API definition/settings/lifetime, re-evaluate existing client-access policy against the snapshot API while preserving the already-authorized consent ceiling, and return server_error on snapshot failure without emitting tokens. Filter only API permissions, preserving existing protocol-scope rules.
- [x] Add `TestRBACRevocation`: revoke after code/device approval; next issuance reflects it. Refresh after removing role/direct source or API scope drops access; assigning a new permission cannot enlarge the family's pre-RBAC scope ceiling. Explicitly test requested-but-initially-unassigned `write:x` becomes issuable after assignment, unrequested `delete:x` does not, and revoke/restore of `read:x` follows current assignments. Test explicit narrowing, rotation replay, issuer/origin binding, unchanged ID-token claims and assignment failure before token release. Assert the documented snapshot timing with synchronization barriers, without promising cancellation of already-started issuance.
- [x] Add `TestRBACIsolationAndFailure`: identical permissions across audiences/tenants, system assignment refusal, missing user/API, plugin unavailable and ordinary store failure; M2M remains client-grant-controlled. Check token response scope equals JWT scope and refresh creation retains the correct ceiling, not a stale output slice.
- [x] Run `go test -race ./internal/oauth ./internal/server -run '^TestRBAC' -count=1`; expect PASS. Commit `feat: enforce RBAC across user token grants`.

## Task 8: Console roles, assignments and API settings

**Files:** Create `console/src/pages/roles/{List,Create,Detail,PermissionsTab,UsersTab}.vue` and tests, `console/src/pages/users/{RolesTab,PermissionsTab}.vue` and tests; modify `console/src/pages/users/Detail.vue`, `console/src/pages/apis/SettingsTab.vue`, `console/src/{router.ts,locales/en.ts}`, API client services and generated schema. Remove the live route's dependency on `pages/planned/Roles.vue`.

**Interfaces:** Typed client methods follow Task 5's generated schema; list state tracks tenant, page/cursor and request generation. Role/permission source information stays structured through rendering. Profile controls map to spec §5's exact four strings.

- [x] Add focused Vitest cases for CRUD, pagination, assignment/removal, inherited versus direct sources, empty/failure states, scoped permission pickers, system API protection, and draft preservation. Assert the Add permissions toggle preserves Auth0/RFC base dialect and disabling RBAC does not silently rewrite saved dialect.
- [x] Run the new focused files with `npm --prefix console test -- src/pages/roles src/pages/users/RolesTab.test.ts src/pages/users/PermissionsTab.test.ts`; expect missing component/interaction failures.
- [x] Implement original localized forms with existing components, confirmations and accessible names. Prevent stale tenant/route replies from changing active state and avoid success messages on uncertain writes. Show permission source labels and token-expiry/revocation explanation.
- [x] Add regression tests for late list/write replies after a tenant switch, deleting an in-use role, and large memberships requiring a second page. Run `make console`; expect all Vitest checks and production build PASS.
- [x] Commit `feat: add role and permission management to console`.

## Task 9: Actual tools, browser flows and deployment migration

**Files:** Create `tests/e2e/{m26-rbac.spec.mjs,m26-node-auth0.mjs,m26-mgmt-cli.mjs,run-m26-rbac.sh}`, local RBAC harness under `tests/e2e/rbac/`; modify `Makefile`, `.github/workflows/ci.yml`, `tests/e2e/deploy-cli/{manifest.json,config.json,normalize.go,normalize_test.go}` and YAML/directory fixtures, existing deploy runner and comparison code as needed.

**Interfaces:** Add `make e2e-rbac` using local issuer, mock federation and a protected Express API. Extend Deploy CLI resource manifest to include supported roles/role permissions and API fields. Use pinned installed tooling; record versions in the implementation record.

- [x] Add SDK/CLI cases covering all 16 operations (use actual SDK or `auth0 api` where no dedicated CLI command exists), all-of scoped denial, memberships/sources and API setting reads. Browser cases cover operator CRUD, role/direct assignments and login/refresh with permission removal. Run the new lane; expect missing fixture/contract failure before setup is complete.
- [x] Implement local fixtures and route checks. With `express-oauth2-jwt-bearer`, prove `requiredScopes('write:x')` denies when `write:x` occurs only in permissions; a separate explicit permissions check may allow it. Verify JWT headers and claims for RFC and legacy profiles, canonical/custom domains and a federated user.
- [x] Extend migration fixtures/comparators: API creation before role permission import; logical identity mapping; negative fixtures for dropped roles, permissions or enforcement/dialect. After every import create/assign a fixture user and exercise actual token issuance. Keep user assignments outside Deploy CLI parity claims.
- [x] Run `make e2e-rbac` and `make e2e-deploy`; require all four YAML/directory × generated/preserved cells and strict comparison, plus post-import RBAC behavior. Missing tools/services are recorded as unavailable, not skipped into a PASS result.
- [x] Commit `test: verify RBAC with SDK CLI browser and deploy migrations`.

## Task 10: Final regression, operator guidance and acceptance record

**Files:** Create `docs/rbac.md`, `docs/superpowers/2026-10-27-plan-26-implementation-record.md`; modify `docs/{deploy-cli.md,compat/matrix.md,compat/decisions.md}`, roadmap and relevant store/plugin/seed documentation.

**Interfaces:** Acceptance record maps every task and Review Focus item to actual command results and separates public docs, local fixtures and optional live evidence.

- [x] Document permission sources, scope versus permissions, all dialects, direct assignment deletion, refresh ceilings/snapshot timing, account linking, seed ownership, reserved APIs and plugin upgrade order. Document groups/organization roles/Actions as deferred, not silently supported.
- [x] Run `go generate ./...` twice (stable), `make check-sources`, `go vet ./...`, `go test -race -timeout=30m ./...`, `./scripts/test-sql.sh ./internal/store/sqlstore/...`, and `make console`. Record actual failures/skips; resolve failures before claiming completion.
- [x] Run `make e2e`, `make e2e-rbac`, `make e2e-deploy`, `make e2e-social`, `make e2e-email-accounts`, `make e2e-domains`, and `tests/conformance/run.sh`. Record conformance warning/review/skip counts and no certification claim. Reuse earlier final-code lane evidence only when no intervening relevant changes occurred, identifying the exact run.
- [x] Review spec coverage and all five Review Focus outcomes; fix defects with regression tests, then rerun only affected checks. Complete the acceptance record and update the roadmap/matrix to the demonstrated subset; retain unavailable verification explicitly.
- [x] Commit `docs: record RBAC behavior and verification evidence`. Hand off results for implementation review; do not merge or publish merely because tasks are checked.
