# Plan 27 — Actions I Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run tenant-authored Auth0 Actions at post-login and credentials-exchange, with npm dependencies, versioned deploys, ordered bindings, redirect/continue, management, console, seed and Deploy CLI support.

**Architecture:** A shared sandboxed Node runner (extracted from `internal/customdb`) executes Action handlers in per-tenant processes that cannot see the server's environment or files. Handlers return recorded `api` commands; a Go flow engine (`internal/actions`) validates and accumulates them into effects, which the authorize pipeline (after consent) and token endpoint apply at mint time. Dependency builds run sandboxed `npm install` once, store a tarball through the store, and every node extracts it locally.

**Tech Stack:** Go 1.26.7, Node ≥ 22.13 with bundled npm, existing protobuf/OpenAPI generators, SQLite/PostgreSQL/MySQL, Vue/TypeScript, Vitest/Playwright, pinned auth0-cli 1.37.0, node-auth0 7.4.0, Deploy CLI 9.1.0, auth0-spa-js.

**Spec:** [Actions I design](../specs/2026-10-27-zeroauthy-actions-design.md). Read it with this plan; section references (§n) point there.

## Global Constraints

- Go 1.26.7 and the existing stacks; Node ≥ 22.13 (already required for custom databases); npm only on nodes that run builds.
- Neither Action code nor npm builds may read the server's environment variables or files: empty environment, `--permission`, reads limited to their own directories, no child processes, workers, addons or WASI (§2).
- Tenant isolation: per-tenant Actions process, secrets, cache, build root, executions and continue states; Actions processes are separate from custom-database processes (§6).
- Fail closed: runner, build, store or unsupported-`api` failure issues no code/token and silently skips no bound Action.
- SQL migrations are additive; next number **0023**. Never edit historical migrations.
- Limits: code ≤ 100 kB; name 1–128 code points, unique per tenant (case-sensitive); runtime `node22` only; ≤ 64 secrets, name `[A-Za-z0-9_]{1,128}`, value ≤ 4096 bytes; ≤ 50 dependencies, exact semver or empty/`latest`; ≤ 20 bindings per trigger; flow budget 20 s; artifact ≤ 50 MB; cache 20 entries, key ≤ 64 B, value ≤ 4 kB, total ≤ 8 kB, default TTL 15 min, max 24 h; continue state 15 min, single-use, ≤ 5 redirects per login; executions retained 10 days; custom-claim payload ≤ 100 kB.
- Next compatibility decision: **D-0053**. Tests never contact the public npm registry or Auth0.
- Plan 19's database-test hold (AGENTS.md) is specific to Plan 19; it does not apply here.

## Review Focus

1. An Action that throws, times out, calls an unsupported `api` member or returns oversized claims must never yield a code or token, at any grant (Tasks 7–9).
2. A tenant's Action or npm build must never read `ZEROAUTHY_*` environment values, `/proc/<ppid>/environ`, another tenant's build root, secrets or cache (Tasks 2, 6).
3. Scope order: `transaction` edits before policy/RBAC, `addScope` after; refresh ceiling never absorbs Action-added scopes; response `scope` equals JWT `scope` (Task 8).
4. A replayed, expired, cross-session or cross-tenant `/continue` state must fail with `invalid_request`, and held metadata must not commit (Task 9).
5. Deleting/rebinding/redeploying an Action while a flow or redirect is in flight must finish on the pinned versions or fail closed, never run a half-updated list (Tasks 3, 7, 9).

## Files, interfaces and execution order

New packages: `internal/noderunner` (shared sandboxed runner), `internal/actions` (flow engine, `api`/`event` model, cache, claims rules), `internal/actions/build` (npm sandbox builds, artifacts, extraction), `internal/actionsrules` (validation and inventory). New store files `internal/store/actions.go` plus driver `actions.go` files. Management in `internal/mgmt/actions*.go`; console under `console/src/pages/actions/`; E2E lane `tests/e2e/run-m27-actions.sh`.

Order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13. Each task verifies and commits only its named files plus generated outputs. Test names are new tests to create. Implementation requires the maintainer's go-ahead on this plan.

## Task 1: Freeze compatibility contracts

**Files:** Create `internal/actionsrules/{inventory.json,inventory.go,inventory_test.go}`, `docs/compat/observations/actions.md`; modify `docs/compat/{decisions,changelog-review,matrix}.md`.

**Interfaces:** `actionsrules.Inventory() Inventory` embedded from JSON: `Operations []OperationContract` (method, path, scopes, request/response fields, statuses, errors, limits, source URL, evidence class: documented/observed/local), `Triggers []TriggerContract` (id, `event` fields, `api` members each marked `supported`/`empty`/`unsupported`), `Limits map[string]int`.

- [ ] Write `TestActionsInventory`: exactly the 14 operations of spec §4 (actions list, create, get, patch, delete; deploy; versions list, get; version deploy; test; triggers list; bindings get, patch; execution get), both triggers, every post-login and credentials-exchange `api` member from §6 classified, every Global Constraints limit present with a source or named D-0053 decision.
- [ ] Run `go test ./internal/actionsrules -run '^TestActionsInventory$' -count=1`; expect FAIL (missing inventory).
- [ ] Read each source in spec §3 and every linked operation; review the changelog since its recorded coverage. Freeze: response envelopes and statuses; deny/error delivery for authorize and token endpoints (default per spec §6; uncaught error → `server_error` to redirect URI with generic description, hosted error page with reference when the client shows error pages); credentials-exchange deny codes; whether secret changes need redeploy; consent-before-post-login order; which `event` fields reflect earlier Actions; `/userinfo` custom claims. Record unknowns as unavailable, never invented.
- [ ] Write D-0053 covering every local choice in Global Constraints and spec "author's call" items. Populate inventory; rerun; expect PASS. Commit `docs: freeze Actions compatibility contracts`.

## Task 2: Shared sandboxed Node runner

**Files:** Create `internal/noderunner/{runner.go,sandbox.go,probe.go,procattr_linux.go,procattr_other.go,runner_test.go,sandbox_test.go}`; move shared code out of `internal/customdb/{node.go,procattr_*.go}` (customdb keeps `runner.mjs`, `Executor`, profiles); create `internal/actions/runner.mjs`.

**Interfaces:**
- `noderunner.Config{Node string; MaxMemoryMB int; IdleTimeout time.Duration; ReadDirs func(tenantID string) []string; Script []byte; Name string}`; `noderunner.New(cfg Config, log *slog.Logger) (*Pool, error)`; `(*Pool).Call(ctx context.Context, tenantID string, req any) (json.RawMessage, error)`; `(*Pool).Close() error`. One process per tenant per Pool; customdb and Actions own separate Pools.
- `noderunner.Sandbox(cmd *exec.Cmd, reads, writes []string, allowNet bool)` builds the empty env and `--permission` args; reused by Task 6 builds.
- Actions protocol (`runner.mjs`): request `{version_key, code, deps_root, handler, event, secrets, cache, roles, state, hostname}`; response `{commands:[{op:string,args:[...]}], logs:[string], error?:{message,stack}}`. `handler` ∈ `onExecutePostLogin`, `onContinuePostLogin`, `onExecuteCredentialsExchange`. `require` resolves only inside `deps_root/node_modules` for that version; one `vm` context per `version_key`.

- [ ] **Feasibility gate first:** write `TestSandboxNPMFeasibility` running bundled `npm-cli.js install --ignore-scripts` of a one-package local registry fixture under `node --permission` with reads = npm dir + build dir, writes = build dir, no child processes, on the Node versions available locally (22.x and the newest installed). If npm cannot complete under these limits, stop and report to the maintainer with the exact failure; do not weaken the sandbox.
- [ ] Write `TestSandboxNoServerEnvironment`: set `ZEROAUTHY_CANARY=s3cr3t-canary` in the test process; from an Action handler and from customdb, assert `process.env` has no canary, and reading `/proc/self/environ`, `/proc/<ppid>/environ`, `/proc/1/environ`, another tenant's build root and the server's config file all throw permission errors (Linux; skip with explicit message elsewhere).
- [ ] Write `TestActionsRunnerIsolation`: two tenants' secrets/cache never visible across processes; a 25 s busy loop is killed at the 20 s budget and only that tenant's in-flight calls fail; a customdb call for the same tenant is unaffected; `require('child_process')`, workers and addons fail.
- [ ] Run `go test ./internal/noderunner ./internal/customdb -count=1`; expect new tests FAIL.
- [ ] Extract the pool/sandbox code, add the Actions runner script, and keep all existing customdb tests passing unchanged.
- [ ] Rerun; expect PASS, including the whole existing `./internal/customdb` suite. Commit `refactor: share a sandboxed Node runner for custom databases and Actions`.

## Task 3: Domain rules and memory store

**Files:** Create `internal/store/actions.go`, `internal/actionsrules/{rules.go,rules_test.go}`, `internal/store/memory/actions.go`, `pkg/storetest/actions.go`; modify `internal/store/{store,types}.go`, `pkg/store/store.go`, `internal/store/memory/{memory,tx,tenants}.go`, `pkg/storetest/storetest.go`.

**Interfaces:** `Store.Actions() Actions`. Types:
- `Action{TenantID, ID, Name, Trigger, Runtime, Code string; Dependencies []Dependency; Secrets []ActionSecret; DraftBuildID string; DeployedVersionID string; CreatedAt, UpdatedAt time.Time}`; `Dependency{Name, Version string}`; `ActionSecret{Name string; Sealed []byte; UpdatedAt time.Time}`.
- `ActionVersion{TenantID, ActionID, ID string; Number int; Code, Runtime, BuildID string; Dependencies []Dependency /*resolved*/; Secrets []ActionSecret; CreatedAt time.Time}`.
- `Build{TenantID, ID /*sha256 of runtime+sorted resolved deps*/ string; Status BuildStatus; Requested, Resolved []Dependency; Errors []string; ArtifactSHA256 string; BuiltAt time.Time}`; `BuildStatus` = `pending|building|built|failed`.
- `Binding{TenantID, Trigger, ID, ActionID, DisplayName string; CreatedAt, UpdatedAt time.Time}`; `BoundVersion{Binding; Action Action; Version ActionVersion}`.
- `Execution{TenantID, ID, Trigger, Status string; Results []ExecutionResult; CreatedAt, UpdatedAt time.Time}`; `ExecutionResult{ActionName, ErrorID, ErrorMsg string; StartedAt, EndedAt time.Time}`.
- `ContinueState{TenantID, StateHash, SessionID string; Sealed []byte; ExpiresAt, CreatedAt time.Time}`.

`Actions` methods (ctx first): `CreateAction`, `GetAction(tenantID, id)`, `GetActionByName(tenantID, name)`, `UpdateAction`, `DeleteAction(tenantID, id string, force bool) error` (`ErrConflict` when bound and !force), `ListActions(tenantID string, f ActionFilter) (Page[Action], error)`, `Deploy(tenantID, actionID, fromVersionID string) (*ActionVersion, error)` (allocates next number atomically; empty `fromVersionID` = draft; requires built draft), `GetVersion`, `ListVersions`, `PutBuild`, `GetBuild`, `PutArtifact(tenantID, buildID string, tar []byte)`, `GetArtifact(tenantID, buildID string) ([]byte, error)`, `Bindings(tenantID, trigger string) ([]BoundVersion, error)` (one consistent read), `ReplaceBindings(tenantID, trigger string, b []Binding) ([]BoundVersion, error)`, `CreateExecution`, `GetExecution`, `PurgeExecutions(before time.Time) (int, error)`, `CreateContinue`, `ConsumeContinue(tenantID, stateHash string, now time.Time) (*ContinueState, error)` (single-use; expired → `ErrNotFound`), `PurgeContinue(before time.Time) (int, error)`.

Rules in `actionsrules`: `NormalizeAction(a *store.Action) []error`, `ValidateDependencies([]store.Dependency) []error` (refuse ranges, git/file/URL/tarball specs, `registry_url`), `ValidateSecrets`, `ValidateBindings`.

- [ ] Add shared conformance `Actions` subtests: CRUD, case-sensitive unique names, copy isolation, limits, version numbering under concurrent deploys, rollback creates n+1, delete with/without force, bindings order/replace/missing-deployed refusal, consistent `Bindings` snapshot during concurrent `ReplaceBindings`, execution and continue purge, `ConsumeContinue` single-use under concurrency, tenant deletion cleanup, two tenants with identical names isolated, transaction rollback.
- [ ] Run `go test ./internal/actionsrules ./internal/store/memory -run 'Test(Actions|Conformance)' -count=1`; expect FAIL.
- [ ] Implement models, rules, memory repository and tx clone/rollback; other Store implementations return explicit unsupported errors until Tasks 4–5.
- [ ] Rerun plus `go build ./...`; expect PASS. Commit `feat: add Actions domain and memory persistence`.

## Task 4: SQL storage and migration

**Files:** Create `internal/store/sqlstore/actions.go`, `internal/store/sqlstore/actions_test.go`, `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0023_actions.sql`; modify `internal/store/sqlstore/{sqlstore,tx,tenants}.go`.

- [ ] Add `TestActionsMigration` (pre-0023 database upgrades; fresh and upgraded schemas agree) and `TestActionsConcurrency` (concurrent deploy numbering, bind-vs-delete, `ConsumeContinue` races) on all dialects; artifacts stored as BLOB/BYTEA/LONGBLOB.
- [ ] Run `./scripts/test-sql.sh -run 'Test(Actions|Conformance)' ./internal/store/sqlstore/...`; expect FAIL. Record any unavailable service as not run.
- [ ] Implement tables with tenant-inclusive keys, per-tenant serialization for bindings/delete (reuse Plan 26's tenant lock pattern), cascades on tenant delete.
- [ ] Rerun; require actual SQLite/PostgreSQL/MySQL results. Commit `feat: persist Actions across SQL drivers`.

## Task 5: Plugin protocol and capability

**Files:** Modify `proto/store/v1/*.proto` (additive), `internal/store/grpcstore/{client_repos,codec}.go`, `pkg/storeplugin/*`, plugin capability negotiation; create `internal/store/grpcstore/actions_test.go`.

- [ ] Add `TestActionsPluginRoundTrip` (every field including sealed secrets and chunked artifacts ≥ 4 MB) and `TestActionsOldPlugin` (server with Actions configured refuses startup against a plugin lacking the capability, with a clear error).
- [ ] Run `go test ./internal/store/grpcstore -run 'Test(Actions|Conformance)' -count=1`; expect FAIL.
- [ ] Implement RPCs, error mapping, streamed artifact transfer and capability check.
- [ ] `go generate ./...` twice (stable), rerun tests, `go build ./...`; expect PASS. Commit `feat: expose Actions through storage plugins`.

## Task 6: Sandboxed dependency builds and artifacts

**Files:** Create `internal/actions/build/{manager.go,npm.go,artifact.go,manager_test.go,registry_fixture_test.go}`; modify `internal/config/config.go` (new `actions` section), `internal/app` wiring, `internal/jobs/runner.go` (build queue reuse if suitable).

**Interfaces:** `config.Actions{Node, NPMCLI, Registry, CacheDir string; MaxMemoryMB int; IdleTimeout, BuildTimeout time.Duration; MaxArtifactMB, MaxConcurrentBuilds int}` defaults `node`, npm resolved beside node, `https://registry.npmjs.org/`, `<data>/actions-cache`, 256, 5m, 2m, 50, 2. `build.Manager.Queue(ctx, tenantID string, deps []store.Dependency, runtime string) (buildID string, err error)`; `(*Manager).Ensure(ctx, tenantID, buildID string) (root string, err error)` (extract from store if absent; verifies SHA-256); `(*Manager).Prewarm(ctx)`. Per-tenant root `<CacheDir>/<tenantID>/<buildID>/`, 0700.

- [ ] Write a local registry fixture (httptest serving packuments and tarballs generated in-test, including a scoped package and one with a `postinstall` that would write a marker file).
- [ ] Write `TestBuildResolvesAndPacks` (exact, empty, `latest` → recorded exact versions; scoped OK), `TestBuildRefuses` (range, git/URL/file spec, `registry_url`, size cap, timeout), `TestBuildIgnoresScripts` (marker never written), `TestBuildNoServerEnvironment` (canary from Task 2 unreadable during install), `TestEnsureExtractsOnFreshNode` (second manager with empty cache dir extracts from store; corrupt artifact fails closed), `TestBuildTenantRoots` (tenant A's process cannot read tenant B's root).
- [ ] Run `go test ./internal/actions/build -count=1`; expect FAIL.
- [ ] Implement with `noderunner.Sandbox`, content-addressed build IDs, bounded concurrency, status transitions `pending → building → built|failed`, prewarm at startup and after deploy.
- [ ] Rerun; expect PASS. Commit `feat: build Action dependencies in a sandbox and share artifacts`.

## Task 7: Flow engine, event and api model

**Files:** Create `internal/actions/{engine.go,event.go,commands.go,claims.go,cache.go,engine_test.go,claims_test.go}`; extend `internal/actions/runner.mjs`.

**Interfaces:**
- `actions.Engine{Store store.Store; Runner *noderunner.Pool; Builds *build.Manager; Secrets secrets.Sealer; Now func() time.Time; Log *slog.Logger}`.
- `(*Engine).PostLogin(ctx, in PostLoginInput) (*Result, error)`; `PostLoginInput{Tenant tenant.Resolved; Client *store.Client; User *store.User; Connection *store.Connection; Session *store.LoginSession; Request RequestInfo; Protocol string; RequestedScopes, TargetScopes []string; ResourceServer *store.ResourceServer; CanRedirect bool}`.
- `(*Engine).CredentialsExchange(ctx, in CredentialsInput) (*Result, error)`.
- `(*Engine).Test(ctx, tenantID, actionID string, payload json.RawMessage) (json.RawMessage, error)` — dry run per spec §4.
- `Result{Effects Effects; Denied *Denial; Redirect *Redirect; ExecutionID string}`; `Effects{AccessClaims, IDClaims map[string]any; AddScopes, RemoveScopes []string; Target *TargetEdit; AppMetadata, UserMetadata map[string]any; TxnMetadata map[string]any}`; `Denial{Code, Reason string}`; `ErrFlow{ExecutionID string; Cause error}`.
- `actions.FilterClaims(kind ClaimTarget, existing map[string]any, custom map[string]any, mgmtAudience bool) (map[string]any, error)`; `Effects.ApplyScopes(base []string, filtered []string) []string`.
- Protocol values: `oidc-basic-profile`, `oauth2-device-code`, `oauth2-password`, `oauth2-resource-owner`, `oauth2-refresh-token`, `oauth2-client-credentials` (freeze in Task 1).

- [ ] Write `TestEngineOrderAndDeny` (three bound Actions; deny in second stops third; metadata from first commits on deny), `TestEngineFailClosed` (throw, timeout, unsupported `api.session.revoke`/`multifactor.enable`/`prompt.render`/`samlResponse.*`, invalid args each produce `ErrFlow` with execution record and no metadata commit), `TestEngineRoles` (`event.authorization.roles` names; `getUserEffectiveRoles` paging `take ≤ 100`, by IDs ≤ 100, by names ≤ 50; groups empty; snapshot fixed at flow start), `TestEngineCache` (limits, TTL, eviction, per tenant+trigger), `TestEngineSecretsMasked` (logs/test output masked), `TestEngineTestDryRun` (no writes, real `fetch` against httptest, roles empty for unknown user, `400`-mapped error when draft not built), `TestEngineCredentialsExchange` (claims, target scopes, deny codes; no `addScope`), `TestFilterClaims` (every reserved name in spec §7 dropped, `auth0.com`/`webtask.io`/`webtask.run`/`urn:auth0` namespaces dropped, non-namespaced dropped for Management audience, > 100 kB fails), `TestEnginePinnedVersions` (rebinding mid-flow does not alter the running list).
- [ ] Run `go test ./internal/actions -count=1`; expect FAIL.
- [ ] Implement: snapshot bindings once, ensure builds, call runner per Action, validate each command in Go, accumulate effects, write execution records, commit metadata via the same merge/validation as `PATCH /api/v2/users/{id}` at flow end per spec §6 rules, schedule execution purge on the jobs worker.
- [ ] Rerun with `-race`; expect PASS. Commit `feat: run post-login and credentials-exchange Action flows`.

## Task 8: Token integration across grants

**Files:** Modify `internal/authz/handlers.go` (`finish`: run post-login **before** `access.Decide`'s consent step, per D-0053 — the consent screen lists Action-edited target scopes; carry sealed effects through the consent transaction so accepting consent does not re-run Actions; metadata commits when the flow ends, before consent, so declining consent does not roll it back), `internal/authz/flow.go` (`approve`: attach effects to code/device approval), proto/grpcstore codec for the new AuthCode/DeviceCode field (controller Ruling 2), amend `0023_actions.sql` (Ruling 1), `internal/store/types.go` (`AuthCode.ActionEffects`, `DeviceCode.ActionEffects []byte`, drivers/codec/migration 0023 columns), `internal/oauth/{user_tokens.go,grant_password.go,grant_refresh_token.go,grant_authorization_code.go,grant_device_code.go,grant_client_credentials.go,minter.go}`, `internal/authz/handlers.go` (deny/error delivery), hosted error page template for the reference; create `internal/oauth/actions_test.go`, `internal/authz/actions_test.go`.

**Interfaces:** `userTokens.effects *actions.Effects` consumed by `mintUserTokens`; `AccessTokenParams.CustomClaims`, `IDTokenParams.CustomClaims map[string]any` (already filtered). Scope order exactly spec §7; refresh ceiling stays Plan 26's pre-Action set.

- [ ] Write `TestActionsUserGrants`, table-driven over code, device, password, password-realm and refresh × RBAC on/off: namespaced access and ID claims present in signed JWTs; `transaction.addTargetScope('write:x')` dropped when RBAC denies; `accessToken.addScope('write:x')` present despite RBAC; `removeScope` removes; response `scope` equals JWT `scope`; refresh family ceiling unchanged and re-run Actions re-add claims; `canRedirect` false on token-endpoint grants and `sendUserTo` there fails closed.
- [ ] Write `TestActionsDenyAndErrorSurfaces`: deny → `error=access_denied&error_description=<reason>` to redirect URI, error page when the client protects redirects, `403 access_denied` at token endpoint; thrown error → `server_error` with generic description and hosted page reference; no code row created in any failure; consent screen lists scopes added via `transaction.addTargetScope` but not via `accessToken.addScope`; accepting consent issues the code without re-running Actions (exactly one execution record); declining consent issues no code.
- [ ] Write `TestActionsClientCredentials`: claims added, deny codes mapped, target scopes intersected with client grant, flow failure → no token.
- [ ] Run `go test ./internal/oauth ./internal/authz -run 'TestActions' -count=1`; expect FAIL.
- [ ] Implement the hooks; store effects sealed on codes/device codes; apply claims through `FilterClaims`; log execution IDs with tenant, trigger and Action name.
- [ ] Rerun with `-race` plus `go test -race ./internal/oauth ./internal/authz ./internal/login`; expect PASS. Commit `feat: apply Action effects to user and machine tokens`.

## Task 9: Redirect and continue

**Files:** Create `internal/actions/continue.go`, `internal/authz/continue.go`, tests `internal/actions/continue_test.go`, `internal/authz/continue_test.go`; modify `internal/server/server.go` routes (`GET`/`POST /continue` on canonical and custom domains).

**Interfaces:** `(*Engine).ContinuePostLogin(ctx, tenantID, state string, sess *store.LoginSession, req RequestInfo) (*Result, error)`; continue payload (sealed) = accumulated effects, held metadata, pinned remaining bound versions, current Action index, redirect count, original flow request, login session ID.

- [ ] Write `TestActionsRedirectRoundTrip`: `sendUserTo(url,{query:{a:'1'}})` redirects with `a=1&state=…`; `/continue` (GET and form POST) runs `onContinuePostLogin` with the new `event.request.query/body`, then the remaining Actions; code issued afterwards carries effects from both phases.
- [ ] Write `TestActionsContinueRejects`: missing, wrong, expired (15 min), replayed, other-session, other-tenant and other-origin states → `invalid_request`; held metadata not committed; sixth redirect fails closed; `prompt=none` → `interaction_required`.
- [ ] Write `TestActionsRedirectTokens`: `encodeToken` HS256 with `sub`, `iss`, `iat`, `exp` (default 900 s), `ip`, payload; `validateToken` rejects bad signature, expiry, missing/mismatched `state`, and reads `session_token` or a named parameter from query or body.
- [ ] Run `go test ./internal/actions ./internal/authz -run 'TestActions(Redirect|Continue)' -count=1`; expect FAIL.
- [ ] Implement; purge expired states on the jobs worker.
- [ ] Rerun with `-race`; expect PASS. Commit `feat: support Action redirects and continue`.

## Task 10: Management API, seed and bootstrap scopes

**Files:** Modify `api/management.yaml` (with `x-source`), generated server/types, `internal/mgmt/{actions.go,actions_versions.go,actions_bindings.go,actions_executions.go}` (create), `internal/tenantsetup` scope registration, `internal/seed/{actions.go,validate.go,apply.go}`; create `internal/mgmt/actions_test.go`, `internal/seed/actions_test.go`.

- [ ] Write `TestActionsManagementContract`: every operation in Task 1's inventory — success shapes, secrets write-only (`name`, `updated_at` only), `all_changes_deployed`, build `status`, deploy of unbuilt draft `400`, rollback numbering, bindings by `action_id`/`action_name`/`binding_id`, binding `secrets` and `registry_url` refused, `DELETE` bound without `force` refused, test endpoint dry-run, execution `404` after purge, 401/403 for each scope, cross-tenant `404`, unknown fields `400`, creating an Action for an unsupported trigger `400`, `GET /actions/triggers` lists only `post-login` and `credentials-exchange`, every limit.
- [ ] Write `TestActionsScopesUpgrade` (existing tenants gain `read/create/update/delete:actions` definitions; restricted grants not expanded) and `TestActionsSeed` (code, dependencies, secrets, deploy flag, bindings; create-only restart preserves management edits; unsupported trigger refused).
- [ ] Run `go test ./internal/mgmt ./internal/seed ./internal/tenantsetup -run 'TestActions' -count=1`; expect FAIL.
- [ ] Implement schema, handlers (secrets sealed with tenant+action binding), build queueing on save, deploy/prewarm, seed.
- [ ] Regenerate; rerun; `make check-sources`; expect PASS. Commit `feat: manage Actions, versions, bindings and executions`.

## Task 11: Console

**Files:** Create `console/src/pages/actions/{Library.vue,Editor.vue,Versions.vue,TestPanel.vue,Triggers.vue,Execution.vue}` and `*.test.ts`; modify router, nav, locales; remove `console/src/pages/planned/Actions.vue` and its planned-page test entry.

- [ ] Write Vitest cases: list/create/delete (force confirmation when bound); editor save keeps draft on failure and reload-before-retry; dependency add/remove with exact-version validation; write-only secrets (never displayed after save); build status/errors polling; deploy and rollback; test panel shows commands/logs/errors with masked secrets; triggers page reorders bindings with up/down buttons and keyboard, refuses undeployed Actions; execution lookup; stale tenant/route replies ignored.
- [ ] Run `npm --prefix console test -- src/pages/actions`; expect FAIL.
- [ ] Implement with existing components (`ScriptEditor`, `Field`, `Modal`, `Banner`), localized strings, accessible names; original layouts only.
- [ ] Run `make console`; expect lint, typecheck, tests and production build PASS. Commit `feat: add Actions to the console`.

## Task 12: Tools, browser flows and Deploy CLI

**Files:** Create `tests/e2e/run-m27-actions.sh`, `tests/e2e/m27-actions-cli.mjs`, `tests/e2e/m27-node-auth0.mjs`, `tests/e2e/m27-actions.spec.mjs`, `tests/e2e/fixtures/npm-registry/` (static registry built by script from pinned tarballs, including `auth0@7.4.0` and its dependency closure); modify `Makefile` (`e2e-actions`), `tests/e2e/deploy-cli/*`, `internal/deploymigration` comparators.

- [ ] Add cases: auth0-cli `actions` commands (create/list/show/update/deploy/delete) plus `auth0 api` for bindings/executions; node-auth0 for all 14 operations; Playwright with auth0-spa-js reading a namespaced ID-token claim and an access-token claim; roles copied into a claim; deny shown on the hosted error page; redirect to a fixture page that adds `a=1` and posts back an `encodeToken` token; credentials-exchange claim and deny; an Action using `require('auth0')` ManagementClient with M2M secrets to assign a default role that appears in `permissions` on the next login; console create/edit/deploy/bind/test.
- [ ] Extend Deploy CLI four-cell matrix (YAML/directory × generated/preserved) with `actions` and `triggers`; compare by Action name; secrets via keyword replacement; negative fixtures for missing Action, binding or code; post-import login proves the claim.
- [ ] Run `make e2e-actions` and `make e2e-deploy`; expect FAIL before fixtures, then PASS. Missing tools recorded as unavailable, not skipped into PASS.
- [ ] Commit `test: verify Actions with CLI SDK browser and Deploy CLI`.

## Task 13: Final regression, documentation and record

**Files:** Create `docs/actions.md`, `docs/superpowers/2026-10-27-plan-27-implementation-record.md`; modify `docs/compat/matrix.md`, `docs/superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md` (Plan 27 done; Plan 28 drops npm dependencies), `docs/custom-db.md` (shared runner note), config reference.

- [ ] Document: supported/empty/unsupported `api` members, scope order and `addScope` bypass, claim rules, redirect/continue, metadata commit rules, execution IDs, npm rules and registry/mirror configuration, sandbox guarantees and the container/dedicated-uid hardening advice, replica artifact behavior, limits.
- [ ] Run `go generate ./...` twice (stable), `make check-sources`, `go vet ./...`, `go test -race -timeout=30m ./...`, `./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/...`, `make console`, `make e2e`, `make e2e-actions`, `make e2e-rbac`, `make e2e-deploy`, `make e2e-social`, `make e2e-email-accounts`, `make e2e-domains`, `tests/conformance/run.sh`. Record actual results, skips and unavailable services.
- [ ] Review the five Review Focus outcomes and spec coverage; fix defects with regression tests; rerun affected checks.
- [ ] Commit `docs: record Actions behavior and verification evidence`. Hand off for review; do not merge or push.
