# Plan 28 — Actions II Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run tenant Actions at pre-user-registration, post-user-registration, post-change-password, password-reset-post-challenge and custom-email-provider, with a durable job queue for the non-blocking triggers, plus Actions Modules, management, console, seed and Deploy CLI support.

**Architecture:** The Plan 27 engine (`internal/actions`) gains a trigger table (handler names, event builder, allowed `api` members per trigger) so new triggers reuse one flow runner. Blocking triggers are called inline from signup and the reset page; non-blocking triggers enqueue a sealed, version-pinned job in the same store transaction as the change that caused them, and a jobs worker claims due jobs with a lease. Modules are built like Action dependencies, pinned into Action versions at deploy, and loaded by the runner through `require('actions:<name>')`.

**Tech Stack:** Go 1.26.7, Node ≥ 22.13 with bundled npm, existing protobuf/OpenAPI generators, SQLite/PostgreSQL/MySQL, Vue/TypeScript, Vitest/Playwright, pinned auth0-cli 1.37.0, node-auth0 7.4.0, Deploy CLI 9.1.0.

**Spec:** [Actions II design](../specs/2026-10-28-zeroauthy-actions-ii-design.md), built on the [Actions I design](../specs/2026-10-27-zeroauthy-actions-design.md). Read both; section references (§n) point to the Actions II design unless marked "P27".

## Global Constraints

- Go 1.26.7 and existing stacks; Node ≥ 22.13; npm only on nodes that run builds.
- Plan 27's sandbox, isolation and fail-closed rules apply unchanged to every new trigger and to module code (P27 §2; `docs/actions.md`), including the unix-socket lockout.
- Blocking triggers (pre-user-registration, password-reset-post-challenge) fail closed: error, timeout or unsupported call → no user created / no password reset.
- Non-blocking triggers never block or undo the change that enqueued them; every run leaves an execution record and, on failure, a log line with the execution ID.
- Jobs are enqueued in the same store transaction as the change; lease 60 s; at-least-once only on lease expiry.
- Custom-email retry schedule: 30 s, 1 m, 2 m, 4 m, 8 m (5 retries); reasons truncated to 1024 characters; pending-job cap 10,000 per tenant; completed/failed jobs and executions purged after 10 days.
- Modules: code ≤ 65,536 characters, name ≤ 255, secret value ≤ 4096, ≤ 100 versions per module, ≤ 100 modules per tenant, ≤ 10 modules per Action (local defaults, D-0054); modules cannot require `actions:*`.
- `api.authentication.*` and `api.prompt.render` throw "not supported by zeroauthy" and fail closed.
- SQL migrations additive; next number **0024**. Next decision **D-0054**. Plugin Actions capability **2 → 3**.
- Tests never contact the public npm registry or Auth0.
- Plan 19's database-test hold (AGENTS.md) is specific to Plan 19; it does not apply here.

## Review Focus

1. A pre-registration Action that throws, times out or denies must leave no user row, no custom-DB `create` call and no queued post-registration job, on both `/dbconnections/signup` and hosted signup (Task 8).
2. POST `/u/reset-password` for a ticket whose challenge has not passed, while the trigger has bindings, must be refused without spending the ticket, including when bindings were added after the page loaded (Task 9).
3. A custom-email job must never be delivered twice unless the Action asked to retry or the lease expired, and must never be retried after `drop` (Task 7, Task 10).
4. Deleting or republishing a module while an Action version or queued job pins one of its versions must not break that version or job (Tasks 2, 6).
5. Module code must not read the importing Action's secrets, another module's secrets, or another tenant's module trees (Task 6).

## Files, interfaces and execution order

New files: `internal/actions/{triggers.go,registration.go,reset.go,jobs.go,email.go,modules.go}`, `internal/store/actions_modules.go`, `internal/store/actions_jobs.go`, driver `actions_modules.go`/`actions_jobs.go` files, `internal/mgmt/actions_modules.go`, console `console/src/pages/actions/modules/`, migration `0024_actions_ii.sql` ×3, E2E `tests/e2e/run-m28-actions-ii.sh`.

Order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14. Each task verifies and commits only its named files plus generated outputs. Implementation requires the maintainer's go-ahead on this plan.

## Task 1: Freeze compatibility contracts

**Files:** Modify `internal/actionsrules/{inventory.json,inventory.go,inventory_test.go}`, `docs/compat/observations/actions.md`, `docs/compat/{decisions,changelog-review,matrix}.md`.

**Interfaces:** `actionsrules.Inventory()` gains the five triggers in `Triggers` (handlers, `event` fields, every `api` member classified `supported`/`empty`/`unsupported`, `blocking bool`), the ten module operations in `Operations`, deferred triggers in a new `DeferredTriggers []DeferredTrigger{ID, Plan string}` and the module/job limits in `Limits` (`module_code_chars`=65536, `module_name_chars`=255, `module_versions`=100, `modules_per_tenant`=100, `modules_per_action`=10, `job_lease_seconds`=60, `job_pending_per_tenant`=10000, `email_retries`=5, `notification_reason_chars`=1024).

- [ ] Extend `TestActionsInventory`: 24 operations (14 + the 10 in spec §8); 7 supported triggers; `send-phone-message`, `custom-phone-provider` → Plan 34, `custom-token-exchange` → 35, `event-stream` → 32, `password-hash-migration`, `login-post-identifier`, `signup-post-identifier`, `post-credential-validation` deferred; every member listed in spec §2 classified; every Global Constraints limit present with a source or D-0054.
- [ ] Run `go test ./internal/actionsrules -run '^TestActionsInventory$' -count=1`; expect FAIL.
- [ ] Read each spec §2 source; review the changelog from 2026-10-26 onward and log it. Confirm the password-reset-post-challenge handler names. Freeze spec §2 items 1–6: when `OBS_AUTH0_*` observer credentials are available (read via `fish -c`), observe items 1–3 on the maintainer's staging tenant with auth0-cli (bind a trivial Action, sign up, create a user via Management API, change a password, record execution presence and the signup error body); otherwise record "unavailable" and keep the spec defaults. Read the pinned Deploy CLI 9.1.0, auth0-cli 1.37.0 and node-auth0 7.4.0 sources for module support and record what each exposes (repo/file/version provenance).
- [ ] Write D-0054 (every spec "author's call" and default), populate the inventory, rerun; expect PASS. Commit `docs: freeze Actions II compatibility contracts`.

## Task 2: Domain types and memory store

**Files:** Create `internal/store/actions_modules.go`, `internal/store/actions_jobs.go`, `internal/store/memory/{actions_modules.go,actions_jobs.go}`, `pkg/storetest/actions_ii.go`; modify `internal/store/{actions.go,types.go}` (Action/ActionVersion `Modules`, `User.LastPasswordReset`, `PasswordResetTicket.ChallengePassedAt/ChallengeResultURL`), `internal/store/memory/{memory,tx,tenants,users,tickets}.go`, `internal/actionsrules/{rules.go,rules_test.go}`, `pkg/store/store.go`.

**Interfaces:**
- `ModuleRef{ModuleID, ModuleName, VersionID string; VersionNumber int}`; `Action.Modules`, `ActionVersion.Modules []ModuleRef` (version refs always fully resolved).
- `ActionModule{TenantID, ID, Name, Code string; Dependencies []Dependency; Secrets []ActionSecret; DraftBuildID string; LatestVersionNumber int; AllChangesPublished bool; CreatedAt, UpdatedAt time.Time}`; `ActionModuleVersion{TenantID, ModuleID, ID string; Number int; Code, BuildID string; Dependencies []Dependency; Secrets []ActionSecret; CreatedAt time.Time}`.
- `ActionJob{TenantID, ID, Trigger, Status string /*pending|done|failed|dropped*/; Sealed []byte; Attempts int; NextAt, LeaseUntil, CreatedAt, UpdatedAt time.Time; ExecutionIDs []string; ModuleVersionIDs []string}`.
- New sentinel `store.ErrPrecondition` (maps to 412).
- `Actions` methods: `CreateModule`, `GetModule(tenantID, id)`, `GetModuleByName(tenantID, name)`, `UpdateModule`, `DeleteModule(tenantID, id) error` (`ErrPrecondition` when a draft or deployed Action version references it; otherwise hides it and keeps pinned versions as tombstones), `ListModules(tenantID string, p PageRequest) (Page[ActionModule], error)`, `PublishModule(tenantID, id string) (*ActionModuleVersion, error)` (`ErrBuildNotReady`, `ErrConflict` when unchanged, `ErrPrecondition` at the version limit), `RollbackModule(tenantID, id, versionID string) (*ActionModule, error)`, `ListModuleVersions`, `GetModuleVersion(tenantID, moduleID, versionID)` (tombstones readable here for runtime use), `ModuleUsers(tenantID, moduleID string, p PageRequest) (Page[ModuleUser], error)`; `EnqueueJob(ctx, j *ActionJob) error` (`ErrPrecondition` at the pending cap), `ClaimJobs(ctx, now time.Time, lease time.Duration, max int) ([]ActionJob, error)`, `FinishJob(ctx, j *ActionJob, leaseUntil time.Time) error` (`ErrConflict` if the lease moved), `PurgeJobs(ctx, before time.Time) (int, error)` (also purges tombstones no longer pinned).
- `PasswordResetTickets.MarkChallengePassed(ctx, tenantID, tokenHash string, at time.Time, resultURL string) error`.

- [ ] Add `pkg/storetest` `ActionsII` subtests: module CRUD and unique names; publish numbering under concurrency, `ErrConflict` when unchanged, version limit, rollback replaces draft only; delete `ErrPrecondition` when a draft or deployed version uses it; delete with only an old version pinned leaves `GetModuleVersion` working; `ModuleUsers` paging; job enqueue cap, claim order by `NextAt`, a claimed job invisible until lease expiry, `FinishJob` lease check, purge; tenant deletion cleanup; tx rollback; challenge mark; `LastPasswordReset` round trip.
- [ ] Run `go test ./internal/store/memory ./internal/actionsrules -run 'Test(ActionsII|Conformance)' -count=1`; expect FAIL.
- [ ] Implement models, `actionsrules.NormalizeModule`/`ValidateModuleRefs`, memory repository; other stores return `ErrActionsUnavailable` for new methods until Tasks 3–4.
- [ ] Rerun plus `go build ./...`; expect PASS. Commit `feat: add Actions II domain and memory persistence`.

## Task 3: SQL storage and migration 0024

**Files:** Create `internal/store/sqlstore/{actions_modules.go,actions_jobs.go,actions_ii_test.go}`, `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0024_actions_ii.sql`; modify `internal/store/sqlstore/{actions.go,users.go,tickets.go,tenants.go}`.

- [ ] Add `TestActionsIIMigration` (0023 database upgrades; fresh and upgraded schemas agree) and `TestActionsIIConcurrency` (concurrent publish numbering; two workers claiming the same due jobs get disjoint sets using `FOR UPDATE SKIP LOCKED` on PostgreSQL/MySQL and the existing tenant lock on SQLite; delete-module vs deploy-Action race yields either 412 or a consistent pin).
- [ ] Run `./scripts/test-sql.sh -run 'Test(ActionsII|Conformance)' ./internal/store/sqlstore/...`; expect FAIL.
- [ ] Implement tables with tenant-inclusive keys; enqueue participates in the caller's transaction.
- [ ] Rerun; require actual SQLite/PostgreSQL/MySQL results. Commit `feat: persist Actions II across SQL drivers`.

## Task 4: Plugin protocol and capability 3

**Files:** Modify `proto/store/v1/store.proto` (additive), generated code, `internal/store/grpcstore/actions*.go`, `pkg/storeplugin/*`; extend `internal/store/grpcstore/actions_test.go`.

- [ ] Add `TestActionsIIPluginRoundTrip` (modules, versions, tombstones, jobs, challenge mark, `LastPasswordReset`) and extend `TestActionsOldPlugin`: a capability-2 plugin fails startup with a clear error when Actions are configured.
- [ ] Run `go test ./internal/store/grpcstore -run 'TestActions' -count=1`; expect FAIL.
- [ ] Implement RPCs, `ErrPrecondition` mapping, capability 3.
- [ ] `go generate ./...` twice (stable), rerun, `go build ./...`; expect PASS. Commit `feat: expose Actions II through storage plugins`.

## Task 5: Trigger table and event/api models

**Files:** Create `internal/actions/triggers.go`, `internal/actions/triggers_test.go`; modify `internal/actions/{engine.go,event.go,commands.go,runner.mjs}`.

**Interfaces:**
- Trigger constants `TriggerPreUserRegistration = "pre-user-registration"`, `TriggerPostUserRegistration`, `TriggerPostChangePassword`, `TriggerResetPostChallenge = "password-reset-post-challenge"`, `TriggerCustomEmailProvider`.
- `triggerSpec{ID, Handler, ContinueHandler string; Blocking bool; API []string}` in a package table used by `handlerFor` and by runner command validation; the runner builds each trigger's `api` object from the `api` list it receives, and records `op:"unsupported"` for listed-but-unsupported members.
- `Denial` gains `UserMessage string`; `Result` gains `ResultURL string` and `Notification *NotificationOutcome{Kind string /*retry|drop*/; Reason string}`.
- Event builders: `registrationEvent(in *RegistrationInput, a *accum)`, `postRegistrationEvent`, `postChangePasswordEvent`, `resetChallengeEvent`, `emailEvent` following spec §4–§6 field lists.

- [ ] Write `TestTriggerAPIs`, table-driven per trigger: each supported member records the right command; `api.authentication.challengeWith`, `challengeWithAny` and `api.prompt.render` fail with `unsupported_api`; post-registration and post-change-password expose only `api.cache`; `notification.retry` then `drop` → only the last counts; reason truncated at 1024; `access.deny(reason, userMessage)` carries both; `transaction.setResultUrl` with a non-https non-localhost URL → `invalid_api_call`.
- [ ] Write `TestTriggerEvents`: golden event JSON per trigger from fixed inputs; no password or password-like field in `event.request.body`; `geoip`/`security_context`/`authentication` absent.
- [ ] Run `go test ./internal/actions -run 'TestTrigger' -count=1`; expect FAIL.
- [ ] Implement the table, builders and runner `api` objects; Plan 27 triggers move into the same table with no behavior change.
- [ ] Rerun the whole `./internal/actions` package with `-race`; expect PASS. Commit `feat: add Actions II trigger table and event models`.

## Task 6: Modules build, pinning and runtime

**Files:** Create `internal/actions/modules.go`, `internal/actions/modules_test.go`; modify `internal/actions/{engine.go,runner.mjs,runnerjs.go}`, `internal/actions/build/manager.go` (module builds reuse `Queue`/`Ensure`).

**Interfaces:**
- Wire request gains `modules: [{name, version_key, code, deps_root, secrets}]` per Action version; runner resolves `require('actions:<name>')` from that list, evaluating each module once per (Action `version_key`, module `version_key`) in its own `vm` context with `module`, `exports`, its own `require` (deps root only; `actions:*` refused) and `actions.secrets`.
- `(*Engine).loadUnits` resolves `ActionVersion.Modules` through `GetModuleVersion` (tombstones included) and `Builds.Ensure` for each module build; a missing version or build fails the flow closed.

- [ ] Write `TestModulesRequire` (an Action calls `require('actions:util').greet()`; a module requiring `actions:other` throws; module `require` of a package outside its deps fails), `TestModulesSecretsIsolation` (module sees only its own `actions.secrets`; Action secrets and other modules' secrets absent; both masked in logs), `TestModulesPinned` (republishing or rolling back the module does not change an already deployed Action version; redeploy picks the referenced version), `TestModulesTombstone` (delete module after an older Action version pinned it; that version still runs; a queued job pinned to it still runs), `TestModulesTenantIsolation` (tenant B cannot `require` tenant A's module by name).
- [ ] Run `go test ./internal/actions -run 'TestModules' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun with `-race`; expect PASS. Commit `feat: run Actions Modules pinned per Action version`.

## Task 7: Job queue and worker

**Files:** Create `internal/actions/jobs.go`, `internal/actions/jobs_test.go`; modify `internal/app/app.go` (start the worker; purge jobs in the sweep loop), `internal/config/config.go` (`actions.job_workers` default 2, `actions.job_poll_interval` default 1s).

**Interfaces:**
- `(*Engine).Enqueue(ctx context.Context, tx store.Store, j AsyncJob) error`; `AsyncJob{TenantID, Trigger string; Input any}` — inside `tx`, snapshots bindings and pins units; no bindings → no job and no error; seals `{units, input}` with label `action-job/v1`.
- `actions.Worker{Engine *Engine; Store store.Store; Workers int; Poll, Lease time.Duration}`; `(*Worker).Run(ctx context.Context)`; `(*Engine).RunJob(ctx, j *store.ActionJob) (next *store.ActionJob)` applying spec §5: once-only for registration/password triggers; retry schedule for email.

- [ ] Write `TestJobsEnqueueInTx` (rolled-back tx leaves no job; committed tx leaves one pinned to the bindings at enqueue time), `TestJobsRunOnce` (post-registration failure → status `failed`, one execution record, log line with execution ID, no retry), `TestJobsEmailRetry` (retry → next attempts at +30 s, +1 m, +2 m, +4 m, +8 m with an injected clock, then `failed`; thrown error counts as retry by default; `drop` → `dropped`, never run again), `TestJobsLeaseExpiry` (a worker that stops mid-run: another claims after 60 s and runs exactly once more), `TestJobsCap` (10,001st pending job → `ErrPrecondition`), `TestJobsPurge` (10-day purge).
- [ ] Run `go test ./internal/actions -run 'TestJobs' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun with `-race`; expect PASS. Commit `feat: run non-blocking Actions from a durable job queue`.

## Task 8: Signup triggers

**Files:** Create `internal/actions/registration.go`, `internal/identity/actions_test.go`, `internal/dbconn/actions_test.go`, `internal/login/signup_actions_test.go`; modify `internal/identity/{database.go,custom.go}`, `internal/dbconn/signup.go`, `internal/login/login.go`, hosted signup template for the user message.

**Interfaces:**
- `(*Engine).PreUserRegistration(ctx, in RegistrationInput) (*Result, error)`; `RegistrationInput{Tenant tenant.Resolved; Client *store.Client; Connection *store.Connection; User *store.User; Request RequestInfo; Transaction *TransactionInfo}` (`Transaction` nil for `/dbconnections/signup`).
- `identity.SignupInput` gains `Actions SignupActions{Run func(ctx context.Context, u *store.User) (*actions.Result, error); Enqueue func(ctx context.Context, tx store.Store, u *store.User) error}`; `identity.ErrSignupDenied{Code, Description string}` and `ErrSignupActionFailed{ExecutionID string}`.

- [ ] Write `TestSignupPreRegistration` over `/dbconnections/signup`, hosted signup and legacy custom-DB signup: metadata set by the Action is on the created user (legacy: `user_metadata` passed to `create`, `app_metadata` only on the local record); deny → D-0054 wire body and no user, no `create` call, no job; `validation.error` → its code; thrown error → generic `extensibility_error` and hosted reference; duplicate email after a passing Action → normal error and no metadata.
- [ ] Write `TestSignupPostRegistration`: a job is queued in the insert transaction and runs after commit with `user_id`; a failing post-registration Action does not affect the signup response; at the tenant's pending-job cap the signup still succeeds and the dropped job is logged; Management API user create and bulk import enqueue nothing and run no pre-registration (D-0054 default unless Task 1 observed otherwise).
- [ ] Run `go test ./internal/identity ./internal/dbconn ./internal/login -run 'TestSignup' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun with `-race` plus the full packages; expect PASS. Commit `feat: run signup Action triggers`.

## Task 9: Password triggers

**Files:** Create `internal/actions/reset.go`, `internal/login/reset_actions_test.go`, `internal/mgmt/users_password_actions_test.go`; modify `internal/login/reset.go`, `internal/actions/continue.go` (reset-bound continuation), `internal/authz/continue.go` or the reset route for `/continue` dispatch, `internal/mgmt/users.go`, reset templates.

**Interfaces:**
- `(*Engine).ResetPostChallenge(ctx, in ResetChallengeInput) (*Result, error)`; `ResetChallengeInput{Tenant tenant.Resolved; Client *store.Client; Connection *store.Connection; User *store.User; Ticket *store.PasswordResetTicket; Request RequestInfo; CanRedirect bool}`.
- `(*Engine).ContinueResetChallenge(ctx, tenantID, state, ticketHash, pageCookie string, req RequestInfo) (*Result, error)`; continuation sealed over tenant, state hash, ticket hash, page cookie hash and origin; `/continue` dispatches to it when the state was issued by a reset flow.
- Post-change-password enqueue helper `actions.PasswordChanged(ctx, tx, eng, tenant, user, conn, req) error` sets nothing itself; callers set `User.LastPasswordReset` in the same tx.

- [x] Write `TestResetPostChallenge`: GET with bindings runs the Action once and records the pass (second GET from another browser skips); deny shows `reason`, ticket unspent, reopening runs again; redirect → `/continue` → form shown and pass recorded; replayed/other-cookie/other-ticket continue state → `invalid_request`; `setResultUrl` overrides the ticket result URL after submit; `challengeWith` fails closed with reference; POST without a recorded pass while bindings exist → refused, ticket unspent (also when bindings are added after GET); no bindings → unchanged behavior.
- [x] Write `TestPostChangePassword`: reset submit and Management API `PATCH /users/{id}` with `password` set `last_password_reset` and enqueue one job in the same tx; a failing Action does not affect the response; bulk import and custom-DB "no change" enqueue nothing.
- [x] Run `go test ./internal/login ./internal/mgmt ./internal/actions -run 'Test(ResetPostChallenge|PostChangePassword)' -count=1`; expect FAIL.
- [x] Implement.
- [x] Rerun with `-race` plus the full packages; expect PASS. Commit `feat: run password Action triggers`.

Task 9 resumption record (2026-10-28): implementation `bbe5701` was already
committed before the previous stop. Independent review found no Critical or
Important issues. Added hosted enqueue-failure regressions: a non-cap storage
error rolls back the password and `last_password_reset` while retaining the
already-consumed ticket; queue-cap overflow allows the reset and logs the drop.
Verification uses Go 1.26.7 with Node required: focused password/reset cases,
full affected login/management/actions/authz/jobs race suites, and `go build
./...`. Management rollback/cap negative tests and a wrong-origin reset
continuation negative test remain minor coverage follow-ups. The pre-existing
server module-route test gap remains assigned to Task 11; no whole-repository
regression success is claimed here. The original implementation's RED run was
not retained in its handover report; resumption verified the committed behavior.

## Task 10: Custom email provider

**Files:** Create `internal/actions/email.go`, `internal/email/custom_test.go`; modify `internal/email/service.go` (route `custom` deliveries to the queue), `internal/emailrules/{provider.go,inventory.json}`, `internal/mgmt/email_provider.go` (allow enabled `custom`; test send waits for the first attempt), `docs/email.md` stored-only note removed.

**Interfaces:** `email.Service.Actions ActionsQueue` where `ActionsQueue interface { EnqueueEmail(ctx context.Context, tx store.Store, in actions.EmailInput) error; RunEmailNow(ctx context.Context, in actions.EmailInput) (actions.EmailOutcome, error) }`; `actions.EmailInput{Tenant string; User *store.User; Client *store.Client; Connection *store.Connection; Message EmailMessage{From, To, Subject, HTML, Text, Locale, Type string}; Request RequestInfo}`; `EmailOutcome{Status string /*sent|retry|drop|failed*/; Reason, ExecutionID string}`. Template → `message_type`: `verify_email`, `reset_email`, `welcome_email`, `blocked_account`, `stolen_credentials`; test send → `try_provider_configuration_email`.

- [ ] Write `TestCustomEmailProvider`: verification email with `custom` enabled reaches the Action with rendered fields and is not sent via any transport; `retry` reschedules per Task 7; `drop` ends; `custom` enabled with no binding → `ErrProviderConfiguration` and nothing queued; disabled `custom` → server fallback as today; test send returns the first attempt's outcome and queues nothing; at the pending-job cap the send reports failure like a provider error.
- [ ] Run `go test ./internal/email ./internal/mgmt -run 'Test(CustomEmailProvider|EmailProvider)' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun with `-race`; expect PASS. Commit `feat: send email through custom-email-provider Actions`.

## Task 11: Management API, seed and triggers list

**Files:** Modify `api/management.yaml` (`x-source` per operation), generated code, `internal/mgmt/{actions.go,actions_versions.go,actions_bindings.go}`, `server/mgmtapi.go` routes/scopes, `internal/seed/{actions.go,validate.go,apply.go}`; create `internal/mgmt/actions_modules.go`, `internal/mgmt/actions_modules_test.go`, `internal/seed/actions_modules_test.go`.

- [ ] Write `TestActionsModulesContract`: every spec §8 operation — shapes (`actions_using_module_total`, `all_changes_published`, `latest_version_number`, `latest_version`), `publish: true` waits for the build and publishes, unbuilt draft publish `400`, unchanged publish `409`, version limit `412`, delete in use `412`, rollback replaces draft only, PATCH `secrets` replaces the list and values are write-only, PATCH with `name` `400`, duplicate name `409`, scopes 401/403, cross-tenant `404`, every limit.
- [ ] Extend `TestActionsManagementContract`: Action `modules` accepted by id pair or name/number pair and returned with all four fields; unknown module/version `400`; > 10 modules `400`; deploy pins refs; `GET /actions/triggers` lists exactly the seven triggers; creating an Action for a deferred trigger `400`; test endpoint dry-runs each new trigger (nothing queued or sent).
- [ ] Write `TestActionsModulesSeed`: modules with publish, Action module references by name+number, create-only restart.
- [ ] Run `go test ./internal/mgmt ./internal/seed -run 'TestActions' -count=1`; expect FAIL.
- [ ] Implement; regenerate; `make check-sources`.
- [ ] Rerun; expect PASS. Commit `feat: manage Actions Modules and Actions II triggers`.

## Task 12: Console

**Files:** Create `console/src/pages/actions/modules/{ModuleLibrary.vue,ModuleEditor.vue,ModuleVersions.vue}` and `*.test.ts`; modify `console/src/pages/actions/{Editor.vue,Triggers.vue,TestPanel.vue,Execution.vue}`, email provider page, router, nav, locales.

- [ ] Write Vitest cases: module list/create/delete (412 shown as "used by N Actions" with the list); module editor save/publish/build status/rollback; write-only module secrets; Action editor module picker (name + version, max 10) and per-trigger test payload templates; Triggers page shows seven triggers; execution view shows job attempts; email provider page enables `custom` with the binding note and test-send result; stale replies ignored.
- [ ] Run `npm --prefix console test -- src/pages/actions src/pages/email`; expect FAIL.
- [ ] Implement with existing components and localized strings; original layouts only.
- [ ] Run `make console`; expect lint, typecheck, tests and build PASS. Commit `feat: add Actions II and Modules to the console`.

## Task 13: Tools, browser flows and Deploy CLI

**Files:** Create `tests/e2e/run-m28-actions-ii.sh`, `tests/e2e/m28-actions-ii.mjs`, `tests/e2e/m28-actions-ii.spec.mjs`; modify `Makefile` (`e2e-actions-ii`), `tests/e2e/deploy-cli/*`, `internal/deploymigration` comparators.

- [ ] Add cases: auth0-cli `actions` create/deploy for each new trigger and `auth0 api` for module operations; node-auth0 for the module operations Task 1 found it exposes (raw requests otherwise, recorded); Playwright: hosted signup denied with the Action's user message, hosted signup with metadata then a post-registration Action posting to a local HTTP sink, reset page redirect round trip then `setResultUrl` landing, custom email provider Action delivering the verification email to the local sink and a `retry` run; console flows for modules and the email provider page.
- [ ] Extend the Deploy CLI four-cell matrix with modules and Action module references if Task 1 found Deploy CLI 9.1.0 supports them; otherwise record unavailable and cover Actions on the new triggers only.
- [ ] Run `make e2e-actions-ii` and `make e2e-deploy`; expect FAIL before fixtures, then PASS. Missing tools recorded as unavailable.
- [ ] Commit `test: verify Actions II with CLI SDK browser and Deploy CLI`.

## Task 14: Final regression, documentation and record

**Files:** Create `docs/superpowers/2026-10-28-plan-28-implementation-record.md`; modify `docs/actions.md`, `docs/email.md`, `docs/compat/matrix.md`, roadmap (Plan 28 done; Plan 34 entry carries the SMS provider note from spec §1), config reference.

- [ ] Document: each trigger's firing points, blocking vs non-blocking, job queue delivery semantics (at-least-once on lease expiry), retry schedule, reset-page challenge rules, custom email provider setup, modules (require, secrets, pinning, tombstones), limits, deferred triggers.
- [ ] Run `go generate ./...` twice, `make check-sources`, `go vet ./...`, `ZA_REQUIRE_NODE=1 go test -race -timeout=50m ./...`, `./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/...`, `make console`, `make e2e`, `make e2e-actions`, `make e2e-actions-ii`, `make e2e-rbac`, `make e2e-deploy`, `make e2e-email-accounts`, `make e2e-domains`, `tests/conformance/run.sh`. Record actual results, skips and unavailable services.
- [ ] Final whole-branch review against Review Focus and spec coverage; fix with regression tests; rerun affected checks; append the disposition to the record.
- [ ] Commit `docs: record Actions II behavior and verification evidence`. Hand off; do not merge or push.
