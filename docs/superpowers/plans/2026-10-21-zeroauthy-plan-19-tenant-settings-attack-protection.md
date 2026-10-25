# zeroauthy Plan 19: Tenant Settings, Attack Protection and User Blocks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Operators configure tenant behavior and password-flow protections through Auth0-compatible APIs and the console, with shared limits and independently removable automatic login blocks.

**Architecture:** Extend the existing tenant model for settings and typed protection policies, backed by migration 0016 and all store drivers. A shared `internal/protection` service owns policy evaluation and atomic attempt receipts; hosted login, password grants and database flows consume it. Management handlers use shared rule packages and generated contracts; the console replaces two planned pages with clients of those same APIs.

**Tech Stack:** Go 1.26.7, existing chi/oapi-codegen, memory/SQLite/PostgreSQL/MySQL/gRPC stores, Vue 3/TypeScript/Vite, Vitest, Playwright, pinned auth0-cli and node-auth0. Standard-library HTTP, hashing and `net/netip`; existing encryption support.

**Spec:** [Tenant settings and attack protection design](../specs/2026-10-21-zeroauthy-tenant-settings-attack-protection-design.md). Read it with the roadmap's Plan 19 section and `CLEAN_ROOM.md` before execution.

**Status:** Approved for implementation by the user on 2026-10-21. Tasks 1–11 are implemented and reviewed; Task 12 documentation and required verification are complete, with final whole-branch review pending. Observed/documented/local-fallback distinctions remain. Based on repository commit `2e175f3`. D-0045 and the observation notes freeze local choices without claiming unobserved upstream parity.

## Global Constraints

- Go 1.26.7; retain the existing Vue 3/TypeScript/Vite console and current dependency pins. No new Go module is required.
- All durable tenant state is tenant scoped and implemented by every store driver, including transactional views and tenant deletion; short-lived opaque CAPTCHA replay tombstones use a shared global namespace.
- Public request/response shapes come from documented Auth0 endpoints and firewalled observation; never add zeroauthy fields to those responses.
- No outbound password lookup without explicit server configuration; never transmit plaintext passwords or full password digests.
- CAPTCHA secrets are encrypted at rest, omitted from logs and never populated back into console forms.
- All Management API writes are audited with the actor; security events contain no passwords, CAPTCHA responses or credentials.
- Hosted and console copy is original and localized; the console retains light/dark themes, keyboard access and tokens in memory.
- Stored-but-inert behavior must be named in the console and compatibility matrix; it is not claimed as runtime parity.
- Preserve existing seed seconds, proxy trust rules, custom-DB failure classification, password-hash upgrades and ticket atomicity. Task 1 freezes wire defaults and error/status/scope assertions before the tasks that consume them.
- **Execution rule (2026-10-23): Do not run any database-backed test from now until Tasks 1–11 are implemented.** This includes SQLite, PostgreSQL, MySQL, SQL-backed gRPC/plugin tests, database-backed integration or browser tests, `./scripts/test-sql.sh`, and broad test commands that select those tests. Write the tests and compile the affected code; run only focused tests known to use memory or mocks. Task 12 is the first point to run the deferred database tests. This rule supersedes earlier per-task test commands below; record deferred checks without calling them passing.
- Do not close general rate limiting, device shared counters, script Try limiting or Plan 21 notification follow-ups as part of this milestone.

## Review Focus

1. Two servers concurrently create the first bucket, finish requests out of order or unblock while verification is running: capacity cannot be overspent and old receipts cannot undo newer decisions. Task 4, `TestProtectionConcurrentAdmission` and `TestProtectionStaleCompletion`.
2. Session settings expressed in hours/minutes versus seconds, partial nested patches and explicit false/empty values: no truncation, silent loss or changed seed interpretation. Tasks 2 and 5, `TestTenantSettingsDurations` and `TestTenantSettingsConcurrentPatch`.
3. User aliases, IPv4-mapped IPv6 and forged forwarding headers: one canonical intended key, correct connection opt-out and no cross-tenant unblock. Tasks 6–7, `TestProtectionIPIdentity` and `TestUserBlocksIsolation`.
4. A checker/provider times out, lies via HTTP 200, reuses proof, or the user resets with a rejected password: no unauthorized login, consumed ticket, modified password or exposed secret. Tasks 8–9, `TestBreachUnavailable` and `TestCaptchaReplayAcrossInstances`.
5. Tenant switch during loading/saving, masked-secret PATCH and imported enabled protection without a configured backend: no cross-tenant write, erased secret or false indication of enforcement. Tasks 3 and 10, `TestCaptchaSecretPatch` and console tenant-switch tests.

## File and dependency map

| Unit | Files and responsibility |
|---|---|
| Evidence | New `docs/compat/observations/management-tenant-settings.md`, `management-attack-protection.md`; update changelog/decisions and these documents with frozen facts. |
| Rules/model | New `internal/tenantrules/{rules.go,rules_test.go}`, `internal/protectionrules/{rules.go,rules_test.go}`; new `internal/store/protection.go`; existing `internal/store/{types.go,store.go}`, `pkg/store/store.go`. |
| Storage | Existing tenant/session codecs and repositories; new `protection.go` in memory and SQL drivers; all three `0016_tenant_protection.sql` migrations; gRPC client/server/codec, proto and plugin exports. |
| Runtime | New `internal/protection/{service.go,keys.go,breach.go,breach_file.go,captcha.go,events.go}` and tests; existing `internal/{app,server,login,oauth,dbconn,identity,session,seed,config}` integration. |
| API | New `internal/mgmt/{tenant_settings.go,attack_protection.go,user_blocks.go}` and tests; existing routing, system tenant detail/capabilities, scopes and generated API contracts. |
| UI | New `console/src/pages/settings/TenantSettings.vue`, `console/src/pages/attack-protection/AttackProtection.vue` and focused tab/policy helpers; existing router, sections, users actions/detail, locales, generated schema and dist. Hosted templates/CSP remain under `internal/ui`. |
| Compatibility | New `tests/e2e/m19-mgmt-cli.mjs`, `m19-node-auth0.mjs`, `m19-console.spec.mjs`; existing harness scripts/seed. New `docs/tenant-settings.md`, `docs/attack-protection.md`; existing reference/matrix/follow-ups. |

Dependencies: 1 → 2 → 3; 2 → 4; 3+4 → 5–9; 5–9 → 10 → 11 → 12. Within Task 1, independent documented contracts can be frozen separately. Do not execute tasks whose required evidence remains unresolved. Create an isolated checkout at implementation time if needed; this plan-writing task does not change product code.

## Task 1: Freeze public contracts and firewalled observations

**Files:** the two observation notes above, `docs/compat/changelog-review.md`, `docs/compat/decisions.md`, this plan and its spec.

**Interfaces:** produces T1–T3/A1–A6 facts, a complete field/flag inventory with runtime owner or deferred milestone, and provider verification requirements. Later tasks use these named records for wire assertions. Allocate the next free decision ID at execution time; do not assume D-0045 is still available.

- [x] **Step 1: Review sources.** Review the public changelog since 2026-10-20, reference operations for both settings methods, ten attack-settings operations, four user-block operations and two anomaly operations. Record date, exact URLs, scope requirements and unavailable source/tenant entitlements. Read official provider verification docs, including Enterprise authentication and Friendly Captcha API version. Confirm current pinned CLI/SDK public APIs without upgrading dependencies.
- [x] **Step 2: Observe in a separate session.** Follow spec §2 T1–T3/A1–A6 and `CLEAN_ROOM.md`. Snapshot/restore tenant-wide settings in guaranteed cleanup, use temporary users and paced requests, never capture hosted/dashboard pages or secrets. The observer does not implement these resources.
- [x] **Step 3: Freeze executable facts.** For every row record response/status/scope, default/range, reset/null/merge semantics and the reference URL; for inaccessible features record a documented fallback, not fabricated observation. Freeze exact suspicious-IP rate units and expiry before counter work. Record read/write CAPTCHA secret rules and direct API challenge behavior before verifier integration.
- [x] **Step 4: Update this plan/spec.** Replace evidence-dependent expectations with the settled values and add contract fixture assertions to their owning task. Inventory every tenant field/flag; mark each enforced, read-only or inert with its later owner. Add decisions for legacy config, local bot risk, breach outage and unsupported CAPTCHA behavior. Resolve any contradiction with the draft before dependent code.
- [x] **Step 5: Verify and commit.** Manually check every gate row has a source/fallback and restoration outcome; scan notes for credentials, tenant names and personal data. Run `git diff --check`; commit only these records as `docs: freeze tenant settings and protection contracts`.

### Frozen fixture requirements for Tasks 2–11

Use [T1–T3](../../compat/observations/management-tenant-settings.md) and [A1–A6](../../compat/observations/management-attack-protection.md), including all nested constraints and every per-field inert/read-only owner. Task 2 must not add the seed-only use_scope_descriptions_for_consent property to the public API. Task 5 tests persistent 168/72-hour and ephemeral 72/24-hour defaults, integer writes/minute-backed numeric GET and session_cookie.mode. Tasks 4/6 test A2 30-day expiry and A3 independent token-bucket intervals. Task 7 tests unknown user-ID read/delete 404 inexistent_user versus unknown identifier delete 204, unblocked IP GET 404/DELETE 204 and the exact scopes. Task 8 labels its local unobserved breach errors. Task 9 tests requires_verification without an invented direct proof transport, Enterprise API-key assessments, Friendly v1 and credential omission/required-child rules. Task 11 calls the actual pinned SDK/CLI methods recorded in A6. Local fallback tests are not labeled live-observed assertions.

## Task 2: Shared settings rules and internal interfaces

**Files:** create `internal/tenantrules/rules.go`, `rules_test.go`, `internal/protectionrules/rules.go`, `rules_test.go`, `internal/store/protection.go`; modify `internal/store/{types.go,store.go,types_test.go}` and `pkg/store/{store.go,store_test.go}`.

**Interfaces:**

- `tenantrules.Apply(current *store.Tenant, patch map[string]any) (*store.Tenant, error)` returns a validated copy; `tenantrules.Public(t *store.Tenant) map[string]any` returns canonical public settings. No HTTP types in this package.
- `protectionrules.Apply(current store.ProtectionSettings, feature string, patch map[string]any) (store.ProtectionSettings, error)`; `protectionrules.Defaults() store.ProtectionSettings`. Feature names are the five documented route suffixes. Typed policies use the exact field inventory from Task 1; error values carry field paths for existing Management error mapping.
- `Tenant` gains typed support/session fields, `SettingsExtra map[string]any`, `ProtectionSettings` and an internal initialization marker; `LoginSession` gains its persisted cookie mode. Add explicit deep-clone support.
- `Store.Protection() Protection` returns the new repository. Define `ProtectionKey{TenantID, Kind, ConnectionID, Identifier, IP string}`; `ProtectionLimit{Key ProtectionKey, Algorithm string, Capacity int, Window, Refill, Lockout time.Duration}`; `ProtectionReceipt{TenantID, ID string}`; `ProtectionAdmission{Allowed bool, Receipt ProtectionReceipt, RetryAt time.Time}`; `ProtectionBlock{Key ProtectionKey, BlockedUntil time.Time}`; `ProtectionFilter{Kind, ConnectionID, Identifier, IP string}`. Empty filter fields are wildcards; public handlers construct narrowly scoped filters.
- Repository methods: `Reserve(ctx context.Context, limits []ProtectionLimit, now time.Time) (ProtectionAdmission, error)`; `Complete(ctx context.Context, receipt ProtectionReceipt, outcome string, now time.Time) error`; `Blocks(ctx context.Context, tenantID string, filter ProtectionFilter, now time.Time) ([]ProtectionBlock, error)`; `Clear(ctx context.Context, tenantID string, filter ProtectionFilter) error`; `UseProof(ctx context.Context, proofHash string, expiresAt, now time.Time) (bool, error)`; `RecordRisk(ctx context.Context, tenantID, ip, attemptID string, now time.Time) error`; `RiskCount(ctx context.Context, tenantID, ip string, since time.Time) (int, error)`; `Sweep(ctx context.Context, now time.Time, limit int) (int, error)`. Risk events are idempotent by tenant/attempt ID, expire after 15 minutes, and support an exact rolling count.

`Reserve` accepts one tenant only and atomically reserves all listed budgets or none. Algorithms: fixed-window, token-bucket and brute-force, with Task 1's units converted to durations by the service (suspicious-IP rate is milliseconds per token, not attempts/day). Outcomes are `failure`, `success`, `refund`; Task 4 defines per-kind handling. Internal state records receipt members/generation rather than trusting caller-supplied bucket mutations. Empty limits produce an allowed admission with an empty no-op receipt. Invalid limits/outcomes return `store.ErrInvalid`.

- [x] **Step 1: Write rule tests.** `TestTenantSettingsDurations`: 1 API hour → 3600 internal seconds; seed's 3600 seconds → 1 public hour; integer minute aliases serialize as numeric hours; fractional-hour writes, zero and paired aliases are rejected per T2. `TestTenantSettingsPartialPatch`: a single device-flow/flag change preserves siblings, false and empty arrays; root empty/unknown/null-invalid patches are 400 invalid_body, and rejected patch changes nothing. Cookie path is session_cookie.mode. `TestProtectionRules`: threshold 1/10/100 accepted, 0/101 refused; feature-specific shields, IPv4/IPv6 CIDRs and future stages follow A1; Extra cannot shadow typed values. Test nested cloning by modifying returned objects.
- [x] **Step 2: Run** `go test ./internal/tenantrules ./internal/protectionrules ./internal/store ./pkg/store`; verify new behavior fails before implementation. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 3: Implement** the interfaces and pure rules above. Store API hours/minutes as checked seconds, preserve presence, and keep field inventories explicit. Test implementation may initially use local models before wiring the new Store method in Task 4; keep the committed tree compiling by adding explicit temporary Unimplemented repository adapters to drivers if necessary, never an authentication fallback.
- [x] **Step 4: Run** the same packages and `go test ./internal/store/... ./pkg/storeplugin`; expect PASS and compile coverage of adapters. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 5: Commit** `feat: tenant and protection settings rules` with the task's files only.

## Task 3: Persist settings, seed precedence and provider secrets

**Files:** modify `internal/store/memory/{tenants.go,sessions.go,clone.go,tx.go}`, `internal/store/sqlstore/{tenants.go,sessions.go,migrate_test.go}`, `internal/store/grpcstore/{codec.go,codec_test.go}`, `proto/store/v1/store.proto`, `pkg/storetest/{tenants.go,sessions.go}`, `internal/seed/{seed.go,validate.go,apply.go}`, `internal/config/{config.go,config_test.go}`, `internal/app/app.go`; add the three dialect migrations at `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0016_tenant_protection.sql` and `internal/seed/protection_test.go`. Update generated proto files.

**Interfaces:** Task 2's model round-trips in every driver. Add `config.Security.BreachedPasswords` with mode/file configuration from spec §5 and explicit-presence tracking for the two legacy login keys. Existing tenant seed fields remain seconds; optional `attack_protection` seed maps through `protectionrules`. Credential encryption uses existing key wrapping rather than a new cipher or key.

- [x] **Step 1: Add store/seed tests.** `TestTenantProtectionRoundTrip`, migration from schema 0015 preserving all users/jobs/sessions, transaction rollback, nested copy isolation and session mode round-trip. `TestProtectionSeedPrecedence`: absent policy initializes once, explicit legacy values are honored, restart preserves API values, seed apply updates only supplied settings, create_only preserves everything. `TestCaptchaSecretPatch`: omitted provider preserves, supplied provider requires all documented credential children, explicit empty credential clears locally per A6, stored bytes differ from plaintext, public/API/log fixtures never expose it beyond A1's authorized contract.
- [x] **Step 2: Run** `go test ./internal/store/... ./internal/seed ./internal/config ./pkg/storeplugin`; establish the failing cases. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 3: Implement** persistent fields, migration, proto conversion and seed rules. Define the full migration with Task 4's bucket/reservation/proof/risk-event tables now; do not amend a committed migration after it has shipped. Existing rows receive compatible defaults. Track legacy initialization in internal persisted state and audit the transition; do not serialize it through Auth0 settings.
- [x] **Step 4: Run** the Step 2 command, `go generate ./...` and `./scripts/test-sql.sh`; expect PASS, deterministic generated output and migration success for all dialects. Capture generated files explicitly. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 5: Commit** `feat(store): persist tenant and protection policy`.

## Task 4: Atomic protection repository across every driver

**Files:** create `internal/store/memory/protection.go`, `internal/store/sqlstore/protection.go`, `pkg/storetest/protection.go`; modify driver Store/transaction constructors, `internal/store/grpcstore/{client.go,client_repos.go,server.go,codec.go}`, `proto/store/v1/store.proto`, `pkg/store/store.go`, `pkg/storeplugin/storeplugin.go`, `pkg/storetest/{storetest.go,tx.go,sweep.go}`, tenant/user/connection deletion implementations; regenerate proto outputs.

**Interfaces:** implement Task 2's entire `Protection` interface. `success` resets eligible brute-force history only through the receipt's admission sequence, refunds the request's unsuccessful-attempt budgets and preserves newer failures; `refund` removes only this reservation; `failure` commits its charge. Reset-mail requests use `failure` to retain their send charge regardless of recipient existence; risk-history counters retain failed outcomes. Clearing bumps generations, so delayed completions are no-ops. Duplicate Complete is a no-op. Pending work older than 60 seconds is a failure; `UseProof` returns false for a live duplicate across all processes and tenants sharing the store (hash provider ID plus response, never tenant or flow). Policy changes that change key/algorithm invalidate affected generations transactionally.

- [x] **Step 1: Add common store tests.** Fixed clock tests for capacity/refill/expiry, duplicate completion, success before/after newer failure, rollback/copy isolation, unknown tenant and cleanup. `TestProtectionConcurrentAdmission`: 20 concurrent reservations with capacity 3 admit exactly 3 before any completes. `TestProtectionStaleCompletion`: clear between reserve and failure, then a fresh failed request; completing the old receipt neither recreates its charge nor clears the fresh one. Repeat across two SQL handles. Test all-or-nothing multi-budget reservation, crashed reservation conversion at 60 seconds, proof replay, tenant/user/connection deletion and bounded Sweep progress. Global replay tombstones survive tenant deletion only until their 5-minute expiry; risk history is tenant-scoped and removed on deletion. Test rolling risk expiry and event deduplication.
- [x] **Step 2: Run** `go test -race ./internal/store/... ./pkg/storeplugin`; the new conformance cases must fail against temporary adapters. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 3: Implement** atomic operations in memory/SQL and matching gRPC RPCs, including transaction views. No hashing or HTTP call inside a transaction. Insert races must retry or serialize without losing increments; sweep uses generation predicates. An older plugin receives clear Unimplemented diagnostics.
- [x] **Step 4: Run** focused memory/mock tests and `go generate ./...`; verify generated code and memory/plugin transport without a database. Defer `./scripts/test-sql.sh`, SQL-backed plugin tests, broad store tests, and the repeated two-handle SQL race cases to Task 12 under the execution rule above. Record each deferred command; do not report it as passing yet. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 5: Commit** `feat(store): shared protection counters and attempt receipts`.

## Task 5: Tenant settings API and live session/runtime settings

**Files:** create `internal/mgmt/tenant_settings.go`, `tenant_settings_test.go`, `internal/server/mgmt_tenant_settings_test.go`; modify `api/management.yaml`, `internal/server/server.go`, `internal/tenantsetup/management.go`, `internal/session/{session.go,session_test.go}`, `internal/ui/{ui.go,templates/layout.html}`, and relevant `internal/{oauth,login,i18n}` tests. Regenerate `internal/gen/mgmtapi/mgmtapi.gen.go` and `console/src/api/schema.d.ts`.

**Interfaces:** generated GET/PATCH settings handlers call `tenantrules.Apply/Public` in `Store.WithTx`. Existing `session.Manager.Start/Current/Lookup` signatures remain; they consume persisted session mode and canonical tenant duration fields. Task 1's per-flag table names each existing consumer and its exact mapping.

- [x] **Step 1: Write API/runtime tests.** Missing auth/scope, wrong tenant, malformed/unknown fields and all-or-nothing validation use T1 errors. `TestTenantSettingsConcurrentPatch` preserves two independent patches. A 1-hour policy sets server expiry to now+3600s; transient cookies have no expiry attributes; idle touches follow T2/fallback. Assert defaults for audience/directory, changed logout allowlist, hosted locales (not console locales), PAR/device/consent and escaped support links. Protected system tenant values remain protected.
- [x] **Step 2: Run** `go test ./internal/mgmt ./internal/server ./internal/session ./internal/ui ./internal/oauth ./internal/login`; verify new tests fail. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 3: Implement** schemas with `x-source`, handlers, scopes, audited writes and actual runtime consumers. Document each stored-only field in schema descriptions without altering wire responses. Use generated contract helpers already in `internal/testutil/contract`.
- [x] **Step 4: Run** Step 2, `go test ./api ./internal/tenantsetup ./internal/i18n`, and `go generate ./...`; expect PASS and matching generated contracts. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 5: Commit** `feat(mgmt): tenant settings and session policy`.

## Task 6: Protection settings and automatic block APIs

**Files:** create `internal/mgmt/{attack_protection.go,attack_protection_test.go,user_blocks.go,user_blocks_test.go}`, `internal/server/mgmt_protection_test.go`; modify `api/management.yaml`, `internal/server/server.go`, `internal/mgmt/{system.go,auth.go}`, `internal/tenantsetup/management.go`; regenerate API types.

**Interfaces:** five feature-specific GET/PATCH pairs use `protectionrules.Apply`; block handlers call `Protection.Blocks/Clear` with canonical filters. Add `internal/protection/keys.go` with `CanonicalIP(raw string) string` and `LoginKey(tenantID, connectionID, identifier, ip, mode string) store.ProtectionKey`; reuse identity normalization and frozen A2 connection semantics. System tenant detail may return nonsecret checker capability to operators only, as specified in design §7.

- [x] **Step 1: Write contract tests.** All 16 operations get at least one success and auth/validation case. A1 defaults, masks, null/merge and exact scopes; A4 unknown user/identifier/IP and enablement query behavior. `TestUserBlocksIsolation`: identical identifier/IP in two tenants; linked identities; clear one tenant's automatic block while administrative `blocked=true` and other tenant/IP/reset-mail state remain. `TestProtectionIPIdentity`: mapped IPv6 and IPv4 match; invalid addresses cannot gain allowlist status. System capability has no secret/path/corpus content and rejects tenant M2M access.
- [x] **Step 2: Run** `go test ./internal/mgmt ./internal/server ./internal/protection`; verify expected failures. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 3: Implement** schemas, handlers, scopes, redaction, canonical keys and audit events. Merge policy writes against current rows in transactions; invalidate generations only when necessary for changed policy identity/algorithm, not on unrelated settings changes. Return public A4 block representations, never internal receipt data.
- [x] **Step 4: Run** Step 2, `go test ./api ./internal/tenantsetup` and `go generate ./...`; expect PASS. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 5: Commit** `feat(mgmt): attack protection settings and unblock APIs`.

## Task 7: Shared limits in login, password grants and reset mail

**Files:** create `internal/protection/{service.go,service_test.go,events.go}`; modify `internal/app/app.go`, `internal/server/server.go`, `internal/login/{login.go,reset.go}`, `internal/oauth/{handlers.go,grant_password.go}`, `internal/dbconn/{dbconn.go,signup.go,reset.go,change_password.go}`, related fixtures/tests, `internal/i18n/{keys.go,locales/en.json}` and existing cleanup wiring.

**Interfaces:** `Service.Begin(ctx context.Context, attempt Attempt) (Decision, error)` and `Service.Finish(ctx context.Context, receipt store.ProtectionReceipt, outcome string) error`. `Attempt` carries tenant/connection objects, normalized identifier, canonical IP and flow (`login|signup|reset-send`); `Decision` carries Allowed, RetryAt and Receipt. Service loads current policy and converts it to Task 2 limits; handlers map decisions to A2/A3 errors. Inject Store, clock and logger. A small structured security-event function accepts tenant, feature, outcome and safe actor identifiers; it rate-limits deferred-notification warnings.

- [x] **Step 1: Write integration tests.** Two server handlers sharing one store alternate wrong hosted/password-grant attempts until the shared threshold; correct credentials remain denied until unblock/expiry. Signup consumes no brute-force bucket. Connection opt-out skips only brute force. Public client spoofed `auth0-forwarded-for` is ignored, confidential-client trusted forwarding is canonicalized. Reset-send shares its 3/hour budget across handlers; successful reset clears the target automatic block, failed reset clears nothing. Store error issues no token/user write; custom-DB errors/refunds preserve existing classification and never refund a newer attempt.
- [x] **Step 2: Run** `go test -race ./internal/protection ./internal/login ./internal/oauth ./internal/dbconn ./internal/server`; establish failures. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 3: Implement** service and replace only the included process-local login/IP/reset-mail dependencies. Keep device and Try throttles intact. Take reservations before expensive work, complete them on every exit path, and run bounded cleanup. Cancellation/timeouts use the explicit recorded policy from Task 1 or existing D-0023 classification, not an accidental deferred success.
- [x] **Step 4: Run** Step 2 plus `go test ./internal/identity ./internal/system ./internal/app`; expect PASS, including existing imported-hash and custom-DB tests. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 5: Commit** `feat(auth): enforce shared password-flow protection`.

## Task 8: Breached-password checks at password boundaries

**Files:** create `internal/protection/{breach.go,breach_file.go,breach_test.go,breach_file_test.go}`; modify configuration/app wiring, `internal/login/{login.go,reset.go}`, `internal/oauth/grant_password.go`, `internal/dbconn/{signup.go,change_password.go}`, and A5's applicable Management password paths; add localized errors.

**Interfaces:** `type BreachChecker interface { Check(ctx context.Context, password string) (bool, error) }`; range/file implementations return an error for unavailable data, never a clean verdict. `Service.CheckPassword(ctx context.Context, tenant *store.Tenant, stage, password string) error` applies stage shields; stages are login, pre-user-registration and pre-change-password, mapped to A5's wire contract. Login callers invoke it only after credential verification and before token/session issuance.

- [x] **Step 1: Write checker/flow tests.** Mock range server sees only the five-character digest prefix and padding header; positive/negative/padded-zero/malformed/oversize/timeout/redirect cases, Unicode password, cache TTL and 1024-entry limit. Offline corpus sorted/unsorted/corrupt/missing cases and bounded indexed lookup. `TestBreachUnavailable`: block stage fails temporarily and monitoring continues; mode off makes zero requests. Rejected reset preserves ticket/password/history; rejected signup never invokes custom-DB create; imported user login cannot issue tokens on a breached password. A5 governs authenticated admin writes. Logs and errors contain neither password nor full digest.
- [x] **Step 2: Run** `go test ./internal/protection ./internal/login ./internal/oauth ./internal/dbconn ./internal/mgmt`; verify failures. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 3: Implement** the spec's fixed endpoint, 2-second/2-MiB limits, 1024-entry/5-minute prefix cache and indexed file lookup. Wire before mutations, with stage-aware policy and deferred notification events. Do not add tenant-controlled endpoint URLs or an HTTP-mode production escape hatch for tests.
- [x] **Step 4: Run** Step 2 with `-race` and configuration tests; expect PASS with network mocked and no external HIBP call. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 5: Commit** `feat(auth): breached-password detection`.

## Task 9: Bot policies and provider-verified CAPTCHA

**Files:** create `internal/protection/{captcha.go,captcha_test.go,bot.go,bot_test.go}` and provider-specific files/tests for the four supported providers; create `internal/ui/templates/captcha.html`; modify existing login/signup/reset templates, UI CSP/render data, flow handlers, configuration/encryption plumbing and locale catalogs.

**Interfaces:** `type CaptchaVerifier interface { Verify(ctx context.Context, challenge CaptchaChallenge, response string) error }`. `CaptchaChallenge` carries tenant ID, flow, transaction ID, expected hostname/site/action and provider ID; secrets are resolved internally. Hosted context comes from existing authenticated transaction/reset-ticket state and CSRF validation; direct-flow context follows the documented A6 mechanism. Providers without action/custom-data binding guarantee site validation and one-time use, not cryptographic first-use transaction binding. `Service.RequireChallenge(ctx context.Context, attempt Attempt) (bool, error)` implements the local classifier; `Service.VerifyChallenge(ctx context.Context, challenge CaptchaChallenge, response string) error` validates provider result then atomically consumes the proof hash using `Protection.UseProof`. Derive the challenge binding from server-held flow context, never trust submitted tenant/provider/hostname. Bot risk calls `RecordRisk/RiskCount` using the qualifying-event list in spec §6; a single failed attempt records at most one event, normal reset-email requests and infrastructure outages record none, and successes do not clear history.

- [x] **Step 1: Write tests.** `never/always/when_risky`, low=10/medium=5/high=1 failures in 15 minutes, allowlists and monitoring; risks aggregate across two services. Wrong credentials from an empty history activate `when_risky` without a previous CAPTCHA; duplicate failure reporting counts once, success does not erase history, and events age out exactly after 15 minutes. Provider success=false on HTTP 200 is failure; missing/mismatched hostname/action/site, malformed/oversize/timeout/redirect responses fail. `TestCaptchaReplayAcrossInstances`: identical verified response on two services proceeds once; an already-used proof cannot be accepted across flows/tenants/transactions; mismatched provider action is refused where supported. Do not assert transaction binding that the provider protocol cannot prove. Missing credentials/unsupported provider fails only a required challenge; no script on nonchallenge pages. Client-credentials/refresh/silent-session paths remain unchanged. Direct password/reset error contract is A6's, not an invented browser redirect.
- [x] **Step 2: Run** `go test ./internal/protection ./internal/ui ./internal/login ./internal/oauth ./internal/dbconn`; verify failures. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 3: Implement** providers from their Task 1 official contracts, 2-second/256-KiB HTTP limits and 5-minute shared replay records. Add narrowly scoped CSP/widget integration and accessible retry/error. Store unsupported provider fields without asserting enforcement. Never log provider responses or secrets. Track local risk independently of enforcement settings so disabling one feature does not disable another.
- [x] **Step 4: Run** Step 2 with `-race`, existing hosted CSP tests and locale parity tests; expect PASS. Add browser mock-verifier coverage to Task 11; real provider credentials are optional manual smoke tests only. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 5: Commit** `feat(auth): bot policies and verified CAPTCHA challenges`.

## Task 10: Live console settings, protection and unblock controls

**Files:** create the settings/attack-protection pages and tests from the map, focused form helpers, `console/src/pages/users/BlocksPanel.vue`; modify `console/src/{router.ts,layout/sections.ts}`, `console/src/pages/users/{Detail.vue,ActionsMenu.vue,Detail.test.ts}`, `console/src/pages/planned/planned.test.ts`, `console/src/locales/en.ts`, generated schema/dist. Remove the two obsolete planned-page components after routing is replaced.

**Interfaces:** generated API request/response types; each panel captures tenant identity before issuing a request and refuses to apply stale results. Settings tabs follow spec §7; blocks use separate public user-block endpoints. Provider capability comes only from the operator system detail field defined in Task 6, never from secret introspection.

- [x] **Step 1: Write Vitest tests.** Each feature loads/saves only its own patch; nested edits preserve unrelated values, unit labels/conversion are correct, server errors appear at the field, and hosted locale choices are independent of console locale. Test dirty forms and delayed responses during tenant switch. Secret omission preserves a saved secret and input clears after success; future fields/provider/notification/backend gaps remain visible. Automatic unblock leaves administrative Block state unchanged and refreshes block data; IP check/delete uses the correct endpoint. Existing planned-page tests now exclude exactly these two live sections.
- [x] **Step 2: Run** `cd console && npm test`; verify new tests fail. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 3: Implement** original accessible forms using existing Field/Toggle/tabs/confirmation patterns. Display explicit duration/refill units, seed overwrite notices, and loading/empty/error states; keep destructive confirmation for unblock as the existing action style requires. Update catalog and sections/router together.
- [x] **Step 4: Run** `make console`; expect lint/typecheck/Vitest/build PASS. Review the live pages in light/dark and narrow layouts, keyboard through tabs/errors/confirmations, and verify no network calls to Auth0 or CAPTCHA from console pages. Commit generated types/dist. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 5: Commit** `feat(console): tenant settings and attack protection`.

## Task 11: CLI, SDK, browser and two-instance compatibility

**Files:** new `tests/e2e/{m19-mgmt-cli.mjs,m19-node-auth0.mjs,m19-console.spec.mjs}`; modify `tests/e2e/{run-m3.sh,run-browser.sh,seed.yaml}`; add local protection mock service/fixtures under `tests/e2e` and server integration fixtures as needed.

**Interfaces:** pinned auth0-cli 1.37.0 and node-auth0 7.4 currently used by the repository; use their installed public method/command names confirmed in Task 1. Harness supplies a local breach range transport/mock verifier and two zeroauthy instances sharing a SQL database; no real provider calls or global insecure TLS workaround.

- [x] **Step 1: Add CLI/SDK cases.** Tenant settings read/patch; every protection feature read/patch; block lookup/delete and IP anomaly read/delete. Assert SDK-parsed values, nested preservation and scope rejection. Snapshot/restore fixture policy so tests do not leave the console operator locked out. Mocks are injected only through test harness construction, never a publicly accessible bypass endpoint.
- [x] **Step 2: Add browser cases.** Save session/name/locale settings; verify hosted effects; lower brute threshold, fail login then inspect/clear automatic block and sign in; show breach refusal from a local mock; require CAPTCHA and test failed/replayed/successful proof; switch tenant while a settings load is delayed. Assert no raw secret appears in DOM after save.
- [x] **Step 3: Add two-instance case.** Alternate requests across instances with one SQL store, restart one, then prove the existing block/send budget still applies and unblocking on the other is immediately effective. Replay proof across instances. Keep these local—never run concurrency experiments on Auth0.
- [x] **Step 4: Run** only e2e cases known to use memory/mocks without a database. Defer database-backed e2e and `make e2e` if it selects them to Task 12 under the execution rule above; record deferred cases without claiming a pass. (Executed or superseded by the focused checks and Task 12 consolidated verification under the database-test hold; see task reports.)
- [x] **Step 5: Commit** `test(e2e): tenant settings and shared attack protection`.


## Task 12: Documentation, final verification and roadmap status

**Files:** create `docs/tenant-settings.md`, `docs/attack-protection.md`; update `README.md`, `docs/{management-api.md,console.md}`, `docs/compat/{matrix.md,decisions.md,changelog-review.md}`, `docs/superpowers/plan-1-followups.md`, roadmap and this plan. Update NOTICE only if implementation introduced a dependency or adapted licensed code.

- [x] **Step 1: Document** duration units/seed precedence, migration of explicit legacy settings, shared-store requirements, supported/inert fields/providers, exact failure policy, local risk difference, corpus configuration/format, proxy trust and automatic-versus-administrative unblock. Include a recovery recipe using a separately authorized Management client for a locked console operator. Record Plan 21 notification/unblock-link follow-ups and leave device/general rate-limiting work open.
- [x] **Step 2: Verify implementation.** Run `gofmt -l` on changed Go files (expect no output), `go vet ./...`, `go test -race ./...`, `./scripts/test-sql.sh`, `go generate ./...`, `make console`, `make check-sources`, `make e2e`, and `make conformance`. Regeneration must produce no unexpected diff; compare against committed generated outputs. Report actual unavailable services or source-fetch failures and do not label failed checks passing.
- [ ] **Step 3: Review coverage.** Match every spec §8 acceptance criterion and T/A evidence row to tests/docs; verify all five Review Focus items have their named cases. Check the only remaining process-local limits are explicitly deferred ones. Review the full implementation diff, then update task checkboxes and roadmap counts based on actual completion.
- [ ] **Step 4: Commit** `docs: tenant settings and attack protection; Plan 19 records`.

## Planning review

This is a documentation deliverable, not permission to mark code complete. Before handing off, check all file paths against the current tree, all interfaces across task boundaries, all spec requirements against a task, and all evidence-dependent claims against the observation gate. Builder review identified ambiguous bot-risk events and an overstated CAPTCHA transaction-binding guarantee; both were resolved explicitly in spec §6 and Tasks 2/4/9. The user approved implementation on 2026-10-21. D-0045 freezes the local engineering choices and the Task 1 notes freeze the evidence/fallback contracts; implementation proceeds under the selected execution workflow.

## Task 12 verification record (2026-10-24)

All Tasks 1–11 were implemented and reviewed before the deferred database
checks ran. Go commands used Go 1.26.7. Earlier unchecked per-task database
commands were superseded by this consolidated verification, not claimed as
passing during the hold.

| Check | Actual result |
|---|---|
| `gofmt -l` changed Go files | Passed, no output |
| `go vet ./...` | Passed after removing obsolete throttle fields in a system-test fixture |
| `go test -race ./...` | Passed after correcting invalid fixture scopes and deferred HTTP-test assumptions |
| `./scripts/test-sql.sh` | Passed: SQLite, PostgreSQL and MySQL race suites |
| `go generate ./...` | Passed; committed generated outputs unchanged |
| `make console` | Passed: lint, types, 41 test files / 315 tests, production build |
| `make check-sources` | Passed |
| `make e2e` | Passed: pinned CLI/SDK including m19; 24 browser cases passed, m19 intentionally skipped without its dedicated harness |
| `./tests/e2e/run-m19.sh` | Passed: SQL two-instance/restart cases and full dedicated browser case (1 passed); local breach/verifier mocks only |
| `make conformance` | Running; no success claimed yet |

Initial deferred-test failures were fixture issues: removed process-local
server dependencies, nonexistent user-block scopes (the correct users scopes
were already granted), wrong-credential status expected as 401/403 rather than
400 invalid_grant, asynchronous mail read before delivery, browser button/sidebar
labels, and an English browser preference incorrectly expected to choose French.
Corrections retain runtime behavior and exact status/code assertions. The
browser locale case now explicitly requests fr-FR. No provider or authenticated
Auth0 tenant calls ran; source checks fetched public documentation URLs only.

Coverage: T1–T3 map to tenant rules, seed/store/session/server and console
settings tests. A1 maps to protection rules, API contracts and secret tests;
A2–A3 to shared store/race/runtime/two-instance tests; A4 to user-block isolation
and CLI/SDK scopes; A5 to breach checker and password-boundary tests; A6 to
provider/risk/replay and dedicated hosted browser tests. All five named Review
Focus groups exist, including TestProtectionConcurrentAdmission,
TestProtectionStaleCompletion, TestTenantSettingsDurations,
TestTenantSettingsConcurrentPatch, TestProtectionIPIdentity,
TestUserBlocksIsolation, TestBreachUnavailable, TestCaptchaReplayAcrossInstances
and TestCaptchaSecretPatch. Device/general/Try limits and Plan 21 delivery
remain open. Real provider accounts/assets remain outside automated local proof.
