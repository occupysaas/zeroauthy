# Plan 28 implementation record

Status: Tasks 1–13 implemented and acceptance verified; final scoped and
whole-branch review pending. This record does not yet claim final approval. Branch `plan-28-actions-ii`, based on `f186364`.
Tasks 1–9 were implemented before the final Tasks 10–14 session.

## Verification

Required toolchain: Go 1.26.7 (selected with `GOTOOLCHAIN=go1.26.7`), Node
required for runner suites via `ZA_REQUIRE_NODE=1`. Tests use local registry,
HTTP and email fixtures; no live Auth0 or public npm calls are intended.
Public documentation checks are separate from runtime tests.

| Lane | Actual result |
|---|---|
| SQL three-dialect race suite | Passed, 1050.317s; snapshot before Task 10 provider guard removal |
| Updated SQL provider restart checks | Passed, 6.405s, three drivers available |
| Updated attempt metadata SQL roundtrip | Passed SQLite/PostgreSQL/MySQL, 3.738s; each executions-and-continue subtest ran |
| Additional broad SQL conformance attempt | Interrupted before final summary; not claimed passing |
| Generation twice, vet | Passed at Task 11 snapshot; generation stable |
| Conformance | Exit 0; Basic/Form Post each 21 pass, 6 warning, 4 review, 4 skipped; Config 1 pass; Logout 3 pass, 8 review; 0 failed modules |
| Offline console gate | Passed at `4949d0f`: lint, types, 65 files / 460 tests, production build; existing bundle warning |
| Full Go race initial run | Failed only three raw Node runner fixtures; repaired in `8303f4d`, focused and full noderunner race passed |
| Full Go race rerun | Passed on corrected tree (`final-go-race-green.log`), including current Task 13 CSP and trigger-reference changes |
| Existing Actions I acceptance | Passed SDK fourteen operations, CLI and five browser cases |
| RBAC acceptance | Passed SDK/CLI and four browser cases |
| Email-account acceptance | Passed SDK/CLI and fourteen browser cases |
| Standard e2e initial attempt | Port 8443 bind failure while Deploy owned the port; no pass claimed; clean sequential retry passed below |
| Task 9 affected race packages and build | Passed on Go 1.26.7; `a925a5c` |
| `make e2e` clean retry | Passed CLI/SDK; 24 browser cases passed, 42 dedicated-lane skips |
| `make e2e-actions-ii` | Passed ten SDK module methods, new-trigger CLI/raw module operations, four browser cases (34.2s) |
| `make e2e-deploy` | Passed all four cells: generated/preserved credentials × YAML/directory |
| `make e2e-domains` | Passed three ACME challenges, nine SDK operations, eight CLI operations and two browser cases |
| Final console gate | Passed offline, 65 files / 460 tests, lint/types/generation/build; existing chunk warning |
| Final `go vet ./...` | Passed; an earlier run during test authoring saw a temporary undefined test handler, subsequently corrected |
| Latest conformance rerun | Running; previous zero-failure result stands only for its earlier snapshot |

## Rulings carried from the execution ledger

- Task 2: Ruling: ModuleUser embeds Action with InDraft/InDeployed booleans and deduplicates by Action ID — spec defines usage by draft/current deployed but leaves storage row shape unspecified — cost if wrong: internal row adaptation in management.
- Task 2: Ruling: hidden tombstones do not reserve the deleted module name; recreated name receives a new ID and old pins remain bound to old IDs — deleted modules are API-invisible and immutable pins must survive — cost if wrong: tighten name uniqueness without changing pins.
- Task 5: Ruling: EmailInput keeps Tenant string per Task10 and adds TenantInfo *store.Tenant to build friendly/support event fields — caller supplies profile instead of replacing declared tenant ID type — cost if wrong: adjust enrichment field at email caller boundary.
- Task 6: Ruling: include necessary continue.go module-pin serialization and regression — existing redirect/resume must preserve Action module pins, cannot drop new fields until later reset task — cost if wrong: localized continuation schema extension already sealed. Task7 must cover real queued-job tombstone runtime because queue does not exist in Task6; Task6 covers lower-level pinned snapshots.
- Task 8: Ruling: extract minimal result data structs to internal/actionresult, alias actions.Result/related types — identity→actions cycles through actions→userrules→identity; data-only dependency preserves requested callback type compatibility — cost if wrong: move aliases/types back after decoupling validation. No broad package refactor.
- Task 8: Ruling: widen signup400 OpenAPI oneOf existing OAuthError/new D0054 ExtensibilityError now — contract harness requires actual signup response accepted this task — cost if wrong: adjust unionschema without changing existing errors. Move pure Effects methods with aliased data types as required Go.
- Task 8: Ruling: custom-DB signup adopting an existing local record keeps that record's metadata (pre-registration app_metadata not applied) — preserves pre-Actions upsert semantics in a rare edge case — cost if wrong: merge Action metadata into adopted record.
- Task 9: Ruling: preserve committed Task9 implementation despite missing prior RED log — no production defect found by independent review and fresh verification; rewriting correct committed code solely to manufacture a RED history would discard existing work — cost if wrong: original test-first provenance remains unavailable; current behavior is verified.
- Task 11: Ruling: accept module api_version as an opaque optional string per cached public/SDK schema (max20,noNUL), without runtime effect or response field — source schema has no enum, runtime remains node22 — cost if wrong: tighten validation or persist version metadata after new evidence. Public module version response uses version_number per sourced schema.
- Task 12: Ruling: complete missing execution-attempt producer with internal ExecutionResult JobID/JobAttempt persisted in existing SQL JSON and additive protobuf fields; serve via local operator system execution-attempt endpoint (job_id,attempt; nonjob204), preserving public Auth0 execution response — store has no lookup-job/update-execution API and UI must show actual attempts, not guessed counters — cost if wrong: local endpoint/internal metadata adaptation; no SQL migration needed. Implementer owns backend+UI together.
- Task 13: Ruling: normalize only module.latest_version_number as readonly per-destination publication history in Deploy comparison — actual staged private-secret reinjection produces source1→target4 with unchanged code/dependencies/name/publication/refcount and allActionpins version1; preserve exact Actionmoduleversion comparison, per-side existence validation and real pinned-version/private-secret runtime claim — cost if wrong: unexpected extra equivalent module publications could be missed, while pin/code regressions still fail.

## Deferred minor findings carried from scoped reviews

The final review will re-grade these by effect on users.

- Task 2: minor (deferred): Extend rollback coverage for mutation of existing module versions, leases and sealed slices (pkg/storetest/actions_ii.go:330).
- Task 2: minor (deferred): Add exact-expiry and challenge timestamp aliasing checks (pkg/storetest/actions_ii.go:363).
- Task 4: minor (deferred): Add ErrPrecondition to codec sentinel expected-assertion list (codec_test.go:505); real RPC test already covers mapping.
- Task 5: minor (deferred): resultURL invalid query/options branches lack array/null/nested-value tests (triggers_test.go:83,112; commands.go:559); report overstates query-error coverage.
- Task 8: minor (deferred): CountingStore assertions in mgmt/jobs signup_actions_test.go are vacuous (engine built on unwrapped store) — make engine use the counting store.
- Task 8: minor (deferred): legacy adoption fallback enqueues in a separate tx; blocked legacy profile still enqueues post-registration.
- Task 8: minor (deferred): duplicate metadata merge helpers / shallow copy may mutate caller maps; history hash inline duplicates RecordLegacyPassword logic.
- Task 8: minor (deferred): hosted request.body includes csrf (and state) — filter internal form fields; hosted protocol fixed oidc-basic-profile; hosted tests lack validation/timeout/unsupported cases.
- Task 9: minor (deferred): management PATCH rollback/cap negative cases, and wrong-origin reset-continuation rejection regression. Existing code inspected correct; hosted rollback/cap coverage added during resumption.
- Task 11: minor (deferred): dry-run seven-trigger test checks success/no jobs/executions but lacks expected command records and unchanged user-metadata assertions.
- Task 12: minor (deferred): pre-existing >500kB console bundle warning (no failure).

## Acceptance and review-focus mapping

| Acceptance area | Evidence owners |
|---|---|
| Module API shapes, errors, scopes and tenant isolation | `TestActionsModulesContract`, limits/isolation/public-tombstone/pins tests; server route/schema checks |
| Memory/SQL/plugin storage and migration | shared `ActionsII` conformance; `TestActionsIIMigration`, `TestActionsIIConcurrency`, plugin roundtrip and capability tests |
| Trigger APIs/events and unsupported calls | `TestTriggerAPIs`, `TestTriggerEvents`, real seven-trigger dry-run cases |
| Module require, secrets and version isolation | `TestModulesRequire`, `TestModulesSecretsIsolation`, `TestModulesPinned`, `TestModulesTenantIsolation` |
| Signup fail-closed before insert/custom create (Review Focus 1) | identity/dbconn/login `TestSignupPreRegistration`, duplicate/no-job/rollback/cap cases |
| Reset submit cannot bypass current bindings (Review Focus 2) | `TestResetPostChallenge/post_without_pass`; cookie/ticket/replay/result URL/unsupported cases |
| Retry/drop and lease semantics (Review Focus 3) | `TestJobsRunOnce`, `TestJobsEmailRetry`, `TestJobsLeaseExpiry`, real `TestCustomEmailProvider` |
| Pinned versions survive module deletion/publication (Review Focus 4) | module tombstone tests and `TestJobsModulesTombstone`; suspended parent/module deletion regression |
| Module cannot read other secrets/tenant trees (Review Focus 5) | `TestModulesSecretsIsolation`, `TestModulesTenantIsolation`, dependency-root rejection |
| Console stale replies, write-only secrets, module pin selection | Actions/Modules/email Vitest cases; delayed deletion success/412 regressions; 460-test offline gate |
| Job execution attempt identity | retry/corrupt-envelope tests, three-driver execution JSON roundtrip, plugin codec and operator authorization tests |
| CLI/SDK/browser/Deploy acceptance | Task 13 SDK/CLI/four-browser and four-cell Deploy lanes passed; historical module-version graph migration remains outside the demonstrated matrix |

Scoped reviews found and fixed canceled execution retention, suspended module
snapshot retention, unbound custom test-send error handling, module deletion
modal races and duplicated editor lifecycle. Task 9's original RED log was
not retained by the prior executor; its committed behavior was freshly
verified and reviewed rather than rewritten to manufacture provenance.

No live Auth0 firing behavior was observed: Task 1's attempted observer Action
creation was unavailable and cleanup retained original bindings. D-0054 local
choices and documented contracts remain distinct from observed upstream parity.

## Acceptance-discovered fixes and scope

Actual Chromium reset acceptance exposed CSP blocking a successful password
form POST's cross-origin Action result redirect. The form now reloads the
committed ticket, allows only its validated Action destination through the
existing CSP origin helper, and retains that destination on validation
rerenders. Both direct challenge success and redirect/continue forms have
regressions. A submitted destination is never trusted.

Deploy CLI roundtrips exposed catalogue-only `binding_policy` in writable
Action trigger references. Action responses now return id/version references;
the trigger catalogue retains its discovery metadata. All seven reference
forms have a roundtrip regression. Comparator self-review also found and fixed
acceptance of equal malformed fractional module-version pins.

The four Deploy cells each migrate one module with published version 1 and
six Actions (existing login plus five new triggers), with canonical module
name/version references, private-secret reinjection and real imported login
claims. This demonstrates pinned version-1 migration and repeated imports,
not arbitrary historical module-version graph migration. SDK acceptance
separately publishes two versions and rolls back the draft. Latest-publication
counters can differ because the tool's staged private-secret restoration
publishes additional equivalent destination revisions; exact Action pins and
module code remain compared, with per-side reference validation and actual
private-secret runtime assertions.

Existing Deploy exclusions remain: database connections are excluded/not
demonstrated; attack-protection migration awaits phone-provider-protection
APIs; unsupported header modes retain pinned-tool rejection; ACUL is excluded.
No missing local tools were reported. All automated calls target local
fixtures; public documentation reachability checks are separate.

Acceptance fixture failures were corrected before the final pass: CLI delete
confirmation, proxy routing of the local sink, reset-screen expectations,
console button labels, template POST's established 200 status, and the fixture
operator's verified email precondition. One Actions II attempt stopped before
tests on shared DNS port 8073; it is not a pass. The clean rerun waited for
domain acceptance to finish. These results do not weaken production
verification or bypass normal browser login/token issuance.
