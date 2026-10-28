# Plan 27 implementation record

Branch `plan-27-actions`; implementation baseline `e089fef`; reviewed runtime
through `7543ea4`. Tasks 1–12 are implemented with scoped reviews and fixes.
Task 13 records the completed local verification and operator documentation.
The final independent whole-branch review (`dbd8712..e1aaee9`) and its fixes
are recorded at the end. No merge or push is part
of this work. Public-source contracts and local tests do not establish live
Auth0 parity; no live upstream tenant was available.

The [operator guide](../actions.md), [D-0053](../compat/decisions.md#d-0053--plan-27-actions-contract-2026-10-27)
and this record qualify the approved [design](specs/2026-10-27-zeroauthy-actions-design.md)
and [plan](plans/2026-10-27-zeroauthy-plan-27-actions.md) where implementation
rulings superseded draft assumptions.

## Tasks and reviewed changes

| Task | Implementation / evidence |
|---|---|
| 1 contracts | `0960cda..c88d436`: fourteen-operation inventory, supported APIs, limits and D-0053; consent-order correction `5a11b0b`. Public citations corrected after review. Live observation unavailable; incomplete changelog/status-fetch evidence remains below. |
| 2 shared runner | `7d7845e`: separate Actions/custom-DB pools, empty environment, permission sandbox, tenant/version isolation. npm feasibility passed Node 22.23.4, 24.20.0 and 26.8.1 before implementation; canary/host-file probes and custom-DB regression pass. |
| 3 domain/memory | `84e2ecf`, `f9a8026`: rules, memory/rollback, pinned bindings, immutable deploys, artifact admission and shared conformance. Separate rules RED was not observed. |
| 4 SQL | `83c8aa1`, `b0a6b17`: three-dialect migration 0023, locking, concurrency and cleanup. Controller found stale LatestVersion=22 fixture; whole SQLite package passed after correction. Full post-marker SQL verification below includes subsequent schema changes. |
| 5 plugin | `29a71cd`, `4e7545f`: all RPCs, 256-KiB streamed artifacts, size/hash integrity, explicit unavailable errors, rollback and startup capability. Actions skips removed from plugin conformance. Final capability is 2 after Task 10. |
| 6 builds | `9f98636`, `fd9ba48`: loopback registry fixtures, exact/latest/scoped dependencies, ignored scripts, private HOME/cache, artifact verification/extraction/prewarm. Review fixed unbounded resolver concurrency and abandoned builds; Node 22/24/26 checks pass. |
| 7 engine | `424250c`, `66e62c9`, `36f9a70`: ordered flow, roles/cache/commands/claims, masking, transactional metadata+execution and fail-closed behavior. Hot-path execution/continue tenant locks removed. Temporary redirect support refused closed until Task 9. |
| 8 grant integration | `af60c21`, `97de5e8`, `3fa0984`: code/device/password/realm/refresh/M2M effects, consent carry, sealed protocol fields and error delivery. Two review rounds corrected target additions, removed/unconsented scopes in refresh ceilings, empty ceiling and no-bindings read cost. |
| 9 continuation | `e11c5cf`, `b2b02ec`: sealed single-use state, original session/origin, pinned tail and roles, JWT helpers and custom domains. Review regressions moved original client/connection validation before resumed code and restored original response-mode error delivery. |
| 10 management/seed | `99e4eb1`, `d8b0c01`: strict generated schemas, exact scopes, fourteen operations, recovery, write-only secrets and seed startup. Review regressions fixed empty-list reseeding with durable initialization markers and structured test error schema. Three-dialect caller-transaction freshness tests pass. |
| 11 console | `2caf472`, `8d94517`: library/editor/version rollback/test/triggers/execution, localization and stale-response guards. Controller completed interrupted agent work; explicit translation keys, 100,000-byte source editor limit and bound-only force prompt fixed. Review regression prevents PATCH [] after failed initial binding reads. Full console 439 tests pass. |
| 12 tools/acceptance | `eba3b0a`, `7543ea4`: actual CLI/SDK/browser and four-cell Deploy CLI matrix. Strict default-role first/next issuance test found post-Action RBAC reload; captured assignments now survive the flow while current API definitions still filter them. All affected race packages and fresh Actions lane pass after review fix. |
| 13 documentation/final verification | Operator/config/custom-DB/compatibility/roadmap/plan records updated. Required local checks finished as recorded below; final whole-branch review remains pending. Scratch task reports are local workflow artifacts, not the permanent record. |

## Controller rulings (complete carry-forward)

1. Amend unreleased `0023_actions.sql` for code/device ActionEffects rather
   than add 0024; migration shape/upgrade assertions extended. This is an
   explicit unreleased-migration exception, not permission to edit history.
2. Add AuthCode/DeviceCode/DeviceDecision effects to protobuf and gRPC codecs
   with round-trip coverage so plugins cannot silently drop token effects.
3. Export `ErrDraftNotBuilt` / `ErrActionNotFound`; Management maps them to
   400 / 404.
4. Run post-login before consent. Carry effects through consent without
   rerunning; metadata committed at flow end persists after declined consent.
5. `Inventory()` returns `Catalog` to avoid the Go name collision; cosmetic.
6. Correct Task 4's stale migration-version fixture to 23. Whole affected
   packages, not only filtered new tests, are required to catch regressions.
7. Keep synchronous dependency resolution to preserve content-addressed IDs,
   with a separate semaphore sized by `MaxConcurrentBuilds` and 15-second
   resolver-process deadline. Timeout maps to 503; cancellation stays distinct.
   Queue wait is bounded only by the caller context.
8. Recover interrupted pending/building records on Queue or Recover, invoked
   on draft GET/deploy/test. There is no startup ListBuilds scan. Duplicate
   replica builds are accepted for deterministic content-addressed output.
9. Until Task 9, `sendUserTo` failed closed as `redirect_not_supported`.
   Task 9 replaced that temporary behavior with real suspension/continuation.
10. **`/userinfo` does not echo Action ID-token custom claims in Plan 27.**
    This supersedes D-0053's original default and remains a parity gap.
11. Refresh ceiling is issued/consented scopes ∩ pre-Action authorized scopes.
    It excludes Action additions and Action-removed/unconsented scopes.
    Refresh target additions for consent-requiring clients also require the
    stored user grant. They never enlarge the persistent ceiling.
12. Every redirect/resume phase gets its own execution record, suspended or
    final; a single mutable execution record does not span browser gaps.
13. `ApplyWithActions` first applies ordinary seed data transactionally, then
    builds outside that transaction to avoid builder/store deadlock. Ready
    Actions are created/deployed atomically; ordinary data can survive a
    failed Action build. Legacy Apply rejects Action-bearing seeds.
14. Supersede the empty-trigger heuristic with durable tenant/trigger ownership
    plus atomic `InitializeBindings`. Management replacement, including [],
    initializes ownership. Rollback/crash stays retryable; tenant deletion
    removes markers; migration backfills existing lists. Store/RPC capability
    rises to **2**, so older plugins refuse startup.

Additional implemented integration choices: device approval cannot redirect;
password/realm protocols are `oauth2-password` / `oauth2-resource-owner`;
`device_code` joins stripped request credentials; validation.error at the
post-login token endpoint is 403 with its code. Codes are 1–128 RFC-6749
charset bytes; deny/messages sanitize disallowed bytes and truncate to 512.
Final access-scope edits do not change ID-token issuance and adding
`offline_access` cannot issue a refresh token. A refresh target edit is
bounded by family/policy/consent rather than the request's narrower scope.
Removing final offline_access suppresses rotation, while removing target-only
offline_access can still rotate an existing family.

The Task 12 acceptance fix freezes assignments only when a bound post-login
flow starts for an RBAC-enabled non-system API. The sealed audience-bound
snapshot survives code/device/consent/continue; APIs without a captured
snapshot retain issuance-time RBAC lookup. Mint still applies current API
settings, declared permission names and application policy. Regression
`TestActionsFrozenPermissionsRespectCurrentAPIDefinition` proves assignment
changes stay frozen while deleted API permission definitions disappear.

## Final local verification (2026-10-28)

The controller ran these checks; Task 13 inspected the logs without rerunning
long suites. The SQL/race timeout was raised from the plan's 30m to 50m after
Task 7 demonstrated that broad SQL packages can exceed default budgets.
Node-required lanes use `ZA_REQUIRE_NODE=1`; tests use local registry fixtures.

| Check | Actual result / local evidence |
|---|---|
| `go generate ./...` twice | Both exit 0; tracked generated hashes stable (`/tmp/plan27-final-generate-1.log`, `-2.log`, `/tmp/plan27-generated-first.json`). |
| `make check-sources` | Exit 0, `/tmp/plan27-final-sources.log`. Documentation URL checking intentionally accesses source sites. |
| `go vet ./...` | Exit 0, repeated after the permission fix in `/tmp/plan27-final-vet-after-fix.log` (earlier `/tmp/plan27-final-vet.log`). |
| `ZA_REQUIRE_NODE=1 go test -race -timeout=50m ./...` | First attempt exit 1: customdomain `TestDomainDiagnostic` local TLS discovery hit its 500ms deadline under parallel race load. All other packages passed, including sqlstore 695.768s and grpcstore 718.552s. `/tmp/plan27-final-go-race.log`. |
| Whole customdomain immediate race rerun | Exit 0, 1.945s; no product/test change. This isolated rerun does not erase the initial failure. |
| `ZA_REQUIRE_NODE=1 go test -race -p2 -timeout=50m ./...` | Retry exit 0, `/tmp/plan27-final-go-race-retry.log`; valid same-code Go test cache reused where available, changed OAuth ran fresh. |
| `./scripts/test-sql.sh -timeout=50m ./internal/store/sqlstore/...` | Exit 0, SQLite/PostgreSQL17/MySQL8.4, `-race -count=1`, 711.392s after durable marker/protocol changes. `/tmp/plan27-sql-post-marker.log`. Earlier full pre-marker run also passed in 744.232s, `/tmp/plan27-sql-final.log`. |
| `make console` | Exit 0, lint/typecheck/production build, 64 files and 439 tests; `/tmp/task11-review-console.log`. Existing chunk-size advisory remains. |
| `make e2e` | Exit 0, browser 24 passed / 33 lane-gated skips, CLI/SDK checks; `/tmp/plan27-e2e-core.log`. Skips are not passes. |
| `make e2e-social` | Exit 0, six browser cases and SDK/CLI verification; `/tmp/plan27-e2e-social.log`. |
| `make e2e-email-accounts` | Exit 0, fourteen browser cases and SDK/CLI verification; `/tmp/plan27-e2e-email-accounts.log`. |
| `make e2e-domains` | Initial port 8073 collision with Task 12 harness; retry exit 0, ACME challenge, SDK nine operations, CLI eight operations, two browser cases; `/tmp/plan27-e2e-domains-retry.log`. |
| `make e2e-rbac` | Exit 0, SDK/CLI/middleware and four browser cases, `/tmp/plan27-final-e2e-rbac.log`. |
| `make e2e-actions` | Fresh post-review exit 0 on `7543ea4`, SDK fourteen operations/grants/default-role first+next issuance, CLI operations including persisted execution read and missing 404, five browser cases; `/tmp/za-m27-actions-review-final.log`. |
| `make e2e-deploy` | Exit 0, all four YAML/directory × generated/preserved cells, Actions/triggers source=1 target=1 each. Import/repeat/credentials/update/target-only/negative/runtime pass; `/tmp/za-m27-deploy.log`. |
| Final affected race after Task 12 fix | Exit 0: Actions 14.276s, build 13.908s, OAuth 133.741s, authz 20.007s; `/tmp/za-m27-review-affected-race.log`. Comparator/deploymigration and offline registry coverage also pass in `/tmp/za-m27-affected-race.log`. |
| `tests/conformance/run.sh` | Initial port 8443 collision with Deploy lane; retry exit 0 with zero failed modules. `/tmp/plan27-final-conformance-retry.log`; counts below. |

Core/social/email regression lanes ran after Task 11 while Task 12 harness
work was underway; the record does not pretend they were rerun after the last
permission fix. The changed runtime has its complete affected-package race
suite, fresh Actions lane, RBAC lane and final full Go retry evidence.

Conformance artifacts: `tests/conformance/results/20261028T053837Z` (ignored
local artifacts). Local conformance is not formal certification and warning,
review and skipped modules are not counted as passing:

| Plan | Modules | Passed | Failed | Warning | Review | Skipped |
|---|---:|---:|---:|---:|---:|---:|
| Basic | 35 | 21 | 0 | 6 | 4 | 4 |
| Configuration | 1 | 1 | 0 | 0 | 0 | 0 |
| Form Post | 35 | 21 | 0 | 6 | 4 | 4 |
| RP-initiated logout | 11 | 3 | 0 | 0 | 8 | 0 |

## Acceptance coverage and review focus

1. **Fail closed:** engine and real grant matrix cover throw, timeout,
   unsupported APIs (including caught exceptions), invalid arguments,
   oversized claims, broken artifact/store effects and no code/token on
   failure. Metadata/execution atomicity has regression coverage. Full OAuth,
   authz, Actions and runner packages pass under race.
2. **Sandbox:** feasibility and canary probes cover Node 22/24/26, empty
   environment, `/proc/*/environ`, host config, cross-tenant roots, isolated
   secrets/cache and separate custom-DB timeout survival. Ignored lifecycle
   script and unsafe dependency fixtures pass; public npm is not an intended
   test dependency. OS/container hardening limits remain explicit in the guide.
3. **Scopes:** user grants × RBAC on/off cover target edits before policy,
   final addScope bypass, response/JWT scope equality, no refreshed ceiling
   growth, no offline grant from addScope, stored-consent bounds and strict
   default-role absence now/presence next issuance. Review fixes have regressions.
4. **Continuation:** GET/POST, expiry/replay/concurrent single consumer,
   wrong tenant/session/origin, sealed-envelope copies/tampering, held metadata,
   original request validation before execution and response-mode delivery are
   covered. Canonical/custom router tests and actual signed POST browser
   continuation pass. Five redirects/cumulative budget are tested.
5. **Pinned flows:** bindings read consistently; versions/secrets/roles and
   remaining tail are pinned across rebinding, redeploy and browser suspension.
   Shared SQL/plugin conformance covers atomic mutation/rollback/concurrency;
   runtime tests change versions and roles during a flow and verify snapshots.

CLI is pinned to 1.37.0, node-auth0 to 7.4.0 and Deploy CLI to 9.1.0. The
Actions browser cases exercise auth0-spa-js claims/roles, hosted deny,
persisted execution lookup, signed POST continuation and console workflow.
A real `require('auth0')` ManagementClient uses M2M secrets to assign a role.
The offline registry packages the installed lockfile-pinned auth0 closure
(including 7.4.0 and the 4.37.1 alias, uuid 11.1.1, jose 5.10.0/4.15.9 and
undici-types 6.29.0) into private static loopback tarballs without scripts or
network install. Unknown dependencies fail locally. Deploy comparison uses
Action names/code and ordered refs, with negative missing/dangling/code/secret
fixtures and actual post-import login claims.

Deploy limitations: **database connections excluded/not demonstrated**;
attackProtection tool-unavailable due phone-provider-protection APIs;
x-azure-clientip/empty-header imports retain pinned-tool rejection; ACUL
excluded. Upstream observer unavailable without credentials; no upstream
call made. These are not passing coverage.

During Task 10's early strict-null RED, a null dependency version reached the
default registry Queue path and returned a building draft. No HTTP trace was
captured, so the exact external request/status is unknown. This accidental
network deviation is retained, not described as an intended registry test.
All subsequent Task 10 engines/direct build managers were changed to loopback
fixtures (`NewOffline`); Task 12 uses the private offline closure.

## Deferred minors and limitations (exhaustive ledger carry)

These were deferred by scoped reviews or remain documentation/test-process
limits. They are not Critical/Important approval claims. Resolved carry items
are listed separately so an old note is not mistaken for an open defect.

| Origin | Remaining carry |
|---|---|
| Task 1 | Changelog read only through the first 100k characters (back to roughly May 2026), with Actions items from a summarizer; complete historical review not demonstrated. The asserted 202/204/200 recheck lacked fresh fetch evidence. Old observations byte-unit rationale is inconsistent and contains a leading-space link; D-0053/operator guide now state exact implemented units. |
| Task 2 | Addon escape probe accepts any thrown error, so ENOENT could satisfy it; strengthen to ERR_ACCESS_DENIED/ERR_DLOPEN_DISABLED. Busy-loop sibling error asserts non-nil rather than errors.Is(ErrUnavailable). ReapGrace remains a public test hook. D-0022 signalling denylist duplicated between runner scripts; add shared assertion/cross-reference. AsyncLocalStorage console capture can lose late callback logs. |
| Task 3 | CreateAction/UpdateAction do not independently validate DraftBuildID existence; ValidateBindings does not check generated empty/duplicate binding IDs. No separate actionsrules RED run was observed (process limitation). |
| Task 4 | Caller-transaction MySQL Deploy MAX(number)/DeleteAction COUNT reads were flagged for freshness, and deploy duplicate keys lack a specific store error mapping; Plan 26 READ COMMITTED mitigates stale views, but no dedicated general deploy/delete closure was recorded. optional.Scan may reject ints returned as []byte with interpolateParams. ConsumeContinue could assert DELETE rows affected; boolean-precedence readability and dedicated in-transaction deploy/bind / deploy-vs-bind races remain coverage follow-ups. List count/page can skew under concurrent writers. |
| Task 5 | Nil list-element ErrInvalid path lacks a dedicated test; truncated PutArtifact test overlaps wrong-size coverage; rollback test does not independently assert the deployed version is gone. |
| Task 6 | Install-size poll can overshoot considerably before cancellation; consider RLIMIT_FSIZE/disk quotas. npm's built-in npmrc is readable. Resolver workdir is created before semaphore acquisition, slot wait depends only on caller ctx, Ensure trusts an existing extracted root. These operational boundaries are documented. |
| Task 7 | A failed-flow record may be absent if its detached write fails (logged). Bindings/role-load failures before execution produce no stored reference. Metadata-tx lock-throughput concern has no dedicated benchmark; execution/continue tenant locks were removed and atomicity is tested. |
| Task 8 | /userinfo claim gap (Ruling 10). Concurrent uses of the same initially valid refresh token can both run Actions; loser receives no token but its metadata/execution may persist. Target edits on refresh are bounded by the family rather than the narrower request, and target-only offline_access removal can still rotate (documented choices). Integration hooks preceded tests; RED was proved by temporarily disabling hooks (32/33 assertions failed). Some fix-round tests were written alongside changes and mutation-checked rather than independently RED first; no stronger TDD claim is made. |
| Task 11 | Dry-run execution ID links to lookup despite no persisted record. Build polling stops after a transient failure without an in-editor retry control. |
| Task 12 | Single-Action Deploy fixture proves presence/reference migration, not runtime reordering of multiple bindings; comparator array-order assertions cover comparison only. |
| Final review | Custom-database runners (D-0022) share the unix-domain-socket gap closed for Actions; their runner script has no socket lockout yet (outside Plan 27). The post-Ensure deadline re-check has no dedicated regression test: Engine takes concrete build/runner types, so a delayed build lock cannot be injected without new seams. An older storage plugin that ignores the new `session_id` field still consumes a continue state for any session; the engine's session check then refuses it, as before. |
| Task 13 self-review | Inventory declares console_log_chars_per_action=256; runtime captures up to 100 messages of 2048 characters each plus level prefix, without that aggregate cap. Runtime behavior is documented; inventory/enforcement drift is deferred. |

Resolved carried items: Task 2 missing bundled npm now fails under
ZA_REQUIRE_NODE (Task 6); secret-masked stderr and reserved request-id rejection
landed in Task 7. Task 3 suite registration/artifact admission landed in Tasks
4–5; transport registry_url and plaintext secret-size validation in Task 10.
Task 4 per-login tenant locks removed in Task 7 and stale migration fixture
fixed in `b0a6b17`. Task 5 Actions plugin exclusions removed. Task 6 resolver
bound/recovery fixes landed in `fd9ba48`; Management recovery landed in Task
10. Task 7 redirect placeholder replaced in Task 9; metadata/execution writes
are atomic after `36f9a70`; credentials stripping and localized reason
sanitizing landed in Task 8. Task 8 empty-flow consent marker and no-bindings
extra loads were fixed; redirect availability became real in Task 9. Task
10 empty-list seed ownership is durable after `d8b0c01`, superseding all
older reports' heuristic. Task 11 failed-read ready gate fixed in `8d94517`.

## Final whole-branch review

An independent reviewer read `dbd8712..e1aaee9` (generated, console and E2E
files sampled), ran the in-memory Actions, runner, authz, mgmt, OAuth and seed
packages, and probed the sandbox on Node 22.23.4, 24.20.0 and 26.8.1. Verdict:
ready with fixes; no Critical issue. The five Review Focus outcomes held inside
the file sandbox. Findings and disposition:

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | Important | Node's permission model does not cover `connect()` to a unix-domain socket path (Node 22/24 have no network permission; `--allow-net` on 26 allows pipes), so Action code could reach peer-auth database or container-runtime sockets owned by the server's uid. Reproduced locally on Node 26.8.1. | Fixed: `runner.mjs` replaces `net.Socket.prototype.connect` (non-writable, non-configurable) and refuses path connections, which covers `net`, `tls` and `http` `socketPath`; TCP stays open. `TestEngineNoUnixSockets` failed before the fix and passes on Node 26.8.1 locally and on Node 22 and 24 (`node:22`, `node:24` containers). Operator guide and D-0053 updated. |
| 2 | Minor | A step whose deadline passed while `Builds.Ensure` waited on a build lock was still dispatched with a 1 ms budget, and the watchdog could kill the tenant's process. | Fixed: deadline/context re-checked after Ensure and secret opening; returns `ErrTimeout` without dispatch. No dedicated test (ledger). |
| 3 | Minor | A continue state was deleted before the session check, so another session holding the state could burn it. | Fixed: `ConsumeContinue` takes the session ID (store interface, memory, SQL `AND session_id=?`, gRPC `ActionsRequest.session_id=19`); another session's row is ErrNotFound and stays. Conformance and engine regression (`other session does not burn state`). |
| 4 | Minor | Credentials-exchange target edits were bounded by raw grant scopes, which can outlive scopes deleted from the API. | Fixed: target edits intersect the grant with the API's defined scopes. Regression subtest failed before the fix. |
| 5 | Minor | `event.transaction.id` was always empty. | Fixed: random 24-character ID per post-login flow, kept across redirects (D-0053). `TestActionsTransactionID`. |

The reviewer set aside, with reasons, outbound TCP/link-local egress (operator
egress per spec §2), same-tenant cross-Action interference (tenant process is
the boundary), test-endpoint dry runs sharing the live process, build/artifact
GC, the fixed in-flight limit of 64, old-plugin startup refusal (Ruling 14),
empty optional event fields and items already in the ledger above.

Post-fix verification on the fixed tree:

| Check | Result |
|---|---|
| `go generate ./...` twice | Stable (identical diff after both runs) |
| `make check-sources`, `go vet ./...` | Exit 0 |
| `ZA_REQUIRE_NODE=1 go test -race` on actions, actions/build, noderunner, oauth, authz, memory, grpcstore, mgmt, seed, pkg/... | All ok (grpcstore 398.7s, oauth 89.4s) |
| `./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/...` | ok, 597.6s (SQLite, PostgreSQL 17, MySQL 8.4) |
| `make e2e-actions` | Exit 0: node-auth0 fourteen operations and grants, five Playwright cases including redirect/continue, auth0-cli operations; no skips |
| Node 22/24 sandbox regression | `TestEngineNoUnixSockets` and `TestEngineFailClosed` pass in `node:22` and `node:24` containers |

Lanes not rerun after these fixes (unaffected code paths): `make console`,
`make e2e`, `e2e-rbac`, `e2e-deploy`, `e2e-social`, `e2e-email-accounts`,
`e2e-domains`, conformance; their Task 13 results above stand for `e1aaee9`.

No live Auth0, formal OIDF certification, deferred triggers/modules or
/userinfo claim parity is claimed.
