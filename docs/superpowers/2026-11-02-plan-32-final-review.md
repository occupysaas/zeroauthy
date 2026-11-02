# Task 14 — Whole-branch review

**Verdict: must fix before merge.** Three Important defects were reproduced. No Critical finding. This is one review of `17d749c..e86157e413fe16ae9afd6b04ed9d73498d7051f8`, using the supplied unified review package, Plan 32, its binding design, the full progress ledger and its rulings, and the committed final-validation report. The branch and production files were not changed; the only workspace write is this report. No subagents or broad suites were started.

## Strengths and coverage

The business transaction owns the outbox append, including nested rollback and tenant-deletion buffer restoration. SQL holds the tenant lock through append commit, rather than relying on the two-second settle interval to solve late commits. The worker checks ownership/version before sending and again while recording, uses a bounded event per lease, and persists fair lease ordering. Retention and delivery counters share the mutation lock. Webhooks use checked IP addresses at dial time, reject redirects, and retain only bounded diagnostic classes. Action deliveries use sealed durable jobs and isolated Node processes that are killed and reaped, preserving unrelated executions. These are substantive protections, with focused regressions in the branch.

Review passes covered the builder and recursive projection, mutation/cascade capture, memory transactions and ring, SQL ordering/migration/retention/leases, gRPC codecs and capability negotiation, all new Management handlers and router scopes, SSE transport and middleware, webhook/Action delivery, Action queue cancellation and Node lifecycle, context propagation, console workflows, seed/Deploy integration, and Task 14 acceptance fixtures. Existing tests were inspected around the five required scenarios and integration boundaries; the completed matrix is execution evidence, not a substitute for reading runtime code.

Generated material was reviewed structurally rather than by dumping the minified bundle or repeated catalog schemas: 25 inventory types match 25 schemas and examples, 16 types are emitted, 11 operations and three destinations are present, all added RPCs have generated bindings, and no old RPC name was removed. Semantic YAML comparison found eight added paths, no changed existing path, and only `ActionTrigger` changed among existing schemas. Generated-file provenance and the committed HTML's asset reference were checked. The final console build already regenerated types/dist without tracked changes. `git diff --check 17d749c..e86157e` passed. The initial PyYAML inspection rejected reusable anchors; the read-only comparison was completed with a loader honoring anchor redefinition, without changing YAML or treating this inspection-tool limitation as a product failure.

## Issues

### Critical

None found.

### Important

**I1. A server-issued cursor from a fresh empty tenant can immediately become “expired.”**

- Files: [events_sse.go:109](/mnt/nvme2/code/zeroauthy-plan32/internal/mgmt/events_sse.go:109), [events_sse.go:128](/mnt/nvme2/code/zeroauthy-plan32/internal/mgmt/events_sse.go:128), [events_sse.go:256](/mnt/nvme2/code/zeroauthy-plan32/internal/mgmt/events_sse.go:256).
- Reproduction: another tenant consumes sequences 1 and 2; connect to a fresh empty tenant and receive the normal 30-second `offset-only` frame with `id: MA` (sequence 0); disconnect; the fresh tenant commits its first event at sequence 3; resume using that exact `Last-Event-ID`. The handler rejects it as `cursor_expired`. No event was purged, evicted, or aged out. The overlay first consumes the actual emitted frame, then calls the same initial-snapshot path used on resume.
- Cause: `bootstrap` exists only in one connection's memory. Parsing an issued offset loses it, while `seq < oldest-1` incorrectly interprets globally allocated sequence gaps as missing tenant history.
- Effect: a normal reconnect before the tenant's first mutation cannot receive that mutation. Reconnecting without the cursor starts at latest and can then skip it. This is separate from the recorded limitation about delayed expiry after an entirely purged ring.
- Fix: preserve enough tenant-local cursor/history state to distinguish a valid empty start from actual expired history. A durable purge/high-watermark contract or an equivalent correct cursor/sequence design is needed; simply disabling the expiry check or accepting every zero cursor would break genuine 410 behavior. Cover both fresh-empty resume with cross-tenant gaps and real expiry on memory/SQL/plugin consumers as appropriate.
- Evidence: `TestReviewPlan32FreshEmptyCursorResume` fails immediately on the unchanged review HEAD in the temporary overlay below.

**I2. Slow synchronous test deliveries lose their response at the application's write deadline.**

- Files: [event_deliveries.go:234](/mnt/nvme2/code/zeroauthy-plan32/internal/mgmt/event_deliveries.go:234), [worker.go:43](/mnt/nvme2/code/zeroauthy-plan32/internal/eventstream/worker.go:43), [app.go:487](/mnt/nvme2/code/zeroauthy-plan32/internal/app/app.go:487).
- The test endpoint waits for four attempts, each permitted ten seconds, plus 1/2/4-second delays, before writing the 202 body. The production HTTP server retains its 30-second write timeout on this route. Only SSE adjusts that deadline.
- Reproduction: the real delivery worker and Management logging middleware ran behind a local `net/http` server with the application's 30-second write timeout. All four transport attempts timed out, the handler tried to return 202 after 47.1 seconds, and the client received EOF with no result.
- Effect: the console/SDK cannot inspect timeout attempts precisely when the operator is testing a hanging receiver or Action. Test outcomes are intentionally not stored, so the result cannot be recovered from failed deliveries.
- Fix: give this synchronous endpoint a finite request/write budget accommodating the full 47-second retry schedule plus bounded processing/response overhead, with client cancellation still propagated. Preserve ordinary Management response capture and other routes' timeouts. Add an actual HTTP transport regression, including cancellation/bounded completion; a recorder-only assertion cannot catch this.
- Evidence: `TestReviewPlan32SlowTestResponseWithinServerTimeout` fails after 47.10 seconds in the overlay, after four actual ten-second timeout attempts.

**I3. Seed provisioning ignores the configured stream quota, including when this prevents startup.**

- Files: [event_streams.go:133](/mnt/nvme2/code/zeroauthy-plan32/internal/seed/event_streams.go:133), [app.go:190](/mnt/nvme2/code/zeroauthy-plan32/internal/app/app.go:190), [app.go:224](/mnt/nvme2/code/zeroauthy-plan32/internal/app/app.go:224).
- Seed compares counts with the frozen default `eventrules.Limits.MaxStreams` (10). The app passes `cfg.Events.MaxStreams` into its capture wrapper and Management handlers, but no configured quota reaches the seed check.
- Reproduction: using the same wrapped-store/`ApplyWithActions` path as startup, `MaxStreams: 2` allows a three-stream seed; `MaxStreams: 20` rejects an eleven-stream seed with `store: conflict`.
- Effect: operators cannot provision the valid larger quota they configured, and app construction returns the seed error instead of starting. Lower quotas are inconsistently bypassed by provisioning.
- Fix: pass the effective deployment limit into the seed path and use the same defaulting/quota rules as the Management API. Preserve create-only behavior when existing streams already meet or exceed a subsequently lowered limit. Cover both nondefault directions and existing-resource reapplication.
- Evidence: both subcases of `TestReviewPlan32SeedUsesConfiguredStreamLimit` fail in a separate temporary memory-only overlay.

### Minor

The previously deferred issues remain nonblocking at their actual effect. One additional deployment-documentation mismatch is included.

| ID | File/line | Effect and recommendation |
| --- | --- | --- |
| M1 | `api/management.yaml:10357` | `aws_partner_event_source` still lacks `readOnly`; runtime correctly forbids writing it. Add the annotation and regenerate when polishing the public schema. |
| M2 (new) | `internal/mgmt/events_sse.go:136`; `docs/event-streams.md:139` | Connection counts live in each `Handlers` instance, while docs say four per tenant without an instance qualifier. Multiple app instances allow multiples of four. Per-instance resource protection remains effective, so this is not a security bypass finding; document the actual scope or explicitly choose and implement a cluster-wide quota. |
| M3 | `internal/eventstream/action.go:31`, `:34`, `:38` | Capability-probe/enqueue failures discard a context deadline and can report generic `action_error` during the cleanup reserve. Delivery remains bounded/retried, but diagnosis is misleading. Preserve timeout classification. |
| M4 | `internal/store/store.go:39`; `internal/store/events.go:17`; `internal/events/build_test.go:8` | Formatting and test import grouping remain inconsistent. Maintenance polish only. |
| M5 | `internal/store/sqlstore/migrate.go:214`; `internal/store/sqlstore/events_test.go:31` | MySQL 0031 uses the existing resumable-DDL path and upgrade/schema equivalence was tested; there is still no explicit interrupted-0031 resume test. Add that focused regression when improving migration fault coverage. No failure was observed. |
| M6 | `console/src/pages/event-streams/StreamEdit.vue:18`, `:31` | Setting the Action destination and applying an Action stream can both start the initial lookup. Sequence guards prevent stale rendering; remove the duplicate request to reduce avoidable traffic. |
| M7 | `console/src/router.ts:1`; `console/dist/index.html:1` | Static page imports contribute to the reported single-bundle advisory (981.86 kB / 258.57 kB gzip). Consider route splitting when optimizing console startup; build and behavior passed. |
| M8 | `internal/mgmt/event_streams_test.go:82`; `internal/eventstream/worker_test.go:439`; `internal/eventstream/action_test.go:1` | Passing fixtures emit routine INFO, expected ERROR/WARN and TLS diagnostics. They make real failures harder to spot but did not establish a credential leak. Capture expected output in fixtures when convenient. |
| M9 | `tests/e2e/m20-deploy-cli.mjs:196` | Dense credential lifecycle code makes future fixture changes harder to review. Expand the code without changing its strict comparisons or credential reinjection assertions. |

## Required review focus

1. **Rollback after a user write:** the capture transaction appends only after its callback succeeds (`internal/events/decorator.go:77`), and append failure rolls back the business write. `TestDecoratorRollbackAfterUserUpdate` (`decorator_test.go:175`) models the write followed by uniqueness conflict; nested rollback/panic and outbox-failure tests cover the buffer paths. SQL business-transaction tests and remote rollback tests cover the backends. The worker and SSE read that outbox, with no independent mutation-time send. No rollback leak found. This is composed code/test evidence, not a claim that I reran a new full API→SSE rollback journey.
2. **Two instances, commit order, resume/checkpoint:** SQL append serialization, monotonic committed timestamps, settled reads, worker checkpoint fencing and SSE unfiltered snapshots address the late-commit skip problem. `TestEventsConcurrentWritersSettled` (`sqlstore/events_test.go:113`) deliberately holds the first transaction beyond the settle window; the second cannot commit ahead. SSE concurrent-writer/resume and worker restart/lease tests pin their consumers. No duplicate-in-one-connection or delayed-commit skip found in that path. **I1 remains a separate, reproduced resume gap.**
3. **SSRF/rebinding:** `webhookClient` disables proxy/custom TLS dialer bypasses and redirects; `GuardedDialer` rejects the entire DNS answer set if any address is blocked and dials checked IP literals. `TestBlockedAddresses` (`worker_test.go:413`) covers loopback/link-local/private destinations and asserts zero listener requests; `TestBlockedAddressesDNSRebinding` (`:695`) covers repeated DNS answers. No default-policy bypass found. Explicit private-network opt-in is intentional; insecure HTTP alone does not disable the address guard.
4. **Provider refresh token/imported hash/customer metadata:** `resourceview.User` omits identity credential fields and recursive projection removes token/hash/profile fields from object and prior object while retaining customer metadata. `TestBuildUserExcludesSecrets` (`build_test.go:53`) explicitly retains `app_metadata.password` and excludes password/imported hashes and access/refresh tokens. Acceptance uses protected-source positive controls and audits event tables, delivery artifacts, receiver bodies, console responses and logs. No leak found. The browser acceptance uses a real Argon2 source hash and seeded sealed provider-token fixture; literal imported-hash/refresh-token projection is covered by builder tests, not a claimed live upstream exchange.
5. **Hanging/500 receiver during 1,000 signups, retry/disable:** mutation capture never invokes delivery. Retry tests pin four attempts and 1/2/4-second intervals, early 4xx stop and diagnostic classes. `TestSlowReceiverDoesNotBlockSignups` (`worker_test.go:524`) compares captured writes with/without the blocked receiver; the retry-safe fixture repair preserves those assertions. The consecutive/total failure tests cover 500/5,000 thresholds and counters. No originating-request dependency on the receiver found. **The original relative 10% capture-overhead target is not met**, and **I2 prevents observing a slow synchronous test's result over HTTP**.

## Rulings and limitations assessed

- The SQL commit lock, monotonic lease ordering, bounded one-event lease work, real Node kill/reap, purge counter correction, old-plugin fail-closed behavior, cascade capture and tenant-buffer restoration are justified correctness changes; their costs are contention, extra repository work and process startup. A single delivery worker can spend up to roughly 47 seconds on one failing event before another stream progresses. Fair scheduling prevents starvation, but it does not imply a throughput or low-latency delivery SLO.
- The low-level memory baseline makes the relative latency miss large (about 0.5 ms/captured create versus raw microsecond writes at the recorded small fixture size). The recorded absolute guard and receiver-isolation test are useful but do not establish a 10% claim or production-scale performance. Given the explicit controller ruling and the development memory-store scope, I do not elevate this recorded miss to a new merge blocker; retain it in completion reporting.
- Dormant organization-role rows remain outside the enumerable active-edge contract. Membership/user/organization events can tell consumers to reconcile/remove related state; exact dormant assignment replication is not guaranteed. This is a real synchronization limitation, accepted narrowly under the recorded ruling, not evidence that Auth0 does the same. Consumers requiring that replica must reconcile membership changes.
- An entirely purged ring lacks an expiry watermark, so 410 may be delayed. The disclosed limitation was evaluated as reduced cursor-expiry precision, not a demonstrated credential leak. It does not justify I1's false expiry of a newly issued cursor with no purged history.
- Empty client metadata follows the existing D-0039 storage limitation; empty geo has no invented data. EventBridge remains visibly disabled/stored-only, groups remain deferred, and `total_failures` is a documented read-only local extension. The runtime does enforce these boundaries. They are not upstream parity evidence.
- Full prior objects on real updates, independent synthetic test-envelope validation, full 1/2/4-second inter-attempt delays, safe URL queries, disabled-stream redelivery and exact pinned Deploy placeholder handling are coherent with the chosen contracts. No new defect was found in those decisions.

## Validation evidence and new focused checks

The committed [final validation report](/mnt/nvme2/code/zeroauthy-plan32/docs/superpowers/2026-11-01-plan-32-final-validation.md) preserves all twelve required command results and their exact logs. Its tested source is `82b00df`; `e86157e` changes only that documentation afterward. The original full Go run failed with the test-fixture double-close panic; `82b00df` fixes only that fixture and its record. The authorized retry exited 0, with **82 cached packages** and only the changed package newly executed. Do not describe all final Go outcomes as fresh runs.

The recorded SQL matrix freshly passed 2,806 leaves across all three drivers with zero skips. Console passed 604 tests. All required E2E commands, including all four final Deploy cells, exited 0; baseline browser lane skips remain recorded as skips. Conformance reports 82 module outcomes: **46 PASS, 12 WARNING, 16 REVIEW, 8 SKIP, 0 FAIL**. A zero runner exit does not convert the latter categories into passes. I did not rerun any reported full suite or inspect active suite logs; all validation was already complete.

Only the three concrete unanswered hypotheses above caused new tests. These used Go overlays in `/tmp/plan32-final-review-3iav0ckp`, leaving repository tests and production source unchanged:

| Command (`GOTOOLCHAIN=go1.26.7`) | UTC start–end, 2026-11-02 | Actual outcome |
| --- | --- | --- |
| `go test -overlay=/tmp/plan32-final-review-3iav0ckp/overlay.json -count=1 -timeout=90s -run '^TestReviewPlan32' -v ./internal/mgmt` | 02:25:26.815–02:26:17.209 | exit **1**; two failing leaf tests, zero skips; I1 and I2 reproduced |
| `go test -overlay=/tmp/plan32-final-review-3iav0ckp/seed-overlay.json -count=1 -timeout=30s -run '^TestReviewPlan32Seed' -v ./internal/seed` | 02:28:44.003–02:28:45.097 | exit **1**; two failing leaf subcases, zero skips; I3 reproduced |

Exact overlay sources, commands, times, statuses and outputs are retained in `overlay.json`, `events_sse_test.go`, `event_deliveries_test.go`, `result.json`, `focused.log`, `seed-overlay.json`, `seed_event_streams_test.go`, `seed-result.json` and `seed-focused.log` in that directory. The Python harness itself completed successfully; the Go child statuses are the actual failing statuses above. Both sessions ended. No database-backed review tests or production mutations occurred.

## Declined to judge

These are the behaviors whose external/future implementation was considered and set aside, with the reason; their existing local boundaries were still assessed above.

- Exact upstream E1 webhook headers/timeout: no separate observer evidence; the supplied specification explicitly permits local defaults.
- Exact upstream E2 update triggers/previous-object shape: same evidence gap; local capture semantics were reviewed.
- Exact upstream E3 delivery identifiers/lifecycle: same evidence gap; local failed-only records and redelivery semantics were reviewed.
- Exact upstream E4 test endpoint/default data/disabled behavior: same evidence gap; local synchronous contract was reviewed and I2 is not excused by it.
- Exact upstream E5 disable ambiguity: same evidence gap; local 500/5,000 thresholds were reviewed.
- Exact upstream E6 quotas/name/PATCH behavior: same evidence gap; configured local quotas were reviewed and I3 is not excused by it.
- Exact upstream E7 cadence/cursor expiry/connection limits: same evidence gap; local guarantees were reviewed and I1/M2 are not excused by it.
- Exact upstream E8 AWS partner-source value and real AWS partner-source delivery: observer evidence absent and actual EventBridge delivery is expressly excluded; the disabled placeholder behavior was checked.
- Future `group.*`/`organization.group.*` capture: the underlying group feature is expressly deferred to Plan 38; subscription/test schemas do not claim real group mutations occur now.
- GeoIP enrichment and persisted client metadata beyond D-0039: neither data source exists in the approved scope; empty output was checked rather than fabricated.
- A new production-load/cluster benchmark or hard real-time process-kill guarantee: no such acceptance environment or SLO is supplied, and the task prohibits filling review with new broad runs. The observed memory overhead, bounded single-worker delays, process admission limits and kill/reap costs were assessed rather than labelled passing performance requirements.
- New live Auth0/provider OAuth observations: this was a read-only implementation review, not the separate clean-room observer session. Existing local acceptance is accurately qualified.

No other runtime concern considered was dismissed merely because the specification was silent. In particular the three Important integration defects were pursued beyond the supplied per-task review conclusions.

## Assessment

**Ready to merge: No, with three focused fixes required.** The core outbox, delivery security and backend work are strong and the recorded matrix is substantial, but valid SSE resumes, slow test responses and configured seed quotas have reproducible user-visible failures. Address I1–I3 in one fix wave, retain genuine expiry/cancellation/quota invariants, and run scoped regressions before the controller adjudicates remaining minors and completion. No merge or final approval is granted by this report.


---

# Task 14 — Scoped final fix re-review

**Verdict: I1, I2 and I3 ADDRESSED. No new Critical or Important finding in the fix diff.**

Reviewed `e86157e413fe16ae9afd6b04ed9d73498d7051f8..474cf753f46d1e620020ba26fac160e93aa516d8` in `/mnt/nvme2/code/zeroauthy-plan32`, against the original final review, consolidated fix report, Plan 32/design and the controller's binding rulings. This is the one replacement scoped re-review, not a second whole-branch review. No subagents, test reruns, builds or production mutations. The only write is this report.

## Strengths and finding disposition

- **I1 — ADDRESSED.** `internal/mgmt/events_sse.go:105` reads tenant-local removal history in the existing transaction/tenant-lock snapshot; line 128 expires explicit offsets below that floor rather than inferring missing history from global sequence gaps. Default initialization uses the greater of latest retained sequence and floor. Memory eviction/purge preserve the maximum removed sequence and transaction snapshots clone it (`internal/store/memory/events.go:68`, `:185`). SQL records the floor only after an actual deletion, inside the same locked transaction (`internal/store/sqlstore/events.go:171`, `:239`); both tenant cleanup paths remove it. Migration 0032 exists in all three dialects and includes MySQL resumable-DDL handling. The additive gRPC operation uses the existing transaction/error mapping; an absent RPC fails SSE closed. Generated descriptor review found only the new method and its input/output mappings plus required index shifts; no existing method mapping was removed. Permanent regressions cover the actual issued empty offset, cross-tenant gaps, genuine expiry and boundary offsets, empty retention, ring rollback, common-store purge rollback/isolation/max/no-op semantics, SQL upgrade/reopen and absent-RPC SSE 501.
- **I2 — ADDRESSED.** `internal/mgmt/event_deliveries.go:153` establishes a finite 60-second derived context and matching response deadline, honoring earlier parent deadlines. The ordinary Management writer exposes its existing `Unwrap`; response capture stays in the path. The cancellation callback at line 166 interrupts blocked writes and is stopped/joined before releasing the writer. The regression uses the real delivery worker behind an actual HTTP server with the application's 30-second write timeout, including all four ten-second attempts. Additional tests exercise real HTTP cancellation and blocked socket writes under cancellation/inherited deadlines. The supplied final focused run reports the four-attempt 202 response at 47.13 seconds, rather than the reproduced EOF.
- **I3 — ADDRESSED.** Compatible variadic seed options reach both ordinary and post-Action provisioning. `internal/seed/event_streams.go:133` uses the configured positive limit with default 10; existing-resource detection still precedes quota enforcement and secret environment resolution. Actual startup (`internal/app/app.go:224`) and CLI (`cmd/zeroauthy/seed.go:70`) pass deployment configuration. Regressions cover low/high/default quotas, existing streams after quota reduction, absent secret environment variables on reapply, and both real entry points.

## Issues

**Critical:** None found in this fix range.

**Important:** None found in this fix range.

**Minor:** No new minor fix requested. M1–M9 remain explicitly deferred by the controller; this review does not reopen them.

## Residual effects for controller adjudication

1. **Pre-0032 history remains unknown.** Upgrade cannot reconstruct past tenant removals from global sequence gaps. Such old offsets may be accepted until a subsequently recorded removal proves expiry. The migration and operator documentation accurately disclose this; no invented floor is introduced.
2. **Timestamp replay accepts existing gaps.** It scans retained history from oldest retained minus one, including rows below the accepted initial removal floor. Only a newly advancing floor can establish a new expiry against that baseline; this is replay of available retained history, not proof of complete history below the accepted floor. Lower offset-only frames are suppressed, but a delivered row below a known higher removed sequence can legitimately receive 410 on offset resume. Timestamp replay is the documented fallback. This implements the controller's explicit ruling.
3. **Plugin compatibility is explicit.** An Events-v1 plugin without the additive floor RPC cannot serve SSE and receives 501; it does not silently claim correct expiry. Prior non-Events operations remain usable.
4. **The synchronous test route can occupy resources for up to its 60-second budget.** Normal cancellation propagates and blocked response writes are interrupted. This finite increase is needed for the existing 47-second retry schedule and does not change other routes' configured timeout.

No residual above is a new Important defect under the binding rulings.

## Evidence and limits

I inspected the production/test/documentation fix diff, relevant surrounding transaction/transport/provisioning code, and generated RPC changes structurally. `git diff --check e86157e..474cf753f46d1e620020ba26fac160e93aa516d8` exited 0. The checkout was clean before writing this report.

The fix report supplies final focused GREEN evidence: 72 SQL leaves across three drivers, 69 memory/gRPC leaves, 165 SSE race executions, four HTTP leaves including the actual 47.13-second case, 29 provisioning plus three startup/config leaves, 604 console tests, generation and affected-package compilation. These are the implementer's recorded results, not reviewer reruns. Intermediate RED/failures remain identified in that report.

The fresh full post-fix matrix is **pending** the designated sole validator. Earlier full-matrix results belong to earlier snapshots and are not evidence of a full matrix on `474cf753f46d1e620020ba26fac160e93aa516d8`.

## Declined to judge

- Unchanged whole-branch behavior and the previously enumerated M1–M9: expressly excluded from this scoped fix review by the controller. Their original disposition remains intact.
- New external Auth0 compatibility observations: outside this local fix review and the implementer's clean-room role; none is needed to establish the three local corrections.

No newly changed runtime behavior was set aside merely because the specification was silent.

## Assessment

**Ready to advance to final validation: Yes.** All three accepted Important findings are addressed, with appropriate permanent regression coverage and no new Critical/Important defect found in the fix diff. Final completion/merge judgment remains with the controller after residual adjudication and the fresh fixed-commit validation matrix; this report does not claim that matrix passed.


Controller completion: all three Important findings are resolved and the fresh twelve-command matrix on `474cf753` exited 0. M1–M9 remain deferred; no Critical or Important finding remains open. The post-fix validation report records actual skips and mixed conformance module outcomes.
