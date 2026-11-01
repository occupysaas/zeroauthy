# Plan 31 final review and decisions

Implementation and acceptance are complete on runtime `cc853d1`; later commits contain monitoring instructions, baseline test fixtures, and this final documentation. The broad Go race snapshot is `e7127d6`, with the selector delta separately covered by full affected Management API/logrules races. See [final validation](2026-11-01-plan-31-final-validation.md) for exact commands, identities, original failures, retries, skips and conformance outcomes.

## Review disposition

The whole-branch review covered `7d55c52..0b02735`. Its four production findings were fixed in `e7127d6`: process-wide captured Action masking/mute, OAuth ingress credentials, absent PII form payloads, and stream canonical metadata preservation. One scoped re-review approved all four, with no new Critical/Important findings. The remaining CLI acceptance gate was independently observed under the existing clean-room authorization, implemented in `cc853d1`, and approved by a separate focused review. Actual logs E2E, including filtered list/tail, then passed. No unresolved Critical/Important review findings remain.

## Deferred minors and costs

These are explicit follow-ups, not claims of implemented coverage:

- Resource-specific ID wording and a separate queue-limit inventory description remain documentation polish. Runtime enforces its existing ID and 10,000-event queue contracts; cost if deferred: confusing internal documentation.
- A credential overlapping the redaction marker can produce cosmetic extra brackets. Cost: presentation noise, no identified extra exposure.
- Direct-store pre-1970 ActiveUsers zero-bound parity differs in SQL/memory; the public API uses a recent window. Cost: unusual direct-store callers can differ.
- Ignored extreme timestamp fields in gRPC stream updates can be validated more strictly than native drivers. Cost: direct-store invalid-input parity.
- Concurrent secret replacement with omitted/marker PATCH deserves a dedicated test beyond existing CAS checks. Cost: narrower regression coverage.
- Partial JSONOBJECT acknowledgement replay deserves a dedicated test beyond existing delivery/restart coverage. Cost: narrower failure-path coverage.
- Existing vue-demi installation and Vite bundle-size advisories remain maintenance work. Cost: build noise and larger initial download.
- Exact per-boundary consent/redirect/device/failed-issuance event assertions can be expanded. Existing audit and broader acceptance remain distinct from exhaustive branch coverage; cost: less precise regression attribution.
- The old CLI checkpoint comment and color-environment warning were corrected in the acceptance work; they are no longer open.

Configured PII cannot be cleared through the form under the present strict API contract: the UI validates this visibly instead of silently retaining or submitting invalid settings. Clearing semantics remain unconfirmed. Cloud sinks and other local compatibility limits remain documented in the operating guide. Conformance warning/review/skipped modules and unavailable upstream Deploy lanes are not passing claims.

## Recorded rulings in chronological order

The following ledger entries are preserved verbatim, including intermediate decisions later superseded by explicit fixes or new evidence. Each stated cost belongs to that decision; surrounding status is historical.

| 3 / 6 | seq/ID assignment vs logs.FormatID | Ruling: storage cannot import logs (cycle); storage owns shared ID primitives, logs forwards — preserves one formatter; cost if wrong: helper relocation. |

| 4 / 6,7,12 | committed time and checkpoint settling | Ruling: a 2s settle delay alone cannot ensure no skips for arbitrarily late transactions; implementation must serialize sequence assignment with commit visibility or withhold through pending lower sequences — spec no-skips wins; cost if wrong: write throughput. |

| 14 | Console components/chart | Ruling: requested dataviz skill absent from catalog; use existing console chart conventions and visual QA — no unavailable skill can be loaded; cost if wrong: chart redesign. |

Task 1: Ruling: checkpoint query precedence follows public GET logs docs: from/take mode ignores q and other page parameters — spec says "as documented"; adjust Task 7 tests accordingly — cost if wrong: checkpoint client filtering differs.

Task 1: Ruling: startFrom uses documented RFC3339 date-time, resolved to a sequence checkpoint, replacing Task 11 log-ID interpretation — primary docs refine unspecified spec §6 — cost if wrong: clients sending log IDs get 400.

Task 1: Ruling: absent documented daily range default/max, use last 7 UTC calendar days including today, maximum 366 days — bounded query required; cost if wrong: date range requests may need explicit bounds.

Task 1: Ruling: canonical public event-code meanings replace provisional spec examples (sdu deletion, ublkdu unblock; scpn is phone change) — do not mislabel emitted events; retain spec-required fapi as explicit local compatibility behavior because absent from current catalog — cost if wrong: code consumers may need mapping changes.

Task 1: Ruling: preserve LogStream.StartFrom time.Time in memory/SQL/proto; create-only RFC3339 timestamp chooses checkpoint before first matching retained sequence, and worker filters out Date<StartFrom while advancing past skipped rows — event Date can differ from sequence order — cost if wrong: one field/column/proto member to remove.

Task 3: Ruling: introduce logsearch evaluator/validation early so memory and later SQL/API share AST policy without duplication — cost if wrong: ownership moves back in Task7.

Task 3: Ruling: UpdateLogStream merges admin fields, preserves runtime checkpoint/state, invalidates lease; paused/suspended→active atomically sets NextAt now, clears Failures/FailingSince/LastErrorClass, preserves checkpoint/StartFrom/LastSuccessAt — prevents stale delivery overwriting admin pause and makes resume immediate — cost if wrong: store-level resume policy adjustment.

Task 4: Ruling: shared rollback test must require monotonic, not contiguous, sequence IDs — SQL identity allocation legitimately has rollback gaps and contract says opaque/increasing — cost if wrong: clients assuming gapless IDs need correction. Rolled-back event absence/state rollback remains asserted.

Task 4: Ruling: new SQL Logs timestamps use fixed-width UTC text with nine fractional digits, empty sentinel for unset, rather than UnixNano BIGINT — preserves exact nanoseconds, Unix epoch and RFC3339 far-future dates without overflow — cost if wrong: schema/index storage overhead; Task7 SQL date arguments must use same encoding. Existing user last_login stays microseconds.

Task 4: Ruling: clamp tenant committed_at to max(now,last committed_at) while holding tenant write lock — instance clock skew must not settle higher sequences before lower ones — cost: one indexed bounded read per tenant append. Shared timestamp validation limits years0000–9999, matching RFC3339 and SQL text order.

Task 7: complete (76f6cb9..de1f267; review7 approved after acceptedJSON search projection fix; all3 SQL parity/migration race/focused/fuzz GREEN). Ruling:0029 searchable_body UTF8hex JSON projection preserves full valid Body bytes, costs roughly2x selected strings plus append extraction; bounded/resumable Go backfill. Reject malformed/nonobject nonempty body atomically; nil/empty accepted. Raw server logs route preserves checkpoint ignore precedence, int64 cursor domain400overflow local limitation.

Task 8: resumed after usage interruption, base de1f267, saved uncommitted auth emitter work. Ruling: packages without direct inventory emit points do not invent codes; privacy propagation still tested. Membership success emitted after outer commit (minimal authz/identity/federation boundaries). WithCredentials registers nonempty credentials including1–3runes while generic WithValues retains4rune minimum; detached masks preserve it. Focused progress log passed before interruption but final coverage/app wiring and full internal-short still owed.

Task 8: Ruling: input-derived dynamic key/value masks must not corrupt fixed log schema, generated Date/catalog Type, or provenance-proven generated execution links; actual dynamic Details always masked — cost: explicit trusted metadata boundary for future fields.

Task 8: Ruling: source attribution must use existing resolved objects/write results, not additional logging DB reads; optional DeniedKinds and OrganizationMembershipWriter/AddMembersResult with additive RPC fields preserve oldplugin auth; unknown attribution omitted — cost: older plugins need upgrade for detailed codes.

Task8 bounded followup ruling: choose process-wide capped masking union (256distinct values/64KiB,60s absolute retention), then permanently mute stderr+capturedconsole and physically clear masks until retirement, businessresponses unchanged. Crossrequest cached credential/config values require mute rather than eviction-and-log. Cost: diagnostics unavailable after cap/window on busyprocess, privacy/memory bounded. Fresh focused implementer task8_bounded; original work remains intact.

Task9 ruling: explicitly include frozen mgmt owning-handler targets users.update/delete/checkPassword, verificationemailjobrequest, orgmemberadded, unblock, customdomainverificationfailure plusapi_limit429 — middlewarebriefalone leaves emittedinventorygap, Task10 asyncjobsdoesnotown these — cost: broader handler/test surface withinTask9. Resourceevents and sapi both intentional, no duplicate samecode.

Task11 complete (d02c6b8..acb4d1f; review11approved aftercreate200fix, focused/race/build/provenanceGREEN). ExactGozerostartFrom400localruling; earlylogstream.SealSecrets/OpenSecrets helper boundAAD. SecretCAScoverageMinor finalreviewrevisit.

Task13 ruling: frozenD0057/inventory explicitlyzero-fill absentstatsdays (earlierscratchsparseinstructionwasincorrect, corrected). Spec7/Task13explicit dateRFC3339midnightUTC wins ambiguous inventory YYYY-MM-DD/dateformat; clarifyregenerateAPI. Missingrowcreated/updated timestampdaymidnight localdeterministic — cost: clarifygenerated date type.

Task14 inprogress; RED13newfail/527baselinepass then35monitoringtestsPASS/visual8routesdesktop390mobile/darkHome nooverflow/pageerrors. ScopeRuling: add safe read-only system logstream health endpoint+UI LastSuccess/error/failures requiredspec6/7, no publicsinksecretshapechange; cost focusedGo API/auth/schemafiles inconsoleTask. FilteredLive disabledwithexplanation; failureonly bounded1000window<=10requests/stalecheckeach. Tempfixturepreviewmustremoved beforecommit. Resumed afterusageinterruption.

Final review recovery report final-review.md confirms I1–I4 production defects; one final_fix agent dispatched complete list plus partial Go failures. I5 selector remains explicit unanswered maintainer decision; question re-presented after session reset. Ruling: preserve strict nonempty PII API and prevent clearing configured PII via UI with localized validation, omit config on absent/no-selection create/edit — cost: clearing remains unsupported until confirmed contract. Final make check-sources recovery: PASS exit0, final-check-sources-recovery.log, before fixwave complete (no source-link contract files modified at run).

Task16b new evidence: discovered existing OBS_AUTH0_* credentialNAMES (no valuesexposed), Plan14 documents maintainerprovided devtenant observer creds; CLEAN_ROOM explicit2026-10-16 observationauthorization alreadyapplies. Separate selector_observer made minimalreadrequests and wrote sanitized docs/compat/observations/2026-11-01-logs-search-selector.md: baseline,v3,filteredv3 allHTTP200. No tenantidentifiers/PII retained. Previoususerexceptionquestion no longerneeded because documentedpolicyconfirmation path fulfilled. I5 unblocked by NEW external evidence afterfinalfixwave; originalfinal_fix resumes outstandingTask16b acceptance ONLY. Ruling: extend completion to newlyconfirmed selector and one focusedreview ratherthan leave requiredacceptance blocked on now-satisfied policy — cost: small extra implementation/review beyond previouslyfrozenwave; no freshwholebranchreview/fixloop. FullGo compiled e7127d6 remains that snapshot, finalquerydelta must get affectedMgmtfullrace andactualE2E; eachstageidentity reportedhonestly.

Final broadGo race PASSexit0 e7127d6 (2026-11-01T05:05:56UTC). Actualmatrix30minFAILexit1 at05:36:06UTC timeout1800.108s TestConformance/sqlite/ActionsII/QueueCap, activeSQLiteEnqueueJob stack, noassertionfailure shown; no completedbackendresults inferredfromnonverboseoutput. Actuale2e-logs PASSexit0 at05:36:32UTC cc853d1 runtime, artifact/tmp/plan31-etIhjP includesCLI/browser/SDK/streams/stats/privacy. Otherstagescontinue. Ruling: script-racematrixsharespackage30min acrossall3backends whilewideSQLitealone~30min; afterremainingstages rerunONCE fullmatrix unchangedrace/count/coverage with120min timeout+JSON backendreporting — cost: potentiallylongerCIwalltime; originaltimeoutretained, nofalsePASS, noperformancechanges/assertionweakening.

## Final closure

The initial 30-minute SQL matrix timed out; its unchanged-coverage 120-minute retry passed all three backends. Four baseline browser fixtures were stale after the existing modal redesign; test-only correction `4b51288` retained resource identity, visible title and confirmation assertions, and the complete baseline rerun passed. An initial source-link retry failed transiently; the subsequent full check passed. No repeated broad Go run was added after its completed pass: the only later runtime delta had its own affected full-package race checks, and subsequent SQL/E2E/conformance used that runtime. This avoids duplicating long tests without new uncovered changes.

The 15-minute monitoring protocol is committed in AGENTS.md. No merge or push has been performed. Raw reports/logs are retained at `/tmp/zeroauthy-plan31-evidence-2026-11-01/`.
