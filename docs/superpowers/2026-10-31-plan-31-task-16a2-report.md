# Task 16a2 — six emitter gaps

Status: DONE_WITH_CONCERNS for the scoped six-gap repair. Task16 is **incomplete**.
Base: c6284b8; managed branch plan-31-logs-streams-stats. Go1.26.7 only,
no new dependencies, no subagents. No store/SQL/protobuf/schema/generated
changes; no full gRPC/SQL or browser/CLI acceptance run.

## Implemented boundaries

- Authorize observes only the actual parsed/PAR-resolved, validated silent
  request. It emits fsa once on returned refusal; issuance marks completed
  before the existing ssa. Actual active session and resolved connection add
  attribution; browser login_hint/organization_name never identify a user/org.
  Cookie/invitation/credential masks precede policy and outcome recording.
- Shared endSession emits slo only after Sessions.End succeeds, using its
  returned session. Valid idempotent no-session completion also emits slo.
  Actual End failure emits flo; RP Lookup failure after URL/client validation
  emits flo. Pending confirmation and invalid targets emit neither. RP's
  already-resolved session supplies attribution on end-write failure.
  Cookies, ID-token/logout hints and CSRF values register masks before events.
- Email Service.deliver observes actual dispatch shared by Send/SendMessage.
  Transport/configuration/enqueue failure emits one fn; no duplicate Send
  wrapper. Disabled templates, verification and synthetic sends, successful
  dispatch and successful custom enqueue emit no fn. App/server inject the
  optional recorder for background reset/notification flows; context/Nop is
  the default. Opened native provider credentials register recursively,
  including short/nested values; events omit recipient/content/raw errors.
- ResolveOrganization emits organization_access_denied only for actual
  resolved third-party block or member-client ErrNotMember. Missing/foreign,
  usage denial, lookup/backend/unavailable failure do not invent policy denial.
  A vanished org stays invalid_request; actual backend/unavailable is
  server_error. No reads added for logging or speculative dedup state.
- Engine.run emits actions_execution_failed at the synchronous failure
  boundary, after execution/metadata commit handling, with its generated
  execution link and safe projection of engine-built canonical metadata.
  Actual deny/validation/success does not emit it; prestart creates no link.
  Existing durable jobID suppresses run-level events for async attempts;
  successful terminal FinishJob remains their sole event. Opened Action and
  Module masks are copied back to the bounded run before recording. The
  final warning uses context and a fixed failure class instead of raw errors.

## Exact outcomes and local rulings

Silent no-session/login_required, consent_required, interaction_required,
disabled/invalid session and issuance failure each emit fsa. Successful silent
auth emits only ssa; ordinary form login emits no fsa. Silent explicit Action
deny emits f,fsa. Silent throw emits actions_execution_failed,f,fsa. A silent
redirect command fails in the engine and authz translates that failure to
interaction_required: actions_execution_failed,fsa, with no ordinary f.
Hosted throw emits actions_execution_failed,f. Pre-registration throw emits
actions_execution_failed,fs. These Action and flow outcomes are distinct;
existing exact tests now assert both plus the same real execution ID.

Rulings/costs: no-session logout counts the completed idempotent local
operation (cost: request retries count multiple successful operations).
fn covers actual dispatch, not earlier template lookup/render preparation
(cost: those failures are not counted as fn). Async sealed custom-email jobs
retain their Action terminal failure; fn/user/message-type metadata is not
guessed from an envelope after FinishJob (cost: no extra fn for that case).
Early malformed/unresolved authorization and organization policy failure
inside request validation are outside the post-validation fsa observer;
the latter owns organization_access_denied and PAR additionally owns fpar.
Source outcome recording never introduces a logging-only DB lookup.

## TDD and verification evidence

All commands use GOTOOLCHAIN=go1.26.7. Logs are in
.superpowers/sdd/2026-10-30-zeroauthy-plan-31-logs-streams-stats/.

- TestLogoutOutcomeEvents RED: six valid completion/failure cases had no
  slo/flo. GREEN2.133s. Expanded matrix includes actual Delete failure,
  confirmation/no-session/invalid/pending negatives. Credential collision
  TestLogoutRequestCredentialMasks RED exposed raw cookie and short logout
  hint in client_name; subsequent logout mask matrix GREEN2.751s.
- TestNotificationFailureEvents RED: four actual stored/legacy × fallback/
  native transport failures had no fn. GREEN0.025s. Initial custom fixture
  supplied nonexistent user/client/org IDs, causing actual enqueue failure;
  corrected to a valid envelope to test enqueue-success suppression.
  Native credential collision plus context mask race GREEN1.227s.
- TestSynchronousActionFailureEvents RED: post-login throw/timeout and
  pre-registration throw had no event. GREEN0.819s. Expanded metadata commit/
  record-failure and deny/validation/success cases pass. Short credential
  collision with schema/date/execution links race GREEN2.590s.
- TestOrganizationAccessDeniedEvents RED: two actual policy refusals lacked
  events; unavailable incorrectly returned access_denied. Fixture capability
  implements both required methods; deterministic org ID avoids random mask
  collisions in unmasked-ID assertions. Combined authz GREEN0.849s.
- TestSilentAuthorizationOutcomeEvents RED: nine missing fsa outcomes,
  including login/consent/interaction, redirect/deny/throw and PAR. Combined
  authz GREEN0.849s; issuance failure added. Cookie collision RED then
  full silent matrix GREEN0.713s.
- Mounted TestHostedLoginOutcomeEvents, TestEndToEndRefreshAndLogout and
  TestMountedNotificationFailureEvent GREEN1.561s. Reset request deliberately
  returns200 after accepting background dispatch; the actual later failure
  emits fn while the accepted reset initiation emits scpr. Test waits for the
  real emitted event, not an arbitrary sleep. Mounted authorize/PAR policy
  denial matrix GREEN0.372s (PAR uses the configured client_secret_post).
- First seven-package race: authz25.017s/email5.892s/oidc32.124s/app20.480s PASS;
  login74.533s FAILED at TestActionExecutionLinksOnSignupEvents/throw and
  TestActionThrowLogged because their old exact counts excluded the new
  Action failure. actions FAILED at TestTriggerAPIs/post-login: direct step
  and synthetic Engine.Test did not initialize run.logCtx, so CopyMasks had
  a nil destination; server102.016s FAILED at
  TestActionsManagementResponseSchemas due the same dry-run panic/500.
  Fixed mask destination initialization from the real step context and
  updated exact Action+flow assertions. The synthetic path still emits no
  runtime failure event. No first-run failure is labeled passing.
- Focused race rerun for all failed names/new sync and mounted matrix:
  actions3.420s/login2.610s/server5.975s PASS. Explicit prestart/no-execution
  negative and strengthened signup links race PASS1.222s/2.174s.
- Final full race rerun `go test -race ./internal/authz ./internal/oidc ./internal/actions ./internal/login ./internal/server -count=1`: PASS authz25.497s/oidc34.262s/actions167.006s/login79.897s/server115.036s. All actual source emitter packages and mounted/dry-run failures are green. Email/app passed the initial complete package race; the later strengthened email credential fixture also passed focused race.
- git diff --check PASS. Source self-review inspected every production hunk,
  all new test fixtures, changed exact assertions and recorder wiring. Static
  audit matches all60 emitted inventory types to60 concrete source→event-test
  rows;54 named test functions and all explicit paths exist. This static
  result is not an all-tests runtime claim.

## Audit and remaining work

The durable full inventory audit is
[2026-10-31-plan-31-task-16a2-audit.md](2026-10-31-plan-31-task-16a2-audit.md).
It replaces six absent/partial mappings with real outcome/test evidence,
retains unchanged source/test evidence for the other54 rows, and separates
actual reruns from historical/static evidence. The two Task16a login/import
repairs are retained. All carry-forward minors remain: ID docs, explicit
queue default, cosmetic marker overlap, ActiveUsers zero bound parity,
gRPC ignored runtime-field validation, bounded customdb diagnostics docs,
and latest migration/upgrade acceptance audit.

Task16b browser/CLI/console/E2E fixtures, docs, broad final regression and
whole-branch review remain. Dedicated event coverage for every unchanged
inventory trigger and every consent/device/redirect continuation is not
claimed. No further implementation gap is silently waived by this stage.

Commit: focused repair, audit and durable report commit; exact SHA in the
scratch report/controller handoff after creation.

## Review correction after 93ec9d2

Two Important review findings reproduced as real persisted event failures:
(1) a valid first Action/Module credential followed by a corrupt second envelope
left the first value visible in actions_execution_failed client_name;
(2) keeping masks only in private flow.logCtx left the caller's f/fsa metadata
unmasked after synchronous Actions. Prior package passes did not cover these
collisions; they are corrected in this follow-up, not waived.

Engine.step now registers every successfully opened Action/Module value
immediately before another open or possible error. It keeps existing private
immutable masks and explicitly adds the opened value to the existing request
execution trace. The trace stores cloned strings, at most256 distinct values
and64KiB, under its mutex. RecordEvent clones a mask snapshot into its recorder
context before enrichment and recording, so an older outer request context
sees credentials already opened by the Action. Generic logscrub.WithValues /
WithCredentials retain their immutable contracts. No process-global history,
DB reads, goroutines or request-context retention in async queue payloads.

Overflow makes the request trace permanently unsafe, releases collector
values and drops subsequent RecordEvent calls; wrapping the same request with
WithRecorder cannot reset this. This is intentional privacy-first loss of
logs/stat increments, without failing business requests. It does not increment
the AsyncRecorder queue-drop counter. No synchronous/raw-credential warning is
introduced. Snapshot tests pin earlier events independently from later masks;
the async recorder still keeps only its detached immutable scrubber.

Actual follow-up evidence (GOTOOLCHAIN=go1.26.7, scratch log prefix
`task-16a2-review-`):

- `go test ./internal/actions -run '^TestPartialSecretOpenFailureEventMasked$' -count=1`
  RED both Action/Module valid-first/corrupt-second cases exposed the opened
  credential. Immediate registration GREEN0.094s (`partial-red/green.log`).
- `go test ./internal/server -run '^TestMountedSilentActionCredentialMasks$' -count=1`
  RED all four real TLS mounted cases (throw/deny × short/long secret) exposed
  client_name in f and fsa (`mounted-red.log`). Assertions inspect complete
  exact sequences, shared resolving execution links, RFC3339 date and every
  affected event, rather than catalog membership.
- `go test ./internal/logs ./internal/actions ./internal/server -run '^(TestFlowCredential.*|TestPartialSecretOpenFailureEventMasked|TestMountedSilentActionCredentialMasks)$' -count=1`
  GREEN logs0.041s/actions0.152s/server1.027s (`green.log`). Includes count/byte
  overflow, duplicate/empty values, immutable snapshots, request isolation and
  concurrent registration/recording tests. Test API additions are secondary
  coverage to the actual runtime RED reproductions above.
- `go test -race ./internal/logs ./internal/logscrub ./internal/actions ./internal/authz ./internal/login ./internal/server -count=1` PASS logs1.562s/logscrub1.027s/actions162.065s/authz21.273s/login80.088s/server113.493s (`race.log`). No test failures or skips reported.
- Updated60-row audit matches all emitted inventory codes;59 named event and
  masking tests exist. Reviewed all3 production hunks and new test helpers.
  No store/SQL/protobuf/generated/dependency changes, no SQL/full-gRPC rerun.

Task16 remains incomplete, with the same Task16b acceptance/docs/regression
and whole-branch review work and prior carry-forward minors outstanding.
