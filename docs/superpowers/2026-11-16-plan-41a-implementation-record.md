# Plan 41a implementation record

Status: **implementation and local verification complete**, starting from
`main` commit `18d01994` (Plan 48 merged). Branch:
`plan-41a-oidc-extras-logout`; worktree:
`/mnt/nvme2/code/zeroauthy-plan41a`. One independent whole-branch review and
its regression-tested fix pass are complete. Full plan-branch CI and maintainer
approval govern integration; formal certification has not been submitted.

## Progress

1. Tasks 1–7: implemented and committed; focused checks and storage round trips passed.
2. Tasks 8–9: durable back-channel delivery, termination triggers and metadata committed.
3. Task 10: pinned upstream global revocation committed; focused JWT/state/handler tests passed.
4. Task 11: console committed; 734 tests, lint, typecheck and build passed.
5. Task 12: seed and bootstrap committed; real Deploy CLI four-cell round trips passed.
6. Task 13: all five conformance plans finished, exit 0; hosted kit render/prepare passed.
7. Task 14: full E2E lane passed (three browser journeys, SDK CRUD, secret scan
   and four-cell Deploy CLI); final aggregate Go run and independent review passed.
   Full plan-branch CI results are reported in the pull request; maintainer approval
   remains required before merge.

## Verification

Local toolchain: Go `1.27.4-X:nodwarf5`; go.mod minimum stays 1.26.11. The
plan's historical 1.26.10 pin is superseded by the repository's patched
minimum; no dependency or toolchain downgrade was made.

- Baseline `go test ./api ./internal/tenantrules ./internal/logrules`: exit 0.
- API contract test: failed on missing client fields, algorithms, parameters
  and revocation route before the schemas changed; passed afterwards.
- Schema validation test: failed when both OIDC scope controls were
  permitted; passed after making them mutually exclusive.
- `go test ./api ./internal/server ./internal/tenantrules ./internal/logrules`:
  exit 0; server tests took 56.683 seconds. Full log retained in the local
  plan workspace as task1-tests.log.
- `make generate`: exit 0.
- `go build ./...`: exit 0 after adding the generated route's 501 adapter.
- [Implicit/Hybrid inventory](2026-11-16-plan-41a-conformance-check.md):
  Implicit exit 1; separate Hybrid run exit 1. Both abort on unsupported response types. No certification claim.

Task 2 added strict environment parsing and per-switch startup warnings.
`go test ./internal/compat ./internal/config` passed (exit 0). The real
application startup test failed before Warn was connected and passed
with all three enabled switches producing one warning each. Empty/0/false
are disabled; 1/true are enabled. Other values fail configuration without
echoing their contents. Unknown switch names still fail strict decoding.

Task 3's claims parser (`f0d2fa60`) accepts Core claim requests and ignores unknown
members, validates target/claim object shapes and value controls, rejects
trailing JSON and invalid UTF-8, and enforces a 4096-byte bound before
parsing. Errors contain no claim values. `go test ./internal/claims` passed
(exit 0). The parser is now connected to authorization, PAR and signed request objects; shared selection governs ID tokens and userinfo without widening consent.

Final local verification passed: full Go, logout E2E, five conformance plans,
vulnerability, workflow and source checks. The independent review and its fix verification are recorded below. Full CI
results belong to the plan-branch workflow and pull request.

## Rulings

The ledger and D-0080 record these choices:

- Use the current public log catalog names, rather than the plan's older
  sslo/fslo shorthand. Consumers expecting those short aliases must use
  oidc_backchannel_logout_succeeded/failed.
- Keep inventories accurate during implementation: enable emitted flags
  and active-setting descriptions alongside their runtime consumers.
- Use main's next available migration number and recheck before merge.
- Preserve go.mod's patched Go minimum; record the installed local compiler.
- Exclude optional Implicit/Hybrid profiles based on their actual failed
  inventory runs; implementing those grants remains outside this plan.
- Keep FromEnv's proposed signature and validate invalid values separately
  in config.Load; both paths use the caller-supplied environment snapshot.
- Accept canonical 0/false as explicit disabled values; other nonempty
  spellings beyond 1/true fail startup.


## Tasks 3–6 checkpoint

Claims now include available phone/address/profile attributes. Federated
standard attributes are bounded and whitelisted in the primary identity's
provider data; root values win, linked identities and metadata cannot leak
through scope claims. OIDC support restrictions are stored, validated and
applied before consent, at exchange, and at userinfo. Client writes fail
closed when a plugin lacks oidc_logout.v1; transient capability-probe
errors remain retryable. Claims-request values are scrubbed from logs.

MFA step-up works with acr_values and essential acr requests. Tenant policy
never, remembered browsers and an Action skip cannot bypass it. Existing
MFA SSO sessions avoid another prompt. Requested ACR survives code exchange
and refresh rotation, and new refresh ID tokens omit it if the MFA session
is gone. The tenant's advertised ACR choices are intersected with implemented
contexts. Explicit [] disables them; absent/null defaults to the MFA value.

ID tokens support RS256, PS256 and HS256 per client. HS256 uses the newest
active sealed client secret, with no kid, and rejects public, hash-only or
private_key_jwt-only clients. Rotation changes subsequent signatures.
RP-initiated logout verifies symmetric hints only with the matching client's
explicit HS256 setting. New API signing-secret writes require 32 characters;
legacy stored shorter secrets retain their signing behavior. The maintainer
rulings from 78bb70cf were carried into this branch's plan/spec/follow-ups.

The compatibility resource profile canonicalizes one resource to audience
at authorize, PAR and token endpoints; conflicts return invalid_request,
repeated values invalid_target. The default profile ignores resource.
Optional redirect fallback is opt-in and requires one callback with no
wildcard or placeholder. Repeated GET resources are represented as an array
in OpenAPI so the generated router reaches the protocol validation.

Verification evidence:

- Initial Tasks 3 package run: exit 1 solely on TestDiscovery and
  TestDiscoveryDeviceEndpoint expecting the old scope list; corrected.
- Subsequent Tasks 3–4 command (13 packages including OAuth, Management,
  federation, hosted login, MFA, schemas and scrubber): exit 0. OAuth
  339.850 s, Management 181.182 s, hosted login 92.656 s. Log retained as
  tasks3-4-packages.log in the ignored plan workspace.
- Focused Tasks 3–6 command (ten packages, including the actual generated
  server router, signing algorithms, rotation, discovery and boundary
  checks): exit 0; log tasks3-6-focused.log.
- Actual verbose OIDCClientSettings subtests pass in memory, SQLite and
  gRPC. Earlier parent-only invocations selected no round-trip subtest;
  those are not counted as round-trip evidence. Suite ordering was fixed.
- AuthCodes/RefreshTokens conformance suites with ACR pass in memory,
  SQLite and gRPC; SQLite took 6.890 s. Protobuf codec tests pass.
- The new script-profile normalization test passed after first failing
  because extended standard attributes were discarded.

No full-plan completion, E2E coverage, final review, full verification or CI
is claimed. No dependency was added. Security-sensitive changes include
keys, OAuth, authorization, Management, hosted login, federation, server
wiring and storage. Nothing has been pushed.


## Checkpoint verification and Task 7

The initial checkpoint ee3b79e0 omitted tenant-rule helper files from staging.
Its isolated 17-package run exited 1 with undefined tenant-rule helpers in
authorization and cascading OAuth/OIDC/Management/login/server build failures.
The omission was fixed in signed commit 3104068c. That corrected source built
successfully; a separate run of the same 17-package command is in progress
against exactly 3104068c in the verification worktree. Both command results
and logs are retained in the ignored plan workspace. The failed snapshot is
not counted as a pass, and the corrected run is not yet reported as passing.

Task 7 adds validated nested client oidc_logout settings and effective tenant
logout discovery settings. Receivers are limited to one HTTPS URL of at most
2048 bytes, with known organization placeholders, no embedded credentials
or fragment. Custom initiators require rp-logout/idp-logout; the three
OpenAPI-only initiators are accepted without implementing their triggers.
Reads supply initiator and metadata defaults. A plugin without oidc_logout.v1
cannot write or clear these settings. The RP logout discovery flag hides
metadata while the endpoint keeps working. Back-channel flags are present
when its storage capability is available. Receiver URL fields are scrubbed
because callback query strings can carry credentials.

The sender, durable jobs and all session-ending trigger wiring remain
unimplemented. This partial branch must not be pushed or advertised as
complete back-channel logout support.


## Task 8 delivery checkpoint

The sender now runs through the durable ActionJob queue (the actual Plan 28
queue in this base). Each session/client pair receives a sealed immutable
job, created in the transaction ending its local session. The worker claims
and fences completion, mints fresh RS256 tokens per attempt, applies guarded
HTTPS delivery with a five-second timeout and no redirects, and retries
network/5xx failures for at most ten minutes. Terminal outcome logs contain
only the client, initiator and receiver host. Logout tokens cannot be used
as ID token hints, including under the JWT type compatibility switch.

RP logout, session revoke/delete, account deletion, email/password updates,
password reset and expiry sweep now enqueue notifications. Global revocation
and its idp-logout trigger remain Task 10. Optional session metadata is sealed
at enqueue and included only when configured; empty metadata becomes {}.
Organization templates use each client's latest validated authorization
organization, persisted separately from mutable metadata in memory, SQL and
gRPC. A missing/deleted organization fails delivery closed.

Focused core and actual trigger checks passed (logout-core.log,
logout-integration.log, task8-final.log). The SQLite restart test closes the
store and reopens it with a new service/key manager before delivering a
reclaimed job. Actual ClientOrganization subtests pass in memory, SQLite and
gRPC. The earlier snapshot 3104068c run finished with exit 1 on three stale
Management test expectations; those expectations were corrected and passed
focused checks. The other sixteen selected packages passed. This supersedes
the earlier in-progress verification and unimplemented-sender statements.

Still pending: global revocation, console, seed/Deploy CLI, new conformance
profiles, E2E lane, final documentation, full local checks and review. Nothing
has been pushed.


## Tasks 9–10 checkpoint

Optional session metadata tests pass for true/false and empty data. Global
revocation now verifies explicit-type asymmetric JWTs with the selected
enterprise OIDC/Okta connection's pinned issuer and JWKS, configured client
subject, exact endpoint audience, five-minute validity and single-use jti.
The audience corrects the earlier design assumption based on current
Auth0-linked Okta documentation; D-0080 records the sources and migration
impact. Unknown subjects return 204 and still consume the jti. Email lookup
is restricted to owners in that connection's federated identity index and
uses the selected identity's email; ambiguous matches select nobody.

A transaction consumes the hashed connection-scoped jti, bumps the user's
version, revokes all refresh tokens and ends sessions with idp-logout jobs.
The sweeper purges expired replay entries. SQL, memory and gRPC carry the
new replay state and lookup. Discovery exposes the connection endpoint
template and the global-token-revocation+jwt authentication profile. Real universal_logout outcome
logs are enabled and contain no JWT, email or upstream user subject.

Focused seven-package verification passed in task10-focused-fixed.log;
actual GlobalRevocationState memory/SQLite/gRPC subtests passed. Retained
failures include malformed log inventory trigger shape and an unquoted YAML
brace description; both were corrected and subsequent checks passed.
No full local suite or final review has been claimed and nothing is pushed.


## Task 11 console

The application detail page has OIDC and logout controls for one receiver,
required RP/IdP initiators, supported optional initiators, metadata, signing
algorithm and OIDC restrictions. HS256 is unavailable without a retrievable
32-character confidential-client secret. Scope editing obeys the API's
mutually exclusive all-scopes/explicit-list forms. Tenant Advanced settings
expose RP logout discovery and the resource profile. Log labels and failure
classification use the shared catalog's actual logout codes.

Generated TypeScript schema and embedded console assets were rebuilt.
Focused UI checks passed (68 tests); full console test run passed 90 files,
734 tests (15.13 seconds). Lint and typecheck passed. Vite build passed with
the existing large-chunk warning. Dependency installation used the unchanged
lockfile with scripts disabled; npm reported 13 moderate dependency findings.
No dependency update or audit fix was applied as part of this feature.
Browser E2E and final full-plan verification remain pending.


## Task 12 seed and Deploy CLI

Seed clients accept the shared validated oidc_logout/oidc_support objects and
jwt_configuration.alg/lifetime_in_seconds, retaining id_token_lifetime as the
legacy spelling and rejecting conflicting values. HS256 checks secret
availability, authentication method and minimum length; old plugins fail
before a partial seed applies. Preserved-ID bootstrap carries these fields
and accepts the implemented signing algorithms.

Both seed and migration package suites passed. The actual unmodified Deploy
CLI 9.1.0 exported/imported/reimported/exported logout settings, OIDC scope
restrictions and PS256 in all four cells, exit 0. Logs: task12-deploy.log/.exit;
protected generated artifacts: /dev/shm/za41a/tmp.jTsvvf8Hht. E2E dependencies
were reused from an existing install only after the lockfiles matched; no
package was added. The backend snapshot suite's two OIDC failure-fixture
regressions were fixed by preserving injected errors in transaction views;
full OIDC/session package rerun passed (13.317 s / 0.012 s). Its original
snapshot run remains recorded as exit 1, with all other 17 packages passing.


## Final local verification checkpoint

`make conformance` exited 0, results `20261121T042726Z`: Basic/Form Post
35 modules each, 26 passed/4 documented warnings/3 review/2 documented skips;
Config 1 passed; RP logout 3 passed/8 review; Backchannel 2 passed. Every
module finished. Phone/address/profile and genuine ACR proof now pass.
Retained essential-name warnings reflect granted-scope consent, not missing
claims parsing. Both official client_secret_post modules ran within the
pinned plans. No separate full-post variant or implicit/hybrid certification
is claimed. Public kit rendering and SQLite preparation passed at protected
`/dev/shm/za41a/certkit.3tQj83`.

`make e2e-logout` exited 0. Pinned node-auth0 settings CRUD and privacy scan
passed; all three Playwright journeys passed (4.0 seconds): another client's
RP logout invalidates the real Express SDK session; real TOTP enrollment
satisfies ACR and silent MFA SSO; pinned upstream global JWT revokes linked
user sessions/refresh tokens and reaches Express. All four actual Deploy
CLI 9.1.0 cells passed. Protected artifacts: `/dev/shm/za41a/tmp.bhQlSqV9JM`.

Two aggregate Go runs reported failures, preserved in full-go.log/.exit and
full-go-fixed.log/.exit. The first exposed a missing process-wrapper optional
interface, a full codec fixture missing its new field, and an accidentally
renumbered unrelated constant in an existing event test. Fixed the wrapper
and public aliases, populated the full fixture and restored the exact base
assertion (42, not 43). Focused real plugin/codec/SQL checks passed. The second
reported only stale generated configuration documentation following a comment
update; `make generate` regenerated it. The latest aggregate run remains the
completion gate, rather than treating either failed run as passing.

The 60-second usersearch fuzz run passed (295,996 executions). govulncheck
found no reachable/imported-package vulnerabilities; one required-module
finding is unreachable. Zizmor passed offline with no findings after the CI
matrix and conformance defaults changed (existing suppressions retained).
Provenance source checks passed. No dependency was added or lockfile changed;
npm installation of the existing console lockfile reported 13 moderate
findings, with no automated audit fixes applied. The final fresh-context
review, its fixes and CI remain outstanding. Nothing has been pushed.

## Complete execution rulings

The following preserves every execution ruling in chronological order. Final
review rulings, if any, will be appended after review.

- Ruling: use main's next free migration number rather than the plan's provisional 0039 — existing migrations must not be overwritten — renumber again before merge if main advances.

- Task 1: Ruling: preserve repository go.mod minimum Go 1.26.11 rather than the older plan's 1.26.10 — do not downgrade the patched toolchain — verification uses installed Go 1.27.4 and records that difference.

- Task 1: Ruling: current public catalog names supersede the older spec's sslo/fslo shorthand — use oidc_backchannel_logout_succeeded/failed and universal_logout_succeeded/failed — consumers expecting short aliases must update. Evidence URLs and L14 recorded in D-0080.

- Task 1: Ruling: activate existing tenant inventory descriptions and log emitted flags only alongside the real runtime consumers/emitters — current schemas already accept the settings and log inventory requires actual trigger functions — contract-stage inventories retain accurate stored/deferred status.

- Task 1: Ruling: omit optional Implicit/Hybrid profiles after real inventory failures — base accepts only response_type=code, contrary to the design's assumption; building implicit/hybrid grants is outside this plan — these profiles remain uncertified.

- Task 2: Ruling: FromEnv keeps the proposed error-free interface; ValidateEnv supplies startup validation and config.Load uses the supplied environment snapshot, never ambient os.Getenv — supports reproducible config callers — both paths must remain in startup wiring.

- Task 2: Ruling: accept canonical false/0 as explicit disabled values along with empty, true/1 as enabled; reject other spellings without echoing raw values — allows operators to disable switches explicitly without startup failures — narrower than Go's broad boolean parser.

- Task 3: Ruling: bring Task 7's client storage fields/capability forward as a prerequisite to Task 3's oidc_support — API/runtime must not accept settings that SQL/plugins silently drop — Task 7 still owns logout validation/discovery and is not complete from storage alone.

- Task 3: Ruling: existing User has no root container for address or the extra standard claims and generic OIDC normalizes them away. Retain a whitelist of standard claims in primary identity ProviderData, bounded by the existing 64 KiB profile limit; root fields remain authoritative and linked identity data is excluded — avoids a second user-storage migration — extra claims are exposed under identity provider data rather than invented writable root fields.

- Task 4: Ruling: bind StepUp in the sealed MFAPending requirement JSON and derive it from validated transaction parameters, rather than duplicate an independent mutable hosted-state flag — preserves binding across every MFA page without extra AuthTransaction schema changes — future consumers must use the sealed requirement or validated params.

- Task 4: Ruling: tenant acr_values_supported is intersected with the single implemented context; absent/null defaults to MFA, explicit [] disables advertised/requested contexts, unknown configured values are stored but never advertised — does not falsely claim support — existing arbitrary stored lists no longer advertise unsupported values.

- Task 4: Ruling: ACR must persist in authorization codes and refresh families (an interface missing from the plan). Add scalar fields to the same unpushed Plan 41a migration 0043 and protobuf, preserving empty defaults for legacy records — otherwise exchange and refresh lose the requested assertion — old plugins cannot be used for step-up without oidc_logout.v1.

- Task 5: Ruling: apply the maintainer's 78bb70cf documentation patch from the original checkout — it was absent from main, but its rulings were already binding and recorded in D-0080 — avoids dropping the 32-character requirement and discovery/JWKS decisions. No code from another plan is started.

- Task 6: Ruling: normalize valid resource aliases before audience/consent checks and persist canonical audience in PAR; ignore resources under the default profile, including repeats — preserves the spec's compatibility-profile boundary — downstream consumers should use canonical audience.

- Task 6: Ruling: exclude placeholder callbacks as well as wildcards from optional fallback — fallback must name one resolved registered callback — a configured organization template needs an explicit redirect_uri.

- Task 8: Ruling: reuse Plan 28 ActionJob sealed queue and its existing claim/finish fence rather than the Management Jobs pool — Plan 28's durable queue is ActionJob in this base, despite the old plan naming internal/jobs — requires worker dispatch for the new job kind and no Actions execution for logout jobs.

- Task 8: Ruling: add per-client validated organization IDs to LoginSession, with atomic participant recording, SQL and gRPC codecs — placeholders must use the latest successful authorization's organization, never mutable session metadata or inferred membership. Missing/deleted organization leaves the URL unresolved and the worker fails closed, without blocking local logout. Explicit non-org authorization clears that participant's previous organization. Old plugins may use legacy participation only when logout is not configured.

- Task 9: Ruling: metadata accessor/token shape brought forward with Task 8's token construction, because queue snapshots need to seal inclusion and data together; no remaining Plan 48 dependency (already on base). Dedicated true/false/empty metadata tests are retained.

- Task 10: Ruling: current Auth0-linked Okta profile and draft-06 bind aud to the exact connection-specific endpoint, rather than the design's tenant issuer URL — correct the stale L13 assumption and require that endpoint, preserving query/fragment exclusion and explicit type — callers using the former tenant-issuer audience must update. Sources and rationale recorded under D-0080 and design corrected. Require JWT sub to equal the configured integration client ID to prevent another integration under the same upstream issuer from authenticating here.

- Task 10: Ruling: use a separate global_revocation_jtis table keyed by tenant/connection/hashed jti, with consumption in the revocation transaction and bounded sweeper purge — prevents collisions with client assertion keys and supports unknown-subject replay protection. Email candidates come only from the selected connection's federated identity index and match that identity's email; ambiguous matches are treated as unknown rather than selecting one account. No lookup by root email across unrelated identities.

- Task 13: Ruling: release-v5.3.3's actual OIDCCBasicTestPlan fixes client_secret_basic for its normal modules and includes a dedicated client_secret_post module; Form Post derives from it. There are no separate full client_secret_post certification plans or selectable authentication variants. Do not invent duplicate basic-post/formpost-post profiles or claim all modules ran with post authentication; retain and verify each official profile's real post module using za-conformance-post / za-cert-post. The pinned primary Java plan sources were read and retained in the workspace. This replaces the plan's assumed standalone post profiles; full-post variant coverage is unavailable in this pin.

- Task 13: Ruling: retain the existing claims-essential warning under D-0080 with corrected rationale — the real module asks for name with only openid, while LR41a-4 prohibits widening granted profile consent. Core 5.5 permits declining it. This is an existing expectation retained after triage, not a new warning acceptance; remove only claims-parameter unsupported rationale, keep actual no-consent-widening behavior. Changing it would expose profile data without its granted scope. Other removed profile/acr/scope warnings must still clear on actual rerun.

## Whole-branch review and fix verification

The one fresh-context review covered 18d01994..7a3e8629. Its correctness fixes
were verified together: adaptive-policy mandatory enrollment, retained
expiry snapshots and draining, transactional lock ordering and participant
snapshots, retired issuer handling, receiver authority validation, safe outcome
logging, actual plugin backing capability checks, online/operator session-end
notifications, and target-specific UserInfo session evidence through code and
refresh exchange. No second reviewer was dispatched.

Only the canonical requested UserInfo session claim names (`auth_time`, `acr`)
are stored on authorization codes and refresh families. They do not enlarge
profile consent. The server carries available values in a reserved signed
access-token claim, filters Action collisions, and omits MFA evidence when the
refresh session is absent or expired. The signer-compatible JSON number type
preserves registered numeric dates when custom claims are merged. SQL, gRPC,
actual authorization, exchange/refresh and UserInfo regressions cover the path.

Post-review aggregate verification on `f149ca5c`: `go test -p 4 ./...` with
TMPDIR/GOTMPDIR `/dev/shm/za41a` exited 0 (`full-go-reviewed-final.log/.exit`).
An earlier reviewed-snapshot run exited 1 only because the unit notification
fixture had not stored its tenant; it now supplies that row and preserves both
rollback and success assertions. Every session test passed before the aggregate.

Post-review conformance on production snapshot `7607f4bc` exited 0, results
`20261121T050646Z`: all 84 modules finished with the same documented profile
counts above. The later commit changes only the session unit fixture.

Post-review `make e2e-logout` exited 0 in isolation: SDK CRUD/privacy checks,
all three browser journeys and four Deploy CLI cells passed. Protected artifacts:
`/dev/shm/za41a/tmp.cojeROhML3` (browser/SDK) and
`/dev/shm/za41a/tmp.IeaOer1qx5` (Deploy CLI). A prior simultaneous run exited 2
at Deploy CLI startup because conformance already owned host port 8443; its log
and status remain preserved, rather than being counted as a pass.

All required local implementation gates are satisfied. Full race, SQL-server,
console reproducibility and all-E2E CI remain the integration checks. No merge
or formal certification is authorized by these local results.

## Final review rulings

- Final: Ruling: browser cookie replacement during new login remains rotation without logout fanout — it is not an explicit RP/IdP/session-revocation operation, and notifying would sign out existing relying parties during a fresh login — if wrong, an older relying-party session can outlive the browser session switch. Explicitly documented in docs/logout.md; ORT revocation and operator removal now do fanout as session-revoked.

- Final: Ruling: skip notifications for invalid, retired or reassigned historical issuers while committing local termination — never mint under a no-longer-owned issuer, and a retired host cannot block credential/account changes — if wrong, the corresponding relying party misses that logout notice. Transient storage errors still preserve atomic rollback.

- Final: Ruling: reviewer-declined optional Implicit/Hybrid and full-post certification follow the actual inventory/pinned-suite rulings above — implementing unsupported grants or invented plan variants would misrepresent coverage — if wrong, these profiles remain uncertified until separately implemented.

- Final: Ruling: reviewer-declined front-channel logout, Session Transfer Tokens and three stored-only initiators retain the explicit spec exclusions — do not expand this plan — if wrong, applications depending on those mechanisms remain unsupported as documented.

- Final: Ruling: reviewer-declined formal certification remains maintainer-owned after merge; full SQL/race/all-E2E verification remains in plan-branch CI — repository mandates that verification split — if wrong, a CI-only issue may still require another branch fix before approval.

Deferred minor: the older compatibility table at docs/compatibility.md:27 still lists claims parameter/back-channel logout as unimplemented. The later summary and operator docs describe the implemented behavior.

## First CI failure triage

[Plan-branch run 44870736008](https://github.com/occupysaas/zeroauthy/actions/runs/44870736008)
on `cc4d9019` passed conformance, logout E2E, console and vulnerability checks.
The existing `e2e-deploy` and `e2e-refresh-tokens` lanes failed: offline export
loading classified `resource_parameter_profile` as a file because its key
contains “file”. Both actual lanes reproduced locally. A failing regression
for both enum values preceded the fix; YAML/directory and explicit traversal
checks pass. The exact scalar key is excluded from the implicit file heuristic;
explicit `file://` references still use all path and symlink protections.

After fixing, the full `make e2e-deploy` matrix exited 0 (protected artifacts
`/dev/shm/za41a/tmp.GdD808k6nW`) and all four actual pinned refresh-token Deploy
CLI cells exited 0 (`/dev/shm/za41a/tmp.afQQIVEQDQ`). These preserve the matrix's
existing tool-unavailable fields and lack of upstream observer credentials;
no upstream coverage is claimed. The full Go aggregate also exited 0.

The Express test fixture now initiates authentication through the SDK's `/login`
route and returns to its public session-status endpoint. The unused `/me` route
was removed; browser assertions still require a real authenticated SDK session
and subsequent verified back-channel invalidation. All three browser journeys,
SDK CRUD and privacy scan passed (`/dev/shm/za41a/tmp.tFiEShyXnr`). An initial
fixture revision used a nonexistent SDK setting and failed before authentication;
that failed result is retained. No new dependency or scanner suppression was added.

The follow-up CodeQL check still classified the public session-status operation
as authorization. The fixture now installs `express-rate-limit` 8.7.5 globally
before SDK middleware, with 100 requests per minute per address. This is a new
E2E-only dependency, verified against the package registry and upstream repository;
its lockfile is committed and installation scripts remain off. Existing dependencies
were unchanged. A real HTTP regression failed without the limiter (request 101
returned 200), then passed with it (429); all three existing browser journeys,
SDK/privacy checks and all four logout Deploy CLI cells also passed. Protected
artifacts: `/dev/shm/za41a/tmp.3IyVlnaQbl` and `/dev/shm/za41a/tmp.cKu8UvkLuR`.
No production dependency, authorization bypass or scanner suppression was added.

## Race-suite timeout and the single rerun

At `66f838ea`, full plan-branch run 44875768271 passed the SQL matrix (56m43s),
every E2E lane, conformance, console and vulnerability checks. All PR checks,
including CodeQL, passed. Its race job 136760086203 failed at the unchanged
60-minute per-package limit in grpcstore and sqlstore, without a reported race
or assertion failure. The active tests were older Actions-II queue-cap and
Guardian cases, advancing through fresh database migrations. The preceding
successful Plan 48 run 44816878045 took 2058s/2301s in those packages.

After reading both logs, the single permitted failed-job rerun was used and
recorded in the PR. Job 136782514634 timed out too (1h18m50s job total), in
older Logs/Guardian cases and migration setup. No second unchanged rerun was
requested. Both failures are retained in the plan evidence and PR.

The CI race tier now places test temporary files at short tmpfs path
`/dev/shm/za-test`, reducing repeated SQLite migration disk I/O, with compiler
scratch explicitly on disk at `/tmp/za-build`. The exact `go test -race
-timeout=60m ./...` command, coverage, migration semantics, assertions and
permissions are retained. Focused race tests covering SQL authorization-code
round trips, Guardian setup, old-plugin queue-cap and capability refusal passed
(SQL 5.049s, gRPC 69.156s); zizmor passed with existing suppressions. Full CI on
the workflow change remains the required final gate.

The tmpfs full run 44890538046 passed grpcstore race tests (3141.723s), the SQL
matrix (51m7s), every E2E lane and every other check, but sqlstore race tests
still reached the 60-minute package limit while setting up an older
Organizations-II cascade case. No unchanged rerun was requested.

The SQLite conformance factory now prepares one fully migrated empty image per
parent suite, closes/checkpoints it, and copies its bytes into an independent
file per case. Every copy still uses normal Open/Migrate and checksum checks.
Dedicated upgrade tests continue using fresh unmigrated databases, and the
PostgreSQL/MySQL factories are unchanged. An isolation/integrity regression
passed under race instrumentation: mutations and close operations do not cross
copies, integrity_check returns ok and Migrate succeeds. Focused race checks
passed in 12.221s; the full non-race Go suite passed. This is test setup only;
production logic, assertions, migrations and timeout limits are unchanged.
