# Plan 33b implementation record — passkeys and WebAuthn MFA

Plan: `docs/superpowers/plans/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn.md`.
Spec: `docs/superpowers/specs/2026-11-05-zeroauthy-passkeys-webauthn-design.md`.
Executor: inline (maintainer chose native execution, 2026-11-05). Branch
`plan-33b-passkeys`, worktree `/mnt/nvme2/code/zeroauthy-plan33b`, from main
`42c1258`.

## Task 1: Contracts, decisions and the virtual-authenticator spike

- `internal/webauthnrules` freezes rules (with source URLs), screens, text
  keys, log detail fields and `Limits`. Ten log codes now name owner Plan 33b;
  `gd_auth_rejected` is `not_planned`. Actions MFA members list the factors
  they accept, including `webauthn-roaming` and `webauthn-platform`. Branding
  gains the two `reset-password-mfa-webauthn-*-challenge` screens.
- D-0062, changelog review (coverage 2026-10-30), matrix row, follow-ups
  W1–W12, roadmap (Plan 40 loses the first-factor methods, K11).
- Playwright `testMatch` now matches `m33b-*` specs.
- Spike: `ignoreHTTPSErrors` alone is enough for create, button get and
  conditional get with the CDP virtual authenticator.
- Rulings: no source re-fetch (one-day-old research); API YAML route
  additions move to Tasks 14/15 (generated interfaces would break the build).

## Task 7: RP IDs, origin policy and passkey prerequisites

- Snapshot: worktree `/mnt/nvme2/code/zeroauthy-plan33b`, branch
  `plan-33b-passkeys`, starting commit
  `77708b260a00003a5d7532d75f7594acc5ba9ca8`. Preserved and finished the
  existing untracked RP ID resolver, resolver tests and connection-policy
  tests. Included the existing Task 6 wrapper capability regression test;
  its production methods were already committed.
- Added the per-request RP ID resolver, canonical/custom/operator host
  classification, strict shared-host restriction and exact native-origin
  allowlist. Hosts lose case, trailing DNS dot and port for the RP ID;
  origins retain the request port. Inactive bindings and invalid stored
  values fail closed with one WARN containing tenant and host.
- Added `connrules.Passkeys` and operator-only prerequisites route, including
  target-tenant checks for both signed and persisted operator grants.
  Added the deployment setting and regenerated `docs/configuration.md`.
  Management custom-domain POST/PATCH and seeded alias RP IDs use R1.
  The application passes the deployment setting to both paths.
- Seed `domains` accepts strings and `{host, relying_party_identifier}`.
  Existing Go `[]string` callers remain compatible; YAML objects are
  normalized before strict decoding and their overrides persist separately
  in `Tenant.DomainRPIDs`. Omitted domains and create-only mode retain
  overrides; explicit string domains remove overrides.
- Ruling: validate seeded overrides after all aliases in the transaction
  have been reconciled, so a later tenant participates in R1. Cost if wrong:
  a seed transaction fails before commit rather than allowing an ambiguous
  shared RP ID.
- Ruling: a create-time null custom-domain RP ID falls back to the domain,
  as specified in §3.2; removed the older test that forbade null. PATCH null
  validates the resulting full-domain RP ID too. Cost if wrong: callers may
  use null in POST where earlier zeroauthy releases rejected it.
- Ruling: native `web_origins` entries must already be serialized HTTPS
  origins; userinfo, paths (including `/`), queries, fragments, malformed
  ports and unnormalized DNS names are rejected rather than rewritten.
  Android fingerprints must have 32 colon-separated hex bytes. Cost if
  wrong: an incorrectly formatted client configuration needs correction.
- Ruling: extend the Tasks 4/5 `HostTenantsUnder` contract to compare the
  hostname without an operator alias's port. Memory and SQL implementations
  now do so; SQL retains literal SUBSTR matching instead of LIKE. This
  closes the demonstrated strict-policy bypass. Cost if wrong: none for
  DNS bindings; privileged aliases with ports now participate in R1.
- Ruling: failure to read the strict host ownership registry, including
  unavailable WebAuthn storage, propagates as an error rather than accepting
  the RP ID. Cost if wrong: strict-policy writes need a capable store.
- TDD: initial focused run failed on missing policy/config/seed APIs.
  Concrete red tests then demonstrated permissive non-origin URLs, inactive
  custom bindings, missing target-tenant authorization, create-null refusal,
  strict PATCH-null bypass, ignored host ports in memory and SQLite, and
  ignored strict-registry unavailability. The final focused run passed.
- Verification (all Go commands set `GOTOOLCHAIN=go1.26.10`, `TMPDIR` and
  `GOTMPDIR=/mnt/nvme2/tmp/plan33b-task7`):
  - `go generate ./internal/config`: exit 0.
  - `go test ./internal/rpid ./internal/connrules ./internal/config
    ./internal/customdomain ./internal/mgmt ./internal/seed ./internal/server
    -run 'RPID|NativeOrigins|PasskeyPolicy|PasskeyPrereq|WebAuthnRestrict|Reference|Domain'
    -count=1`: exit 0, all seven packages passed.
  - `go test ./internal/store/memory ./internal/store/grpcstore
    -run '^TestConformance$/^WebAuthn$/^HostTenantsUnder' -count=1`:
    exit 0, both packages passed.
  - `./scripts/test-sql.sh -v -timeout=15m ./internal/store/sqlstore
    -run '^TestConformance$/.*/^WebAuthn$/^HostTenantsUnder'`: exit 0;
    both host-ownership subtests passed on PostgreSQL, MySQL and SQLite
    with `-race` (six leaf subtests; SQL package 8.128s).
  - Focused seed parser, transaction and retry regressions: exit 0.
    Wrapper capability regression: exit 0. Application compile with
    `go test ./internal/app -run '^$' -count=1`: exit 0; no tests selected.
  - `git diff --check`: exit 0.
- An initial SQL command contained a space in its selector and selected no
  tests (exit 0); it is not counted as validation. The corrected verbose
  command above proved all six subtests ran. The initial mixed memory/SQL
  red command also selected no SQL tests; a separate SQLite red run proved
  the database regression before the SQL fix.
- No full regression suite ran; Task 19 owns it. No tests were skipped in
  the selected successful runs. Detailed commands, failure history and logs:
  `.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/task-7-report.md`.
  One implementer monitored each command; no additional agents were spawned.

### Task 7 review fix round 1

- Review base: `b07742495d86b33de00aafc66159851b9c4fd1d6`. Two important
  findings reproduced: a distinct port alias inherited the unported alias's
  override, and an alias sharing the canonical hostname was classified as
  canonical because the comparison discarded ports.
- Preserve the complete normalized host for canonical classification and
  registry lookup. Read alias overrides by the matched binding's exact
  `Host`; strip the port only when deriving the RP ID. A bound port alias
  with no override defaults to its own bare hostname. Its invalid or
  strict-policy-refused override fails closed, even when its hostname
  equals the canonical hostname. The actual canonical host remains valid
  with its own RP ID.
- The same identity defect permitted an unregistered port to fall back to
  an unported binding. A separate red test demonstrated that path; removed
  the fallback so registry lookup matches tenant resolution's exact host
  identity.
- TDD: `go test ./internal/rpid -run '^TestRPIDPortAlias' -count=1`
  exited 1 on seven subcases before the first fix, then exited 0.
  `go test ./internal/rpid -run '^TestRPIDPortAliasUnbound$' -count=1`
  exited 1 before removing the fallback. Final seven-package Task 7 focused
  command (same selector and environment as above) exited 0, including all
  new regressions. Logs: `task-7-review1-red.log`,
  `task-7-review1-green.log`, `task-7-review1-unbound-red.log`, and
  `task-7-review1-focused.log` under the task report directory. Actual exit
  statuses are also stored in matching `.exit` files.
- `git diff --check` exited 0. No SQL implementation changed in this round;
  no SQL or broad regression suite reran. No agents were spawned.
  Implementation verified; controller re-review owns final completion.

### Task 8 — implementation verified / review pending

- Base: `2fc2afc284ab9a2ef0d6f602e0de2e6c69c09a05`. Added the shared
  `internal/passkey` service, hosted/native single-use challenges, exact
  binding comparisons, credential-owner login, atomic assertion counter and
  backup-state updates, passkey enrollment, creation/request options and
  passwordless user creation through `CreateUserWithPasskey`.
- Connection effectiveness, client enablement and realm checks use the
  credential's saved database identity (including linked identities), not a
  typed identifier. Possession is verified before returning the blocked-user
  error. Enrollment rechecks the stored user's block and identity policy
  inside its insertion transaction. Other first-factor login errors expose
  only `ErrCeremony` and a bounded `webauthn.Reason`.
- Added scrubber keys for WebAuthn response material at any casing/depth,
  including JSON encoded in strings. Service operations register parsed
  response fields, challenges, handles and native sessions in the existing
  flow credential masks; tests verify free-text outcome attribution cannot
  carry those values. No ceremony outcomes or HTTP/session flows are emitted
  by this service; Tasks 9–15 own those consumers and their policy hooks.
- App constructs the service with the deployment RP policy and supplies
  `server.Deps.Passkeys`. No new dependency, generated file or module changed.
- Controller-approved contract ruling: registration JSON does not contain the
  WebAuthn user handle, so the initial plan's options/finish interface could
  not preserve the offered handle across requests. `Issue` now generates or
  reuses it and persists it in the challenge's binding metadata; `Issued`
  gains `UserHandle`. `CreationOptions` takes `ch, userHandle []byte`.
  `Take` returns `*Taken{Challenge, UserHandle, Binding}` from the consumed
  row. `Enroll`/`Signup` take `raw []byte, taken *Taken`, replacing the old
  raw/challenge/binding arguments. `Login` keeps its original arguments.
  Only server-produced `Taken` is accepted by consumer code. Cost if wrong:
  subsequent tasks must adapt to the explicit metadata contract. This avoids
  storing a handle different from the one the authenticator registered.
- Controller-approved handle race ruling: insert first to acquire the
  store's per-user write lock, then compare the offered handle with the
  canonical preexisting credential in the same transaction; a mismatch
  rolls back and requires new options. Exclude the just-inserted row from
  that comparison. Linked accounts can retain different original handles;
  choose the oldest `CreatedAt` (ID breaks ties) for later enrollment and
  verify every assertion against its credential's own saved handle. Cost if
  wrong: a racing first enrollment retries; linking never rewrites a handle
  that the browser already saved.
- Storage ruling: keep `MFAChallenge.Kind = "webauthn"`, as Task 4's
  no-existing-user path requires. Exact purpose and draft/enrollment user ID
  remain in binding metadata. This supports signup before the user row
  exists without changing a driver or a foreign key. Cost if wrong: future
  purpose-specific storage filtering must inspect binding metadata.
- Lifetime ruling: `Issue` treats native TTL as the navigator timeout and
  adds the documented grace only to expiry; nonpositive values use defaults,
  and longer supplied lifetimes are capped. Hosted bindings need transaction
  and cookie; native bindings need client and realm. All fields, including
  origin-list order, compare exactly. Cost if wrong: callers supplying a
  precomputed native expiry must instead supply the timeout.
- Identifier ruling: caller-supplied `UserDisplay` resolves linked or special
  connection identifiers; the default uses email, phone, username and skips
  explicitly inactive flexible identifiers. Older connections without
  flexible attributes retain identifier fallback. Cost if wrong: a caller
  must supply the documented identifier explicitly.
- TDD evidence: initial focused runs failed on the absent service and 24
  scrubber-key cases. Additional concrete red tests demonstrated unavailable
  storage still being offered, stale blocked-user enrollment, inactive email
  selection, response fields escaping free-text masks, and post-link
  enrollment refusal. Each was fixed and the focused command passed.
- Verification environment: every Go command used `GOTOOLCHAIN=go1.26.10`,
  `TMPDIR=/mnt/nvme2/tmp/plan33b-task8` and the same `GOTMPDIR`.
  Final focused `go test ./internal/passkey ./internal/logscrub -count=1`
  exited 0. Final `go test -race -v ./internal/passkey ./internal/logscrub
  -count=1` exited 0, including 20-way challenge/counter races, competing
  first-handle enrollment, cross-instance handle preservation, atomic signup
  rollback and linked-handle login. No selected tests skipped.
  `go test ./internal/app ./internal/server ./internal/login ./internal/oauth
  ./internal/mfa ./internal/mgmt -run '^$' -count=1` exited 0; this only
  compiles, with no tests selected. `git diff --check` exited 0.
- No SQL, external-service, browser or broad regression suite ran in Task 8;
  Task 19 retains full regression ownership. Only this implementer monitored
  the short focused commands; no agents were spawned. Detailed commands,
  logs, actual failures/exits and snapshot identity are in
  `.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/task-8-report.md`;
  consumer migration details are in `shared-contract.md` beside that report.
  Controller review owns the final completion gate.

Task 8 review: spec and quality approved; captured/asserted the intentional invalid-host warning in TestEffective, focused test exit 0 (0.015s). No deferred findings.

## Task 9: Hosted passkey login and session methods

- Base `8ba64e84545121adcefd5f145cf38424a8733abd`; verified implementation tree `829eec33ba1d483214784884ad6f1de92bb25ea9`; branch/worktree unchanged. Status: **implementation verified / controller review pending**. Detailed commands, logs, red→green findings, actual exits, snapshot and limits: `.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/task-9-report.md`.
- Hosted discoverable options and inline nonce-bound script; explicit/conditional cancellation; POST ceremony with exact transaction/browser/origin/RP/client/realm binding, generic errors, blocked-user answer, CAPTCHA/protection and normal authorization continuation. Token-exchange test proves no passkey-only `amr`; MFA, consent, organizations and Actions tests exercise their real handlers.
- Session Start accepts performed methods; password, federated, email, sms and MFA callers now record them. Controller authorized missing storage integration: atomic Sessions.AddMethod across memory/SQL/gRPC, additive protobuf regenerated, existing webauthn.v1 old-plugin omission retained without losing concurrent session writes.
- Controller authorized activating the hosted failure log before Task 16, which otherwise silently discarded it. Successor retry transactions copy only validated server-side authorization state, preserve original expiry/client/org constraints and cookie path, and mint their own browser/CSRF binding; retry creation creates no session and clears no protection budget. Prior cookie is expired.
- Unknown assertion failures spend the shared login-IP budget through protection passkey-login-failure and RecordFailure; valid possession uses flow=login with the exact enrolled linked identity's identifier, obeying blocks and resetting failures on success.
- Required focus, affected regression packages, final retry/double-submit race check, atomic append on memory/SQLite/gRPC (including SQLite backend), old-plugin behavior and five Node script tests passed with actual exit0. Initial compiler, replay/log-fixture and catalog failures are preserved in the report.
- A grouped-slash selector accidentally ran broader storage conformance than intended, once: memory 6.913s, SQL 329.371s, gRPC 337.708s, actual exit0. It finished naturally before a scope-correction stop attempt found no process; never label it terminated. Correct narrow verbose runs had already started per preceding controller request. No full ./..., broad browser E2E, push/merge or subagents. PostgreSQL/MySQL DSNs absent: not selected, not passing. Nonverbose package logs do not enumerate internal skips.

### Task 9 required SQL dialect follow-up

- Corrected the initial coverage limitation: absent ZA_TEST_POSTGRES_DSN/ZA_TEST_MYSQL_DSN did not establish backend unavailability; Task 7 had already used the provisioning runner successfully.
- Ran once on commit `402362a6d3539f8466016d29bc7c7f15e3f05933`, tree `7c5f01ddea8175a19d170cb4dd874b70534386e2`: `GOTOOLCHAIN=go1.26.10 TMPDIR=/mnt/nvme2/tmp GOTMPDIR=/mnt/nvme2/tmp ./scripts/test-sql.sh -v -timeout=15m ./internal/store/sqlstore -run '^TestConformance$/.*/^WebAuthn$/^Session(AuthMethodsRoundTrip|MethodsAtomicAppend)$'`.
- Actual exit **0**, package runtime 9.040s. Both SessionAuthMethodsRoundTrip and SessionMethodsAtomicAppend passed on SQLite, PostgreSQL and MySQL: six PASS, no failures/skips. Session handle 27709, sole implementer monitor using a blocking process wait; no routine polling or overlapping rerun.
- Evidence: `.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/task-9-all-dialects.log` and matching `.exit`; detailed report updated. No implementation edits. Implementation verified / controller review pending.

### Task 9 controller review fix round 1: late duplicate recovery

- Base `69ee8004d614262427bf0888e64aa5941ce06e64`; verified Go implementation snapshot before documentation `4f6987a420cd2d2489d84ee436f5735671a7dedc`. Status: **focused passkey checks verified / controller re-review pending**. Affected login regressions retain the baseline timeout below; no complete-regression claim.
- Review found the existing concurrent-submit test barrier excluded a queued duplicate that first loads after the winner deletes the authorization transaction. Such a request had no usable login-id retry. The new deterministic late-duplicate regression failed red (actual exit1), then the focused implementation run passed (actual exit0); retained `task-9-review1-{red,green}.log/.exit` beside the detailed task report.
- Controller-approved ruling: save an immutable server-side AuthTransaction plus selected connection ID in existing no-user MFAChallenge metadata, Kind=webauthn, with a deterministic namespaced hash ID and original expiry. Normalize mutable hosted form state; accept a uniqueness conflict only for the exact saved immutable identity/expiry and never overwrite it. Cost: one snapshot row per transaction that offers passkeys, using existing expiry/purge behavior.
- When the original transaction is absent, validate tenant, exact origin, original cookie hash, posted CSRF and expiry; reload current client/connection/organization policy. Posted authorization parameters supply no authority. Issue only a generic failure and bound successor with fresh state/CSRF/cookie/challenge at the original deadline. Recovery returns before assertion verification or session creation. The regression proves one prior session, a usable fresh retry, preserved authorization parameters, binding/revocation refusals, collision refusal and event/log secret exclusion. Snapshot material is masked and never added to events, Actions or console data. Self-review traced the early return and bindings; no further blocker found in the scoped fix.
- Interrupted race/regression handles42561/16033 were unavailable on resumption; their logs had ok output but no `.exit`, so no actual exit was inferred. Old secret-check output likewise lacks an exit file. No Go test process remained. Resumed verification used Go1.26.10 and TMPDIR/GOTMPDIR=/mnt/nvme2/tmp, one monitor, retained handles, blocking waits and explicit `.log/.exit` files. No new agents or broad suites.
- `go test -race ./internal/login -run 'HostedPasskey|LoginIDPasskey|WebAuthnError' -count=1`: handle39644, actual exit0, login6.295s; `task-9-review1-resumed-race.log/.exit`. Includes new recovery, bindings, collisions and secret assertions. Nonverbose output does not enumerate skips.
- `go test ./internal/login -run 'IdentifierFirst|Organization|Consent|Captcha|HostedLogin|HostedOutcome' -count=1`: handles69115 and93622, both actual exit1; `task-9-review1-resumed-regression{,-final}.log/.exit`. Both failed `TestIdentifierFirstConcurrentPassword` at identifier_test.go:221, `first authentication stuck` (205.73s/package265.290s; 60.12s/package119.996s). The second run followed the recorded failure and baseline comparison; no further retries.
- On unchanged fix, isolated `go test ./internal/login -run '^TestIdentifierFirstConcurrentPassword$' -count=1 -v -timeout=5m`: handle84216, exit0, test0.53s/package0.671s; `task-9-review1-identifier-investigation.log/.exit`. Baseline comparison replaced all three changed Go files with exact HEAD69ee800 source via `/mnt/nvme2/tmp/task9-review1-baseline/overlay.json`, without editing the worktree. `go test -overlay=/mnt/nvme2/tmp/task9-review1-baseline/overlay.json ./internal/login -run '^TestIdentifierFirstConcurrentPassword$' -count=1 -v -timeout=5m`: handle59905, exit1, same failure, test60.09s/package60.514s; `task-9-review1-identifier-baseline.log/.exit`. The timeout therefore also occurs without this review fix; its underlying intermittent cause remains unresolved. No environmental-cause claim or assertion weakening.
- Next debugging: identifier_test.go:152 uses two SQLite stores and a first-script reached/release barrier; releaseScript runs at214, then the first handler must finish through browser.send (login_test.go:208) before the five-second completion wait at221. SQL Close defers can extend total runtime. Capture the pending goroutine stack before cleanup; the exact stuck stage was not captured here. SQLite uses one connection/store and busy_timeout5000 in sqlstore.go. Controller owns separate baseline-debug resolution and authorized this focused fix commit with failures disclosed. No push or merge; detailed report/ledger retain ruling, evidence and review-pending status.


### Task 9 baseline identifier-concurrency timeout resolution

- Base `423d4484731a3cf75db94f2487e69508deb68933`. Scoped fix verified / controller review pending. Detailed commands, retained log/exit names, handles, exact blocking stacks and limits: `.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/debug-identifier-timeout-report.md`.
- Captured the original `first authentication stuck` failure at its unchanged five-second completion assertion: the released first request had reached Authz.Resume and authCodes.Create, then blocked in database/sql.Tx.Commit → modernc SQLite WAL `_unixSync` → libc.Xfsync → kernel syscall. Actual exit1, test74.75s/package75.175s. A preceding 45-second diagnostic timed out during migration31 commit in the same fsync path (actual exit1). Thus the fixture's disk-sync latency, rather than its release barrier or a Go/store lock, caused the captured timeout. The underlying storage-device latency is not diagnosed; prior baseline failures remain recorded.
- Controller-approved fixture ruling: append `?_pragma=synchronous(OFF)` to this disposable test's DSN, used for both independent SQL handles. Cost: the fixture does not test crash durability, which is outside its concurrency contract. Keep the real file/WAL, both stores, reached/release synchronization, both five-second waits, second-request refusal, first-request success and exactly-one-script assertion. Remove temporary stack instrumentation. No production behavior/settings changed.
- Red→green on Go1.26.10, TMPDIR/GOTMPDIR=/mnt/nvme2/tmp: isolated `go test ./internal/login -run '^TestIdentifierFirstConcurrentPassword$' -count=1 -v -timeout=5m` actual exit0, test4.17s/package4.308s (handle23122). Once after the fix, `go test ./internal/login -run 'IdentifierFirst|Organization|Consent|Captcha|HostedLogin|HostedOutcome' -count=1 -v -timeout=10m` actual exit0, package73.729s, 144 PASS lines and no failures/skips; concurrency test14.40s including setup (handle63631). Same implementer sole monitor, retained `.log/.exit` evidence. No broad suite, stress loop, push/merge or subagents; later full-regression ownership unchanged.
- Tested Go-file SHA256 `6dc80323e146885d67854efd29a0a2954c1441c8aaf6d7ea7d1cf6adc4170fb8`; formatting and `git diff --check` clean.

## Task 10: Hosted passkey signup

- Base `02fdd058d505f44598adce4dc1d7d16ee99c606b`; verified code/test tree before documentation `fa70b27837bd3308e756ec3d0133c81ed1a9f9e9`. Status: **implementation verified / REVIEW PENDING**. Controller approval remains outstanding; Task 10 is not marked complete. Exact commands, log/exit pairs, process handles, failures, limits and self-review are in `.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/task-10-report.md`.
- Effective signup uses identifier/profile entry, passkey creation or a plain POST password choice, and the existing password rules. Non-effective and invitation signup retain the prior page. Server-owned immutable drafts bind stable prospective identity/profile to the authorization/browser/connection and original expiry. Posted profile changes, direct-step requests, stale revisions, origin/browser changes and disabled policy cannot replace that authority. Current profile, identifier proofs, bot policy and final organization/connection rules are rechecked. Invalid RP configuration fails closed.
- Pre-registration Actions run outside storage transactions after the hosted claim; atomic user/passkey insertion, membership and post-registration enqueue commit together. Verification mail, `ss` with `authentication_methods: ["passkey"]`, `user.created`, session method and normal authorization continuation follow success. Password `ss` now carries `["pwd"]`; passkey-only users keep no password and receive normal wrong-credentials password failure. Ceremony data never enters Action bodies or event projections.
- Controller-approved dependencies: the events decorator intercepts atomic passkey user creation and explicitly delegates WebAuthn capabilities; rollback tests prove credential insertion failure leaves neither user nor event. Activate only the required `gd_webauthn_enrollment_failed` catalog emitter before Task 16. Post-rollback classification prevents credential-only uniqueness collisions from disclosing an identifier-exists answer. D-0062 and the shared contract record these rulings.
- Controller-required prepaid admission avoids charging identifier entry and first password completion twice. A separate no-user metadata credit binds draft/transaction/browser/connection/IP and original expiry. CAPTCHA rejection leaves the credit untouched; conditional consumption has one winner; a loser reserves normally before credential checks. Changed IP discards the original credit and uses the new IP's budget. The protection admission flag is in-process only and honored only for signup registration reservation. Capacity-one fallback, repeated-password failure throttling, CAPTCHA retry, concurrent one-winner credit and IP-budget refusal all passed.
- TDD retained actual red results for missing flow/log fields; real event producer/capability omissions; changed phone/bot policy bypasses; invalid RP fallback; credential-conflict privacy; and capacity-one admission double charging. Intermediate fixture compilation mistakes, nil GET form panic and catalog-registry failure are disclosed in the report; all were corrected. No red run is relabeled passing.
- Final current-source command, handle29603: `GOTOOLCHAIN=go1.26.10 TMPDIR=/mnt/nvme2/tmp GOTMPDIR=/mnt/nvme2/tmp go test ./internal/login ./internal/protection ./internal/i18n ./internal/server -run 'PasskeySignup|PasswordSignupLogsPwd|HostedPasskey|LoginIDPasskey|WebAuthnError|Signup|Invitation|Organization|IdentifierFirst|Captcha|HostedOutcome|Catalog|Registration|Suspicious|ProtectionStoreFailure' -count=1 -v -timeout=15m` exited **0**: 366 PASS lines, no failures/skips; login78.171s, protection0.025s, i18n0.008s, server3.937s. Retained `task-10-verified-final.log/.exit`.
- Affected full UI/logrules/events/identity package tests passed in the earlier grouped package run; that command exited1 solely on `TestCatalogMatchesUsage`, then repaired and rechecked above. UI0.066s, logrules1.865s, events2.854s, identity115.289s; no skips. The prior hosted/server selector exited0 (291 PASS lines) before the admission refinement. Credit-specific affected login/protection selector exited0 (153 PASS lines). Seven Node WebAuthn script tests passed, including creation options/attestation and abort-on-password-submit. Formatting and both diff checks passed.
- Each command started once with retained output and actual exit, monitored only by this implementer using blocking waits; no agents were spawned, no suite reran for quietness, and no controller monitored these handles. No full repository suite, broad browser E2E, PostgreSQL/MySQL runner or full SQL/gRPC conformance ran; the hosted selector includes the existing SQLite identifier-concurrency fixture. Task 19 retains remaining broad/backend/browser coverage, never called passing here. No push or merge. Reviewer attention: hosted admission state machine and producer atomicity; no known unresolved scoped implementation failure remains.

## Task 11: Progressive and local passkey enrollment

- Base `50dda06606384e6afff7846ae826920a9543db3e`; final code/test tree staged before documentation `31df68042b5e4c0419a5479f10bb4a290d247367`. Status: **implementation verified / REVIEW PENDING**. Controller review owns the final completion decision. Detailed commands, retained log/exit pairs, process handles, RED→GREEN evidence and limitations: `.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/task-11-report.md`.
- `authz` decides a durable `za_pk_prompt` stage after required MFA and before consent/confirmation/redirect. Progressive enrollment selects fresh password authentication, including successful password signup, with no credential for the effective RP, fewer than 20 total passkeys and no active RP snooze. Local enrollment selects a verified assertion's cross-platform attachment plus the page's platform-capability report. The report and attachment stay outside Actions and events. Missing attachment never selects local enrollment.
- Current browser/session, exact origin, user, connection/client/organization policy, RP and MFA state are rechecked at page access and inside the final answer transaction. The Guardian configuration version invalidates an outdated prompt. A separate single-use no-user `webauthn` answer gate makes concurrent answers produce one redirect; insertion or snooze, gate consumption and transaction deletion commit together. The handlers, session manager and passkey service use transaction-bound copies, avoiding the nested outer-store read deadlock captured in the initial attempt.
- Progressive/local creation have distinct purpose bindings; registration retains the trusted Task 8 handle and atomic maximum. Local creation requests platform attachment, excludes credentials for that RP and refuses a non-platform result. The two normal-form routes preserve hosted revisions, CSRF and browser binding. Completed refresh/back, direct unissued access, another browser and pre-MFA access expire. Attempts to finish pending enrollment through consent or password pages also expire.
- Skip answers only this login. A checked snooze lasts 30 days per user/RP for progressive or per user/hashed random browser cookie for local. Injected-clock tests show progressive enrollment returning on day 31. The shared inline script preserves the enrollment form action, reports platform availability and auto-skips without snoozing when unsupported. No CSP, permissions policy, dependencies or pins changed. Catalog/page text is original.
- Controller ruling: progressive enrollment follows a password signup, including an invitation signup's first password continuation, only after all ownership verification and MFA; passkey signup suppresses progressive enrollment. Tests cover the split password fallback and an invitation remaining blocked until verified ownership. The existing Task 10 fixture explicitly disables progressive enrollment to isolate signup behavior. Cost: one additional skippable prompt after a successful password signup. D-0062 records this and the answer-row, cookie, purpose and configuration-invalidation costs.
- Required Actions effects remain sealed through MFA, enrollment and consent; completed forced-MFA state survives each stage. The final defensive MFA guard in `approve` remains alongside the earlier decision. The first resumed affected run exposed its accidental removal in `TestGateActionForceSurvivesConsentAndCompletes`; restoration passed all 320 full-authz test/subtest results. A new logging regression first failed because enrollment failure lacked `authentication_methods`; adding `["passkey"]` passed it. Success logs `gd_enrollment_complete` with authenticator type `passkey`.
- Final affected check, handle5579: `GOTOOLCHAIN=go1.26.10 TMPDIR=/mnt/nvme2/tmp GOTMPDIR=/mnt/nvme2/tmp go test ./internal/login ./internal/authz ./internal/passkey ./internal/ui ./internal/i18n ./internal/server -run 'Enrollment|Passkey|WebAuthn|MFA|Gate|Consent|Signup|Invitation|Organization|IdentifierFirst|Captcha|HostedOutcome|Catalog|LoginID' -count=1 -v -timeout=15m` exited **0**: 626 PASS lines, no failures/skips; login125.806s, authz4.024s, passkey0.039s, ui0.041s, i18n0.016s, server3.958s. Retained `task-11-verified-final.log/.exit`.
- Final script command `node --test internal/ui/webauthn_test.mjs` exited **0**, 10 passed, no failures/skips, 73.537065ms (`task-11-script-final-3.log/.exit`). Initial harness lookup/asynchronous-timing failures and the later shared-projection assertion mistake are retained honestly. The required original enrollment run `green-5` recorded exit0; earlier missing exit/handle/exact invocation metadata remains explicitly unknown. No completion status was inferred from a log's printed PASS.
- Final race check, handle43087: `GOTOOLCHAIN=go1.26.10 TMPDIR=/mnt/nvme2/tmp GOTMPDIR=/mnt/nvme2/tmp go test -race ./internal/login ./internal/authz -run 'Enrollment|HostedPasskey|Gate.*MFA|GateActionForce' -count=1 -v -timeout=15m` exited **0**: 89 PASS lines, no failures/skips/race reports; login10.545s, authz2.604s. Retained `task-11-race-final.log/.exit`. Formatting and staged/unstaged diff checks passed. No source changes followed the verified staged snapshot.
- Each run retained output, handle and actual status under Go1.26.10 with temporary directories on `/mnt/nvme2/tmp`. This implementer was the sole monitor; no additional agents, broad suite, browser E2E, SQL/backend conformance, push or merge. Task 19 retains broad/backend/browser coverage. The affected hosted selector includes its existing SQLite identifier-concurrency fixture; Plan 19's test hold does not apply to Plan 33b.

### Task 11 review fix round 1

- Base `03635d0ba24172a68c91dad2a5e5451f1682a0ec`; staged code/test snapshot `1f618cc7cc7d0e3f5e9523cbe431e7023d364b1a`. Two Important review findings were reproduced before production edits. Detailed commands, log/status pairs, handles and results are appended to `task-11-report.md`.
- A negative platform-capability result had incorrectly skipped progressive enrollment, preventing roaming registration. The script now applies a negative result only to local enrollment; missing WebAuthn or platform-check APIs still skip either prompt without snoozing. New behavior tests exercise a roaming creation and its bound POST action with UVPAA=false, local negative-capability skip, and missing APIs for both prompt kinds. RED `node --test internal/ui/webauthn_test.mjs` exit1 (11 pass/1 fail) became GREEN exit0 (12 pass/0 fail/0 skip,54.072561ms); retained `task-11-review1-script-{red,green}.log/.exit`.
- A nested organization transaction flushed its staged membership success log before the outer enrollment answer committed. The outer operation now uses `orglogin.WithMembershipEvents`; its returned context is installed on the request used by nested policy, membership, enrollment and store calls. Cost: a recreated membership's success log waits for the complete enrollment commit. The new hosted behavior regression removes automatic membership while enrollment is pending, then checks that invalid registration leaves no membership and no success log, and valid registration commits membership with exactly one log. RED handle7765 actual exit1 observed status400/member=false/event count1; GREEN handle40326 actual exit0, parent and both cases passed,login0.253s. Retained `task-11-review1-membership-{red,green}.log/.exit`. D-0062 records both corrections and the commit-bound event cost.
- Focused race command `GOTOOLCHAIN=go1.26.10 TMPDIR=/mnt/nvme2/tmp GOTMPDIR=/mnt/nvme2/tmp go test -race ./internal/login -run '^TestEnrollment(MembershipEventsCommitAndRollback|PromptConcurrentAnswer)$' -count=1 -v -timeout=10m`, handle48358, actual exit0: four PASS lines, no failures/skips/race reports,login2.382s. Retained `task-11-review1-race.log/.exit`.
- Final affected command `GOTOOLCHAIN=go1.26.10 TMPDIR=/mnt/nvme2/tmp GOTMPDIR=/mnt/nvme2/tmp go test ./internal/login ./internal/authz ./internal/orglogin ./internal/ui -run 'Enrollment|HostedPasskey|Gate|Organization|Consent|WebAuthn|LoginID|Membership|Invitation' -count=1 -v -timeout=15m`, handle98175, actual exit0:391 PASS lines, no failures/skips; login142.476s, authz2.370s, orglogin0.140s, ui0.014s. Retained `task-11-review1-affected.log/.exit`. Source stayed unchanged after the recorded staged snapshot; formatting and both diff checks passed. Status: **implementation verified / scoped re-review pending**. This implementer alone monitored retained sessions with blocking completion waits, with no active log scans, quietness-driven rerun, broad suite, new agent, push or merge.

## Task 12: WebAuthn security-key MFA

- Base: `a38387d5837a9b201a0871b5c5d84500a99d1177`, worktree
  `/mnt/nvme2/code/zeroauthy-plan33b`, branch `plan-33b-passkeys`.
- Added roaming enrollment and assertion services using `ParamsFor`,
  passkey `Issue`/`Take`, persisted per-factor throttles and proof commits.
  Hosted detection, registration, nickname, recovery, success, assertion and
  remember-browser paths use the existing CSRF/revision/session guards.
  Actions and Guardian enrollment tickets now accept the enforced factor.
- Added the operator GET/PUT UV settings extension and exact target-tenant
  authentication binding. Stored key is `webauthn-roaming/settings`; default
  is `discouraged`, and only `discouraged`, `preferred`, `required` are accepted.
  No v2 route or generated API edit was introduced; Tasks 14/15 own generation.
- Binding ruling: `WithWebAuthnBinding` receives the server's full RP/origin,
  transaction, cookie hash, client, connection and organization binding. Empty
  or mismatching binding fails closed; metadata from a submitted form is never
  deserialized as trusted ceremony state. Cost: downstream consumers must pass
  this explicit request-local binding.
- Persistence ruling: namespaced `Kind=webauthn` options/verified rows retain
  authoritative factor, parameters and enrollment restrictions. Registration
  spends its ceremony before parsing; a verified credential, without raw
  browser response, survives nickname retries and service replicas. Its
  conditional consumption, insertion, first recovery and ticket callback share
  one transaction and the original expiry. Cost: three expiring registration
  rows and a fresh ceremony after expiration.
- Decision ruling: provisional authorization only determines whether detection
  is needed. No factor is offered before detection; an absent browser result
  disables WebAuthn, retaining alternate methods and recovery. Only current-RP
  credentials count for enrollment/challenge and first-only restrictions.
  Cost: one additional hosted form submission when a WebAuthn factor is possible.
- UV remains enforced if an operator tightens the setting after issuance or
  registration verification. Existing imported roaming methods can verify an
  assertion with no user handle; a supplied handle still requires a match.
  Cost: imported methods returning an unrecorded handle require metadata repair.
- Controller approved pulling the small shared passkey exclusion in
  `resourceview.Multifactor` forward from Task 14: passkeys alone must not mask
  the first/last MFA change or its transactional `user.updated`. A red event
  regression reproduced it. Broader Management projections remain Task 14.
  The roaming reset capability/screen hook was also tested here; platform and
  device progression remain Task 13. Cost: these narrow producer integrations
  arrive earlier than their surrounding task.
- Required WebAuthn failure log codes were already activated by Tasks 9/10;
  Task 12 records the new producers and emits bounded reasons, factor type and
  `first_factor:false`. Secret masking includes decoded and encoded credential
  components. Existing decorators/outbox own user-change events.
- Final focused/catalog verification: 39 PASS/no failures/skips, actual exit 0;
  complete affected core packages: 966 PASS/no test failures/skips, actual exit 0
  (`resourceview` has no test files; events exercises the predicate). Browser
  script: 14 PASS/no failures/skips, exit 0. Code/test tree
  `e92695201047970e9ee6994de44c82ab4f8204cb`. Hosted/management/server: 315 PASS/no failures/skips,
  actual exit 0. Initial focused race: 36 PASS/no failures/skips/race reports, actual exit 0 (pre-guard correction). Evidence and every preliminary failure are in
  `.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/task-12-report.md`.
  Full `./...` and broad browser coverage remain Task 19 and are not claimed
  passing. No subagents, push or merge.

Task 12 final guard correction: scoped self-review found that recognizing
roaming methods in the shared predicate made an only-foreign-RP key block
ordinary first-only OTP/email confirmation after the hosted decision offered
it. It also exposed a no-script path where an owned unavailable key could
lead to fresh OTP enrollment instead of an existing proof. Three focused RED
regressions reproduced both decision and confirmation failures plus the hosted
redirect loop (`task-12-guard-red.log/.exit`, session 81835, exit 1). Added an
ordinary guard-only `WithWebAuthnRPID` view, populated from the hosted server's
resolved RP; it grants no WebAuthn issuance/verification authority. Full binding
also supplies this scope. Decide now refuses that unavailable-owned-key
fallback unless a trusted Action explicitly requested enrollment. Cost: users
with no usable alternate/recovery proof see the unavailable page rather than
enroll around their key. Per controller direction, the final delta repeats
full MFA tests, bounded login regressions and focused guard races; unchanged
packages retain the earlier green results rather than rerunning broad checks.

Task 12 implementation verified / REVIEW PENDING. Final guard-correction code/test
tree `ed5919dbf25bfe7cad63f4fea8421eed6f2da364`; final full MFA: 97 PASS, bounded
login: 185 PASS, guard race: 42 PASS, all actual exit 0 with no failures or test
skips, and no race reports. Exact final commands (all with
`GOTOOLCHAIN=go1.26.10 TMPDIR=/mnt/nvme2/tmp GOTMPDIR=/mnt/nvme2/tmp`):

- `go test -json ./internal/mfa -count=1 -timeout=15m`
  (`task-12-guard-mfa.log/.exit`, sequential session 38822).
- `go test -json ./internal/login -run 'MFA|WebAuthn|Roaming|Passkey|ResetPostChallenge|HostedPhone|PhoneMFA' -count=1 -timeout=20m`
  (`task-12-guard-login.log/.exit`, same sequential session).
- `go test -race -json ./internal/mfa ./internal/login -run 'WebAuthn|Roaming|EnrollConcurrent|EnrollNewFactorConcurrent|MFAEnrollmentConfirmRace|MFAConfirmFirstEnroll|MFAOTPConcurrentSubmit|MFATicketConcurrentNoMultiple' -count=1 -timeout=20m`
  (`task-12-guard-race.log/.exit`, session 73139).

Pre-correction snapshot `e92695201047970e9ee6994de44c82ab4f8204cb` retained the
39-test focused/catalog run, 966-test full affected core run, 315-test bounded
hosted/management/server run and 36-test initial focused race, all exit 0.
`resourceview` had no test files; its predicate is exercised by the events
regression. Unchanged script tests passed 14/14 with exit 0. Per controller,
unchanged packages were not rerun after the guard correction. All preliminary
failures, invalid first imported-key RED setup, exact commands, process handles,
actual statuses, snapshot limits and deferred breadth are retained in
`task-12-report.md`; none are omitted or called passing. Final scoped review,
formatting and diff checks found no remaining blocker. The implementation commit
containing this entry is recorded by SHA in the retained report and progress
ledger after creation. Controller owns final review and task completion.


### Task 12 review round 1 — requested-factor exclusions and legacy capability

Base `5ccc548b070132aad08be3bfd9b54494f28376b6`; final verified source/test
snapshot `4fc2c5ba8977c2bd077d1bb5e15dc376b880572d`. Registration now excludes only the user's requested factor at the
current RP, allowing a security key holding a passkey/platform credential to
remain available for roaming MFA enrollment. Authorization preserves the valid
RP scope even when `webauthn.v1` is absent; legacy MFA list results still count
as enrolled for confidence policy and recovery. Availability still gates the
ceremony and detection. Existing alternate/recovery proof is required, with
access denied if no proof is usable. The ordinary all-applications guard was
already protected and is unchanged. Costs and consumer duties are in D-0062
and the shared contract; no new RPC, storage state or ceremony authority.

Focused tests first reproduced the authorization bypass (no-fallback and
recovery cases issued codes, existing OTP correctly challenged), session 9413,
`task-12-review1-red.log/.exit`, actual exit 1. The initial registration fixture
failed before exclusions because its synthetic passkey lacked a handle; this
is retained as setup failure, not exclusion RED evidence. Correcting the
fixture produced exclusion RED4807, actual exit 1: passkey/platform IDs were
included. Minimal fixes followed, then focused GREEN39106, actual exit 0,
5 passing tests/subtests, no failures/skips. Exact commands, log paths and
snapshot limits are in the Task 12 retained report. All Go commands use
`GOTOOLCHAIN=go1.26.10 TMPDIR=/mnt/nvme2/tmp GOTMPDIR=/mnt/nvme2/tmp`.
Final verification on that unchanged snapshot:

- `go test -json ./internal/mfa ./internal/authz -run 'TestWebAuthnEnrollExcludesOnlyRequestedFactorAtOwnedRP|TestGateWebAuthnUnavailableConfidenceRequiresExistingProof' -count=1 -timeout=5m`
  — session 39106, `task-12-review1-green.log/.exit`, actual exit 0,
  5 PASS/no failures/skips.
- `go test -json ./internal/mfa ./internal/authz ./internal/login -run 'WebAuthn|Roaming|Gate' -count=1 -timeout=15m`
  — session 38444, `task-12-review1-affected.log/.exit`, actual exit 0,
  69 PASS/no failures/skips.
- `go test -race -json ./internal/mfa ./internal/authz ./internal/login -run 'WebAuthn|Roaming|Gate' -count=1 -timeout=15m`
  — session 96266, `task-12-review1-race.log/.exit`, actual exit 0,
  69 PASS/no failures/skips/race reports.

Retained logs/exits and report/ledger live in
`.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/`.
One monitor used blocking completion waits without active-log scans or reruns
due to quietness. The first RED used baseline production source; the second
used baseline MFA source and the corrected final exclusion fixture. Self-review
found no remaining blocker in the two fixes. Post-run source/test snapshot
comparison, formatting and staged/unstaged diff checks pass. IMPLEMENTATION
VERIFIED / SCOPED RE-REVIEW PENDING; controller owns approval. Prior Task 19
broad/dialect/real-browser/hardware deferrals remain. The resulting commit SHA
is recorded in the retained report/ledger after creation. No broad suite,
subagent, push or merge.

### Task 13 — Device biometrics, reset screens and MFA API

IMPLEMENTATION VERIFIED / REVIEW PENDING. Base
`c373f03007ac2a95b4d37bc8a9a363e2bae818b6`; final renderer source/test snapshot
`c836e65d8a30c6955d7406d3c705a71a2071396d`. Worktree/branch remain
`/mnt/nvme2/code/zeroauthy-plan33b`, `plan-33b-passkeys`.

Platform enrollment follows successful proof with another MFA factor, including
explicit Actions and tickets. Trusted proof comes from sealed hosted state and
is persisted only in bound service metadata. Another confirmed enabled primary
method must still exist at issue/commit; passkeys and recovery records do not
qualify as that method. Device class uniqueness is checked inside the existing
user-lock transaction; challenge allow lists use the saved user-agent device
key, and platform UV is always required. Current RP ownership remains independent
of plugin/browser capability, preserving the Task12 confidence/recovery guards.

Ordinary progression offers 14-day remind, 365-day refuse (durable row and bound
secure cookie), and login-only skip. Names default to browser/OS labels, with the
existing validated nickname screen. Both WebAuthn reset screens complete actual
password resets. MFA API lists/deletes confirmed WebAuthn methods, excludes and
protects passkeys, and rejects WebAuthn associate/challenge operations. Platform
is activated in the frozen factor and Actions inventories. Guardian permits
platform alone and returns boolean `requires_other_factor` on its platform row;
other rows omit it. This optional zeroauthy schema extension and its generated
Go type were pulled forward with controller approval. Costs: older strict
response schemas need the optional property; explicit enrollment requires another
proof; same-class devices can be refused as specified by LR33b-19.

Controller ruling permits optional progression after a successful recovery proof
only while another confirmed enabled primary method remains. Recovery does not
establish eligibility. Cost: an extra optional prompt after recovery. Final
renderer correction hides a broken another-method loop during platform enrollment
and nickname entry; challenge alternatives remain. No route or policy changed.

All Go commands use `GOTOOLCHAIN=go1.26.10 TMPDIR=/mnt/nvme2/tmp GOTMPDIR=/mnt/nvme2/tmp`.
Detailed commands, actual statuses, failures and snapshot limits are retained in
`.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/task-13-report.md`
and its log/exit files. Meaningful REDs reproduced unsupported platform rules,
missing progression/reset/API listing, platform-only/unavailable explicit guards,
recovery progression and the broken alternate-method link. Intermediate fixture
errors, a compile edit error and the initial lost process-handle recovery are
explicitly disclosed, never counted as feature RED or passing evidence.

Verification:

- Focused eleven-package Task13/catalog selector: session37085, exit0,
  19 PASS/no failures/skips. Packages without selected tests establish compilation.
- Full affected core/API: session45395, `task-13-affected-core.log/.exit`, exit0,
  856 PASS/no failures/skips at snapshot4667f3c00298bfb938062eb3ac0141d54735f5aa.
- Bounded login/OAuth/management/server: same retained chain, hosted exit1,
  381 PASS/one fixture FAIL/no skips. Only the new repeated-login snooze fixture
  replayed a TOTP step; its clock advance was restored. OAuth, management and
  server selected cases passed. The planned race had not run at this failure.
- Final recovery delta: session84959 at snapshot4fd13ef0371674f90a75c774fbbc84cbc1c6e666,
  focused login15 PASS, affected login205 PASS and scoped mfa/login/authz race87
  PASS; all actual exit0/no failures/skips/race reports. Unchanged core/other
  hosted-package results remain attached to their earlier snapshot.
- Final renderer-only delta: RED7393 exit1 reproduced five broken-link cases;
  GREEN41961 exit0, 11 PASS/no failures/skips at final snapshotc836e65d8a30c6955d7406d3c705a71a2071396d.
  Selector covers platform enrollment/nickname, roaming alternatives and both
  reset types, including a platform challenge alternative-method assertion.
- `make generate`: session12200, actual exit0; only the approved Guardian schema
  generated type changes. Pins unchanged.

One implementer monitored retained processes with blocking completion waits;
commands were not rerun for quietness. No full repository suite, broad browser
suite, subagent, push or merge. Task19 broad/dialect/real-browser/hardware checks
remain deferred and are not labelled passing. Self-review covered the requested
rules, trusted proof/ticket boundaries, atomic class refusal, RP/UV filtering,
snooze clocks/cookie, reset completion, API exclusion and warning contract. The
identified guard, recovery and navigation findings were reproduced and corrected.
No known remaining blocker. Formatting, staged/unstaged diff checks and final
source-snapshot comparison pass. Controller owns review and task completion;
the resulting commit SHA is recorded in the retained report/ledger after creation.


## Task 13 review round 1 — enrollment alternatives and controls

Base `78b73d0fc4f15f14d02e19d29125781be285f886`; implementation source/test
snapshot `e707a3703c494a22e91260c1eba76e99a80e8f34` (retained in
`task-13-review1-code-tree.txt`). IMPLEMENTATION VERIFICATION RUNNING /
SCOPED RE-REVIEW PENDING. No architecture blocker, subagents, broad/full suites,
push or merge. All Go commands below use
`GOTOOLCHAIN=go1.26.10 TMPDIR=/mnt/nvme2/tmp GOTMPDIR=/mnt/nvme2/tmp`.

Reviewer findings confirmed and addressed:
- Important 1: platform presence in `enrollWithAny` replaced requested choices
  with all other factors, then made platform mandatory. Preserve the actual
  requested alternatives, filter unavailable/disabled/enrolled methods, and
  enter the existing mandatory other-proof sequence only after platform is
  selected. A selected OTP enrollment completes the requested Action without
  optional platform progression. Platform selection recomputes trusted decision
  data and persists its target in the existing revision-guarded sealed page;
  no browser input supplies proof authority. Pure platform Actions and tickets
  still require the other proof and mandatory final platform confirmation.
- Important 2: the initial platform presentation flag also rendered deferrals
  during mandatory Action/ticket enrollment, although submission rejects them.
  Split presentation from optional-deferral eligibility. Mandatory screens keep
  their Continue button and omit all deferrals; manual mandatory skip remains
  refused by the existing handler.
- Related minor: optional platform cancellation used the error-screen prefix
  for platform-only control keys. Error retry uses the existing error button
  key, while optional deferrals use their platform enrollment keys. No raw keys
  remain; optional deferral after cancellation completes successfully.

Ruling/cost: mixed Actions retain their requested choice semantics. Another
factor becomes a prerequisite only after platform is the selected target; that
prerequisite cannot substitute for platform completion. A completed Action
request for another enrollment does not add an unsolicited biometric prompt.
The selection incurs the existing store-backed decision reads and sealed-page
revision transition. No schema, capability, RP/origin, UV, ticket-consumption,
trusted-proof, or service-insertion boundary changes. Current-RP same-class
platform enrollment is filtered; foreign-RP methods do not suppress eligibility.

RED/GREEN evidence, logs and actual-status files beside this report:
- `go test -json ./internal/mfa ./internal/login -run '^(TestPlatformEnrollWithAnyKeepsAlternatives|TestPlatformActionEnrollmentAlternatives|TestPlatformActionChoiceRequiresOtherProof)$' -count=1 -timeout=15m`
  session1480, `task-13-review1-mixed-red.log/.exit`, actual exit1. Unit RED
  shows unrequested email substitution/mandatory platform when available and
  ErrNoFactor despite OTP when unavailable/disabled. Hosted fixtures initially
  expected303 for an existing302 login gate; those setup failures are NOT
  claimed as meaningful hosted RED (10 FAIL events total, no passes/skips).
- `go test -json ./internal/login -run '^(TestPlatformActionEnrollmentAlternatives|TestPlatformActionChoiceRequiresOtherProof|TestPlatformMandatoryActionControls|TestPlatformRulesTicketOtherProofFirst|TestPlatformOptionalEnrollmentErrorControls)$' -count=1 -timeout=15m`
  session59886, `task-13-review1-hosted-red.log/.exit`, actual exit1; corrected
  login-gate fixture. 10 FAIL events/no passes/skips: missing requested platform
  choice; unavailable/no-script detection400 despite requested OTP; selection400;
  mandatory Action and both ticket sequences exposing optional deferrals; error
  controls showing raw catalog keys. These are meaningful hosted RED results.
- `go test -json ./internal/mfa ./internal/login -run '^(TestPlatformEnrollWithAnyKeepsAlternatives|TestPlatformActionEnrollmentAlternatives|TestPlatformActionChoiceRequiresOtherProof|TestPlatformMandatoryActionControls|TestPlatformRulesTicketOtherProofFirst|TestPlatformOptionalEnrollmentErrorControls)$' -count=1 -timeout=15m`
  session18022, `task-13-review1-green.log/.exit`, actual exit0, 15 PASS events,
  no failures/skips. This interim snapshot precedes the final test extensions:
  selected platform now completes registration/nickname/login; mandatory manual
  skip is refused; enrolled/current-RP/foreign-RP alternatives are asserted.

Final frozen-snapshot commands run once sequentially under retained session74894:
1. `go test -json ./internal/mfa ./internal/login ./internal/authz ./internal/ui ./internal/i18n -run 'Decide|MFA|Platform|WebAuthn|Roaming|Gate|CatalogMatchesUsage' -count=1 -timeout=15m`
   `task-13-review1-affected.log/.exit`.
2. `go test -race -json ./internal/mfa ./internal/login ./internal/authz -run 'Decide|Platform|WebAuthn|Roaming|Gate' -count=1 -timeout=15m`
   `task-13-review1-race.log/.exit`.
The chain stops on an actual failure. Sole implementer uses blocking completion
waits; no active-log scans or routine process checks. Results remain pending
until completion. Task19's broad/dialect/hardware/browser checks remain deferred,
not passing. No tests silently skipped. Parent controller owns scoped re-review.


Review1 final-extension fixture correction: affected chain74894 returned actual
exit1 (`task-13-review1-affected.log/.exit`), 126 PASS/one FAIL/no skips.
`TestPlatformActionChoiceRequiresOtherProof` completed platform registration and
nickname, then panicked in `mfaFixture.post` because its form-map argument was
nil. Replaced only that fixture call with `url.Values{}`; no production delta.
The scoped race had NOT RUN and is not passing. This is a test fixture failure,
not an implementation regression or a meaningful new RED result.

Corrected final source/test snapshot `6102e6828a666ded6b29645137b9e7148f63cc9c` is retained in
`task-13-review1-final-code-tree.txt`. Retained session55877 runs the same affected
command to `task-13-review1-affected-2.log/.exit`, then the same scoped race command
to `task-13-review1-race.log/.exit`, stopping on actual failure. Commands run once
for this corrected snapshot, sole implementer uses blocking completion waits.
Results pending. No broad suites, subagents, push or merge.


## Exact completed-enrollment validation

Corrected affected chain55877 returned actual exit1
(`task-13-review1-affected-2.log/.exit`), 207 PASS/one FAIL/no skips.
`TestPlatformActionChoiceRequiresOtherProof` completed registration/nickname,
then received callback `access_denied`: the original mixed enrollment was
re-evaluated after both requested types had become enrolled, so no NEW candidate
remained. This is a meaningful dependent completion RED. Race still had NOT RUN.

Controller approved minimal trusted completion handling, requiring exact factor
binding and live disabled/capability/RP/unproven guards. The final proven hosted
enrollment page passes its server-owned factor to `MFAComplete`. Its trusted
context marker is separate from the session's ordinary MFA completion marker.
Authorization checks membership in the original requested enrollment alternatives
and validates only that exact confirmed factor as a live challenge before
satisfying the forced prompt. It does not mutate the original Effects. Missing,
unrelated or unproven enrollment markers cannot satisfy explicit enrollment;
platform's intermediate other-factor proof never reaches this final path.
Consent carries the marker only in its server transaction, tied to the same
session's exact MFA timestamp, and restores it only after that timestamp matches.
Cost: one internal optional completion argument and a server-only consent field;
there is no browser, public API, plugin or schema extension. Factor enablement,
capability revocation, current RP/device eligibility and platform's separate
other-proof insertion guard remain enforced.

`go test -json ./internal/authz ./internal/login -run 'TestGateCompleted(Enrollment|PlatformEnrollment)|^TestPlatformActionChoiceRequiresOtherProof$' -count=1 -timeout=15m`
with the stated Go1.26.10/tmp prefix, session24857,
`task-13-review1-completion-green.log/.exit`, actual exit0: 14 PASS,
no failures/skips. Covers actual platform-choice registration/nickname/login,
exact requested factor vs unrelated/missing/unproven marker, disabled factor,
platform current/foreign RP, revoked capability, original Effects immutability,
and consent continuation. The final source/test tree is now
`e726b9f4d4c188840d058aeb61aae5b847a94603` (`task-13-review1-verified-code-tree.txt`); earlier snapshots are not
relabeled. Session92654 runs once: the same affected command to
`task-13-review1-affected-3.log/.exit`, then the same scoped race command to
`task-13-review1-race.log/.exit`. Sole monitor blocks for completion; no active-log
scans. Results pending; SCOPED RE-REVIEW PENDING. No optional expansion, broad
suites, subagents, push or merge.


## Review1 final verification and self-review

Final chain92654 completed actual exit0 at unchanged source/test snapshot
`e726b9f4d4c188840d058aeb61aae5b847a94603`:
- `task-13-review1-affected-3.log/.exit`: actual exit0, 221 PASS/no failures/skips
  (mfa64, login98, authz47, ui11, i18n1). Exact command, with the stated prefix:
  `go test -json ./internal/mfa ./internal/login ./internal/authz ./internal/ui ./internal/i18n -run 'Decide|MFA|Platform|WebAuthn|Roaming|Gate|CatalogMatchesUsage' -count=1 -timeout=15m`.
- `task-13-review1-race.log/.exit`: actual exit0, 144 PASS/no failures/skips or
  race reports (mfa64, login33, authz47). Exact command, with the stated prefix:
  `go test -race -json ./internal/mfa ./internal/login ./internal/authz -run 'Decide|Platform|WebAuthn|Roaming|Gate' -count=1 -timeout=15m`.

No package lacked selected tests in these runs. Source comparison
`git diff e726b9f4d4c188840d058aeb61aae5b847a94603 -- internal` is empty.
`git diff --check`, `git diff --cached --check` and gofmt checks pass. Self-review
checked requested-alternative membership/eligibility, selected-platform-only
prerequisite transition, mandatory Action/ticket controls and manual-skip denial,
optional retry labels/deferral, exact final enrollment proof vs ordinary MFA,
unchanged original Effects, server-only consent continuation, disabled/revoked
capability/current-RP/device filtering and unchanged service/ticket insertion
boundaries. No known remaining finding. The two setup mistakes and dependent
completion failure above are retained, not omitted or called passing.

IMPLEMENTATION VERIFIED / SCOPED RE-REVIEW PENDING. Controller owns approval and
Task13 completion. No full/broad suites, extra audits/agents, push or merge.
Task19 broad/dialect/real-browser/hardware checks remain deferred and are not
passing. Final scoped commit metadata is supplied after creation in the retained
workspace report/ledger and handoff.

## Task 14 — Management passkeys, linked credentials and native settings

Implementation based on `4e7b89cb39b41de8ef50e6b06a39e05f3c63a4d2` in isolated
branch `plan-33b-passkeys`. The authorized predecessor test file was preserved
and extended. Retained workspace evidence is under
`.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/`; details and
actual outcomes are collected in `task-14-report.md`.

The initial predecessor RED log contains six missing-feature failures. The
resumed expanded RED (`task-14-red-2.log/.exit`, session48164, actual exit1)
confirms all nine top-level checks fail on the baseline. Tests correct the
predecessor's full-user-ID identity fixtures to the raw identity convention and
replace invented mobile regex expectations with the fetched public schema.
D-0062 and the shared contract record the public OAS hash, controller ruling,
compatibility costs and Task15 fail-closed association requirement.

Passkey create uses the atomic store API after the user lock; it validates COSE,
identity ownership and handle length, applies default RP and stable-handle
selection, and maps limits/conflicts/capability errors. List/get/rename project
only documented credential fields, with BE/BS-derived flags. MFA-only operations
and recovery eligibility exclude passkeys. Passkey changes suppress Guardian and
resource events while retaining normal scrubbed Management audit logs. Linking
moves credentials before deletion in the existing transaction; unlinking moves
only the selected identity's credentials, preserving saved handles. Tests cover
real assertions before/after unlink and injected post-move transaction failures.
Session views expose recorded proofs and preserve the legacy password view.
Client mobile settings follow actual schema types/defaults/minimum lengths and
are ignored before validation on old plugins. Passkey grant accepted. Deferred
system-extension/mobile/passkey schemas generated with `make generate`; no
hand-edited generated files.

Verification in progress at source/test tree
`badb9e057b3aa9c8ec8a1a6df050e0e51d3800e3` (`task-14-final-code-tree.txt`),
focused session29661. `task-14-generate-final.log/.exit` actual exit0. Initial
generation failed on an implementation YAML indentation error, corrected before
successful generation. First green found two predecessor fixture assumptions:
MFA.UpdateAuthenticator deliberately does not rewrite saved credential metadata,
and normal sapi audit logging is expected. Second green found the new linked-login
fixture had not created a hosted-login configuration. These are disclosed fixture
failures, not passing results. Additional empty-handle RED reproduced an invalid
explicit empty handle being defaulted; the empty-identity and limit failures in
that run also reflect the unintended insert. Both explicit empties are now
validated and failed subtests use distinct credential IDs.

REVIEW PENDING. No full repository suite, broad browser suite, subagents, push or
merge. Task19 dialect/browser/hardware verification is deferred and not passing.

Task14 final verification, unchanged source/test tree
`badb9e057b3aa9c8ec8a1a6df050e0e51d3800e3`:
- focused session29661 `task-14-green-3.log/.exit`: actual exit0,
  29 PASS/no failures/skips (mgmt20, clientrules2, server2, api3, mfarules2).
- final chain61023, `task-14-affected.log/.exit`: actual exit0,
  1,048 PASS/no failures/skips (mgmt877, clientrules5, session17, passkey34,
  mfarules4, events94, api17). resourceview has no standalone test files; its
  new projection is verified through Management sessions.
- `task-14-server.log/.exit`: actual exit0, 61 PASS/no failures/skips in selected
  Management HTTP integration checks.
- `task-14-race.log/.exit`: actual exit0, 23 PASS/no failures/skips or race
  reports (mgmt20, clientrules2, events1). Every selected package ran tests.

Exact commands and prior failure/fixture details remain in task-14-report.md.
Source comparison against the recorded final tree is empty for api/internal.
Whitespace and gofmt checks pass; Management provenance script exit0. Self-review
checked the Task14 requirements, atomic limits/uniqueness, database-identity
ownership, stable handles and RP defaults, public projection and event isolation,
link/unlink rollback and live login resolution, legacy session fallback, mobile
schema/old-plugin handling and generated system-extension routing/scopes. No
known remaining Task14 finding. IMPLEMENTATION VERIFIED / REVIEW PENDING.
No full repository, SQL matrix, broad browser/hardware, console, seed or native
endpoint tests were run for this task. Later plan coverage remains deferred and
is not called passing. No subagents, push or merge. Commit metadata follows in
workspace report/ledger and handoff; controller owns review and completion.

### Task14 review1 — provider-qualified unlink ownership

Review found an Important ownership bug: unlink filtered passkeys by raw identity
ID for every provider. A linked `auth0|X` and `google-oauth2|X` therefore allowed
social unlink to move a database credential to a social-only user, breaking its
next assertion. The capability/move block now runs only for database identities.
No stored handle, metadata, store method or API shape changes. The minor duplicate
passkey enum in MFAAuthenticationMethod was removed; GET still accepts passkey.
Pinned make generate completed exit0; final regenerated Go matches the base
because duplicate enum removal does not change its generated value set.

RED session85648 at source/test tree
`5b338e8739b3e97eaf181043dfdc3dffb73ae562`,
`task-14-review1-red.log/.exit`, actual exit1: normal database linked
login/unlink PASS; provider-collision actual assertion after social unlink FAIL
with bounded verifier reason key. Regression now also runs a real assertion
concurrently with social unlink, verifies afterward primary ownership and saved
handle, no social credentials, and subsequent normal database unlink/login.

Initial fixed-Go chain23392 at tree
`475e3aa34c29a62d7589a33dcc790182aa9af51e`:
focused `task-14-review1-green.log/.exit` actual exit0, 4 PASS/no skips. A mistaken
schema cleanup removed the adjacent GET enum's sole passkey value instead of the
duplicate. `task-14-review1-affected.log/.exit` actual exit1: 41 PASS/3 FAIL
(TestPasskeyWireContracts, TestPasskeyMethodsPatchDelete,
TestPasskeyMethodsNoResourceEvents), no skips. Race did NOT RUN. Corrected exact
named schema and restored GET before regeneration. Two ad hoc source-inspection
scripts also failed (PyYAML rejected pre-existing repeated anchors; a string
section helper used an incorrect boundary); these are inspection errors, not
passing checks or production failures. Final source review confirms one passkey
entry in each schema; generated GET validator retains passkey.

Corrected source/test tree `4c35f7dc01179b121523c28687780a1ee734db0e`
(`task-14-review1-verified-code-tree.txt`), final generate-2 exit0. Chain19266
runs the corrected affected selection, then scoped linking races only on exit0.
Source Go/tests are unchanged from the successful focused4 snapshot. Sole
implementer blocks for completion and forwards stage notices, no active-log
scans or duplicate monitor. No broad suites, subagents, push or merge.
RE-REVIEW PENDING; actual final results follow.

Review1 final chain19266 actual exit0 at unchanged corrected tree
`4c35f7dc01179b121523c28687780a1ee734db0e`:
- `task-14-review1-affected-2.log/.exit`: actual exit0, 44 PASS/no failures/skips
  (mgmt35, passkey1, server5, api3). Every selected package executed tests.
- `task-14-review1-race.log/.exit`: actual exit0, 4 PASS/no failures/skips or race
  reports, including concurrent real assertion/social unlink. Ordinary database
  login/unlink and injected move rollback remain covered.

Source/test comparison to corrected tree is empty; final generated Go matches
base, retaining GET's passkey validator. Named YAML sections each contain one
passkey value. Staged/unstaged whitespace and gofmt checks pass. Self-review
confirms the provider gate surrounds both capability and move, keeps the existing
transaction, preserves saved handles and avoids social credential inheritance.
No known remaining finding in this reviewed scope. IMPLEMENTATION VERIFIED /
SCOPED RE-REVIEW PENDING. No broad reruns, subagents, push or merge. Controller
owns review and completion; commit metadata retained in workspace report/ledger.

### Task15 — Native Passkey APIs, grant and association files

Base `619e6e80a06f066a63f36f4146b8e6cf0f4f8c4e`; isolated branch
`plan-33b-passkeys`. IMPLEMENTATION VERIFIED / REVIEW PENDING. Controller owns
acceptance. Native registration/challenge and the passkey grant now share trusted
single-use bindings, exact RP/origin/client/realm/organization checks, R3
registration/failure budgets, signup Actions and atomic user/credential/events,
post-login Actions, normal token/refresh/MFA/version/block rules. Registration
accepts the documented bounded profile/metadata and existence behavior only after
admission; JSON objects preserve form credential semantics. Association files
serve only usable first-party native identities on verified custom/operator hosts,
with five-minute caching. OAS/adapters are generated with the pinned generator;
CORS and general rate limiting use normal server middleware. Grant stays absent
from discovery. Required native and MFA success/failure inventory emitters enabled.

D-0062 records costs and controller calls: two short-lived rows per native
ceremony; sealed server draft/admission; changed IP pays again; permissive mobile
storage confers trust only for usable serving identities; minimum Task16 Actions
producer pulled forward under K11, with native proof body/query scrubbing.
Organization-required MFA permits only a trusted sealed organization-bound passkey
continuation for OTP/OOB/recovery. The authenticated guard peeks once and uses a
private request-only context; final proof transaction consumes once and rechecks
live user/client/org/membership/connection/app policy. Public organization fields,
password/no-org/other-client tokens cannot authorize this exception. No new
public/store/plugin interface. Reviewer attention: context admission never replaces
MFA proof or the final transaction. SQL revocation fixture alone disables sync
on its disposable SQLite DSN after exact migration fsync stack confirmation;
deadline/barrier/assertions and production settings unchanged, no crash-durability
coverage claimed there.

All Go commands use `GOTOOLCHAIN=go1.26.10 TMPDIR=/mnt/nvme2/tmp
GOTMPDIR=/mnt/nvme2/tmp`, `-count=1`, test timeout15m except the explicitly
intentional15s SQL stack diagnostic. Full original/resumed commands, failures,
preliminary fixture errors, snapshots and actual exits are retained in
`.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/task-15-report.md`
and its named logs/exits. Pinned final `make generate`, session83126, exit0.

Original chain85143, tree `a41a5b9b532c99aa0148e79e28773e53f263cd2b`:
focused80PASS exit0; full affected1032PASS/10FAIL exit1/no skips. Failures were
Actions coverage table missing the new grant and seven SQLite revocation cases
failing fixture migration plus parents. Other affected packages passed:
actions288/rpid17/logs43/passkey35/signupactions1/logrules9/api17. Stopped chain's
hosted/race/source stages did NOT RUN. Isolated predecessor retry exit1 retained:
Actions and association2PASS, six migration cases+parents8FAIL; exact predecessor
command/session were not retained, not invented. SQL stack diagnostic91582 actual
exit1 captures Migrate→Tx.Commit→_unixSync→Xfsync under intentional15s timeout.

Required-org endpoint RED23386 exit1: bound success/live-policy4FAIL+parent;
password/no-org/other-client3PASS. Earlier compile/negative-status/secret fixture
mistakes disclosed separately. Minimal fix followed valid RED. Failed-group90136
exit1,16PASS/2FAIL: SQL7+parents and Actions PASS; successful MFA failed only on
replay fixture expecting400 instead of retained403. Corrected that assertion;
no production change. Final delta16524 command:
`go test -json ./internal/oauth -run 'Passkey|NativeOrigin|MFA|^TestAssociateOTPThenOTPGrant$|^TestAssociateEmailOOBAndGrant$|^TestRecoveryCodeGrantReturnsNewCode$|^TestActionsBodyStripsEveryGrant$' -count=1 -timeout=15m`, exit0,163PASS/no failures/skips.
Includes all six success codes and required-org OTP/OOB/recovery, current
membership/connection/app/client-usage/org-existence and token/replay guards.

Final source/test tree `31c9c7c17ce2e922871707e83c2729f66baf7443`; remaining
chain75802 actual exit0 at that unchanged tree, exact script `task-15-resume-verify.sh`:
- `go test -json ./internal/login ./internal/authz ./internal/server -run 'Passkey|WebAuthn|MFA|Actions|CORS|RateLimited|TestAPIRoutesThroughServer|TestRateLimitThroughServer|TestHostedLoginOutcomeEvents' -count=1 -timeout=15m`: hosted-server316PASS (login160/authz68/server88), exit0/no failures/skips.
- `go test -race -json ./internal/oauth ./internal/passkey -run 'Passkey|NativeOrigin|AssociationFiles' -count=1 -timeout=15m`: race86PASS (oauth85/passkey1), exit0/no failures/skips/race reports.
- `./scripts/check-sources.sh api/authentication.yaml`: sources exit0.
All selected packages executed tests in final remaining stages. Prior successful
unchanged-package evidence is attributed to its original tree; no aggregate full
suite passing claim replaces the recorded affected failure. Source/test comparison
to final frozen tree is empty; gofmt and staged/unstaged diff checks pass.
Self-review covered task/spec contracts, single-use/binding, atomic signup/events,
rate budgets, exact native origins/mobile trust, Actions scrubbing, org-bound MFA,
current-policy mint checks, association HTTP routing/cache and generation. No
known remaining Task15 finding. One implementer monitored blocking waits; no new
agents, full-repository suite, broad E2E, push or merge. Later Task19 SQL matrix,
real-browser/native hardware acceptance remains deferred and is not passing.
