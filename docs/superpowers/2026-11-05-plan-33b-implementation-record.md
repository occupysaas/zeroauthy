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
