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
