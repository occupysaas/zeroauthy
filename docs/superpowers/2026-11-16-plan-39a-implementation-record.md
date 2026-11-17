# Plan 39a implementation record

Started 2026-11-16 from `7691b15d92bcfef3a2d48908b29de112bb74f08b`.
Worktree: `/mnt/nvme2/code/zeroauthy-plan39a`.
Branch: `plan-39a-apple`.

**Current status:** Tasks 1–7 implemented and reviewed on `plan-39a-apple`.
Apple web/native runtime is active; Task 8 acceptance and final plan gates
are recorded below. Full Go tier, whole-branch review and CI have not yet
completed. No merge authorization is implied.

Initial scope: Task 3, the internal ES256 client-secret signer and cache,
while the independent Plan 45b branch is in CI. This task consumes existing
`CacheKey`, `Providers` and go-jose interfaces, so it can precede strategy/API
activation. If later provider work needs a different signature, adapt the
internal helper there. Main's Go 1.26.11 minimum and dependency pins are
retained rather than downgrading to the design's stale Go 1.26.10 reference.

- Task 3: signed JWT uses Key ID header and Team ID issuer, Services ID or
  bundle ID subject, Apple's fixed audience, integer issue time and a
  five-minute lifetime. Four-minute cache is bounded and isolated by tenant,
  connection, revision, signing identifiers and subject; concurrent calls
  share one signature. Cache holds no private key.
- Task 1: API/inventory contracts frozen: Apple options and strategy,
  write-only PEM credential, typed native switches and bounded native
  first-login profile. D-0170 and D-0039 now describe active Apple behavior
  and stored native-social fields; A1–A7 retain explicit local answers and
  remain unobserved. Task 1 itself did not activate the routes.
- Tasks 2 and 4–7: option rules, verified provider/profile, cross-site form
  callback, native exchange, typed storage (migration 0037), seed references,
  console and Deploy CLI completed and reviewed. Task 7 ran all four real
  Deploy CLI cells. Task 8 adds the complete Apple acceptance umbrella and
  current documentation. Full-plan Go verification/review/CI remain pending.

Verification uses `GOTOOLCHAIN=go1.26.11 TMPDIR=/dev/shm/za39a GOTMPDIR=/dev/shm/za39a`:

- RED: `go test ./internal/federation -run '^TestApple(ClientSecret|SecretCache)' -count=1`, exit 1: missing signer and cache methods (build failure).
- GREEN: same command, exit 0 (0.121 s). Tests verify signatures with the
  public key, required claims/headers, wrong-key rejection, invalid keys,
  cache expiry at exactly four minutes, revision/key rotation, isolation
  across tenant/connection/subject/Team ID/Key ID, and 32 concurrent calls.
- Package check: `go test -race ./internal/federation -count=1`, exit 0 (10.143 s); log `task3-package.log`.
- Logs retained in `.superpowers/sdd/2026-11-16-zeroauthy-plan-39a-apple/task3-{red,green}.log`.

Task 1 verification uses the same environment:

- RED: `go test ./api -run '^TestApple' -count=1`, exit 1: missing Apple
  options/profile and untyped native switches; `go test ./internal/federation
  -run '^TestFederationInventory$' -count=1`, exit 1: three strategies
  instead of four.
- GREEN: `go test ./api ./internal/federation -run
  '^(TestApple(ConnectionContract|NativeClientContract|NativeProfileContract)|TestFederationInventory)$'
  -count=1`, exit 0. Schemas reject empty/null keys, bad signing identifiers,
  unsupported scopes, malformed switches and untrusted/oversized name fields.
- `make generate`, `go build ./...`, and `go test ./api/ ./internal/federation/`
  each exited 0. No Go minimum or dependency pins changed. Logs retained as
  `task1-{red,inventory-red,green,generate,build,packages}.log` in the same SDD
  directory. Whole-plan local/CI/E2E verification remains pending.

## Tasks 2 and 4–7 implementation

Reviewed commits: option rules `fee5a663`; provider/profile `44730e96`;
form-post callback `80fa0363` (review corrections through `ccdf077c`);
native exchange `ee821df8`; console/seed/Deploy CLI `36728024`.
Task reports and retained command logs are under
`.superpowers/sdd/2026-11-16-zeroauthy-plan-39a-apple/`.

The Apple adapter fixes production endpoints, verifies RS256 ID tokens and
web nonce, handles email verification strings and relay addresses, and
preserves first-login names. `ProviderData` survives store/plugin round trips
separately from linked-secondary profile data. Native exchange reserves the
Apple type ahead of custom profiles, binds to the client bundle ID, and
rechecks configuration/identity epoch through issuance and MFA continuation.
The first usable Apple connection follows the store's `LOWER(name), id`
order; clients have no separate priority list. Migration 0037 adds the typed
native-social column in all three SQL dialects. Facebook/Google switches
remain stored-only until Plan 39b. `.p8` seed keys require file/environment
references. Public reads and exports omit signing keys; Deploy CLI imports
require explicit private reinjection.

Task 7 console evidence: 684 tests, lint, typecheck and build exited 0.
Task 7 four-cell Deploy CLI acceptance exited 0 on SQLite production source
and target processes, with YAML/directory × generated/preserved client IDs.
Those results do not claim PostgreSQL/MySQL runtime acceptance or live Apple
interoperability. No Apple certification or optional A1–A7 observation is
claimed. Task 8 reruns the complete Apple umbrella; final evidence follows.

## Task 8 local acceptance (2026-11-16)

`GOTOOLCHAIN=go1.26.11 TMPDIR=/dev/shm/za39a GOTMPDIR=/dev/shm/za39a
E2E_KEEP_WORK=1 make e2e-apple` exited **0** (attempt 5). All four Playwright
tests passed with no skips. The upstream has a different registrable domain
(`apple.idp.test` vs `sdk.e2e.test`); Chromium's callback request reported
`Sec-Fetch-Site: cross-site`, and the attempt cookie was Secure/SameSite=None.
The lane completes real provider and downstream code exchanges, verifies
local ID-token signatures through JWKS, and proves repeated-name retention,
private relay, string false and boolean true email verification. Raw Node
proves public/confidential native success, first-name preservation,
wrong-bundle audience rejection with no created user, disabled switch,
missing confidential authentication, upstream invalid_grant and reserved
custom-profile isolation. The pinned node-auth0 7.4.0 performs full
connection CRUD; Auth0 CLI 1.37.0 performs connections list/show. File/env
seed credentials load through the production parser. The actual runtime
secret audit checks **39 distinct sensitive values** against **12 artifacts**
and Management logs, including PEM, ES256 secrets, upstream tokens and native
codes. Private credentials are mode 0600.

The same umbrella then passed all four production-source/target Deploy CLI
9.1.0 cells: YAML/directory × generated/preserved client IDs, explicit
credential reinjection, repeat import, public export exclusion and private
sealed-key checks. SQLite is the selected acceptance backend. No live
Apple/Auth0 tenant, PostgreSQL/MySQL runtime or certification is claimed.

Focused Apple API/federation/provider tests exited 0; inventory test first
failed on all nine remaining planned Apple options, then passed with their
active classification. `make generate`, console `npm run gen` and
`npm run build` exited 0 after the API descriptions changed; the bundle is
unchanged. Existing large-chunk build advisory remains. Shell/Node syntax
and whitespace checks are recorded in the Task 8 report. Prior failed
E2E attempts are retained there: harness import shadowing, unsupported seed
grant declaration, cookie-path/string-metadata expectations, and omitted
Playwright security headers. Each retry followed an actual recorded failure.

Ignored local evidence: `task-8-logs/e2e-attempt-5.log` and protected
`task-8-artifacts/passed-{runtime,deploy}/` under the SDD directory above.
Task 8 report lists commands, handles, actual exits, selected checks and
failures. The full local Go tier and whole-branch review remain controller
responsibilities. **No push or CI before all local checks and reviews finish;
no merge without green CI and maintainer approval.**

## Full Go tier follow-up: migration expectation (2026-11-16)

The controller's full Go run at `8275e499` exited 1 in
`TestEventsMigrationFrom30/sqlite`: its latest-version assertion still
expected 36 after Task 6 added migration 0037. The test had successfully
migrated the database and reported actual latest version 37. Updated that
single stale expectation; the explicit version-30 upgrade starting point
remains unchanged. No production migration changed.

Focused verification used `GOTOOLCHAIN=go1.26.11 TMPDIR=/dev/shm/za39a
GOTMPDIR=/dev/shm/za39a go test ./internal/store/sqlstore -run
'^TestEventsMigrationFrom30$|^TestLatestVersion$|^TestMigrationSetsMatch$|^TestNativeSocialMigrationLeavesClients$|^TestOrganizationsIIMigrationFrom25$'
-count=1 -v` and exited **0** (0.818s), with all named gates selected and
no skips. Database execution was SQLite; embedded version/set checks cover
all three dialects. The existing full-tier failure remains recorded in
`final-go.log`; this focused pass does not establish a full-tier pass.
The controller will rerun that tier and perform final review. No push or CI.

## Local completion and final review

At `02d6e210`, the required `GOTOOLCHAIN=go1.26.11 TMPDIR=/dev/shm/za39a
GOTMPDIR=/dev/shm/za39a go test -p 4 ./...` rerun exited **0**
(`final-go-2.log`, actual exit retained). The earlier failed run is recorded
above. Apple acceptance passed all four browser tests, native/SDK/CLI checks,
the runtime secret audit and four actual Deploy CLI cells. Console 684 tests,
lint, typecheck and build passed. No additional runtime changes followed
that acceptance run.

All eight implementation tasks and task reviews are complete. Independent
whole-branch review of `326fc3bf..02d6e210` found no Critical, Important or
Minor issues. Final review inspected recorded evidence without rerunning tests.
Migration 0037 remains next after main's 0036 at this check. The completed
branch is ready for plan-branch CI; PostgreSQL/MySQL, full race, remaining
E2E regression suites and conformance results are pending that CI. No live
Apple tenant test or formal certification is claimed. Merge still requires
green CI and maintainer approval.

## Plan-branch CI follow-up: browser discovery

[Run 43981706721](https://github.com/occupysaas/zeroauthy/actions/runs/43981706721)
failed only `ci / e2e (e2e)`: `make e2e` exited **2**. Its general browser
runner discovered the dedicated Apple spec with no Apple fixture flag, and
the spec's top-level guard threw before execution. The dedicated Apple job
passed; the overall branch CI is still failed until a subsequent green run.

The shared Playwright configuration now excludes that dedicated spec outside
Apple mode. Apple mode keeps the existing fail-fast guard and all four
required browser cases. A Node regression runs actual general/Apple collection
and checks that the general SPA suite remains selected, Apple is excluded
outside its lane, and Apple mode discovers exactly four runnable cases. The
Apple runner includes that regression as preflight. No production code or
validation policy changed. Local results and the exact CI failure are retained
in `.superpowers/sdd/2026-11-16-zeroauthy-plan-39a-apple/ci-fix-report.md`.

Local follow-up verification passed: the collection regression first reproduced
the failure, then passed **2/2** with no skips; the general browser runner's
focused `m4-spa-login` case passed its real SDK login/API flow. A subsequent
sequential `make e2e-apple` exited **0**: discovery preflight 2/2, Apple
browser 4/4, native/SDK/CLI checks, 39-value/12-artifact runtime secret audit,
and all four actual Deploy CLI cells. An earlier local Apple attempt failed
because it overlapped the general runner's `npm ci` against shared
`node_modules`; that orchestration failure and its exact exits/artifacts are
retained in the report. No production fix was required. Test-only integration
changes do not require another broad Go run. This fix still requires review
and a new green plan-branch CI run before merge approval.
