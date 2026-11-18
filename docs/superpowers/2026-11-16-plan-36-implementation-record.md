# Plan 36 implementation record

Branch: `plan-36-enterprise-oidc`. Base: `7a87b2fb`.
Workspace: native managed worktree `/home/thomas/.codex/worktrees/ac19/zeroauthy`.

Status: All 16 implementation tasks committed, including acceptance. Final
review and full Go verification in progress. No push, CI result or merge claimed yet.

Security-sensitive areas changed: federation, login, Management authentication
and API adapters, server, storage and gRPC plugin contract, log scrubbing,
seed validation and console. Read SECURITY.md, THREAT_MODEL.md and CLEAN_ROOM.md.
No new dependency or pin changes. Go 1.26.11 retained from main.

Migration 0041 creates connection keys in SQLite/PostgreSQL/MySQL and
backfills previously omitted OIDC type to back_channel. Private key envelopes
bind tenant, connection, key ID, use and algorithm. Key rotation is atomic.

Implementation commits through Task 15:
5752ce3e contracts; e253209b options; d70f37e4/872a60fb evaluator;
c07508b1 memory keys; aeb840be SQL/gRPC keys; 58c03cf7 keys API;
d144040a endpoints/PKCE/tokens; e1346212 assertions/PAR; 85216fe4 JWE;
86b00580 front channel; 1308b9b3 mapping; eb60cdb2 HRD;
5f86c5f8 delete/status; ae6edbef console; f30e383d seed/Deploy CLI.

Focused tests passed per task (commands and output retained in the plan's
ignored `.superpowers/sdd` directory). SQLite migration and keys checks
passed after updating the existing schema-version assertion from 40 to 41.
Full gRPC package passed, exit 0, 139.457 seconds. `make console` passed,
exit 0: schema generation, lint, typecheck, 85 files/700 tests, build;
no skips. Seed/deploy helper packages passed. New tests were run failing
before implementation where the feature or contract was absent.

Final checks, actual failures/skips, review findings and CI URL will be
recorded below when they finish.

## Acceptance diagnostics

The first enterprise run exited 2 (3 browser failures, 2 passes). It exposed
one runtime integration issue: HRD returned a POST redirect to the provider,
which Chromium blocked under the hosted page's form-action policy. HRD now
uses the existing GET handoff page, without widening the hosted policy.
`TestIdentifierHRDRedirect` and `TestHRDCandidatesOrganization` reproduced
the missing handoff (RED), then passed (GREEN); focused Social tests passed.
The fixture also needed scalar hidden values and the correct console
password confirmation field. Its front-channel regression passed after
failing on the bracketed state value.

The second run exited 2 (4 passes, 1 failure): the console mapping test
needed a textarea value assertion. The third run exited 2 after all five
browser tests passed: the ordinary user projection assertion accidentally
used a token with `read:user_idp_tokens`. It now explicitly requests only
`read:users`, retaining a separate privileged front-channel token check.

`uvx zizmor .` (1.32.0) exited 0: no findings; 4 ignored and 27 suppressed
by the existing repository configuration. `govulncheck ./...` (v1.10.0)
exited 0: no called-symbol or imported-package vulnerabilities; one unused
required-module vulnerability reported. Tool installation was isolated in
ignored scratch storage and changed no dependency manifests.

Main still ends at migration 0040, checked via the repository API on
2026-11-18; this branch's migration remains 0041.

The fourth enterprise invocation passed, exit 0: five Chromium tests
(4.6 seconds), SDK create/keys/rotate/delete-by-email/status, scoped profile
projections, Auth0 CLI public keys, and the runtime privacy audit. Fourteen
actual assertion/JWS/JWE/access-token samples were absent from twelve public
runtime files and Management logs. Runtime artifacts are retained at
`/dev/shm/za36/tmp.LOhxxbRR3o`; logs and snapshot hashes use
`e2e-enterprise-4.*` in the plan evidence directory. No test skips.

Required security fuzz command:
`GOMAXPROCS=4 go test -run='^$' -fuzz='^FuzzParse$' -fuzztime=60s ./internal/usersearch`
passed, exit 0, 61.046 seconds, 632,495 executions and two new interesting
inputs. No skips. Logs and exact exits: `security-*.log` / `security-*.exit`.

Final review package: `7a87b2fb..6c207b63`; required fresh-context reviewer
started after all implementation commits. The full Go fast tier remains
owned by its sole monitoring agent; no duplicate polling or invocation.

## Implementation rulings

- Preserve current Go 1.26.11 and dependency pins over stale plan toolchain versions — avoids downgrading main — cost if wrong: plan fixtures may require adjustment.
- Use native managed worktree /home/thomas/.codex/worktrees/ac19/zeroauthy on plan-36-enterprise-oidc instead of plan's manual path — required by worktree skill — cost: commands and log paths differ.
- grammar validation belongs in leaf rules with evaluator in federation to avoid an import cycle — cost: parser helper placement differs.
- deletion through connection cascade on every backend, avoiding separate public deletion — cost: future consumers need new method if explicit deletion required.
- Final review and required local checks precede push, per AGENTS.md, overriding Task 16's push-before-review order — cost: CI starts later.
- migration 0041 (0037–0040 already on main), key_use column avoids reserved SQL use keyword — schema contract preserved — cost: numbering may change again before merge.
- GenerateConnectionKey and EnsureKeys take wrapper and connection identity explicitly so private keys are sealed before a store model leaves generation — original signature lacked sealing context — cost: callers use a larger signature.
- assertion signing accepts explicit store/wrapper/connection parameters and ExchangeInput carries a signing callback, rather than mutating shared Providers with credentials — avoids shared state and exposing keys in Config — cost: internal helper signature differs from draft.
- pinned go-jose v4.1.5 has no RSA-OAEP-384/512 key-management implementation; use its OpaqueKeyDecrypter with standard-library rsa.DecryptOAEP(SHA-384/SHA-512), keeping go-jose content authentication — preserves documented algorithms without new dependencies — cost: small adapter plus independent compact fixtures to maintain. Decrypt helper receives key-aware opener to preserve per-key AAD binding.
- reuse existing bounded GET/POST SocialCallback from Apple implementation, adding channel-aware parameter validation instead of another POST route — main already registers POST /login/callback outside hosted-form CSRF — cost: callback handler handles both provider response types.
- retain existing failure statuses (provider denial 401; invalid provider ID token 502; malformed/unbound callback 400) and login log type f. Draft fs denotes failed signup and contradicts existing login attribution contract — keeps API/log semantics consistent — cost: draft test name/expectations differ. Front login deletes historical upstream tokens atomically so a channel switch cannot expose stale credentials.
- store mapped custom attributes in existing ProviderData, already projected as identity.profileData, rather than primary ProfileData which marks linked identities — preserves account ownership and linkage — cost: internal representation differs from draft terminology. Use deep equality for mapped arrays/maps during synchronization.
- MatchHomeRealm preserves supplied eligible order; current store lists connections by name and has no per-client connection-order field — deterministic name order is the available tie-breaker — cost: observation V9 must revisit ordering if a per-client order is added. Organization/client/purpose filtering precedes matching via socialConnections/EligibleConnections.

## Final review and fix pass

Fresh-context whole-branch review of `7a87b2fb..6c207b63` completed. The
required fix pass covers:

- Keep provider credentials outside profile mapping inputs and reject
  credential references at configuration time. Existing request scrubbing
  remains defense in depth; ordinary later reads/events are covered.
- Honor explicit database selection in HRD and allow enterprise-only,
  hidden-connection identifier flows without a password database.
- Preserve unmapped back-channel userinfo email fallback with subject checks.
- Seal endpoint decisions inside the existing opaque attempt proof, so older
  plugin codecs cannot discard the channel/PKCE snapshot. Pre-upgrade proofs
  without a snapshot retain code/S256 behavior. Stored plugin records with
  sealed credentials and omitted type retain back-channel/S256 defaults.
- Skip unused token authentication selection for front-channel providers.
- Refuse empty signing allowlists, malformed scope aliases and mapping types.
- Keep permitted phone attributes as identity profile data, without changing
  local phone ownership or verification.
- Restore console authentication and profile synchronization controls.
- Cover cross-attempt and HS256 callback rejection, no identity/session writes,
  and authentication-method revision changes. These checks already existed;
  the new entry-point coverage passed without a production change.

Regression runs reproduced the runtime/configuration/editor findings before
fixing them (`review-*-red.log`) and then passed (`review-*-green.log`).
The first full Go run exited 1: an additional schema-version test still
expected 40, and the front-channel fixture test observed its in-progress
assertion edit. Both are corrected; final full verification is pending.

Deferred minors from the review:

- Lazy versus API-generated signing certificate subject names differ.
- A trailing blank line in `docs/compat/decisions.md`.

Final rulings:

- Credential source references in the draft spec are refused to preserve the
  existing scoped upstream-token contract. Cost: configurations that rely on
  mapping a credential into a public profile are rejected.
- Permitted mapped phone values remain identity attributes rather than local
  phone identifiers. Cost: no local phone login/verification is implied.
- V1–V13 live Auth0/provider observations remain unperformed, as documented;
  local rulings govern this implementation. Cost: live behavior may differ.
- PostgreSQL/MySQL, race and conformance outcomes remain owned by the required
  CI runs. Cost: any CI-specific failures must be fixed before merge.

Fix-pass verification completed before the final full tier:

- `go test ./internal/federation/... ./internal/login ./internal/seed -count=1`
  exited 0; all five selected packages passed. Login package: 66.898s.
- Callback/attempt/HRD targeted regressions exited 0, including an old opaque
  proof, an old plugin codec for both channels, protected profile reads and
  a later event emitted outside the callback request context.
- `make console` exited 0: generation, lint, typecheck, 85 files/701 tests,
  build; no skips. Embedded dist regenerated. Bundle-size advisory only.
- Required enterprise E2E exited 0 on the corrected tree: five browser tests
  (4.4s), SDK negative writes/scoped profiles, CLI and runtime audit passed.
  Fourteen sensitive samples absent from twelve public files and Management
  logs. Artifacts: `/dev/shm/za36/tmp.SiN1wnR30J`.
- Final full Go tier launched once after these checks with the corrected
  schema assertion; sole monitor retains `fast-tier-2.log` and snapshot.

No second reviewer was dispatched; regression tests verify the single fix pass.
