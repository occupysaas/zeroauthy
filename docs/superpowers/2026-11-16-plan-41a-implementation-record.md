# Plan 41a implementation record

Status: **in progress**, starting from `main` commit `18d01994` (Plan 48
merged). Branch: `plan-41a-oidc-extras-logout`; worktree:
`/mnt/nvme2/code/zeroauthy-plan41a`. Nothing has been pushed or submitted for
certification. The full plan remains active until all tasks, final local
checks and branch review are complete.

## Progress

1. Contracts, D-0080 and conformance inventory: complete (`dd5f5114`).
2. Compatibility switches: complete (`145311d1`); focused verification passed. Later protocol tasks still need to consume them.
3. Claims and client OIDC restrictions: implemented; package and focused checks passed.
4. MFA step-up and acr: implemented; package and focused checks passed.
5. Client ID-token signing algorithms: implemented; focused checks passed, broader verification pending.
6. Resource profile and redirect fallback: implemented; focused checks passed, broader verification pending.
7. Logout settings and storage: implemented; focused validation, CRUD/capability, discovery and scrubbing tests passed. Actual sending remains Task 8.
8. Durable back-channel delivery and session-ending triggers: pending.
9. Logout session metadata: pending (Plan 48 fields already available).
10. Global revocation: pending; reserved route returns 501 without mutation.
11. Console: pending.
12. Seed and Deploy CLI: pending.
13. Conformance and certification kit: pending.
14. E2E, documentation, fast local tier, review and CI: pending.

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

Full Go, E2E, full conformance, vulnerability and workflow checks have not run.
There is no CI run yet; partial plan work must not be pushed.

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
template and private_key_jwt authentication. Real universal_logout outcome
logs are enabled and contain no JWT, email or upstream user subject.

Focused seven-package verification passed in task10-focused-fixed.log;
actual GlobalRevocationState memory/SQLite/gRPC subtests passed. Retained
failures include malformed log inventory trigger shape and an unquoted YAML
brace description; both were corrected and subsequent checks passed.
No full local suite or final review has been claimed and nothing is pushed.
