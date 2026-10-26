# Plan 23 implementation record

Implementation: 2026-10-26, feature branch `feat/plan-23-custom-domains`.
Baseline: `99f9cb5`; implementation checkpoints through console: `30d213d`.
[Plan](plans/2026-10-26-zeroauthy-plan-23-custom-domains.md),
[specification](specs/2026-10-26-zeroauthy-custom-domains-design.md),
[operator guide](../custom-domains.md).

Tasks 1–14 are complete for the documented local subset. All required final
commands exited 0. Unavailable external lanes and intentional skips are recorded
separately; interrupted or failed preliminary runs are never counted as passes.

## Acceptance map

| Criterion | Evidence |
|---|---|
| AC1 wire/client | Nine-operation inventory; `TestDomainInventory`, `TestCustomDomainManagementContract`, CLI/SDK m23 |
| AC2 registry/storage | Shared custom-domain/lease/origin conformance; independent SQL handles; schema-0019 upgrades; memory/SQLite/PostgreSQL/MySQL/gRPC |
| AC3 proof/lifecycle | DNS bounds, lifecycle retries/grace/races and secret tests; application scheduler regression; API-backed harness DNS proof |
| AC4 managed ACME | Real local Pebble HTTP-01/TLS-ALPN-01 with two SQL handles, interrupted persisted order recovery, concurrent claimant, renewal, constructor-injected CA outage, expiry and cache invalidation |
| AC5 hosted DNS-01 | Real local Pebble apex/wildcard via fake DigitalOcean and local authoritative DNS; unrelated TXT preservation, crash/ownership tests |
| AC6 proxy/network | Proxy peer/key/IP/Host/SNI and spoofing tests; pinned diagnostic/rebinding tests; shared challenges and safe redirects |
| AC7 origins/mail | `TestDomainOriginBindings`, notification/job origin suites, expired certificate selection/execution tests, first-read failure/consumed-origin regressions, branded PKCE browser |
| AC8 console | Custom-domain Vitest; polling/draft/stale mutation/uncertain verify regressions; narrow/wide and keyboard browser |
| AC9 migration | Strict nonempty domain/template fixtures; comparator negatives; four actual CLI modes; declaration/proof/default staging and API-only header rejection |
| AC10 final gates | Actual results recorded below; local conformance counts are not certification |
| AC11 operator docs | Fleet drain/migration/rollback, legacy origin boundary, ports/DNS/proxy trust/secrets/backups/renewal and tool limits |

## Whole-branch review and fix pass

A fresh read-only reviewer examined the whole branch and all five Review Focus
groups. No Critical findings. Six Important findings were fixed. Two initially
Minor console findings were regraded Important because stale mutation replies
can apply another tenant/domain view and absent progress reads leave required
asynchronous certificate state invisible. The fix pass includes:

1. Schedule ownership proof checks in `App.Serve`, including ACME-off proxy
   deployments; cancel and wait for the loop before closing storage.
2. Require and renew the current resource lease before bounded DNS cleanup, including the
   expired-intent janitor; retain stale/uncertain cleanup for the successor. The
   120-second renewal outlasts the ten-second provider request budget.
3. Check active managed-certificate tenant/domain/generation and time at default,
   notification, queued-send, diagnostic and request admission boundaries.
   Expired public reads project failure while retaining the configured default.
4. Fail closed on authorization-code/PAR preliminary read failures; also recheck
   the consumed authorization-code origin before issuance or replay revocation.
5. Reconcile against the actual configured private-origin namespace at startup.
6. Restore console controls after an uncertain Verify response, guard all
   mutation replies against navigation, and poll for bounded background progress
   while retaining dirty settings and canceling stale reads.

Regressions were observed RED then GREEN: application proof lifecycle and
namespace startup; managed notification expiry and public read projection;
DNS stale-worker takeover preserving the resumed order's TXT records and
near-expiry cleanup renewal;
authorization-code/PAR first-read failure and consumed-origin defense; uncertain
Verify, delayed mutations, polling/draft preservation and cancellation. Existing
mock managed-domain fixtures now include valid certificate metadata; no expiry
or security assertion was relaxed to make them pass.

The reviewer left final in-flight E2E/documentation acceptance to the coordinator
and live external behavior to an authorized observer. Final gates below own
those local acceptance claims. Live upstream/provider observation is unavailable.
No deferred Minor findings remain from this review.

## Local decisions and limits

The complete prior task decisions are in the task ledger and source commits.
For this continuation:

- Continue the already-authorized feature branch and implemented Tasks 1–12;
  independent acceptance harnesses use separate files/ports. Cost if wrong:
  additional coordinated harness maintenance, without redoing implementation.
- Use an advancing clock with offsets for renewal/expiry and a single local
  Pebble certificate profile. Pebble's example advertises multiple validity
  profiles, which makes a later shorter certificate incompatible with a clock
  advanced into the first certificate's renewal period. No production CA policy
  was changed. Cost if wrong: the deterministic fixture misses profile diversity.
- Validate managed certificate metadata at use time rather than trusting worker
  status. Cost: one bounded asset read per managed-origin operation.
- DNS cleanup renews the resource lease before bounded external I/O and fences the
  subsequent CAS deletion. Provider requests cannot be database transactions;
  exactly-once external side effects after uncertain responses are not promised.
  Cost: cleanup may retain an intent for retry.
- Explicitly prepare destination-local identity/proof/origin fields and stage
  declaration/proof/default imports; strict source/target configuration comparisons
  retain all portable settings. Cost: operators perform an additional preparation
  phase instead of a one-shot migration.

Real CA/provider credentials, ACUL and exact live Auth0 tenant behavior are
outside local evidence. RP ID is stored-only. Custom public signing JWKS remains
stored-only and separate from TLS/token-signing state. Hosted wildcard backoff
is per worker in memory. Prompt partials do not yet receive domain context.
Additional DNS providers/delegation and those runtime features remain follow-ups.

## Verification

| Check | Actual result |
|---|---|
| Three SQL dialects | `./scripts/test-sql.sh ./internal/store/sqlstore/... -timeout=30m`: exit 0, 652.266s; SQLite/PostgreSQL/MySQL race tests |
| Generation | `go generate ./...` twice: exit 0, generated output fingerprints unchanged |
| Console | `make console` after review: exit 0; full lint/typecheck/Vitest/build, 51 files / 373 tests |
| Public references | `make check-sources`: exit 0 |
| Local ACME after review | HTTP-01, TLS-ALPN-01, DNS-01: exit 0, all three real Pebble tests; loopback CA/DNS/fake provider only |
| Full Go race / vet | `go test -race -timeout=30m ./...` and `go vet ./...`: exit 0 after review and directory/template parser fixes; 63 tested packages |
| Domains E2E | `E2E_CHROMIUM=/usr/bin/chromium make e2e-domains`: exit 0; three real Pebble lanes (constructor-injected interruption/outage and clock offsets), nine SDK operations, eight high-level CLI operations plus diagnostic, two browser scenarios and fetch-isolation regression |
| Deploy CLI | `make e2e-deploy`: exit 0; all four YAML/directory × generated/preserved credential modes, staged real proof/defaults, repeat/update/runtime and negative checks |
| Branding / email | `make e2e-branding`: exit 0, all 16 SDK/CLI operations and 4 browser scenarios; `make e2e-email`: exit 0, SDK and 1 browser scenario |
| Baseline E2E | `E2E_CHROMIUM=/usr/bin/chromium make e2e`: exit 0; pinned baseline SDK/CLI lanes and 24 browser cases passed, 9 intentional dedicated-harness skips |
| Local OIDC conformance | `make conformance`: exit 0; 46 passed, 0 failed, 12 warnings, 16 review, 8 skipped; no certification claim |

The first unrestricted full race run passed before review. Review runs exposed
old fake managed-domain rows without certificate metadata; those fixtures were
corrected and final verification rerun. Earlier sandbox/cache/listener failures
are environmental failures, never test passes. Initial local CA failures came
from frozen test time and variable profile validity; the fixture correction is
recorded above. Template PUT preparation uses `template`; GET/export uses `body`.

The first strict generated-YAML round trip exposed an ignored external template
body file; `TestBrandingTemplateBodyReferences` reproduced missing/changed bytes
and missing-file acceptance, then passed with safe YAML-root/directory-relative
loading. A directory fixture initially used a hyphenated template filename;
the pinned tool actually writes `universal_login.json` and the fixture now uses
that exact filename. These failures were not normalized away.

The first baseline browser run exposed import-time mutation of Undici's shared
fetch dispatcher by the skipped domain spec. Its new Node regression failed
before the helper switched to explicit per-request dispatchers, then passed.
The standalone SDK process owns its own dispatcher. Affected baseline and domain
lanes passed their final reruns; the initial 23-pass/1-fail/9-skip output is not final acceptance.

Local conformance artifacts: `tests/conformance/results/20261026T212533Z/`.

| Plan | Passed | Failed | Warning | Review | Skipped |
|---|---:|---:|---:|---:|---:|
| Basic | 21 | 0 | 6 | 4 | 4 |
| Config | 1 | 0 | 0 | 0 | 0 |
| Form Post | 21 | 0 | 6 | 4 | 4 |
| RP-Initiated Logout | 3 | 0 | 0 | 8 | 0 |

The pinned CLI high-level `domains` commands cover eight operations; only the
Test diagnostic uses raw `auth0 api`. Separate SDK calls cover all nine methods.
The diagnostic reaches the second node with explicit fixture CA trust and
returns a real proxy-admission failure because it cannot impersonate a proxy.
Client-harness state changes use scoped APIs and actual DNS proofs; managed
restart/renewal evidence is the separate SQL-backed Pebble integration lane.
Diagnostic rebinding attacks are covered by constructor-injected security tests.

A concurrent baseline/domain rerun hit Playwright output-directory deletion
races; the domain runner now uses a unique scratch output path. Both passed their final reruns after
that fixture correction. No product assertion was removed.

Implementation follow-up commits: `44d141a` fixes the review boundaries;
`5cc4514` preserves domain collections and external template body files.
The directory loader regression additionally covers the pinned tool's one-array
`custom-domains.json` representation, rather than nesting that collection again.

The final verification does not use real DigitalOcean credentials, public CA
issuance or an authenticated Auth0 tenant. Source review fetched public
reference URLs only. The hosted wildcard is a local deployment extension;
local OpenID success is not certification. No new production dependency or
adapted licensed code was introduced in this continuation; Pebble and the
existing DNS parser provenance remain in the fixture lock record.

Both generated-credential deployment modes passed the complete actual CLI
workflow before the preserved lane exposed a missing destination-schema
precondition. The separate target database is now explicitly migrated before
offline bootstrap; no server or seed pre-creates the destination tenant. The
corrected four-mode rerun completed with exit 0, including both preserved
credential modes. The earlier schema setup failure is not counted as a pass.

Baseline skips are the dedicated Plan 19, 20, 21, four Plan 22 and two Plan 23
browser cases. Plan 22/23 and email have separate passing targets; skipped cases
are not counted as passing baseline cases. The SPA request that exposed global
fetch-dispatcher pollution passes on the final baseline rerun.

Final task 13 acceptance commit: `0088854`.
The feature branch is retained for integration. No unresolved Critical or
Important review finding remains; no deferred Minor findings. The operator guide,
compatibility matrix, roadmap and follow-ups reflect actual accepted coverage.
