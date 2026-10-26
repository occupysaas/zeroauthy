# Plan 22 implementation record

Implementation date: 2026-10-25–26. Baseline: `75e04ce` (Plan 21).

Fix-pass commit: `71741fa`. Implementation checkpoints: `0cac282`, `bbca0d4`,
`e08f290`, `9cb1545`, `26ca12c`.

Plan: [Branding and Universal Login](plans/2026-10-25-zeroauthy-plan-22-branding-universal-login.md).
Operator contract and limitations: [branding guide](../branding.md).

## Acceptance evidence

Commands below ran locally on 2026-10-26. Database checks are permitted: the
Plan 19 hold applied to its implementation tasks, which were already complete.

| Check | Actual result |
|---|---|
| Full Go suite after review fixes | `go test -race -timeout=30m ./...`: exit 0; 60 tested packages; SQL package 275.792s |
| Vet after review fixes | `go vet ./...`: exit 0 |
| Console after review fixes | `make console`: exit 0; 48 test files, 358 tests; lint, typecheck and build pass; bundle-size advisory |
| Generation after review fixes | `go generate ./...` twice: exit 0, identical before/after tracked diff |
| Branding clients/browser after review fixes | `E2E_CHROMIUM=/usr/bin/chromium make e2e-branding`: exit 0; all 16 SDK operations, all 16 CLI operations, four browser scenarios; keyboard, tenant-switch race, template Cancel and 390/1280px preview checked |
| Baseline email after review fixes | `E2E_CHROMIUM=/usr/bin/chromium make e2e-email`: exit 0; actual SDK plus one browser scenario |
| Baseline SDK/CLI/browser after review fixes | `E2E_CHROMIUM=/usr/bin/chromium make e2e`: exit 0; all selected SDK/CLI lanes and 24 browser scenarios; seven intentional fixture skips (Plan 19/20/21 plus four Plan 22 scenarios run in dedicated lanes) |
| Deployment after review fixes | `make e2e-deploy`: exit 0; all four YAML/directory × generated/preserved modes; import/repeat/credentials/update/target-only/negative/runtime checks pass. Template export and other blocked handler families remain explicitly unavailable |
| Three SQL dialects | `./scripts/test-sql.sh ./internal/store/sqlstore/... -timeout=30m`: exit 0, 382.442s; SQLite, PostgreSQL, MySQL; no store/schema changes in review fix pass |
| Public references | `make check-sources`: rerun exit 0; first attempt had a transient RFC 7636 fetch timeout |
| Formatting and documentation | `git diff --check`: exit 0; changed Go files have no `gofmt -l` output; changed local Markdown links resolve |
| Local conformance after review fixes | `make conformance`: exit 0; 46 passed, 0 failed, 12 warning, 16 review, 8 skipped; details below, no certification claim |
| Bounded fuzz | Source/CSS before review: 40,580/264,983 executions, pass; affected source parser after review: 28,092 executions, pass |

Local conformance artifacts: `tests/conformance/results/20261026T055651Z/`.
The earlier pre-fix run (`20261026T052130Z`) had the same aggregate counts.

| Local plan | Passed | Failed | Warning | Review | Skipped |
|---|---:|---:|---:|---:|---:|
| Basic | 21 | 0 | 6 | 4 | 4 |
| Config | 1 | 0 | 0 | 0 | 0 |
| Form Post | 21 | 0 | 6 | 4 | 4 |
| RP-Initiated Logout | 3 | 0 | 0 | 8 | 0 |

AC1–AC10 are accepted for the documented local subset. All implementation and
review fixes are committed; integration, merging and publishing remain separate.
The externally managed detached worktree is preserved.

## Acceptance mapping

| Acceptance | Evidence |
|---|---|
| AC1 | Frozen operation/theme inventory, management validation/scope/isolation suites, actual pinned SDK/CLI |
| AC2 | Shared memory/SQL/gRPC conformance, CAS/deep-copy/rollback/cascade/migration/seed tests, SQLite close/reopen login fixture |
| AC3 | Typed effective-theme projection, hosted-page matrix, default deletion and browser lifecycle checks |
| AC4 | Renderer/HTML/CSS/context/fallback tests, fuzz, unchanged email regression suites, sandbox preview/browser CSP checks |
| AC5 | Identifier-step no lookup, bound transition/race/replay/protection tests, custom DB/CAPTCHA browser cases |
| AC6 | Locale aliases and fallback, partial field lifecycle/ownership/limits, configuration changes and no-side-effect tests |
| AC7 | Resource-editor tests, failed reads, uncertain writes, stale replies, real empty-200 Cancel and isolated preview |
| AC8 | Actual SDK/CLI operations and four strict deployment modes; unavailable template/ACUL export explicitly asserted |
| AC9 | Branded hosted-page browser matrix, default browser/email lanes, local conformance counts below |
| AC10 | Branding/operator/migration guide, compatibility matrix, D-0048, changelog disposition and follow-ups |

## Whole-branch review

One fresh-context read-only reviewer reviewed the whole implementation against the plan,
spec and rulings. No Critical findings. Five Important findings and one initially Minor
finding entered one fix pass: the preview finding was regraded Important because losing
saved sibling-language overrides changes an operator's preview.

Each regression was observed failing before its fix, then passing:

1. Reject self-closing non-void and mismatched HTML boundaries that could swallow or disable trusted controls; invalid stored fragments fall back without capturable fields.
2. Supply the same public application display name to outer templates and partials, including synthetic preview.
3. Evaluate Liquid conditions and filters on raw values and escape only HTML output; retain explicit escape semantics and unchanged email output mode/limits. A separately reproduced quoted filter-argument operator parsing bug was fixed in this pass.
4. Canonicalize custom-text language identities and remove case-equivalent legacy entries on replacement/clear.
5. Preserve saved sibling languages and unrelated prompt/partial data when applying preview drafts.
6. Snapshot successful empty-200 template writes and observe refreshed remote state so Cancel restores the last acknowledged save.

Regression names: `TestPartialHTMLFragmentBoundaries`,
`TestPartialInvalidStoredFragmentKeepsWidget`, `TestPageTemplateApplicationContext`,
`TestPartialExpressionsUseUnescapedValues`, `TestTemplateExpressionsUseUnescapedValues`,
`TestHostedOutputEscapingPreservesEmailMode`, `TestQuotedFilterArgumentsKeepOperatorText`,
`TestCustomTextLanguageIdentity`, `TestBrandingPreviewDraftKeepsOtherResources`, and
the console empty-200 save/draft/Cancel regression.

No deferred Minor findings. Existing authentication and email regression cases remain.

The first extended browser run was terminated after its new stale-response fixture
stalled on `route.fetch` TLS verification. The fixture now serves a delayed explicit
response with CORS headers and follows the existing switcher's home navigation before
opening Universal Login; the complete rerun passed. Full-page screenshots distorted
iframe viewport units during capture; fixed-viewport screenshots and independent
geometry assertions pass, with narrow/wide images visually inspected.

## Compatibility boundaries

Actual pinned node-auth0 7.4.0 and auth0-cli 1.37.0 exercise all 16 supported
operations. Deploy CLI 9.1.0 covers YAML/directory and generated/preserved credentials.
Its custom-domain discovery blocks Universal Login template export: the source template
is nonempty, export omission is asserted, and this is **unavailable**, not a successful
template round trip. ACUL export/runtime and live upstream observation are unavailable.
Classic, future WebAuthn/social controls, Actions and custom-database prompt forwarding
remain explicitly stored-only/deferred. No upstream parity or certification claim.

The server template override directory is superseded for tenant hosted-login composition;
protocol/system pages retain their original rendering. See the operator guide and
[follow-ups](plan-1-followups.md) for migration and future contracts.

## Rulings in execution order

The following preserves every recorded ruling, including repeated entries in the working ledger.

- Task 1: Ruling: no separate authorized observer or tenant credentials in this workspace — record unavailable and use cited public references plus explicit local choices; risk is undocumented Auth0 defaults may differ.

- Task 1: Ruling: public changelog's Oct 22 brute-force unblock setting goes to Plan 19 follow-up — outside Plan 22 runtime; risk is roadmap drift until that follow-up is planned.

- Task 2: Ruling: adding HostedState to AuthTransaction before the storage/codec task caused the existing exhaustive gRPC fixture to fail. Defer the field insertion to Task 4 and its protobuf encoding to Task 5 so each task retains a green boundary; cost is Task 2 alone does not persist the newly defined state.

- Task 2: Ruling: the draft uses generic maps for theme data but inventory drives nested field allowlisting. Validate from inventory now; later runtime task must distinguish stored-only values. Cost if wrong: a newly documented field requires an inventory update before accepted writes.

- Task 3: Ruling: HTML elements are allowlisted and widget ancestors are limited to normal noninteractive containers — structurally balanced HTML such as details/dialog/template or hidden/inert can suppress mandatory controls without CSS — cost if wrong: some otherwise benign semantic wrappers require rewriting.

- Checkpoint ruling: commit the mutually dependent storage, renderer, management and first runtime integration as one coherent checkpoint — the shared aggregate/AuthTransaction fields require coordinated generated codecs, and the page integration now has a green whole-Go boundary — cost if wrong: reviewers must inspect a larger checkpoint; Tasks 3–8 remain subject to outstanding acceptance work.

- Task 9: Ruling: persist FormLanguage and FormFields alongside the planned screen/config revision — locale or public application metadata can change a conditional partial's actual field set without changing the configuration revision — cost if wrong: two additive JSON state fields; old stored transactions default to a fresh form binding. Clone and gRPC exhaustive codec fixtures updated.

- Task 9: Ruling: reserve 128 KiB of the 512 KiB page budget for the built-in widget; partial output above 384 KiB falls back with no capturable controls — a valid isolated partial must not suppress the required widget when composed — cost if wrong: heavily amplified partials can fall back before the standalone evaluator's cap.

- Task 10 ruling: consolidate the six resource editors behind one shared editor with resource-specific controls and lifecycle logic — common draft, stale-request and uncertain-write invariants should not drift between tabs — cost if wrong: a shared component has more resource-specific branches; tests cover each resource's methods and clears.

- Task 10 follow-up ruling: srcdoc inherits parent CSP, so bind validated preview styles to a random per-console-document style nonce while retaining script-src self on the console and script-src none inside the capability-free preview — independent preview nonces are blocked by the inherited policy — cost if wrong: preview styling relies on the console's bootstrap nonce metadata; no tenant content is inserted into the console DOM.

- Task 10: Ruling: share resource-editor state logic rather than six separate components — load failure, draft retention, stale replies and uncertain writes need consistent semantics — cost if wrong: more resource-specific branches in one tested component.

- Task 10: Ruling: rebind validated preview styles to a per-console-document nonce — srcdoc inherits the parent CSP and blocks independent nonces — cost if wrong: preview styling depends on console nonce metadata; tenant HTML still never enters the parent DOM.

- Task 11: Ruling: freeze the pinned Deploy CLI's documented future text prompt/screen enums — its export probes these groups even when workflows are unavailable — cost if wrong: recognized future data can be stored before it has runtime behavior; unknown groups remain rejected and stored-only limits are documented.

- Final: Ruling: Classic, WebAuthn, social controls, Actions and ACUL remain deferred/stored-only as explicitly designed — accepted plan scope, with UI/docs labels — cost if wrong: users need later feature work rather than an implied runtime today.

- Final: Ruling: exact live Auth0 parity remains unobserved — no separate observer/credentials; assess frozen public/local contract and pinned clients only — cost if wrong: undocumented upstream defaults can differ.
