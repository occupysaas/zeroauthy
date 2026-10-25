# Plan 22 — Branding and Universal Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make tenant branding, themes, safe page templates, prompt text/partials and identifier-first database login configurable through compatible APIs and the console.

**Architecture:** Persist a versioned hosted-login aggregate and resolve one snapshot per request. Keep the original Go widgets and their security boundaries, compose them through bounded Liquid, and persist login-stage transitions separately on auth transactions. Extend all storage drivers and existing Management/console/tooling patterns.

**Tech Stack:** Go 1.26.7, Go HTML templates, existing restricted Liquid evaluator, SQLite/PostgreSQL/MySQL, protobuf/gRPC, OpenAPI generation, Vue/TypeScript, Vitest, Playwright, pinned Auth0 SDK/CLI/deploy-cli clients.

**Spec:** [Plan 22 design](../specs/2026-10-25-zeroauthy-branding-universal-login-design.md). Read both documents. Status: implementation in progress. Baseline `75e04ce` includes Plan 21.

## Global Constraints

- Keep Go 1.26.7 and the existing Vue/TypeScript toolchain.
- Follow `CLEAN_ROOM.md`; original UI/copy only, with a separate authorized observer for live upstream evidence. Never capture Auth0 hosted pages or dashboard assets.
- Preserve issuer, tenant resolution, redirects, PKCE, nonce/state, consent, tickets, sessions, protection decisions and token validation. No custom wrappers on form-post/web-message responses.
- No tenant JavaScript, event handlers, nested forms, remote server-side asset fetching, arbitrary CSS or filesystem template overrides. ACUL remains unsupported; Classic/WebAuthn settings are visibly stored-only.
- Local limits: template source 100 KiB UTF-8; each partial 10,000 Unicode characters and at most 40 KiB; aggregate configuration 1 MiB; Management/preview request 2 MiB; variable context 64 KiB; output 512 KiB; nesting 32; loop iterations 10,000; evaluation steps 100,000; deadline 100 ms; eight active renders per process.
- At most 20 themes per tenant. Captured partial fields: 30 fields, 128-byte names, 1 KiB per value, 8 KiB total; retain the 16 KiB hosted-form cap. At most 30 custom text variables per screen/language.
- CAS retries: at most three fresh-read attempts. Do not confuse missing configuration with unavailable storage.
- Plan 19's database hold applies to Plan 19, recorded complete. Recheck applicable instructions before testing.
- Do not mark observations, skipped lanes, generated commands or deferred tests as passing. Merge/push remain separate decisions.

## Review Focus

- A valid Liquid program emits zero/two widgets only for a particular branch: detect after evaluation and retain a usable built-in page (Task 3).
- Seed reruns or simultaneous settings writes resurrect removed configuration or lose unrelated text: one authority, bounded CAS retries and preserved ownership (Tasks 2, 4, 6).
- Two password submissions race across server instances, or a stale tab changes identifier: only one authentication call, no changed callback/expiry (Tasks 4, 8).
- Tenant template values become CSS, URLs, executable HTML, or a console-origin document: validate each context and isolate preview (Tasks 3, 7, 10).
- Deploy CLI silently omits templates because custom-domain discovery is unavailable: record handler-level support and test nonempty exports without fake domains (Task 11).

## File and dependency map

| Responsibility | Files |
|---|---|
| Public contract and shared validation | New `internal/brandingrules/{inventory.json,branding.go,themes.go,prompts.go,templates.go}` and tests |
| Bounded language engine | New `internal/liquid/{engine.go,engine_test.go}`; extraction from `internal/email/render.go` with existing email tests retained |
| Domain/persistence | New `internal/store/hosted_login.go`, `pkg/storetest/hosted_login.go`; existing `internal/store/{store.go,types.go}`, `pkg/store/store.go`; driver implementations |
| Render policy and projection | New `internal/hostedlogin/{service.go,context.go,render.go,html.go,css.go}` and tests; `internal/ui/ui.go` and templates |
| Login transition | New `internal/login/identifier.go`, original identifier/password widget templates, transaction repository methods/codecs |
| Management | New `internal/mgmt/{branding.go,branding_themes.go,prompts.go,system_branding.go}` and tests; schema/server/catalog wiring |
| Console | New `console/src/pages/branding/` components/tests; existing router, API, section and locale files |
| End-to-end/docs | New `tests/e2e/m22-*`, runner, operator guide; existing deploy fixtures, Makefile, CI and compatibility records |

Tasks 1–2 establish contracts. Tasks 3–5 implement rendering/storage. Task 6 exposes management. Tasks 7–9 integrate hosted behavior. Task 10 adds console/preview; Tasks 11–12 validate and document the whole feature. Use sequential implementation unless the chosen execution workflow explicitly delegates independent work.

## Task 1: Freeze branding, prompt and tool contracts

**Files:** Create `docs/compat/observations/branding-prompts.md`, `internal/brandingrules/inventory.json`; modify `docs/compat/changelog-review.md`, `docs/compat/decisions.md`, and these draft documents where evidence changes a decision.

**Interfaces:** The inventory is the source for schemas, validators, prompt/screen/slot names, field-to-CSS mappings and SDK cases. Include an `effective`/`stored_only`/`unsupported` disposition for every field and resource.

- [x] Review public changelog entries since the repository's last reviewed date; record new relevant behavior in original words. Resolve the draft's response-size fetch limitation without claiming a review from search snippets alone.
- [x] Arrange a separate authorized observer for documented Management endpoints, or record why that lane is unavailable. Request facts about default theme activation/deletion, absent resources, partial replacement, template content types/tag rules, null/empty values and scopes. No upstream UI capture or real login automation.
- [x] Inventory every listed operation, exact documented limits and variables, plus theme identifiers/future fields. Confirm `classic`, WebAuthn and unsupported ACUL disposition. Freeze the local lifecycle in spec §3 where evidence is absent; revise both documents on any contradictory evidence before implementation.
- [x] Inspect the repository-pinned licensed node-auth0/auth0-cli/deploy-cli calls as clients. Record which handler needs custom domains, whether themes have a handler, and exact directory paths/media types. No invented custom-domain response or downgraded strict comparison.
- [x] Add a fixture completeness test `TestBrandingInventory` in `internal/brandingrules/inventory_test.go`: every operation has sources, scopes, request/response shapes and a disposition; every supported theme field has a runtime target; every partial prompt/screen/slot combination has a classification. Run `go test ./internal/brandingrules -run TestBrandingInventory -count=1`; expect exit 0 only after the inventory is complete.
- [x] Commit the contract inventory and evidence with `docs: freeze Plan 22 branding and prompt contracts`.

## Task 2: Define versioned configuration and validation

**Files:** Create `internal/store/hosted_login.go`, `internal/brandingrules/{branding,themes,prompts,templates}.go` and `_test.go` files; modify `internal/store/{store,types}.go`, `pkg/store/store.go`, and store wrappers/mocks discovered by compilation.

**Interfaces:** Define `HostedLoginConfig struct { TenantID string; Revision int64; Branding map[string]any; Template *string; Themes map[string]map[string]any; DefaultThemeID string; Prompts map[string]any; CustomText CustomText; Partials map[string]map[string]map[string]string }`. Define `HostedLogins` with `Get(ctx context.Context, tenantID string) (*HostedLoginConfig,error)` and `Put(ctx context.Context, config *HostedLoginConfig, expectedRevision int64) error`; expose `Store.HostedLogins()`. Missing = `ErrNotFound`; expected 0 creates, success increments revision; CAS mismatch = `ErrConflict`. Export `ErrHostedLoginRepositoryUnavailable` and an unimplemented adapter. Define `brandingrules.Validate(config *store.HostedLoginConfig) error` for new configurations, `ValidateUpdate(current, next *store.HostedLoginConfig) error` for grandfathered size handling, `Merge(current *store.HostedLoginConfig, resource string, body []byte) (*store.HostedLoginConfig,error)` and `FromLegacy(tenant *store.Tenant) *store.HostedLoginConfig`.

- [x] Write `TestBrandingMergePresence`, `TestThemeDefaultLifecycle`, `TestHostedLoginLimits`, `TestLegacyProjection`, `TestPromptDisposition`. Assert omitted nested keys preserved, explicit false retained, optional URL null cleared, required color null rejected, new theme active, deleting active restores base, old theme not reactivated, 21st theme rejected, new 1 MiB aggregate accepted and +1 byte rejected, grandfathered oversized aggregate accepted only when a write strictly reduces its size, future settings stored without execution.
- [x] Run `go test ./internal/brandingrules -count=1` and capture the expected missing implementation failures. Add the types, deep-copy helpers, field-specific merge rules and validation. No arbitrary map accepted without inventory validation.
- [x] Add identifier state fields to `AuthTransaction` through `HostedState HostedLoginState`, where `HostedLoginState` contains `Step, Identifier, ConnectionID string`, `PromptFields map[string]string`, `Revision, FormConfigRevision int64`, `FormScreen string`. Empty legacy state means combined login. Do not put these values into authorize `Params`.
- [x] Add `AuthTransactions.CompareAndSwapHosted(ctx context.Context, tenantID, id string, expectedRevision int64, next HostedLoginState, now time.Time) error`. It atomically checks existence, expiry and revision; increments only hosted revision; never changes expiry/cookie/CSRF/client/Params. Use `ErrNotFound` for absent/expired and `ErrConflict` for stale revision. Update adapters/mocks so packages compile before implementations land.
- [x] Run rules tests and `go build ./...`; expect exit 0. Commit `feat(branding): define hosted login configuration and rules`.

## Task 3: Extract bounded Liquid and implement safe composition

**Files:** Create `internal/liquid/{engine,engine_test}.go`, `internal/hostedlogin/{render,html,css,context}.go` and adjacent tests/fuzz tests; modify `internal/email/render.go`, keeping its tests.

**Interfaces:** `liquid.Limits` holds §5 budgets. `liquid.Render(ctx context.Context, source string, vars map[string]any, tags map[string]string, limits Limits) (string,error)` operates on projected data and explicitly supplied trusted tags. `hostedlogin.Renderer.Render(ctx context.Context, in RenderInput) (RenderOutput,error)` consumes `RenderInput{Source string, Variables map[string]any, Head, Widget string, Partials map[string]string}` and returns `RenderOutput{HTML string, AssetOrigins []string}`. `hostedlogin.ValidateSource(source string, partial bool) error` validates save-time language/HTML/CSS policy. Keep trusted tags internal; callers cannot register arbitrary safe-HTML variables through HTTP.

- [ ] Write `TestLiquidEmailCompatibility` and retain all original email parser/render/fuzz cases. Add `TestTemplateTagBranches`, `TestRenderBudgets`, `TestHTMLContexts`, `TestCSSPolicy`, `TestTemplateCapabilities`, `TestProjectedContext`. Assertions: exactly one emitted head/widget; zero/two rejected; 100 KiB source accepted and +1 rejected; output 512 KiB cap; cancellation and eight-slot cap release resources; no token/password/CSRF projection; dynamic URL scheme checked; nested forms/event handlers/scripts/style-attribute/import/CSS-URL and raw interpolation rejected; escaped selectors, parent concealment, overlays, negative spacing, opacity and positioning rejected.
- [ ] Run `go test ./internal/email ./internal/liquid ./internal/hostedlogin -run 'Liquid|Render|Template|HTML|CSS|Projected' -count=1` to capture failures. Extract shared parsing/evaluation without changing email limits or escaping; add explicit host-owned tag handling and save-time validation using a structural HTML parser. Select a maintained parser already available in the dependency graph where possible; record any new parser dependency/license.
- [ ] Implement the constrained CSS grammar from spec §5 (`.za-decoration` only, no widget descendant, numeric bounded typography/spacing and safe colors); reject constructs outside its allowlist rather than attempting to sanitize general CSS. Validate before and after rendering; insert trusted fragments only after validating tenant-controlled output.
- [ ] Run those package suites with `-race` and short bounded fuzz runs for the new parser entrypoints. Expected: exit 0, no email output regression, no leaked render capacity after errors. Commit `feat(ui): add bounded safe hosted template rendering`.

## Task 4: Persist configuration and auth transitions in memory and SQL

**Files:** Create `internal/store/{memory,sqlstore}/hosted_login.go`, `pkg/storetest/hosted_login.go`; modify driver store registration, tenant deletion, transactions/codecs, `pkg/storetest/{storetest,auth_transactions}.go`; create `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0019_hosted_login.sql` and migration tests. Add focused driver concurrency tests.

**Interfaces:** Implement Task 2 repositories. One aggregate JSON record per tenant with revision and FK cascade. Add hosted-state JSON/revision to auth transactions; legacy rows decode as empty. Driver transaction views include both repositories. Register `"HostedLogin": testHostedLogin` in `pkg/storetest.Suites`; implement `testHostedLogin(t *testing.T, newStore Factory)` using the existing conformance harness.

- [ ] Add storetest cases `HostedLoginCAS`, `HostedLoginCopies`, `HostedLoginRollback`, `HostedLoginTenantDelete`, `HostedTransitionCAS`, `HostedTransitionExpiry`. Assert mutate-after-get cannot change state; two expected-revision writes produce one winner; rollback restores default and config together; wrong tenant cannot see records; transition keeps Params/expiry byte-for-byte unchanged; expired boundary `now == ExpiresAt` fails.
- [ ] Run `go test ./internal/store/memory -count=1` and focused SQLite storetest selection after wiring names to the existing suite; confirm failing assertions before implementing. Implement memory locking, SQL conditional updates and driver transaction support.
- [ ] Add migration fixtures from schema 0018 with nonempty legacy branding/text, an oversized legacy text aggregate and an in-flight transaction; assert exact data survives, default two-step state is absent, migrations are idempotent and restarting does not overwrite API edits. Assert oversized legacy data is never truncated, reads still work, increasing/equal-size writes fail until under 1 MiB, and small resource-clearing requests can reduce it incrementally. Migrate existing tenants once; missing new aggregate still supports legacy read fallback.
- [ ] Test two independent SQL handles racing config and password-stage CAS; exactly one wins and no lost unrelated config. Run `go test -race ./internal/store/memory ./internal/store/sqlstore` and `./scripts/test-sql.sh`; require actual successful results for all three dialects, or record a blocker without claiming parity.
- [ ] Commit `feat(store): persist hosted login configuration and transitions`.

## Task 5: Extend the gRPC storage boundary

**Files:** Modify `proto/store/v1/store.proto` and generated files, `internal/store/grpcstore/{client,client_repos,server,server_repos,codec}.go`; create `internal/store/grpcstore/hosted_login_test.go`; update plugin adapters/examples identified by `go build ./...`.

**Interfaces:** RPCs mirror `HostedLogins.Get/Put` and `AuthTransactions.CompareAndSwapHosted`, including expected revision and clock timestamp; preserve nullable template and empty maps. Errors map to the same sentinels; old server returns repository unavailable instead of legacy-default success.

- [ ] Add codec, unavailable-server, shared conformance and SQL-backed transaction tests. Assert nested Unicode partials/text, nil versus empty template, revision conflict, expired transition, tenant cascade and rollback match local drivers. Assert no logs contain captured partial values.
- [ ] Run `go test ./internal/store/grpcstore -run 'Hosted|Codec' -count=1` and capture failures. Implement additive proto messages/RPCs/codecs and wrappers; use existing generation commands.
- [ ] Run `go generate ./...`, `go test -race ./internal/store/grpcstore` and `go build ./...`. Generate twice and verify the second run adds no diff. Commit `feat(store): expose hosted login configuration over gRPC`.

## Task 6: Implement Management APIs and authoritative seed behavior

**Files:** Create `internal/mgmt/{branding,branding_themes,prompts}.go` and tests; modify `api/management.yaml`, `internal/server/server.go`, `internal/tenantsetup` scope catalog, `internal/mgmt/auth.go`, `internal/seed/{seed,apply,validate}.go`; generated API files and console schema.

**Interfaces:** Handlers use Task 2 validation, Task 3 source validation and Task 4 repository CAS. Define `hostedlogin.Service` with `Store store.Store` and `Load(ctx context.Context, tenantID string) (*store.HostedLoginConfig,error)`; absence projects the legacy tenant, unavailable/other failures propagate. Mutations read fresh config, apply one resource operation and retry a CAS conflict at most three times.

- [ ] Write `TestBrandingManagementContract`, `TestThemeManagementContract`, `TestPromptManagementContract`: all inventoried operations, media types, scopes, lifecycle, empty/null, body limits, wrong tenant, revoked grants and reserved tenant. Assert `/themes/default` is not treated as an ID, and template HTML is not accidentally JSON-quoted.
- [ ] Write `TestSeedHostedLoginOwnership`, `TestConcurrentTextAndBrandingWrites` and `TestPluginUnavailableBranding`. Assert omitted sections preserve current API records; migration reads old fields only once; seeded updates preserve unrelated text/theme IDs; concurrent successful updates both survive; third conflict produces no partial write; unavailable plugin gives a visible error, not empty settings.
- [ ] Run focused management/seed/server tests to capture failures. Implement handlers, `x-source` schemas, scope registration and seed projection; switch new writes away from legacy tenant fields. Reject unsafe template/partial writes before storage and never log raw submitted HTML or fields.
- [ ] Run `go generate ./...`, `go test -race ./internal/mgmt ./internal/seed ./internal/server ./api`; require exit 0. Commit `feat(mgmt): manage branding themes and login prompts`.

## Task 7: Apply branding, themes and page templates to hosted pages

**Files:** Create `internal/hostedlogin/{service_test,theme,theme_test}.go`, `internal/ui/branding_test.go`; modify `internal/ui/{ui,captcha}.go`, `internal/ui/templates/{layout,login,signup,consent,error,logout_confirm,logged_out,reset_request,reset_email_sent,reset_password,reset_success,reset_error,email_verification,device_code,device_confirm,device_result}.html`, `internal/login/{login,reset,verify,consent,device}.go`, `internal/email/{service,notifications}.go`, `internal/i18n/localizer.go`, `internal/oidc/logout.go`, app/server wiring and relevant tests.

**Interfaces:** `hostedlogin.ResolveTheme(config *store.HostedLoginConfig) (Theme,error)` returns typed safe CSS/asset values. Define `hostedlogin.LocalizedTenant(tenant *store.Tenant, config *store.HostedLoginConfig) *store.Tenant` as a deep-copy projection of canonical custom text; load it for every email/verification/reset/security-notification localizer as well as hosted pages. Add request-scoped presentation data to `ui.Tenant`; preserve the public Render helper shapes where practical. Widgets render to a buffer, then optional wrapper composition runs under the request context. Tenant resolution and auth remain outside the template engine.

- [ ] Write `TestHostedPageBrandingMatrix` for all spec §5 hosted pages plus explicit excluded protocol/system pages. Assert each inventoried active theme field alters its target style; base → theme precedence; deleting active theme/template restores baseline; current locale and text survive composition. Add `TestCanonicalEmailLocalization`: update an existing email text override through the new canonical store and assert verification/reset/welcome/security messages use it while the old tenant field stays stale; no-config fallback still uses legacy text. Test concurrent localized views cannot mutate shared tenant data.
- [ ] Write `TestBrandingFailureFallback`, `TestBrandingStoreFailure`, `TestBrandingCSP`, `TestCrossTenantBranding`. Assert render error keeps status/functional widget/CSRF/CAPTCHA/consent, storage error gives built-in 503, no partial response precedes headers, CSP includes only validated assets and existing CAPTCHA sources, callback form-action rules unchanged, no cross-tenant cache leak.
- [ ] Run `go test ./internal/ui ./internal/login ./internal/oidc ./internal/hostedlogin -run 'Branding|CSP|HostedPage' -count=1` before implementation. Refactor only the necessary layout/body boundary; retain original widgets, forms and translation hooks. Never wrap form-post/web-message responses.
- [ ] Run full affected package tests, including email/localization, with `-race` and existing authorization response-mode tests; expect exit 0. Commit `feat(ui): apply tenant branding to hosted authentication pages`.

## Task 8: Implement identifier-first database login

**Files:** Create `internal/login/{identifier,identifier_test}.go`, `internal/ui/templates/{login_id,login_password}.html`; modify `internal/login/login.go`, `internal/ui/ui.go`, `internal/server/server.go`, `internal/i18n/{keys.go,locales/en.json}` and transaction completion tests.

**Interfaces:** Add handlers `LoginIdentifierPost`, `LoginPasswordGet`, `LoginPasswordPost`, `LoginIdentifierResetPost` with `(http.ResponseWriter,*http.Request)`. Routes are POST `/u/login`, GET/POST `/u/login/password`, POST `/u/login/identifier`; existing login handler dispatches combined versus captured two-step flow. Use Task 2 CAS for `identifier → password → authenticating` and password-stage reset after ordinary failure.

- [ ] Write `TestIdentifierFirstFlow`, `TestIdentifierFirstNoLookup`, `TestIdentifierFirstBindings`, `TestIdentifierFirstReplay`, `TestIdentifierFirstProtection`, `TestIdentifierFirstSettingChange`. Assertions: valid login reaches same PKCE code flow; unknown/existing identifiers have the same first-step behavior; no custom DB call at step one; direct password stage denied; tampered posted identity never replaces stored identity; back/reset needs CSRF; expiry unchanged; in-flight flow survives setting change; combined login remains default.
- [ ] Add `TestIdentifierFirstConcurrentPassword` using two handlers sharing SQL and a counted blocking auth fake: one authentication invocation, one valid stage transition, second request denied, no second session/code. Add crash/in-progress fixture requiring restart; expiry and stale revisions cannot unlock it.
- [ ] Run focused login tests to capture failures. Implement state transitions and original localized screens; reuse existing connection eligibility, identity authentication and protection pipeline rather than copying it. On denied attempt restore password stage using the claimed revision; successful flow deletes state through existing completion.
- [ ] Run `go test -race ./internal/login ./internal/authz ./internal/protection ./internal/dbconn` and focused SQL/gRPC transition suites; expected exit 0. Commit `feat(login): add transaction-bound identifier-first login`.

## Task 9: Render localized partials and capture bounded transient fields

**Files:** Create `internal/hostedlogin/{partials,partials_test}.go`, `internal/login/prompt_fields_test.go`; modify login/signup handlers and templates, `internal/i18n/{localizer,validate,keys}.go` and tests/catalog.

**Interfaces:** `hostedlogin.CaptureFields(values url.Values, allowed map[string]bool) (map[string]string,error)` enforces spec §7. `allowed` comes from parsed rendered active form-content partials, never from the submitted form. Record `FormConfigRevision`/`FormScreen` via hosted CAS during GET and emit the resulting state revision in a hidden field. POST checks all three before capture; stale configuration/state requires redisplay with no auth call. This applies to combined login/signup as well as the two-step flow. `hostedlogin.RenderPartials(ctx context.Context, config *store.HostedLoginConfig, prompt, screen, language string, vars map[string]any) (map[string]string,error)` returns safe slot fragments. Preserve field state with Task 2 CAS and clear it when restarting identification.

- [ ] Write `TestPromptTextMapping`, `TestPartialSlotPlacement`, `TestPartialFieldLimits`, `TestPartialFieldRedisplay`, `TestPartialFieldLifecycle`. Assert four supported slots; future slots stored but not shown; 30 vars supported/31 rejected; Unicode character limit distinguished from byte limit; `${...}` substitution and locale fallback retained; `ulp-` declared fields accepted; duplicate/core/unknown/file/password-type controls rejected; 8 KiB total accepted and +1 rejected; no raw HTML echo; no metadata/token/mail/log side effects; transaction deletion removes values. Add `TestPartialConfigChangedBetweenGetPost` and `TestPartialCrossScreenOwnership`: changed config or stale hidden revision redisplays without auth/capture; identifier values survive password-stage capture; unchecked values clear only the owning screen; duplicate names across screens fail configuration validation; reset clears everything.
- [ ] Run `go test ./internal/i18n ./internal/hostedlogin ./internal/login -run 'Prompt|Partial' -count=1` before implementation. Extend the catalog/alias validation without claiming all stored future keys render. Add link-only Markdown handling with scheme validation; do not render arbitrary HTML from custom text.
- [ ] Integrate form-content capture only after cookie/CSRF checks and before authentication, without relaxing existing body limits. Do not implement Actions validation, script-context forwarding or legal-consent enforcement.
- [ ] Run full affected suites with `-race`; expected exit 0. Commit `feat(login): render localized prompt partials safely`.

## Task 10: Add isolated preview and live console editors

**Files:** Create `internal/mgmt/{system_branding,system_branding_test}.go`, `internal/server/system_branding_test.go`, `console/src/pages/branding/{Branding,Settings,Theme,Template,Prompts,TextPartials,Preview}.vue` and adjacent tests; modify schema, server wiring, `console/src/{router.ts,api/client.ts,api/schema.d.ts,layout/sections.ts,locales/en.ts}` and planned-page tests.

**Interfaces:** POST `/api/system/tenants/{tenant}/branding/preview` accepts `{screen,language,overrides?}` and returns `{html,warnings}`. Resolve target tenant before checking both token and persisted operator grants; require read branding/prompts scopes. Synthetic screen data is server-chosen. Reuse the same validators and renderer as production; preview enforces a stricter no-network policy.

- [ ] Write `TestBrandingPreviewAuth`, `TestBrandingPreviewNoSideEffects`, `TestBrandingPreviewIsolation`: reject M2M, wrong tenant, stale grants and reserved writes; apply 2 MiB body limit and render budgets; no transaction/ticket/session rows created; no real identifiers/URLs in preview; no external network calls.
- [ ] Run focused server/management tests and observe failures. Implement preview response with in-document CSP suitable for sandboxed srcdoc. Return validation diagnostics without raw private context.
- [ ] Write console tests for each editor: load/save/clear, visible stored-only fields, seed banner, permission denial, failed-read write lock, unsaved edits retained, stale responses resolved in reverse order, uncertain write refresh without retry, correct theme activation/deletion copy. Assert HTML never enters console DOM; iframe sandbox grants no scripts/same-origin/forms/popups/navigation; remote assets replaced with labeled placeholders.
- [ ] Implement accessible localized editors and synthetic preview selection for every supported screen. Regenerate schema/build assets through normal commands. Run `make console` and focused Go preview tests; expect exit 0. Commit `feat(console): configure and preview Universal Login branding`.

## Task 11: Exercise actual clients, migration and browser flows

**Files:** Create `tests/e2e/{m22-node-auth0.mjs,m22-mgmt-cli.mjs,m22-console.spec.mjs,run-m22-branding.sh}`; modify `tests/e2e/playwright.config.mjs`, existing deploy runner/comparator/fixtures/manifest, `internal/deploymigration/{export,export_test}.go`, `Makefile` and `.github/workflows/ci.yml`.

**Interfaces:** New `make e2e-branding` isolated local lane, explicitly wired into CI. Actual pinned clients and local fixture assets; no live upstream/paid domain dependency. Extend existing `make e2e-deploy` only for handlers whose discovery/CRUD prerequisites exist.

- [ ] Add SDK/CLI scenarios covering every supported operation, default lifecycle, template content types, text/partial clearing, scopes, two tenants and rejected unsafe content. Assert actual client response fields, not a custom test client that bypasses wire incompatibility.
- [ ] Add YAML/directory × generated/preserved credential round trips using nonempty branding/theme/template/prompt/text/partial fixtures for supported handlers. Assert repeat import stable and a changed field fails strict comparison. For blocked custom-domain-dependent export, assert/report the handler limitation and preserve exclusion; never normalize missing resources away or fake a domain. Keep ACUL excluded.
- [ ] Add browser scenarios for combined baseline and identifier-first success/failure/back, locale/custom text, branded signup/reset/verification/consent/logout/device pages, partial fields and preview confinement. Exercise theme/template deletion, two tenants, custom DB, CAPTCHA, failed preview and tenant-switch race. Check visual behavior at narrow/wide viewports and keyboard access using only zeroauthy's local pages.
- [ ] Add a two-server restart test proving default/theme updates and partial state isolation survive persistence; assert replay produces no duplicate authentication or session. Check protocol response pages retain original CSP.
- [ ] Run `make e2e-branding`, `make e2e-deploy`, `make e2e-email`, `make e2e`; require exit 0 for selected supported lanes. Record intentional skips and unavailable upstream/tool cases separately. Commit `test(e2e): verify branded login and migration`.

## Task 12: Final verification and implementation records

**Files:** Create `docs/branding.md`; modify README, roadmap, `docs/compat/{matrix,decisions,changelog-review}.md`, `docs/superpowers/plan-1-followups.md`, source/license records if necessary, and this plan's final acceptance record.

**Interfaces:** Operator guide covers active/future fields, migration precedence, seed ownership, theme lifecycle, supported syntax/CSS, asset CSP, fallback, preview restrictions, identifier-first restart semantics, transient partial data and plugin/tool upgrade limitations. Explain that Actions validation, custom domains, Classic and ACUL remain separate work.

- [ ] Review AC1–AC10 against the mapping below and obtain the implementation workflow's final review. Fix findings and rerun affected checks before claiming completion. Keep all legacy authentication/email tests; do not replace the baseline with only customized fixtures.
- [ ] Run `git diff --check`, changed Go formatting checks, `go vet ./...`, `go test -race ./...`, `./scripts/test-sql.sh`, `go generate ./...`, `make console`, `make check-sources`, `make e2e`, `make e2e-branding`, `make e2e-email`, `make e2e-deploy`, `make conformance`. Require exit 0 and unchanged generation on a second run. Record conformance pass/warning/review/skip counts; no certification claim.
- [ ] Record actual dated command results and unavailable observations; label any remaining compatibility differences precisely. Update roadmap completion only after acceptance is met, not because this plan was drafted. Record template-directory supersession and deferred Actions/custom-DB context/ACUL follow-ups.
- [ ] Commit `docs: branding and Universal Login; Plan 22 records`. Integration, merge and push are separate decisions.

## Acceptance mapping and handoff

| Acceptance | Tasks |
|---|---|
| AC1 wire/scopes/evidence | 1, 2, 6, 11 |
| AC2 storage/migration/seed | 2, 4, 5, 6 |
| AC3 effective branding | 7, 11 |
| AC4 safe rendering/email/preview | 3, 7, 10 |
| AC5 login/protection invariants | 4, 5, 8, 11 |
| AC6 text/partial semantics | 2, 6, 9, 11 |
| AC7 console | 10, 11 |
| AC8 clients/migration | 1, 11 |
| AC9 browser/conformance | 7, 8, 11, 12 |
| AC10 documentation | 1, 12 |

Task boxes track the implementation as it progresses. The drafting stage ran no tests. Review the spec's local choices before execution, particularly restricted template capabilities, theme activation, stored-only Classic/WebAuthn, and deferred ACUL. Native execution is a reasonable default because the rendering/state/storage interfaces are tightly coupled; any subagent-driven execution should preserve the task dependencies and shared interface contracts.
