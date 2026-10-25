# Plan 21 — Email Providers and Templates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver tenant-configurable email providers and bounded Liquid templates while preserving existing mailer and OIDC behavior.

**Architecture:** Explicit tenant-aware delivery composes validated persisted provider/template snapshots, a bounded renderer and transport adapters. Existing ticket and identity services retain security decisions; email hooks receive authoritative events only. Provider secrets use existing envelope encryption, and notification claims serialize duplicate suppression across stores and instances.

**Tech Stack:** Existing Go 1.26.7, Vue/TypeScript, OpenAPI generation, memory/SQLite/PostgreSQL/MySQL, protobuf/gRPC, Vitest/Playwright and pinned Auth0 client tools. A permissively licensed Go Liquid dependency is selected and pinned only after Task 2 proves resource bounds; no vendor transport SDKs.

**Spec:** [Plan 21 design](../specs/2026-10-25-zeroauthy-email-provider-templates-design.md). Read it before executing this plan. This is a proposed implementation plan, not an implementation record.

## Global Constraints

- Preserve issuer and tenant resolution, authorization redirects, PKCE, nonce/state, consent, token validation, sessions, refresh tokens and signing-key eligibility.
- Keep `email.Mailer.Send(context.Context, email.Message) error` and the global mailer constructor usable by existing callers/tests.
- No provider or `enabled:false` selects the configured server-wide driver. Failure of an enabled tenant provider never triggers fallback.
- Provider transports use standard protocols and small HTTP clients, without vendor SDKs.
- `custom` remains stored-only and cannot be enabled until Actions support exists; future template workflows remain stored-only.
- Local limits: API request 256 KiB; body source 128 KiB UTF-8; subject source 1 KiB; sender source 1 KiB; result URL source 4 KiB; serialized render context 64 KiB; nesting depth 32; cumulative loop iterations 10,000; evaluation steps 100,000; output 256 KiB across all fields; render deadline 100 ms.
- Bound concurrent renders to eight per process with immediate capacity rejection. Template compilation cache, if used, is bounded to 128 entries and keyed by tenant/name/revision.
- Each send has a 15-second transport deadline within the caller's existing shorter deadline, no automatic delivery retry, and at most 64 KiB of provider response consumed.
- Provider secrets use length-prefixed AAD `email-provider/v1`, tenant ID and provider name; neither credentials nor rendered security links belong in logs.
- Test-send is limited durably to three attempts per operator/tenant per ten minutes; preview to 30 per operator/tenant per minute.
- No product implementation is authorized by the request to write this plan. Begin execution only when requested.
- The repository's Plan 19 database-test hold is specific to Plan 19; it does not defer Plan 21 tests.

## Review Focus

- A disabled or broken tenant provider must not unexpectedly send through another tenant or an unintended fallback (Tasks 7, 9).
- Concurrent PATCH and provider-kind changes must preserve the correct secret without returning it (Tasks 3–5, 8).
- A successful render with CR/LF, malicious HTML or a dynamic redirect must still be refused at its security boundary (Tasks 2, 7, 9, 11).
- A stale tenant/template response or uncertain send must not overwrite another tenant's editor or cause duplicate mail (Tasks 10–12).
- Verification replay, block retries and aliases must not multiply mail or send to an attacker-provided address (Tasks 3–5, 9–10, 12).

## File map and task order

New `internal/emailrules/` owns wire inventory, validated configuration and template policy. New `internal/store/email.go` owns persistence records/interfaces. New `internal/email/{service,render,context,notifications}.go` owns orchestration, rendering and event messages; `internal/email/providers/` owns vendor protocols and outbound dialing. Extend existing `internal/keys` for credential envelopes; existing login/dbconn/protection/jobs packages own event integration. Keep API handlers thin in `internal/mgmt/email_*.go` and UI in `console/src/pages/emails/`.

Tasks 1–2 freeze the contract and renderer feasibility; Tasks 3–5 implement all stores; Tasks 6–7 implement transports/service; Task 8 exposes CRUD; Tasks 9–10 wire runtime; Task 11 provides console/extensions; Task 12 supplies integration lanes; Task 13 verifies and documents completion. Do not integrate an unbounded renderer or claim a named provider implemented before its protocol tests pass. Parallel work is optional at execution time, never required to understand this plan.

## Task 1: Freeze public contracts and compatibility decisions

**Files:** Create `docs/compat/observations/management-email.md`, `internal/emailrules/inventory.json`, `internal/emailrules/inventory_test.go`; modify `docs/compat/{decisions,changelog-review}.md` and the spec if evidence changes it.

**Interfaces:** Produces the exact endpoint/provider/template/variable/settings inventory consumed by Tasks 2, 6 and 8. `inventory.json` records source URL and evidence class for every group; raw credentials and tenant identifiers are prohibited.

- [ ] Read the linked public API references and changelog; inspect the already pinned node-auth0/deploy-cli types under their licenses. Verify the eight operation routes, scopes and statuses. Record all fourteen names including `auth_email_by_code`; correct the roadmap collection POST path.
- [ ] Freeze create/replace/patch/null/unknown-field/error behavior, redacted credential metadata, provider settings, zero/null lifetime, legacy aliases and template defaults. Use the spec's named local fallbacks where docs are silent; record upstream observations as unavailable unless a separate authorized observer supplies notes.
- [ ] For every provider, record the vendor's official send/auth documentation, URL construction, required credential/settings fields, TLS/regions and success/error meanings. Resolve Azure/MS365 credential variants here, not by guesswork in adapter code. Record SDK method signatures and import/export resource names.
- [ ] Write `TestEmailInventoryComplete`: assert 8 operations, 14 template names, 9 executable provider names plus disabled-only `custom`, nonempty sources and evidence classes, and no duplicate route/method or schema field. Run `go test ./internal/emailrules -run TestEmailInventoryComplete -count=1`; demonstrate failure before loading the completed inventory, then PASS.
- [ ] Commit `docs: freeze Plan 21 email compatibility contract` with inventory and corrected spec. Do not label documentation review as live observation.

## Task 2: Prove and implement bounded Liquid rendering

**Files:** Create `internal/email/{render,render_test,render_fuzz_test,context}.go`, `internal/emailrules/{templates,templates_test}.go`; modify `go.mod`, `go.sum`, `NOTICE`.

**Interfaces:** Define `email.RenderInput struct { Fields map[string]string; Variables map[string]any }`, `email.Rendered struct { From, Subject, Text, HTML, ResultURL string }`, `email.Renderer interface { Render(context.Context, RenderInput) (Rendered, error) }`, and `email.NewRenderer() (Renderer, error)`. Define `emailrules.ValidateTemplate(raw map[string]json.RawMessage, partial bool) error`; Task 1 inventory controls fields. Export typed sentinel errors `ErrRenderLimit`, `ErrRenderSyntax`, `ErrRenderCapacity`.

- [ ] Write `TestRenderBudgets` and `TestRenderCapabilities`: assert nested loops exceeding cumulative 10,000 iterations fail, 100,001 steps fail, oversized intermediate filter/string allocations fail before allocation, ninth concurrent render fails promptly, and file/debug tags, object methods and unknown syntax cannot execute. Test exact byte boundaries including multibyte UTF-8, depth 33, output over 256 KiB and cancellation during parse/render.
- [ ] Run `go test ./internal/email -run 'TestRender(Budgets|Capabilities)' -count=1`; record the initial failure. Evaluate the candidate engine in a disposable local spike. Confirm cancellation and allocation checks inside execution, not just a caller timeout. Pin an acceptable release/license only after this gate passes. If it needs instrumentation/process isolation, document that concrete mechanism and update this task before integrating it.
- [ ] Implement the interfaces and supported tag/filter allowlist from the inventory. Use an explicit context projection; no whole-store object serialization. Limit parsing, intermediate values and execution, render deterministic errors, produce text without fetching HTML resources. Original defaults escape user-controlled values; custom Liquid retains documented explicit escaping semantics.
- [ ] Add `TestRenderContextSecrets`, `TestRenderMissingOptional`, `TestRenderFields`, `TestRenderParallelTenantIsolation` and fuzz seeds for nested ranges/filter amplification. Assertions: sentinel password/token/provider secret absent; absent optional value empty; required link rejected by event validation; separate tenant renders never share data. Run `go test -race ./internal/email ./internal/emailrules` and the targeted fuzz command `go test ./internal/email -run '^$' -fuzz FuzzRender -fuzztime 15s` after the fuzz target exists.
- [ ] Commit `feat(email): add bounded Liquid rendering and validation` only with demonstrated bounds and NOTICE attribution.

## Task 3: Define email storage, encryption and memory conformance

**Files:** Create `internal/store/email.go`, `internal/store/memory/email.go`, `pkg/storetest/email.go`, `internal/keys/{emailprovider,emailprovider_test}.go`; modify `internal/store/store.go`, `pkg/store/store.go`, memory store/transaction/tenant/user deletion wiring and `pkg/storetest` suite registration.

**Interfaces:** Add the following contract (all reads/writes deep-copy):

```go
type EmailProvider struct {
    TenantID, Name string
    Enabled bool
    DefaultFrom string
    PublicConfig map[string]any // allowlisted nonsecret credentials/settings
    SealedCredentials []byte
    Revision int64
}
type EmailTemplate struct {
    TenantID, Name string
    Fields map[string]any // validated effective Task 1 fields
    Revision int64
}
type EmailProviders interface {
    Get(context.Context, string) (*EmailProvider, error)
    Put(context.Context, *EmailProvider, int64) error
    Delete(context.Context, string, int64) error
}
type EmailTemplates interface {
    Get(context.Context, string, string) (*EmailTemplate, error)
    Put(context.Context, *EmailTemplate, int64) error
}
type EmailNotifications interface {
    Claim(ctx context.Context, tenantID, subjectID, purpose, eventKey string,
        now, expiresAt time.Time, limit int) (bool, error)
    Sweep(context.Context, time.Time, int) (int, error)
}
```

`Put` expected revision 0 means create-only; positive means exact-match update; template repository sets revision 1 or increments on success. Provider revisions come from a durable tenant-local counter allocated atomically with each successful Put; first value is 1, and provider deletion preserves the counter/tombstone so recreation always gets a higher revision. Remove the counter only on tenant deletion; Get still returns ErrNotFound for a deleted configuration. Mismatch is `ErrConflict`. Delete requires a matching revision; absent is `ErrNotFound`. Public idempotent DELETE is handled above the repository. `Claim` atomically increments an existing window counter up to limit; false means denied with no increment. Zero expiry means permanent; otherwise expiry must be after now. Key is tenant/subject/purpose/eventKey. Welcome uses permanent key; protection and extension throttles use fixed UTC window keys. Validate positive limit and reject absent tenant. User deletion removes its claims; system operator deletion removes its preview/test subject claims across all target tenants. Sweep deletes at most its limit of expired records, including empty results.

Encryption signatures: `keys.SealEmailProvider(w Wrapper, tenantID, provider string, plaintext []byte) ([]byte,error)` and matching `OpenEmailProvider(..., sealed []byte) ([]byte,error)`.

- [ ] Write shared tests for no-record reads, create/update CAS, delete, deep copies, wrong tenant, transactional rollback of all repositories, exact revision changes, delete/recreate monotonic revision and rejection of stale pre-delete CAS updates/deletes, permanent/window claims, concurrent limit enforcement, expired claim cleanup and user/tenant deletion. Write envelope tests that wrong tenant/provider/AAD/master key fail and sentinel secret never appears in stored bytes/errors.
- [ ] Run `go test ./internal/keys ./internal/store/memory ./pkg/storetest -run 'Email|Provider' -count=1`; observe failure before implementing new repositories/crypto helpers.
- [ ] Implement records, encryption, exported plugin aliases and memory repositories, including transaction snapshots and cascade paths. Do not store cleartext in public config or claims. Public projection uses Task 1 allowlists rather than removing only known secret keys.
- [ ] Run the same focused tests with `-race`; run the memory conformance package in full. Confirm legacy tenants require no new email record and existing mailer-focused tests compile.
- [ ] Commit `feat(store): add email configuration and notification claims`.

## Task 4: Persist email configuration and claims in SQL

**Files:** Create `internal/store/sqlstore/email.go`, three `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0018_email.sql` files, and `internal/store/sqlstore/email_test.go`; modify SQL repository, transaction and user/tenant deletion wiring.

**Interfaces:** Implements Task 3 unchanged. Provider/template keys include tenant IDs; claims use a unique compound key. Provider revision counters survive configuration deletion; CAS, counter allocation and claim-limit operations serialize through database transactions, not a process mutex. Add expiry index for bounded sweep.

- [ ] Enable shared email conformance for SQL and add `TestEmailRestart`, `TestEmailConcurrentHandles`, `TestEmailUpgradeWithoutRecords`, `TestEmailCredentialsAtRest`. Assert two separately opened handles cannot exceed claim limit or lose a provider update, rollback restores ciphertext/revision, and legacy installations retain empty configuration after upgrade.
- [ ] Run the focused SQLite tests and capture failures; compile migration statements for all three dialect paths before implementation.
- [ ] Implement schema and repositories using existing dialect/transaction conventions. Preserve ciphertext as bytes and JSON shape/null distinctions from the inventory. All queries include tenant keys; all cascade paths delete claims/configuration.
- [ ] Run `go test ./internal/store/sqlstore -run Email -count=1`, then `./scripts/test-sql.sh` for actual SQLite/PostgreSQL/MySQL parity. Record actual outcomes; never substitute SQLite for the other dialects.
- [ ] Commit `feat(store): persist tenant email settings across SQL backends`.

## Task 5: Carry the email contract across plugin/gRPC stores

**Files:** Modify `proto/store/v1/store.proto`, `internal/store/grpcstore/{client,client_repos,server,server_repos,codec,conformance_test}.go` and generated protobuf files; add `internal/store/grpcstore/email_test.go`.

**Interfaces:** Task 3 repositories cross RPC with opaque ciphertext, int64 revisions, timestamp presence and unchanged claim semantics. Transactional callback views must use the transaction's repositories.

- [ ] Write `TestEmailGRPCRollback`, `TestEmailGRPCClaims`, `TestEmailGRPCUnimplemented`, and codec round-trip cases for nested fields, empty/null settings, ciphertext and permanent expiry. Assert unsupported server operations propagate an error rather than falling back to empty config/global delivery.
- [ ] Run `go test ./internal/store/grpcstore -run Email -count=1` and observe failure. Add RPCs/codecs/client/server wrappers following existing protection/signing patterns; regenerate using repository generation commands.
- [ ] Run shared conformance plus SQL-backed gRPC rollback and concurrency tests with `-race`. Confirm sentinel credentials do not appear in error/debug output and generated files are reproducible.
- [ ] Commit `feat(store): expose email repositories over gRPC`.

## Task 6: Implement the nine provider transports

**Files:** Create `internal/email/providers/{transport,outbound,smtp,sendgrid,mailgun,mandrill,sparkpost,resend,ses,azure,ms365}.go` and adjacent `_test.go` files; modify `internal/config/{config.go,config_test.go}` for explicit operator outbound/development options. Use `internal/email/providers/message.go` for provider-neutral wire data to avoid an import cycle.

**Interfaces:** Define `providers.Config struct { Name string; Credentials, Settings map[string]any }`, `providers.Message struct { From, To, Subject, Text, HTML string }`, `providers.Transport interface { Send(context.Context, Message) error }`. `providers.Factory.New(ctx context.Context, tenantID string, revision int64, cfg Config) (Transport,error)` uses injected dialer/HTTP client/clock for tests; production construction fixes endpoints and enforces outbound policy. No provider imports parent `email`.

- [ ] Write table-driven `TestProviderProtocols` against local HTTP/SMTP fakes. Assert exact auth/payload/sender mapping, EU/default region, SES SigV4 with official reference vectors, Azure signing, MS365 token cache tenant/revision isolation including delete/recreate with new credentials, and single Graph send, and redacted errors. Test every executable name; `custom` must reject construction.
- [ ] Write `TestOutboundPolicy`: DNS rebinding, multiple-address private answers, IPv4-mapped IPv6, metadata/loopback, invalid region/domain injection, redirects, TLS certificate mismatch, STARTTLS refusal and operator allowlist. Test public default vs explicitly allowlisted local SMTP. No test disables production TLS globally.
- [ ] Run `go test ./internal/email/providers -count=1` and capture red results. Implement each adapter from Task 1 vendor sources, centralized bounded errors/deadlines and fixed host policy; translate provider acceptance responses accurately.
- [ ] Add slow response, over-64-KiB error, disconnect-after-acceptance and cancelled-context cases; assert no retry/fallback and no secret in errors. Run `go test -race ./internal/email/providers ./internal/config`.
- [ ] Commit independently testable adapter groups if useful, ending with all nine passing: `feat(email): add tenant SMTP and HTTP provider transports`. Do not omit complex providers while marking this task complete.

## Task 7: Compose tenant delivery and legacy fallback

**Files:** Create `internal/email/{service,service_test,policy,policy_test}.go`; modify `internal/email/{email,message,smtp,dir,log}.go`, existing email tests and constructor wiring as needed.

**Interfaces:** Define `email.Event struct { TenantID, UserID, ClientID, Template, Language, URL string; Variables map[string]any }`; trusted callers supply explicit tenant IDs and approved variables only. Define `email.Service` with Store, Wrapper, Renderer, Providers, Fallback and clock dependencies. Methods: `Resolve(ctx context.Context, tenantID, name string) (Policy,error)`, `Send(ctx context.Context, event Event) error`, `SendMessage(ctx context.Context, tenantID string, msg Message) error`. `Policy` contains `Enabled bool`, `Template *store.EmailTemplate`, `Lifetime time.Duration`, `ResultURL string`, `IncludeEmailInRedirect bool`; returned values preserve no-record defaults. Add optional `Message.From string`. No changes to `Mailer` signature.

- [ ] Write `TestTenantDeliverySelection` covering absent/disabled/deleted/valid/broken provider, disabled template, absent legacy templates, provider read failure, decrypt failure and two-tenant isolation. Assert enabled-provider errors make zero fallback sends; no-record calls emit the old localized content through existing recorder mailers.
- [ ] Write `TestRenderedHeaders` and `TestProviderSnapshot`: validate rendered sender/recipient/subject before transport; mutation affects later sends but cannot alter an in-flight snapshot. Test secret/context sentinel redaction and capacity/renderer failures without mail.
- [ ] Run `go test ./internal/email -run 'Test(TenantDelivery|RenderedHeaders|ProviderSnapshot)' -count=1`; observe failure, then implement selection, sender precedence, bounded render context and explicit dependencies. Extend legacy log/dir/SMTP formatting safely for optional From, preserving their prior defaults and log-link redaction.
- [ ] Run `go test -race ./internal/email ./internal/email/providers` including unchanged original tests. If caching compiled templates, test eviction at 128 entries and revision/tenant separation; otherwise omit the cache.
- [ ] Commit `feat(email): route messages through tenant policy with legacy fallback`.

## Task 8: Expose Management API provider and template CRUD

**Files:** Modify `api/management.yaml`, `internal/system/system.go`, `internal/tenantsetup` scope catalog, `internal/mgmt/clients.go`, `internal/server/server.go` and generated Go/console schema; create `internal/mgmt/{email_provider,email_templates,email_provider_test,email_templates_test}.go`, `internal/server/mgmt_email_test.go`, `internal/emailrules/{provider,provider_test}.go`.

**Interfaces:** Generated operation IDs: `GetEmailProvider`, `CreateEmailProvider`, `PatchEmailProvider`, `DeleteEmailProvider`, `CreateEmailTemplate`, `GetEmailTemplate`, `PutEmailTemplate`, `PatchEmailTemplate`; use the handler signature pattern of existing generated interfaces. Provider rule helpers: `ValidateProvider(raw map[string]json.RawMessage, current *store.EmailProvider) error` and `ProjectProvider(*store.EmailProvider) map[string]any`; projection never opens secrets. Use Task 3 CAS and Task 2 validation. Extend the actual existing scope catalog wherever Task 1 locates it, not only a UI permission list.

- [ ] Write HTTP tests for all eight operations with full-scope, read-only, missing-scope, wrong issuer/audience/tenant and reserved-tenant credentials. Assert Task 1 statuses and all field/null/default semantics. Test no-record 404, create conflict, PUT vs PATCH and disabled-only `custom`.
- [ ] Write `TestProviderSecretPatch` with sentinel secrets: omitted preserve, replacement changes, blank/mask rejects, kind switch drops old, concurrent updates retry at most three times and one conflict has no partial writes. Assert GET/create/patch/export/log/error never contains the sentinel; test invalid template source fails save.
- [ ] Run focused management/server tests to see failures. Keep operation scope checks in `internal/tenantsetup` catalog and handler routing aligned. Implement schemas with `x-source`, generated handlers, scope catalog and rules. Audit successful writes using existing repository logging conventions, with tenant/actor/template/provider names only. Add limits before decoding request bodies.
- [ ] Run `go generate ./...`, console type generation, `go test -race ./internal/mgmt ./internal/server ./api`, and verify a second generation creates no diff.
- [ ] Commit `feat(mgmt): manage tenant email providers and templates`.

## Task 9: Integrate verification, reset, welcome and import messages

**Files:** Modify `internal/login/{verify,verify_test,reset,login}.go`, `internal/dbconn/{dbconn,signup,signup_test,reset,reset_test}.go`, `internal/jobs/{importer,importer_test,verify_test}.go`, `internal/app/app.go`, `internal/server/server.go`; create `internal/email/{notifications,notifications_test}.go`, new original welcome text/HTML templates and localized strings.

**Interfaces:** Use Task 7 `Resolve` before ticket creation and `Send` after the existing ticket issuer returns its link. Add `email.Service.Welcome(ctx context.Context, tenantID, userID, clientID, language string) error`, claiming Task 3 permanent welcome key only for eligible enabled messages. Keep `VerificationMailer.SendVerification` and existing dbconn verifier interface intact; add narrow optional lifecycle hooks where needed rather than an email→login import.

- [ ] Extend old verify/reset tests in place with no-record cases; add `TestEmailTemplateTicketPolicy`, `TestWelcomeAfterVerification`, `TestWelcomeSignupBothPaths`, `TestNoWelcomeFromManagementImport`, `TestImportCompletionTenantProvider`. Assert defaults unchanged, explicit ticket API precedence, disabled message creates no ticket, replay makes no new welcome, wrong tenant/user fails, mail failure cannot undo successful account mutation.
- [ ] Test lifetime 0/default/604800/604801, unsafe dynamic redirect, cross-origin callback rejection, missing client and trusted tenant origin; exact HTTPS `Client.Callbacks` equality (no wildcards/prefixes), no userinfo/fragment, and retention of both internal ClientID and validated ResultURL; assertion: none modifies OIDC redirect_uri/issuer/state or relaxes single-use ticket consumption. Verify no-record old result redirect semantics stay intact.
- [ ] Run `go test ./internal/login ./internal/dbconn ./internal/jobs -run 'Email|Welcome|Verify|Reset|Import' -count=1` to see failures. Add an email-only redirect validator; leave public Management ticket validation and OAuth callback matching unchanged. Implement event hooks for hosted and Authentication API signup, successful verification transitions, and import completion transport. Keep admin creates/imports/linking free of new welcome side effects.
- [ ] Run those packages in full with `-race` plus existing ticket management tests. Verify nil legacy mock injection still works and background hooks carry explicit tenant/user IDs after request contexts end.
- [ ] Commit `feat(email): apply tenant templates to account email flows`.

## Task 10: Send deduplicated attack-protection notifications

**Files:** Modify `internal/protection/{service,events,breach}.go` and their tests; extend `internal/email/notifications.go`, add protection email templates/localization; modify server/app hook wiring and user/tenant cleanup tests.

**Interfaces:** Add `protection.Notifier interface { Notify(ctx context.Context, tenantID, userID, purpose string) error }` to `protection.Service`; implement it on `email.Service`. Purposes are `blocked_account` and `stolen_credentials`. Claim keys use purpose and fixed UTC 24-hour windows with limit 1; resolve canonical user address from the tenant store, not the supplied identifier.

- [ ] Write `TestNotificationAfterAuthoritativeEvent`, `TestNotificationAliasRecipient`, `TestNotificationConcurrentInstances`, `TestNotificationFailedSendClaim`, `TestAdminNotificationStillDeferred`. Assert no notification at `Begin` merely because a shield exists, no mail to unknown/attacker identifiers, no suspicious-IP user notice, both purposes independent, concurrent instances send once, uncertain failure retains claim.
- [ ] Run `go test ./internal/protection ./internal/email -run Notification -count=1` and capture failures. Move user notification calls to actual block/breach outcomes; preserve monitor/block semantics and existing public responses. Keep admin warning distinct. A notification failure never reverses the security decision.
- [ ] Wire bounded asynchronous sends with redacted outcomes; connect claim sweep to existing bounded maintenance and cascade subject deletion. Add boundary tests across midnight UTC and verify the documented fixed-window semantics (not a sliding 24-hour claim).
- [ ] Run `go test -race ./internal/protection ./internal/email ./internal/login ./internal/dbconn`, plus shared claim conformance on SQL/gRPC after wiring changes.
- [ ] Commit `feat(protection): deliver tenant security notification emails`.

## Task 11: Provide operator preview/test APIs and live console pages

**Files:** Create `internal/mgmt/{system_email,system_email_test}.go`, `internal/server/system_email_test.go`, `console/src/pages/emails/{Provider,Templates,Preview}.vue` and adjacent tests; modify `api/management.yaml`, `internal/server/server.go`, `internal/mgmt/auth.go`, `console/src/{router.ts,api/client.ts,api/schema.d.ts,locales/en.ts}`, `console/src/layout/{sections.ts,sections.test.ts}`, and console generated assets via `make console`.

**Interfaces:** System-host POST `/api/system/tenants/{tenant}/emails/preview` and `/test`, with tenant-name lookup and target-aware operator authentication. Resolve the path tenant before the operator grant check on these two routes; require both signed token and persisted grants against that target, while preserving system-host/operator-only restrictions. Existing operators have all catalog scopes; do not add a fictional read-only operator model. `PreviewEmail` accepts `{template,overrides?}` and returns Task 2 rendered fields; `TestEmail` accepts `{template}`, chooses the verified operator address itself and returns 204 on acceptance. Synthetic `example.invalid` URLs only, no real ticket issuance. Task 3 claims enforce fixed UTC minute/ten-minute window limits (30/3).

- [ ] Write HTTP tests for system-host restriction, tenant access, required delegated scopes, operator-only preview, verified operator-only send, no arbitrary recipient, real-template eligibility, reserved tenant, bounded overrides and distributed limits. Assert M2M cannot preview or send; a tenant-limited operator succeeds for its own target and fails for another, stale token grants and revoked persisted grants independently deny access, other system routes are unchanged, accepted is not claimed delivered, and transport failure consumes its started attempt.
- [ ] Run those tests and observe failures. Implement the extensions with safe errors, synthetic context and redacted audit metadata; regenerate types. Add public docs in the schema labeling both zeroauthy-specific extensions.
- [ ] Write provider/template UI tests before replacing the planned page: stored-only labels, empty secret inputs with omission semantics, failed-read lock, edits preserved on errors, delete fallback confirmation, loading/permission guards and template selection. For stale responses, resolve requests in reverse tenant/template order and assert only current content changes.
- [ ] Write preview tests asserting sandbox has no script/same-origin/form capability, CSP prevents remote resources, and app DOM never receives template HTML. Lost send/write response must refresh state and show uncertainty without retry; assert exactly one POST. Verify preview can use unsaved edits, send uses saved template, and button copy explains this distinction.
- [ ] Implement typed API helpers, accessible forms, localized copy and sandboxed preview. Run `make console` and focused Go extension tests, then commit `feat(console): configure and test tenant email delivery`.

## Task 12: Exercise SDK, deploy-cli and browser email flows

**Files:** Create `tests/e2e/m21-node-auth0.mjs`, `tests/e2e/m21-console.spec.mjs`, `tests/e2e/run-m21-email.sh`, `tests/e2e/email-server/{http_test,shared_test}.go`; modify the actual e2e Make include/runner files discovered alongside existing `run-m20-signing.sh`, `.github/workflows/ci.yml`, `tests/e2e/deploy-cli/{config.json,seed.yaml}`, `tests/e2e/m20-deploy-cli.mjs`, `internal/deploymigration/{export,export_test}.go` and manifest.

**Interfaces:** New `make e2e-email` lane uses isolated fresh DB/tenant fixtures, directory capture and local SMTP/HTTP transports; no paid provider credentials. Existing `make e2e`, `make e2e-deploy` remain runnable. Preserve exact deployment credential exclusions and deletion-disabled imports established in Plan 20.

- [ ] Write SDK scenarios using current pinned node-auth0 `emails.provider` and `emailTemplates`: all operations, secret redaction, scopes, errors and tenant separation. Extend actual pinned deploy-cli tests to include nonempty email provider/template resources in both YAML/directory and generated/preserved credential modes. Do not fake exports or broaden comparator normalization.
- [ ] Establish export-secret behavior from Task 1. Import provider credentials only via explicit operator/private test configuration, never committed seed credentials or a GET secret-recovery path. Assert raw/masked secret values are absent from public export, private reinjection preserves the expected test credential, repeat import is stable and a changed template/provider setting fails strict comparison until updated.
- [ ] Add two-server SQL tests for current-config visibility, CAS provider updates, welcome/protection/test-send dedupe, store restart, tenant deletion and unaffected legacy fallback. Assert failed/unknown sends do not trigger another provider.
- [ ] Add browser flow: create a custom verification/welcome template; signup; read captured directory email; consume verification link; capture custom welcome once; replay the link and assert no extra message. Configure allowlisted local SMTP for a second tenant and prove delivery moves only for that tenant. Test stored-only labels, cross-tenant editor race, forbidden write and aborted send response with no repeat POST.
- [ ] Run `make e2e-email`, `make e2e-deploy`, `make e2e`; every selected local case must pass or have a concrete failure fixed before completion. Wire `e2e-email` into CI so default harness skips cannot conceal this lane. Record unsupported tool handlers separately from executed cases.
- [ ] Commit `test(e2e): verify tenant email delivery and migration`.

## Task 13: Verify the whole change and publish implementation records

**Files:** Create `docs/email.md`; modify README, roadmap, compatibility matrix/decisions, source/license records and this plan's final acceptance record. Update only real generated/dist artifacts from standard generation commands.

**Interfaces:** Produces operator instructions covering server fallback, provider credentials/TLS/outbound allowlists, templates and escaping, active/stored-only workflows, test-send semantics, delivery uncertainty, fixed-window throttles, plugin upgrades and migration secret reinjection. No claim of upstream observation or OIDF certification without its own evidence.

- [ ] Review AC1–AC10 against Tasks 1–12; obtain the final implementation review required by the execution skill, fix material findings, and rerun affected tests. Confirm old tests remain in place and no unrelated OIDC behavior changed.
- [ ] Run `git diff --check`, changed-file gofmt checks, `go vet ./...`, `go test -race ./...`, `./scripts/test-sql.sh`, `go generate ./...`, `make console`, `make check-sources`, `make e2e`, `make e2e-email`, `make e2e-deploy`, and `make conformance`. Compare generated outputs across a second run. Expected: exit 0; record conformance pass/warning/review/skip counts, not just command success.
- [ ] Record actual command/date/results and all unavailable live provider/upstream lanes. Check source attribution for Liquid and official adapter protocol docs. Do not mark Tasks 1–13 complete from this proposed plan.
- [ ] Commit `docs: email providers and templates; Plan 21 records`. Integration/merge/push is a separate execution decision and is not part of this documentation request.

## Acceptance mapping and execution handoff

| Spec acceptance | Owning tasks |
|---|---|
| AC1 contract and API | 1, 8, 12 |
| AC2 stores/secrets | 3, 4, 5 |
| AC3 fallback/legacy | 7, 9, 12 |
| AC4 transports | 1, 6, 12 |
| AC5 rendering | 2, 7, 11 |
| AC6 runtime/OIDC | 9, 10, 12, 13 |
| AC7 console | 11, 12 |
| AC8 SDK/migration | 8, 12 |
| AC9 browser/conformance | 12, 13 |
| AC10 docs/limitations | 1, 13 |

Implementation has not started. Review the spec and plan before execution; either native or task-by-task subagent execution can follow these interfaces. Native execution is a reasonable default because store, rendering and delivery boundaries are tightly coupled, with independent whole-branch review before completion.
