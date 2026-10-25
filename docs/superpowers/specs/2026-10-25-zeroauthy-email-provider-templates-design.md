# zeroauthy — Plan 21 design: email providers and templates

- **Status:** Proposed implementation contract; documentation only. No implementation or live provider testing is claimed.
- **Date:** 2026-10-25
- **Baseline:** Plan 20, `5919dc6`; [management roadmap](2026-10-19-zeroauthy-management-roadmap-design.md#plan-21--email-provider-and-email-templates).
- **Implementation:** [Plan 21 tasks](../plans/2026-10-25-zeroauthy-plan-21-email-provider-templates.md).
- **Policy:** [CLEAN_ROOM.md](../../../CLEAN_ROOM.md). Public documentation and licensed client tools only; a separate authorized observer supplies sanitized upstream observations.

## 1. Outcome, boundaries and compatibility

Operators configure one email provider per tenant, edit reusable Liquid email templates, preview them safely, and send a test message. Existing verification and password-reset flows use that configuration. New welcome and attack-protection messages use the same delivery service. Existing installations continue to work with the server-wide log, directory or SMTP driver without creating tenant email records.

Included: provider and template Management APIs; encrypted credentials; memory, SQLite, PostgreSQL, MySQL and gRPC parity; bounded rendering; nine transport adapters; live console pages; SDK, deploy-cli and browser coverage. Keep the current Go/Vue toolchain. Provider transports use standard protocols and small HTTP clients, without vendor SDKs.

Excluded: Actions execution (`custom` remains stored-only until the Actions plans), MFA/code authentication/invitations/async approval workflows, branding/custom domains, email queues with guaranteed delivery, bounce ingestion, analytics and a general bulk-mail API. Template storage does not imply that its future workflow is implemented. Existing import-completion messages retain their original embedded content but use the tenant's transport.

**OIDC invariant:** Preserve issuer and tenant resolution, authorization redirects, PKCE, nonce/state, consent, token validation, sessions, refresh tokens and signing-key eligibility. An email template cannot mark an account verified, mint a login token, authorize an arbitrary callback or change ticket single-use semantics. Extend old tests; do not replace them with exclusively tenant-configured fixtures. Retain an explicit no-email-record baseline through every store/runtime migration.

The choices labeled **local** below are design recommendations, not observed Auth0 behavior or previously approved user decisions. They make this plan implementable without an upstream account. Task 1 records exact compatibility facts and any differences before dependent implementation.

## 2. Sources and contract freeze

Public sources reviewed for this draft:

| Source | Fact used |
|---|---|
| [Provider create](https://auth0.com/docs/api/management/v2/emails/post-provider), [provider overview](https://auth0.com/docs/customize/email/smtp-email-providers) | Singleton provider configuration; supported provider names and credential families. |
| [Template create](https://auth0.com/docs/api/management/v2/email-templates/post-email-templates), [template patch](https://auth0.com/docs/api/management/v2/email-templates/patch-email-templates-by-template-name) | Create is the collection path, updates use the named path; template fields and names include `auth_email_by_code`. |
| [Liquid syntax](https://auth0.com/docs/customize/email/email-templates/supported-liquid-syntax) | Context-dependent variables, filters and tags; unsafe capabilities require explicit local restrictions. |
| [Template customization](https://auth0.com/docs/customize/email/email-templates/customize-email-templates) | Custom templates belong to particular workflows; redirect behavior varies by flow. |
| [Candidate Go Liquid engine](https://github.com/osteele/liquid) | Candidate only; pin/license and bounded execution must be proved before adoption. |

Task 1 produces a checked-in inventory with each endpoint's scopes, statuses, required/nullable fields, defaults, omission behavior, provider-specific credential/settings schema, template lifecycle semantics and SDK calls. Separate documented facts, observations and local fallbacks. Review the public changelog since the last repository review. Do not query undocumented dashboard endpoints or send upstream email as part of passive observation. No upstream credentials were used in drafting these documents.

A missing observer is recorded as unavailable, never passing. Public documentation plus explicit local choices may freeze the contract; unresolved contradictions affecting credentials, template aliases or ticket behavior must be resolved in the documents before those tasks proceed. No silent promise of full upstream parity.

## 3. Management API

| Method and route | Required scope | Intended success |
|---|---|---|
| GET `/api/v2/emails/provider` | `read:email_provider` | 200, redacted provider |
| POST `/api/v2/emails/provider` | `create:email_provider` | 201, created redacted provider |
| PATCH `/api/v2/emails/provider` | `update:email_provider` | 200, updated redacted provider |
| DELETE `/api/v2/emails/provider` | `delete:email_provider` | 204 |
| POST `/api/v2/email-templates` | `create:email_templates` | 200, template |
| GET `/api/v2/email-templates/{templateName}` | `read:email_templates` | 200, template |
| PUT/PATCH `/api/v2/email-templates/{templateName}` | `update:email_templates` | 200, template |

Task 1 verifies these intended scopes/statuses against sources and the pinned SDK. Reuse tenant Management API authorization and operator delegation, including reserved-system-tenant write restrictions. Wrong-tenant requests cannot expose provider configuration, template content or secret presence. No template DELETE or collection GET is invented for Auth0 compatibility.

**Local lifecycle defaults:** unconfigured provider/template GET returns 404; POST conflicts with an existing record; PATCH requires an existing record; template PUT replaces or creates the named record; deleting an absent provider returns 204. PATCH preserves omitted fields and applies explicit false/zero values. Null handling is field-specific in the inventory, never a generic merge patch. PUT supplies all required fields and resets omitted optional fields to frozen defaults. Unknown names/fields fail validation. A named request cannot change its template identity.

### 3.1 Provider configuration and secrets

Support `smtp`, `sendgrid`, `mailgun`, `mandrill`, `sparkpost`, `ses`, `azure_cs`, `ms365`, `resend`; accept `custom` only with `enabled:false` until Actions exists. Reject enabling unsupported execution with an actionable validation error. Common fields are `name`, `enabled`, `default_from_address`, `credentials`, `settings`; the Task 1 inventory defines exact allowed keys per variant. Do not accept inert provider settings while presenting them as effective.

Store credential material as an envelope-encrypted blob bound through length-prefixed AAD to `email-provider/v1`, tenant ID and provider name. Reuse `internal/keys` wrapping primitives; never persist cleartext secrets or expose them in GET, write responses, audit, errors, export, logs or gRPC debug output. Export-safe public credential metadata is separately projected from an allowlist. OAuth access tokens for MS365 are short-lived in-memory values keyed by tenant and configuration revision.

PATCH of the same provider preserves omitted secret fields; supplied nonempty secret values replace them. Empty strings/null/masked placeholders do not mean keep-secret and fail validation for required credentials. A provider-name change requires the full new credential set and drops the old one atomically. No merge occurs across provider kinds. Compare-and-swap revisions prevent lost secret updates; internal conflicts are retried with a fresh snapshot at most three times, then fail without a partial write. Public revision metadata is a zeroauthy extension only if separately exposed, not an invented Auth0 field.

### 3.2 Template inventory and effective behavior

Store all fourteen documented names: `verify_email`, `verify_email_by_code`, `auth_email_by_code`, `reset_email`, `reset_email_by_code`, `welcome_email`, `blocked_account`, `stolen_credentials`, `enrollment_email`, `mfa_oob_code`, `user_invitation`, `async_approval`, `change_password`, `password_reset`.

Fields: `template`, `body`, `from`, `subject`, `syntax`, `enabled`, `resultUrl`, `urlLifetimeInSeconds`, `includeEmailInRedirect`. Only Liquid syntax executes. Distinguish omitted/null/default in input DTOs; persistence holds the effective validated record. Store future workflow fields faithfully, and mark the associated templates stored-only in the console and compatibility matrix.

**Local alias rule:** `reset_email` is the active reset-link template. `change_password` and `password_reset` remain independently stored legacy resources and are not silently mapped to it. Future code templates, MFA, invitations and async approval are stored-only. Task 1 must explicitly confirm this local difference or replace it with supported alias evidence; no double dispatch.

No record uses existing localized verification/reset defaults. An explicitly disabled active template suppresses that message; it does not fall back to an enabled default. Absent welcome/protection records use new original localized defaults; welcome is disabled by default, protection messages are enabled when the corresponding shield is selected. Existing verification/reset defaults remain enabled. Custom templates may use the server-wide fallback transport: this is a deliberate self-hosting extension.

## 4. Persistence and service boundaries

Add `EmailProviders()`, `EmailTemplates()` and `EmailNotifications()` repositories to the store contract and public plugin aliases. Provider records carry encrypted credentials, safe configuration and a monotonic revision. Allocate provider revisions from a durable tenant-local counter that survives provider deletion; deleting configuration leaves only this nonsecret counter/tombstone. Recreating a provider receives a higher revision, never 1 again. Delete the counter only with the tenant. This prevents stale CAS writes/deletes and cached MS365 tokens from matching a recreated configuration across instances. Template records are keyed by tenant/name with revisions. Notification claims carry tenant, user ID, purpose, stable event key and expiry; no recipient address, message body or raw ticket. Use a unique key and atomic claim operation for cross-instance deduplication. Claims expire after their applicable window; cleanup is bounded and runs through the existing cleanup lifecycle. Permanent welcome claims are removed with their user; deleting a system operator removes that subject’s preview/test claims across target tenants.

Create migration `0018_email.sql` for all SQL dialects, respecting migrations allocated before implementation. Do not eagerly populate email settings for existing tenants. Include transactional rollback, deep copies, concurrent writes, restart and tenant deletion in shared store conformance. gRPC must transport opaque ciphertext, revisions and claim operations. Older plugins fail closed for unsupported email operations; deployment docs require rebuilding plugins rather than inventing successful empty configuration.

Keep `email.Mailer.Send(context.Context, email.Message) error` and the global mailer constructor usable by existing callers/tests. Add an explicit tenant delivery service; never infer a tenant from a background context or recipient domain. Extend `Message` with optional `From` while keeping legacy zero-value behavior. Validate the sender and recipient before any transport. All runtime paths, including import completion, pass the tenant ID explicitly to the new service; constructor wiring retains legacy mock injection for existing focused tests.

Read current provider/template state at the start of each send. A provider change affects later sends; an already-started send may complete using its snapshot. Do not retain stale decrypted configuration across sends. Template compilation cache, if used, is bounded to 128 entries and keyed by tenant/name/revision.

## 5. Transport selection, safety and failures

**Local selection rule:** no provider or `enabled:false` selects the configured server-wide driver. An enabled tenant provider selects only that provider. Failure to load/decrypt/render/connect/send does not switch to the global driver; silent failover could leak messages and conceal configuration errors. Deleting a provider restores the global fallback. `custom` cannot be enabled.

For custom templates, sender precedence is rendered template `from`, then provider default, then global configured sender. Empty/null template sender uses the next source. Legacy embedded messages also use the provider default when present. Header CR/LF and invalid/multiple addresses are rejected after rendering; multipart text/HTML encoding remains centralized. Generate readable text from custom HTML without executing markup or fetching resources.

Each send has a 15-second transport deadline within the caller's existing shorter deadline, no automatic delivery retry, and at most 64 KiB of provider response consumed. Non-2xx HTTP replies and SMTP failures become bounded typed/redacted errors, never reflected upstream bodies. For asynchronous cloud acceptance, report accepted rather than delivered; no delivery guarantee is implied. MS365 token acquisition may refresh a token before the single send attempt, but cannot replay a possibly accepted send.

SMTP requires verified TLS (implicit TLS or STARTTLS); an explicit server-level development option can allow plaintext to configured destinations, never via tenant API. Tenant-selected SMTP endpoints use a shared outbound policy: resolve and validate every address, disallow loopback/private/link-local/metadata destinations unless the operator explicitly allowlists that host/CIDR, pin the validated address for dialing and verify TLS against the original hostname. The global SMTP configuration remains operator-controlled. HTTP provider destinations are fixed HTTPS vendor endpoints selected from validated region/domain/account components, no arbitrary base URL or redirects. Apply address validation at actual dial time, including MS365 token endpoints. Test-only injected transports do not create production bypass settings.

Adapters: SMTP protocol; SendGrid/Mailgun/Mandrill/SparkPost/Resend documented send APIs; SES HTTPS with SigV4; Azure Communication Services signed send request; MS365 client-credentials OAuth plus Graph sendMail. Task 1 records official vendor endpoints, authentication, exact credential mappings, scopes/permissions and response interpretation. Each adapter needs local protocol tests, not paid live sends. Do not downgrade Azure/MS365/SES to arbitrary SMTP while claiming their named configuration works.

## 6. Bounded Liquid rendering

Evaluate a permissively licensed Go Liquid engine behind `internal/email/render.go`; pin its version and add NOTICE attribution. A feasibility gate proves these limits before adopting it. A context timeout around an uninterruptible goroutine is not a sandbox. If the engine cannot enforce evaluation/iteration/allocation budgets, add an instrumented evaluator or process-isolated implementation and revise the execution task before integration; do not ship unbounded execution.

**Local limits:** API request 256 KiB; body source 128 KiB UTF-8; subject source 1 KiB; sender source 1 KiB; result URL source 4 KiB; serialized render context 64 KiB; nesting depth 32; cumulative loop iterations 10,000; evaluation steps 100,000; output 256 KiB across all fields; render deadline 100 ms. Limits also apply during validation/preview, intermediate string/filter allocations and parsing. Bound concurrent renders to eight per process with immediate capacity rejection. Boundary tests cover multibyte input and nested multiplicative loops.

No filesystem, network, environment, reflection methods or arbitrary Go functions are reachable. Reject `include`, `layout`, `render` and `debug`, even though some upstream syntax supports file/debug tags. Freeze the supported tag/filter allowlist and unsupported syntax errors in Task 2; common conditional, loop, assignment, string, date and escaping filters must be tested. Unknown unsupported syntax fails save rather than failing silently at send time. Missing optional variables render empty; required event link/recipient context is validated before rendering.

Build an explicit data map per event: safe user profile fields and bounded metadata, safe application ID/name/metadata, tenant friendly name/support contacts, language, friendly_name/support_url and the server-issued `url` when relevant. Never serialize whole store structs, credentials, password hashes, access/refresh tokens, configuration blobs or arbitrary user lookup results. Do not fake OTPs or organization data for workflows that do not exist. Preview uses synthetic values only. Liquid interpolation follows the engine's documented escaping rules; original default HTML explicitly escapes untrusted values, and operators receive an escaping hint. Tenant HTML never executes in the console origin.

## 7. Tickets and runtime events

Resolve the active template's ticket options before issuing its ticket. Omitted/null lifetime retains the existing flow default; local zero means use that default, and positive integer values are capped at 604800 seconds. Existing explicit ticket-API fields take precedence over template defaults; ticket API endpoints still only issue tickets and never send email. Template options apply only to server-generated email tickets, and use the existing ticket stores and validators.

Render `resultUrl` from safe event data without a raw ticket. For email-created tickets only, require an absolute HTTPS URL without userinfo or fragment. With an associated application, require exact string equality with an entry in that tenant's `Client.Callbacks` (no wildcard, prefix or origin-only match). Without an application, require the normalized origin to equal the already-resolved canonical tenant issuer and reject scheme-relative or encoded authority tricks. Retain both `ClientID` and the validated `ResultURL` on the internal ticket, using the existing record fields; the internal issuer can store both. The public ticket API's existing mutual-exclusion and URL rules remain unchanged. Never use a template URL as an OIDC redirect_uri or bypass authorization callback checks. Invalid custom result URL makes the send fail safely rather than falling back to an unchecked redirect. `includeEmailInRedirect` uses the frozen template default only for email-created tickets; no record preserves existing defaults. Expiry, reset revocation and consume-once behavior stay in existing transaction paths. Do not issue a ticket for an explicitly disabled template.

| Event | Message and local timing |
|---|---|
| Hosted/database signup with unverified address | Existing verification email; welcome waits for verification. |
| Successful ticket-driven transition from unverified to verified | Welcome if enabled, once per user; replay or already-verified does not resend. |
| New interactive signup already verified by a trusted connection | Welcome if enabled, once per user after successful creation. |
| Management user create/import/link/profile update | No new welcome side effect; existing explicit verification behavior retained. |
| Password reset request | Active `reset_email`; generic response and existing rate limits retained. |
| Brute-force user block with `user_notification` | `blocked_account` to the resolved local user's recorded address. |
| Breach detection with `user_notification` | `stolen_credentials` to a resolved existing user's recorded address. |
| Unknown identifier, suspicious-IP-only event, failed signup without an existing account | No user mail; never send to an attacker-supplied alias. |
| Import completion | Original content; tenant transport. |

Wire both hosted and database Authentication API signup paths. Welcome uses an atomic durable claim keyed by tenant/user/`welcome`, retained until user or tenant deletion. Protection claims use tenant/user/purpose and fixed UTC calendar-day windows, independently for blocked and stolen messages. Two messages on opposite sides of midnight are permitted; this is not a sliding 24-hour guarantee. Claim only after the authoritative event succeeds and a message is eligible/enabled; claims are committed before sending. Failed or uncertain delivery retains the claim: this is at-most-one attempt per window, not exactly-once delivery. No automatic retry queue is introduced; log a redacted failure. Protection notices never carry an automatic unblock or login capability. The existing explicit user unblock workflow remains unchanged.

Expose a narrow notification hook to protection so it need not import login. Resolve recipients using canonical local user identity and verified tenant ownership. Avoid mail enumeration in public responses. Notifications never undo a successful signup, verification, block or reset mutation. Existing verification jobs retain their failure reporting. `admin_notification` remains explicitly deferred with its bounded warning; it must not be accidentally reported as implemented by replacing the user notification warning.

## 8. Console and zeroauthy test extensions

Replace the planned Emails page with Templates and Provider views in the current navigation structure. Show active versus stored-only templates and fallback provider status clearly. Provider editor uses a discriminated form, empty write-only secret fields and an unchanged-secret hint; it never reads secrets back or submits masking text. Confirm delete and explain fallback. Clear credential fields after successful writes and on tenant changes; preserve non-secret edits on validation errors. Disable mutation for reserved tenant, missing scope, pending initial read, or an uncertain mutation result. Refresh authoritative state after a lost response; never replay a send or write automatically.

Template editor supports enabled/from/subject/body/redirect/lifetime options, accessible validation, an isolated preview and a send-test button. Render HTML in a sandboxed iframe without scripts, forms, same-origin privileges, remote images/styles or navigation; CSP `default-src 'none'` plus narrowly permitted inline styles. Never use raw HTML in the app DOM. Tenant and template request-generation guards prevent stale reads, preview responses and mutation completion from overwriting the new selection.

**Local system extensions**, on the system host, with `{tenant}` resolved by tenant name:

These two routes must authenticate the operator against the resolved **target tenant**, not merely the system host tenant. Verify signature/issuer/audience/console-client binding with the existing operator verifier; require both the signed token tenant grant and current persisted operator grant to authorize the target. Apply this target resolution only to these routes before the target-aware operator authorization, preserving system-host/operator-only guards and other system route behavior. A revoked persisted grant or stale token grant denies access even if the other grants access. Current operators receive the full management scope catalog; do not invent per-scope operator delegation. Scope requirements below document operation capability and protect any future scoped operator model. Preview also requires an operator token; M2M preview access is outside this extension.

- `POST /api/system/tenants/{tenant}/emails/preview`: body `{template, overrides?}`, uses synthetic context and saved config, returns rendered `{from,subject,text,html}`; no delivery or tickets. Requires delegated `read:email_templates`.
- `POST /api/system/tenants/{tenant}/emails/test`: body `{template}`, sends the saved template to the authenticated operator's verified address; no arbitrary recipient, user ID, URL, transport or credentials accepted. Requires delegated `update:email_templates`, verified human operator and access to the target tenant. Return 204 on transport acceptance, safe failure otherwise. Tokens without a verified operator identity are rejected.

Test messages use inert example.invalid links and synthetic account data, never real account tickets; stored-only templates can be tested but that does not activate their workflow. Preview supports unsaved template overrides under the same field/size validation and render limits. Test-send is limited durably to three attempts per operator/tenant per ten minutes; preview to 30 per operator/tenant per minute. Invalid input consumes no delivery attempt; a started send counts even if its result is uncertain. Extensions are documented as zeroauthy-specific, not a discovered Auth0 test endpoint.

## 9. Verification and acceptance

| ID | Acceptance evidence |
|---|---|
| AC1 | Frozen sourced contract, all eight Management operations, SDK scope/error cases and no secret leakage. |
| AC2 | Four stores plus gRPC pass CRUD/CAS/rollback/isolation/deletion, encrypted-at-rest and restart tests. |
| AC3 | No-record legacy flows and mailer tests stay green; configured/disabled/deleted/error selection behaves as specified. |
| AC4 | All nine transports pass local protocol/authentication/timeout/TLS/SSRF/error-redaction tests. |
| AC5 | Liquid limits are enforceable; malicious syntax/input/loops/filter growth cannot read host data or exhaust rendering. |
| AC6 | Verification/reset/welcome/protection/import flow tests establish recipient, timing, duplicate suppression and unchanged OIDC/ticket security. |
| AC7 | Console tests cover permissions, stored-only labels, secret handling, isolated preview, tenant races and lost responses. |
| AC8 | Actual pinned node-auth0 and deploy-cli exercise provider/template resources; exports omit secrets and secret reinjection uses private local files. |
| AC9 | Browser signup/verification and custom welcome captured by directory driver; local SMTP proves tenant override; baseline OIDC conformance rerun with exact results. |
| AC10 | Operator docs, plugin upgrade notes, source attribution and compatibility/roadmap records distinguish implemented, stored-only and unobserved behavior. |

Run existing race, SQL cross-dialect, console, e2e, source and conformance checks during final implementation verification. The Plan 19-only database hold does not apply to Plan 21. No live third-party provider account is required for local completion; record its absence. Do not mark OIDF certification, live provider delivery or upstream parity complete based on mocks.
