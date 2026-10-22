# zeroauthy — Plan 19 design: tenant settings, attack protection and user blocks

- **Status:** Approved for implementation by the user on 2026-10-21; Task 1 contracts frozen on 2026-10-22. Runtime implementation remains pending.
- **Date:** 2026-10-21
- **Roadmap:** [Management roadmap, Plan 19](2026-10-19-zeroauthy-management-roadmap-design.md#plan-19--tenant-settings-attack-protection-user-blocks-slice-5a).
- **Implementation plan:** [Plan 19](../plans/2026-10-21-zeroauthy-plan-19-tenant-settings-attack-protection.md).
- **Basis:** Plan 18 completed at `2e175f3`; the roadmap supplies the scope. Local engineering choices are frozen in D-0045; they are not presented as observed Auth0 behavior.

## 1. Outcome and boundaries

Operators manage tenant settings and attack protection through the public Management API and the console. Changes affect authentication on every server using the same store. An operator can distinguish an administrative user block from an automatic login block, inspect the latter and clear it without changing the former. Auth0 CLI and node-auth0 clients exercise the same endpoints.

This is one roadmap milestone with three deliverable layers: tenant configuration, shared protection state and its runtime consumers, then the console and compatibility tests. Tenant settings can be reviewed independently; attack settings, counters and block endpoints must agree before the milestone ships.

Included:

- Tenant settings read/patch, including validated storage for documented fields belonging to future features.
- Brute-force, suspicious-IP, breached-password, bot-detection and CAPTCHA configuration; corresponding behavior on existing password flows.
- User-block and IP-anomaly reads/deletes, shared login counters and the existing password-reset email send limit.
- Memory, SQLite, PostgreSQL, MySQL and gRPC plugin support, seed integration, localization, API contract tests, CLI/SDK and browser tests.

Excluded: signing keys (Plan 20), notification delivery and unblock email links (Plan 21), branding templates/custom error pages (Plan 22), passwordless/phone protection (Plan 34), custom-token-exchange enforcement (Plan 35), vendor bot intelligence, a general Authentication API rate limiter, and moving the device activation or custom-script Try limits. Keep those follow-ups open. No new Redis dependency, proprietary UI capture, dashboard endpoints, or copied Auth0 presentation.

**Global constraints** (also apply to every implementation task):

- Go 1.26.7; retain the existing Vue 3/TypeScript/Vite console and current dependency pins. No new Go module is required.
- All durable tenant state is tenant scoped and implemented by every store driver, including transactional views and tenant deletion; short-lived opaque CAPTCHA replay tombstones use a shared global namespace.
- Public request/response shapes come from documented Auth0 endpoints and firewalled observation; never add zeroauthy fields to those responses.
- No outbound password lookup without explicit server configuration; never transmit plaintext passwords or full password digests.
- CAPTCHA secrets are encrypted at rest, omitted from logs and never populated back into console forms. Omit unchanged provider objects; supplying a provider object requires its documented credential children, so editing site/project keys requires replacement credentials. GET/PATCH responses omit secret/api_key.
- All Management API writes are audited with the actor; security events contain no passwords, CAPTCHA responses or credentials.
- Hosted and console copy is original and localized; the console retains light/dark themes, keyboard access and tokens in memory.
- Stored-but-inert behavior must be named in the console and compatibility matrix; it is not claimed as runtime parity.

## 2. Evidence and the observation gate

Public sources read on 2026-10-21:

- [Tenant settings PATCH](https://auth0.com/docs/api/management/v2/tenants/patch-settings): includes hours and minute variants of session durations, ephemeral sessions, device flow and feature flags.
- [Brute-force GET](https://auth0.com/docs/api/management/v2/attack-protection/get-brute-force-protection) and [behavior](https://auth0.com/docs/secure/attack-protection/brute-force-protection): identifier/IP and identifier-only modes; threshold default 10, range 1–100; connection protection and automatic blocks are distinct from user administration.
- [Suspicious-IP PATCH](https://auth0.com/docs/api/management/v2/attack-protection/patch-suspicious-ip-throttling) and [behavior](https://auth0.com/docs/secure/attack-protection/suspicious-ip-throttling): separate stages and refill rates, not a single fixed lockout setting.
- [Breached-password PATCH](https://auth0.com/docs/api/management/v2/attack-protection/patch-breached-password-detection): login shields and separate registration/change-password stages.
- [Bot-detection PATCH](https://auth0.com/docs/api/management/v2/attack-protection/patch-bot-detection): sensitivity, per-flow challenge policies, allowlist and monitoring mode.
- [CAPTCHA PATCH](https://auth0.com/docs/api/management/v2/attack-protection/patch-captcha): four implementable external providers plus Arkose, Auth0 challenge and simple CAPTCHA. Turnstile is not listed in the reference read for this draft; do not invent its wire value.
- [User blocks](https://auth0.com/docs/api/management/v2/user-blocks/get-user-blocks): lookup is by identifier, not a paginated listing of every tenant user.
- [Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords): range queries and padded responses support a lookup without transmitting the whole digest.

Task 1 reviewed the public changelog through 2026-10-22. The 2026-10-21 CLI Agent Mode entry does not change the pinned v1.37.0 interface; the 2026-10-20 IPv6 bot-model entry concerns proprietary classification, which remains a documented difference. See `docs/compat/changelog-review.md`.

Task 1 produced [tenant evidence](../../compat/observations/management-tenant-settings.md) and [attack evidence](../../compat/observations/management-attack-protection.md) in a separate authorized observer session under `CLEAN_ROOM.md`. Those records distinguish observations, documented schemas and explicit local fallbacks; they are the frozen source for dependent tests. Use only documented APIs, paced requests, throwaway identities and a nonproduction tenant. Snapshot settings, restore them in cleanup and verify restoration; tenant-wide policy experiments cannot be isolated merely by creating another user. Record entitlement failures honestly.

| ID | Facts to freeze before dependent implementation |
|---|---|
| T1 | Complete GET/PATCH field inventory, writable/read-only fields, scopes, defaults, projection parameters, unknown/null/empty handling, nested merge versus replacement, validation errors and limits. |
| T2 | Hours/minutes conflicts and response representation, fractional hours, zero values, ephemeral defaults, cookie mode, existing-session effects; seed seconds remain a separate interface. |
| T3 | Runtime flags already supported, device-flow nested updates, default directory/audience validation, locale validation, URL validation and unsupported feature fields. |
| A1 | Each attack endpoint's scopes, defaults, accepted enums/shields, limits, nested patch behavior, secret omission/redaction and active-provider validation. Do not infer every shield applies to every feature. |
| A2 | Brute-force key scope across connections, identifier normalization, modes, count/reset/expiry rules, threshold response, connection opt-out, allowlists and monitoring-only behavior. Never load/fuzz test. |
| A3 | Suspicious-IP stage defaults and rate units, refill/burst behavior, failed-versus-successful attempts, IP anomaly response/status, expiry and unblock semantics. |
| A4 | Block lookup/delete by identifier and user ID, linked identities, unknown/deleted users, `consider_brute_force_enablement`, invalid IP/ID and missing identifier errors; distinguish administrative `blocked`. |
| A5 | Breach methods, stage/shield restrictions, notification frequencies, public login/signup/reset errors and whether authenticated Management API password writes are checked. |
| A6 | Bot challenge policies across hosted and direct password/reset endpoints, challenge error shape, provider credential patch/read rules and missing provider behavior. Confirm provider versions using vendor documentation. |

**Task 1 gate settled:** every T/A row is resolved by the linked evidence or an explicitly labeled documented/local fallback in D-0045. T1/T2 use the full nested field inventory, integer PATCH durations and session_cookie.mode. A3 freezes milliseconds-per-token and token-bucket cleanup. A4 freezes unknown-user-ID 404. A6 has no invented inline ROPG proof protocol. Runtime lockout/breach/provider behavior was not live-observed; do not relabel local fallbacks as confirmed parity. Required per-task fixture assertions are listed in the observation notes. Paid features unavailable to the observer may use their public contracts; proprietary risk classification remains a documented difference. Unknown semantics must not be converted into invented observations. Implementation of a dependent behavior waits for that row, while unrelated tasks may proceed. New scope beyond the roadmap is recorded for its owning plan.

## 3. Tenant settings contract and runtime

`GET/PATCH /api/v2/tenants/settings` use the existing tenant host, authorization, error envelope, CORS and audit path. Scopes are `read:tenant_settings` and `update:tenant_settings`; attack reads/writes use `read:attack_protection` / `update:attack_protection`, user-block reads/deletes `read:users` / `update:users`, and anomaly reads/deletes `read:anomaly_blocks` / `delete:anomaly_blocks`. PATCH is validated in full before mutation, merged inside `Store.WithTx` against a freshly read tenant, and returns the canonical public representation. Independent patches must not lose one another's fields. Arrays replace; nested/null rules follow T1. Preserve omitted values including explicit false and empty arrays where accepted.

Keep existing `store.Tenant` runtime fields as the canonical source for existing behavior. Add typed fields for support details and session cookie/ephemeral settings, and `SettingsExtra` for the remaining documented fields. Extra is validated against the frozen field inventory, not an arbitrary JSON escape hatch; it may not shadow typed fields, change tenant ID/domains, or bypass protected system-tenant invariants. Deep-clone nested values in every driver.

| Field family | Behavior in Plan 19 |
|---|---|
| `friendly_name`, `picture_url`, `support_email`, `support_url` | Hosted layout uses tenant name/logo and escaped support links. `picture_url` maps to existing `Branding.LogoURL`; never fetch it server-side. Empty values clear optional presentation. Branding API remains Plan 22. |
| `default_audience`, `default_directory` | Map to existing OAuth defaults and validate as T3 specifies; explicitly requested audience/realm still wins. |
| `allowed_logout_urls` | Existing logout allowlist; do not relax redirect checks. |
| `enabled_locales` | Existing catalog negotiation and fallback. Supported hosted locales come from `internal/i18n`, not the English-only console catalog. |
| `device_flow`, PAR support, callback-confirmation skip | Map to existing device, PAR and consent runtime fields. A partial device-flow patch preserves the other setting. |
| Persistent/ephemeral absolute and idle durations; `session_cookie.mode` | Enforce in session creation, lookup/touch and cookie emission, with a persisted session mode. Cookie mode selects the matching durations. |
| `flags` | Enforce only explicitly mapped existing behavior. T3 produces a per-flag table naming its consumer or later milestone; accepting a JSON flag is not enforcement. |
| `default_redirection_uri`, `error_page`, MFA/Actions/passwordless/organization and other future-feature settings | Validate, store and return, visibly inert. Do not execute custom HTML or create a new redirect route in this plan. |

**Duration decision:** store seconds internally and retain existing seed units. API hours multiply by 3600 and API minute variants by 60, using checked exact conversions rather than integer truncation. API writes require integers >=1; paired hours/minute aliases cannot coexist. GET serializes hours as numbers, allowing minute-backed fractions. Zero and fractional-hour writes are 400 invalid_body; arithmetic overflow is refused. Existing 3600-second seed values must serialize as one hour. Persisted zero/default values retain the current 7-day absolute/3-day idle defaults for persistent sessions. Ephemeral defaults are 72 hours absolute and 24 hours idle; cookie mode defaults persistent, with non-persistent as the other accepted value. Frozen local fallback when existing-session behavior is undocumented: new lifetimes apply to new sessions, existing absolute expiry never extends, and touches may shorten idle expiry to the current policy. Record that fallback separately from confirmed compatibility.

Cookie persistence changes browser retention, not server authorization: transient cookies omit `Expires` and `Max-Age`, still expire server-side, and retain HttpOnly/Secure/SameSite behavior. Session listing/token management from Plan 17 remains intact.

Seed apply and Management API share `tenantrules`; seed seconds are converted before common validation. Seed `apply` overwrites only seed-defined settings; `create_only` preserves API edits. New attack settings are optional in seed. Store configured policy rather than caching it per process; fetch current policy for each authentication request. Do not rewrite all tenant settings during application bootstrap.

## 4. Protection policy and shared state

### 4.1 Data ownership

Add `store.Protection()` repository and `Tenant.ProtectionSettings`. Settings contain separately typed brute-force, suspicious-IP, breach, bot and CAPTCHA policies; only provider credentials use the existing encryption machinery. Defaults and patch validation live in `internal/protectionrules`, shared by seed and Management API. Pure rule code must not import handlers or generated HTTP types.

Migration **0016_tenant_protection.sql** for all SQL dialects adds tenant settings, session mode, protection buckets, attempt reservations and consumed CAPTCHA proof hashes and timestamped risk events. Buckets are indexed by tenant, kind, identifier/connection/IP where relevant, and expiry. Internal buckets also serve reset-mail limits; public block queries expose only Auth0-relevant automatic login/IP blocks. Driver cleanup removes expired entries in bounded batches and tenant deletion removes everything. User/connection deletion invalidates associated entries; connection IDs, not mutable names, identify internal records.

The shared algorithm needs an atomic reservation before credential work and an idempotent completion after it. No transaction spans password hashing, a custom database call or outbound verification. Each attempt has a unique receipt, bucket generation and reservation time; completion touches only its own reservation. A completion from before unblock, expiry, policy reset or a later generation cannot recreate a block or erase newer failures. Crash-abandoned reservations become failed attempts after 60 seconds (frozen conservative local fallback); no capacity is leaked forever. Counter expiry must not delete a newer generation.

Memory uses its existing transaction lock. SQL uses database transactions/row locking or conditional writes, including the first-insert race; SQLite serializes writes. gRPC exposes atomic operations, never a client read/modify/write sequence. Outdated plugins fail with the existing “plugin too old” diagnostic; no silent process-local fallback. Store failures refuse protected authentication with a temporary server error and perform no user mutation or token issuance.

### 4.2 Brute-force and suspicious IP

Brute-force keys include tenant and normalized identifier, plus canonical IP in `count_per_identifier_and_ip`; The explicit A2 local fallback includes stable connection ID; cross-connection aggregation was not observed. Identifier-only mode must aggregate across addresses. Email/username aliases and linked identities resolve according to A2/A4 without revealing account existence. `brute_force_protection: false` bypasses this connection's brute-force checks only, not independent suspicious-IP/breach/CAPTCHA policies.

Implement the documented 10-attempt default and configurable 1–100 threshold. The documented block expiry is 30 days since the last failed attempt; A2 defines explicit local success/reset/generation semantics; do not preserve the old 900-second lockout as an undocumented Auth0 default. Monitoring records events without denying; allowlists bypass the corresponding protection. Signup does not consume a brute-force login bucket.

Suspicious IP has separate login and registration buckets using A3's burst/refill units and counting semantics. Wire rate is milliseconds per replenished attempt, not attempts/day. Use independent token buckets; login defaults 100/864000 and registration 50/1728000 (capacity/rate); observed existing-tenant overrides are not defaults. It must not be implemented as the old “10 × user threshold” fixed-window limiter. Custom token exchange settings round-trip but remain inert until Plan 35. Public and confidential password grants retain existing `auth0-forwarded-for` trust rules. Normalize IPv4-mapped IPv6 to the same address, remove zones, and use a stable non-allowlisted unknown-address bucket for invalid input; malformed text must not mint unlimited keys. Honor the existing single-trusted-proxy boundary.

Legacy `security.login_max_attempts` and `login_lockout_seconds` remain readable configuration. Frozen local migration (D-0045): track whether explicitly supplied; explicit legacy settings initialize a tenant's absent protection policy once in a transaction and log the compatibility mode. Default-valued, unsupplied configuration initializes Auth0 defaults. Later seed/API values take precedence, and restart does not overwrite them. Legacy per-IP behavior is preserved only in that explicitly initialized compatibility policy and documented; new tenant policy edits move the relevant feature to its documented semantics. Do not expose invented legacy fields through `/api/v2`.

### 4.3 Unblock and reset

Implement `GET/DELETE /api/v2/user-blocks?identifier=…`, `GET/DELETE /api/v2/user-blocks/{user_id}`, and `GET/DELETE /api/v2/anomaly/blocks/ips/{ip}` with A4's response/status/scope rules. Identifier lookup works even without a persisted user. User-ID lookup covers that user's applicable identities; never cross tenants. Deletes invalidate matching generations atomically. Unknown identifier delete is 204; unknown well-formed user-ID read/delete is 404 inexistent_user; an unblocked IP reads 404 and deletes 204.

Automatic block removal does not change `User.Blocked`, revoke sessions/refresh tokens or erase unrelated IP/reset-mail state. Completing an existing password-reset flow clears the corresponding brute-force state in the same successful store transaction as the password change where possible; failed/expired tickets clear nothing. Both hosted reset and `/dbconnections/change_password` share the existing 3-emails/hour send budget, now in the store. Continue generic account-existence responses. A5 settles how successful administrative password replacement interacts with blocks.

## 5. Breached passwords

Add a pluggable `BreachChecker` behind `internal/protection`; configured server-side as `security.breached_passwords.mode: off|range|file` (default `off`). Tenant API policy cannot turn outbound access on. Range mode uses the fixed HTTPS Pwned Passwords range endpoint, a 2-second timeout, no redirects, a 2 MiB response bound and padded responses; send only the first five hexadecimal SHA-1 characters. SHA-1 is a lookup key only, never the password storage algorithm. Cache at most 1024 prefix responses for 5 minutes; no per-password or per-user cache. The injectable HTTP transport supports local test servers without exposing an arbitrary tenant-controlled URL.

File mode reads an operator-configured, sorted `40-hex-SHA1:positive-count` corpus at startup into an indexed read-only lookup (sparse offsets are acceptable); no plaintext corpus, per-request full-file scan or whole-corpus in-memory requirement. Validate format/order and fail startup for an unreadable or corrupt configured file. Prefix matching, count-zero padding and non-ASCII password bytes have explicit tests.

Check plaintext only at existing user password submission points: hosted login/signup/reset, password grants, Authentication API signup and password completion; authenticated Management API create/update checks follow A5. Imported hashes cannot be checked until first successful credential verification; perform the breach decision before session/token issuance, keeping the existing imported-hash upgrade correct. Never reject a login as breached before proving its supplied credentials. Registration/reset refusal must precede a password write, custom-DB create/change call or ticket consumption.

**Frozen local failure policy (D-0045):** checker unavailable or mode off yields “unavailable,” never “not breached.” If the active stage has `block`, refuse with a temporary failure and leave user/password/ticket unchanged; monitoring-only policy permits continuation and emits a redacted event. New tenants default breach detection off until the operator supplies a checker. Explicitly imported enabled policies remain enabled and display the unavailable capability; they are not silently rewritten. Match public A5 error shapes where established; document local availability errors as a difference.

`standard`/other documented methods and notification frequencies are accepted per A5. Differences in Auth0's proprietary corpus or notification-based method are marked explicitly; only the available local corpus/checker verdict is enforced. Both user and administrator notification shields log a rate-limited warning instead of sending mail until Plan 21. Provide a structured event boundary for that follow-up, without prematurely implementing an email job type or a logs API.

## 6. Bot detection and CAPTCHA

Expose policy fields from A1/A6. Implement `never`, `always`, `when_risky`, monitoring and per-policy allowlists. Passwordless policy is stored until Plan 34. No claim to Auth0's proprietary risk engine: frozen local sensitivity rule (D-0045) uses the preceding 15 minutes of qualifying failed operations by canonical tenant/IP, with thresholds low=10, medium=5, high=1. Counters are shared, bounded by expiry, and independent of whether brute-force/suspicious-IP blocking is enabled. Record this deterministic classifier as a compatibility difference.

Qualifying events are admitted wrong-credential logins, rejected registration attempts (duplicate identifier or password-policy/breach refusal), rejected password replacements (invalid/expired ticket or policy/breach refusal), and invalid/missing CAPTCHA submissions when a challenge is required. Count at most one event per server attempt receipt, even when several checks fail. Successful operations do not reset this rolling history. Normal reset-email requests, including unknown addresses, are not failures; neither are store/provider outages, cancelled/abandoned forms, or requests rejected by an already-active throttle. This allows failed credentials to activate `when_risky` before any CAPTCHA has appeared and avoids making account existence a risk signal. Retain timestamped failure events, not a fixed-window approximation that changes the 15-minute rule.

Challenge before password verification or sending reset mail when required. Integrate the challenge into existing hosted forms; direct password/reset endpoints follow A6's documented challenge-required contract, never silently bypass a required challenge. Client credentials, refresh-token grants and existing-session silent authorization do not acquire an interactive challenge.

Provide server verifiers and hosted widgets for `recaptcha_v2`, `recaptcha_enterprise`, `hcaptcha`, `friendly_captcha`; use the frozen A6 credential fields and provider HTTP protocols. Friendly Captcha uses a matched v1 widget/solution verifier; Enterprise uses projects.assessments.create with its API key, not legacy siteverify. Use provider-specific fixed HTTPS endpoints with 2-second deadlines, no redirects and 256 KiB response limits. Validate the success result and all supported hostname/site/action bindings, not merely HTTP 200. The server derives tenant/flow/transaction from the existing hosted authentication transaction or reset ticket, validates its normal CSRF/state protection, and ignores client-supplied binding values. ROPG cannot complete CAPTCHA inline; a required challenge returns requires_verification and directs the caller to interactive web login. Direct signup/reset use the same refusal fallback when no documented completion transport is established; do not invent extra required Authentication API parameters. Local verification and replay consumption happen within that validated request context. Use a provider action/custom-data binding when its documented protocol supports it; validate hostname/site ownership in every provider that returns those fields.

A provider without transaction-bound proofs cannot prove which local transaction originally obtained an unused response. The supported guarantee is provider/site validation, a valid local request context, and at-most-once acceptance across contexts—not cryptographic first-use binding to a transaction. Document that limitation instead of claiming a token-transfer test can prove otherwise. Hash the provider ID and response (without tenant/flow) and consume that hash globally across the shared store for 5 minutes, so sharing provider credentials across tenants cannot permit reuse. Do not expose this internal global replay namespace through tenant APIs; tenant deletion removes tenant-owned context/state but may retain these short-lived opaque replay tombstones. Concurrent verification may occur, but at most one completion may proceed. Tests use fake verifiers; no real account is required for CI.

The current public CAPTCHA schema also lists `arkose`, `auth_challenge`, `simple_captcha`. Frozen local decision (D-0045): store these configurations but mark their verification unavailable in this milestone; do not build an undocumented substitute or treat any token as success. A required challenge with no supported configured verifier fails closed with an actionable localized error. This is an explicit scope exception alongside the roadmap's vendor-dependent providers. Do not add Turnstile unless Task 1 confirms a documented wire contract and updates the plan.

Provider credentials are encrypted using existing key wrapping, redacted exactly as A1 requires on the public API, and write-only in the UI. Omitted credentials preserve existing secrets; explicit clearing follows A1. Hosted CSP adds only the active provider's documented script/frame/connect origins; no wildcard or blanket `unsafe-inline`. Widget markup is original. No CAPTCHA scripts load on the console or when no challenge is required. Accessible errors/retry are provided when provider JS fails.

## 7. Console

Replace the two Plan 16 previews and mark only Settings and Attack protection live in `console/src/layout/sections.ts` and the router.

- **Tenant settings:** General (name, logo, support); Sessions (persistent/ephemeral idle/absolute duration with explicit units and cookie mode); Languages (hosted locales and ordering); Advanced (audience, directory, logout URLs, device flow, PAR/consent and supported flags). Future-feature fields are labeled “saved, not enforced yet.” Preserve the seed overwrite banner.
- **Attack protection:** sections for brute force, suspicious IP, breached passwords, bot detection and CAPTCHA. Each saves its own patch; explain allowlist CIDRs, rate units and stage effects. Secret inputs are blank after save. Display notification-delivery, corpus-availability and unsupported-provider limitations adjacent to the controls.
- **User detail:** separate automatic login blocks from the existing administrative Block action; show current automatic blocks and “Clear login blocks.” Clearing reloads block state and leaves administrative status untouched. Attack protection also provides IP check/unblock using the public anomaly endpoint, not an invented list endpoint.

No private console-only endpoints. Nonsecret server checker availability may be added to the existing operator-only system tenant detail as a documented zeroauthy capability field, so the console can report configuration without inferring it from a failed login. It is not added to Auth0 responses. Tenant switching aborts/ignores stale loads and saves; dirty edits cannot reach the newly selected tenant. Maintain existing loading/empty/error, field-error and confirmation patterns.

## 8. Acceptance and handoff

1. API/seed updates round-trip all inventoried fields without losing omitted nested settings, and enforce the mapped runtime fields. Session units, ephemeral cookies and locale sources are tested.
2. A single database shared by two server instances shares lockout, reset-mail and replay budgets. Concurrent first use, success/failure completion, unblock races and restart cannot bypass enforcement or resurrect stale blocks.
3. Block endpoints obey scope/tenant boundaries and distinguish automatic from administrative blocks, including linked identities and unknown identifiers.
4. Local range and CAPTCHA mocks prove positive, negative, unavailable and replay behavior with no external service in CI; no credential leaks in responses/logs.
5. Existing password, custom-DB, import-upgrade, reset, consent, PAR, device and session regressions pass. Console/browser tests demonstrate changing policy, locking out, unblocking and logging in again.
6. CLI/SDK tests use pinned installed versions and record actual method/command names. All drivers pass storetest and SQL race cases; normal generation, console, source and conformance checks pass or their actual blockers are recorded.
7. Documentation lists each inert field/feature and closes only follow-ups actually fixed. Plan 19 becomes “done” only after implementation and verification, not when these documents are written.

Builder discretion: helper/file subdivision, SQL indexes beyond the required access paths, visual spacing, and test fixture organization. The legacy-config transition, checker outage policy, deterministic local risk rule and unsupported simple CAPTCHA behavior are frozen local choices in D-0045. Task 1 resolves compatibility facts; it is not permission to weaken these invariants silently.
