# zeroauthy — Design: finishing the Management API (roadmap, Plans 19 onward)

- **Status:** Draft for maintainer review (2026-10-19)
- **Date:** 2026-10-19
- **Scope:** every Auth0 Management API v2 resource not covered by slices 1–4 (applications, APIs, client grants, database connections, users and jobs), broken into plans with an order, dependencies and a short design each.
- **Inputs:** the management design (`2026-10-18-zeroauthy-management-design.md`), the users design (`2026-10-19-zeroauthy-users-design.md`), the compatibility matrix, the follow-ups file, and the maintainer's 2026-10-19 rulings.

## 0. Where we are (2026-10-28)

**Plans done:** 26. **Implemented and locally verified, final review pending:** 1 (Plan 27). **Left to implement in this roadmap:** 11 (Plans 28–38), subject to splitting larger designs.

### Done

| Plans | What |
|---|---|
| 1–6 | Core server, keys, discovery, client credentials, hosted login, code flow with PKCE, refresh rotation, logout, i18n, password grants, signup and reset, email, SQL drivers |
| 7–8 | gRPC storage plugins; custom database connections (Node runner, import mode) |
| 9–11 | Consent and third-party apps, PAR, device flow |
| 12 | OIDF conformance in CI (Basic, Config, Form Post, RP-Initiated: passing locally) |
| 13 | Management API foundation, operators and console sign-in, **applications** |
| 14 | **APIs** (resource servers) and **client grants** |
| 15 | **Database connections** and enabled clients |
| 16 | Console frame: every section routed, planned pages previewed |
| 17–18 | Users, search, identities, sessions, refresh tokens, grants, tickets; import/export and verification-email jobs |
| 19 | Tenant settings, attack protection, user blocks and shared password-flow enforcement |
| 20 | Managed signing keys, stored-only custom JWKS, console controls and local Deploy CLI migration for supported families |
| 21–23 | Email providers/templates, branding and Universal Login, custom domains and automatic certificates |
| 24–25 | Generic OAuth/OIDC, Google and Microsoft personal/work/school account connections |
| 26 | Tenant roles/direct permissions, runtime RBAC, four token profiles, console and Deploy CLI role migration |
| 27 | Actions I implemented and locally verified; final review pending. Post-login/credentials-exchange, npm builds, redirect/continue, Management API, console, seed and Deploy CLI; /userinfo custom claims deferred |

### Management API coverage by resource

Auth0's Management API reference has about 40 resource groups. Status of each:

| Status | Count | Resources |
|---|---|---|
| **Done / implemented locally** | 24 | signing keys (custom public-key publication deferred); clients, resource-servers, client-grants, connections (database strategy); users, users-by-email, tickets, grants, sessions and refresh tokens (Plan 17); jobs (Plan 18); tenant settings, attack protection, user blocks (Plan 19); email provider and templates (Plan 21); branding, themes, prompts/custom text (Plan 22); custom domains (Plan 23); social strategies I (Plan 24), Microsoft/Google email-account connections (Plan 25), roles and permissions (Plan 26), Actions I (Plan 27; final review pending) |
| **Planned, short design** | 5 | Actions II, organizations II, event streams, client credentials / token exchange, enterprise OIDC |
| **Planned, full design** | 9 | organizations, logs, log streams, stats, guardian (MFA), passwordless and phone branding, SAML/WS-Fed/SCIM/self-service, AD/LDAP, forms and flows |
| **Not planned** | 4 | rules, rules-configs, hooks (end-of-life on Auth0), customer-managed encryption keys |

The future Additional social providers plan is deferred without an assigned number and is not an extra counted resource group here.

Read as the roadmap's resource groupings, about 57% is implemented. Read as work, the remaining plans are larger than the finished Management API ones, because most carry a runtime feature (MFA, Actions, organizations, social login) rather than only endpoints. The Authentication API side (sub-project 1) is complete apart from what those features add.

## 1. Goal and ground rules

**Goal:** zeroauthy is a 1:1 drop-in replacement for Auth0's Management API. "Finished" means every resource in Auth0's public Management API reference, except the ones listed in §5 as not planned, is either:
- **implemented:** the endpoints answer in Auth0's shape, and the behaviour they configure actually happens at login, token or email time; or
- **stored, not enforced:** accepted, stored and returned so tools such as `auth0-deploy-cli` round-trip, while the feature behind it is visibly marked as not enforced yet (the D-0042 pattern). This is a temporary state, never the end state for a plan's own resources.

**Parity rule.** The endpoints alone are not parity: a role that never reaches a token, or a branding theme that never reaches a page, is a broken drop-in. Each plan therefore includes the runtime work (Authentication API, hosted pages, emails) that its resources configure. That makes several plans "feature" plans with a Management API face, and it is why the sub-project 2 features (MFA, passwordless, social, Actions) appear in this roadmap.

**Every plan keeps the established shape** (Plans 13–17):
1. A changelog review since the last one (core spec §13).
2. **Task 1: observation** on the maintainer's dev tenant for points the docs leave open, by a separate observer session, in `docs/compat/observations/` (CLEAN_ROOM.md). Some resources need a paid Auth0 plan or add-on; where the maintainer's tenant cannot show the behaviour, the documented behaviour is followed and the gap is logged (as for permissive third-party clients, D-0025).
3. Store changes in memory, SQL and gRPC drivers with storetest; a migration; proto fields and RPCs.
4. Endpoints in `api/management.yaml`, contract-tested; shared rules in a `*rules` package used by seed, API and console.
5. Runtime work, localized through the catalog.
6. Console pages: the Plan 16 preview becomes live.
7. Black-box E2E: `auth0-cli` where it has commands, `node-auth0` or `go-auth0` otherwise, Playwright for hosted pages and the console, and from Plan 20 the growing `auth0-deploy-cli` round trip.
8. Docs, compatibility matrix, decisions, follow-ups.

**Design depth.** Plans marked **short** can be planned directly from their section here after Task 1. Plans marked **full** need their own brainstorming and design document first, because they carry product decisions this roadmap cannot settle (a runtime, a protocol, a new UI flow).

## 2. Order

Ordered by dependencies first, then by how much a typical tenant (and the maintainer's own use) relies on the resource, then by size. The maintainer may reorder anything without breaking a dependency in the "needs" column.

| Plan | Area | Depth | Needs |
|---|---|---|---|
| 17 | Users, tickets, grants, sessions, refresh tokens (users design) | short (done) | — |
| 18 | Jobs: user import with hashes, export, verification email (users design) | short (done) | 17 |
| 19 | Tenant settings, attack protection, user blocks | short (done) | 17 |
| 20 | Signing keys, `auth0-deploy-cli` round trip | short (done) | 19 |
| 21 | Email provider and email templates | short (done) | 19 |
| 22 | Branding: themes, settings, Universal Login page templates, prompts and custom text | full (done) | 21 |
| 23 | Custom domains with automatic certificates | full (done) | 19 |
| 24 | Social connections I: generic OAuth 2 and OIDC, Google | full (done) | 17 |
| 25 | Email-account sign-in: Microsoft personal and work/school; Google/Gmail/Workspace coverage | full (done) | 24 |
| 26 | Roles and permissions (RBAC) | short (done) | 17 |
| 27 | Actions I: runtime, post-login, credentials exchange, npm dependencies, the Actions API | full (implemented/verified; final review pending) | 26 |
| 28 | Actions II: the remaining triggers and modules | short | 27 |
| 29 | Organizations I: organizations, members, roles, enabled connections, login with an organization | full | 26 |
| 30 | Organizations II: invitations, client grants, discovery domains | short | 29, 21 |
| 31 | Logs, log streams, stats | full | 19 |
| 32 | Event streams | short | 31 |
| 33 | MFA I: OTP, email, recovery codes, WebAuthn, policies, the MFA API, user authentication methods | full | 21, 27 |
| 34 | Passwordless and phone: email and SMS connections, phone providers and templates, MFA by SMS and voice | full | 33 |
| 35 | Client credentials: `private_key_jwt`, JAR, token exchange profiles | short | 27 |
| 36 | Remaining enterprise OIDC: `oidc`, `okta`, Entra extras, connection keys (`waad` sign-in moves to 25) | short | 24, 25 |
| 37 | SAML and WS-Federation (sub-project 4), SCIM, self-service SSO profiles | full | 36 |
| 38 | AD/LDAP connector, Forms and Flows, remaining resources | full | 27, 37 |

Plans 17 and 18 come from the users design. Plan 37 is sub-project 4 of the core spec and may itself split.

## 3. Plans

### Plan 19 — Tenant settings, attack protection, user blocks (slice 5a)

**Implementation records (2026-10-25):** [standalone spec](2026-10-21-zeroauthy-tenant-settings-attack-protection-design.md), [implementation plan](../plans/2026-10-21-zeroauthy-plan-19-tenant-settings-attack-protection.md), and operator guides ([tenant settings](../../tenant-settings.md), [attack protection](../../attack-protection.md)). Tasks 1–12 are implemented, reviewed and verified. The final whole-branch review's legacy suspicious-IP transition finding was fixed and re-reviewed. Local SQLite/PostgreSQL/MySQL, race, console, source, CLI/SDK/browser and conformance checks passed with the documented warning/review/skip counts. No live Auth0 tenant or CAPTCHA/breach provider was called.

**Endpoints:**
- `GET/PATCH /api/v2/tenants/settings`: every documented field. Enforced where zeroauthy has the feature: `friendly_name`, `picture_url`, `support_email`, `support_url`, `default_audience`, `default_directory`, `session_lifetime`, `idle_session_lifetime`, `enabled_locales`, `device_flow`, `pushed_authorization_requests_supported`, `skip_non_verifiable_callback_uri_confirmation_prompt`, `session_cookie.mode` and `allowed_logout_urls`. Flags (except read-only disable_impersonation), `default_redirection_uri`, `error_page`, `customize_mfa_in_postlogin_action` and other inventoried future fields are stored, not enforced, until their plan.
- `/api/v2/attack-protection/brute-force-protection`, `/breached-password-detection`, `/suspicious-ip-throttling`, `/bot-detection`, `/captcha`.
- `/api/v2/user-blocks` (by identifier, by user ID; list and unblock), `/api/v2/anomaly/blocks/ips/{ip}` (check and unblock).

**Runtime:**
- Login throttles move into the store (the Plan 2, 5 and 6 multi-instance follow-ups), using the frozen documented/local rules (connection and identity plus optional IP for brute force; IP for suspicious-IP throttling), with Auth0's thresholds as defaults and the `shields` (`block`, `user_notification`, `admin_notification`) and `allowlist`.
- Breached password detection: checks at signup, login and reset against a k-anonymity range API (Have I Been Pwned's Pwned Passwords, opt-in, outbound HTTPS) or an offline list file; Auth0's shields (`block`, `user_notification`, `admin_notification`) and stages.
- CAPTCHA: server-side verification for the documented providers zeroauthy can reach (reCAPTCHA v2 and Enterprise, hCaptcha, Friendly Captcha v1); providers that need a vendor contract (Arkose, Auth Challenge, Simple CAPTCHA) stored but unavailable; required challenges fail closed. Turnstile has no frozen wire contract. Bot detection levels drive when the CAPTCHA appears.
- The "blocked account" and "breached password" notification emails wait for Plan 21; until then the `user_notification` shield logs a warning (a decision).

**Console:** Tenant settings (General, Sessions, Advanced, Languages) and Attack protection become live; the user detail gains "unblock" for brute-force blocks.

**E2E:** `auth0 tenant-settings` and `auth0 protection` commands (auth0-cli), a Playwright brute-force lockout and unblock, a breached-password refusal against a local mock range API.

### Plan 20 — Signing keys and the `auth0-deploy-cli` round trip (slice 5b)

**Design and execution records (2026-10-25):** [standalone spec](2026-10-25-zeroauthy-signing-keys-deploy-cli-design.md) and [implementation plan](../plans/2026-10-25-zeroauthy-plan-20-signing-keys-deploy-cli.md). Managed signing APIs, stored-only custom JWKS, console controls and offline bootstrap are implemented. Local Deploy CLI YAML/directory generated/preserved-credential round trips pass for clients, APIs, grants and tenant settings. Database/provider/attack-protection handlers are explicitly tool-unsupported pending their required APIs. Upstream observer evidence remains unavailable. See [signing-keys.md](../../signing-keys.md), [deploy-cli.md](../../deploy-cli.md), and the plan's acceptance record.

**Endpoints:** `GET /api/v2/keys/signing`, `GET /api/v2/keys/signing/{kid}`, `POST /api/v2/keys/signing/rotate`, `PUT /api/v2/keys/signing/{kid}/revoke`; GET/PUT/DELETE `/api/v2/keys/custom-signing` stores custom **public** JWKS. Public documentation describes custom-domain key distribution, not private-key signing; the draft defers publication to Plan 23 and prohibits using uploaded keys for zeroauthy's internal token verification. `/api/v2/keys/encryption` (customer-managed root key) is listed in §5.

**Runtime:** the key manager exposes rotate and revoke through the API; previous keys are retained until explicit revocation. Custom public keys remain outside canonical JWKS and internal token trust.

**Round trip:** `auth0-deploy-cli` export from an Auth0 tenant (the maintainer's dev tenant), import into zeroauthy, export from zeroauthy, and compare. Resource types that zeroauthy does not have yet are listed in `AUTH0_EXCLUDED`; each later plan removes its types from that list, so the round trip grows with the roadmap. Open decisions carried from the follow-ups and settled here: keeping client IDs and secrets on migration (D-0039), the system API name (D-0041).

**Console:** Signing keys under Settings (list, rotate, revoke with confirmation).

**E2E:** `auth0-deploy-cli` in YAML and directory formats; `auth0 api` for the key endpoints.

### Plan 21 — Email provider and email templates

**Implementation record (2026-10-25):** [standalone design](2026-10-25-zeroauthy-email-provider-templates-design.md), [implementation plan](../plans/2026-10-25-zeroauthy-plan-21-email-provider-templates.md), and [operator guide](../../email.md). Implemented and covered by local Go, SQL, SDK, deploy-cli and browser lanes. Live upstream observation and paid-provider delivery were not performed; formal OIDF certification is not claimed.

**Endpoints:** `GET/POST/PATCH/DELETE /api/v2/emails/provider`; `POST /api/v2/email-templates` and `GET/PUT/PATCH /api/v2/email-templates/{templateName}` for every documented template name (`verify_email`, `verify_email_by_code`, `auth_email_by_code`, `reset_email`, `reset_email_by_code`, `welcome_email`, `blocked_account`, `stolen_credentials`, `enrollment_email`, `mfa_oob_code`, `user_invitation`, `change_password`, `password_reset`, `async_approval` and any added since).

**Runtime:**
- Tenant providers: SMTP, SendGrid, Mailgun, Mandrill, SparkPost, SES, Azure Communication Services, MS365 and Resend. The server-wide driver remains the fallback when no tenant provider is enabled. `custom` is stored disabled until Actions execution exists.
- Restricted Liquid evaluator with bounded parsing and execution; no external Liquid engine dependency. Provider credentials are envelope-encrypted and write-only. See `docs/email.md` for TLS, outbound policy, template escaping and secret reinjection.
- Verification, reset, welcome and user security notices are active. Code, MFA, invitation and approval templates remain stored-only until their workflows are implemented. Welcome and security sends use durable claims; uncertain sends are not retried.

**Console:** Provider, template and isolated preview pages are implemented. Zeroauthy-specific system-host preview and test-send routes target an authenticated operator's authorized tenant and verified address; details are in D-0047 and `docs/email.md`.

**E2E:** node-auth0 `emails` and `emailTemplates`; actual deploy-cli YAML/directory import; Playwright signup, verification, welcome replay and second-tenant SMTP isolation. `make e2e-email` runs the dedicated browser lane and is included in CI. Local conformance results and unavailable handlers are recorded in the Plan 21 acceptance record.

### Plan 22 — Branding and Universal Login (full design)

**Implemented (2026-10-26):** [spec](2026-10-25-zeroauthy-branding-universal-login-design.md), [plan](../plans/2026-10-25-zeroauthy-plan-22-branding-universal-login.md), [acceptance record](../plan-22-implementation-record.md), and [operator guide](../../branding.md).

**API and persistence:** All 16 branding/theme/template/prompt/custom-text/partial operations, scoped tenant isolation, canonical configuration with CAS, seed ownership and one-time legacy migration. Memory, SQLite, PostgreSQL, MySQL and additive gRPC support are verified. Creating a theme activates it; deleting the default restores base branding.

**Runtime:** Original hosted pages use typed theme styles and a bounded Liquid/HTML/CSS subset with trusted head/widget insertion and built-in fallback. Identifier-first database login binds both steps to the existing authorization transaction and protection pipeline. Four partial slots on login/identifier/password/signup support accessible transient `ulp-` fields. Locale aliases share one custom-text resource. Email rendering retains its existing mode and limits.

**Console:** Accessible resource editors preserve drafts, reject stale replies and handle uncertain writes. Synthetic preview renders saved settings plus drafts in a capability-free sandbox with no network access.

**Verified boundaries:** Actual pinned Node SDK and Auth0 CLI exercise all 16 operations; branded and baseline browser/email lanes and local OpenID conformance pass. Strict Deploy CLI YAML/directory × generated/preserved credential migrations cover unblocked families. Plan 23 supersedes the former unavailable-template result with real custom-domain inventory and strict template-body round trips. Exact live upstream observation is unavailable; no certification or unrestricted Auth0-template parity is claimed.

**Deferred/stored-only:** Classic, WebAuthn/social controls, Actions validation/forwarding, organization context and ACUL require later plans. Custom domains are implemented by Plan 23. Captured partial values remain in the expiring transaction and never reach metadata, tokens, mail or custom database scripts. Tenant JavaScript and arbitrary HTML/CSS are rejected. Tenant templates supersede the old filesystem template-directory follow-up.

### Plan 23 — Custom domains with automatic certificates (implemented)

[Design](2026-10-26-zeroauthy-custom-domains-design.md),
[implementation record](../2026-10-26-plan-23-implementation-record.md),
[operator guide](../../custom-domains.md).

**API/storage:** Nine scoped operations (including Test and default selection),
TXT ownership proof, one normalized global host owner, pinned canonical identity,
additive memory/SQLite/PostgreSQL/MySQL/gRPC state and fenced TLS leases.

**Runtime:** Managed HTTP-01/TLS-ALPN-01 ACME, encrypted shared account/orders/keys,
renewal/expiry, cross-replica challenges, authenticated customer proxies and
bounded public-only diagnostics. Deployment-owned apex/wildcard DNS-01 uses
DigitalOcean, as a local extension. Authentication artifacts and notification
links retain their public origin; canonical Management API audiences stay stable.

**Console/tooling:** Accessible add/detail/proof/diagnostics/default controls,
one-time secret recovery, stale-response guards and bounded polling. Pinned
SDK/CLI exercise nine operations; strict Deploy CLI migrations include real
domains and nonempty Universal Login template body files, with explicit
proof/default staging and canonical-default preparation.

**Boundaries:** Exact live Auth0/provider behavior is unobserved. RP ID and custom
public signing JWKS remain stored-only; ACUL, prompt-partial domain context,
additional DNS providers and challenge delegation remain follow-ups. The operator
guide defines fleet rollout/rollback and legacy noncanonical reauthentication.

### Plan 24 — Social connections I: generic OAuth 2 and OIDC, Google (full design; slice 6a)

**Draft design and plan (2026-10-26):** [standalone spec](2026-10-26-zeroauthy-social-connections-design.md) and [implementation plan](../plans/2026-10-26-zeroauthy-plan-24-social-connections.md). Includes the basic `oidc` back-channel strategy ahead of Plan 36; enterprise discovery and remaining OIDC features stay there. Implemented 2026-10-26: see the [implementation record](../2026-10-26-plan-24-implementation-record.md) and [operator guide](../../social-connections.md).

**Endpoints:** `/api/v2/connections` accepts strategies `oauth2` and `google-oauth2` with their documented `options`; `/users/{id}/identities` link and unlink social identities; `federated-connections-tokensets` stays out.

**Runtime:** federated login from `/authorize` (`connection=` and buttons on the login page), state and PKCE to the upstream, ID token validation for OIDC upstreams, profile mapping into Auth0's normalized profile (`identities[].isSocial`, `access_token` storage rules), `set_user_root_attributes`, upstream token storage as Auth0 stores it (readable with `read:user_idp_tokens`), matching imported users by provider user ID (the users design import keeps `identities`).

**Full design questions:** the upstream-token storage policy, how Auth0's `fetchUserProfile` script for `oauth2` runs (Node runner from Plan 8 or Actions), account linking (Auth0 links nothing automatically; zeroauthy matches that).

**E2E:** a mock OIDC provider in a container; auth0-cli `connections` with the new strategies; Google against the maintainer's dev credentials, manual and optional.

### Plan 25 — Microsoft and Google email-account sign-in

**Implemented 2026-10-27:** see the [implementation record](../2026-10-26-plan-25-implementation-record.md) and [operator guide](../../email-account-connections.md). [Standalone spec](2026-10-26-zeroauthy-email-account-connections-design.md) and [implementation plan](../plans/2026-10-26-zeroauthy-plan-25-email-account-connections.md). Add `windowslive` for Microsoft personal accounts (including Outlook/Hotmail) and the `waad` Microsoft Entra work/school sign-in subset brought forward from Plan 36. Preserve and explicitly verify existing `google-oauth2` support for Gmail, other Google accounts and Google Workspace. This is account authentication, not mailbox access or outbound email delivery. **Full**, because organizational issuer/key validation and safe identity migration require more than provider profiles.

**Deferred: Additional social providers (future plan, number unassigned).** Move `apple`, `facebook`, `github`, `linkedin`, `twitter`, `amazon`, `discord`, `slack` and the remaining social list here. Apple still requires client-secret JWT and private-email relay handling. Do not implement these in Plan 25 or renumber Plans 26–39.

### Plan 26 — Roles and permissions (RBAC)

**Implemented and locally verified (2026-10-27):** [standalone spec](2026-10-27-zeroauthy-roles-permissions-design.md), [implementation plan](../plans/2026-10-27-zeroauthy-plan-26-roles-permissions.md), [implementation record](../2026-10-27-plan-26-implementation-record.md), and [operator guide](../../rbac.md). Tenant roles, direct permissions, runtime RBAC, four token dialects and live console controls are implemented. Groups and organization roles remain deferred. All local SQL/race/console/SDK/CLI/browser/Deploy CLI checks pass; local OpenID conformance has zero failed modules with warning/review/skip counts recorded. Live observations remain unavailable.

**Endpoints:** `/api/v2/roles` (CRUD), `/roles/{id}/permissions`, `/roles/{id}/users`, `/users/{id}/roles`, `/users/{id}/permissions`; resource server `enforce_policies` and `token_dialect` values `access_token_authz`, `rfc9068_profile`, `rfc9068_profile_authz` become enforced (D-0041 lists them inert).

**Runtime:** with RBAC on, requested scopes are capped by the user's permissions; the `permissions` claim appears for the `_authz` dialects; client credentials unaffected, as on Auth0.

**Console:** Roles list and detail (permissions, users); a Roles tab on user detail; RBAC switches on API detail.

**E2E:** auth0-cli `roles` and `users roles`; express-oauth2-jwt-bearer `requiredScopes` against a token carrying permissions.

### Plan 27 — Actions I (full design)

**Implemented and locally verified (2026-10-28); final independent review
pending:** [spec](2026-10-27-zeroauthy-actions-design.md),
[plan](../plans/2026-10-27-zeroauthy-plan-27-actions.md),
[implementation record](../2026-10-27-plan-27-implementation-record.md) and
[operator guide](../../actions.md). Fourteen Management operations, immutable
versions, encrypted secret snapshots, ordered bindings, post-login and
credentials-exchange run through the shared permission-sandboxed Node runner.
Npm dependency builds, store-backed replica artifacts, redirect/continue,
console, durable create-only seed ownership and Actions-capable plugins are
implemented. Remaining triggers/Modules and /userinfo custom-claim echo remain
deferred; unsupported security APIs fail closed.

**Verification:** complete SQL/race/console, SDK/CLI/browser and all four local
Deploy CLI cells finished successfully; local OpenID conformance has zero
failed modules, with warning/review/skip counts retained in the record. The
first full Go run's local diagnostic timeout and successful retry are recorded.
Live upstream observation remains unavailable. This is local implementation
evidence, not formal certification or a claim that all Actions APIs exist.

### Plan 28 — Actions II

Remaining triggers: `pre-user-registration`, `post-user-registration`, `post-change-password`, `send-phone-message` (used by Plan 34), `password-reset-post-challenge`, `custom-email-provider` and `custom-phone-provider` (Plans 21 and 34), `custom-token-exchange` (Plan 35), `event-stream`? if Auth0 has it at build time. Modules (`/actions/modules` and versions). Npm dependencies, Action secrets, immutable build artifacts and offline registry configuration were delivered in Plan 27 and are removed from this plan. **Short**, on Plan 27's design.

### Plan 29 — Organizations I (full design)

**Endpoints:** `/api/v2/organizations` (CRUD, `name/{name}` lookup), `/organizations/{id}/members`, `/members/{user_id}/roles`, `/organizations/{id}/enabled_connections` (`assign_membership_on_login`, `show_as_button`, `is_signup_enabled`), `/users/{id}/organizations`; client fields `organization_usage`, `organization_require_behavior` become enforced (inert since D-0039).

**Runtime:** `organization` parameter at `/authorize`; the organization prompt (`pre_login_prompt`, `post_login_prompt`, `no_prompt`); `org_id` and `org_name` claims; membership checks; organization branding on hosted pages (Plan 22 variables); organization-scoped roles in tokens (Plan 26).

**Console:** Organizations list and detail (members, connections, roles, branding).

**E2E:** auth0-cli `orgs`; auth0-spa-js with `organization`; Playwright login through the organization prompt.

### Plan 30 — Organizations II

`/organizations/{id}/invitations` (create, list, delete) with the `user_invitation` email (Plan 21) and the invitation acceptance flow (`invitation` and `organization` parameters at `/authorize`); `/organizations/{id}/client-grants` and grant `organization_usage`/`allow_any_organization` enforcement (inert since D-0041); `/organizations/{id}/discovery-domains` and home-realm discovery by email domain if documented at build time. **Short.**

### Plan 31 — Logs, log streams, stats (full design)

**Endpoints:** `GET /api/v2/logs` (Lucene `q`, paging, checkpoint `from`/`take`), `GET /api/v2/logs/{id}`, `GET /api/v2/users/{id}/logs`; `/api/v2/log-streams` (CRUD) for types `http`, `datadog`, `splunk`, `sumo`, `segment`, `mixpanel`, `eventbridge`, `eventgrid` (the two cloud-account types stored, not enforced, unless the design finds a clean way); `GET /api/v2/stats/active-users`, `GET /api/v2/stats/daily`.

**Runtime:** every Authentication API, hosted-page and Management API event writes an Auth0-typed log event (`s`, `f`, `fp`, `fu`, `ss`, `fs`, `scp`, `sapi`, `seccft`, `limit_wc`, … per Auth0's documented event-type codes), replacing "Management writes go to the server log" (management design §6); tenant retention as configured; streams deliver with retries and filters; stats aggregate from logs.

**Full design questions:** storage volume and retention per driver, the query engine (reuse of the Plan 17 query tree), delivery guarantees for streams, privacy (IP and user agent handling).

**Console:** Logs (search, detail), Log streams, stats on Home.

**E2E:** auth0-cli `logs list/tail` and `logs streams`; an `http` stream received by a test server.

### Plan 32 — Event streams

`/api/v2/event-streams` (CRUD, `test`, `/deliveries`, `/redeliver`) for `webhook` and `eventbridge` destinations; Auth0's CloudEvents payloads for `user.created`, `user.updated`, `user.deleted` and any event types added by build time; signed webhook delivery with retries, sharing Plan 31's delivery machinery. **Short.**

### Plan 33 — MFA I (full design)

**Endpoints:** `/api/v2/guardian/factors` (`GET`, `PUT /{name}`), `/guardian/policies`, `/guardian/enrollments/{id}`, `POST /guardian/enrollments/ticket`, `/guardian/factors/sms|phone/...` templates and providers stored for Plan 34; user endpoints `/users/{id}/authentication-methods` (CRUD), `/users/{id}/enrollments`, `DELETE /users/{id}/multifactor/{provider}`, `POST /users/{id}/recovery-code-regeneration`, `POST /users/{id}/multifactor/actions/invalidate-remember-browser`.

**Runtime:** factors `otp`, `email`, `recovery-code`, `webauthn-roaming`, `webauthn-platform` (passkeys as a second factor); policies (`all-applications`, `confidence-score`, never); MFA prompts on hosted login with remember-browser; the Authentication API `/mfa/associate`, `/mfa/challenge`, `/mfa/authenticators` and the `mfa-otp`, `mfa-oob`, `mfa-recovery-code` grants with `mfa_required` (the Plan 5 follow-up); `api.multifactor.enable` in post-login Actions; the MFA email templates from Plan 21. `push-notification` (needs Auth0's Guardian app) and `duo` stay stored, not enforced (§5).

**E2E:** Playwright enrolment and challenge with a TOTP generator and a virtual WebAuthn authenticator; node-auth0 `guardian`; auth0-auth-js MFA grants.

### Plan 34 — Passwordless and phone (full design)

**Endpoints:** `/api/v2/connections` with strategies `email` and `sms` and their options (templates, OTP length and lifetime, brute force); `/api/v2/branding/phone/providers` (`twilio`, `custom`) and `/branding/phone/templates` (CRUD, test); `/guardian/factors/sms|phone` providers and templates go live.

**Runtime:** `/passwordless/start` and the `passwordless/otp` grant; code and magic-link login on hosted pages; SMS through Twilio or the `send-phone-message`/`custom-phone-provider` Actions; MFA by SMS and voice; phone-based password reset (the management design follow-up); phone numbers as identifiers (`attributes` stored since D-0042 become enforced).

### Plan 35 — Client credentials, JAR, token exchange

`/api/v2/clients/{id}/credentials` (CRUD) with `public_key` and `x509_cert` credentials; `private_key_jwt` client authentication at `/oauth/token`, `/oauth/par` and `/oauth/revoke`; JAR (`request` objects signed with those keys); `signed_request_object` client settings; `/api/v2/token-exchange-profiles` with the custom token exchange grant and its Action (Plan 28). mTLS client auth and RAR are listed in §5 for a later decision. **Short.**

### Plan 36 — Enterprise OIDC connections

Remaining `oidc` and `okta` enterprise features, front-channel OIDC, home-realm discovery by `domain_aliases`, and `/api/v2/connections/{id}/keys` (`GET`, `POST .../rotate`) for connections that sign requests. Also `GET /api/v2/connections/{id}/status`, and `DELETE /api/v2/connections/{id}/users?email=`. Basic `oidc` back-channel login was brought forward to Plan 24; the public-cloud v2 `waad` work/school sign-in subset was implemented in Plan 25. This plan retains Entra features beyond that subset and must not reimplement its login adapters. **Short**, on Plans 24–25's federation core.

### Plan 37 — SAML, WS-Federation, SCIM, self-service SSO (full design; sub-project 4)

SAML as identity provider (`samlp` addon on clients) and as service provider (`samlp` connections), WS-Federation (`wsfed` addon, `adfs` connection), `/samlp/{client_id}` metadata, SAML logout; `/api/v2/connections/{id}/scim-configuration` (and tokens) with an inbound SCIM 2.0 server; `/api/v2/self-service-profiles` and SSO tickets with the self-service setup flow. Likely two or three plans after its design.

### Plan 38 — AD/LDAP, Forms and Flows, the rest (full design)

- **AD/LDAP:** the `ad` strategy. Auth0's AD/LDAP connector is open source (MIT); the design decides whether zeroauthy speaks that connector's protocol (so existing connectors keep working) or ships its own LDAP bind.
- **Forms and Flows:** `/api/v2/forms`, `/api/v2/flows`, `/flows/{id}/executions`, `/flows/vault/connections`; a visual flow builder is a large console project.
- **Remaining resources** listed at build time from Auth0's reference: `/api/v2/device-credentials`, `/api/v2/network-acls`, `/api/v2/user-attribute-profiles`, `/api/v2/connection-profiles`, `/api/v2/risk-assessments` settings, and anything Auth0 adds while the roadmap runs (the changelog review feeds this plan).

## 4. Cross-cutting work and where it lands

| Item | Plan |
|---|---|
| Rate-limit headers and a Management API limiter (Plan 13 follow-up) | 19 |
| Store-backed throttles and send limits for multi-instance deployments | 19 |
| Tenant log for Management API writes (Plan 13 follow-up) | 31 |
| Per-tenant operators (Plan 13 follow-up): system API and tenant-scoped operator tokens | 29 (alongside organization membership; short sub-design) |
| Keeping client IDs and secrets on migration (D-0039), the system API name (D-0041) | 20 |
| `HS256`/`PS256` and `signing_secret` for resource servers | 35 |
| Inert client and grant fields from D-0039/D-0041 | the plan owning each feature (organizations 29–30, RAR §5, token encryption §5) |
| Stored-not-enforced connection options from D-0042 | passkeys 33, attributes and phone 34, MFA 33, `display_name`/`show_as_button` 22 |
| Console translations beyond English | any plan; no dependency |
| `auth0-deploy-cli` round trip | grows from Plan 20 onward; each plan removes its resource types from `AUTH0_EXCLUDED` |

## 5. Not planned (with reasons)

- **Rules, Hooks, rules-configs** (`/api/v2/rules`, `/rules-configs`, `/hooks`): end-of-life on Auth0 in favour of Actions. `GET` returns empty lists so `auth0-deploy-cli` exports work; writes answer as Auth0 answers for a tenant without them (Task 1 of Plan 20 records it).
- **Customer-managed encryption keys** (`/api/v2/keys/encryption`, BYOK): zeroauthy's master key is already the operator's own; revisit if a hosted offer needs per-tenant keys.
- **Guardian push notifications and Duo:** need Auth0's own app or a vendor contract. Stored, not enforced.
- **Vendor-contract CAPTCHA (Arkose) and Auth0's own bot challenge:** stored, not enforced.
- **Marketplace, integration catalogues, extensions:** dashboard features with no Management API surface worth matching.
- **Deprecated endpoints** (already listed in the matrix).
- **mTLS client authentication, RAR, token encryption, DPoP:** each a separate protocol feature; a decision when a user asks.

Anything here can move into a plan by maintainer decision.

## 6. Risks

- **Size.** Plans 22, 27, 31, 33 and 37 are each larger than any plan so far; their full designs should split them further rather than grow single plans.
- **Observation limits.** Some resources need paid Auth0 plans (organizations at scale, enterprise connections, log streams, custom domains with managed certificates). Task 1 records what the maintainer's tenant can show; the rest follows the docs and is logged.
- **Moving target.** Auth0 ships Management API changes monthly. The changelog review before each plan keeps the roadmap current; Plan 38 collects new resources.
- **Runtime security.** Actions, Liquid templates and email templates run tenant-supplied code or markup. Each full design must state the sandbox (no environment, no host files, limits), as D-0022 did for custom databases.
