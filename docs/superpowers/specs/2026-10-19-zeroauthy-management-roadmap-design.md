# zeroauthy — Design: finishing the Management API (roadmap, Plans 19 onward)

- **Status:** Draft for maintainer review (2026-10-19)
- **Date:** 2026-10-19
- **Scope:** every Auth0 Management API v2 resource not covered by slices 1–4 (applications, APIs, client grants, database connections, users and jobs), broken into plans with an order, dependencies and a short design each.
- **Inputs:** the management design (`2026-10-18-zeroauthy-management-design.md`), the users design (`2026-10-19-zeroauthy-users-design.md`), the compatibility matrix, the follow-ups file, and the maintainer's 2026-10-19 rulings.

## 0. Where we are (2026-10-19)

**Plans done:** 16. **Specified, not built:** 2 (Plans 17–18). **Left in this roadmap:** 20 (Plans 19–38); the five "full" plans will likely split, so expect roughly 25–30 more plans.

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

### Management API coverage by resource

Auth0's Management API reference has about 40 resource groups. Status of each:

| Status | Count | Resources |
|---|---|---|
| **Done** | 4 | clients, resource-servers, client-grants, connections (database strategy) |
| **Specified** (Plans 17–18) | 6 | users, users-by-email, tickets, grants, sessions and refresh tokens, jobs |
| **Planned, short design** | 13 | tenant settings, attack protection, user blocks, signing keys, email provider, email templates, social strategies II, roles, Actions II, organizations II, event streams, client credentials / token exchange, enterprise OIDC |
| **Planned, full design** | 15 | branding, themes, prompts and custom text, custom domains, social strategies I, Actions, organizations, logs, log streams, stats, guardian (MFA), passwordless and phone branding, SAML/WS-Fed/SCIM/self-service, AD/LDAP, forms and flows |
| **Not planned** | 4 | rules, rules-configs, hooks (end-of-life on Auth0), customer-managed encryption keys |

Read as resource groups, about 10% is done and 15% is specified. Read as work, the remaining plans are larger than the finished Management API ones, because most carry a runtime feature (MFA, Actions, organizations, social login) rather than only endpoints. The Authentication API side (sub-project 1) is complete apart from what those features add.

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
| 19 | Tenant settings, attack protection, user blocks | short | 17 |
| 20 | Signing keys, `auth0-deploy-cli` round trip | short | 19 |
| 21 | Email provider and email templates | short | 19 |
| 22 | Branding: themes, settings, Universal Login page templates, prompts and custom text | full | 21 |
| 23 | Custom domains with automatic certificates | full | 19 |
| 24 | Social connections I: generic OAuth 2 and OIDC, Google | full | 17 |
| 25 | Social connections II: Apple, Facebook, Microsoft, GitHub, the rest of the common list | short | 24 |
| 26 | Roles and permissions (RBAC) | short | 17 |
| 27 | Actions I: runtime, post-login, credentials exchange, the Actions API | full | 26 |
| 28 | Actions II: the remaining triggers, secrets, modules, npm dependencies | short | 27 |
| 29 | Organizations I: organizations, members, roles, enabled connections, login with an organization | full | 26 |
| 30 | Organizations II: invitations, client grants, discovery domains | short | 29, 21 |
| 31 | Logs, log streams, stats | full | 19 |
| 32 | Event streams | short | 31 |
| 33 | MFA I: OTP, email, recovery codes, WebAuthn, policies, the MFA API, user authentication methods | full | 21, 27 |
| 34 | Passwordless and phone: email and SMS connections, phone providers and templates, MFA by SMS and voice | full | 33 |
| 35 | Client credentials: `private_key_jwt`, JAR, token exchange profiles | short | 27 |
| 36 | Enterprise OIDC connections: `oidc`, `okta`, Microsoft Entra ID (`waad`), connection keys | short | 24 |
| 37 | SAML and WS-Federation (sub-project 4), SCIM, self-service SSO profiles | full | 36 |
| 38 | AD/LDAP connector, Forms and Flows, remaining resources | full | 27, 37 |

Plans 17 and 18 come from the users design. Plan 37 is sub-project 4 of the core spec and may itself split.

## 3. Plans

### Plan 19 — Tenant settings, attack protection, user blocks (slice 5a)

**Endpoints:**
- `GET/PATCH /api/v2/tenants/settings`: every documented field. Enforced where zeroauthy has the feature: `friendly_name`, `picture_url`, `support_email`, `support_url`, `default_audience`, `default_directory`, `session_lifetime`, `idle_session_lifetime`, `enabled_locales`, `flags` that map to built behaviour, `device_flow`, `pushed_authorization_requests_supported`, `skip_non_verifiable_callback_uri_confirmation_prompt`, `sessions` (cookie mode), `allowed_logout_urls`, `default_redirection_uri`, `error_page`, `customize_mfa_in_postlogin_action` and the rest stored, not enforced, until their plan.
- `/api/v2/attack-protection/brute-force-protection`, `/breached-password-detection`, `/suspicious-ip-throttling`, `/bot-detection`, `/captcha`.
- `/api/v2/user-blocks` (by identifier, by user ID; list and unblock), `/api/v2/anomaly/blocks/ips/{ip}` (check and unblock).

**Runtime:**
- Login throttles move into the store (the Plan 2, 5 and 6 multi-instance follow-ups), keyed as Auth0 keys them (user plus IP for brute force; IP for suspicious-IP throttling), with Auth0's thresholds as defaults and the `shields` (`block`, `user_notification`, `admin_notification`) and `allowlist`.
- Breached password detection: checks at signup, login and reset against a k-anonymity range API (Have I Been Pwned's Pwned Passwords, opt-in, outbound HTTPS) or an offline list file; Auth0's shields (`block`, `user_notification`, `admin_notification`) and stages.
- CAPTCHA: server-side verification for the documented providers zeroauthy can reach (reCAPTCHA v2 and Enterprise, hCaptcha, Friendly Captcha, Cloudflare Turnstile if Auth0 lists it at build time); providers that need a vendor contract (Arkose, Auth0's own challenge) stored, not enforced. Bot detection levels drive when the CAPTCHA appears.
- The "blocked account" and "breached password" notification emails wait for Plan 21; until then the `user_notification` shield logs a warning (a decision).

**Console:** Tenant settings (General, Sessions, Advanced, Languages) and Attack protection become live; the user detail gains "unblock" for brute-force blocks.

**E2E:** `auth0 tenant-settings` and `auth0 protection` commands (auth0-cli), a Playwright brute-force lockout and unblock, a breached-password refusal against a local mock range API.

### Plan 20 — Signing keys and the `auth0-deploy-cli` round trip (slice 5b)

**Endpoints:** `GET /api/v2/keys/signing`, `GET /api/v2/keys/signing/{kid}`, `POST /api/v2/keys/signing/rotate`, `PUT /api/v2/keys/signing/{kid}/revoke`; `/api/v2/keys/custom-signing` (bring your own signing JWKS) stored and used for signing if Task 1 and the docs settle the semantics, else stored, not enforced. `/api/v2/keys/encryption` (customer-managed root key) is listed in §5.

**Runtime:** the existing key manager's rotation becomes reachable from the API; revoke removes a key from JWKS and refuses tokens it signed.

**Round trip:** `auth0-deploy-cli` export from an Auth0 tenant (the maintainer's dev tenant), import into zeroauthy, export from zeroauthy, and compare. Resource types that zeroauthy does not have yet are listed in `AUTH0_EXCLUDED`; each later plan removes its types from that list, so the round trip grows with the roadmap. Open decisions carried from the follow-ups and settled here: keeping client IDs and secrets on migration (D-0039), the system API name (D-0041).

**Console:** Signing keys under Settings (list, rotate, revoke with confirmation).

**E2E:** `auth0-deploy-cli` in YAML and directory formats; `auth0 api` for the key endpoints.

### Plan 21 — Email provider and email templates

**Endpoints:** `GET/POST/PATCH/DELETE /api/v2/emails/provider`; `GET/POST/PUT/PATCH /api/v2/email-templates/{templateName}` for every documented template name (`verify_email`, `verify_email_by_code`, `reset_email`, `reset_email_by_code`, `welcome_email`, `blocked_account`, `stolen_credentials`, `enrollment_email`, `mfa_oob_code`, `user_invitation`, `change_password`, `password_reset`, `async_approval` and any added since).

**Runtime:**
- Provider per tenant, replacing the global SMTP config as the default: `smtp` and the HTTP providers zeroauthy can implement without vendor SDKs (`sendgrid`, `mailgun`, `mandrill`, `sparkpost`, `ses`, `azure_cs`, `ms365`, `resend` as Auth0 lists them at build time), and Auth0's `custom` provider (an Action) once Plan 27 lands. The server-wide SMTP setting stays as the fallback, so self-hosters need no per-tenant setup.
- Templates use Liquid, as Auth0's do, with Auth0's documented variables (`user`, `application`, `tenant`, `url`, `support_url`, `friendly_name` …). A permissively licensed Go Liquid engine (recorded in NOTICE) renders them; untrusted templates run with no file or network access.
- `welcome_email` after signup and verification; `blocked_account` and `stolen_credentials` for Plan 19's shields; templates for later plans' emails (MFA, invitations) are stored now and wired in those plans.

**Console:** Email templates and Email provider pages go live; a "send test email" action (Auth0 has one in its dashboard; the API equivalent is whatever Task 1 finds, else a system API extension logged as a decision).

**E2E:** node-auth0 `emails` and `emailTemplates`; Playwright signup with a welcome email from a custom template captured by the dir driver.

### Plan 22 — Branding and Universal Login (full design)

The maintainer's own priority: sign-in pages that look like the customer's site, on the customer's domain (with Plan 23).

**Endpoints:**
- `GET/PATCH /api/v2/branding` (`colors.primary`, `colors.page_background`, `favicon_url`, `logo_url`, `font.url`);
- `GET/PUT/DELETE /api/v2/branding/templates/universal-login` (the page template);
- `/api/v2/branding/themes` (`POST`, `GET/PATCH/DELETE /{themeId}`, `GET /default`): the full theme (borders, colors, fonts, page background, widget);
- `GET/PATCH /api/v2/prompts` (`universal_login_experience`, `identifier_first`, `webauthn_platform_first_factor`);
- `GET/PUT /api/v2/prompts/{prompt}/custom-text/{language}` (storage exists since Plan 4);
- `GET/PUT /api/v2/prompts/{prompt}/partials` (custom form fields injected into widget slots);
- `/api/v2/prompts/{prompt}/screen/{screen}/rendering` (Advanced Customizations for Universal Login) is listed for the full design to decide: it needs Auth0's client-side SDK contract.

**Runtime:**
- Every hosted page renders inside the tenant's page template. The template is Liquid with Auth0's tags (`{%- auth0:head -%}`, `{%- auth0:widget -%}`) and variables (`application`, `organization`, `prompt`, `locale`, `user`, `branding`, `tenant`, `custom_domain`, `transaction`); a template written for Auth0 renders unchanged. Auth0's limits (size, required tags) are enforced.
- Theme and branding values become CSS custom properties consumed by the widget; the widget's markup stays zeroauthy's own (CLEAN_ROOM.md: the behaviour and contract are Auth0's, the look is not copied).
- `identifier_first` switches the login page to the two-step identifier flow.
- Partials render into documented slots and their form values reach Actions (Plan 27) as `event.prompt` data; until then they are stored and rendered.

**Design questions for the full design:** template sandboxing (no network, no file access, render time limit), CSP for templates that load external fonts and scripts, how a template preview works in the console, what happens to zeroauthy's own template override directory (the Plan 2 follow-up).

**Console:** Universal Login page: branding fields, theme editor, template editor with a live preview rendered by the server in a sandboxed frame, custom text per prompt and language.

**E2E:** auth0-cli `universal-login` (`customize`, `templates`, `prompts`) commands; Playwright: a template and theme set through the API render on `/u/login`, custom text replaces a catalog string.

### Plan 23 — Custom domains with automatic certificates (full design)

**Endpoints:** `GET/POST /api/v2/custom-domains`, `GET/PATCH/DELETE /api/v2/custom-domains/{id}`, `POST /api/v2/custom-domains/{id}/verify`, `GET/PATCH /api/v2/custom-domains/default`; fields `type` (`auth0_managed_certs` and `self_managed_certs`), `verification` methods, `custom_client_ip_header`, `tls_policy`, `domain_metadata`, `status`.

**Runtime:**
- Custom domains become the source of the tenant's `domains` (the system API keeps working and writes the same data).
- Verification as Auth0 documents it (a CNAME or TXT record), checked by DNS lookups with a retry schedule.
- `auth0_managed_certs` (named zeroauthy-managed in our wording): certificates issued and renewed by ACME (Let's Encrypt or any ACME CA in config) with a store-backed certificate cache so several instances share certificates; HTTP-01 and TLS-ALPN-01.
- `self_managed_certs`: zeroauthy sits behind the customer's proxy; Auth0's `cname-api-key` header check and `custom_client_ip_header`.
- Issuer and token `iss` follow the domain the request arrived on, as Auth0 does for custom domains (Task 1 confirms which claims change).

**Hosting (the maintainer's later offer):** the design also covers wildcard subdomains under `base_domain` (one DNS-01 wildcard certificate, provider plug-in for DigitalOcean DNS first) so new tenants get HTTPS without per-tenant issuance. This part is a zeroauthy extension, documented as such.

**Console:** Custom domains page: add, show the DNS record to create, verify, status.

**E2E:** auth0-cli `domains` commands; an ACME test CA (Pebble) in a container issuing a certificate for a test domain; sign-in on the custom domain.

### Plan 24 — Social connections I: generic OAuth 2 and OIDC, Google (full design; slice 6a)

**Endpoints:** `/api/v2/connections` accepts strategies `oauth2` and `google-oauth2` with their documented `options`; `/users/{id}/identities` link and unlink social identities; `federated-connections-tokensets` stays out.

**Runtime:** federated login from `/authorize` (`connection=` and buttons on the login page), state and PKCE to the upstream, ID token validation for OIDC upstreams, profile mapping into Auth0's normalized profile (`identities[].isSocial`, `access_token` storage rules), `set_user_root_attributes`, upstream token storage as Auth0 stores it (readable with `read:user_idp_tokens`), matching imported users by provider user ID (the users design import keeps `identities`).

**Full design questions:** the upstream-token storage policy, how Auth0's `fetchUserProfile` script for `oauth2` runs (Node runner from Plan 8 or Actions), account linking (Auth0 links nothing automatically; zeroauthy matches that).

**E2E:** a mock OIDC provider in a container; auth0-cli `connections` with the new strategies; Google against the maintainer's dev credentials, manual and optional.

### Plan 25 — Social connections II

Strategies `apple`, `facebook`, `windowslive` (Microsoft account), `github`, then `linkedin`, `twitter`, `amazon`, `discord`, `slack` and the rest of the most-used list from public usage data at build time. Each is an `oauth2` profile with its documented options, scopes and profile mapping. Apple adds its client-secret JWT and private-email relay handling. **Short.**

### Plan 26 — Roles and permissions (RBAC)

**Endpoints:** `/api/v2/roles` (CRUD), `/roles/{id}/permissions`, `/roles/{id}/users`, `/users/{id}/roles`, `/users/{id}/permissions`; resource server `enforce_policies` and `token_dialect` values `access_token_authz`, `rfc9068_profile`, `rfc9068_profile_authz` become enforced (D-0041 lists them inert).

**Runtime:** with RBAC on, requested scopes are capped by the user's permissions; the `permissions` claim appears for the `_authz` dialects; client credentials unaffected, as on Auth0.

**Console:** Roles list and detail (permissions, users); a Roles tab on user detail; RBAC switches on API detail.

**E2E:** auth0-cli `roles` and `users roles`; express-oauth2-jwt-bearer `requiredScopes` against a token carrying permissions.

### Plan 27 — Actions I (full design)

The most-used extension point on Auth0 (custom claims alone justify it).

**Endpoints:** `/api/v2/actions/actions` (CRUD), `/actions/{id}/versions` (list, get, `deploy` a version), `POST /actions/{id}/deploy`, `POST /actions/{id}/test`, `/actions/triggers`, `/actions/triggers/{triggerId}/bindings` (`GET/PATCH`), `/actions/executions/{id}`.

**Runtime:** the Plan 8 Node runner, generalized: per-tenant processes, empty environment, `--permission`, time and memory limits, Auth0's `event` and `api` objects for **post-login** (`api.accessToken.setCustomClaim`, `api.idToken.setCustomClaim`, `api.access.deny`, `api.user.setUserMetadata`/`setAppMetadata`, `api.redirect.sendUserTo` with `continue`, `api.multifactor` once Plan 33 exists) and **credentials-exchange** (`api.accessToken.setCustomClaim`, `api.access.deny`); secrets per Action, encrypted with the master key; execution records for `/executions`.

**Full design questions:** npm dependencies (Plan 28) versus a fixed allow-list; the redirect-and-continue state; how errors and timeouts surface at login; cold-start budget.

**Console:** Actions list, editor (the Plan 15 code editor), secrets, test runner, trigger flows with drag-free ordered bindings.

**E2E:** auth0-cli `actions` commands; a post-login Action adding a namespaced claim, read by auth0-spa-js; a deny Action shown on the error page.

### Plan 28 — Actions II

Remaining triggers: `pre-user-registration`, `post-user-registration`, `post-change-password`, `send-phone-message` (used by Plan 34), `password-reset-post-challenge`, `custom-email-provider` and `custom-phone-provider` (Plans 21 and 34), `custom-token-exchange` (Plan 35), `event-stream`? if Auth0 has it at build time. Modules (`/actions/modules` and versions), npm dependencies resolved at deploy time into a per-version cache with an offline mirror option. **Short**, on Plan 27's design.

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

Strategies `oidc`, `okta` and `waad` (Microsoft Entra ID), with front- and back-channel OIDC, home-realm discovery by `domain_aliases`, and `/api/v2/connections/{id}/keys` (`GET`, `POST .../rotate`) for connections that sign requests. Also `GET /api/v2/connections/{id}/status`, and `DELETE /api/v2/connections/{id}/users?email=`. **Short**, on Plan 24's federation core.

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
