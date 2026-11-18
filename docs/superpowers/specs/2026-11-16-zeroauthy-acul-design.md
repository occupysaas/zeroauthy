# Plan 44 — Advanced Customizations for Universal Login (ACUL) and the remaining Universal Login modes

**Date:** 2026-11-16. **Status:** design; not implemented; needs maintainer
rulings (§11) before Task 2.

**Roadmap entry:** [management roadmap, Plan 44](2026-10-19-zeroauthy-management-roadmap-design.md)
(full); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **H1** (track H, only item; Plans 22, 29 and 33 merged). Read the
[clean-room policy](../../../CLEAN_ROOM.md) (open-source Auth0 code may be
read and studied; provenance recorded), `AGENTS.md`, the
[Plan 22 branding spec](2026-10-25-zeroauthy-branding-universal-login-design.md),
the [branding guide](../../branding.md) and D-0047/D-0050 (hosted page
security decisions).

## 1. Outcome and scope

An operator switches a Universal Login screen to **advanced rendering**:
zeroauthy then serves a minimal host page that loads the operator's own
JavaScript and CSS (built with Auth0's ACUL SDK) and exposes the screen's
context as `window.universal_login_context`. The operator's UI posts the
same form fields to the same `/u/...` route as the standard page. The
Management API `prompts/.../rendering` routes, Deploy CLI `screenRenderers`
and the Auth0 CLI `acul` commands work against zeroauthy. Plan 22's
remaining deferrals close where Auth0 documents them.

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first). The wire contract of the host page (the global, the form posts) is
learned from Auth0's MIT-licensed ACUL SDK (`auth0/universal-login`,
`packages/auth0-acul-js`, tag `auth0-acul-js-v1.11.0`), as CLEAN_ROOM.md
allows; every behaviour learned only from it is confirmed by running the
SDK against zeroauthy (E2E) and recorded with provenance. Local rulings
**LR44-n**, observation points **Z1–Zn** in **D-0230** (H1 block
D-0230–0239).

### In scope

1. **Rendering API:** `GET`/`PATCH /api/v2/prompts/{prompt}/screen/{screen}/rendering`,
   `GET /api/v2/prompts/rendering` (list, filters `fields`, `include_fields`,
   `page`, `per_page`, `include_totals`, `prompt`, `screen`,
   `rendering_mode`), `PATCH /api/v2/prompts/rendering` (bulk). Body per
   the OpenAPI: `rendering_mode` (`advanced` | `standard`),
   `context_configuration[]`, `default_head_tags_disabled`,
   `use_page_template`, `head_tags[]` (`tag`, `attributes`, `content`),
   `filters` (`match_type` `includes_any` | `excludes_any`, `clients`
   by id or metadata, `organizations`, `domains`). Scopes `read:prompts`,
   `update:prompts`.
2. **ACUL host page** for every screen zeroauthy already renders (§4 list),
   with the context object (§5), the operator's head tags, and the security
   boundary (§6).
3. **Form contract:** every `/u/...` POST route accepts the SDK's payloads
   (field names and `action` values per screen) in addition to today's
   standard-page fields, with CSRF bound to `state` (§7).
4. **Remaining Universal Login controls** documented by Auth0 that Plan 22
   stored only: `widget.social_buttons_layout` (`top` | `bottom`), the
   secondary-action partial slots on the screens that have them, prompt
   partials and Liquid context gaining `transaction.custom_domain`, and
   `webauthn_platform_first_factor` (passkey-first on identifier-first login,
   on Plan 33b's passkeys).
5. **Phone factor on MFA enrollment tickets** (`POST /guardian/enrollments/ticket`
   with `factor: phone`, Plan 34 providers).
6. **Deploy CLI** `prompts.screenRenderers` round trip; **auth0-cli** `acul`
   config commands that only call the rendering API.
7. **Console:** per-screen rendering editor (mode, head tags, context
   items, filters) with validation and a local preview using a synthetic
   context.

### Not in scope

- **Classic Login** (`universal_login_experience: classic`, Lock-based
  custom login page): a separate legacy runtime with cross-origin
  authentication; stays stored-only (decision §11.1).
- Screens zeroauthy does not have: Guardian push (`mfa-push-*`),
  `customized-consent` (RAR), Experiment Center (`experiment` context),
  `email-identifier-challenge` if Plan 34 has no such flow (Z1), Forms
  (A2). Their renderings are stored and returned, never served (LR44-1).
- Operator-hosted assets are not hosted by zeroauthy (as on Auth0: the
  operator's CDN).

### Anti-goals

- **Script injection through context.** The context JSON is embedded with
  HTML-safe escaping (`<`, `>`, `&`, U+2028/2029 escaped) in a
  non-executable `<script type="application/json">` element read by a
  small nonce'd bootstrap that assigns `window.universal_login_context`;
  tenant data never becomes markup.
- **Arbitrary head content.** Only `script` (with `src`), `link` (with
  `href`) and `meta` tags (the §6 proposal, decision §11.2); attributes from
  an allowlist; absolute HTTPS URLs only;
  `integrity` required on `script` and stylesheet `link` (SRI, documented
  at run time by Auth0, LR44-2); no inline `script` content.
- **Data beyond configuration.** `untrusted_data.*`, `user.*_metadata.*`,
  `client.metadata.*`, `organization.metadata.*` enter the context only
  when listed in `context_configuration` (documented opt-in).
- **CSRF on state-only posts.** The SDK posts `state` and fields only; the
  route must still bind the post to the browser that owns the transaction
  (§7).
- **Weakening standard pages.** Screens left `standard` keep Plan 22's
  CSP, markup and behaviour byte for byte.

## 2. Evidence

- Management OpenAPI (read 2026-11-16): `get_rendering`, `patch_rendering`,
  `get_all_rendering`, `patch_bulk_rendering`; schemas `AculContextConfigurationItem`
  (static enum `branding.settings`, `branding.themes.default`,
  `country_codes`, `client.logo_uri`, `client.description`,
  `organization.display_name`, `organization.branding`, `screen.texts`,
  `tenant.name`, `tenant.friendly_name`, `tenant.logo_url`,
  `tenant.enabled_locales`, `untrusted_data.submitted_form_data`,
  `untrusted_data.authorization_params.login_hint|screen_hint|ui_locales`,
  `user.organizations`, `transaction.custom_domain.domain`, `experiment`;
  dynamic `client.metadata.<k>`, `organization.metadata.<k>`,
  `transaction.custom_domain.domain_metadata.<k>`, `user.user_metadata.<k>`,
  `user.app_metadata.<k>`, `untrusted_data.authorization_params.ext-<k>`),
  `AculHeadTag`, `AculMatchTypeEnum`, `AculClientFilter` (by id or by
  metadata).
- Auth0 ACUL pages: `/docs/customize/login-pages/advanced-customizations/getting-started/configure-acul-screens`
  (minimal host page referencing the operator's CDN assets, SRI verified
  by the browser; requires Universal Login, a custom domain and a
  first-party application), `.../reference` (JS and React SDKs, Management
  routes, Deploy CLI, Terraform `prompt_screen_renderer`, `auth0 acul`).
- ACUL SDK source (MIT, `auth0-acul-js-v1.11.0`): the context is read from
  `window.universal_login_context`; top-level members `branding`,
  `client`, `country_codes`, `experiment`, `organization`, `prompt`,
  `screen`, `tenant`, `transaction`, `user`, `untrusted_data`; forms are
  native POSTs to the current URL (or a screen-specific route) with the
  payload fields, `state`, and an `acul-sdk` telemetry field; 81 screen
  modules (list read at build time).
- Deploy CLI 9.1.0 `prompts` handler (`screenRenderers` from
  `prompts.rendering.list`).

## 3. Rendering resource

- Stored per tenant, prompt and screen (only pairs from the SDK's screen
  list and Auth0's prompt/screen pairs; unknown pairs `404`, Z2).
- `rendering_mode: standard` with other fields keeps them stored (Auth0
  returns them); `advanced` requires at least one `head_tags` `script`
  (LR44-3).
- Limits (LR44-4, Z3): 25 head tags, 2048-byte URLs, 50 context items,
  100 client/organization/domain filters, attribute values ≤ 2048 bytes.
- **Filters:** `includes_any` — advanced rendering applies only when the
  request's client (by `id`, or by a `metadata` key/value), organization
  (`id` or `metadata`) or custom domain matches any entry; `excludes_any` —
  applies unless one matches. No filters → always.
- `use_page_template: true` — the tenant's Plan 22 page template wraps the
  host page (`{%- auth0:head -%}` gets the ACUL head, `{%- auth0:widget -%}`
  gets the mount point).
- `default_head_tags_disabled: true` — the host page omits zeroauthy's
  default head tags (base styles and the favicon), keeping only the
  security bootstrap.
- Custom domain: Auth0 requires one for ACUL (documented); zeroauthy serves
  ACUL on canonical and custom hosts alike (LR44-5: the requirement is an
  Auth0 platform constraint; refusing on the canonical host would only make
  local testing harder) — decision §11.3.

## 4. Screens

ACUL is served for the screens whose standard pages exist (map from Auth0
screen names to zeroauthy routes, built in Task 1 and checked by test):
`login`, `login-id`, `login-password`, `login-passwordless-email-code`,
`login-passwordless-sms-otp`, `login-email-verification`, `signup`,
`signup-id`, `signup-password`, `passkey-enrollment`,
`passkey-enrollment-local`, `phone-identifier-enrollment`,
`phone-identifier-challenge`, `reset-password-request`,
`reset-password-email`, `reset-password`, `reset-password-success`,
`reset-password-error`, the `reset-password-mfa-*` screens zeroauthy has
(OTP, email, SMS, voice, recovery code, WebAuthn), `mfa-*` screens for OTP,
email, SMS, voice, recovery code and WebAuthn (enrollment, challenge,
lists, `mfa-begin-enroll-options`, `mfa-login-options`,
`mfa-detect-browser-capabilities`, `mfa-enroll-result`,
`mfa-country-codes`), `consent`, `device-code-*`,
`organization-selection`, `organization-picker`, `accept-invitation`,
`logout`, `logout-complete`, `logout-aborted`,
`email-verification-result`, `interstitial-captcha`,
`brute-force-protection-unblock*` (if Plan 19 has the unblock page, Z1),
`redeem-ticket`.

## 5. Context

Built from the same view model the standard page uses (no second
authorization path):

| Member | Content |
|---|---|
| `client` | `id`, `name`; `logo_uri`, `description`, `metadata.<k>` when configured |
| `organization` | `id`, `name`; `display_name`, `branding`, `metadata.<k>` when configured |
| `prompt` | `name` |
| `screen` | `name`, `links` (signup, reset, back), `data` (screen-specific: e.g. identifier, captcha config, TOTP QR data, phone masked), `texts` when configured (Plan 22 custom text merged with the catalog) |
| `tenant` | `name`, `friendly_name`, `logo_url`, `enabled_locales` when configured |
| `transaction` | `state`, `locale`, `errors[]` (`code`, `message`, `field`), `connection` (`name`, `strategy`, `options` subset: username/password policy, signup flags), `alternate_connections[]` (social/enterprise buttons), `custom_domain.domain` when configured |
| `user` | for screens after identification: `id`, `email`, `username`, `phone_number`, `picture`, `enrolled_factors`; `organizations`, `user_metadata.<k>`, `app_metadata.<k>` when configured |
| `untrusted_data` | `submitted_form_data` (the last post's non-secret fields), `authorization_params` items when configured |
| `branding` | `settings`, `themes.default` when configured (Plan 22) |
| `country_codes` | when configured (Plan 34's list) |

Field names follow the SDK's interfaces (`interfaces/models/*.ts`); each
member's provenance is recorded per field in D-0230 (Z4 lists the members
whose meaning is learned only from the SDK).

## 6. Security boundary (proposal for §11.2)

- `Content-Security-Policy` for ACUL pages:
  `default-src 'none'; script-src 'nonce-<n>' <script origins>;
  style-src <style origins> 'nonce-<n>'; img-src https: data:;
  font-src <font origins from link preload>; connect-src 'self' <script origins>;
  form-action 'self' <the client's callback origins for this transaction>;
  frame-ancestors 'none'; base-uri 'none'`. Origins are derived from the
  head tags' URLs; `'unsafe-inline'` and `'unsafe-eval'` never appear.
- `integrity` required on every `script` and stylesheet `link`
  (`sha256|sha384|sha512-…`), `crossorigin="anonymous"` added.
- Allowed tags: `script` (`src`, `integrity`, `defer`, `async`, `type=module`,
  `crossorigin`), `link` (`rel` in `stylesheet|preload|modulepreload|icon`,
  `href`, `integrity`, `as`, `crossorigin`), `meta` (`name`, `content`).
  No `style` content, no inline script, no `base`, no `iframe`.
- The host page sets `Referrer-Policy: no-referrer`, `X-Content-Type-Options:
  nosniff`, and the Plan 22 `Permissions-Policy`.
- Passkey and WebAuthn screens still call `navigator.credentials` from the
  operator's script; the RP ID rules of Plan 33b apply server-side.

## 7. Form contract and CSRF

- Each route accepts the SDK payload for its screen (field names learned
  from the SDK screen modules, e.g. `username`, `password`, `action`
  `default`/`back-to-login`/`toggle-view`, `connection` for federated
  buttons, `code` for OTP, `captcha`), mapped onto the same handler code
  the standard page uses.
- CSRF: standard pages keep their hidden CSRF field. ACUL posts carry no
  such field, so on screens rendered advanced for this transaction the
  route accepts the post when (a) `state` names the transaction, (b) the
  transaction cookie set on the host page matches (Plan 22 binding), and
  (c) `Origin` (or `Referer` when Origin is absent) equals the request host
  (LR44-6). Posts failing any check get the Plan 22 stale-form answer.
- The `acul-sdk` field is ignored (telemetry) and never logged with values
  other than the SDK name and version.

## 8. Remaining Universal Login controls

- `widget.social_buttons_layout`: `top` renders federated buttons above the
  form, `bottom` (default) below (Z5).
- Secondary-action partial slots (`secondary-actions-start/end`) on the
  screens Auth0 lists for them; same Plan 22 control rules.
- Liquid and partial context gain `transaction.custom_domain.domain`
  (Plan 23).
- `webauthn_platform_first_factor: true` with identifier-first: the
  identifier page offers passkey sign-in (conditional UI autofill and a
  button) before the password step, on Plan 33b's ceremony (Z6).
- MFA enrollment tickets with `factor: phone`.

## 9. Storage, console, tooling, tests

- **Storage:** one table `prompt_renderings(tenant_id, prompt, screen,
  config JSON, updated_at)` (migration numbered at merge); gRPC capability
  `prompt_rendering.v1` (without it the rendering API answers `501` and
  every screen renders standard).
- **Console:** Branding → Universal Login → per-screen "Rendering" tab.
- **Deploy CLI:** `screenRenderers` in the four-cell round trip.
- **Tests:** rendering rules table; filter evaluation; CSP construction;
  context builder snapshots per screen (with and without each
  configuration item); escaping fuzz test; CSRF checks; standard pages
  unchanged (golden HTML from Plan 22).
- **E2E** `make e2e-acul` (new lane): a small operator app built with
  `@auth0/auth0-acul-js` 1.11.0 (pin needs maintainer approval, §11.4),
  served from a local HTTPS "CDN" with SRI hashes, driving login-id,
  login-password, signup, MFA OTP challenge and reset-password screens
  through Playwright; node-auth0 7.4.0 `prompts.rendering` calls; Deploy CLI
  `screenRenderers`.

## 10. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR44-1 | Renderings for screens zeroauthy lacks are stored, never served. |
| LR44-2 | SRI `integrity` required on scripts and stylesheets. |
| LR44-3 | `advanced` needs at least one script head tag. |
| LR44-4 | Head-tag, context and filter limits as §3. |
| LR44-5 | ACUL served on canonical and custom hosts. |
| LR44-6 | State + transaction cookie + same-origin check replace the CSRF field on ACUL posts. |

Observe later (`docs/superpowers/plan-1-followups.md`):

- **Z1** Which unblock and email-identifier screens exist on zeroauthy.
- **Z2** Answer for an unknown prompt/screen pair.
- **Z3** Auth0's head-tag and filter limits.
- **Z4** Context members learned only from the SDK.
- **Z5** `social_buttons_layout` default.
- **Z6** Passkey-first behaviour details with identifier-first.

## 11. Decisions needed from the maintainer

1. **Classic Login:** not built (recommended), or a later plan.
2. **Content-security boundary (§6):** confirm the tag/attribute allowlist,
   mandatory SRI and the CSP; this is the roadmap's open question for
   Plan 44.
3. **ACUL on the canonical host** (LR44-5): allow (recommended) or require a
   custom domain as Auth0 does.
4. **New E2E pin** `@auth0/auth0-acul-js` 1.11.0 (MIT).

## 12. Left to the builder

- The screen → route map's file location and test.
- Whether the context builder lives in `internal/hostedlogin` or a new
  `internal/acul` package.
