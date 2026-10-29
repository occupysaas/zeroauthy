# Branding and Universal Login

Tenant branding, themes, bounded Liquid page templates, localized text and
form partials configure zeroauthy's own hosted pages. Use **Universal Login**
in the console, or the Management API below. Page markup remains zeroauthy's
original implementation; arbitrary Auth0 templates are not guaranteed to work.

## Management API

| Resource | Methods | Required M2M scopes |
|---|---|---|
| `/api/v2/branding` | GET, PATCH | `read:branding`, `update:branding` |
| `/api/v2/branding/templates/universal-login` | GET, PUT, DELETE | `read:branding`, `update:branding` |
| `/api/v2/branding/themes` | POST | `create:branding` |
| `/api/v2/branding/themes/default` | GET | `read:branding` |
| `/api/v2/branding/themes/{themeId}` | GET, PATCH, DELETE | `read:branding`, `update:branding`, `delete:branding` |
| `/api/v2/prompts` | GET, PATCH | `read:prompts`, `update:prompts` |
| `/api/v2/prompts/{prompt}/custom-text/{language}` | GET, PUT | `read:prompts`, `update:prompts` |
| `/api/v2/prompts/{prompt}/partials` | GET, PUT | `read:prompts`, `update:prompts` |

Console operators require both signed and persisted grants for the target
tenant. Writes to the reserved system tenant are rejected. A failed read is
reported visibly; it does not mean an empty saved configuration. The console
retains drafts after errors and refreshes saved state once after an uncertain
write response, without retrying that write.

Branding PATCH merges nested settings. `colors.primary` and
`colors.page_background` require six-digit hex colors. Optional `logo_url`,
`favicon_url` and `font.url` accept HTTPS URLs, an empty string, or null to clear.
URLs cannot contain credentials or fragments. Themes override branding values
where present; absent values use branding or built-in defaults.

Creating a theme returns its `themeId` and activates it as the default. Editing
an inactive theme does not activate it. Deleting the default clears the pointer
and restores branding-level styling; it does not select another saved theme.
Only the active theme is exported by the pinned Deploy CLI. The console supports
looking up other themes by ID. Every active component has a labeled editor;
JSON preserves stored compatibility values such as `widget.social_buttons_layout`,
which currently has no runtime effect.

Template GET returns `{ "template": "..." }`. PUT accepts JSON with a `template`
string or `text/html` and returns an empty 200 response; DELETE returns 204 and
restores the built-in page. Custom-text and partial PUT replace their selected
resource. Send `{}` to clear overrides and restore fallback. Language tags are
canonicalized, so `en` and `EN` address the same overrides.

## Page templates

A minimal page is:

```liquid
<html>
  <head>{%- auth0:head -%}</head>
  <body>
    <p class="za-decoration">Welcome to {{ application.name }}</p>
    {%- auth0:widget -%}
  </body>
</html>
```

Every rendered branch must contain exactly one head tag in the document head
and one widget tag in a visible body container. The renderer inserts the trusted
built-in widget without making it available as a Liquid variable. Templates
cannot move it into a label, link, hidden element or arbitrary control.

The shared email/hosted Liquid subset supports bounded conditionals,
assignments, loops and documented filters from [email templates](email.md).
Unknown tags and filters are rejected even in branches that would not execute.
Full Liquid compatibility is not claimed. Variables expose selected public
presentation fields under `application`, `tenant`, `prompt`, `locale`,
`branding` and, for an organization transaction, `organization`.
`prompt.screen.text` includes localized custom variables. Other
reserved roots can be empty until their feature exists. User metadata, secrets,
transaction identifiers, tickets, tokens, passwords and raw captured fields
are never projected into template context.

HTML is validated before saving and after rendering. Tags must balance exactly;
self-closing non-void elements are rejected. Liquid comparisons and filters use
original values; substitutions are escaped when emitted into HTML. Scripts, event attributes, inline style attributes, forms in the outer
template, embedded documents, SVG/MathML and executable URLs are rejected.
Decorative CSS is restricted to `.za-decoration` with bounded colors, spacing,
font size/weight and alignment. It cannot position overlays, hide the widget,
load URLs or introduce arbitrary selectors. Use the theme fields for widget
styling. Validated HTTPS image/font origins are added to the production CSP;
CAPTCHA provider policy remains controlled by the built-in widget.

A template/partial evaluation failure falls back to the built-in widget,
preserving status, fields, CSRF, CAPTCHA and CSP. A configuration-store failure
returns a built-in 503 page. Protocol form-post and web-message response pages,
and system-tenant login, retain their original rendering and CSP.

| Local limit | Value |
|---|---|
| Template source | 100 KiB UTF-8 |
| Each partial | 10,000 Unicode characters and 40 KiB UTF-8 |
| Aggregate saved configuration | 1 MiB; a migrated oversized record may only shrink |
| Management/preview request | 2 MiB |
| Public render context | 64 KiB |
| Rendered page | 512 KiB |
| Partials within a page | 384 KiB, reserving space for the widget |
| Nesting / loop iterations / evaluation steps | 32 / 10,000 / 100,000 |
| Render deadline / active renders per process | 100 ms / 8 |

These are zeroauthy limits, not claims about observed upstream defaults.
Existing email limits remain unchanged after sharing the evaluator.

## Text and partials

Custom text uses the existing locale negotiation and `${...}` placeholders.
Unknown recognized future text is saved without claiming it renders. Each
screen/language allows up to 30 `var-` custom variables. Raw HTML in text is
escaped. Link-only `[label](https://...)` or `mailto:` Markdown is supported;
arbitrary Markdown HTML is not. Empty maps restore the catalog fallback.

Partials use `{ "screen": { "slot": "Liquid HTML" } }`. Four slots are active
on combined login, identifier login, password login and signup:
`form-content-start`, `form-content-end`, `form-footer-start`, `form-footer-end`.
Secondary-action slots and recognized future prompt groups are stored only.
Only form-content slots may contain controls. Every control needs an accessible
label, and its name must start with `ulp-`. Password/file/hidden controls,
buttons, nested forms and attributes that change trusted form routing are
rejected. Duplicate field names across screens are rejected.

Captured values are bounded to 30 declared fields, 1,024 bytes per value and
8 KiB total including field names. Only the exact fields rendered for that
screen and locale can be submitted. Duplicate values are rejected; unchecked
controls clear their own screen's values. Redisplayed values are escaped.
Forms bind configuration and state revisions, screen and locale. A changed
configuration or stale submission returns 409 and a fresh form without
attempting authentication.

Values live only in the expiring authentication transaction. They survive the
identifier/password transition, but reset, successful completion or expiry
removes them. They are not copied to profiles, metadata, claims, logs, email,
custom database script arguments or Liquid context. Future Actions validation
requires a separate contract; no Actions hook exists today.

## Identifier-first login

Set `identifier_first: true` in `/api/v2/prompts`. The identifier step validates
syntax and captures the selected database connection without looking up a
user. Known and unknown accounts advance identically. The password step uses
the stored identifier and existing authentication, brute-force, breach,
CAPTCHA, migration and session pipeline. Signup remains a combined form.

The mode is captured when the authorization transaction starts, including a
transaction initially opened on signup. Changing the setting affects new
transactions. Ordinary credential denial returns a fresh password revision.
An infrastructure failure after authentication starts leaves the transaction
in its terminal authenticating state; start again rather than replaying it.
Shared-store CAS ensures concurrent password submissions cannot authenticate
twice. Change-identifier resets identity and transient fields.

`universal_login_experience: classic` and
`webauthn_platform_first_factor: true` are stored for compatibility and do not
activate Classic or WebAuthn flows. ACUL, arbitrary tenant JavaScript and
additional Actions hooks remain separate work.

## Preview, migration and storage upgrades

POST `/api/system/tenants/{tenant}/branding/preview` on the system host accepts
`{screen, language, overrides?}` and returns `{html, warnings}`. It requires a
console operator with target grants and read access to branding/prompts.
Overrides affect only an in-memory copy. The server chooses synthetic example
data and creates no session, transaction or ticket. External assets are
replaced/blocked. The document contains a restrictive CSP and must be shown
only in `iframe sandbox=""` through `srcdoc`. The console binds validated style
nonces to its own per-document CSP; scripts, forms, navigation, popups and
same-origin access remain disabled. Preview is intentionally stricter than
production and cannot verify remote asset appearance.

Migration 0019 adds canonical hosted-login configuration storage. The first
canonical load projects existing branding/custom text exactly once using CAS.
Subsequent operations read the aggregate, so stale legacy fields cannot
resurrect cleared settings. Explicit existing seed `branding` and `custom_text`
sections update their owned values; omitted sections preserve API configuration,
including theme IDs and default pointers. `create_only` seed mode preserves
existing records. Canonical text also reaches verification/reset/security mail.

Memory, SQLite, PostgreSQL, MySQL and gRPC drivers implement the same clone,
transaction, CAS and cascade contract. Upgrade external storage plugins before
using these APIs: older plugins return a visible repository-unavailable error
instead of pretending settings are empty. Transaction state is additive JSON;
older transactions acquire a fresh form binding.

The pinned Node SDK and Auth0 CLI exercise the API. The pinned Deploy CLI can
round-trip nonempty branding settings, the active theme, prompts, custom text
and partials in YAML/directory exports with generated or preserved credentials.
Its branding handler requires custom-domain discovery and omits page templates
when that prerequisite is unavailable. This limitation is explicitly asserted;
no domain is fabricated and missing templates are not normalized away. ACUL
screen-renderer discovery is unavailable. See [Deploy CLI guidance](deploy-cli.md).

The tenant page-template API supersedes the earlier template-override-directory
follow-up. There is no filesystem template loading path. Evidence and local
choices are recorded in [the field inventory](../internal/brandingrules/inventory.json)
and [observation availability](compat/observations/branding-prompts.md). No live
upstream parity observation or certification is claimed.

## Custom-domain context and template export

Plan 23 adds public `custom_domain.domain` and bounded `custom_domain.metadata`
to full hosted-page templates and notification email. Private origin aliases,
proof, keys and certificate material are excluded. Synthetic preview uses an
example domain without DNS resolution. Partial templates currently do not
receive this context. ACUL remains excluded.

Template GET now returns documented `body` plus the existing `template` alias;
PUT still accepts `template`. The Deploy CLI's nonempty custom-domain inventory
prerequisite can now be satisfied by real declarations. The strict migration
lane checks nonempty template bodies; it supersedes Plan 22's historical
unavailable-template result. See [Deploy CLI migration](deploy-cli.md).

## Organization context

[Organizations](organizations.md) can override the tenant-theme logo and primary
and background colors on login, signup, consent and error pages. Other theme
settings remain tenant-level. Full page templates expose `organization.id`,
`name`, `display_name`, `metadata`, `branding.logo_url` and
`branding.colors.primary/page_background`. Individual transactions have no
organization context. The `organizations` custom-text prompt supports
`organization-selection` and `organization-picker` screens; the existing
escaping, render bounds, fallback and CSP rules apply.
