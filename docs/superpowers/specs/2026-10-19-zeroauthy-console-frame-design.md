# zeroauthy — Design: console frame, planned pages, Tailwind, Pinia and translations

Status: draft for maintainer review, 2026-10-19. Builds on the management design (`2026-10-18-zeroauthy-management-design.md`, §4.4 "The console") and on what slices 1–3 shipped in `console/`.

## 1. Intent

The maintainer wants a starting point for the console's look and UX: a frame that already holds every section the Management API program will add, so styling and interaction can be planned against real screens rather than imagined ones. Today the planned sections are greyed-out labels in the sidebar (`console/src/layout/planned.ts`). That was a stopgap to save tokens, not a design.

After this work:
- every planned section is a real, routed page;
- each page draws as much of its final UI as the Auth0 Management API and docs let us design now, with the controls disabled and a banner naming the missing API;
- sections without enough to design say "planned" and name the API;
- the console has a deliberate visual identity (the "hybrid" direction below), built on Tailwind with theme tokens so more themes can come later;
- app state lives in a Pinia store;
- strings run through vue-i18n so translations can be added as files, with a globe menu in the header.

**Success:** the maintainer can click through every section of the sidebar, see a plausible page for each, and use that to plan styling and UX. Existing pages (Applications, APIs, Connections, Operators, sign-in) keep working exactly as they do now, restyled.

## 2. Goals, non-goals, anti-goals

**Goals**
- One sidebar list drives all sections, live and planned, grouped by area.
- A page per planned section: a disabled preview, or a "planned" placeholder.
- Restyle the whole console with Tailwind v4 in the agreed look; light and dark themes.
- Pinia for shared state; vue-i18n for every user-visible string; a globe language menu.
- Bundle Glacial Indifference as the UI font.

**Non-goals**
- No new Management API endpoints. Planned pages make no API calls.
- No second language in this work. English is the only catalog; the globe menu shows it.
- No new themes beyond light and dark. The token structure makes them possible later.
- No detail pages for planned resources (e.g. a single user). List or settings pages only.
- No deployment. The maintainer first asked for a deploy to their droplet, then withdrew it (2026-10-19): leave the server alone.

**Anti-goals** (failure even if it "works")
- Planned controls that look live, or that send requests. A disabled preview must read as disabled at a glance and be inert.
- Washed-out, hard-to-read navigation. The maintainer rejected light-grey sidebar items: all items are black (light theme) and bold, planned or not.
- An Auth0 look-alike. The management design rules the look is original (management design §4.4, memory ruling 2026-10-18). Auth0 decides *which fields exist* (parity); it does not decide how they look.
- Two styling systems living side by side. Scoped CSS is replaced, not kept beside Tailwind.
- Loading fonts or CSS from third-party hosts. The console's CSP is `font-src 'self'; style-src 'self'` (`internal/server/admin.go`), and that stays.

## 3. Visual direction (decided by the maintainer)

Chosen from three mockups ("colors only", "full protest poster", "hybrid"): **hybrid**, with these changes from the maintainer:

- **Palette** from occupysaas.com: ink `#111111`, protest red `#d7141a` (hover/dark `#a50e13`). The site's off-white paper (`#f5f2eb`) is **not** used: "the off white isn't my taste".
- **Backgrounds:** white everywhere except the header, which is black (ink) with white text.
- **Sidebar:** 3px ink rule on its right edge. Every item black and bold. The active item has a red left border and a faint red tint. Planned items look the same as live ones except for a small grey "planned" tag; all are clickable.
- **Headings:** uppercase, bold, letter-spaced. The brand reads `ZERO` + `AUTHY` with `AUTHY` in red.
- **Typography:** Glacial Indifference for all UI text ("a typography font is needed like glacial indifference"). It has only regular (400) and bold (700); hierarchy comes from size, case and spacing, not weight. Monospace for IDs, paths and code stays a system mono stack.
- **Buttons:** red primary; disabled buttons are mid-grey with dark-grey text and `cursor: not-allowed`.
- **Planned banner:** white box, 2px ink border, a red uppercase label "Planned · slice N", then the API path in mono and a one-line note that the controls preview the page.
- **Dark theme:** near-black background (`#121212`), black header, light text, a lighter red (`#ff3b40`) for contrast, the sidebar rule in light text color. The maintainer approved both light and dark mockups.
- **Language menu:** a globe icon in the header ("universal language symbol"), shown now with English as the only entry.

Mockup reference: `.superpowers/brainstorm/*/content/visual-style-v3.html` (local only, not committed). Exact hex values for secondary tokens (hairlines, tag background, disabled grey) are the builder's call within this direction, subject to WCAG 2.2 AA contrast (management design §4.4).

## 4. Constraints

- Existing stack stays: Vue 3.5, Vite 8, TypeScript, vue-router 4, reka-ui (headless components), Vitest + happy-dom, ESLint, vue-tsc. `console/dist` is committed and embedded with `go:embed`; `make console` must pass (gen, lint, typecheck, test, build) and CI fails on a dist diff.
- CSP (`internal/server/admin.go`): `script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:`. Consequences: Tailwind output must be a built stylesheet (no runtime CDN); fonts are bundled assets; no inline `<style>` in `index.html`. Vue `:style` bindings set the CSSOM and are not blocked, but prefer classes.
- Sign-in stays as designed: tokens in memory only, never in localStorage, and not exposed through any store a devtools panel would show in production.
- Accessibility: keyboard reachable, visible focus, WCAG 2.2 AA. Disabled preview controls use the `disabled` attribute (or `aria-disabled` plus inert behavior where a native `disabled` isn't available) so screen readers announce them.
- Clean room (`CLEAN_ROOM.md`): fields come from Auth0's public docs and Management API reference, as for earlier slices. No copying of Auth0 dashboard markup, text or assets.
- Font license: Glacial Indifference is published by Hanken Design Co. under the SIL Open Font License (verify on download from the publisher's or Font Library's page). Ship the license text next to the font files and add an entry to `NOTICE`. If the license is not OFL or the files can't be converted to woff2, stop the font task and ask the maintainer; meanwhile the console runs on the system sans stack. Don't pick a substitute font alone (Claude's call).

## 5. How it is built (calls made in the conversation)

These were proposed by Claude and accepted by the maintainer ("sounds good").

### 5.1 Tailwind v4

- `tailwindcss` + `@tailwindcss/vite` (current: 4.3.x), CSS-first config.
- Design tokens are CSS custom properties defined per theme (`:root` for light, `:root[data-theme='dark']` and the `prefers-color-scheme: dark` guard for dark — the same three-block pattern `src/ui/base.css` uses today). Tailwind's `@theme` maps utility names (`bg-surface`, `text-ink`, `border-rule`, `bg-accent`, …) onto those variables, so a new theme is one more block of variable values and no component changes.
- All existing scoped `<style>` blocks and `base.css` component rules are converted to utilities or a small `@layer components` set (button, field, banner, tag). `base.css` is replaced by the Tailwind entry stylesheet.
- `theme.ts` keeps its behavior (system/light/dark, per-browser, may be lost) but its `Theme` type becomes a list so later themes slot in.

### 5.2 Pinia

- `pinia` (current: 3.0.x). Stores:
  - **tenants** — replaces the `Tenants` class (`src/tenants.ts`): list, loaded, error, `load`, `find`, `first`, `create`. Drives the tenant switcher and the router guard.
  - **preferences** — theme and locale, each persisted per browser with the try/catch pattern `theme.ts` uses.
  - **session** — the signed-in operator's public profile and authenticated flag, read from `Auth`. Tokens stay private inside `Auth`; the store never holds them.
- The `Services` injection (`src/context.ts`) keeps `auth` and `api`; `tenants` comes from Pinia. Test helpers (`src/test/services.ts`, `src/test/mount.ts`) install a fresh Pinia per test.
- Pages keep loading their own resource data locally, as today. Pinia is for state shared across pages, not a cache of API resources.

### 5.3 vue-i18n

- `vue-i18n` (current: 11.x), Composition API mode (`legacy: false`).
- `src/strings.ts` becomes the English message catalog (e.g. `src/locales/en.ts`); call sites move from `t.key` to `t('key')` (or `$t` in templates). Strings with values use named interpolation instead of string concatenation. Constants that are not translatable (`docsURL`, `sourceURL`, product name) move out of the catalog.
- Locale: the preferences store picks the saved choice, else the first supported entry of `navigator.languages`, else `en`. Sets `<html lang>`.
- Header gets a globe-icon menu (reka-ui dropdown) listing supported locales by their own name ("English"). Adding a language later = adding a catalog file and one list entry.
- The hosted login pages have their own i18n (Plan 4); the console catalog is separate. Sharing is out of scope.
- New planned-page strings go in the catalog too, including field labels and help text.

### 5.4 Font

- Glacial Indifference regular and bold, as `woff2` (convert from the published files if only `woff`/`otf` exist), under `src/assets/fonts/` with `@font-face` in the Tailwind entry, `font-display: swap`. Vite hashes them into `dist/assets/`, which the admin handler already serves with immutable caching.

### 5.5 Globe icon

Inline SVG component; no icon library for one icon. (Builder may add a tiny icon set later if more icons appear; not needed now.)

## 6. Sidebar and routing

### 6.1 One section list

Replace `planned.ts` and the inline `sections` array in `Shell.vue` with a single typed list (e.g. `src/layout/sections.ts`). Each entry:

```ts
interface Section {
  key: string            // also the route name
  label: string          // i18n key
  group?: string         // i18n key; undefined = top of the sidebar
  path: string           // under /t/:tenant/
  status: 'live' | { planned: string /* 'slice 4' | 'later' */, api: string[] }
  systemOnly?: boolean   // e.g. Operators: only in the reserved system tenant
}
```

Routes for every entry are generated from or checked against this list (a test asserts every section has a route and vice versa). Shipping a slice later = flip `status` to `'live'` and enable the page's controls.

### 6.2 Groups and order

| Group | Section | Path | Status |
|---|---|---|---|
| — | Home | `/` | live |
| Applications | Applications | `/applications` | live |
| | APIs | `/apis` | live |
| Authentication | Database | `/connections` | live (path unchanged; label changes from "Connections" to "Database") |
| | Social | `/social` | planned, slice 6 |
| User management | Users | `/users` | planned, slice 4 |
| | Roles | `/roles` | planned, later |
| | Organizations | `/organizations` | planned, later |
| Security | Attack protection | `/attack-protection` | planned, slice 5 |
| | Multi-factor | `/mfa` | planned, later |
| Actions | Actions | `/actions` | planned, later |
| Branding | Universal Login | `/branding` | planned, later |
| | Email templates | `/emails` | planned, later |
| | Custom domains | `/custom-domains` | planned, later |
| Monitoring | Logs | `/logs` | planned, later |
| Settings | Tenant settings | `/settings` | planned, slice 5 |
| System | Operators | `/operators` | live, system tenant only |

The "planned" tag in the sidebar shows the word only; the slice and API appear on the page's banner and in the item's `title`.

Mobile (≤720px): the sidebar collapses behind a menu button in the header rather than the current horizontal strip, since the list is now long. Builder's call on the exact pattern, keyboard and focus handling required.

## 7. Planned pages

Every planned page uses one shared layout component: group breadcrumb, uppercase title, primary action button (disabled), the planned banner, then the preview. Preview form controls are disabled and do nothing. In-page navigation (tabs, the email-template picker) stays live so every part of the preview can be seen; it changes only what is shown and sends nothing (Claude's call, from the builder check); tables show an empty state ("Users will appear here.") rather than fake rows. No requests are made from planned pages.

What each preview shows. Fields come from the named Management API resources; the builder confirms names against Auth0's public reference and may trim, but should not invent fields Auth0 doesn't have.

| Section | API | Preview |
|---|---|---|
| Users | `/api/v2/users`, `/api/v2/jobs/users-imports`, `/api/v2/tickets/password-change` | Buttons: Create user, Import users, Send reset emails. Search box (email, name, user_id). Table: name/email, connection, logins count, last login. Empty state. |
| Social | `/api/v2/connections` (social strategies) | Create connection button; provider tiles for Generic OAuth 2 / OIDC, Google, Apple, Facebook, Microsoft (slice 6 order), each disabled. |
| Roles | `/api/v2/roles` | Create role button; table: name, description. |
| Organizations | `/api/v2/organizations` | Create organization button; table: name, display name. |
| Attack protection | `/api/v2/attack-protection/*` | Three panels: Brute-force protection (enabled, max attempts, shields: block / notify user, allow list); Breached password detection (enabled, shields, admin notification frequency); Suspicious IP throttling (enabled, shields, allow list, login and signup rate limits). |
| Multi-factor | `/api/v2/guardian/*` | Factor list with toggles (one-time password, push, SMS, voice, email, WebAuthn with security keys, WebAuthn with device biometrics, recovery code); policy choice (never / always / adaptive). |
| Actions | `/api/v2/actions` | **Placeholder only.** Triggers, code editor and deploy flow need their own design. |
| Universal Login | `/api/v2/branding`, `/api/v2/prompts` | Logo URL, favicon URL, primary color, page background color (color inputs), font URL; a static, non-interactive login-box preview using those defaults is the builder's call. |
| Email templates | `/api/v2/email-templates`, `/api/v2/emails/provider` | Template picker (verify email, welcome, change password, blocked account, password breach, MFA enrollment, user invitation); fields: enabled, from, subject, result URL, URL lifetime, body (disabled textarea). Provider panel: provider choice, default from address. |
| Custom domains | `/api/v2/custom-domains` | Add domain button; table: domain, status, type (self-managed / zeroauthy-managed certs). |
| Logs | `/api/v2/logs`, `/api/v2/log-streams` | Search/filter row (type, date range); table: event type, description, date, connection, application. Log streams link as a secondary disabled button. |
| Tenant settings | `/api/v2/tenants/settings` | Tabs or sections: General (friendly name, logo URL, support email, support URL), Session (inactivity timeout, require log in after), Languages (enabled locales, default), Login (default login route / redirection URI). |

## 8. Testing

- Existing Vitest suites keep passing after the Pinia/i18n/Tailwind changes; adjust selectors that relied on scoped class names.
- New tests:
  - the section list and the router agree (every section routed, no orphan routes, system-only entries hidden outside the system tenant);
  - each planned page renders its title and banner, and every `button`, `input`, `select` and `textarea` in its preview is disabled, except in-page navigation (tabs, template picker), which is allow-listed by a marker such as `data-preview-nav`;
  - planned pages issue no API calls (a spy on the API client);
  - language: the globe menu lists English, choosing it sets `<html lang>`, and the choice persists through the preferences store;
  - theme switching still sets `data-theme`.
- `make console` passes; `console/dist` rebuilt and committed. Go tests for the admin handler unchanged.
- Visual check in a browser of light and dark, a live page and a planned page.

## 9. Deployment

Out of scope; see §2 non-goals.

## 10. Calls Claude made (for the maintainer to check)

- Tailwind replaces all existing CSS, not just new pages.
- Pinia stores: tenants, preferences, session; tokens never in a store; pages keep local resource data.
- vue-i18n, Composition API mode; locale from saved choice → browser → `en`.
- Font bundled locally as woff2 with OFL license and `NOTICE` entry.
- Inline SVG globe, no icon library.
- Sidebar groups and the "Database" label for the existing connections page (§6.2).
- Mobile sidebar becomes a menu-button drawer.
- Actions is placeholder-only; all other planned sections get previews (§7).
- Empty states in preview tables, never fake rows.

## 11. Left to the builder

- Exact secondary color values within §3, checked for AA contrast.
- Component breakdown (shared `PlannedPage`, `Panel`, `Toggle`, etc.) on top of reka-ui.
- Whether routes are generated from the section list or hand-written and checked by test.
- Trimming preview fields that turn out not to match Auth0's reference.
