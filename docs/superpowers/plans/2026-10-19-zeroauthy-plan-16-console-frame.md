# Console frame (Plan 16) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn every planned console section into a routed page with a disabled preview, and move the console onto Pinia, vue-i18n and Tailwind v4 in the approved "hybrid" look.

**Architecture:** Shared state moves into three Pinia stores; every string goes through a typed vue-i18n English catalog; styling becomes Tailwind utilities over theme tokens defined as CSS variables per theme. One section list (`src/layout/sections.ts`) drives the grouped sidebar and the planned routes. Planned pages share one `PlannedPage` layout and make no API calls.

**Tech Stack:** Vue 3.5, vue-router 4, reka-ui 2, Pinia 3.0.x, vue-i18n 11.x, tailwindcss + @tailwindcss/vite 4.3.x, Vitest + happy-dom, vue-tsc, ESLint.

**Spec:** `docs/superpowers/specs/2026-10-19-zeroauthy-console-frame-design.md`

## Global Constraints

- All work is in `console/` unless a task says otherwise. Every task ends with `cd console && npm run lint && npm run typecheck && npm test && npm run build` passing, and its commit includes the rebuilt `console/dist` (CI fails on a dist diff).
- CSP stays `script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:` (`internal/server/admin.go`). No CDN, no third-party font or CSS hosts, no `eval`/`new Function` in the bundle, no inline `<style>` in `index.html`.
- Tokens are never in a Pinia store, localStorage or anything devtools shows in production.
- Palette (spec §3): ink `#111111`, red `#d7141a`, red hover `#a50e13`; white backgrounds everywhere except the black header; dark background `#121212`, dark red `#ff3b40`. No off-white (`#f5f2eb` is not used).
- Sidebar items: black (light) / light text (dark), bold, planned or not. Planned items differ only by a "planned" tag.
- UI font Glacial Indifference 400 and 700 only; headings uppercase, bold, letter-spaced.
- Every user-visible string is in the English catalog; nothing is concatenated in templates.
- Planned pages: form controls disabled and inert; in-page navigation (tabs, template picker) live; tables show an empty state, never fake rows; no API calls.
- Field names on planned pages come from Auth0's public Management API reference (clean room, `CLEAN_ROOM.md`); look is original, not Auth0's.
- WCAG 2.2 AA contrast for text; keyboard reachable; visible focus.
- No deployment (spec §2).
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Catalog syntax characters.** vue-i18n treats `{ } @ $ |` as syntax. Any English string containing them (an email, a pipe, a brace in a hint) must render literally. Pinned by the parity test in Task 2, which compares every old string to its i18n rendering.
2. **CSP in the built bundle.** vue-i18n's message compiler must not use `eval`/`new Function`, and fonts/CSS must come from `dist/assets`. Pinned by `src/build.test.ts` in Task 4 (scans `dist/`).
3. **Deep links and reloads on planned routes.** `/admin/t/acme/users` loaded cold must sign in, return, and render the Users page, and `/admin/t/acme/users/x` must be not-found. Pinned by router tests in Task 7.
4. **System-only sections.** Operators must appear in the sidebar only on the `system` tenant, including after switching tenants without a reload. Pinned by the Shell test in Task 7 (both tenants mounted).
5. **Mobile drawer focus and close.** On a narrow screen the drawer must close on navigation and on Escape, and return focus to the menu button. Pinned by the Shell test in Task 7.

---

## File map

| Path | Responsibility |
|---|---|
| `src/stores/tenants.ts` | Pinia tenants store (replaces `src/tenants.ts`) |
| `src/stores/preferences.ts` | theme + locale, persisted per browser |
| `src/stores/session.ts` | operator's public profile, references `auth.user` |
| `src/i18n.ts` | `createConsoleI18n`, `Locale`, `locales`, `savedLocale`, `applyLocale` |
| `src/locales/en.ts` | English catalog (replaces `src/strings.ts`) |
| `src/links.ts` | untranslated constants: product name, docs/source URLs, home doc links |
| `src/layout/LanguageMenu.vue` | globe dropdown |
| `src/ui/GlobeIcon.vue` | inline SVG |
| `src/ui/app.css` | Tailwind entry: fonts, tokens, `@theme`, base and component layers (replaces `src/ui/base.css`) |
| `src/assets/fonts/` | `GlacialIndifference-Regular.woff2`, `-Bold.woff2`, `OFL.txt` |
| `src/layout/sections.ts` | the one section list (replaces `src/layout/planned.ts`) |
| `src/pages/planned/` | `PlannedPage.vue`, `PreviewTable.vue`, one page per planned section, `index.ts` |
| `src/ui/Tag.vue`, `src/ui/Toggle.vue` | small primitives |

---

### Task 1: Pinia stores

**Files:**
- Create: `src/stores/tenants.ts`, `src/stores/preferences.ts`, `src/stores/session.ts`, `src/stores/stores.test.ts`
- Delete: `src/tenants.ts`
- Modify: `package.json` (add `pinia`), `src/main.ts`, `src/context.ts`, `src/router.ts`, `src/router.test.ts`, `src/layout/TenantSwitcher.vue`, `src/layout/CreateTenantDialog.vue`, `src/layout/AccountMenu.vue`, `src/pages/Root.vue`, `src/pages/operators/List.vue`, `src/test/services.ts`, `src/test/mount.ts`, `src/layout/Shell.test.ts`, `src/layout/TenantSwitcher.test.ts`

**Interfaces:**
- Produces:
  - `useTenantsStore()`: state `{ list: SystemTenant[]; loaded: boolean; error: string }`; actions `load(api: Api): Promise<void>`, `find(name: string): SystemTenant | undefined`, `first(): SystemTenant | undefined`, `create(api: Api, body: TenantCreate): Promise<SystemTenant>`. Same behavior as the old class (sorted insert on create, error text on failed load, `loaded` set in `finally`).
  - `type TenantsStore = ReturnType<typeof useTenantsStore>`
  - `usePreferencesStore()`: state `{ theme: Theme; locale: string }`; actions `setTheme(t: Theme): void` (calls `applyTheme`), `setLocale(l: string): void` (no-op body until Task 2 wires `applyLocale`; stores the value).
  - `useSessionStore()`: setup store with `attach(user: { authenticated: boolean; email: string; sub: string }): void` and getters `authenticated`, `email`, `sub` reading the attached reactive object (same object as `auth.user`, so no syncing).
  - `Services` becomes `{ auth: Auth; api: Api }`. `installGuards(router, s: { auth: Pick<Auth, 'user' | 'login'>; tenants: Pick<TenantsStore, 'loaded' | 'load'>; api: Api })`.
  - Test helper: `fakeServices` returns `{ services, calls, pinia }` with a fresh `createPinia()` already `setActivePinia`'d and the tenants store usable; `mountAt` installs that pinia.

- [ ] **Step 1: Write failing tests** in `src/stores/stores.test.ts`:
  - `tenants.load` stores the list and sets `loaded`; on a 500 it sets `error` to the message and `loaded` true.
  - `tenants.create` inserts sorted: list `[b, d]` + create `c` → names `['b','c','d']`.
  - `tenants.first()` returns the first non-reserved tenant, else the system tenant.
  - `preferences.setTheme('dark')` sets `document.documentElement.dataset.theme === 'dark'` and `localStorage['zeroauthy.console.theme'] === 'dark'`.
  - `session.attach(user)` then `user.email = 'x@y.test'` → `session.email === 'x@y.test'`.
- [ ] **Step 2: Run** `cd console && npx vitest run src/stores` — expect FAIL (modules missing).
- [ ] **Step 3: Install** `npm i pinia@3.0` (exact version pinned in package.json like the others). **Implement** the three stores and move all `services.tenants` users onto `useTenantsStore()`; `main.ts` does `app.use(createPinia())`, `useSessionStore().attach(auth.user)`, and the guard receives the store and `api`. AccountMenu reads email from the session store and theme from the preferences store.
- [ ] **Step 4: Run** the full suite and typecheck — all pass, including the updated `router.test.ts` fakes (`tenants: { loaded, load }`).
- [ ] **Step 5: Build and commit** — `feat(console): Pinia stores for tenants, preferences and session`.

---

### Task 2: vue-i18n catalog

**Files:**
- Create: `src/i18n.ts`, `src/locales/en.ts`, `src/links.ts`, `src/locales/en.test.ts`, temporary `src/locales/parity.test.ts`
- Delete: `src/strings.ts` (at the end of the task, with `parity.test.ts`)
- Modify: every file importing `../strings` (41 files), `src/main.ts`, `src/stores/preferences.ts`, `src/test/mount.ts`, `src/test/services.ts`, `package.json` (add `vue-i18n`), `vite.config.ts` if a define is needed (Step 3)

**Interfaces:**
- Consumes: `usePreferencesStore` (Task 1).
- Produces:
  - `src/locales/en.ts`: `export default { … } as const`; `export type MessageSchema = typeof en`. `declare module 'vue-i18n' { export interface DefineLocaleMessage extends MessageSchema {} }` so vue-tsc checks keys.
  - `src/i18n.ts`: `export const locales = [{ code: 'en', name: 'English' }] as const`; `export type Locale = (typeof locales)[number]['code']`; `createConsoleI18n(locale: Locale): I18n` (`legacy: false`, `fallbackLocale: 'en'`, `missingWarn`/`fallbackWarn` off in production); `savedLocale(): Locale` (localStorage key `zeroauthy.console.locale`, then first supported `navigator.languages` entry by primary subtag, then `'en'`; try/catch like `theme.ts`); `applyLocale(i18n: I18n, l: Locale): void` (sets `i18n.global.locale.value`, `document.documentElement.lang`, saves).
  - `preferences.setLocale` calls `applyLocale`.
  - `src/links.ts`: `product`, `docsURL`, `sourceURL`, `homeLinks: { titleKey: string; href: string }[]`.
  - Components use `const { t } = useI18n()`; templates use `t('…')`.
  - Test helpers install `createConsoleI18n('en')` in `mountAt` and wherever components are mounted.

Conversion rules (decided here, apply everywhere):
- `${x}` in function strings → named `{x}`; call sites pass `{ x }`.
- Logic-bearing functions become split keys chosen by the caller: `apis.scopesInUse(values, grants)` → four keys `apis.scopesInUse.oneOne`, `.oneMany`, `.manyOne`, `.manyMany` (permission count × grant count), each taking `{values}` (joined with `', '` by the caller) and `{grants}`; `conns.…rateLimited(seconds?)` → `rateLimited` and `rateLimitedSeconds` (`{seconds}`).
- `Record<string, …>` maps (`apps.types`, `conns.strategies`, …) stay nested objects; call sites use template-literal keys (`t(\`apps.types.${type}.label\`)`), and a `te()` check where the key may be unknown, falling back to the raw value as today.
- Arrays of `{ title, href }` move to `links.ts` with `titleKey`.
- Literal `{ } @ $ |` in English text are escaped with literal interpolation (`{'@'}`).

- [ ] **Step 1: Write the parity test** `src/locales/parity.test.ts`: walk the old `t` from `strings.ts`; for every string leaf assert `i18n.global.t(path) === leaf` (paths mapped where the rules above moved them; a small explicit map for moved keys); for each function leaf, a table of sample args → expected old output vs the new key(s), e.g. `apps.deleteBody('Shop')` vs `t('apps.deleteBody', { name: 'Shop' })`, `apis.range(1, 20, 45)` → `'1–20 of 45'`, `rateLimited(undefined)` and `rateLimited(30)`. Also `src/locales/en.test.ts`: every leaf key in `en` renders without throwing and the output contains no unescaped `{` (catches broken syntax).
- [ ] **Step 2: Run** — FAIL (no catalog).
- [ ] **Step 3: Install** `npm i vue-i18n@11` (pin exact). Write `en.ts` from `strings.ts` by the rules; write `i18n.ts`; convert call sites. If the build contains `new Function` (checked in Task 4, but check now with `grep -l "new Function" dist/assets/*.js`), alias `vue-i18n` to its runtime-only ESM build and keep JIT compilation on per vue-i18n's CSP docs.
- [ ] **Step 4: Run** full suite + typecheck — parity and all page tests pass.
- [ ] **Step 5: Delete** `strings.ts` and `parity.test.ts`; run suite again — pass.
- [ ] **Step 6: Build and commit** — `feat(console): vue-i18n English catalog`.

---

### Task 3: Globe language menu

**Files:**
- Create: `src/ui/GlobeIcon.vue`, `src/layout/LanguageMenu.vue`, `src/layout/LanguageMenu.test.ts`
- Modify: `src/layout/Shell.vue` (header, between project links and account menu), `src/locales/en.ts` (`language: 'Language'`)

**Interfaces:**
- Consumes: `locales`, `usePreferencesStore().setLocale` (Task 2).
- Produces: `<LanguageMenu />` — reka-ui `DropdownMenu` with a trigger button `aria-label="Language"` containing `<GlobeIcon aria-hidden="true" />`, and a radio group of `locales` showing each `name`.

- [ ] **Step 1: Test:** trigger has accessible name "Language" and contains an `svg`; opening lists exactly `['English']`; selecting it sets `document.documentElement.lang === 'en'` and `localStorage['zeroauthy.console.locale'] === 'en'`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** Inline SVG globe (circle, meridian ellipse, two parallels), `currentColor`, 18px.
- [ ] **Step 4: Run** — PASS. **Step 5: Build and commit** — `feat(console): globe language menu`.

---

### Task 4: Tailwind foundation, tokens and font

**Files:**
- Create: `src/ui/app.css`, `src/assets/fonts/GlacialIndifference-Regular.woff2`, `src/assets/fonts/GlacialIndifference-Bold.woff2`, `src/assets/fonts/OFL.txt`, `src/ui/app.test.ts`, `src/build.test.ts`
- Delete: `src/ui/base.css`
- Modify: `package.json` (`tailwindcss`, `@tailwindcss/vite`), `vite.config.ts` (plugin), `src/main.ts` (import `./ui/app.css`), `src/theme.ts`, `/NOTICE` (repo root)

**Interfaces:**
- Produces Tailwind color utilities backed by runtime variables — `@theme inline { --color-<name>: var(--<name>); }` for: `bg`, `surface`, `text`, `muted`, `rule`, `hair`, `accent`, `accent-hover`, `accent-text`, `active`, `disabled`, `disabled-text`, `tag`, `header`, `header-text`, `header-chip`, `danger`, `danger-soft`, `warn-soft`, `warn-border`, `focus`. So `bg-surface`, `text-muted`, `border-rule`, … exist. Fonts: `--font-sans: 'Glacial Indifference', system-ui, sans-serif; --font-mono: ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace`.
- Component layer classes (ported from `base.css`, restyled): `card`, `muted`, `row`, `stack`, form controls (`input[type=text|number|password]`, `select`, `textarea`, `[aria-invalid=true]`), `table.data`, `overlay`, `dialog`, `menu`, `menu-item`, `menu-label`, `menu-sep`, `visually-hidden`, `mono`.
- `theme.ts`: `export const themes = ['system', 'light', 'dark'] as const; export type Theme = (typeof themes)[number]`; behavior unchanged.

Token values (three blocks, same pattern as old `base.css`: `:root`, `@media (prefers-color-scheme: dark) { :root:not([data-theme='light']) }`, `:root[data-theme='dark']`):

| token | light | dark |
|---|---|---|
| bg, surface | `#ffffff` | `#121212` |
| text | `#111111` | `#f2f2f2` |
| muted | `#5a5a5a` | `#a8a8a8` |
| rule | `#111111` | `#f2f2f2` |
| hair | `#e3e3e3` | `#2c2c2c` |
| accent | `#d7141a` | `#ff3b40` |
| accent-hover | `#a50e13` | `#ff6b6f` |
| accent-text | `#ffffff` | `#121212` (white on `#ff3b40` fails AA) |
| active | `#fdecec` | `#2a1213` |
| disabled / disabled-text | `#d6d6d6` / `#5f5f5f` | `#333333` / `#9a9a9a` |
| tag | `#f1f1f1` | `#222222` |
| header / header-text / header-chip | `#111111` / `#ffffff` / `#262626` | `#000000` / `#ffffff` / `#222222` |
| danger / danger-soft | `#b42318` / `#fdecea` | `#ff8a7f` / `#3a1714` |
| warn-soft / warn-border | `#fff4d6` / `#e5b84a` | `#3a2e10` / `#a37f22` |
| focus | `#2563eb` | `#7aa7ff` |

- [ ] **Step 1: Fetch the font.** Download Glacial Indifference from its Font Library page (`https://fontlibrary.org/en/font/glacial-indifference`) into a fresh scratch directory. Confirm the license is SIL OFL 1.1; **if not, stop and ask the maintainer** (spec §4) and continue the task with `--font-sans` set to the system stack. Convert regular and bold to woff2 (`fonttools ttLib.woff2 compress -o out.woff2 in.otf`; needs the `brotli` Python module), copy with `OFL.txt` into `src/assets/fonts/`, and add a NOTICE entry (name, author Hanken Design Co., license, path).
- [ ] **Step 2: Write failing tests.** `src/ui/app.test.ts` reads `app.css` as text and asserts: the three theme blocks exist; light `--accent: #d7141a`, `--bg: #ffffff`, dark `--bg: #121212`, `--accent: #ff3b40`; the string `f5f2eb` does not appear; no `http://` or `https://` URLs; `@font-face` for weights 400 and 700 with `font-display: swap`. `src/build.test.ts` (skips with a message if `dist/` is absent) reads `dist/index.html` and `dist/assets/*`: no `new Function(`, no `eval(`, no `<style` in `index.html`, no `fonts.googleapis`/`cdnfonts`/`http` font URLs in CSS, at least one `.woff2` in `dist/assets`.
- [ ] **Step 3: Run** — FAIL.
- [ ] **Step 4: Install** `tailwindcss@4.3 @tailwindcss/vite@4.3` (pin exact); add the plugin; write `app.css` (`@import 'tailwindcss';`, `@font-face`, tokens, `@theme inline`, `@layer base` for body/headings/links/focus ring `outline-2 outline-focus`, `@layer components` for the classes above); delete `base.css`.
- [ ] **Step 5: Build, then run** the full suite — PASS (scoped component styles still exist and use old variable names like `--border`, `--accent-soft`; keep aliases `--border: var(--hair)`, `--accent-soft: var(--active)`, `--surface-2: var(--tag)`, `--text-2: var(--muted)`, `--radius: 4px` in `app.css` until Task 6 removes the last user, so pages don't break mid-plan).
- [ ] **Step 6: Commit** — `feat(console): Tailwind v4, theme tokens and Glacial Indifference`.

---

### Task 5: Restyle shared UI, layout and simple pages

**Files:**
- Modify (remove `<style>`, use utilities/component classes): `src/ui/{Banner,Button,CodeBlock,CopyButton,Field,Modal}.vue`, `src/layout/{Shell,TenantSwitcher,AccountMenu,CreateTenantDialog}.vue`, `src/pages/{Home,Callback,NotFound,Root}.vue`
- Create: `src/ui/Tag.vue`

**Interfaces:**
- Produces: `<Button variant>` keeps its props (`primary` = `bg-accent text-accent-text hover:bg-accent-hover`, disabled = `bg-disabled text-disabled-text cursor-not-allowed`); `<Banner kind>` keeps props and adds `kind: 'planned'` (white, `border-2 border-rule`); `<Tag>` slot-only, `text-[10px] uppercase tracking-wide bg-tag text-muted rounded-sm px-1.5`.
- Shell header: `bg-header text-header-text`; brand renders `ZERO` + `<span class="text-accent">AUTHY</span>` from `links.product`, uppercase, bold, letter-spaced; tenant switcher trigger `bg-header-chip`. Sidebar markup is replaced in Task 7; restyle only the header and frame here.

- [ ] **Step 1: Restyle** each file; no behavior or markup-role changes.
- [ ] **Step 2: Run** the full suite — PASS (tests select by role/text, not scoped classes; fix any that relied on a removed class).
- [ ] **Step 3: Visual check** with `npm run dev` against a local `zeroauthy serve` (see `docs/console.md`), light and dark: header black, brand red AUTHY, body white.
- [ ] **Step 4: Build and commit** — `style(console): hybrid look for shared UI and layout`.

---

### Task 6: Restyle the resource pages

**Files:**
- Modify (remove `<style>`): all of `src/pages/applications/*.vue`, `src/pages/apis/*.vue`, `src/pages/connections/*.vue`, `src/pages/operators/List.vue`; `src/ui/app.css` (drop the temporary aliases from Task 4)
- Create: `src/ui/nostyle.test.ts`

- [ ] **Step 1: Write the failing test** `nostyle.test.ts`: glob `src/**/*.vue`; assert none contains `<style`; assert no file under `src/` contains `var(--border)`, `var(--accent-soft)`, `var(--surface-2)`, `var(--text-2)`.
- [ ] **Step 2: Run** — FAIL (lists the remaining files).
- [ ] **Step 3: Restyle** page by page; headings use the base-layer uppercase style; keep every role/label the tests and E2E use.
- [ ] **Step 4: Run** full suite — PASS.
- [ ] **Step 5: Build and commit** — `style(console): hybrid look for applications, APIs, connections and operators`.

---

### Task 7: Section list, grouped sidebar and mobile drawer

**Files:**
- Create: `src/layout/sections.ts`, `src/layout/sections.test.ts`, `src/pages/planned/index.ts`, `src/pages/planned/Placeholder.vue` (temporary target for every planned route until Task 8)
- Delete: `src/layout/planned.ts`
- Modify: `src/router.ts`, `src/router.test.ts`, `src/layout/Shell.vue`, `src/layout/Shell.test.ts`, `src/locales/en.ts`, `tests/e2e/m15-console.spec.mjs` and any other console E2E spec that clicks the "Connections" sidebar link

**Interfaces:**
- Produces (`sections.ts`):
  ```ts
  export interface Planned { planned: 'slice 4' | 'slice 5' | 'slice 6' | 'later'; api: string[] }
  export interface Section {
    key: string            // route name
    label: string          // i18n key, e.g. 'nav.users'
    group?: string         // i18n key, e.g. 'navGroup.userManagement'
    path: string           // relative to /t/:tenant/, '' for home
    status: 'live' | Planned
    systemOnly?: boolean
  }
  export const sections: Section[]
  export function isPlanned(s: Section): s is Section & { status: Planned }
  export function visibleSections(reserved: boolean): Section[]
  ```
  Entries, keys, groups, paths and statuses exactly as spec §6.2. Live keys keep today's route names (`home`, `applications`, `apis`, `connections`, `operators`). Planned keys: `social`, `users`, `roles`, `organizations`, `attack-protection`, `mfa`, `actions`, `branding`, `emails`, `custom-domains`, `logs`, `settings`. APIs per spec §7 table.
- `src/pages/planned/index.ts`: `export const plannedPages: Record<string, Component>` (all → `Placeholder` in this task).
- `router.ts` appends `sections.filter(isPlanned).map(s => ({ path: '/t/:tenant/' + s.path, name: s.key, component: plannedPages[s.key], meta: { section: s.key } }))` before the not-found route.
- Catalog: `nav.*` labels (`Database` for `connections`), `navGroup.*` (Applications, Authentication, User management, Security, Actions, Branding, Monitoring, Settings, System), `planned: 'Planned'`, `menu: 'Menu'`.

Sidebar: groups render as small uppercase muted headings; items `font-bold text-text`; active `border-l-[3px] border-accent bg-active`; planned items append `<Tag>` with `t('planned')` and `title` = slice + APIs; sidebar `border-r-[3px] border-rule`. Below `md`: sidebar hidden behind a header button (`aria-expanded`, `aria-controls`, label `Menu`); opening moves focus to the first link; Escape or a route change closes it and returns focus to the button.

- [ ] **Step 1: Write failing tests.**
  - `sections.test.ts`: every section key is a route name in `routes`; every `/t/:tenant/…` route that isn't a `-new` or `:id` route is a section; keys are unique; `visibleSections(false)` excludes `operators`, `visibleSections(true)` includes it last.
  - `router.test.ts`: unauthenticated push to `/t/acme/users` calls `login('/t/acme/users', true)`; authenticated push resolves name `users`; `/t/acme/users/x` → `not-found`.
  - `Shell.test.ts` (replace the old label test): on `/t/acme/` the sidebar's link texts (tags stripped) are `['Home','Applications','APIs','Database','Social','Users','Roles','Organizations','Attack protection','Multi-factor','Actions','Universal Login','Email templates','Custom domains','Logs','Tenant settings']`; on `/t/system/` the same plus `'Operators'`; the `Users` link contains a tag with text `Planned`; group headings in order `['Applications','Authentication','User management','Security','Actions','Branding','Monitoring','Settings']` (+ `'System'` on system); menu button toggles `aria-expanded`, Escape sets it to `false` and focuses the button, a route push closes it.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** `sections.ts`, routes, Shell sidebar and drawer; delete `planned.ts`; update E2E specs for the `Database` label.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Build and commit** — `feat(console): grouped sidebar with routed planned sections`.

---

### Task 8: PlannedPage and preview primitives

**Files:**
- Create: `src/pages/planned/PlannedPage.vue`, `src/pages/planned/PreviewTable.vue`, `src/ui/Toggle.vue`, `src/pages/planned/Actions.vue`, `src/pages/planned/planned.test.ts`, `src/pages/planned/preview.ts`
- Delete: `src/pages/planned/Placeholder.vue`
- Modify: `src/pages/planned/index.ts`, `src/locales/en.ts`

**Interfaces:**
- Consumes: `sections`, `isPlanned` (Task 7), `<Banner kind="planned">`, `<Tag>`, `<Button>` (Task 5).
- Produces:
  - `<PlannedPage section-key="users">` — looks up the section; renders a group breadcrumb (`t(section.group)`), `<h1>` `t(section.label)`, slot `actions` (header buttons), `<Banner kind="planned">` with `t('plannedBanner.label', { when })` → `Planned · slice 4` (or `Planned · later`), the APIs in `<code>`, and `t('plannedBanner.note')` = `The controls below preview the page.`; default slot = preview; when the default slot is empty, renders `t('plannedBanner.placeholder')` = `This section is planned. Its page will be designed when its API is built.`
  - `<PreviewTable :columns="string[]" :empty="string" />` — `table.data` with header cells and one row whose single cell spans all columns with the empty text.
  - `<Toggle :label :model-value :disabled />` — reka-ui `Switch` with visible label.
  - `src/pages/planned/preview.ts`: `export function assertPreviewInert(wrapper: VueWrapper): void` for tests — every `button, input, select, textarea, [role=switch]` that is **not** inside `[data-preview-nav]` is `disabled` (or `aria-disabled="true"` for reka-ui switches).
  - Actions page = `<PlannedPage section-key="actions" />` with no preview.

- [ ] **Step 1: Write failing tests** in `planned.test.ts` using `mountAt` at `/t/acme/actions`: `h1` text `Actions`; banner text contains `Planned · later` and `/api/v2/actions`; placeholder sentence present; `calls` is empty. A synthetic page with a slot containing a disabled input and a `data-preview-nav` tab button passes `assertPreviewInert`; one with an enabled input outside nav fails it.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Build and commit** — `feat(console): planned page layout and preview primitives`.

---

### Task 9: List-style planned previews

**Files:**
- Create: `src/pages/planned/{Users,Social,Roles,Organizations,CustomDomains,Logs}.vue`, `src/pages/planned/lists.test.ts`
- Modify: `src/pages/planned/index.ts`, `src/locales/en.ts` (`planned.<key>.*`)

Contents exactly per spec §7 table rows for these six. Social tiles in slice-6 order: Generic OAuth 2 / OIDC, Google, Apple, Facebook, Microsoft (each a disabled button-card). Logs: type select and date-range inputs, secondary disabled "Log streams" button.

- [ ] **Step 1: Write failing tests** — for each of the six, `mountAt('/t/acme/<path>')` then: `h1` is the section label; `assertPreviewInert(wrapper)`; `calls.length === 0`; and one content assertion each — Users column headers `['Name','Connection','Logins','Last login']` and buttons `Create user`, `Import users`, `Send reset emails`; Social tile names in the order above; Roles headers `['Name','Description']`; Organizations headers `['Name','Display name']`; Custom domains headers `['Domain','Status','Type']`; Logs headers `['Event','Description','Date','Connection','Application']`. Every table shows its empty-state text and no other rows.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Build and commit** — `feat(console): planned previews for users, social, roles, organizations, domains and logs`.

---

### Task 10: Settings-style planned previews

**Files:**
- Create: `src/pages/planned/{AttackProtection,MultiFactor,TenantSettings,Branding,Emails}.vue`, `src/pages/planned/settings.test.ts`
- Modify: `src/pages/planned/index.ts`, `src/locales/en.ts`

Contents exactly per spec §7 rows. Tenant settings tabs (General, Session, Languages, Login) and the Email templates picker are wrapped in `data-preview-nav` and switch the visible panel; reka-ui `Tabs` for the former, a listbox or radio-tab list for the latter. Branding color fields are disabled `input type="color"` with default values `#d7141a` (primary) and `#ffffff` (background); the optional static login-box preview is the builder's call (spec §11).

- [ ] **Step 1: Write failing tests** — for each of the five: `h1`, `assertPreviewInert`, `calls.length === 0`, plus — Attack protection has three panel headings `['Brute-force protection','Breached password detection','Suspicious IP throttling']`; Multi-factor lists the eight factors of spec §7 and policy options `Never`, `Always`, `Adaptive`; Tenant settings: clicking the `Session` tab shows the `Inactivity timeout` field and hides `Friendly name`, all four tabs reachable; Email templates: selecting `Welcome` changes the panel heading to `Welcome`, the seven templates of spec §7 are listed, the body is a disabled `textarea`; Branding shows the four fields of spec §7 and both color inputs disabled.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Build and commit** — `feat(console): planned previews for attack protection, MFA, tenant settings, branding and emails`.

---

### Task 11: Docs and final verification

**Files:**
- Modify: `docs/console.md` (sidebar groups, planned pages, language menu, themes, font credit), `docs/superpowers/plan-1-followups.md` ("Plan 16 follow-ups": second language, more themes, Actions design, any preview fields trimmed), `.gitignore` (add `.superpowers/`), this plan (completion note)

- [ ] **Step 1: Write the docs.**
- [ ] **Step 2: Verify:** `make console` with no `dist` diff afterwards; `go test ./internal/server/...`; `make check-sources`; `tests/e2e/run-browser.sh` console specs (m13, m14, m15) pass — or state exactly why they cannot run.
- [ ] **Step 3: Visual check** in a browser, light and dark, at desktop and 375px width: a live page (Applications), a list preview (Users), a tabbed preview (Tenant settings), the placeholder (Actions), the globe menu, the mobile drawer. Sidebar items read black and bold; no off-white anywhere.
- [ ] **Step 4: Commit** — `docs: console frame; Plan 16 records`.
