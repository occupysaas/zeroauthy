# Plan 46 leftovers — Versioned docs links, console translations, Android TV sample

**Date:** 2026-11-16. **Status:** design; not implemented.

**Roadmap entry:** [management roadmap, Plan 46](2026-10-19-zeroauthy-management-roadmap-design.md)
("Left: versioned docs links from the console, `govulncheck` in CI if not
added for 1.0, the Android TV sample and translations"); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **O5** (track O, independent). Read `RELEASING.md`, `docs/i18n.md`,
`docs/device-flow.md` and `AGENTS.md`. The console design direction
requires translations and a globe language menu (maintainer, 2026-10-19).

## 1. Status of the Plan 46 list (checked 2026-11-16)

| Item | State |
|---|---|
| `govulncheck` in CI | **done** (`.github/workflows/ci.yml` uses `golang/govulncheck-action`) — closed |
| Conformance gate as the release's last step | **done** (`release.yml` `conformance` job gates `binaries`, `image`, publish) — closed |
| Upgrade and rollback notes | **done** (`docs/upgrading.md` "Rolling back", per-plan sections) — closed; each later plan keeps adding its section |
| Versioned docs links from the console | open → §2 |
| Console translations beyond English | open → §3 (hosted pages already ship `en` and `fr`) |
| Android TV device-flow sample (Plan 11 follow-up) | open → §4 |

Local rulings **LR46-n** in **D-0290** (O5 block D-0290–0299).

## 2. Versioned docs links

- The server exposes its build version (already set with
  `-X main.version`) to the console through the existing system bootstrap
  response (`version` member; `dev` for unreleased builds).
- `console/src/links.ts` builds every docs link from a base:
  `https://github.com/occupysaas/zeroauthy/blob/v<version>/docs/` for a
  release version (`vX.Y.Z` or `vX.Y.Z-rc.N`), `…/blob/main/docs/` for
  `dev` (LR46-1).
- A unit test checks every link path exists in `docs/` at build time
  (catches renamed docs).
- The About panel shows the version and links to the matching
  `CHANGELOG.md` section.

## 3. Console translations

- Add **French** (`fr`) first: it matches the hosted pages' existing
  second locale, so one product-wide second language ships end to end
  (LR46-2; decision §5.1 for more languages).
- `console/src/locales/fr.ts` with every key of `en.ts`; the existing
  `parity.test.ts` enforces identical key sets and placeholder parity.
- Locale negotiation: stored choice → browser languages → `en`; the globe
  menu lists every shipped locale by its own name.
- Formatting through `Intl` (dates, numbers, relative times) with the
  active locale; no string concatenation of translated fragments (a lint
  test greps for `t(...) +`).
- A contributor guide section in `docs/i18n.md` for adding a console
  language (copy `en.ts`, translate, run the parity test).
- Translation quality: a machine-assisted first pass must be reviewed by a
  fluent speaker before release (decision §5.2); the plan marks the locale
  `beta` in the menu until reviewed (LR46-3).

## 4. Android TV device-flow sample

- `examples/android-tv/`: a minimal Kotlin Android TV app (Leanback-free,
  Compose for TV) that runs the device authorization grant against a
  zeroauthy tenant: request `/oauth/device/code`, show `user_code` and a QR
  of `verification_uri_complete`, poll `/oauth/token` honouring `interval`
  and `slow_down`, show the user's name from the ID token, refresh with
  the refresh token, log out locally.
- Plain `HttpURLConnection` + `org.json` (no Auth0 SDK dependency; Auth0's
  Android SDK has no device-flow helper we can rely on, LR46-4).
- Build: Gradle wrapper pinned; not part of CI's Go/Node jobs; a separate
  optional workflow builds the APK on changes under `examples/android-tv/`
  (decision §5.3).
- Docs: `docs/device-flow.md` "Android TV sample" section; the sample's
  README with the seed snippet for a device client.

## 5. Decisions needed from the maintainer

1. Which console languages after French (the parallel-paths brief asks
   "which languages").
2. Reviewer for the French console catalog, or ship it marked beta.
3. Whether the Android TV sample gets its own CI workflow (Android SDK in
   CI adds several minutes) or is built manually per release.

## 6. Local rulings

| ID | Ruling |
|---|---|
| LR46-1 | Release builds link to the tagged docs; `dev` links to `main`. |
| LR46-2 | French is the first console translation. |
| LR46-3 | Unreviewed locales show as beta. |
| LR46-4 | The TV sample uses no Auth0 SDK. |
