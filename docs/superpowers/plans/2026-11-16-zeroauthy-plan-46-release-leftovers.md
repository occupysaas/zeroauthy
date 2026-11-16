# Plan 46 leftovers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Versioned console docs links, a French console catalog with
locale negotiation and formatting, and an Android TV device-flow sample;
close the Plan 46 items already done.

**Architecture:** console-only changes for §2–§3 (`console/src/links.ts`,
`i18n.ts`, `locales/fr.ts`) plus one `version` member in the system
bootstrap response; a standalone Gradle project under
`examples/android-tv/`.

**Tech Stack:** Vue/TypeScript (vue-i18n already in use), Go 1.26.10 for
the bootstrap field, Kotlin + Compose for TV with a pinned Gradle wrapper
(new toolchain only inside `examples/`; no change to the server build).

**Spec:** [Plan 46 leftovers design](../specs/2026-11-16-zeroauthy-release-leftovers-design.md). § refers to it.

**Gates:** Task 4 (TV sample CI) waits for ruling §5.3; Task 3 can ship as
beta without §5.2.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; no new Go module; no new npm
  dependency for the console (vue-i18n and `Intl` suffice). Android
  dependencies only inside `examples/android-tv/`, pinned.
- **D-0290** records LR46-1…4 and closes the three done items in the
  roadmap's Plan 46 entry.
- **Verification:** `npm --prefix console test && npm --prefix console run build`;
  `go test ./internal/server/...`; the sample builds with
  `./gradlew assembleDebug` locally; push `plan-46-release-leftovers`;
  report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan46`, branch
  `plan-46-release-leftovers`; record in
  `docs/superpowers/2026-11-16-plan-46-leftovers-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Dead links:** every console docs link resolves to an existing file in
   `docs/`. Task 2 `links.test.ts`.
2. **Catalog parity:** `fr` has exactly the `en` keys and placeholders.
   Task 3 `parity.test.ts`.
3. **Polling etiquette** in the TV sample: honours `interval`, adds 5 s on
   `slow_down`, stops on `expired_token`/`access_denied`. Task 4 unit test
   of the poller.

---

### Task 1: Decisions and roadmap

- [ ] D-0290; roadmap Plan 46 entry marks govulncheck, conformance gate and upgrade notes closed; commit `docs: D-0290 and Plan 46 status`.

### Task 2: Versioned docs links

**Files:** `internal/server/admin.go` (or the bootstrap handler: add
`version`), test; `console/src/links.ts` (base from version), `links.test.ts`
(existence check against a generated list of `docs/**/*.md` written by the
console build script), About panel.
- [ ] Tests first (release, rc and `dev` bases; all paths exist) → implement → `console/dist` → commit `feat(console): docs links follow the server version`.

### Task 3: French console catalog

**Files:** `console/src/locales/fr.ts`, `i18n.ts` (negotiation, `beta`
flag), date/number formatting helpers, the concatenation lint test,
`docs/i18n.md`.
- [ ] Tests first (parity, negotiation order, formatting per locale, lint) → translate → `console/dist` → commit `feat(console): French translation (beta)`.

### Task 4: Android TV sample

**Files:** `examples/android-tv/` (Gradle wrapper, app module, README,
poller unit tests), `docs/device-flow.md` section; optional
`.github/workflows/android-sample.yml` per ruling §5.3.
- [ ] Poller unit tests (Review Focus 3) → app → manual run against `make dev` seed with a device client → commit `docs(examples): Android TV device-flow sample`.

### Task 5: Final verification

- [ ] Console tests/build, Go tests, sample build; push `plan-46-release-leftovers`; record CI; review; maintainer approval.
