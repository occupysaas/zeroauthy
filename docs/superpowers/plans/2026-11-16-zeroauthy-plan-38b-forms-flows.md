# Plan 38b — Forms and Flows Implementation Plan (Phase 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Forms, flows, executions and core vault connections in Auth0's
JSON format; a pure-Go expression evaluator and flow engine with the core
actions; hosted form rendering; `api.prompt.render` in Actions. Vendor
integrations are a later Phase 2 plan (spec §1).

**Architecture:**
- **`internal/forms`** (new): validation (OpenAPI-derived), renderer on the
  hosted stack, form session in the transaction.
- **`internal/flows`** (new): expression evaluator, engine, core action
  implementations, executions, vault secret resolver.
- **`internal/actions`**: `api.prompt.render` and `event.prompt`.

**Tech Stack:** Go 1.26.10 (no new module), Vue/TypeScript console,
Playwright 1.64.0, auth0-deploy-cli 9.1.0.

**Spec:** [Plan 38b design](../specs/2026-11-16-zeroauthy-forms-flows-design.md). § refers to it.

**Gate:** Task 9 console scope per ruling §6.1. **Depends on:** Plan 40
(A1) for `event.prompt`.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Parity.** LR38b-1…3 and FF-1…7 in **D-0200**; follow-ups; update the
  Actions inventory (`prompt.render` supported).
- **Limits.** 50 actions, 30 s, 1 MiB vars per execution; HTML sanitizer of
  Plan 22; outbound policy for `HTTP`.
- **Never logged:** vault secrets, `PASSWORD` field values, OTP codes.
- **Migration.** One forward-only migration in three dialects written as
  `0055_forms_flows.sql`; renamed to main's latest + 1 at merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za38b GOTMPDIR=/dev/shm/za38b go test -p 4 ./...` plus
  `make e2e-forms e2e-deploy`; push `plan-38b-forms-flows`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan38b`, branch
  `plan-38b-forms-flows`; record in
  `docs/superpowers/2026-11-16-plan-38b-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Vault secrets in debug output:** an execution whose HTTP action uses a
   bearer secret → debug shows a placeholder. Task 5 `TestExecutionDebugScrub`.
2. **HTML block injection:** `<script>`, `onerror=`, `javascript:` URLs
   removed. Task 7 `TestFormHTMLSanitized`.
3. **Resume integrity:** a forged form submission for another transaction
   or a skipped step → refused; the Action resumes once. Task 8
   `TestPromptRenderResume`.
4. **Expression evaluator** cannot reach secrets or other tenants' data;
   fuzzing finds no panic. Task 4 `FuzzExpressions`.

---

### Task 1: Contracts and decisions
- [ ] `api/management.yaml` for forms, flows, executions, vault connections (schemas generated from the Auth0 OpenAPI subset with `x-source`), `make generate`, stubs; D-0200; follow-ups → commit `docs: freeze Plan 38b contracts and D-0200`.

### Task 2: Storage
- [ ] Repositories + storetest + migration + capability `forms_flows.v1` (sealed vault setup, execution retention sweep) → commit `feat(store): forms, flows, vault connections and executions`.

### Task 3: Validation and Management routes
**Files:** `internal/forms/validate.go`, `internal/flows/validate.go`, `internal/mgmt/forms.go`, `flows.go`, `flow_vault.go`, tests.
- [ ] Tests: every component and action schema (accept and refuse); vendor actions stored (LR38b-2); vault secrets write-only; CRUD and scopes → implement → commit `feat(mgmt): forms, flows and vault connections`.

### Task 4: Expressions
**Files:** `internal/flows/expr.go`, tests, `FuzzExpressions`.
- [ ] Tests: references (`fields`, `vars`, `actions.<id>`, `user`, `context`), helper functions per FF-3, type coercions, errors; `FuzzExpressions` (Review Focus 4) → implement → commit `feat(flows): expression evaluator`.

### Task 5: Engine and core actions
**Files:** `internal/flows/engine.go`, `actions_*.go`, tests with fixtures.
- [ ] Tests per core action; limits; error handling; `TestExecutionDebugScrub` (Review Focus 1); executions API reads → implement → commit `feat(flows): flow engine with core actions`.

### Task 6: Form sessions and routing
**Files:** `internal/forms/session.go`, `router.go` (STEP/FLOW/ROUTER nodes), tests.
- [ ] Tests: step navigation (next/previous/jump), routers, flow nodes between steps, ending → implement → commit `feat(forms): form sessions and node routing`.

### Task 7: Rendering
**Files:** `internal/forms/render.go`, templates, i18n (messages/translations), Plan 22 theming, CAPTCHA widget, tests.
- [ ] Tests: each field/block, validation messages per language, `TestFormHTMLSanitized` (Review Focus 2), unavailable widgets (LR38b-3) → implement → commit `feat(forms): hosted form rendering`.

### Task 8: `api.prompt.render`
**Files:** `internal/actions` (prelude + result), `internal/authz/flow.go` resume, `internal/login` form routes, tests.
- [ ] Tests: `TestPromptRenderResume` (Review Focus 3); post-login and reset-password-post-challenge; `event.prompt.fields/vars` in continue → implement → commit `feat(actions): api.prompt.render`.

### Task 9: Console, seed, Deploy CLI, E2E, docs, final verification
- [ ] Console editors and preview per ruling §6.1; seed; Deploy CLI four-cell round trip; `make e2e-forms`; docs (`docs/forms-and-flows.md`, `docs/actions.md`, compatibility files, `CHANGELOG.md`, roadmap, implementation record); fast tier + E2E; push; review; maintainer approval.
