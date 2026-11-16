# Plan 42b — My Organization API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Phase A of Auth0's My Organization API (`/my-org/v1`): config,
details, members, memberships, invitations and member roles for
organization administrators, scoped by the token's `org_id`. Phase B
(domains, identity providers, provisioning) is a follow-on plan after
Plans 36, 37a and 37c merge (spec §5).

**Architecture:** `internal/myorg` (new) mirrors `internal/myaccount`
(router, bearer checks for the per-host `/my-org/` audience with `org_id`,
problem-style errors) and calls the Plans 29/30 services
(`internal/orgrules`, invitations, roles).

**Tech Stack:** Go 1.26.10 (no new module), Vue/TypeScript console,
Playwright 1.64.0, `@auth0/auth0-spa-js` 2.28.3 (organization login).

**Spec:** [Plan 42b design](../specs/2026-11-16-zeroauthy-my-organization-api-design.md). § refers to it.

**Gate:** ruling §8.1 (build Phase A while Early Access). **Depends on:**
Plan 42a (shared router helpers; if absent, build them here).

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Parity.** LR42b-1…3 and MO-1…8 in **D-0220**; follow-ups; record the
  pinned OpenAPI version and its SHA-256 in D-0220.
- **Contract file.** `api/myorg.yaml` (our own OpenAPI for the routes we
  serve, `x-source` per operation), generated server types.
- **Isolation.** Organization from `org_id` only; tests for every route
  with a token of another organization.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za42b GOTMPDIR=/dev/shm/za42b go test -p 4 ./...` plus
  `make e2e-my-org e2e-organizations-ii`; push `plan-42b-my-organization`;
  report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan42b`, branch
  `plan-42b-my-organization`; record in
  `docs/superpowers/2026-11-16-plan-42b-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Org isolation:** admin of organization A with a valid token cannot
   read or change organization B through any route. Task 3
   `TestMyOrgIsolation` (table over every route).
2. **Escalation:** assigning a non-assignable role or one with higher
   `my_org` permissions → `403`. Task 5 `TestMyOrgRoleEscalation`.
3. **Lockout:** removing the last admin's admin role (including self) →
   refused. Task 5 `TestMyOrgLastAdmin`.
4. **`roles` field gating** on `GET /members`. Task 4 `TestMembersRolesScope`.

---

### Task 1: Contracts, OpenAPI pin, decisions
- [ ] Re-read the newest My Organization OpenAPI; pin version and hash; write `api/myorg.yaml` (Phase A routes), `make generate`, stubs; D-0220; follow-ups → commit `docs: freeze Plan 42b contracts and D-0220`.

### Task 2: Activation and token issuance
**Files:** `internal/tenantsetup` (system resource server), `internal/oauth` (tokens for the audience need an organization; `org_id` and `my_org` scopes from organization member roles), `internal/apirules`, tests.
- [ ] Tests: activation; token without organization refused; scopes only from org member roles; client credentials refused → implement → commit `feat(myorg): activation and organization-bound tokens`.

### Task 3: Router, auth and isolation
**Files:** `internal/myorg/router.go`, `auth.go`, `problem.go`, tests.
- [ ] Tests: `TestMyOrgIsolation` (Review Focus 1); per-host audience; error shape → implement → commit `feat(myorg): router and organization-scoped auth`.

### Task 4: Config, details and members
- [ ] Tests: `/config` shape; details read/patch (OpenAPI members only); members paging, `include_totals`, `TestMembersRolesScope` (Review Focus 4); member detail; bulk delete-memberships keeps users and cleans roles → implement → commit `feat(myorg): details and members`.

### Task 5: Roles and invitations
**Files:** organization role flag "assignable through self-service" (store + Management API extension recorded as local, LR42b-2), `internal/myorg/roles.go`, `invitations.go`, tests.
- [ ] Tests: `/roles` lists assignable roles; assign/unassign; `TestMyOrgRoleEscalation` (Review Focus 2); `TestMyOrgLastAdmin` (Review Focus 3); invitation create/list/get/bulk delete/roles using Plan 30's service and email → implement → commit `feat(myorg): member roles and invitations`.

### Task 6: Console, seed, E2E, docs, final verification
- [ ] Console activation card and assignable-role marking; seed; `make e2e-my-org` (two organizations, admin and non-admin); docs (`docs/my-organization-api.md`, `docs/organizations.md`, compatibility files, `CHANGELOG.md`, roadmap, implementation record); fast tier + E2E; push; review; maintainer approval. Then open the Phase B plan once F1, F2 and F4 have merged.
