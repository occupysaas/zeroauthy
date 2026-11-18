# Plan 37c — Inbound SCIM, groups, self-service SSO and directory provisioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Three phases that merge separately: (A) SCIM configuration,
tokens, the SCIM 2.0 server and directory groups with roles; (B)
self-service profiles, SSO tickets, the hosted assistant and connection
profiles; (C) Google Workspace directory provisioning.

**Architecture:** `internal/scim` (server, filter parser, mapping),
`internal/groups` (service used by SCIM, RBAC and Actions),
`internal/selfservice` (profiles, tickets, assistant handlers on the hosted
stack), `internal/dirsync` (Directory API client, sync runner on the job
queue).

**Tech Stack:** Go 1.26.10 (no new module; Google Directory API over plain
HTTPS with the Plan 24 OAuth client), Vue/TypeScript console, Playwright
1.64.0.

**Spec:** [Plan 37c design](../specs/2026-11-16-zeroauthy-scim-self-service-design.md). § refers to it.

**Depends on:** Plans 36, 37a, 37b (strategies). Phase order per ruling
§10.1 (default A → B → C).

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Parity.** LR37c-1 and Q1–Q11 in **D-0150**; follow-ups; amend D-0026
  (group roles) and D-0055 (organization groups); close Plan 38d LR38d-2.
- **Isolation.** Every SCIM request is scoped to (tenant, connection) from
  the token; tests prove cross-connection denial.
- **Never logged:** SCIM tokens, SSO tickets, Directory API credentials.
- **Migrations.** One per phase, written as `0051_scim_groups.sql`,
  `0052_self_service.sql`, `0053_directory_sync.sql`; renamed at merge.
- **Verification** per `AGENTS.md` per phase: focused tests; fast tier
  `TMPDIR=/dev/shm/za37c GOTMPDIR=/dev/shm/za37c go test -p 4 ./...` plus
  the phase's E2E; push `plan-37c-<phase>`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan37c`; record in
  `docs/superpowers/2026-11-16-plan-37c-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Token isolation:** a SCIM token of connection A reading or patching a
   user of connection B → `404`. Task A3 `TestSCIMConnectionIsolation`.
2. **Deprovisioning:** `active:false` blocks, ends sessions, revokes refresh
   tokens, enqueues back-channel logout. Task A3 `TestSCIMDeactivate`.
3. **Group roles in tokens:** adding a member to a group with a role puts the
   role's permissions in the next token; removing takes them out. Task A5
   `TestGroupRolesInTokens`.
4. **Ticket scope:** the assistant cannot enable a client outside the
   ticket's `enabled_clients` or pick a strategy outside the profile.
   Task B3 `TestAssistantScope`.

---

## Phase A — SCIM and groups

### Task A1: Contracts and decisions
- [ ] `api/management.yaml` (Phase A operations), our own `api/scim.yaml` for the SCIM server routes, `make generate`, stubs; D-0150; follow-ups; Deploy CLI handler check (Q-list) → commit `docs: freeze Plan 37c phase A contracts and D-0150`.

### Task A2: Storage
- [ ] Repositories + storetest (SCIM config, hashed tokens with 2-active limit, groups unique name per connection, members, group roles, organization group roles), migration, capability `scim.v1` → commit `feat(store): SCIM configuration, tokens and groups`.

### Task A3: SCIM server — Users
**Files:** `internal/scim/server.go`, `users.go`, `filter.go`, `mapping.go`, `errors.go`, tests, fuzz.
- [ ] Tests: RFC 7644 user examples; filters (`eq`/`and`/`or`); paging; PATCH ops; `TestSCIMConnectionIsolation` (Review Focus 1); `TestSCIMDeactivate` (Review Focus 2); delete parity with the Management API; later federated login attaches by subject only → implement → commit `feat(scim): inbound SCIM users`.

### Task A4: SCIM server — Groups and discovery endpoints
- [ ] Tests: group CRUD, member PATCH, `displayName eq`, uniqueness, only same-connection users, ServiceProviderConfig/ResourceTypes/Schemas → implement → commit `feat(scim): inbound SCIM groups`.

### Task A5: Groups Management API and RBAC
**Files:** `internal/mgmt/groups.go`, role/user/organization group routes, `internal/rbacrules` (group sources), Plan 38d effective endpoints, `internal/actions` `api.groups.*`.
- [ ] Tests: each route's scopes and shapes; `TestGroupRolesInTokens` (Review Focus 3); organization group roles; effective roles sources include groups; Actions group helpers → implement → commit `feat(mgmt): directory groups and group roles`.

### Task A6: SCIM Management routes, console, E2E
- [ ] SCIM config/tokens/default-mapping routes; console provisioning tab and groups pages; `make e2e-scim`; docs `docs/scim.md`; push phase A; review; maintainer approval.

## Phase B — Self-service SSO

### Task B1: Contracts and storage
- [ ] OpenAPI for Phase B, storage + storetest (profiles, custom text, hashed tickets with TTL and revoke, connection profiles), migration, capability → commit `feat(store): self-service profiles, tickets and connection profiles`.

### Task B2: Management routes
- [ ] Profiles CRUD, custom text, ticket create/revoke, connection profiles CRUD + templates; tests → commit `feat(mgmt): self-service profiles and SSO tickets`.

### Task B3: Hosted assistant
**Files:** `internal/selfservice/assistant.go`, templates, i18n, tests.
- [ ] Tests: each step; test login through the new connection; SCIM setup step; `TestAssistantScope` (Review Focus 4); ticket single use/expiry/revoke; branding from the profile → implement → commit `feat(selfservice): hosted SSO configuration assistant`.

### Task B4: Console, E2E, docs
- [ ] Console pages; Playwright through the assistant (SAML with the Plan 37a fixture IdP); docs `docs/self-service-sso.md`; push phase B; review; approval.

## Phase C — Directory provisioning

### Task C1: Contracts, storage, `google-apps` strategy if missing
- [ ] OpenAPI, storage, migration; `google-apps` strategy rules on the Plan 24/25 code if absent (Q1) → commit `feat: directory provisioning storage and google-apps strategy`.

### Task C2: Sync runner
**Files:** `internal/dirsync/client.go` (Directory API over HTTPS), `sync.go` (job queue, mapping, blocking removed users, selected groups), tests with a fixture Directory API.
- [ ] Tests: create/update/block; group selection; on-demand and automatic runs; status fields; failure recording → implement → commit `feat(dirsync): Google Workspace directory provisioning`.

### Task C3: Management routes, console, docs, final verification
- [ ] Routes and tests; console status; docs; push phase C; review; approval.
