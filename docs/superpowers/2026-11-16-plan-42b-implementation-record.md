# Plan 42b implementation record

Status: **Phase A merged 2026-11-26 (PR #99)**; Phase B:
[record](2026-11-26-plan-42b-phase-b-implementation-record.md). Originally
**implemented and verified locally**, branched from
`plan-42a-my-account` (`e2c0fc07`; Plan 42a, PR #98, not yet merged).
Branch: `plan-42b-my-organization`; worktree:
`/mnt/nvme2/code/zeroauthy-plan42b`. Plan-branch CI and maintainer approval
govern integration; merge after Plan 42a.

Spec: [My Organization API design](specs/2026-11-16-zeroauthy-my-organization-api-design.md).
Plan: [Plan 42b](plans/2026-11-16-zeroauthy-plan-42b-my-organization-api.md).
Decisions: D-0220 (LR42b-1…14, MO-1…8). Operator guide:
[My Organization API](../my-organization-api.md). Contract:
`api/myorg.yaml`, from Auth0's My Organization OpenAPI 1.0.0 (SHA-256 in
D-0220), the guide and the Management OpenAPI.

Maintainer ruling (2026-11-25): build Phase A while Early Access. Phase B
(domains, identity providers, provisioning) is unblocked: Plans 36, 37a
and 37c have merged.

## Auth0's contract over the 2026-11-16 design

The guide and OpenAPI read on 2026-11-25 differ from the design: the
application carries `my_organization_configuration` (required), the
permission ceiling and self-assignment restriction are its options (off by
default), administrators' permissions are RBAC permissions through
organization roles, tokens live 600 s and the ID token lists the
administrator's permissions, and invitations need a user store. zeroauthy
follows Auth0 (LR42b-2, LR42b-4…7).

## Progress

1. Task 1: contract, contract test, D-0220, MO-1…8.
2. Task 2: `my_org.v1` store in every backend (migration 0050), RBAC on
   the My Organization API only, activation, organization-bound 600 s
   tokens with RBAC, ID token claim, client configuration in the
   Management API.
3. Task 3: `internal/myorg` router, token and membership checks, CORS.
4. Task 4: configuration, details, members, membership removal, user
   stores, log events.
5. Task 5: roles, member roles with ceiling, self-assignment and
   last-admin guards; invitations through `internal/orginvite` (extracted
   from the Management API); role visibility extension; isolation table.
6. Task 6: console, seed, `make e2e-my-org`, docs.

## Verification

Local toolchain: Go `1.27.4-X:nodwarf5`; Node 26.8.1; Chromium.

| Check | Result |
|---|---|
| Focused tests per task (ledger) | passed |
| `MyOrg` conformance on memory, SQLite, gRPC (memory, SQLite) and the plugin process | passed |
| Mutation checks | dropping the client configuration write fails `TestClientMyOrgConfiguration`; ignoring the scope for member roles fails `TestMembersRolesScope`; skipping the permission ceiling fails `TestMyOrgRoleEscalation`; skipping the last-admin guard fails `TestMyOrgLastAdmin`; not storing role visibility fails `TestRoleMyOrganizationVisible` |
| Console: Vitest 764 tests, `vue-tsc`, ESLint | passed; `console/dist` built in a clean clone |
| `make e2e-my-org` | first run: the seed refused `initiate_login_uri` (moved to setup through the Management API); then passed: setup, raw requests, Playwright 1 test (admin, member, other organization), log audit of 8 private values |
| Fast tier `TMPDIR=/dev/shm/za42b GOTMPDIR=/dev/shm/za42b go test -p 4 ./...` | passed (exit 0, 118 packages ok) |
| `api/myorg.yaml` source check | every x-source reachable |
| Final review | self-review (no reviewer subagent dispatched); added `TestMyOrgRefresh` (passed) |

## Not verified locally

PostgreSQL and MySQL (plan-branch CI), a live Auth0 tenant (MO-1…8),
invitation email delivery (the lane disables the template), and a custom
domain in the browser lane (per-host audience logic shared with Plan 42a
and covered there).

## Deferred minors

- `GET /user-stores` accepts but does not apply its filters.
- The invitation landing application is not checked for association with
  the organization.
- Member and admin-role lookups walk all roles per guarded request
  (fine for typical tenants; an index would help large ones).
