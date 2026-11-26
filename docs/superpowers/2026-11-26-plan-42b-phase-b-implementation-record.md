# Plan 42b Phase B implementation record

Status: **merged** 2026-11-26 (PR #100), from `plan-42b-phase-b`
(worktree `/mnt/nvme2/code/zeroauthy-42bB`), based on `main` after Plan 42b
Phase A merged (PR #99). Plan-branch CI and maintainer approval govern
integration.

Plan: [Plan 42b Phase B](plans/2026-11-26-zeroauthy-plan-42b-phase-b-my-organization-sso.md).
Spec: [My Organization API design](specs/2026-11-16-zeroauthy-my-organization-api-design.md)
§1 Phase B, §5. Decisions: D-0221 (LR42b-15…24, MO-9…13). Operator guide:
[My Organization API](../my-organization-api.md). Contract: `api/myorg.yaml`,
Auth0's My Organization OpenAPI 1.0.0 (unchanged since Phase A, SHA-256 in
D-0221).

Maintainer requests (2026-11-26): write the Phase B plan; start on it.

## What was built

1. Task 1: the 24 operations in the contract, every contract operation
   routed and scope-checked (`TestMyOrgRoutesContract`), 18 new system API
   scopes (30 in all) added at startup to activated APIs, D-0221 with
   Auth0's log codes from the guide's table.
2. Task 2: domains over the discovery domains, DNS TXT verification
   through the deployment's bounded resolver, 7-day claim expiry,
   takeover refusal; `my_org.v1` domain claims (migration 0051) and
   `VerifiedDomainOrganizations`; the SQL discovery-domain update now
   updates in place.
3. Task 3: `GET /config/identity-providers`, provider list/get/create
   through the Management API (`internal/mgmt/myorg_calls.go`, the
   assistant's in-process seam with a caller per surface),
   `internal/orgidp` option allowlists.
4. Task 4: provider updates by access level and profile, delete
   (`allow_if_empty`), detach, domain links, `update-attributes`.
5. Task 5: provisioning and SCIM tokens with the profile's token rules.
6. Task 6: console connection profile field, E2E (fixture DNS server,
   SCIM user created with an issued token), docs.

## Rulings beyond the plan

- 30 scopes, not the plan's 31 (its own list has 18 new).
- Scope upgrade at startup (activation answers 409 for an existing API).
- `pingfederate` cannot be created (not a sign-in strategy here).
- `domain_verification` is always `optional`: no configuration source in
  the Management API, so the plan's `required` mode and Review Focus 5 do
  not apply.
- `use_for_third_party_client_access: true` is refused (no
  connection-level third-party control).
- Domain links and provisioning writes need access level `full`.
- Final review: a connection shared with other organizations is not one
  organization's to delete or reconfigure (`403`); found in review and
  fixed with `TestIdPSharedConnection`.
- The E2E lane runs the production binary, which cannot reach a loopback
  upstream IdP; home realm discovery sign-in through an upstream IdP stays
  covered by `make e2e-enterprise-oidc`.

## Verification

Local toolchain: Go `1.27.4-X:nodwarf5`; Node 26.8.1; Chromium.

| Check | Result |
|---|---|
| Focused tests per task (ledger) | passed |
| `MyOrg` conformance on memory, SQLite, gRPC (memory, SQLite) and the plugin process | passed |
| Mutation checks | removing the domain takeover check, claim expiry, the access-none gate, the full-level gates, unlinking on domain delete, the verified-domain requirement, the SQL in-place update, the profile token maximum and scope subset each fail a test |
| Console: Vitest 764 tests, `vue-tsc`, ESLint | passed; `console/dist` built in a clean clone |
| `make e2e-my-org` | first runs: missing `node_modules`, then a SCIM fixture without `externalId`; then passed: Phase A and Phase B browser tests, log audit of 12 private values |
| Fast tier `TMPDIR=/dev/shm/za42bB GOTMPDIR=/dev/shm/za42bB go test -p 4 ./...` | 118 packages ok, 1 failure: `TestSeedMyOrganizationAPIRefusals` used `read:my_org:domains` as an unknown scope; fixed to `read:my_org:groups`, then seed, myorg and server reran green |
| `make e2e-my-org e2e-organizations-ii e2e-scim e2e-enterprise-oidc` after the review fix | all passed; `e2e-organizations-ii` first failed to launch Playwright's bundled headless Chromium (not installed locally) and passed with `E2E_CHROMIUM` set to the system Chromium |
| `make check-sources` | stops on the two known dead Plan 37c `management.yaml` URLs; `api/myorg.yaml` sources all reachable |
| Final review | self-review (no reviewer subagent dispatched) |

## Deferred minors

- Re-verifying a verified domain whose record was removed sets `failed`
  while provider links stay.
- Domain association and provider domain lookups make one in-process
  Management read per provider per request.
- A provider name conflict reveals that the connection name exists
  elsewhere in the tenant.
- `GET /user-stores` filters (Phase A) are still not applied.
