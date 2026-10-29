# Plan 30 implementation record

Plan: [Organizations II](plans/2026-10-29-zeroauthy-plan-30-organizations-ii.md).
Spec: [design](specs/2026-10-29-zeroauthy-organizations-ii-design.md).
Base: `6746624`. Branch: `plan-30-organizations-ii`.
Worktree: `/mnt/nvme2/code/zeroauthy-plan-30`.

## Progress

Task 1 implementation is submitted for controller review; its ledger remains
open until that review. Tasks 2–17 have not been implemented. The inventory
freezes contracts, not operational endpoints. API YAML, individual public scope
audit, Authentication/reset context, expanded EA connection contracts and D-0056
are now included in the Task 1 submission.

Ruling: preserve the Plan 29 inventory and its historical deferred list; add a
separate OrganizationsII inventory — old-plugin compatibility needs the original
surface — consumers must explicitly select the newer contract inventory.

Ruling: native worktree creation failed with a local MCP transport error; use a
Git worktree fallback — isolation is still available — no runtime behavior change.

Public documentation correction: POST `/organizations/{id}/clients` returns 201
and an association array, rather than the initial test's assumed 204. Source:
https://auth0.com/docs/api/management/v2/organizations/post-organization-clients .
This was found during contract research, before any handler implementation.

The initial operation inventory's client/domain scopes were provisional. The
Task 1 follow-up confirmed each using the public endpoint documentation's `.md`
representation and embedded operation OpenAPI `security.oAuth2ClientCredentials`,
including separate read/create/update/delete scopes. No live tenant observation
was performed; unsupported/default/error details are explicitly local D-0056
rulings rather than claimed observations.

## Verification

- Baseline `go test ./internal/orgrules ./api -count=1`: PASS.
- RED `go test ./internal/orgrules -run TestOrganizationsIIInventory -count=1`:
  FAIL with missing contracts for all 19 enumerated new/expanded operations.
- GREEN `go test ./internal/orgrules ./api -count=1`: PASS after adding the draft
  inventory (this verifies the inventory structure, not runtime endpoints).
- No database, runtime organization II, plugin, console or browser suite has
  been run. No product implementation is claimed complete.
- Shared `InvitationTTL` validation is implemented: zero defaults to 604800 seconds,
  1–2592000 accepted, negative/over-limit and int64 overflow inputs rejected before
  duration conversion. RED failed to compile for the missing function; GREEN
  `go test ./internal/orgrules ./api -count=1` passed. HTTP decoding/handling remains
  unimplemented; fractional/null request validation is not claimed tested.


## Task 1 follow-up — contract audit submission

The II accessor now exposes 37 new/affected operations (including both authorize
methods, PAR, token, reset email/ticket, reverse grant organizations and both EA
connection resource levels). Typed scope evidence, omission/null policy and error
mappings survive accessor decoding. The original Plan 29 operations/metadata and
historical deferred list remain untouched. Public scopes were checked individually;
no SDK-only scope inference or live Auth0 observation was used.

Public corrections: invitation totals envelope has no total; domain collection
key is domains; app association POST requires explicit use_for_member_access;
organization list annotation is client:{use_for_member_access}, omitted when
absent. Search lists two OAuth scopes; the local conservative contract requires
both rather than assuming a summary-only projection. Corrected source slugs and
grant_id placeholder are recorded in the inventory and D-0056. Search documented
q/predicate/take limits and local depth/cursor rules are explicit.

D-0055's observed EA member access omission/migration default limited wins over
the draft spec's none. Explicit null locally clears either access level to none;
PATCH omission preserves. Spec and plan were corrected together. App entitlement
omits to false, grant policy to deny/false; association POST has no omitted-true
flag. Domain create accepts omitted/pending status; verified attestation uses
PATCH locally. Exact Authentication organization vs ticket organization_id naming,
PAR/resume binding and OAuth denial/revocation mappings are frozen. Scope move:
explicit-org M2M belongs to 30, quotas/headers remain 35; delegation execution
remains 42. API contracts do not announce route implementation.

Actual follow-up verification:

- RED `go test ./internal/orgrules -run TestOrganizationsIIContractAudit -count=1`:
  FAIL for absent per-operation audit fields, API paths/schemas, reset organization
  property and deferred authorize invitation description.
- RED stronger documented-shape check: FAIL because search take default was only
  in prose; represented default 50 structurally in schema, then reran successfully.
- `go test ./internal/orgrules -run 'TestOrganizationsII|TestInvitationTTL' -count=1`:
  PASS. Includes route/status completeness, typed evidence, public scopes,
  invitation TTL boundaries, invitation no-total envelope, domains key, required
  association boolean and search numeric limits.
- Final `go test ./internal/orgrules ./api -count=1`: PASS.
- `make generate`: PASS (`go generate ./...`). Inspected generated authapi and
  mgmtapi changes: new context/contract types and routes; existing EA operation
  IDs preserved. No protobuf or TypeScript output changed. One intermediate
  regeneration failed on an incorrectly indented added YAML filter parameter;
  indentation was corrected and generation plus validation rerun to PASS.
- `go test ./internal/mgmt -run '^$'`: PASS (compile only, no tests selected).
- `git diff --check`: PASS.
- Controller-reported baseline `go test ./internal/store/memory -run
  'TestConformance/Organizations' -count=1`: PASS; not rerun by Task 1 implementer.
- No database-backed tests, full Go suite, plugin/browser/console/runtime II tests
  run by this contract-only task; no such tests are claimed passing. Runtime
  implementation and its broader validation remain Tasks 2–17.

Task 1 review report: `.superpowers/sdd/2026-10-29-zeroauthy-plan-30-organizations-ii/task-1-report.md`.
