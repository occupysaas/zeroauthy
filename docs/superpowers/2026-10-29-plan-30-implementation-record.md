# Plan 30 implementation record

Plan: [Organizations II](plans/2026-10-29-zeroauthy-plan-30-organizations-ii.md).
Spec: [design](specs/2026-10-29-zeroauthy-organizations-ii-design.md).
Base: `6746624`. Branch: `plan-30-organizations-ii`.
Worktree: `/mnt/nvme2/code/zeroauthy-plan-30`.

## Progress

Task 1 is in progress. Tasks 2–17 have not been implemented. The new inventory
is a contract draft, not an announcement that routes are operational. API YAML,
route-specific permission confirmation, authentication contracts, expanded EA
connection contracts and D-0056 remain before Task 1 can be marked complete.

Ruling: preserve the Plan 29 inventory and its historical deferred list; add a
separate OrganizationsII inventory — old-plugin compatibility needs the original
surface — consumers must explicitly select the newer contract inventory.

Ruling: native worktree creation failed with a local MCP transport error; use a
Git worktree fallback — isolation is still available — no runtime behavior change.

Public documentation correction: POST `/organizations/{id}/clients` returns 201
and an association array, rather than the initial test's assumed 204. Source:
https://auth0.com/docs/api/management/v2/organizations/post-organization-clients .
This was found during contract research, before any handler implementation.

The operation inventory's permission names for new client/domain resources are
provisional local choices pending scope confirmation. The documentation pages
expose bearer authorization but do not establish those scope names in the text
reviewed. Do not label those names observed or enforce them without finishing
Task 1's evidence/local-ruling audit. No live tenant observation was performed.

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
