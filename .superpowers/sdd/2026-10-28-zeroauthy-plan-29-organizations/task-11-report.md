# Task 11 — Per-tenant operators

Status: DONE_WITH_CONCERNS (source-link reachability checks fail on existing RFC URLs; implementation tests pass).

Base: `46e4cb7`. Branch: `plan-29-organizations`.

Commit subject: `feat: scope operators to tenant lists`.

## Implemented

- Added `PATCH /api/system/operators/{id}` with strict `{tenants: []string}` validation. Existing tenant names, an empty list and exactly `["*"]` round-trip. Missing/null/non-array grants, unknown tenants, unknown fields and mixed wildcard lists return 400. Unknown operators return 404. The returned operator retains its creation timestamp and records its update time.
- Kept the repository's existing `/api/system/` prefix instead of the stale `/api/v2/system/` prefix in the brief. Existing per-request signed-token and stored-list checks enforce grant shrinkage immediately against old tokens.
- Added controller-authorized, read-only `GET /api/console/tenants` on the system tenant's hosts. It verifies the normal signed operator token and live operator record, intersects signed and stored grants, and filters the existing tenant DTO. Tenant-only operators can discover their own tenants while remaining forbidden from system administration endpoints. M2M/anonymous callers and ordinary tenant hosts are refused. The signed token still limits discovery after a stored grant expands.
- Serialized operator PATCH/delete and system-tenant Users API delete/block/link-as-secondary on the existing system tenant transaction read before locking users. Last-admin checks count only system-capable grants backed by an existing, unblocked user. Scoped, blocked and orphaned operator rows cannot serve as fallback administrators. A final usable administrator cannot be removed, demoted, blocked or linked away (409 `last_operator`).
- Updated the console to use filtered discovery, hide tenant creation without system tenant access, and refresh discovery after a 403. A failed refresh clears stale tenant entries. Discovery errors cannot recursively trigger another refresh; the switcher's subscription is removed when it unmounts.
- Regenerated Go Management API bindings, console OpenAPI types and the committed console production bundle. Updated D-0055 with these local wire contracts and the dedicated discovery ruling.

## Decisions and scope

The design's blanket denial of system administration access for tenant-only operators conflicts with loading the old switcher from `/api/system/tenants`. The controller explicitly selected a separate `/api/console/tenants` discovery endpoint, with no system grant exception on the old route. It also authorized extending the existing Users API guard and excluding blocked/missing users as fallback administrators.

No new store fields, migrations, RPCs, external dependencies or storage persistence implementations were needed. SQL `Tenants.Get` uses `FOR UPDATE` inside an existing transaction; memory transactions serialize. `grpcstore.clientTenants.get` forwards the transaction ID, and the server's `TenantsGet` dispatches to that transaction's same tenant repository, preserving the existing lock behavior. No new plugin lock contract was introduced.

The Go concurrency coverage exercises memory and SQLite. The new concurrency test can also run against the existing `ZA_TEST_POSTGRES_DSN` test fixture when configured; that variable was absent in this run. PostgreSQL/MySQL-specific concurrency was not run or claimed passing.

Regenerating the console schema also incorporated earlier Plan 29 organization API definitions that were already in management.yaml but absent from its previously stale generated TypeScript file. Those generated additions were kept; no generated files were edited by hand.

Clean-room inputs: supplied task brief, constraints, spec §9, D-0055, CLEAN_ROOM.md and existing repository code. No Auth0 requests or observations, proprietary pages/assets, or external identity services were used. Source checks only fetched the public provenance URLs. No subagents/reviewers were dispatched. `progress.md` was not edited.

## TDD evidence

Initial backend RED, before production changes:

`GOTOOLCHAIN=go1.26.7 go test ./internal/mgmt -run TestOperatorTenants -count=1`

Exit 1, package FAIL (1.619s). Expected behavioral failures:

- `TestOperatorTenants/round_trip_and_old_token`: `PATCH = 501` (a temporary test-only runtime bridge returned 501 while the production handler was absent; it was replaced with a direct typed handler call after implementation).
- `TestOperatorTenants/validation`: all validly constructed PATCH requests reached the missing feature (501).
- `TestOperatorTenants/last_system_admin`: PATCH 501; DELETE incorrectly returned 204 despite the only remaining operator being tenant-only.
- `TestOperatorTenants/concurrent_changes_retain_system_admin`: no PATCH success because the handler was absent.
- `TestOperatorTenantsDiscovery`: discovery returned 403 because authentication required a system grant.

Route integration RED:

`GOTOOLCHAIN=go1.26.7 go test ./internal/server -run TestOperatorTenantRoutes -count=1`

Exit 1, FAIL (0.209s): `PATCH = 404`, proving the real generated/server route was absent. An earlier compile attempt found and corrected a local variable declaration while the implementation was in progress; it is not counted as a behavioral RED.

Initial frontend RED:

`npm --prefix console test -- TenantSwitcher`

Exit 1: 2 failed, 4 passed (6 tests). `lists only allowed tenants and hides tenant creation without system access` found an extra `+ Create tenant` item; `refreshes allowed tenants after a Management API 403` still found the removed acme tenant. Earlier test-fixture mistakes (current-tenant label and query-string URL matching) were corrected and rerun before recording this behavioral RED.

Blocked fallback RED:

`GOTOOLCHAIN=go1.26.7 go test ./internal/server -run TestOperatorTenantsBlockedAlternative -count=1`

Exit 1, FAIL (0.662s). The `shrink`, `delete_operator`, `delete_user` and `block_user` subtests incorrectly succeeded (200/204) when the sole alternative administrator was blocked. Excluding blocked/missing alternative users fixed all four paths.

Failed-refresh RED:

`npm --prefix console test -- TenantSwitcher`

Exit 1: `clears stale tenants when the refresh after a 403 fails` found one stale menu item instead of zero; 6 other tests passed. Clearing the store list on discovery failure fixed it.

Focused GREEN:

- `GOTOOLCHAIN=go1.26.7 go test ./internal/mgmt ./internal/server -run 'TestOperatorTenant|TestSystemTenantUsersKeepLast' -count=1`: both PASS (mgmt 1.374s, server 1.010s), followed by expanded concurrency coverage in the full race run below.
- Final `GOTOOLCHAIN=go1.26.7 go test ./internal/mgmt -run '^TestOperatorTenants' -count=1`: PASS (1.650s).
- Final `npm --prefix console test -- TenantSwitcher`: 1 file, 7 tests PASS.

## Full verification

- `GOTOOLCHAIN=go1.26.7 go test -race ./internal/mgmt ./internal/server -count=1`: exit 0; mgmt PASS (49.358s), server PASS (70.301s), no race findings. Includes real HTTP route checks, old-token enforcement, token/stored grant intersection, usable last-admin guards and concurrent grant shrink against operator shrink/delete and user delete/block/link in memory and SQLite. An earlier run failed only because my new concurrency assertion omitted the correct 201 success for identity linking (`TestOperatorTenantsConcurrentMutations/*/link_user`); the assertion now accepts successful 2xx, and the complete race command was rerun successfully.
- `npm --prefix console test`: exit 0; **65 files, 465 tests PASS** (13.25s). The initial full run exposed 330 failures across 41 files because the shared `mountAt` fixture still matched the old discovery URL (including Application detail/API tabs and social creation). Updating that shared fixture resolved the failures; the complete suite was rerun successfully.
- `npm --prefix console run typecheck`: exit 0, repeated after the final production store change.
- `npm --prefix console run lint`: exit 0, repeated after the final production store change.
- `GOTOOLCHAIN=go1.26.7 go generate ./internal/gen/mgmtapi`: exit 0.
- `npm --prefix console run gen`: exit 0, OpenAPI TypeScript 7.13.0.
- `npm --prefix console run build`: exit 0, 908 modules, 1.06s; existing Vite warning that the JS chunk exceeds 500 kB (output 752.61 kB).
- `git diff --check`: exit 0.
- `make check-sources`: exit 2 (source script exit 1), fails on pre-existing RFC Editor source URLs (redirect/timeouts reported as `301000` and some 502 responses), during authentication.yaml, before Make can proceed to management.yaml. Examples include RFC 6749 sections 2.3.1/4.1/4.1.3/4.3/4.4/6, RFC 6750 sections 2.1/2.2, RFC 7009, RFC 7517, RFC 7636, RFC 8628 section 3.1 and RFC 9126. This is not counted as passing.
- Independently ran `./scripts/check-sources.sh api/management.yaml`: exit 1 solely on its existing `https://www.rfc-editor.org/rfc/rfc1123#section-2.1` URL (`301000`). The new operations' shared public dashboard-operator source URL returned `ok`; all other management provenance URLs returned `ok`.

## Files changed

- API source: `api/management.yaml`; generated bindings: `internal/gen/mgmtapi/mgmtapi.gen.go`, `console/src/api/schema.d.ts`.
- Backend: `internal/mgmt/system.go`, `auth.go`, `users.go`, `user_identities.go`; `internal/server/server.go`, `mgmtapi.go`.
- Backend tests: `internal/mgmt/system_operators_test.go`, `internal/server/mgmt_operators_test.go`.
- Console: `console/src/api/client.ts`, `layout/TenantSwitcher.vue`, `stores/tenants.ts`, `layout/TenantSwitcher.test.ts`, `layout/Shell.test.ts`, `test/mount.ts`; regenerated `console/dist/index.html` and hashed JavaScript asset.
- Decision/report: `docs/compat/decisions.md` and this report.

## Self-review and concerns

Reviewed the complete diff against the requirements, including wildcard/empty grants, missing fields, atomic rejection, old-token revocation, stored-expansion token limits, system endpoint denial, host/method boundaries, last usable admin preservation, consistent tenant-before-user lock order and stale-menu clearing. No implementation correctness concerns remain.

The required source-link check did not pass because existing RFC URLs are not reachable from this environment; those upstream URLs were not rewritten. The frontend build retains its existing bundle-size advisory. PostgreSQL/MySQL-specific concurrency was not executed. `system.go` was already a broad system-API handler file and is larger after this task; no unrelated restructuring was introduced.
