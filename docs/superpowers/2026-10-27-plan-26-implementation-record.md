# Plan 26 implementation record

Branch: `plan-26-roles-permissions`; baseline: `52d56d3` (Plan 25 merged).
Implemented, reviewed and locally verified. All ten tasks are complete; this
record reports actual results and the limits of the evidence.

| Task | State / evidence |
|---|---|
| 1 compatibility inventory | Complete, `64e5d34`. Missing inventory RED then focused inventory tests GREEN. Public-source statuses and all-of membership scopes corrected. Live upstream observations unavailable; changelog coverage not advanced past retrieval failure. |
| 2 domain/memory | Complete, `7165101`. Shared RBAC conformance RED missing interfaces → GREEN; delete/recreate-user regression RED retained membership → GREEN cleanup fix. Full memory and shared rules tests exit 0. |
| 3 SQL | Complete, `b457d81`; focused race tests on SQLite/PostgreSQL/MySQL exit 0, including pre-0022 upgrade and atomic snapshot concurrency. Full initial script hit its default 10-minute timeout during SQLite migration-heavy conformance. The pre-review rerun was superseded after concurrency fixes. The final complete post-review run with a 30-minute timeout passed all three dialects (675.179s). |
| 4 plugin/lifecycle | Complete, `f66c572`; RBAC round trip and old-plugin setting rejection RED→GREEN, gRPC memory/SQLite conformance exit 0. Startup-capability and account-link lifecycle checks pass. Whole-repository final race run exits 0. |
| 5 management/seed | Complete, `93b0ffb`; full affected-package race tests pass (mgmt 33.791s; apirules/tenantsetup/seed/server/app exit 0). Generated contracts stable twice. Existing tenants gain canonical role/member scope definitions while restricted grants and API settings are preserved. |
| 6 profiles | Complete, `150fc1b`; signed JWT and userinfo failures RED→GREEN, focused and full package race tests exit 0 before grant integration. Whole-repository final race run exits 0. |
| 7 token grants | Complete; scope/refresh assertions RED→GREEN. Endpoint matrix covers code, device, password, password-realm, refresh and M2M; focused race tests exit 0. Whole-repository final race run exits 0. |
| 8 console | Complete, `d67f3a9`; fresh `make console` exit 0: 63 files, 423 tests, lint/typecheck/generation/production build. Existing bundle-size advisory retained. |
| 9 SDK/CLI/browser/Deploy CLI | RBAC lane exit 0: pinned SDK all 16 operations, Auth0 CLI, actual Express authorization middleware, 4/4 Chromium cases. Directory-role loader defect RED→GREEN (`69a4d32`). All four YAML/directory × generated/preserved credential cells exit 0, roles 1/1, strict comparisons and post-import federated RBAC token exchange (`889ef13`). |
| 10 final regression/docs | Complete; all required local checks below passed, operator guide and compatibility/roadmap records updated. |

## Findings and decisions

- Use an in-place feature branch to preserve approved documents in the shared
  checkout. No merge or push is part of implementation.
- Current public documentation requires multiple scopes together on membership
  operations. Endpoint authorization uses all-of checks for those operations.
- Role/permission mutation status codes follow the frozen operation inventory,
  correcting the draft's generic status defaults.
- The original authorized refresh ceiling is stored before RBAC filtering,
  as explicitly selected in the approved design.
- Atomic snapshots read current API settings and rights. An issuance already
  using a snapshot may finish; no immediate JWT revocation is claimed.
- The existing operator-claim unit fixture supplied an unstored user and API.
  With current authorization reads that fixture correctly failed invalid_grant.
  Persist the fixture records to retain its intended operator-isolation check.

Live Auth0 observations: **not run**. Local fixtures are not live evidence.

## Independent review and regression fixes

Independent reviews found and verified these defects:

- MySQL outer transactions could reuse a pre-lock REPEATABLE READ view and
  reassign a deleted permission. `TestRBACNestedTransactionCurrentReads`
  reproduced stale API settings and accepted revoked permission. Public
  transactions now use READ COMMITTED on MySQL; tenant authorization locks
  serialize current reads/writes. Focused and complete three-dialect race
  verification pass.
- Concurrent resource-server PATCH requests could merge omitted fields from a
  stale object and silently undo an RBAC enable. Transactional API and role
  reads now acquire the same tenant lock before loading fields. The API
  concurrency test failed on PostgreSQL/MySQL before the fix and passes after;
  role PATCH merge behavior is also covered.
- RBAC removing every requested permission omitted response `scope`, allowing
  OAuth clients to infer the original requested scope. The response now
  explicitly includes `scope: ""`; regression RED→GREEN.
- An issuance snapshot could disable offline access after the grant's earlier
  read, yet still create a refresh token. Refresh creation now checks final
  issued scopes. Regression RED→GREEN.

The independent whole-branch reviewer found no other Critical/Important issue
in source retention, cleanup, tenant/API isolation, account linking, grant
revocation, refresh ceilings, plugin failures, token profiles, console or
migration fixtures. The complete repository race run passes after these fixes; the complete post-review SQLite/PostgreSQL/MySQL run also passed.

## Other local regression evidence

| Command | Actual result |
|---|---|
| `make e2e` | exit 0; browser 24 passed, 33 lane-gated skips |
| `make e2e-social` | exit 0; 6/6 browser cases |
| `make e2e-email-accounts` | exit 0 |
| `make e2e-domains` | exit 0 |
| Focused post-review SQL RBAC race tests | exit 0, SQLite/PostgreSQL/MySQL (30.450s) |
| `go generate ./...` twice | Stable generated Go, protobuf and TypeScript contracts; recorded during Task 5 final verification |
| `make check-sources` | exit 0 |
| `go vet ./...` | exit 0 |
| `make console` | exit 0; 423 tests, lint, typecheck and production build |
| `make e2e-rbac` | exit 0; SDK/CLI/middleware and 4/4 browser cases |
| `make e2e-deploy` | exit 0; all four format/credential cells, including post-import RBAC behavior |
| `go test -race -timeout=30m ./...` | exit 0; 67 packages ok. First broad run found obsolete pre-RBAC refusal/default/schema fixtures, now updated |
| `./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/...` | exit 0, SQLite/PostgreSQL/MySQL, 675.179s. Separate ports 55433/53307 isolated this final run from the superseded run. |
| `tests/conformance/run.sh` | exit 0, zero failed modules; result counts below. Local execution is not formal certification. |

## OpenID conformance (2026-10-27)

Results: `tests/conformance/results/20261027T163653Z` (local, ignored artifacts).

| Plan | Modules | Passed | Failed | Warning | Review | Skipped |
|---|---:|---:|---:|---:|---:|---:|
| Basic | 35 | 21 | 0 | 6 | 4 | 4 |
| Configuration | 1 | 1 | 0 | 0 | 0 | 0 |
| Form Post | 35 | 21 | 0 | 6 | 4 | 4 |
| RP-initiated logout | 11 | 3 | 0 | 0 | 8 | 0 |

## Review Focus outcomes

1. Source retention and scope deletion/recreation: shared memory/SQL/gRPC
   conformance covers direct plus two-role union, removing individual sources,
   atomic invalid batches, rollback, delete/recreate users/scopes, and reserved
   APIs. API deletion/tenant deletion remove affected edges.
2. Current issuance and refresh ceiling: actual code/device/password/realm and
   refresh endpoint matrix, with all four profiles; revocation after approval,
   initially requested but initially unassigned permission gains, never-requested
   scope exclusion, final offline-access setting, empty output scope and store
   failures all have regression assertions.
3. Isolation and account linking: same keys in another tenant stay unassigned;
   primary linking rights survive, secondary privileges are discarded and do
   not reappear on unlink. Actual federated/custom-domain browser cases pass.
4. Capability and concurrency: old plugins refuse RBAC writes/startup; failed
   snapshots release no token. Server-dialect regressions exercise current outer
   transaction reads and serialized API/role read-modify-write behavior.
5. Token consumers: actual signed profile claims/headers and userinfo tests,
   plus real Express `requiredScopes` versus explicit permissions middleware,
   SDK/CLI contracts and post-import runtime checks pass.

No review findings remain deferred. Deliberate compatibility decisions are in
D-0052 and the public-contract observations; unavailable live upstream/provider
observations remain explicitly unclaimed.
