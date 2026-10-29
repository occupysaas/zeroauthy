# Task 1 submission

Completed contract implementation; controller review/ledger completion pending.

- Freeze 37 new/affected operations separately from Plan 29 with per-operation
  public scope evidence, request/response shape, null/omission, paging and errors.
- Add Management resource schemas/routes, Authentication invitation and reset
  context, grant/entitlement policy fields and expanded EA connection contracts.
- Confirm scopes from each public endpoint's embedded OpenAPI security definition.
  No live Auth0 observation; D-0056 explicitly owns unobserved local behavior.
- Correct documented draft errors: invitation no-total envelope, domains list
  key, required association boolean, client annotation shape and source slugs.
- Preserve observed D-0055 omitted/migrated member access limited; explicit null
  clears locally to none. Spec and plan updated consistently.
- Regenerate API Go outputs and preserve existing EA operation IDs.

Verification: contract-audit RED failed for missing facts/routes/schemas; stronger
shape check failed for absent structural search take default. Final focused
orgrules/API tests PASS; make generate PASS; mgmt compile-only PASS;
git diff --check PASS. An intermediate generate failed due to YAML indentation,
then corrected and rerun successfully. Actual commands/results and baseline
attribution are in the implementation record. No database/full-suite/runtime II,
plugin, console or browser suite was run or claimed passing.

Rulings/limitations: search requires both scopes listed by public OAuth security;
summary-only projection is conservatively unsupported. Domain creation verifies
only via a later administrative PATCH, not DNS lookup. No operational guide
claim or controller ledger checkbox was changed. Runtime implementation remains
subsequent tasks. Explicit-org M2M moves to Plan 30; quotas stay Plan 35 and
self-service delegation stays Plan 42.
