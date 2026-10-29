# Plan 30 implementation record

Plan: [Organizations II](plans/2026-10-29-zeroauthy-plan-30-organizations-ii.md).
Spec: [design](specs/2026-10-29-zeroauthy-organizations-ii-design.md).
Base: `6746624`. Branch: `plan-30-organizations-ii`.
Worktree: `/mnt/nvme2/code/zeroauthy-plan-30`.

## Progress

Task 1 is complete and controller-reviewed, including review fix `5e2ae89`.
Task 2 is submitted for controller review in this commit; Tasks 3–17 remain. The inventory
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

## Task 1 review round 1 fixes

Verified both important review findings and the client-list paging discrepancy.
JSON null appeared in nullable access-level enum arrays, causing oapi-codegen to
emit a valid string constant `<nil>` in all four create/update access validators.
Keep nullable:true and the four real string enum values; remove the null enum
entry. Regenerated output removes the invented constant, while schema validation
still accepts JSON null for the documented clear behavior.

Reverse grant organization offset responses now require start, limit, total and
organizations; checkpoint responses require organizations. With existing closed
objects, these oneOf branches are disjoint even when next is omitted on the last
page. Client-list take now structurally records default50/max100.

Actual checks:

- RED `go test ./internal/orgrules -run
  'TestOrganizationsII(NullableAccessLevels|ReverseGrantResponseValidation|ClientListTakeContract)$'
  -count=1`: FAIL for four generated `<nil>` validators, overlapping empty and
  nonempty terminal checkpoint responses, accepted partial offset objects, and
  missing client take maximum/default. Schema validation is real VisitJSON on
  parsed payloads, not merely checking schema text.
- `make generate`: PASS; inspected generated enum removal, required response
  fields, and take parameter changes. No generated file was edited by hand.
- GREEN same focused regression command: PASS. Tests assert all four legitimate
  access strings remain valid, JSON null clears are accepted, `<nil>` is rejected,
  terminal/empty/nonterminal checkpoint, offset and bare-array responses validate,
  and malformed partial objects fail validation.
- `go test ./internal/orgrules ./api -count=1`: PASS.
- `go test ./internal/mgmt -run '^$'`: PASS (compile only, no tests selected).
- `git diff --check`: PASS. No broad/database/runtime suites run for these fixes.

Controller reviewed Task 1 and its fixes clean at `5e2ae89`.


## Task 2 — transactional memory persistence submission

Implemented the full OrganizationsII model/repository contract, public aliases,
fail-closed SQL/gRPC placeholders and all store/transaction views. All five II
maps live inside memory transactional state and snapshot/restore. Input/output
metadata, roles and wrapped ticket slices are copied. Active reads use the
injected store clock; consume requires WithTx and creates one tenant-scoped,
fully bound durable receipt. Same transaction/organization/invite/user replay
is idempotent; other replay is ErrPrecondition. Failed later membership/role
writes restore the invite and remove the receipt.

Memory stores invitation, client association, client-grant association/reverse
lookup and verified discovery-domain operations with tenant/owner validation,
atomic batches, scoped paging, expiry filtering and deletion cascades. Grant
lists return original grant records, including origin and scopes; associations
never copy authority. User deletion removes both accepting receipt and retained
invite to avoid reactivation; role/forced-connection/client deletion revokes
associated invites. API/grant deletion removes org-grant edges before ID reuse.

Internal representation ruling: retain IsEnabled bool and add IsEnabledSet bool.
Legacy omitted literals create enabled links; explicit false needs the marker.
Stored/read links carry marker true, future SQL/plugin codecs must restore it,
and the marker is absent from API DTOs. Omitted replacement II fields preserve
current policy; create access defaults none/limited and explicit null maps to
none in the API layer. This additive marker resolves the indistinguishable old
zero bool / intended disabled value without breaking old callers. The shared
plan, design and D-0056 now document the same contract. Organization entitlement
defaults false; legacy grants normalize OrganizationUsage to deny and allow-any
remains false. HTTP input presence/null checks remain management work.

`PutClients` deliberately remains the proposed batch upsert: POST duplicate and
PATCH existence checks must be serialized in the caller's WithTx. PutClientGrant
is idempotent; HTTP duplicate checks use HasClientGrant in that transaction. Invitation
sort defaults created_at descending with ID ties; storage also permits ascending
and scoped checkpoints, while HTTP remains offset-only. The wrapped ticket
bundle supplies recoverable ticket_id/URL without plaintext bearer fields.

Actual verification evidence:

- Initial RED `go test ./internal/store/memory -run OrganizationsII -count=1`:
  compile FAIL for absent OrganizationInvitation and OrganizationsII methods.
- Behavioral RED same command after adding models and unavailable placeholders:
  all six required cases FAIL for unavailable persistence or missing connection
  defaults. The top-level wrapper selected real registered conformance cases.
- Expanded RED same command: accepting-user deletion made a consumed invitation
  usable again, and API deletion/recreated grant inherited old access. Fixed by
  removing the retained invite with its deleted receipt owner and cascading API
  grant edges. GREEN same command after fixes.
- Expanded RED same command: user-subject grant association incorrectly returned
  nil; now rejects ErrInvalid. GREEN after fix.
- Expanded RED same command: invitation list used ID order instead of newest
  creation first; corrected created_at ordering and validated sort. GREEN.
- `go test ./internal/store/memory -run
  'OrganizationsII|TestConformance/(Organizations|ClientGrants)$' -count=1`: PASS.
  One intermediate run exposed the old exact connection expectation's omitted
  II defaults; updated it to explicit enabled/none/limited and underlying name.
  The shared legacy grant fixture now records the required deny default.
- `go test ./internal/store/... -run '^$'`: PASS (all store backends compile;
  no runtime SQL/gRPC test selected).

Focused shared coverage includes all six named cases, reference validation,
repository CRUD/paging/copies, org/client/grant/API/role/user/tenant cascades,
transaction cascade rollback, same-receipt replay binding, simultaneous acceptors,
exact-expiry consume, and memory-only injected-clock active-read boundaries.
SQL and gRPC TestOrganizationsII wrappers are wired but runtime tests remain for
Tasks 3/4. No broad/full suite, database-backed, browser or console tests run;
none are claimed passing. Controller owns the Task 2 review and ledger state.

Final focused verification before commit:

- `go test ./internal/store/memory -run OrganizationsII -race -count=1`: PASS.
- `go test ./internal/store/... ./internal/mgmt ./internal/orglogin ./pkg/store
  ./pkg/storetest -run '^$'`: PASS (compile only, no runtime tests selected).
- `git diff --check`: PASS.

- Final reference-validation RED `go test ./internal/store/memory -run
  'TestOrganizationsII/OrganizationsII/OrganizationsIIReferenceValidation'
  -count=1`: FAIL because a cross-tenant batch owner returned ErrInvalid; changed
  it to ErrNotFound per the tenant-hiding contract. Subsequent full focused
  OrganizationsII/legacy-memory race run passed.
- Final `go test ./internal/store/memory -run
  'OrganizationsII|TestConformance/(Organizations|ClientGrants)$' -race -count=1`:
  PASS, including the added reference regression.
