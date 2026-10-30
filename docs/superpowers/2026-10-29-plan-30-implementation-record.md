# Plan 30 implementation record

Plan: [Organizations II](plans/2026-10-29-zeroauthy-plan-30-organizations-ii.md).
Spec: [design](specs/2026-10-29-zeroauthy-organizations-ii-design.md).
Base: `6746624`. Branch: `plan-30-organizations-ii`.
Worktree: `/mnt/nvme2/code/zeroauthy-plan-30`.

## Progress

Task 1 is complete and controller-reviewed, including review fix `5e2ae89`.
Task 2 is complete and controller-reviewed at `2caddb4`. Task 3 is complete
and controller-reviewed at `e8f48a8`, with the race-test scheduling and tenant
serialization limitations recorded below. Task 4 is complete and controller-reviewed at `60c0d29`; the minor reconnect
coverage limitation (actual backend replacement remains unverified) is retained.
Task 5 is complete and controller-reviewed. Task 6 is complete and controller-reviewed,
including sender fix `b13ad41`. Task 8 is submitted for controller review; Task 7
and Tasks 9–17 remain. The inventory
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


## Task 3 — SQL Organizations II submission

All 22 OrganizationsII storage methods now persist on SQLite, PostgreSQL and
MySQL, using existing Store/WithTx views. Migration 0026 preserves Plan 29
organizations, links, memberships, roles and grants, supplies entitlement=false,
enabled=true, connection name from the underlying connection, access none/limited,
and grant deny/false. Codecs round-trip actual enablement with IsEnabledSet=true;
omitted replacement fields preserve current policy. Wrapped invitation payloads
preserve metadata null/empty distinctions, role slices, timestamps and sealed
bytes. No plaintext bearer or URL column is introduced.

The tenant policy lock now precedes dependent reads/writes in II operations and
existing client/connection/grant/user policy operations. User deletion takes the
tenant lock before the user row. User update, password/imported-hash/version and
login-stat writes use the same order to avoid inversion when composed with policy
reads inside WithTx. Transaction policy reads hold that lock until commit.
Consumed receipt, membership and role writes use the caller's transaction only;
receipt replay is fully bound and survives explicit invitation deletion.

Integration rulings:

- New tables constrain organization, client, grant, optional forced connection,
  user and role ownership through composite tenant foreign keys. Existing Plan 29
  organization tables retain their established manual cascades; rebuilding those
  tables is unnecessary to constrain every new reference and would enlarge a
  data-preserving migration. New child FKs cascade with those existing deletes.
- Receipts deliberately have no invitation FK: invitation DELETE must preserve
  committed receipt replay. They still reference organization/user by tenant.
  The role edge uses a restrictive role FK; repository role deletion first revokes
  the whole invite, avoiding silent removal of a promised role. User deletion
  destroys its retained consumed invitation before its receipt can disappear.
- Existing standalone repository fixtures without tenant rows remain supported
  by policyRead/policyWrite; real tenants always acquire the tenant lock. II
  operations themselves require an existing tenant/owner and never use that
  compatibility exception.
- Controller ruling: AuthTransaction.Params remains the sole validated invitation
  binding authority for Task 7, so no duplicate InvitationID field/column is added.
  PasswordResetTicket.OrganizationID is added now and carried through SQL codecs;
  Task 4 must carry it through the additive plugin protocol.
- The SQL invitation clock is injectable before use, including transactional
  handles. Active reads compare the decoded precise expiry, so the nanosecond
  before expiry remains active and exact expiry does not. Explicit consume time
  remains authoritative for acceptance, with SQL receipt times at microseconds.

Actual RED/GREEN and verification:

- Initial `go test ./internal/store/sqlstore -run OrganizationsII -count=1`:
  FAIL: unavailable SQL II placeholder in every shared operation group, plus
  missing enabled/access defaults. This preceded persistence implementation.
- After persistence: same command FAIL: role deletion left a usable invite.
  Role deletion now removes the promised-role invite before removing its role.
- `go test ./internal/store/sqlstore -run OrganizationsIIResetContext -count=1`:
  compile FAIL for missing PasswordResetTicket.OrganizationID; then added the
  scalar model field, migration and SQL create/read/consume codecs.
- `go test ./internal/store/sqlstore -run OrganizationsIIReadExpiryBoundary
  -count=1`: compile FAIL for missing orgIIClock (and the still-missing reset
  field); added injected clock propagation and exact expiry comparisons.
- Named migration-from25 and first barrier race tests were added after the
  initial shared-suite RED and initial implementation. Their first run passed
  (0.244s); no named-test RED is claimed.
- `go test ./internal/store/sqlstore -run OrganizationsII -count=1`: PASS
  (1.042s), including shared suites, migration, both named races, reset and clock.
- `ZEROAUTHY_TEST_PG_PORT=55632 ZEROAUTHY_TEST_MYSQL_PORT=53506
  ./scripts/test-sql.sh -run OrganizationsII -count=1 -timeout=30m -v
  ./internal/store/sqlstore/...`: PASS (52.401s, race enabled by script).
  SQLite, PostgreSQL and MySQL shared suites, migration, races, reset and exact
  expiry each ran and passed; no configured driver skipped.
- Added reverse schedule barriers: a policy reader holds its transaction while a
  launched writer attempts a mutation with a bounded context; the writer must
  block until its deadline. Acceptance commits, then the writer succeeds. Covers
  organization/association/link/client/connection/grant/user updates and
  invitation/organization/client/user/tenant deletes. Uses no scheduling sleeps.
  `go test ./internal/store/sqlstore -run OrganizationsIIPolicyReadHoldsWriter
  -count=1`: PASS (2.361s on SQLite).
- Raw SQL composite-owner tests reject cross-tenant organization/client/grant
  references and absent user references, independently of repository validation.
- Compile-only `go test ./internal/store/... ./internal/mgmt ./internal/orglogin
  ./pkg/store ./pkg/storetest -run '^$'`: PASS; no runtime plugin tests selected.

Final covering/targeted evidence:

- Final covering command (race enabled by script):
  `ZEROAUTHY_TEST_PG_PORT=55632 ZEROAUTHY_TEST_MYSQL_PORT=53506
  ./scripts/test-sql.sh -run
  'OrganizationsII|^TestOrganizationsMigration$|^TestOrganizationsConcurrency$|^TestOrganizationMembershipSQLPolicyOrdering$|^TestRBAC'
  -count=1 -timeout=30m -v ./internal/store/sqlstore/...`.
  Actual overall result FAIL (475.803s), solely
  TestRBACNestedTransactionCurrentReads/mysql Error 1205 lock wait timeout.
  All new II groups, migration, both race schedules, reset/expiry/owner checks and
  the focused legacy wrapper passed on SQLite, PostgreSQL and MySQL. The legacy
  wrapper passed MySQL 94.77s, SQLite 181.11s, PostgreSQL 20.10s. It selects exactly
  Organizations, ClientGrants, TenantsDelete, RBAC, Clients, Connections, Users,
  UserDelete, PasswordResetTickets and AuthTransactions. Existing organization
  migration/concurrency/membership-ordering and other selected RBAC tests passed.
  No SKIP lines. Log: `task-3-all-drivers-final.log`.
- Root cause: the old MySQL stale-snapshot test established its earlier read with
  transactional Users.Get, then synchronously used the outer store for an
  independent API mutation. Users.Get now intentionally takes the tenant policy
  lock, so that independent writer correctly blocks until the outer transaction
  finishes. Replaced only that setup read with a raw nonlocking SELECT, preserving
  every original stale-snapshot/removed-permission assertion. No production code
  changed in response to this failure.
- Targeted correction verification:
  `ZEROAUTHY_TEST_PG_PORT=55632 ZEROAUTHY_TEST_MYSQL_PORT=53506
  ./scripts/test-sql.sh -run '^TestRBACNestedTransactionCurrentReads$'
  -count=1 -timeout=30m -v ./internal/store/sqlstore/...` PASS (1.946s;
  MySQL case 0.92s). This existing test is intentionally MySQL-only; no PostgreSQL/
  SQLite coverage is claimed for this targeted command. Log:
  `task-3-rbac-current-reads.log`. The large covering run was not repeated after
  this fixture-only correction; its actual failure is retained above.
- Concrete review risk: transactional client/connection/grant/user reads now hold
  the tenant policy lock until commit, serializing independent writes for that
  tenant. Callers composing an outer-store write after such a read can block, as
  the regression above demonstrated. WithTx callers must use the supplied store;
  independent reviewer should assess the wider read-lock impact. The new reverse
  race tests pin intended lock retention across acceptance and later revocation.
- Only task-specific container instances were created/removed by the script;
  shared services were left running. Both driver ports were task-specific.
- `git diff --check`: PASS before commit.

No full Go/SQL suite, browser, console or runtime plugin tests are claimed.
Controller owns Task 3 review and ledger completion.


## Task 4 — OrganizationsII storage plugin submission

Task 3 was controller-reviewed and approved with minor limitations: its reverse
writer test signals immediately before SQL entry rather than proving that the
writer has reached the SQL lock, and tenant policy locking serializes throughput
within a tenant. The original covering-run MySQL fixture failure and targeted
fixture-only correction remain recorded above; no replacement covering PASS is
claimed.

Implemented the independent version-1 OrganizationsII capability and all 22
named typed RPCs. The old Organizations capability and its RPC minimum stay at
version 1. Client and transaction views share only the capability predicate;
every II call and active II field write re-probes, so a reconnected plugin's
cached earlier success cannot authorize dropped policy. Unknown methods and
version zero are definitive unsupported answers. Transport failures remain
retryable. The server respects OrganizationsIISupporter and explicitly refuses
UnimplementedOrganizationsII backing repositories. It does not read an outer
store during capability checks, which would deadlock while a memory transaction
holds that store's lock. Custom backing stores must expose their unavailable
repository or supporter, rather than claim a functioning custom repository.

Existing organization create/update, connection create/update, client-grant
create/update, and password-reset creation reject unsupported active policy or
organization context. Legacy enabled=true and none/limited access defaults stay
compatible. Organization entitlement, optional connection enablement/presence,
connection name/access levels, grant policy, and PasswordResetTicket.OrganizationID
are additive protobuf fields. Read boundaries normalize absent old connection
enablement to true/present and absent access to none/limited. Write decoding
preserves omitted presence, so replacements retain stored policy. AuthTransaction
Params remains the sole future invitation binding; no additional field was added.

Invitations, receipts, clients and discovery domains use typed protobuf messages;
JSON bytes are limited to arbitrary invitation metadata, preserving null versus
empty objects. Errors on malformed metadata omit payload data. WrappedTicket is
opaque sealed bytes; no plaintext ticket or invitation URL field is introduced.
The existing original grant/reset full codec fixtures now include new fields,
and grant zero/empty expectations explicitly carry the documented deny default.
Public store aliases and the external plugin wrapper preserve II capability
negotiation.

Actual verification:

- Initial `go test ./internal/store/grpcstore -run OrganizationsII -count=1`
  FAIL: unavailable stub across shared operation groups, plus absent enabled/
  access defaults. This is the preimplementation behavioral RED.
- Same command after the initial implementation PASS (0.055s).
- Added capability matrix initially FAIL because its fixture used an invalid
  organization ID; corrected to a valid org_ ID. Next run FAIL because its
  positive PutClients case supplied an invalid empty batch; seeded a client and
  supplied a valid association. Corrected focused command PASS (1.286s).
  These were test-fixture corrections, not production regressions.
- An earlier combined race command selected the still-empty positive batch and
  FAIL (69.521s). It is not claimed passing.
- `go test ./internal/store/grpcstore -run '^TestClientGrantRoundTrip$' -count=1`
  FAIL on newly required full-fixture fields and old empty organization-usage
  expectations. Updated the fixtures to require/true and explicit deny defaults.
- `go test ./internal/store/grpcstore -run
  '^(TestOrganizationsII.*|TestClientGrantRoundTrip|TestPasswordResetTicketRoundTrip|TestCodecDefaultsForOldPlugins)$'
  -race -count=1` PASS (31.950s).
- `go test ./internal/store/grpcstore -run
  '^TestConformance(SQLite)?$/(Organizations|ClientGrants)$'
  -race -count=1 -timeout=5m` PASS (49.496s): original organization and client-grant
  shared suites through memory and SQLite gRPC backends.
- `go test ./internal/store/... ./pkg/store ./pkg/storeplugin ./pkg/storetest
  ./internal/mgmt ./internal/orglogin -run '^$'` PASS (compile only).
- Final focused check after the reset wire assertion and final capability-error
  handling: `go test ./internal/store/grpcstore -run
  '^(TestOrganizationsII.*|TestClientGrantRoundTrip|TestPasswordResetTicketRoundTrip|TestCodecDefaultsForOldPlugins|TestOrganizationsPluginRoundTrip|TestOrganizationsPreconditionMapping|TestOrganizationsOldPlugin|TestOrganizationsVersionZeroRefused)$'
  -race -count=1 -timeout=5m` PASS (28.229s).
- `make generate` PASS; generated protobuf outputs were not edited manually.
  A source-declaration comparison against HEAD verified all 1,146 existing
  protobuf field declarations retain type and number, with 72 additive fields.
- `git diff --check` PASS.

Matrix coverage includes no-RPC/v0, org-v1-only, II-v1, transient unavailable then
recovery, downgraded/upgraded capability on the same client, transaction views,
new protocol over an unavailable backing repository, and active old-route write
rejection. Shared memory and SQLite II conformance covers every repository group,
consume/membership/role rollback, receipt binding/replay, tenant boundaries,
cascades and sealed-byte copies. Named codec checks pass through actual protobuf
marshal/unmarshal for nil/empty/nested invitation metadata and nanosecond times;
this specific nil/empty matrix is a codec-wire test, not a separate persistence
matrix for every driver. Organization string metadata continues to use the
existing StringMap wrapper and codec; no new claim about every old plugin's
string-map behavior is made. No PostgreSQL/MySQL gRPC run, full Go/SQL suite,
external plugin process, console or browser tests were run for Task 4. Broad
release validation remains Task 17. Controller owns Task 4 review and ledger.


## Task 5 — Invitation management

Implemented scoped invitation POST/list/get/DELETE, 200 creation, strict
TTL/null/body/metadata validation and tenant-scoped reference checks before
writes. The frozen invitation list envelope contains start/limit/invitations
without total. Authorized reads recover the same ticket and URL from a
context-bound envelope; audit records contain resource IDs only. A 32-byte
crypto/rand bearer is independent of the uinv_ resource ID; SHA-256 supports
lookup. HTTPS URL construction preserves unrelated parameters and replaces
reserved parameters with URL encoding. Application login URI precedes the tenant
default; explicit notification domains and owned login-domain claims are checked.

Creation and typed durable email work share Store.WithTx. Disabled templates
and explicit send=false retain a usable invitation without queue work. Missing
queue service, corrupt provider configuration, custom provider without bindings,
and storage enqueue failures cannot leave a committed invitation. The job uses
the existing custom-email-provider trigger/lease store with a sealed
jobPayload.Kind=invitation discriminator and InvitationDelivery IDs/frozen
presentation context. The intermediate worker preserves these jobs as pending;
Task 6 must dispatch, reload active state, recover the existing ticket and render
through the existing email service. It must replace the temporary pending branch,
not introduce another queue. SMTP invitations require no Action bindings.

Prerequisite ruling authorized by controller: initiate_login_uri was previously
ignored. Added Client.InitiateLoginURI, mgmt create/update/read, clientrules,
SQL CRUD/migration 0027 for all three dialects and additive protobuf field 24.
The supported subset requires an HTTPS URI of at most 2048 bytes; omission on
PATCH preserves, explicit null rejects. This supersedes D-0039's historical
ignored-field entry only for this setting. Go/protobuf and TypeScript outputs
were regenerated. The TypeScript regeneration also synchronizes Task 1's II
contracts, which had not yet reached that output; no console runtime change.

Generated Task 1 II operations had left internal/server uncompilable (missing
AssociateOrganizationClientGrant on mgmtAPI). Embedded generated Unimplemented
for future-task routes and overrode only operational invitation methods with
frozen route scopes. Existing unkeyed constructors were converted to keyed form.
Future tasks must supply their scoped overrides before claiming those routes live.

Actual Task 5 verification:

- Initial focused mgmt/orglogin command failed compilation for absent handlers,
  BuildInvitationURL and ticket helpers (RED). Initial actions queue test failed
  compilation for missing typed payload/enqueue API (RED).
- Invalid-provider test failed behaviorally (200 instead of 503); provider
  preflight now rejects corrupt credentials and malformed transport config before
  commit. Projection test failed behaviorally because GET returned all fields;
  it now validates and applies the requested field projection.
- Intermediate checks exposed and corrected a misplaced worker branch during
  editing, EmailTemplate fixture field/signature errors, and unkeyed server
  constructors after embedding. A client PATCH test initially lacked
  update:clients in its caller fixture; corrected the test caller's scopes.
- Final `go test ./internal/mgmt ./internal/orglogin ./internal/actions
  ./internal/server -run 'OrganizationInvitation|InvitationURL|InvitationQueue'
  -race -count=1` PASS (mgmt 3.251s; others 1.021–1.081s).
- `go test ./internal/store/memory -run '^TestConformance$/^Clients$' -count=1`
  PASS; `go test ./internal/store/sqlstore -run
  '^TestConformance$/^sqlite$/^Clients$' -count=1 -v` PASS (0.491s), including
  create/update URI round trips over migration 0027.
- `go test ./internal/store/grpcstore -run '^TestClientRoundTrip$' -count=1`
  PASS; actual protobuf marshaling retains the new URI. Corrected shared command
  `go test ./internal/store/grpcstore -run
  '^TestConformance(SQLite)?$/^Clients$' -count=1 -v` PASS (0.576s), memory and
  SQLite plugin clients. Earlier optional-slash selector ran no SQL subtests;
  that invocation is not counted as SQL coverage.
- `go test ./internal/clientrules -run TestFromClientApplyRoundTrip -count=1`
  PASS. Affected mgmt/orglogin/actions/server/clientrules/store packages,
  pkg/storetest and cmd/zeroauthy compile with `go test ... -run '^$'`.
- `go generate ./proto/store/v1` and `go generate ./internal/gen/mgmtapi` PASS.
  First console `npm run gen` failed because dependencies were absent;
  `npm ci --no-audit --no-fund` then `npm run gen` PASS under Node v26.8.1.
  npm reported the existing vue-demi install-script approval warning.
- `git diff --check` PASS. No full Go suite, browser/console runtime suite,
  PostgreSQL/MySQL migration execution or external SMTP/provider send was run.
  Task 6 owns actual delivery and retry lifecycle; Task 17 owns broad release
  validation. No deferred validation is claimed passing.


### Task 5 review fix round 1 — Reject mutation query parameters

Verified the review finding against D-0056 and the route inventory: invitation
POST and DELETE declare no query parameters, while GET/list already validate
their explicit allowed keys. Added orgQuery(r) before either mutation. The scope
is confined to Task 5 invitation handlers. Updated the adapter comment to explain
the temporary generated 501 fallback and required scoped future overrides.

- RED: `go test ./internal/mgmt -run
  '^TestOrganizationInvitationMutationQueryRejected$' -count=1` FAIL (0.187s).
  All three unsupported query cases (`unknown=yes`, repeated unknown, `page=0`)
  produced POST 200 with one persisted invitation and one queued job; DELETE
  returned 204 and removed its target.
- GREEN: same command PASS (0.364s). Every rejected POST leaves zero invitations
  and zero durable jobs, and each rejected DELETE preserves its existing target.
- `go test ./internal/mgmt ./internal/orglogin ./internal/actions ./internal/server
  -run 'OrganizationInvitation|InvitationURL|InvitationQueue' -race -count=1`
  PASS (mgmt 5.036s; orglogin/actions/server 1.035–1.130s).
- `git diff --check` PASS. No new dependency installation or broad/database suite
  was performed in this fix round. The earlier vue-demi install-script warning
  remains explicitly recorded as dependency-install noise, not a clean-output
  claim or a runtime test result.


## Task 8 — Application associations and member entitlements

Task 6 controller review is complete, including provider-default-sender fix
`b13ad41`. Task 8 implements collection GET/POST/DELETE and item GET/PATCH
application associations, with the frozen organization_clients scopes also added
to the Management API scope registry. POST requires an explicit boolean and
returns a 201 array; list returns clients/optional next. Dedicated summaries
contain no credentials. Validation rejects unknown/repeated query keys, null
booleans and malformed batches; reference/duplicate/existence checks and writes
share a transaction, preserving all-or-none mutation.

Organization CRUD persists is_app_entitlement_active, defaults false and preserves
PATCH omission. The list association option adds only
client:{use_for_member_access}, omits absent associations and never filters rows.
The shared CheckMemberClient helper preserves default-false behavior on old
plugins and refuses active policy when II is unavailable. It is available for
Task 7; invitation acceptance is deliberately not implemented here.

Current policy is checked for explicit authorization, picker selection before
its 20-row bound, database login/signup, federation completion, code exchange and
refresh. Existing membership, connection enablement, third-party and client
organization checks remain required. SQL final transaction reads use the Task 3
policy lock, shared with organization and association mutations. Already signed
JWTs are unchanged. No new upstream observation or wire ruling was introduced;
these implement D-0056. A resumed database login whose bound organization policy
has been revoked follows the existing invalid-transaction hosted 400 path before
credential processing; federation completion denies authorization without adding
membership. Code/refresh revocation returns invalid_grant.

Verification from the finishing worker:

- Previous worker reported initial missing-handler/helper RED and subsequent
  focused GREEN; the finishing worker did not witness that initial RED and does
  not claim independent evidence for it. Earlier organization runs had an old
  annotation-rejection assertion, corrected to the now-invalid empty option.
- Observed `GOTOOLCHAIN=go1.26.7 go test ./internal/mgmt ./internal/orglogin
  ./internal/authz ./internal/login ./internal/oauth ./internal/federation
  ./internal/server -run Organization -race -count=1` FAIL: all runtime packages
  passed, server organization fixtures failed because organization_clients
  scopes were absent from the Management API scope registry. Added those four
  scopes; no route scope was weakened. Log: /tmp/plan30-task8-finish-race.log.
- Added database-login removal/disable/activation revocation tests and extended
  both federation-provider tests with activation after provider authorization.
  First login test expected an OAuth redirect and failed on the existing hosted
  400 invalid-transaction response. Corrected that expectation after tracing
  loadTxn/CheckOrganizationBinding; no production error mapping changed.
  The targeted route test passed after the scope fix.
- Final `GOTOOLCHAIN=go1.26.7 go test ./internal/mgmt ./internal/orglogin
  ./internal/authz ./internal/login ./internal/oauth ./internal/federation
  ./internal/server ./internal/tenantsetup -run Organization -race -count=1`
  PASS: mgmt 9.225s, orglogin 1.178s, authz 4.735s, login 14.258s,
  oauth 26.623s, server 12.920s. Federation and tenantsetup selected no tests;
  federation completion coverage runs in login's two-provider fixture.
  This includes existing organization tests and login's SQLite organization
  test selected by that name. Log: /tmp/plan30-task8-final-race.log.
- `GOTOOLCHAIN=go1.26.7 go test ./internal/tenantsetup -count=1` PASS (0.007s).
- `GOTOOLCHAIN=go1.26.7 go test ./internal/server ./cmd/zeroauthy -run '^$'`
  PASS (compile only). Log: /tmp/plan30-task8-final-compile.log.
- `git diff --check` PASS. No broad SQL driver, full Go, external plugin,
  console or browser suite was run for Task 8. Controller owns review/ledger.
