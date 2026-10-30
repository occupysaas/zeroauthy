# Plan 30 — Organizations II Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship invitations, application/grant organization enforcement, discovery,
search and the remaining scoped Plan 29 follow-ups.

**Architecture:** Extend the existing organization repositories and transactional
login policy, adding an independently negotiated OrganizationsII capability.
Reuse the email job engine and shared authorization policy; implement search with
a bounded AST evaluated identically in memory and SQL.

**Tech Stack:** Go 1.26.7, Node >=22.13, Vue/TypeScript, SQLite/PostgreSQL/MySQL,
protobuf/gRPC, existing Actions/email workers and Playwright. Keep dependency pins.

**Spec:** [Organizations II design](../specs/2026-10-29-zeroauthy-organizations-ii-design.md).
Read it before executing any task; numbered sections below refer to that document.

## Global Constraints

- Use Go 1.26.7 and Node >=22.13; retain repository dependency pins.
- Follow `CLEAN_ROOM.md`; SDK-only behavior needs documentation or firewalled
  observation. Never capture hosted Auth0 pages, secrets or personal data.
- Preserve D-0055 unless an explicit evidence-backed ruling supersedes it.
- Every new reference is tenant-scoped and every batch mutation is atomic.
- Keep Organizations capability v1 functional; negotiate OrganizationsII v1
  separately. Unsupported active II operations fail closed, never become no-ops.
- Minimal explicit-org M2M moves into 30; quotas stay in 35. No groups, SAML,
  My Organization API, default-M2M-org selection, or new search infrastructure.
- Plan 19's database hold applies only to Plan 19, not this plan.
- Add sources to API operations and regenerate outputs; don't hand-edit generated
  Go/protobuf/TypeScript. `console/dist` is a committed build artifact.
- Create an isolated implementation worktree before execution. Do not change the
  existing Plan 29 worktree. Record commits, reviews, commands and actual results
  in `docs/superpowers/2026-10-29-plan-30-implementation-record.md`.

## Review Focus

1. Two acceptors, a delete and a policy revocation racing: at most one acceptance,
   no partial roles or policy bypass. Pin in Tasks 2, 3 and 7.
2. Browser resume/PAR changes client, organization or primary connection: the
   original invitation binding must win. Pin in Task 7.
3. Older plugin or transient capability failure: retain Plan 29 functionality,
   refuse active II policy and retry transient failures. Pin in Tasks 4 and 15.
4. Same domain/sort value across tenants and cursor tampering: no cross-tenant
   discovery/search or unstable ties. Pin in Tasks 10–12.
5. Email worker restarts after send, or tenant switch resolves requests out of
   order: repeated delivery uses one ticket and stale UI cannot mutate the new
   tenant. Pin in Tasks 6 and 15.

## File boundaries and shared interfaces

Follow existing package conventions; do not introduce a generic organization
service layer. The file groups below are new unless identified as existing.

| Responsibility | Files |
| --- | --- |
| Contracts and source inventory | existing `internal/orgrules/inventory.json`, `rules.go`; new `organizations_ii_test.go`; existing API YAML |
| II models/repository and memory | `internal/store/organizations_ii.go`, `internal/store/memory/organizations_ii.go`, `pkg/storetest/organizations_ii.go`; existing Store/WithTx wiring |
| SQL persistence | `internal/store/sqlstore/organizations_ii.go`; migration 0026 in all three driver directories |
| Plugin capability and codecs | `internal/store/grpcstore/organizations_ii.go`; existing `proto/store/v1/store.proto`, client/server transaction wiring |
| Invitations | `internal/mgmt/organization_invitations.go`, `internal/orglogin/invitations.go`, `internal/email/invitations.go`; existing authz/login/Actions flows |
| Policy management | `internal/mgmt/organization_clients.go`, `organization_client_grants.go`; existing `organization_connections.go`, `client_grants.go` |
| Runtime policy | `internal/orglogin/entitlements.go`; existing authz/login/oauth organization and client-credentials files |
| Discovery | `internal/orglogin/discovery.go`, `internal/mgmt/organization_domains.go`; existing hosted identifier/org prompt |
| Search | `internal/orgsearch/{ast,parse,eval,sql,cursor}.go`, `internal/mgmt/organization_search.go`; existing SQL organizations paging |
| Reset context | existing `internal/dbconn/change_password.go`, `internal/mgmt/tickets.go`, `internal/login/reset.go`, `internal/email/context.go` |
| UI and provisioning | existing organization pages, seed/deploy migration; new tab components and Plan 30 E2Es |

Task 2 owns the common model contract. Add `Store.OrganizationsII()
OrganizationsII` to all store/transaction views, with an unavailable stub until
each driver lands. The repository is storage only; HTTP validation lives in
orgrules/mgmt and policy validation in orglogin. Its proposed method groups are:

```go
// All ctx parameters are context.Context. IDs are strings. p is store.OrgPage.
CreateInvitation(ctx, *OrganizationInvitation) error
GetInvitation(ctx, tid, orgID, id string) (*OrganizationInvitation, error)
FindInvitation(ctx, tid, ticketHash string) (*OrganizationInvitation, error)
ListInvitations(ctx, tid, orgID string, p OrgPage) (OrgResult[OrganizationInvitation], error)
DeleteInvitation(ctx, tid, orgID, id string) error
ConsumeInvitation(ctx, tid, orgID, id, transactionID, userID string, now time.Time) (InvitationReceipt, error)
GetInvitationReceipt(ctx, tid, transactionID string) (*InvitationReceipt, error)
PutClients(ctx, tid, orgID string, clients []OrganizationClient) error
GetClient(ctx, tid, orgID, clientID string) (*OrganizationClient, error)
ListClients(ctx, tid, orgID string, p OrgPage) (OrgResult[OrganizationClient], error)
DeleteClients(ctx, tid, orgID string, clientIDs []string) error
PutClientGrant(ctx, tid, orgID, grantID string) error
DeleteClientGrant(ctx, tid, orgID, grantID string) error
ListClientGrants(ctx, tid, orgID string, p OrgPage) (OrgResult[ClientGrant], error)
GrantOrganizations(ctx, tid, grantID string, p OrgPage) (OrgResult[Organization], error)
HasClientGrant(ctx, tid, orgID, grantID string) (bool, error)
PutDiscoveryDomain(ctx, *OrganizationDiscoveryDomain, create bool) error
GetDiscoveryDomain(ctx, tid, orgID, id string) (*OrganizationDiscoveryDomain, error)
GetDiscoveryDomainByName(ctx, tid, orgID, domain string) (*OrganizationDiscoveryDomain, error)
ListDiscoveryDomains(ctx, tid, orgID string, p OrgPage) (OrgResult[OrganizationDiscoveryDomain], error)
DeleteDiscoveryDomain(ctx, tid, orgID, id string) error
DiscoverOrganizations(ctx, tid, normalizedDomain string) ([]Organization, error)
```

`OrganizationInvitation` contains spec §3 fields, `TicketHash`, `WrappedTicket`,
and `ExpiresAt`; timestamps are `time.Time`, metadata `map[string]any`, roles
`[]string`. No raw ticket in storage/logs. `InvitationReceipt` contains tenant,
organization, invitation, transaction and user IDs plus accepted time.
`OrganizationClient` contains tenant/org/client IDs and `UseForMemberAccess bool`.
`OrganizationDiscoveryDomain` contains tenant/org/id/domain, status, verification
TXT/host strings and `UseForOrganizationDiscovery bool`. Extend `Organization`
with `IsAppEntitlementActive bool`; `OrganizationConnection` with `IsEnabled bool`,
`ConnectionName`, `OrganizationAccessLevel`, `OrganizationMemberAccessLevel`;
`ClientGrant` with the two §5 policy fields. Internal Go connection values also
carry `IsEnabledSet bool`: false means the old caller omitted the new field;
true means `IsEnabled` is intentional, including false. Normalize omitted values
to enabled on creation, preserve stored enablement on replacement, and return
all persisted/read values with the marker true. SQL/plugin codecs persist the
actual bool and restore the marker; never expose it in API DTOs. Empty access
strings default to none/limited on creation and preserve stored values on
replacement. HTTP explicit-null clears become explicit none (or underlying
connection name / enabled true). New internal callers disabling a connection
must set the marker. This is the smallest additive representation preserving
existing bool-based construction; a bare false cannot encode both meanings.

`ConsumeInvitation` is a conditional state transition, called only on a WithTx
view after current policy validation. It creates the receipt and hides the invite
from active reads. Same transaction/user receipt is idempotent; another transaction
gets `ErrPrecondition`. The caller adds membership/roles/metadata within that same
transaction. Use existing `ErrInvalid`, `ErrNotFound`, `ErrConflict`,
`ErrPrecondition` and new `ErrOrganizationsIIUnavailable`; define HTTP mapping
in Task 1. The repository clock is injectable for active-read expiry tests. `PutClients`
is a validated batch upsert; HTTP POST duplicate checks and PATCH existence checks
must run in the caller's WithTx. `PutClientGrant` is idempotent, so HTTP duplicate
association checks also use `HasClientGrant` in that transaction. The sealed invitation bundle carries recoverable
ticket_id and invitation_url; no plaintext bearer field is added to the model.
Invitation lists default to created_at descending with ID ties; storage also
supports ascending and scoped checkpoints (HTTP still exposes offset only).
Role/forced-connection/client deletion revokes dependent invites. Deleting an
accepting user removes its receipt and retained consumed invite together, so
receipt cleanup cannot reactivate a ticket. Grant/client/API/org deletion removes
grant associations, including before ID reuse.

Policy entry points in `internal/orglogin` (all accept context.Context):

```go
CheckMemberClient(ctx, st store.Store, tenantID, orgID, clientID string) error
CheckMachineGrant(ctx, st store.Store, tenantID string, grant *store.ClientGrant, orgID string) error
AcceptInvitation(ctx, st store.Store, in AcceptanceInput) (*store.InvitationReceipt, error)
Discover(ctx, st store.Store, tenantID, clientID, email string) ([]store.Organization, error)
```

`AcceptanceInput` has TenantID, OrganizationID, ClientID, InvitationID,
TransactionID, UserID, PrimaryConnectionID strings and Now time.Time. It accepts
trusted server transaction data only and opens WithTx itself. It reads verification
and MFA completion from the established authenticated transaction, not a client
boolean. A store read helper may be added if existing transaction access does
not expose those facts; never trust a request assertion of completion.

For each task below: write the named test(s), run the exact focused command and
observe the stated failure, implement, rerun to PASS, review the diff, then commit
only the task's files. Do not manufacture a failing test for documentation alone.
Commands are run from the implementation worktree root unless a `cd` is shown.

### Task 1: Freeze the wire contracts and compatibility decisions

**Files:** modify `internal/orgrules/inventory.json`, `internal/orgrules/rules.go`,
`api/management.yaml`, `api/authentication.yaml`, `docs/compat/decisions.md`;
create `internal/orgrules/organizations_ii_test.go` and the implementation record.

**Interfaces:** produces the route/body/paging/error contract for Tasks 5–14.
Use the documented sources in spec §2 and the references linked from them for
collection variants, scopes and password change/tickets. New code must not guess
that similarly named route families have identical scopes/envelopes.

- [ ] Write `TestOrganizationsIIInventory`: enumerate every route in spec §§3–8;
  assert source URL, permission, request/response shape, null/omission default,
  paging mode and errors are present. Assert invitation POST=200, TTL=604800/max
  2592000, search take=50/max100, q max1000 and predicates max5.
- [ ] Run `go test ./internal/orgrules -run TestOrganizationsIIInventory -count=1`;
  expect FAIL for absent contracts.
- [ ] Complete inventory/schema and D-0056, including local rulings, old-plugin
  behavior, deferred self-service access levels and the Plan 35 scope correction.
  Freeze M2M denial as OAuth `invalid_request` for malformed parameters and
  `access_denied` for a valid but forbidden organization (local if unobserved).
  Use normal `invalid_grant` for revoked code/refresh eligibility. Freeze each
  Management operation's scopes and missing-resource/error mappings individually.
  Add independently written observation notes only if needed and available;
  record remaining local choices instead of claiming observations.
- [ ] Rerun the focused test; expect PASS. Run `go test ./api -count=1`, regenerate
  with `make generate`, and inspect generated changes. Contracts may precede
  route implementation; do not mark endpoints operational in the user guide yet.
- [ ] Commit: `docs: freeze Plan 30 organization contracts`.

### Task 2: Model and implement transactional memory persistence

**Files:** create the three store/memory/storetest files in the map; modify
`internal/store/{store,types,organizations}.go`, `internal/store/memory/{memory,tx,clone}.go`
and affected driver stubs/transaction views. Extend `pkg/storetest/storetest.go` suite registration and add a top-level
`TestOrganizationsII` wrapper in each driver using `storetest.RunSuites`.
This is required so the focused `-run OrganizationsII` commands select the
shared cases rather than reporting success with no tests.

**Interfaces:** produces every model/repository method above and unavailable stub.
The memory driver is the semantic reference, including copies of metadata/slices.

- [ ] Write conformance cases `OrganizationsIIInvitationAtomicity`,
  `OrganizationsIITenantIsolation`, `OrganizationsIICascades`,
  `OrganizationsIIReceiptReplay`, `OrganizationsIIExpiration` and
  `OrganizationsIIPolicyDefaults`. Assert two acceptors yield one receipt;
  failed role mutation rolls back consumption; exact expiry is invalid; deleting
  an org removes all II rows; client/grant/role/user deletion has no dangling access.
  Domain deletion removes discovery; grant removal cannot leave HasClientGrant true.
- [ ] Run `go test ./internal/store/memory -run OrganizationsII -count=1`;
  expect FAIL for missing repository behavior (wire new cases into the suite).
- [ ] Implement models/memory transaction views, clone boundaries and cascades.
  Preserve existing client-grant origin behavior. Default old grants deny/false,
  org entitlement false, connections enabled=true, organization access none and member access limited (D-0055 observed omission/migration defaults). Explicit null resets either access level to none (D-0056). Client association POST requires use_for_member_access; PATCH omission preserves it, null is invalid.
  Keep existing literal construction safe by normalizing defaults at creation;
  don't interpret an omitted Go bool as an intentional disable on old callers.
- [ ] Rerun focused tests and `go test ./internal/store/... -run '^$'`; expect
  PASS/compile success. All backends must compile before continuing.
- [ ] Commit: `feat: add Organizations II memory persistence`.

### Task 3: SQL migration, constraints and acceptance serialization

**Files:** create `internal/store/sqlstore/organizations_ii.go` and
`internal/store/sqlstore/organizations_ii_test.go`; modify existing codec,
organization/client-grant/deletion/transaction paths. Create
`internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0026_organizations_ii.sql`
(one file in each directory; use the actual existing driver directory names).

**Interfaces:** implements Task 2 repository with existing transaction handles;
serializes membership/invitation/entitlement/grant writers on the established
Plan 29 tenant-policy lock before dependent rows.

- [ ] Write `TestOrganizationsIIMigrationFrom25` with existing org/member/role/grant
  fixtures; assert all data survives with spec defaults. Add
  `TestOrganizationsIIAcceptDeleteRace` and `TestOrganizationsIIPolicyRevocationRace`
  using barriers rather than sleeps; rollback leaves no receipt or membership.
- [ ] Run `go test ./internal/store/sqlstore -run OrganizationsII -count=1`;
  expect FAIL until SQLite persistence/migration is implemented.
- [ ] Implement parameterized queries, composite ownership constraints, cleanup
  and indexes. Keep the validated invitation binding in existing AuthTransaction.Params (no
  duplicate authority); carry PasswordResetTicket.OrganizationID through SQL
  reset codecs and the later plugin protocol.
  Apply policy lock ordering consistently to pre-existing deletion/update paths.
- [ ] Run focused SQLite tests, then
  `./scripts/test-sql.sh -run OrganizationsII -count=1 ./internal/store/sqlstore/...`;
  expect PASS on SQLite, PostgreSQL and MySQL, with no skipped configured driver.
  Inspect the script's port options and use free task-specific ports; leave shared
  services running. Record each driver's actual result.
- [ ] Commit: `feat: persist Organizations II across SQL stores`.

### Task 4: Negotiate OrganizationsII without breaking v1 plugins

**Files:** create `internal/store/grpcstore/organizations_ii.go` and its test;
modify `proto/store/v1/store.proto`, existing grpcstore client/server/transaction
wiring and generated outputs through `make generate`.

**Interfaces:** `OrganizationsIISupporter` exposes
`CheckOrganizationsIISupport(context.Context) error` and
`OrganizationsIISupported() bool`; the separate capability RPC returns version 1.
Implement all Task 2 methods and transaction handles without changing v1 minimum.

- [ ] Write `TestOrganizationsIICapabilities` with v0, org-v1-only, II-v1, transient
  unavailable then recovery, and transaction client cases. Assert v1 organization
  reads still work; II mutations fail unavailable; no field is silently discarded.
  Write `TestOrganizationsIIPluginRollback` and round-trip tests for nil/empty
  metadata, timestamps, disabled connection, grant policy and sealed ticket bytes.
- [ ] Run `go test ./internal/store/grpcstore -run OrganizationsII -count=1`;
  expect FAIL for absent RPC/capability behavior.
- [ ] Add additive proto fields/RPCs and codecs, capability checks and server
  forwarding. Keep unknown-method failures definitive, transport failures retryable.
  Do not serialize private plaintext tickets or expose them through diagnostics.
- [ ] Run `make generate` then the focused command and grpcstore conformance;
  expect PASS. Inspect output for accidental old field-number changes.
- [ ] Commit: `feat: add Organizations II storage plugin capability`.

### Task 5: Invitation management with atomic delivery scheduling

**Files:** create `internal/mgmt/organization_invitations.go` and its test;
modify existing mgmt route registration and org rules; add
`internal/orglogin/invitation_ticket.go` and tests for ticket/URL handling.

**Interfaces:** consume Task 2 persistence and Task 4 capability; produce
invitation HTTP routes per Task 1. Define
`BuildInvitationURL(loginURI, ticket, orgID, orgName string) (string, error)`
and ticket creation using existing key-wrapper APIs, not a new encryption format.
Task 6 supplies actual job rendering; this task stores a typed delivery job
atomically through the existing enqueue transaction interface.

- [ ] Write `TestOrganizationInvitationCRUD`: create returns 200; omitted/zero
  TTL=604800; max2592000 accepted; negative/fraction/max+1 rejected; bad foreign
  client/role/connection writes nothing; roles=[] rejected; duplicates independent;
  disabled template and send=false still create usable URLs; expired get=404.
  Add `TestInvitationURLReservedParameters` for encoding/HTTPS/fallback/custom-domain
  ownership, and `TestInvitationQueueFailureRollsBack`.
- [ ] Run `go test ./internal/mgmt ./internal/orglogin -run 'OrganizationInvitation|InvitationURL|InvitationQueue' -count=1`;
  expect FAIL for unregistered routes or missing behavior.
- [ ] Implement strict validation, full batch reference checks, hash lookup and
  wrapped recovery, redacted logging, scoped read/delete and transactional enqueue.
  Honor legacy-client capability refusals and existing Management scope middleware.
- [ ] Rerun focused command; expect PASS. Verify database rows/jobs contain no
  unwrapped ticket or URL and management list/get never crosses tenants.
- [ ] Commit: `feat: manage organization invitations`.

### Task 6: Activate user_invitation rendering and durable delivery

**Files:** create `internal/email/invitations.go`, `invitations_test.go`,
`internal/email/templates/user_invitation.{html,txt}`; modify existing
`internal/email/{service,context}.go`, `internal/actions/email.go`, email job
payload/worker code and existing i18n catalog files discovered via `rg`.

**Interfaces:** add an invitation delivery discriminator to the existing sealed
email job input; fields are tenant/org/invitation/client IDs and frozen rendering
context. Rendering uses existing `email.Event`/`Service` and transport interfaces.
The worker reloads active invitation state before send and decrypts only in memory.

- [ ] Write `TestInvitationEmailLifecycle`: inviter/org/client variables render
  escaped; fallback localized; stored template overrides work; disabled suppresses;
  TTL30days is not clipped to generic template lifetime. Write
  `TestInvitationEmailRetrySameTicket` and `TestInvitationEmailRestartAfterSend`:
  retry keeps URL/expiry, no second invitation; expiry/delete/consumption suppress
  sends; pending Action delivery uses frozen context and existing retry ceilings.
- [ ] Run `go test ./internal/email ./internal/actions -run InvitationEmail -count=1`;
  expect FAIL while the template is stored-only or job kind is unsupported.
- [ ] Implement render/delivery through existing service and Plan 28 worker.
  Persist no raw URL in diagnostics; provider failure after commit leaves invite
  valid and retryable. Reuse transport/custom-domain validation, not another queue.
- [ ] Rerun focused command with the repository Node requirement for Action tests;
  expect PASS. Include fake clock/provider tests rather than external SMTP.
- [ ] Commit: `feat: deliver organization invitation emails`.

### Task 7: Bind and accept invitations in interactive login

**Files:** create `internal/orglogin/invitations.go`, `invitations_test.go`;
modify `internal/authz/organization.go`, existing authorization/PAR transaction
serialization, `internal/login/{organization,login,verify,social}.go`, and
`internal/oauth/organization.go`; add focused invitation tests in those packages.

**Interfaces:** implements `AcceptInvitation` and `AcceptanceInput` above;
produces the durable receipt used only by the same live, pending authorization transaction.
Completed hosted transactions end before Actions and cannot be replayed.
Local supported limitation: new federated account provisioning during invitation
login fails closed; accounts provisioned separately may accept. Existing federated
users remain eligible. The documented database-only signup flag is not extended.
Consume Task 8 `CheckMemberClient`; Task 8 must be complete before this task.
Do not introduce an interim entitlement bypass.

- [ ] Write `TestInvitationAcceptance` for existing verified user and verified
  signup, exact org roles, metadata existing-key precedence, one receipt and no
  tenant roles. Add `TestInvitationBoundResume` for PAR, changed client/org,
  alternate linked identity, session reuse and browser query/form tampering.
  Add `TestInvitationAcceptanceFailures` for wrong email, unverified email,
  blocked account, MFA incomplete, disabled signup/connection, deleted role,
  expiry, prompt=none and cross-tenant ticket. No failure may consume or enroll.
  Add `TestInvitationActionsDenialAfterAcceptance`: membership/receipt survive;
  replay by another transaction fails; same transaction resume is safe.
- [ ] Run `go test ./internal/orglogin ./internal/authz ./internal/login ./internal/oauth -run Invitation -count=1`;
  expect FAIL for absent acceptance/transaction binding.
- [ ] Implement ticket resolution after normal authorize validation, immutable
  server-side binding, verification/MFA continuation and atomic acceptance before
  Actions snapshot. Revalidate issuance without replaying acceptance. Receipt
  lookup must verify transaction/user, not just invitation ID.
- [ ] Rerun focused tests and the Task 3 SQL race cases; expect PASS.
- [ ] Commit: `feat: accept organization invitations transactionally`.

### Task 8: Application associations and member entitlement enforcement

**Files:** create `internal/mgmt/organization_clients.go` and its test,
`internal/orglogin/entitlements.go` and test; modify org CRUD/list DTOs,
`internal/orglogin/organization.go`, authz/login/oauth organization policy.

**Interfaces:** implements `CheckMemberClient`; consumes Task 2 client associations.
Task 7 wires acceptance to this completed helper. Association summaries
use a dedicated secret-free client DTO, not the full Management client response.

- [ ] Write `TestOrganizationClientAssociations` for batch rollback, omitted
  annotations and secret-free summaries. `TestOrganizationMemberEntitlement`
  asserts false preserves v1, true requires use=true, and membership/connection/
  third-party checks still apply. `TestOrganizationEntitlementRevocation` removes
  association between authorize/code exchange and login/refresh: issuance fails.
  `TestOrganizationEntitlementPickerBeforeLimit` puts eligible org after 20
  ineligible rows and confirms filtering happens before selection/truncation.
- [ ] Run `go test ./internal/mgmt ./internal/orglogin ./internal/login ./internal/oauth -run 'OrganizationClientAssociation|OrganizationMemberEntitlement|OrganizationEntitlement' -count=1`;
  expect FAIL for missing endpoints/gates.
- [ ] Implement route contracts, annotation joins and shared policy; enablement
  changes take the same transaction lock as acceptance/token eligibility reads.
- [ ] Rerun focused command and existing Plan 29 organization tests; expect PASS.
  Task 7 subsequently proves invitation acceptance uses the same helper.
- [ ] Commit: `feat: enforce organization application entitlements`.

### Task 9: Persist grant organization policy and issue bound M2M tokens

**Files:** create `internal/mgmt/organization_client_grants.go` and test;
modify `internal/mgmt/client_grants.go`, `internal/orglogin/entitlements.go`,
`internal/oauth/{grant_client_credentials,organization,actions}.go`, existing
Actions event snapshot code; add `internal/oauth/organization_m2m_test.go`.

**Interfaces:** implements `CheckMachineGrant`, consumes live `ClientGrant` fields
and association repository; no application member entitlement check for M2M.

- [ ] Write `TestOrganizationM2MPolicyMatrix` for every spec §5 table cell,
  explicit association vs allow-any, names switch, missing org, wrong tenant,
  third-party opt-in, subject=user active-field rejection, grant deletion and
  scope ceilings. Success has org_id, conditional org_name, no refresh/ID token
  and no membership writes. `TestOrganizationM2MRevocationRace` uses barriers:
  policy writer winning before final eligibility read prevents issuance.
  `TestOrganizationM2MActionSnapshot` asserts frozen org context, no scope elevation.
- [ ] Run `go test ./internal/mgmt ./internal/orglogin ./internal/oauth ./internal/actions -run OrganizationM2M -count=1`;
  expect FAIL while grant fields are inert and org M2M is refused.
- [ ] Implement grant CRUD round trips, associations and reverse lookup if required
  by Task 1; integrate explicit org into existing credentials flow. Keep current
  client authentication and API access policy. Do not add quotas/default orgs.
- [ ] Rerun focused tests and existing client-grant/OAuth policy suites; expect PASS.
- [ ] Commit: `feat: enforce organization grants in client credentials`.

### Task 10: Discovery-domain management and exact-domain resolution

**Files:** create `internal/mgmt/organization_domains.go`, its test,
`internal/orglogin/discovery.go` and test; use Task 2 repository and API schemas.

**Interfaces:** `NormalizeDiscoveryDomain(string) (string, error)` and
`Discover(ctx, st, tenantID, clientID, email)` above. Discover returns current
eligible candidates, sorted by ID, before the caller applies picker bounds.

- [ ] Write `TestOrganizationDiscoveryDomains` for pending creation, verified
  admin attestation, disabled flag, duplicate within same org, same domain in
  multiple orgs/tenants, get-by-name and deletes. Add
  `TestOrganizationDiscoveryNormalization`: IDNA/case normalization; reject
  wildcard/IP/URL/port/trailing-dot; exact subdomain must not match parent.
  `TestOrganizationDiscoveryPolicy` asserts no members are added and filters
  entitlement/third-party policy before any cap. Pending records never match.
- [ ] Run `go test ./internal/mgmt ./internal/orglogin -run OrganizationDiscovery -count=1`;
  expect FAIL for missing routes/resolver.
- [ ] Implement resource validation, challenge creation and scoped status writes.
  Use existing IDNA support; never resolve user-controlled URLs or claim DNS was
  verified. Canonical domain drives uniqueness and exact lookup on every backend.
- [ ] Rerun focused command and shared conformance discovery cases; expect PASS.
- [ ] Commit: `feat: manage organization discovery domains`.

### Task 11: Email discovery in hosted organization login

**Files:** modify `internal/login/{organization,identifier}.go`, existing hosted
organization templates/i18n catalogs, `internal/authz/organization.go`;
create `internal/login/organization_discovery_test.go`.

**Interfaces:** consumes Task 10 Discover and existing pending transaction CAS.
No new browser-supplied authorization fields; explicit org/invite always wins.

- [ ] Write `TestOrganizationDiscoveryPrompt`: 0/1/many matches, allow vs require,
  email-only/name-only/both methods, no account-existence disclosure, filtering
  before20 and accessible/localized errors. `TestOrganizationDiscoveryStalePost`
  changes domain/app policy and transaction revision between GET/POST: reject
  stale selection without replacing explicit org/invitation context.
- [ ] Run `go test ./internal/login ./internal/authz -run OrganizationDiscovery -count=1`;
  expect FAIL because Plan 29 always asks for a name.
- [ ] Implement configured email prompt and fallback rules, preserve rate/CSRF
  controls and revalidate current client/policy before advancing transaction.
- [ ] Rerun focused command; expect PASS. Add browser cases in Task 17.
- [ ] Commit: `feat: discover login organizations by email domain`.

### Task 12: Bounded search parsers, consistent stores and SQL paging

**Files:** create `internal/orgsearch/{ast,parse,eval,sql,cursor}.go` and tests,
`internal/mgmt/organization_search.go` and test; modify
`internal/store/organizations_ii.go`, memory/SQL/grpc II implementations and
existing SQL organization paging.

**Interfaces:** define a storage-owned `OrganizationQuery` AST and
`OrganizationSearchPage` in `internal/store/organizations_ii.go` to avoid a store
import cycle. Add `Search(ctx, tid string, q OrganizationQuery, p OrganizationSearchPage)
(OrgResult[Organization], error)` to OrganizationsII and its additive RPC.
`orgsearch.Parse(q, parser string) (store.OrganizationQuery, error)` produces
only validated predicates. `orgsearch.Match(store.OrganizationQuery,
store.Organization) bool` and SQL translation consume that exact AST.
Page carries Take, Sort and a validated last-sort-value/ID tuple; only HTTP
boundary encodes/authenticates opaque cursors using existing server key material.

- [ ] Write `TestOrganizationSearchParity` table with exact id, quoted terms,
  escaped characters, metadata keys, timestamp ranges, SCIM presence/AND/OR,
  prefix/suffix/contains; every driver returns identical IDs and tie ordering.
  `TestOrganizationSearchLimits` tests 5 vs6 predicates, depth16 vs17, q1000
  vs1001, contains literal2 vs3, take0/101 and unknown/regex/fuzzy syntax.
  `TestOrganizationSearchCursorBinding` tampers tenant/query/parser/sort/signature;
  all reject, cursor remains valid across process restart using stable key material.
  `TestOrganizationSQLPageBound` verifies page queries bound result hydration and
  joined summaries don't issue one query per row. Add parser fuzz seeds.
- [ ] Run `go test ./internal/orgsearch ./internal/mgmt -run OrganizationSearch -count=1`;
  expect FAIL for missing search implementation.
- [ ] Implement grammar in spec §7, shared typed AST, parameterized SQL (escape
  LIKE wildcard literals), deterministic ID tie-breaks and cursor integrity.
  Preserve legacy list envelopes; search sort is field-only ascending, not the
  legacy `field:direction` syntax. Register /search before /{id}.
- [ ] Rerun focused tests, plugin search round trips, and
  `./scripts/test-sql.sh -run 'OrganizationSearch|OrganizationSQLPage' -count=1 ./internal/store/sqlstore/...`;
  expect PASS across three drivers. Run `go test ./internal/orgsearch -run '^$' -fuzz FuzzOrganizationQuery -fuzztime=30s`
  after adding that fuzz target; no external search service or arbitrary SQL interpolation.
- [ ] Commit: `feat: search organizations with bounded SCIM and Lucene filters`.

### Task 13: Expand EA connections while preserving legacy behavior

**Files:** modify `internal/mgmt/organization_connections.go`, org rules and
store connection codecs/repositories; extend `internal/orglogin/organization.go`
and OAuth revalidation; add `internal/mgmt/organization_connections_ii_test.go`.

**Interfaces:** Task 2 connection fields become live. EA lists include disabled
associations; enabled_connections filters them. Access-level enums stay metadata
until Plan 42, and never alter current Management authorization or token scopes.

- [ ] Write `TestOrganizationConnectionsIIViews`: disabled EA association stays
  readable but disappears from enabled list; legacy add re-enables; delete removes.
  Name/null and enum/null round-trip defaults match spec §5. Add
  `TestOrganizationConnectionsIIDisabledDuringLogin`: signup, enrollment, code
  exchange and refresh fail after disable; metadata full never grants a permission.
- [ ] Run `go test ./internal/mgmt ./internal/orglogin ./internal/oauth -run OrganizationConnectionsII -count=1`;
  expect FAIL for missing fields/disabled filtering.
- [ ] Implement all EA DTO fields and scoped display name; ensure both routes
  operate on one association and all eligibility helpers enforce IsEnabled.
- [ ] Rerun focused tests, existing org connection tests and Deploy connection
  fixture tests; expect PASS with preserved D-0055 paging conventions.
- [ ] Commit: `feat: expand organization connection management`.

### Task 14: Carry organization through password-change workflows

**Files:** modify `internal/dbconn/change_password.go`, `internal/mgmt/tickets.go`,
`internal/login/reset.go`, `internal/email/context.go`, reset ticket models/codecs;
create focused organization-reset tests beside each entry point.

**Interfaces:** add resolved `OrganizationID string` to reset ticket and email
context using Task 1 wire field names. Use existing reset-ticket creation and
consumption interfaces; do not reuse invitation tickets or receipt semantics.

- [ ] Write `TestOrganizationPasswordChangeContext`: email/hosted reset use the
  requested organization branding, allowed connection/client and allowlisted
  return URL. Cross-tenant/removed org and disabled connection fail safely;
  missing email still follows existing anti-enumeration behavior. Assert no
  membership/role writes, one-use reset and no switch of primary identity.
- [ ] Run `go test ./internal/dbconn ./internal/mgmt ./internal/login ./internal/email -run OrganizationPasswordChange -count=1`;
  expect FAIL while context is rejected/dropped.
- [ ] Implement validated context capture, rendering and completion recheck;
  preserve legacy reset behavior when absent. Preserve context through Action
  customization without permitting Action metadata to replace authorization IDs.
- [ ] Rerun focused command plus shared password-reset ticket conformance;
  expect PASS on memory/SQL/plugin.
- [ ] Commit: `feat: preserve organization context in password reset`.

### Task 15: Console management and retained Plan 29 polish

**Files:** create `console/src/pages/organizations/{InvitationsTab,ApplicationsTab,ApiGrantsTab,DiscoveryDomainsTab}.vue`
and associated tests; modify existing List/Detail/context/ConnectionsTab,
`console/src/stores/tenants.ts`, tenant switcher tests and organization lifecycle tests.

**Interfaces:** use generated Management API types from Tasks 1–14; capture
request tenant/org keys and a monotonic request revision for tenant discovery.
No separately maintained manual API DTOs or browser-stored invitation secrets.

- [ ] Write tests `invitations create and copy URL`, `entitlement gates member apps`,
  `domain attestation is explicit`, `disabled connection remains manageable`,
  `search resets cursor`, `latest tenant discovery wins`, `stale invitation reply
  is ignored`, `legacy plugin capabilities are truthful`, and existing clearing/
  role-removal regression cases. Assert stale requests cannot restore prior tenant
  lists or apply actions to newly selected tenant/org.
- [ ] Run `cd console && npm test -- --run`; expect new cases FAIL before UI changes.
- [ ] Implement tabs/forms, confirmation for domain status attestation, pending/
  retry states, usable errors, localized labels and permission/capability guards.
  Do not expose implementation internals except the documented attestation and
  stored-only delegation limitations that affect operator decisions.
- [ ] Run `make console`; expect lint/typecheck/tests/build PASS. Inspect generated
  types/dist. Triage every historical Plan 29 ledger row in the implementation
  record with fixed/already-resolved/deferred reason and relevant test evidence.
- [ ] Commit: `feat: manage Organizations II in the console`.

### Task 16: Seed and Deploy CLI compatibility

**Files:** modify `internal/seed/organizations.go` and related seed types/tests,
`internal/deploymigration` organization handling, existing
`tests/e2e/deploy-cli/{manifest,normalize}.go` and fixtures; add focused II tests.

**Interfaces:** resolve symbolic organization/client/grant/connection references
using existing seed/deploy mapping. Invitations and receipts are never portable.
Only supported Deploy CLI 9.1.0 resource fields enter its manifest.

- [ ] Write `TestOrganizationsIISeedCreateOnly`: initial policy applies; API-managed
  changes survive reseed; domains default pending; bad references are rejected
  without partial batch changes; no invitation secrets accepted/exported.
  `TestOrganizationsIIDeployRoundTrip` asserts enabled/disabled connections and
  supported policy survive YAML/directory and generated/preserved ID modes.
  Unknown unsupported active policy must produce an explicit error, not be dropped.
- [ ] Run `go test ./internal/seed ./internal/deploymigration ./tests/e2e/deploy-cli -run OrganizationsII -count=1`;
  expect FAIL before new mappings/validation.
- [ ] Implement create-only reference resolution and the pinned tool's supported
  shape. Document omitted resources and member-export limitations. Preserve
  existing secret substitution and API-created grant ownership.
- [ ] Rerun focused command and `make e2e-deploy`; expect PASS in all four cells.
- [ ] Commit: `feat: provision Organizations II configuration`.

### Task 17: SDK/CLI/browser acceptance and final regression evidence

**Files:** create `tests/e2e/{m30-node-auth0,m30-mgmt-cli,m30-organizations.spec}.mjs`,
`tests/e2e/run-m30-organizations-ii.sh`; modify `Makefile`, E2E fixture/server wiring,
`docs/organizations.md`, roadmap and implementation record. Add
`e2e-organizations-ii` target; retain `e2e-organizations` for Plan 29 regression.

**Interfaces:** tests use real HTTP application login route forwarding invitation
and organization, a mail capture fixture, actual authorization/token endpoints
and existing test SDK pins. Browser filename must match `m*.spec.mjs` discovery.

- [ ] Add black-box cases: CLI/SDK invitation CRUD, email captured invitation
  through signup/verification/MFA and Actions, wrong-account retry, same-ticket
  replay, entitlement revocation before exchange/refresh, organization M2M
  truth table, verified-domain login and search cursor rejection. Add console
  tenant-switch and domain-attestation paths. Test supported EA tools without
  claiming SDK-only behavior as parity evidence.
- [ ] Run the new runner once to detect missing fixture/flow support, then fix
  failures through the owning implementation and test. Never weaken assertions
  simply to obtain green. Add regressions for discovered defects.
- [ ] Run final verification sequentially where fixtures/ports overlap:
  - `ZA_REQUIRE_NODE=1 go test -race -timeout=50m ./...`
  - `./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/...`
  - `make console` and `make check-sources`
  - `make e2e-organizations-ii` and `make e2e-organizations`
  - `make e2e`, `make e2e-rbac`, `make e2e-actions`, `make e2e-actions-ii`
  - `make e2e-email-accounts`, `make e2e-email`, `make e2e-domains`
  - `make e2e-deploy` only if changes since Task 16 affect it; otherwise cite its
    recorded passing commit and verify it remains an ancestor of the final head.
  - `make conformance` with the repository-supported affected-plan selection.
  Expected: every selected test passes; no unavailable/timeout/skipped suite is
  represented as passing. Record network source-check failures separately.
- [ ] Finish guide/API support status and implementation record: actual tested
  versions, driver results, browser cases, capability matrix, local differences,
  retained ledger dispositions and quota/default-M2M-org/self-service exclusions.
  Obtain whole-branch review using the repository's review skill before integration;
  resolve correctness/security findings and rerun only affected checks after fixes.
- [ ] Commit: `test: verify Organizations II end to end`.

## Dependency order and completion audit

Execute 1 → 2 → 3 → 4. Policy work 8 precedes acceptance 7; the execution order is
**1, 2, 3, 4, 5, 6, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17**.
Task 8 is a prerequisite of Task 7; the numbering groups subjects rather than
overriding the recommended execution order.
Parallel agents, if chosen by the user, must respect shared-file ownership and
these dependencies. Do not concurrently mutate shared store/proto/policy files.

| Spec requirement | Owning tasks |
| --- | --- |
| Evidence, scopes, defaults, local differences | 1, 17 |
| Atomic invitation/receipt, tenant isolation | 2–7 |
| Durable email and template activation | 5–6 |
| App/grant runtime enforcement and Actions | 7–9 |
| Domains and hosted discovery | 10–11 |
| Search and bounded SQL reads | 12 |
| EA connection compatibility | 13 |
| Password-change context | 14 |
| Migrations/plugin capability/rollback | 2–4, regression in 12–14 |
| Console and complete Plan 29 ledger disposition | 15, 17 |
| Seed and supported Deploy portability | 16 |
| SDK/CLI/browser, full regression, documentation | 17 |

Planning self-review: all spec sections map above; common method names/types are
owned here; all five Review Focus risks have tests; generated outputs use existing
tooling. The spec received a fresh independent builder check with no important
questions remaining. No implementation, migration or product test was executed
as part of writing these documents.
