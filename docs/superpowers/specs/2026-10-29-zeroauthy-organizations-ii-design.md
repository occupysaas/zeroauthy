# Plan 30 — Organizations II

**Date:** 2026-10-29. **Status:** specification; implementation not started.

**Predecessor:** [Organizations I](2026-10-28-zeroauthy-organizations-design.md),
implemented through `3288198` on main. Read the
[implementation record](../2026-10-28-plan-29-implementation-record.md),
[organization guide](../../organizations.md), and [clean-room policy](../../../CLEAN_ROOM.md).

## 1. Outcome and scope

An administrator can invite someone into an organization, configure which apps
and API grants the organization may use, and help users discover their organization
by email. Acceptance creates membership and organization roles exactly once.
Search and the console make those resources manageable. Every policy is enforced
through authentication, code exchange, refresh, and the storage plugin boundary.

This is one release with five implementation tracks: invitations, application
and grant policy, discovery, search, and integration. The roadmap's old “Short”
label no longer describes the accumulated Plan 29 follow-ups.

**Scope ruling:** minimal organization-aware client credentials issuance moves
from Plan 35 into Plan 30 because grant `organization_usage` and
`allow_any_organization` govern that flow. Quotas and quota headers stay in
Plan 35. This supersedes the Plan 29 deferral of *all* organization M2M tokens;
it does not change client-level organization policy for interactive login.

Included:

- Invitation create/list/get/delete, live `user_invitation` delivery, acceptance.
- Organization-to-client-grant associations and effective grant enforcement.
- Organization-to-application associations and member access enforcement.
- Discovery-domain management and email discovery at the pre-login prompt.
- Separate organization search endpoint with Lucene and SCIM filters.
- EA connection resource expansion while preserving `enabled_connections`.
- Organization context in database password-change email/tickets.
- Console, seed, supported Deploy CLI round trips, all storage implementations,
  API documentation, and the retained Plan 29 polish ledger.

Excluded: groups (38), SAML/WS-Fed login (37), My Organization API and delegated
self-service connection administration (42), token quotas (35), new log/event
stream delivery (31/32), and application-default organization selection for M2M.
No new external search service or dependency upgrade is required.

## 2. Evidence and compatibility rules

Public references reviewed for this specification:

| Contract | Primary source |
| --- | --- |
| Invitation fields, 200 creation, TTL | [Create invitation](https://auth0.com/docs/api/management/v2/organizations/post-invitations) |
| Application route and acceptance parameters | [Invite members](https://auth0.com/docs/manage-users/organizations/configure-organizations/invite-members) |
| Grant organization policy belongs to client credentials | [Client grants](https://auth0.com/docs/get-started/applications/application-access-to-apis-client-grants) |
| App association member-access field | [Update association](https://auth0.com/docs/api/management/v2/organizations/patch-organization-client) |
| Discovery domain lifecycle fields | [Create domain](https://auth0.com/docs/api/management/v2/organizations/post-discovery-domains), [update domain](https://auth0.com/docs/api/management/v2/organizations/patch-discovery-domains-by-discovery-domain-id) |
| Search grammar, fields and paging | [Search organizations](https://auth0.com/docs/api/management/v2/organizations/get-search) |
| EA connection fields | [Update connection](https://auth0.com/docs/api/management/v2/organizations/patch-organization-connection) |

These are documentation evidence, not live-tenant observations. Task 1 freezes
all route-specific scopes, envelopes, defaults, null handling and error codes in
`internal/orgrules/inventory.json` and D-0056 (or the next free decision ID).
Use permitted firewalled observation only for remaining ambiguities; an
implementer must not observe the same area. SDK-only details are leads, not
server behavior evidence. Existing D-0055 observed behavior remains authoritative
unless explicitly superseded with evidence.

The local rulings below are deliberate implementation contracts, not claims of
exact Auth0 behavior. Task 1 may correct a documented wire discrepancy and must
update this spec and its plan together; it must not silently expand scope.
If evidence is unavailable, keep the stated local ruling and record the gap.
In particular, support articles report wrong-account attempts consuming invites;
our local retry rule below intentionally differs and must be documented.

All resource IDs are tenant-scoped; cross-tenant references behave as missing.
Preserve Management API authentication, live operator grant checks, permissions,
strict body parsing and pagination conventions. Unknown fields never silently
activate policy. Publish `x-source` entries and regenerate API/protobuf outputs.
Use Go 1.26.7 and Node >=22.13; retain repository dependency pins.

## 3. Invitations and delivery

Routes under `/api/v2/organizations/{id}/invitations`: POST and GET collection,
GET and DELETE `/{invitation_id}`. List accepts fields/include_fields and sort (default created_at:-1); include_totals returns `{invitations,start,limit}` without total, as documented. An invitation has an opaque `uinv_` ID,
tenant/org/client IDs, inviter name, invitee email, optional forced connection,
optional role IDs and user/app metadata, timestamps, ticket ID and invitation URL.
The bearer ticket is independent of the resource ID and contains at least 256
random bits. Store a hash for lookup and wrap the recoverable URL/ticket with
the existing key wrapper for authorized read responses and queued delivery.
Never log tickets or put them in seed/export files.

Required input: inviter name, invitee email and client ID. TTL omitted or zero
means 604800 seconds; integers 1–2592000 are valid. Email delivery defaults true.
Omitted roles means none; a supplied roles array must be nonempty, deduplicated,
and fit the existing per-member role cap. Validate all roles/client/connection
in the same tenant before writing. JSON metadata objects follow existing user
metadata size/type limits. Duplicate invitations are independent resources;
creating a second invitation does not revoke the first (local ruling).

Resolve the URL from application login URI then tenant default login URI;
require a validated HTTPS URL and reject missing configuration before commit.
Use URL encoding, preserving unrelated query values but replacing reserved
`invitation`, `organization`, `organization_name` parameters. The display name
parameter is informational; the stored organization ID is authoritative.
Use existing custom-domain selection and tenant ownership checks.

Creation atomically stores the invite and durable email work when requested.
Reuse the Plan 28 email job/lease machinery; extend its payload discriminator,
not its execution engine. Queue failure rolls back creation. Disabled template
suppresses sending while retaining the invite and usable URL. With
`send_invitation_email=false`, no delivery work is created. `user_invitation`
gets localized fallback text/HTML, inviter, organization branding, application,
expiry and URL variables. The invitation TTL controls expiry, independently of
any generic email template URL lifetime.

Delivery is at-least-once: retries reuse the same ticket, never create another
invite, and stop after expiry/deletion/consumption. Delivery failure after
creation does not invalidate the invite or roll back a successful API response.
Use existing queue retry limits and sealed payload rules; expose failure through
existing job diagnostics without introducing Plan 31 logs. A worker already
sending can race deletion; the resulting link must still be unusable.

Expired/consumed invites disappear from active lists and get returns 404;
delete is idempotent for a missing invite in an existing organization (local).
Cleanup can physically remove them later; correctness cannot depend on cleanup.

## 4. Invitation acceptance

`/authorize` accepts an invitation only together with organization. Validate
normal client/redirect/PKCE policy first, then ticket tenant, organization,
client, expiry and forced connection. Persist the validated invitation ID in
the server-side authorization transaction, including PAR/resume paths; neither
browser form fields nor later query parameters may replace it. Never accept
an invitation at `/oauth/token` or on refresh.

Require an authenticated account matching the invited email using the existing
identity email normalization rules. Require verified ownership of that address;
the invitation itself does not mark an arbitrary existing account verified.
An existing unverified account uses the normal verification flow before acceptance.
Wrong-account attempts show a recoverable error and leave the invite usable.
`prompt=none` never silently accepts or creates membership; return interaction
required. A forced connection must match the original primary authentication
connection, not any linked identity. Existing sessions follow the same checks.

After authentication, verification and MFA, before the post-login Actions event
is constructed, one `WithTx` operation revalidates current client, organization,
connection, app entitlement, user state, roles and invitation expiry; consumes
the pending invite; adds membership; unions invitation roles with existing
organization roles; applies invitation metadata. Existing metadata keys win,
new keys are shallow-added (local ruling). Do not modify tenant roles or
membership in other organizations. Missing/deleted role or disabled policy
fails the whole transaction; no partial acceptance.

Acceptance is the durable business event. An Action denial, failed token
exchange or abandoned redirect afterward does not undo membership/consumption.
Actions see the accepted organization and effective roles. A resumed *same*
authorization transaction can continue using its acceptance receipt; a second
transaction cannot replay the ticket. Concurrent accept/delete/expiry races
have one serialized outcome. Recheck all active authorization policy at code
exchange and refresh as Plan 29 does; no re-enrollment at those stages.

Invitation signup may bypass the requirement for *existing membership*, but
must still respect client connection enablement, blocked users, database signup
restrictions and the organization's `is_signup_enabled`. Creating an invite
is not a bypass of those controls. Explain that restriction in the console.

## 5. Application entitlement, grant policy and EA connections

### Application associations

Implement documented collection list/associate/remove and item get/update at
`/organizations/{id}/clients`. Store `use_for_member_access` with each association. POST requires an explicit boolean on every item; there is no omitted-true default. PATCH omission preserves the stored value; null is rejected.
`is_app_entitlement_active` defaults false on existing and new organizations
(local default). False preserves Plan 29 interactive behavior. True requires an
association with `use_for_member_access=true` for interactive organization login.
This is an additional condition, never a replacement for membership, enabled
connections, third-party access restrictions or client organization policy.
Bulk operations validate the complete batch and commit all or none.

Apply this condition before auto-selecting or truncating picker choices, at
explicit organization login, invitation acceptance, code exchange and refresh.
A later revocation blocks new issuance; it does not revoke already signed JWTs.
`include_client_association_for` annotates list results with `client:{use_for_member_access}` for the matching client
association; absent associations omit the annotation. It does not filter rows
or grant access. Do not return client secrets in embedded client summaries.

### Client-grant associations and M2M

Persist `ClientGrant.OrganizationUsage` (`deny`, `allow`, `require`, default
`deny`) and `AllowAnyOrganization` (default false). For `subject_type=user`,
retain inert deny/false and reject active values (local supported subset).
Implement list/associate/delete at `/organizations/{id}/client-grants`, plus
GET `/client-grants/{id}/organizations` with read:organization_client_grants and documented offset/checkpoint variants. DELETE uses `/{grant_id}`.
Associations reference an existing client-subject grant; they never copy scopes.
Deleting the grant/client/API/org cascades its associations.

| Grant policy | No organization parameter | Organization parameter |
| --- | --- | --- |
| deny | Existing M2M behavior | Reject |
| allow | Existing M2M behavior | Require existing org and explicit association or allow-any |
| require | Reject | Require existing org and explicit association or allow-any |

Grant scopes remain the ceiling; organization roles never become M2M scopes.
For third-party clients reject allow-any and require explicit association plus
the existing third-party organization opt-in (local conservative rule).
Authenticated M2M requests resolve explicit organization IDs, or names only
under the existing tenant names switch. There is no inferred/default org.
Success includes `org_id`, and `org_name` only under the existing names policy;
no ID token, refresh token or membership. Reuse current authentication, resource
server policy, signing, Actions credentials-exchange event and scope processing.
Freeze organization in that event before execution. Policy/grant writes serialize
with the final issuance eligibility read; a winning revocation prevents issuance.
Application *member* entitlement does not govern M2M.

### EA connections

Retain both connection route families. EA `/connections` can retain a disabled
association (`is_enabled=false`); legacy `/enabled_connections` lists only enabled
ones, and legacy deletion removes the association. Legacy add may enable a
retained disabled association. Existing records migrate to enabled=true.

Persist optional organization-local connection name and the documented
`organization_access_level` / `organization_member_access_level` enums:
none, readonly, limited, full. Omission on create and migration preserves D-0055: organization access none, member access limited. Explicit null clears either access level to the local default none; optional
name null clears to the underlying connection name. These access-level fields
are stored management/delegation metadata, **not** user login permission or
Management API scope grants; delegated execution belongs to Plan 42. The
console labels them accordingly. `is_enabled` null resets true (local rule).
Enablement, signup and auto-membership flags remain live in login and refresh.

Internal storage representation (Task 2 local ruling): keep `IsEnabled bool`
and add `IsEnabledSet bool` as a Go presence marker. Existing Go literals omit
both fields; creation normalizes them to enabled. Explicit disabled callers set
the marker true. All persisted/read records carry the marker true; SQL/plugin
codecs store actual enablement and restore presence, with no API marker field.
Replacement literals omitting the marker or access strings preserve the current
II values. Access omission on creation normalizes to none/limited; API null
clears are translated to explicit none, underlying name or enabled true before
storage. This preserves old callers without treating zero-value false as disable.

## 6. Discovery domains and email prompt

Implement documented discovery-domain collection create/list (`{domains,next?}`), item get/update/
delete, and `/name/{discovery_domain}` lookup. Creation accepts omitted/pending status (verified requires PATCH locally), returns pending status,
verification TXT challenge/host, and use-for-discovery (default true). PATCH
supports pending/verified and the use flag. Only a caller with the resource's
Management write scope may assert verified status. This is an administrative
attestation, not proof that zeroauthy resolved DNS. Automated DNS verification
and self-service verification are excluded; describe this clearly in the guide.
Use a random challenge and local `_zeroauthy-org.<domain>` verification host.

Normalize domains to lowercase ASCII IDNA, reject IPs, wildcards, ports, URLs
and trailing dots, and require valid DNS label lengths. Uniqueness is per
organization; the same domain may identify several organizations. Never treat
parent domains as implicit subdomain matches. Only verified, enabled records
participate in exact email-domain matching. Domain ownership is not mailbox
ownership or membership and must never auto-enroll a user.

When `organization_discovery_methods` includes email at pre-login prompt,
accept an email identifier. Eligible candidates also pass current client/app/
third-party policy. Zero candidates gives a generic retry/name-entry option
when organization_name is configured; an allow client can continue personally,
a require client cannot. One candidate selects that org; multiple show the
existing bounded picker, with policy filtering before its 20-choice bound.
Do not expose members, email existence, client secrets or domain challenges.
Bind chosen org by transaction revision CAS and revalidate before authentication.
Explicit org/invitation takes precedence; discovery never replaces it. Disabling
email discovery restores the configured name flow. Apply existing hosted-form
CSRF and rate protections, accessible error labels and localization.

## 7. Search and paging

Require both read:organizations and read:organizations_summary, following the public operation OAuth security scope array (the narrower summary-only alternative is not implemented locally). Add `/api/v2/organizations/search` ahead of the parameterized ID route.
Use `q`, parser lucene (default) or scim, take 1–100 (default 50), opaque from
cursor, and ascending sort name/display_name/created_at (default created_at).
Return organizations plus next only when another page exists. No list totals
or offset paging on this endpoint. Query length <=1000; max five predicates.

Implement a bounded, typed AST shared by memory evaluation and parameterized
SQL translation. Fields: exact case-sensitive id; name/display_name; created_at;
metadata.<key>. Support Lucene field terms, quoted strings, AND/OR, parentheses,
prefix/suffix/contains wildcards and timestamp ranges; SCIM eq/ne/sw/ew/co/pr,
gt/ge/lt/le and and/or with grouping. Contains/suffix literals require >=3
characters. Reject unsupported fields, operators, regex/fuzzy syntax and excess
complexity with 400; do not pretend to run arbitrary Lucene. Policy boolean
filters advertised only in the changelog remain excluded until endpoint evidence
confirms them. Name/display/metadata comparison is case-sensitive locally.

AST depth is capped at 16; one range counts as one predicate. Empty q matches
all. Presence means key exists, including an empty metadata value if legacy
storage contains one. No arrays or nested metadata traversal. Ordering ties use
ID. Cursor authenticates tenant, normalized query/parser/sort and last tuple;
changing query or tenant invalidates it. A cursor is not a snapshot: concurrent
updates can change membership in later pages. Reads are immediately consistent
locally, a documented stronger guarantee than upstream eventual consistency.

Move existing SQL organization list paging into SQL, preserving D-0055 envelopes
and limit semantics. Batch connection/client summaries for each page. SQL should
fetch O(page-size) result rows, not hydrate the tenant collection; do not claim
an index avoids every substring scan. No unmeasured latency SLA is promised.

## 8. Password change, storage and compatibility

Accept documented organization context on database password-change requests
and reset-ticket creation. Validate tenant/org/client/connection, carry the
resolved ID through ticket, email rendering and hosted reset branding. It never
adds membership, changes roles or selects an arbitrary user's identity. Reset
completion rechecks extant organization and connection policy; invalid context
must not fall back to a different org. Keep existing anti-enumeration responses,
redirect allowlists and one-use reset rules. The Authentication request field is `organization`; Management reset tickets use `organization_id`. Both accept IDs only, reject null and preserve anti-enumeration for unknown emails. Tickets reject result_url with organization_id. Missing or cross-tenant org/client/connection is invalid_request for Authentication and 404 not_found for Management (local D-0056). Omission carries no organization; reset completion rechecks the bound context.

Use migration `0026_organizations_ii.sql` in SQLite/PostgreSQL/MySQL (renumber
only if another migration lands first). Add invitations, app associations,
grant associations, discovery domains and acceptance receipts; extend organization,
connection, client-grant and reset/authorization transaction records. Composite
tenant foreign keys and indexes enforce ownership. All mutations participate in
existing `WithTx`; use the Plan 29 tenant-policy lock ordering, including MySQL
READ COMMITTED, so policy and acceptance cannot race past each other.

Keep Organizations capability v1 functional. Add a separately negotiated
OrganizationsII v1 capability/RPC group; do not bump the old minimum and disable
Plan 29 features on existing plugins. New API writes/read routes return 501
`organizations_ii_unavailable` without it, and active II authentication fails
closed. Legacy deny/false defaults and Plan 29 reads remain available; never
silently discard active fields. Shared plugin transaction handles cover the new
repositories. Tests must cover rollback and errors after reconnect; transient
capability errors are not permanently cached.

## 9. Console, provisioning and retained polish

Organization detail gains Invitations, Applications, API Grants and Discovery
Domains tabs. Forms show expiry/delivery choices, role scope, entitlement state,
verified attestation and pending status. Copying an invitation URL is explicit;
never persist it in browser storage. All requests carry captured tenant/org keys
and ignore stale responses after navigation or deletion. Latest tenant-discovery
request wins, closing the Plan 29 menu race.

List search uses the new endpoint. Connection UI distinguishes disabled from
removed associations. Add regression coverage for branding/metadata clearing
and member-role removal. Old plugins show truthful capabilities/defaults rather
than echoing discarded client settings. Triage every historical ledger row with
fixed/already resolved/deferred and a reason. Bounded capability singleflight
and unrelated frontend build notices may remain documented follow-ups.

Seed is create-only, resolves symbolic org/client/grant/connection references,
and supports durable policy/domain configuration. Invitations and acceptance
receipts are excluded. Seed must not overwrite API-managed policy or mark a
domain verified by default. Deploy CLI 9.1.0 round trips only what it supports;
exercise both YAML/directory and generated/preserved IDs. Document unsupported
resources explicitly; don't add fake support or silently drop policy on import.
No member export is promised by this plan.

## 10. Acceptance and completion

- SDK/CLI create/read/delete invitations and a browser accepts through a real
  application login route, MFA/verification as applicable, Actions and code exchange.
- Wrong email, wrong org/client/connection, expiration, role deletion, replay,
  simultaneous acceptance and revocation cannot grant unauthorized membership.
- Entitlement removal and disabled connections block code exchange/refresh;
  every grant-policy truth-table cell is exercised with first/third-party clients.
- Discovery handles pending, verified, disabled, duplicate-domain and no-match
  cases without granting membership; search results agree across all drivers.
- SQL migrations preserve Plan 29 data; gRPC II and legacy capability matrices
  are tested. Email retry, restart, suppressed delivery and deletion races pass.
- Console, seed and supported Deploy round trips pass with no silent data loss.
- Run actual focused tests, full Go race suite, all three SQL drivers, console,
  organization and affected regression E2Es. Report each result and any unrun
  checks honestly. Plan 19's database hold applies only to Plan 19, not this plan.

The implementation record must map every acceptance condition and Plan 29 ledger
row to evidence or an explicit remaining limitation. Documentation-only creation
of this spec and plan does not imply any implementation or test has passed.
