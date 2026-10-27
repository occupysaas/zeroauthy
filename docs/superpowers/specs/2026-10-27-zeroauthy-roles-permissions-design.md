# zeroauthy — Plan 26: Roles and permissions (RBAC)

- **Status:** Implemented, reviewed and locally verified; [actual results](../2026-10-27-plan-26-implementation-record.md).
- **Date:** 2026-10-27
- **Roadmap:** [Plan 26](2026-10-19-zeroauthy-management-roadmap-design.md#plan-26--roles-and-permissions-rbac).
- **Predecessor:** [Plan 25 acceptance record](../2026-10-26-plan-25-implementation-record.md).
- **Implementation plan:** [Plan 26](../plans/2026-10-27-zeroauthy-plan-26-roles-permissions.md).

## 1. Intent and scope

Make tenant roles and direct user permissions affect access to custom APIs.
An operator can define permissions on an API, collect them into roles, assign
roles or individual permissions to users, and enable RBAC for that API. New
user access tokens then reflect current assignments. Existing clients keep
their present behavior until RBAC or a different token dialect is selected.

The roadmap already selects this scope. The detailed defaults below are the
implementation design choices approved with this plan, rather than additional
maintainer rulings. Success
means management, memory/SQL/plugin storage, token grants, console and migration
tools agree. Endpoints that store assignments without enforcing them do not
complete this plan.

Included: 16 Management API operations, role and assignment persistence,
resource-server RBAC settings, four access-token dialects, all existing user
grants, console editing, seed support for roles and API settings, and local
CLI/SDK/browser/Deploy CLI evidence.

Excluded: organizations and organization roles (Plans 29–30), groups and group
inheritance, Authorization Extension compatibility, Actions/custom claims
(Plans 27–28), automatic role claims in ID tokens, wildcard/hierarchical roles,
role assignment through user metadata, new signing algorithms, and immediate
revocation of already-issued JWTs. Recent public docs expose group endpoints,
effective roles, and early-access organization-role fields; inventory them as
deferred rather than silently claiming whole-resource parity.

## 2. Evidence and constraints

Read `CLEAN_ROOM.md` before implementation. Public API/behavior documentation
is permitted; proprietary dashboard/page capture is not. Task 1 reviews the
changelog from the last recorded coverage, inventories each operation, and
uses a separate observer session for optional live-tenant observations. No
live tenant was contacted while writing this draft. Missing live evidence is
recorded as unavailable, never replaced by a claim that local mocks prove it.

Public sources consulted on 2026-10-27:

- [Enable RBAC](https://auth0.com/docs/get-started/apis/enable-role-based-access-control-for-apis): requested API scopes are limited by assigned permissions; the optional permissions claim represents assignments, not just requested scopes.
- [Token profiles](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles): four dialect names and the RFC profile's header/client claim differences.
- [Roles API](https://auth0.com/docs/api/management/v2/roles/get-roles): paging, name filtering and newer early-access role types.
- [User permissions API](https://auth0.com/docs/api/management/v2/users/get-permissions): permission identity, presentation fields and sources.
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068): JWT access-token validation and required claims; review its normative requirements in Task 1.

Task 1 must inspect linked create/update/assignment operations as well as these
entry points. Freeze exact required scopes, limits, envelopes, statuses,
checkpoint behavior and source representations before generating the schema.
Unspecified behavior follows the explicit local decisions below, with a
compatibility decision; source-backed corrections update spec and plan together.
New scope or authorization semantics require maintainer review.

Global constraints:

- Preserve Go 1.26.7 and the existing Vue/TypeScript, JOSE, SQL and protobuf stack; no new runtime service or dependency is required.
- All role and permission references are tenant-scoped; custom API assignments never confer operator or Management API authority.
- Defaults remain `enforce_policies=false` and `token_dialect=access_token`; system APIs retain their current restrictions.
- SQL migrations are additive; use the next free migration number, currently 0022. Never edit historical migrations.
- RBAC lookup or capability failures fail closed; no cached or empty-success fallback.
- Tests use local fixtures. Live Auth0 evidence is optional and reported separately.
- Plan 19's database-test hold remains specific to Plan 19; this plan does not alter it.

## 3. Management contract

| Resource | Operations | Purpose |
|---|---|---|
| `/api/v2/roles` | GET, POST | List/filter roles; create a role |
| `/api/v2/roles/{id}` | GET, PATCH, DELETE | Read, rename/describe, delete |
| `/api/v2/roles/{id}/permissions` | GET, POST, DELETE | Read/add/remove API permissions |
| `/api/v2/roles/{id}/users` | GET, POST | List members; assign users |
| `/api/v2/users/{id}/roles` | GET, POST, DELETE | List/add/remove role assignments |
| `/api/v2/users/{id}/permissions` | GET, POST, DELETE | Effective permissions; add/remove direct assignments |

There is no invented DELETE role-users operation: remove through user-roles.
Role responses carry `id`, `name`, `description`. Permission writes contain
`permissions: [{resource_server_identifier, permission_name}]`; user-role
writes contain `roles: [role_id]`; role-user writes contain `users: [user_id]`.
Descriptions and API display names are derived from the current API definition.
The user permission list unions direct and role-derived grants while retaining
all sources. Locally project `sources` as `[{source_type:"DIRECT"},
{source_type:"ROLE",source_id:role_id,source_name:role_name}]`, including only
the applicable sources. Public docs leave the source-object schema unconstrained;
this representation is a local D-0052 contract. Removing a direct grant must leave a permission inherited through
a role; removing one role must leave other sources intact.

Proposed local defaults where sources leave gaps: role names have 1–128 Unicode
code points and descriptions 0–255; reject whitespace-only names and control
characters; preserve spelling, with tenant-local exact case-sensitive uniqueness.
PATCH omission preserves a field; null is invalid; an empty description clears
it. IDs are opaque `rol_`-prefixed random strings. Assignment batches contain
1–100 items, deduplicate identical items, validate the entire batch and commit
atomically. Repeated valid additions/removals are idempotent. Missing parent
resources return 404; malformed bodies/unknown referenced items return 400;
conflicting role names return 409. Success follows each operation: POST role and POST role-users return 200;
POST role-permissions and POST user-permissions return 201; DELETE role and
DELETE role-permissions return 200; user-role POST/DELETE and direct permission
DELETE return 204. GET/PATCH return 200. Mutations return no body except role
creation/update. Freeze differences in Task 1.

Lists use `page=0`, `per_page=50` (1–100), `include_totals=false`, stable ID
ordering, and an empty JSON array for empty results. Totals envelopes use
`start`, `limit`, `total` and the appropriate `roles`, `users` or `permissions`
array. Role name filtering is case-insensitive substring matching. Role-users
also supports documented `from`/`take` checkpoint pagination: tenant/role-bound
opaque cursor, exclusive last user ID, no offset/checkpoint mixture. Its response wrapper is `{users:[...],next?:string}`; omit `next` on the
last page. Role-user summaries contain only `user_id`, `picture`, `name`, `email`. New early-access role-list checkpoint fields,
organization type/owner filters, group APIs and effective-role APIs are deferred;
reject unsupported query fields rather than quietly ignoring them. `type=tenant`
may be accepted as a no-op; organization ownership is never accepted.

Each operation uses its documented Management API scopes, frozen in the
inventory, requiring **all** listed scopes. Membership reads require
`read:users`, `read:roles`, `read:role_members`; role-user assignment requires
`update:roles` and `create:role_members`; user-role assignment/removal requires
`update:users` plus `create:role_members`/`delete:role_members`, respectively. Add them to tenant bootstrap/upgrade; existing restricted client
grants must not automatically gain scopes. The operator path continues to use
its existing tenant authorization, and ordinary user RBAC cannot bypass it.
Role-users responses use only documented user summary fields; never passwords,
provider credentials/tokens or private metadata. Protect all 16 operations with
missing-token, insufficient-scope and cross-tenant tests.

## 4. Domain and persistence

Create a focused `RBAC()` repository on `store.Store`. Models: `Role`,
`PermissionKey` (resource-server identifier plus permission name), and
`PermissionGrant` (key plus presentation data and sources). Store role membership,
role permissions and direct user permissions as distinct sets. Never encode
assignments in user metadata, consent grants, or client grants.

Every driver provides atomic batch validation/mutation, copy isolation,
transaction rollback, deterministic lists and an atomic authorization snapshot.
The snapshot reads the current API settings/scopes and the user's effective
permission union in one transaction. It is not built by following independently
paged management responses. SQL must obtain a consistent view even under
PostgreSQL READ COMMITTED; use an appropriate transaction/locking strategy or
one joined query. Memory and gRPC must provide the same semantics.

Use tenant-inclusive keys and constraints in tables for roles, user-role edges,
role-permission edges and user-permission edges. Persist API enforcement/dialect
fields with safe legacy defaults. Resolve a permission to an existing custom
API and currently defined scope at assignment time. Reject assignments to
reserved system APIs. A scope deletion removes both direct and role assignments
for that permission atomically with API update; recreating the same scope does
not restore old rights. API deletion removes its permission edges; role deletion
removes memberships and role grants; user/tenant deletion removes their edges.
Shared permission text in another API or tenant is unaffected.

Account linking must not union the secondary account's privileges into the
primary. Retain primary assignments; remove secondary assignments when that
standalone account is deleted by the existing link lifecycle. Unlink does not
copy assignments. Document this local authorization decision and test it.

Extend public store aliases, conformance tests and additive protobuf RPCs/fields.
Add an explicit RBAC capability check. A new server requires this capability
before serving authentication or management with a plugin: old plugins fail
startup clearly, including when they would otherwise discard new API settings.
Operators upgrade all server/plugin writers before enabling RBAC; mixed old
writers are not a supported rolling configuration. No silent downgrade to
legacy token behavior. Include this requirement in deployment documentation.

Seed API settings and role definitions use shared validation. Roles reference
APIs by identifier and permissions by name; apply APIs before roles. Keep the
existing create-only seed ownership policy: restarting must not overwrite
management edits. User assignments remain management operations in this plan.

## 5. Token enforcement

Let `D` be the custom API's currently defined permissions, `U` the union of the
user's direct and role-derived permissions for that API, and `R` the requested
scopes already capped by existing client-access and consent rules.

- RBAC enabled: API scope output is `R ∩ D ∩ U`.
- RBAC disabled: retain `R ∩ D`.
- Preserve separately allowed `openid`, `profile`, `email`, and `offline_access`;
  they are protocol scopes, not assignable RBAC permissions.
- For a user token with RBAC enabled and an `_authz` dialect, emit `permissions`
  as the sorted unique array `D ∩ U`, including unrequested permissions. Emit
  `[]` when empty, never null. With RBAC disabled, omit this claim (explicit
  local choice to verify in Task 1).
- No role-name claim, no permissions claim in ID tokens or `/userinfo`, and no
  cross-audience permissions. The current userinfo-only/operator flows remain
  unchanged. M2M scope authorization remains controlled by client grants; it
  does not consult user assignments or emit user permissions.

The permissions claim is broader than the scope claim by design. Existing
client/consent restrictions still cap scope. A resource server chooses which
claim to authorize against; tests must show that scope middleware does not
interpret permissions as scope.

Apply this to authorization-code exchange (database and federated login),
password and password-realm, device-code exchange and refresh. Read current
assignments at issuance, not just at login or device approval. A previously
created code cannot carry a removed permission into a new token.

The refresh family ceiling is the initially requested scope set after existing
API-definition, client-access and consent checks, **before** RBAC filtering.
For example, requesting `read:x write:x` while owning only `read:x` initially
issues scope `read:x`; assigning `write:x` later permits it on refresh because
it was already inside that ceiling. An unrequested `delete:x` never enters
refresh scope. Revoking then restoring `read:x` permits it again. Explicit
refresh narrowing keeps the existing family behavior; it does not enlarge the
ceiling. This is a local design decision, not claimed live Auth0 evidence.

Retain that original authorized scope ceiling on refresh families. Refresh
recomputes current RBAC permissions and intersects scopes with that ceiling;
new assignments do not expand scope beyond it. The `_authz` permissions array
still represents current assignments even when outside that ceiling. Preserve
existing refresh rotation, reuse detection, idle lifetime, origin binding and
explicit narrowing rules. Revocation takes effect at the next authorization
snapshot; an already-started issuance may finish using its earlier snapshot.
Already-issued JWTs remain valid until expiry. No stronger revocation timing is
claimed. Snapshot errors return server_error and release no token response.

| Dialect | JOSE `typ` | Client claim | `gty` | User permissions |
|---|---|---|---|---|
| `access_token` | `JWT` | `azp` | existing behavior | omitted |
| `access_token_authz` | `JWT` | `azp` | existing behavior | when RBAC enabled |
| `rfc9068_profile` | `at+jwt` | `client_id` | omitted | omitted |
| `rfc9068_profile_authz` | `at+jwt` | `client_id` | omitted | when RBAC enabled |

All profiles retain issuer, subject, audience, expiry, issuance time and unique
`jti`; legacy already emits `jti` and must not lose it. RFC profiles apply to
M2M too, without changing client-grant authorization. Continue RS256 and managed
keys. Extend signing with an explicit allowed token type; never change the
header of ID tokens or let a caller select an arbitrary algorithm. Adapt local
access-token consumers (especially `/userinfo`) to RFC `client_id` where needed,
while retaining strict ID/access token separation and reserved API restrictions.

## 6. Console and migration experience

Replace the Roles preview with a paginated list, create form and detail page
with Settings, Permissions and Users tabs. Support role deletion with explicit
confirmation; display affected member counts. Permission selection groups by
API. User detail gains Roles and Permissions tabs: show direct/inherited
sources and only offer direct removal for direct grants. Removing an inherited
grant directs the operator to its role. All empty, loading, failure and retry
states use the established components and locale catalog.

API settings expose Enable RBAC, the profile selector, and Add permissions to
access token. Preserve the base profile when toggling `_authz`; disable the
permissions toggle when RBAC is off while preserving a saved dialect. Explain
that existing tokens persist until expiry. Protect system API settings. Stale
tenant/route replies cannot overwrite new state; failed/uncertain writes retain
drafts and allow reload before retry. No proprietary Auth0 UI is copied.

Deploy CLI round trips include roles and role permissions plus both API fields,
in YAML/directory × generated/preserved credential modes. Resolve role IDs by
logical role identity and permissions by API identifier/name; do not compare
volatile IDs. User assignments are verified separately with the SDK and are
not falsely advertised as Deploy CLI resources. Missing role definitions,
permission edges or RBAC fields must fail comparisons. After import, assign a
local fixture user and prove effective scope/claim behavior through login.

## 7. Acceptance and handoff

Acceptance covers memory, SQLite, PostgreSQL, MySQL and gRPC; migration from the
pre-26 schema; scope deletion/recreation and account-link cleanup; every route
and scope; every user grant and all dialects; refresh revocation and store
failures; console pagination/accessibility; actual pinned CLI/SDK and Deploy CLI;
and the existing federation, custom-domain and conformance regressions.

Use a local API protected by `express-oauth2-jwt-bearer`: `requiredScopes` must
allow a scope present in `scope` and deny one found only in `permissions`.
Separately test explicit permissions-claim authorization. Inspect real signed
JWTs, including RFC type/client fields, rather than only mocked minter calls.

Record commands, actual outcomes, skips and unavailable services in a Plan 26
implementation record. Update compatibility matrix/decisions, API sources,
operator guide and roadmap only to the degree demonstrated. The implementation
record distinguishes completed work, actual verification results and
unavailable live evidence.
