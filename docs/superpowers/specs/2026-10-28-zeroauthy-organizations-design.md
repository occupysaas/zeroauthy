# zeroauthy — Plan 29: Organizations I (organizations, members, roles, connections, login)

- **Status:** Draft for maintainer review. Implementation has not started.
  Builder check done 2026-10-28; its ten questions are settled as author
  calls (§5.1, §5.3, §6 and §9–§12).
- **Date:** 2026-10-28
- **Roadmap:** [Plan 29](2026-10-19-zeroauthy-management-roadmap-design.md#plan-29--organizations-i-full-design).
- **Predecessor:** [Plan 28 implementation record](../2026-10-28-plan-28-implementation-record.md).
- **Builds on:** Plan 26 [roles and permissions](2026-10-27-zeroauthy-roles-permissions-design.md),
  Plan 22 branding/Universal Login, Plans 24–25 federation, Plans 27–28 Actions.
- **Implementation plan:** [Plan 29](../plans/2026-10-28-zeroauthy-plan-29-organizations.md).

## 1. Intent and scope

Organizations let one tenant serve many business customers. Each customer is
an *organization* with its own members, member roles, enabled connections and
branding, and users log in "through" an organization. That puts `org_id`
(and optionally `org_name`) in their tokens, along with permissions from their
roles in that organization.

The maintainer handed design to the author (2026-10-28: "it should work like
Auth0's"). The rule throughout is strict Auth0 parity: documented Auth0 behavior beats
local preference, and every deviation is recorded. Where Auth0's public docs are silent, Task 1 observes
the maintainer's tenant if Organizations is available there. Otherwise the
default below stands, and every default and author's call is frozen as
**D-0055**.

**In scope**

| Area | What |
|---|---|
| Management API | organizations CRUD and lookup by name; members; member roles (and effective roles); enabled connections; `GET /users/{id}/organizations`; `GET /organizations/{id}/roles/{role_id}/members` (§4) |
| Client fields | `organization_usage` and `organization_require_behavior` become live (inert since D-0039); `organization_discovery_methods` is stored and validated (§5.2) |
| Tenant setting | `allow_organization_name_in_authentication_api` becomes live (stored since Plan 19) |
| `/authorize` | `organization` parameter (ID, or name when the tenant setting allows); organization prompt before login; organization picker after login; membership and connection checks; auto-membership; organization signup (§5) |
| Tokens | `org_id` / `org_name` in ID and access tokens; organization-role permissions in access tokens; refresh tokens keep their organization (§6) |
| Hosted pages | organization branding on login pages; organization fields in page templates; the `organizations` prompt's two screens with custom text (§7) |
| Actions | `event.organization` in post-login, pre-user-registration and post-user-registration (§8) |
| Operators | per-tenant operators: the system API sets an operator's tenant list, and the console and Management API respect it (§9, carried in from the Plan 13 follow-up) |
| Console, seed, Deploy CLI | Organizations list and detail (§10) |

**Deferred**, each to the plan that owns it:

- Invitations (`/organizations/{id}/invitations`, the `invitation` parameter,
  the `user_invitation` email), `/organizations/{id}/client-grants` and grant
  `organization_usage`/`allow_any_organization` (inert since D-0041),
  discovery domains and email-based organization discovery, the
  `organization` parameter on `/oauth/token` (client credentials), and the
  Early Access `/organizations/{id}/clients` (app entitlement) →
  **Plan 30**. Until then the `invitation` parameter stays refused, and
  client credentials refuses `organization` with `invalid_request`.
- `GET /organizations/search` (Lucene/SCIM, eventually consistent) →
  Plan 30. It isn't needed for login, and its query language needs its own
  design.
- Organization groups (`/organizations/{id}/groups`, group roles) → with
  tenant groups, which Plan 26 left out (Plan 38 "remaining resources").
  Effective roles in Plan 29 are direct roles only.
- `token_quota` (Early Access) → Plan 35 with client-credentials organizations.
- `is_app_entitlement_active` (Early Access) → Plan 30.
- `/organizations/{id}/connections`, the newer "all connections" listing in
  node-auth0 7.4.0 → Task 1 checks the public reference. If it is a
  documented GA alias of `enabled_connections`, it joins Plan 29. If not, it
  moves to Plan 30, and either way this is recorded.
- The My Organization API → Plan 42. SAML/WS-Fed organization login → Plan 37.
- The `organization` parameter on change-password requests (followup list) →
  Plan 30, with invitations.

**Anti-goals.** These must never happen:

- A user who is not a member of an organization, and could not be made one by
  auto-membership, receives a token carrying that organization's `org_id`.
- A login through an organization uses a connection that the organization
  hasn't enabled.
- A token carries permissions from roles in an organization other than the
  one it was issued for.
- An organization name in a token or request lets anyone reach an
  organization while `allow_organization_name_in_authentication_api` is
  false.

Removing a member, deleting an organization or disabling a connection must stop
new tokens for that organization at the next login or refresh.

## 2. Evidence and constraints

Read `CLEAN_ROOM.md` first. Public sources consulted 2026-10-28:

- Overview: https://auth0.com/docs/manage-users/organizations/organizations-overview
- Behavior settings: https://auth0.com/docs/manage-users/organizations/configure-organizations/define-organization-behavior
- Login flows: https://auth0.com/docs/manage-users/organizations/login-flows-for-organizations
- Tokens: https://auth0.com/docs/manage-users/organizations/using-tokens
- Names in the Authentication API: https://auth0.com/docs/manage-users/organizations/configure-organizations/use-org-name-authentication-api
- Custom development: https://auth0.com/docs/manage-users/organizations/custom-development
- Management API reference: `post-organizations`, `get-organizations` and
  the member, member-role, enabled-connection and user-organization pages
  under `https://auth0.com/docs/api/management/v2/organizations/`.
- The post-login `event.organization` reference.
- node-auth0 7.4.0 (pinned, MIT) `management/api/resources/organizations/**`
  for the endpoint inventory and request/response types.

Facts found (in our words):

- **Client settings.**
  - `organization_usage` is `deny` (default; no organization login), `allow`
    (with or without one) or `require` (always through one).
  - `organization_require_behavior` is `no_prompt` (default; a request
    without a valid `organization` is rejected), `pre_login_prompt` (the user
    names the organization before logging in; only valid with `require`) or
    `post_login_prompt` (log in first, then choose an organization).
  - `organization_discovery_methods` is `email` and/or `organization_name`,
    and only applies with `pre_login_prompt`.
- **Organizations are not supported with** Classic Login/Lock, the resource
  owner password grant, the device flow, or WS-Fed with Auth0 as the IdP.
  There are no per-organization custom domains.
- **Organization object.**
  - `name` is 1–50 characters in the `organization-name` format and unique
    within the tenant.
  - `display_name` is 1–255 characters.
  - `branding` holds `logo_url` (https) and `colors.primary` and
    `colors.page_background` (hex; both required once `colors` is present).
  - `metadata` has at most 25 keys, each value a string of at most 255
    characters, or null.
  - `enabled_connections` at create time holds at most 10 entries, each with
    `connection_id`, `assign_membership_on_login`, `show_as_button`
    (enterprise only, default true) and `is_signup_enabled` (database only,
    default false).
  - `third_party_client_access` is `block` (default) or `allow`.
  - Responses: 201 on create, 409 for a duplicate name.
  - Scopes: `create:organizations`, and `create:organization_connections`
    when connections are supplied.
- **Listing.** Offset pagination (`page` up to 1000, `per_page` up to 100,
  `include_totals`) or checkpoint pagination (`from`, `take` up to 100,
  `next`). Checkpoint is required past 1000. `sort` accepts `name`,
  `display_name` or `created_at` with `1`/`-1`.
- **Tokens.**
  - ID and access tokens carry `org_id`. They also carry `org_name` when the
    tenant allows names.
  - Third-party apps get no ID token, but their access tokens carry `org_id`.
  - With an organization, the access token's `permissions` include those
    from the member's roles in that organization only. Without one, tenant
    roles behave as before.
- **Names.**
  - With the tenant setting on, `organization` accepts a name or an ID.
  - `org_name` is the `name`, never the display name.
  - The setting is tenant-wide.
- **Login flows.**
  - A user who belongs to several organizations under "Business Users"
    reaches a picker after login that shows up to 20 organizations.
  - Auto-membership (`assign_membership_on_login`) makes the user a member on
    login through that connection. Under the post-login prompt it applies
    only when exactly one organization has the connection enabled with
    auto-membership.
  - Identifier-first routing considers connections enabled for both the
    application and the organization.
- **Actions.** `event.organization` has `id`, `name`, `display_name` and
  `metadata`.

**Not documented publicly.** Task 1 freezes each of these as D-0055,
observing the maintainer's tenant through the documented Management and
Authentication APIs when the `OBS_AUTH0_*` observer credentials and an
Organizations-capable tenant are available:

1. `/authorize` errors and where they surface. These are the defaults
   (bodies are error codes only; the descriptions are ours):
   - **Unknown organization**, or a name while names are off:
     `invalid_request` to the redirect URI.
   - **`organization` sent to a `deny` client:** `invalid_request`.
   - **Missing organization with `require` + `no_prompt`:** `invalid_request`.
   - **Not a member and no auto-membership:** `access_denied`, redirected
     after authentication.
   - **Connection not enabled for the organization:** `invalid_request`
     before authentication when the request names it (`connection=`).
     Otherwise that connection is simply not offered.
   - **Third-party client with `third_party_client_access: block`:**
     `access_denied`.
   - **No eligible organization in the post-login picker** (`require`, and
     the user is in none): `access_denied`.
   - An error that can't be redirected safely renders the existing hosted
     error page (D-0026).
2. `prompt=none` with an organization. Default:
   - A session user who is a member, or who auto-membership can add, gets
     tokens silently.
   - Otherwise the result is `login_required`.
   - `require` + `post_login_prompt` without `organization`: silent success
     if the user has exactly one eligible organization, otherwise
     `interaction_required`.
3. Whether tenant roles and direct permissions still apply in an organization
   login. Default:
   - **Yes:** `permissions` is the union of the user's tenant roles, direct
     permissions and active-organization roles, filtered by the API as in
     Plan 26.
   - The docs only say that roles from *other* organizations don't apply.
4. Refresh with organizations. Default:
   - A refresh token keeps the organization it was issued for.
   - Each refresh re-checks that the organization exists and that the user is
     still a member. A failed check is `invalid_grant`, and the token is not
     revoked.
   - Organization-role permissions are recomputed on each refresh.
5. `allow` + `post_login_prompt` without `organization`. Default: no picker;
   the user logs in as an individual. The docs describe the picker only for
   Business Users.
6. `is_signup_enabled` without `assign_membership_on_login`. Default: `400`.
   Signup without auto-membership would create a user who then fails the
   membership check.
7. The resource owner password and device grants for a `require` client.
   Default: `unauthorized_client`. For `deny`/`allow` clients they work
   unchanged and never carry an organization.
8. The organization `name` format. Default:
   - Lowercase ASCII letters, digits, `-` and `_`.
   - Starts with a letter or digit, 1–50 characters.
   - Task 1 confirms against the public schema.
9. Limits, from Auth0's entity limit policy where it is public. Local
   defaults:
   - 10,000 organizations per tenant
   - 50 enabled connections per organization (10 at create, as documented)
   - 50 roles per member
   - unlimited members
   - 1,000 organizations per user listed (paginated)
10. Membership removal versus live sessions. Default:
    - Removal affects only the next authorization or refresh.
    - Sessions stay valid for non-organization logins.

Global constraints: Go 1.26.7; Node ≥ 22.13 (Actions only). SQL migrations are
additive, and the next number is **0025**. The next decision is **D-0055**.
New plugin RPC `OrganizationsCapabilities`, version 1. Tests never contact
Auth0. Every check fails closed. Plan 19's database-test hold does not apply.

## 3. Domain

New domain types in `internal/store` (names are the builder's):

- **Organization.** `ID` (`org_` + 16 random URL-safe characters, ≤ 50),
  `TenantID`, `Name` (unique per tenant), `DisplayName`, `Branding`
  (`LogoURL`, `PrimaryColor`, `PageBackground`), `Metadata`
  (`map[string]*string`), `ThirdPartyClientAccess`, `CreatedAt`,
  `UpdatedAt`.
- **OrganizationConnection.** `(TenantID, OrganizationID, ConnectionID)`, with
  `AssignMembershipOnLogin`, `ShowAsButton`, `IsSignupEnabled`.
- **OrganizationMember.** `(TenantID, OrganizationID, UserID)` and
  `CreatedAt`.
- **OrganizationMemberRole.** `(TenantID, OrganizationID, UserID, RoleID)`.
  Roles are the tenant's Plan 26 roles. Auth0 assigns tenant roles inside
  organizations and has no separate "organization role" object.

Cascades, all in the same transaction as the deletion that causes them:

- Deleting an organization removes its connections, members and member roles.
- Deleting a user removes their memberships and member roles.
- Deleting a connection removes it from every organization.
- Deleting a role removes its member assignments.
- Removing a member removes that member's roles.

Validation lives in a pure `internal/orgrules` package, mirroring
`rbacrules`/`actionsrules`. It checks the name format, display name, branding
URL/colors, metadata limits, connection flag applicability (`show_as_button`
on enterprise strategies only, `is_signup_enabled` on database only, §2 item 6)
and the limits.

## 4. Management API

All routes are under `/api/v2`. Shapes, pagination and status codes follow
the public reference and node-auth0 7.4.0 types. Unknown body properties
return `400`, and every route returns `404` across tenants.

| Operation | Scope | Notes |
|---|---|---|
| `GET /organizations` | `read:organizations` | offset and checkpoint pagination, `sort` (§2) |
| `POST /organizations` | `create:organizations` (+ `create:organization_connections` with `enabled_connections`) | 201; 409 duplicate name; ≤ 10 connections |
| `GET /organizations/{id}` / `GET /organizations/name/{name}` | `read:organizations` | 404 unknown |
| `PATCH /organizations/{id}` | `update:organizations` | `name`, `display_name`, `branding`, `metadata`, `third_party_client_access`. `branding`/`metadata` are replaced whole, as Auth0's PATCH does; Task 1 confirms |
| `DELETE /organizations/{id}` | `delete:organizations` | 204; cascades |
| `GET /organizations/{id}/members` | `read:organization_members` | `user_id`, `email`, `picture`, `name`, and `roles` with `fields=roles` (needs `read:organization_member_roles`); offset and checkpoint |
| `POST /organizations/{id}/members` | `create:organization_members` | `{members: [user_id…]}`, ≤ 10 per call; 204; unknown user 400 |
| `DELETE /organizations/{id}/members` | `delete:organization_members` | `{members: […]}`; 204 |
| `GET/POST/DELETE /organizations/{id}/members/{user_id}/roles` | `read/create/delete:organization_member_roles` | `{roles: [role_id…]}`; the user must be a member (400 otherwise) |
| `GET /organizations/{id}/members/{user_id}/effective-roles` | `read:organization_member_roles` | direct roles only until groups exist |
| `GET /organizations/{id}/roles/{role_id}/members` | `read:organization_members` | members holding that role |
| `GET /organizations/{id}/enabled_connections` | `read:organization_connections` | each entry includes the `connection` summary (`name`, `strategy`) |
| `POST /organizations/{id}/enabled_connections` | `create:organization_connections` | 201; 409 already enabled; connection must exist and be one the tenant can log in with |
| `GET/PATCH/DELETE /organizations/{id}/enabled_connections/{connection_id}` | `read/update/delete:organization_connections` | PATCH changes the three flags only |
| `GET /users/{id}/organizations` | `read:organizations` | offset pagination |

Other changes:

- `PATCH /clients/{id}` and `POST /clients` accept and enforce
  `organization_usage`, `organization_require_behavior` and
  `organization_discovery_methods`. `pre_login_prompt` without `require` is a
  `400`.
- Tenant settings make `allow_organization_name_in_authentication_api` live.
- The OpenAPI document, provenance (`x-source`), generated bindings and
  `make check-sources` cover every route.
- `GET /api/v2/organizations/{id}/members` returns a `401`/`403` matrix like
  existing resources.

## 5. Login with an organization

### 5.1 Resolving the organization

Before anything is shown, `/authorize` (and PAR, where a pushed request
carries `organization`) resolves the organization:

1. A `deny` client sending `organization` → `invalid_request`.
2. `organization` is matched as an ID first. It is matched as a name only
   while the tenant setting is on. A name match is exact; `name` is lowercase
   by format. Unknown → `invalid_request`.
3. A third-party client with the organization's `third_party_client_access`
   = `block` → `access_denied`.
4. No `organization`:
   - **`deny`/`allow`:** individual login.
   - **`require` + `no_prompt`:** `invalid_request`.
   - **`require` + `pre_login_prompt`:** the organization prompt (§5.2).
   - **`require` + `post_login_prompt`:** log in first, then the picker
     (§5.3).

The resolved organization ID (or the pending "choose after login" state) is
held in the authorization transaction (`AuthTransaction.Params`, under an
internal key) like the other bound request values, so a later request cannot
change it. Social and enterprise callbacks, identifier-first steps and
password reset reload that same transaction, so they all see it. MFA does
not exist yet (Plan 33). Author's calls:

- **PAR.** A pushed request's `organization` is bound with the pushed
  parameters. `/authorize?request_uri=` cannot add or override it, under the
  existing Plan 10 rule.
- **Codes and tokens.** The authorization code records the organization ID,
  and the token endpoint reads it only from the code.

### 5.2 Organization prompt (before login)

A hosted screen (`organizations` prompt, `organization-selection` screen)
asks for the organization name. An unknown name re-renders with an error and
does not say whether a similarly named organization exists. The chosen
organization then continues as in §5.1 step 3.

Author's call: `organization_discovery_methods` is stored and validated, but
Plan 29 always asks for the name. Email discovery needs discovery domains
(Plan 30). D-0055 records this, and a client configured for `email` only
still gets the name field until Plan 30.

### 5.3 Login page and picker

With an organization in the transaction:

- **Connections offered.** The login page offers the intersection of the
  connections enabled for the client (each connection's `enabled_clients`,
  Plan 15) and the organization's enabled connections. If the intersection is
  empty, the page behaves as it does today for a client with no enabled
  connections, including under `prompt=none` (author's call).
- **`show_as_button: false`.** The connection is hidden from the button
  list but still usable with `connection=`.
- **Database signup.** Shown only when the database connection's
  `is_signup_enabled` is true, on top of the existing client/connection
  signup rules.
- **`connection=` naming a connection outside that intersection** →
  `invalid_request`.
- **Identifier-first routing** (Plan 25 home-realm by domain, where it
  exists) considers only that intersection.

**Picker.** `require` + `post_login_prompt` without an organization shows the
picker after a successful authentication (`organizations` prompt,
`organization-picker` screen). It lists the user's organizations where the
connection just used is enabled. When an existing session satisfied the
login, that means the connection of the session's last authentication
(author's call). The picker shows at most 20, sorted by display name, with the
organization's logo where set:

- one eligible organization is selected automatically;
- none, but exactly one organization has that connection enabled with
  auto-membership → that organization, with membership granted (Auth0's
  documented rule);
- otherwise none → `access_denied`.

### 5.4 Membership, auto-membership, signup

After authentication, with an organization chosen, before consent and token
issuance:

- **Member** → continue.
- **Not a member, and the organization has this connection enabled with
  `assign_membership_on_login`** → add membership in the same transaction as
  the login's user write, then continue.
- **Otherwise** → `access_denied` to the redirect URI. The session remains,
  because the user did authenticate.

**Organization signup.** On a database connection with `is_signup_enabled`
(which requires auto-membership, §2 item 6), the new user becomes a member in
the user-insert transaction. Pre-user-registration Actions run before the
insert with `event.organization` (§8), and post-user-registration jobs carry
it.

**Social and enterprise first login.** The membership is created in the
transaction that creates or links the user.

**Consent and `prompt=none`.**

- Consent (Plan 9) is unchanged, except that third-party access follows
  §5.1 step 3.
- `prompt=none` follows §2 item 2.
- A session alone never selects an organization. Every authorization request
  resolves one afresh.

## 6. Tokens

- **ID token:** `org_id`, plus `org_name` when the tenant setting is on.
  These are reserved claims, so Actions `setCustomClaim` cannot overwrite
  them (Plan 27 reserved-claim rule extended).
- **Access token** (JWT for a custom API, and the `/userinfo` audience where
  a JWT is issued today): `org_id` and optional `org_name`. Plan 26
  `permissions` and RBAC scopes include the member's roles in that
  organization (§2 item 3). The four token dialects from Plan 26 are applied
  unchanged.
- **Refresh tokens and authorization codes** store the organization ID.
  - Each refresh resolves the organization and membership again (§2 item 4).
  - `org_name` is re-read on each refresh. Auth0 warns that long-lived tokens
    keep an old name, and zeroauthy issues new tokens with the current name.
  - A refresh-token rotation family keeps the organization of its first token.
- **`/userinfo`** returns `org_id`/`org_name` when the access token carries
  them.
- **The resource owner password and device grants** never carry an
  organization (§2 item 7).
- **Permission resolution** (author's call). The Plan 26 resolver takes an
  optional organization ID and returns, in one call, the union of direct
  permissions, tenant roles and that organization's member roles. The API's
  RBAC filtering is then applied once to the union, for all four token
  dialects.
- **Refresh after a client policy change** (author's call; fails closed):
  - A refresh token carrying an organization is refused with `invalid_grant`
    if the client is now `deny`.
  - A refresh token without one is refused if the client is now `require`.
- **Third-party clients.** `org_name` follows the tenant setting, exactly as
  for first-party clients. The consent page text is unchanged.

## 7. Hosted pages and branding

- **Organization branding.** When an organization is in the transaction,
  login, signup, consent and error pages use its `branding.logo_url` and
  colors over the tenant theme's logo and primary/page-background colors.
  Everything else (theme fonts, borders, widget layout) stays tenant-level, as
  Auth0 does.
- **Page templates** (Plan 22 Liquid) gain the `organization` object:
  - `id`, `name`, `display_name`, `metadata`
  - `branding.logo_url`, `branding.colors.primary`,
    `branding.colors.page_background`

  It is empty when there is no organization. This replaces the current
  "renders without organization context" behavior.
- **Prompts.** The `organizations` prompt joins the custom text catalogue.
  Its two screens are `organization-selection` and `organization-picker`,
  with keys taken from the public custom text reference. The English catalogue
  and i18n plumbing follow Plan 4.
- **Copy.** Pages are original zeroauthy layouts. No Auth0 page markup is
  copied.

## 8. Actions

`event.organization` (`id`, `name`, `display_name`, `metadata`) is set in:

- post-login, when the login has an organization;
- pre-user-registration and post-user-registration, for organization signup.

It is absent otherwise, as now. The Plan 28 queued jobs seal it into the job
envelope. Post-login `api.access.deny` works as before. No organization
`api` members exist in Auth0's post-login reference, so none are added.

## 9. Per-tenant operators (carried in)

Operators already carry a tenant list (`["*"]` today):

What exists today, so Plan 29 doesn't rebuild it:

- system create/list/delete operator endpoints (`internal/mgmt/system.go`);
- `store.Operator.Tenants` in every store;
- a `403` for operator tokens whose token claim **or** stored list lacks the
  tenant (`internal/mgmt/auth.go`).

New:

- The system API gains `PATCH /system/operators/{id}` (`tenants: [...]` or
  `["*"]`, system-operator scope only).
- The stored list is the authority. Because the existing check reads it on
  every request, shrinking a list takes effect immediately, even for tokens
  that were already issued.
- A PATCH or delete that would leave no operator able to manage the system
  tenant (`"*"` or the system tenant's name) is refused with `409` (author's
  call).
- The console tenant switcher lists only the allowed tenants.
- A list without the system tenant can never call the system API.

These are local zeroauthy endpoints, with no Auth0 counterpart. Plan 47
(hosting) builds on them. A short section of D-0055 records the shapes.

## 10. Console, seed, Deploy CLI

- **Console.** User Management → Organizations: a list with search by name
  (client-side over a page) and create; and a detail page with these tabs:
  - **Settings:** name, display name, metadata, third-party access.
  - **Branding:** logo URL and the two colors, with a live preview swatch.
  - **Connections:** enable or disable, with the three flags; the flags not
    applicable to a connection's strategy are disabled.
  - **Members:** add by user search, remove, and member roles.

  User detail gains an Organizations tab, and Application settings gain the
  three organization fields with the `pre_login_prompt` rule. All strings are
  localized, and stale replies are ignored, as on the existing pages.
- **Seed.** `organizations` (with connections by name, members, and member
  roles by role name). Seeded objects are create-only like other seeded
  resources. A member is given by `user_id`, or by `email` together with a
  `connection` name, because email alone is not unique across connections.
  An unresolvable member, connection or role fails startup, like other seed
  references (author's call).
- **Deploy CLI 9.1.0.** Task 1 reads its `organizations` handler. Plan 29
  adds the handler to the four-cell matrix (generated/preserved credentials ×
  YAML/directory), covering organizations, connections and, if the tool
  exports them, member roles. If the pinned tool doesn't handle something, it
  is recorded as unavailable.

## 11. Storage and plugins

- **Migration 0025** (×3 dialects): four tables with tenant-inclusive primary
  keys:
  - unique `(tenant_id, name)` on organizations;
  - an index on members by `(tenant_id, user_id)` for
    `/users/{id}/organizations`;
  - cascades implemented in the store, because foreign keys differ across
    dialects (existing practice).
- **Memory store and `pkg/storetest`** `Organizations` conformance: CRUD,
  unique names under concurrency, pagination in both modes and with `sort`,
  cascades, tx rollback, tenant deletion cleanup, limits.
- **gRPC plugin:** Organizations RPCs and `OrganizationsCapabilities` v1.
  With a plugin that lacks the capability, the server starts with a warning,
  and there is no startup scan (author's call). In that case:
  - organization Management routes return `501`;
  - writes setting `organization_usage` ≠ `deny` return `501`;
  - any `organization` parameter is `invalid_request`.

## 12. Listing details (author's calls)

- **Member listings.** `GET /organizations/{id}/members` and the role-members
  listing paginate the membership table, ordered by `user_id` ascending, in
  both offset and checkpoint modes (the checkpoint cursor is the last
  `user_id`). User fields are joined per page.
- **Field selection.** The `fields`/`include_fields` semantics and `per_page`
  limits come from the public reference, and Task 1 freezes them. There is no
  search parameter; Auth0's reference has none.
- **Connection summary.** The `connection` summary (`name`, `strategy`) in
  enabled-connection responses needs only the organization-connection read
  scope, as the reference's response shape implies.

## 13. Acceptance

- **Contract tests.** Every §4 operation has contract tests: shapes, errors,
  scopes, limits and cross-tenant 404.
- **Runtime tests** cover each §5 branch, each §2 D-0055 default, token
  claims and permissions (§6) and refresh re-checks. The four anti-goals in
  §1 are explicit tests on both the code-flow and PAR paths.
- **Storage.** Shared conformance on memory, SQLite, PostgreSQL, MySQL and the
  plugin, plus the migration upgrade and concurrency tests.
- **Console.** Vitest for every tab plus the stale-reply and write-validation
  cases, and `make console`.
- **E2E.**
  - auth0-cli 1.37.0 `orgs` commands: create, list, show, update, delete,
    members, roles.
  - node-auth0 7.4.0 for each Plan 29 SDK method.
  - auth0-spa-js (or auth0-react) with `organization`.
  - Playwright: pre-login prompt, post-login picker, non-member denial,
    auto-membership, organization signup, and organization branding on the
    login page.
  - The Deploy CLI four-cell matrix.
- **Regression.** Every existing lane plus local OIDF conformance, with
  results recorded in the Plan 29 implementation record.
