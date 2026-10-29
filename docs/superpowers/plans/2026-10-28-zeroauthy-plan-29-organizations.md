# Plan 29 — Organizations I Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Auth0-compatible Organizations: organizations, members, member roles, enabled connections, and login through an organization. This covers the organization prompt, the picker, membership checks and auto-membership. Tokens gain `org_id`/`org_name` and organization-role permissions. Organization branding reaches hosted pages, and Actions get `event.organization`. Per-tenant operators are included, along with console, seed and Deploy CLI support.

**Architecture:**

- **Pure rules.** A pure `internal/orgrules` package validates organizations and holds the frozen contract inventory.
- **Store.** A new `store.Organizations` repository is implemented by memory, SQL (migration 0025) and gRPC plugin stores (capability `OrganizationsCapabilities` v1).
- **Resolution.** `/authorize` resolves the organization into the existing `AuthTransaction.Params`.
- **Login.** Hosted login filters connections, runs the prompt and picker, and enforces membership before consent.
- **Tokens.** Codes and refresh tokens carry the organization ID. The Plan 26 permission resolver gains an optional organization.

**Tech Stack:** Go 1.26.7, existing protobuf/OpenAPI generators, SQLite/PostgreSQL/MySQL, Vue/TypeScript, Vitest/Playwright, pinned auth0-cli 1.37.0, node-auth0 7.4.0, auth0-spa-js (pinned in `tests/e2e`), Deploy CLI 9.1.0.

**Spec:** [Organizations I design](../specs/2026-10-28-zeroauthy-organizations-design.md). Read it in full; §n references point there.

**Status:** Not started. The maintainer approved the spec on 2026-10-28.

## Global Constraints

- Go 1.26.7 (`GOTOOLCHAIN=go1.26.7`) and existing stacks. Do not hand-edit generated code; regenerate it.
- Strict Auth0 parity. Every default and author's call in spec §2 items 1–10 and §5–§12 is frozen as **D-0055**, marked "documented", "observed" or "local decision".
- SQL migrations are additive. The next number is **0025** (`0025_organizations.sql` for each of sqlite/postgres/mysql). The next decision is **D-0055**.
- Plugin RPC `OrganizationsCapabilities` is version **1**. A plugin without it starts with a warning, without scanning data. In that case organization routes and writes of `organization_usage` ≠ `deny` return `501`, and the `organization` parameter is `invalid_request`.
- Organization `name`: 1–50 characters, unique per tenant, format per D-0055 (default `^[a-z0-9][a-z0-9_-]{0,49}$`). `display_name`: 1–255.
- Branding: `logo_url` https or null; when `colors` is present, both `primary` and `page_background` are hex.
- Metadata: ≤ 25 keys, each value a string ≤ 255 characters or null.
- Enabled connections: ≤ 10 in `POST /organizations`, ≤ 50 per organization. `show_as_button` only on enterprise strategies (default true). `is_signup_enabled` only on database connections (default false) and requires `assign_membership_on_login`.
- Local limits (D-0055): 10,000 organizations per tenant; 50 roles per member; ≤ 10 user IDs or role IDs per member/role POST or DELETE.
- Pagination: offset (`page` ≤ 1000, `per_page` 1–100, default 50, `include_totals`) and checkpoint (`from`, `take` 1–100, `next`). Organization `sort` is `name|display_name|created_at` with `:1|:-1`. Member listings are ordered by `user_id` ascending.
- The picker shows at most 20 organizations, sorted by display name.
- The organization ID is `org_` plus 16 random URL-safe characters.
- `org_id`/`org_name` are reserved claims. `org_name` appears only while `allow_organization_name_in_authentication_api` is true.
- Fail closed. A token never carries an organization the user is not a member of, nor permissions from another organization's roles.
- Invitations, organization client grants, discovery domains, `/organizations/search`, groups, `token_quota` and `is_app_entitlement_active` stay deferred (spec §1).
- Tests never contact Auth0. Plan 19's database-test hold does not apply to this plan.

## Review Focus

1. **A removed member's refresh token.** Removing a member or deleting an organization, then refreshing a token issued in that organization, must give `invalid_grant`. It must not give a token without `org_id` (Task 9).
2. **Name vs ID collision.** An organization *named* like another organization's ID, with names enabled, must resolve the ID match, never the name match (Task 7).
3. **Picker tampering.** The picker form posting an organization ID the user isn't eligible for, or one from another tenant, must re-render with an error. It must not log the user in to that organization (Task 8).
4. **Revocation inside an open login.** A connection disabled for an organization, or auto-membership turned off, between page load and credential submit must not let the login through (Task 8).
5. **A shrunk operator list.** An operator whose tenant list is reduced while their console session is open must get `403` on the next Management call, and the switcher must drop the tenant on reload (Task 11).

## Files, interfaces and execution order

New files:

- `internal/orgrules/{rules.go,inventory.go,inventory.json}` and tests
- `internal/store/organizations.go`
- `internal/store/memory/organizations.go`
- `internal/store/sqlstore/organizations.go`
- migrations `0025_organizations.sql` ×3
- `pkg/storetest/organizations.go`
- `internal/store/grpcstore/organizations.go`
- `internal/mgmt/{organizations.go,organization_members.go,organization_connections.go}`
- `internal/authz/organization.go`
- `internal/login/organization.go`
- `internal/oauth/organization.go`
- `console/src/pages/organizations/`
- `tests/e2e/run-m29-organizations.sh` and the `make e2e-organizations` target
- `docs/organizations.md`

Order: 1 → 2 → … → 14. Each task includes its own verification and commit. Test names below are new tests to create.

Before claiming a memory-only focused run, confirm that it actually executes tests. Commit the named files and generated outputs only.

## Task 1: Freeze compatibility contracts

**Files:**

- Create:
  - `internal/orgrules/inventory.json`
  - `internal/orgrules/inventory.go`
  - `internal/orgrules/inventory_test.go`
  - `docs/compat/observations/organizations.md`
- Modify:
  - `docs/compat/{decisions,changelog-review,matrix}.md`
  - spec corrections backed by evidence

**Interfaces:** `orgrules.Inventory() []OperationContract`, using the same shape as `rbacrules.OperationContract`: method, path, scopes, request/response shape, pagination, statuses, limits, source URL and classification. Also `orgrules.Deferred() []DeferredItem` (name, target plan).

- [ ] Write `TestOrganizationsInventory`. Assert:
  - the spec §4 operations, with the scopes in that table;
  - the client fields and the tenant setting;
  - every spec §1 deferred item with its target plan;
  - every Global Constraints limit with a source or D-0055;
  - every D-0055 item from spec §2 (1–10), each marked documented/observed/local.
- [ ] Run `go test ./internal/orgrules -run '^TestOrganizationsInventory$' -count=1`; expect FAIL.
- [ ] Read each spec §2 source and each Management reference page for the §4 routes. Freeze:
  - field-level schemas (the `name` format, PATCH replace vs merge for `branding`/`metadata`, member `fields`/`include_fields`);
  - status codes and checkpoint wrappers.

  Check whether `/organizations/{id}/connections` is a documented GA alias (spec §1) and record the ruling. Review the public changelog from 2026-10-28 onward and log it.

  Read the pinned auth0-cli 1.37.0 `orgs` commands, node-auth0 7.4.0 organizations resources and Deploy CLI 9.1.0 organizations handler. Record what each exposes, with repo/file/version provenance.
- [ ] Observation:
  - **When `OBS_AUTH0_*` credentials (read via `fish -c`) and an Organizations-capable tenant are available:** in a separate observer session, observe spec §2 items 1–8 through documented Management/Authentication API calls and auth0-cli. The observer writes notes only, without verbatim messages.
  - **Otherwise:** record "unavailable" and keep the spec defaults.
- [ ] Write D-0055 (every default, author's call and observation result). Populate the inventory, rerun, expect PASS. Commit `docs: freeze Organizations compatibility contracts`.

## Task 2: Domain rules, store interface and memory store

**Files:**

- Create:
  - `internal/orgrules/rules.go`, `rules_test.go`
  - `internal/store/organizations.go`
  - `internal/store/memory/organizations.go`
  - `pkg/storetest/organizations.go`
- Modify:
  - `internal/store/store.go` (`Organizations() Organizations`)
  - `internal/store/types.go` (`AuthCode.OrganizationID`, `RefreshToken.OrganizationID`, both `string`, empty for non-organization tokens; memory stores them)
  - memory clone/tenant-deletion code
  - the user/connection/role delete paths for cascades
  - sql and grpc stores, returning `store.ErrOrganizationsUnavailable` until Tasks 3–4

**Interfaces:**

- `store.Organization{TenantID, ID, Name, DisplayName string; Branding *OrgBranding; Metadata map[string]*string; ThirdPartyClientAccess string; CreatedAt, UpdatedAt time.Time}` and `store.OrgBranding{LogoURL *string; Colors *OrgColors{Primary, PageBackground string}}`.
- `store.OrganizationConnection{TenantID, OrganizationID, ConnectionID string; AssignMembershipOnLogin, ShowAsButton, IsSignupEnabled bool}`.
- `store.OrgPage{Page, PerPage int; IncludeTotals bool; From string; Take int; Sort string}` and `store.OrgResult[T]{Items []T; Total int; Next string}`.
- `store.Organizations` interface:
  - `Create(ctx, *Organization, []OrganizationConnection) error`
  - `Get(ctx, tid, id)`, `GetByName(ctx, tid, name) (*Organization, error)`
  - `List(ctx, tid, OrgPage) (OrgResult[Organization], error)`
  - `Update(ctx, *Organization) error`, `Delete(ctx, tid, id) error`
  - `Connections(ctx, tid, orgID, OrgPage)`, `GetConnection(ctx, tid, orgID, connID)`, `PutConnection(ctx, OrganizationConnection, create bool) error`, `DeleteConnection(ctx, tid, orgID, connID) error`
  - `ConnectionsByConnection(ctx, tid, connID) ([]OrganizationConnection, error)` for the picker auto-membership rule
  - `Members(ctx, tid, orgID, OrgPage) (OrgResult[string], error)`, `AddMembers(ctx, tid, orgID string, userIDs []string) error`, `RemoveMembers(...)`, `IsMember(ctx, tid, orgID, userID) (bool, error)`
  - `UserOrganizations(ctx, tid, userID, OrgPage) (OrgResult[Organization], error)`
  - `MemberRoles(ctx, tid, orgID, userID, OrgPage) (OrgResult[string], error)`, `ChangeMemberRoles(ctx, tid, orgID, userID string, add bool, roleIDs []string) error`, `RoleMembers(ctx, tid, orgID, roleID, OrgPage) (OrgResult[string], error)`
- Errors: `store.ErrConflict` (duplicate name or connection), `ErrNotFound`, `ErrPrecondition` (limit, or roles for a non-member).
- `orgrules.NormalizeOrganization(in) (store.Organization, error)`, `orgrules.ValidateConnection(strategy string, oc store.OrganizationConnection) error`, `orgrules.NewID() string`.

- [ ] Write `TestOrgRules`, table-driven over every Global Constraints value at and one beyond each limit: name format, display name, branding (https, both colors required, null logo), metadata (25/26 keys, 255/256 characters, null values), `show_as_button` on database refused, `is_signup_enabled` without auto-membership refused.
- [ ] Add `pkg/storetest` `Organizations` subtests:
  - CRUD; unique name under 10 concurrent creates (exactly one succeeds);
  - offset and checkpoint pagination with each `sort`;
  - member ordering by `user_id`; `IsMember`;
  - roles refused for non-members; the role-members listing;
  - each cascade from spec §3 (organization, user, connection, role, member removal);
  - tenant deletion; tx rollback;
  - the 10,000/50/50 limits (with test-sized overrides through an exported limits struct).
- [ ] Run `go test ./internal/orgrules ./internal/store/memory -run 'Test(OrgRules|Conformance)' -count=1`; expect FAIL.
- [ ] Implement. Then rerun, plus `go build ./...`; expect PASS. Commit `feat: add Organizations domain and memory persistence`.

## Task 3: SQL storage and migration 0025

**Files:**

- Create:
  - `internal/store/sqlstore/organizations.go`
  - `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0025_organizations.sql`
  - `internal/store/sqlstore/organizations_test.go`
- Modify: the sqlstore cascade paths for users/connections/roles/tenants.

**Interfaces:** satisfies `store.Organizations` (Task 2).

- [ ] Add `TestOrganizationsMigration` (a 0024 database upgrades; fresh and upgraded schemas agree) and `TestOrganizationsConcurrency` (concurrent same-name creates yield one row and `ErrConflict`; concurrent `AddMembers` of the same user is idempotent; organization delete racing a member add leaves no orphan rows).
- [ ] Run `./scripts/test-sql.sh -run 'Test(Organizations|Conformance)' ./internal/store/sqlstore/...`; expect FAIL. If default ports are taken, use the script's port override and record that.
- [ ] Implement the `organization_id` columns (nullable, default empty) on the auth code and refresh token tables in the same 0025 migration, with round-trip coverage in the conformance suite.
- [ ] Implement tables with tenant-inclusive primary keys:
  - `UNIQUE(tenant_id, name)`;
  - member index `(tenant_id, user_id)`;
  - store-side cascades in the caller's transaction.
- [ ] Rerun; require actual SQLite/PostgreSQL/MySQL results. Commit `feat: persist Organizations across SQL drivers`.

## Task 4: Plugin protocol and capability

**Files:** Modify `proto/store/v1/store.proto`, `internal/store/grpcstore/{client,server,codec}.go`, `pkg/storeplugin`. Create `internal/store/grpcstore/organizations.go` and `organizations_test.go`.

**Interfaces:** the `Organizations*` RPCs mirror Task 2 methods. Additive proto fields carry `OrganizationID` on auth codes and refresh tokens. `rpc OrganizationsCapabilities(PingRequest) returns (OrganizationsCapabilitiesResult)` with `version = 1`. `store.OrganizationsSupported(st store.Store) bool` is used by Tasks 5–8 for the `501` gates.

- [ ] Write the tests:
  - `TestOrganizationsPluginRoundTrip`: every method, `ErrConflict`/`ErrPrecondition`/`ErrNotFound` mapping, and pagination `Next` round trip.
  - `TestOrganizationsOldPlugin`: a plugin without the RPC starts with a warning, and `OrganizationsSupported` is false.
- [ ] Run `go test ./internal/store/grpcstore -run 'TestOrganizations' -count=1`; expect FAIL.
- [ ] Implement. Run `go generate ./...` twice (stable), rerun, `go build ./...`; expect PASS. Commit `feat: expose Organizations through storage plugins`.

## Task 5: Management API — organizations and enabled connections

**Files:**

- Create:
  - `internal/mgmt/organizations.go`
  - `internal/mgmt/organization_connections.go`
  - `internal/mgmt/organizations_test.go`
- Modify:
  - `api/management.yaml` (routes, schemas, `x-source`)
  - generated `internal/gen/mgmtapi`
  - `internal/mgmt` router and scope table

**Interfaces:**

- Handlers: `(*API).ListOrganizations`, `CreateOrganization`, `GetOrganization`, `GetOrganizationByName`, `UpdateOrganization`, `DeleteOrganization`, `ListOrganizationConnections`, `CreateOrganizationConnection`, `GetOrganizationConnection`, `UpdateOrganizationConnection`, `DeleteOrganizationConnection`.
- JSON shapes follow the Task 1 inventory exactly.

- [ ] Write `TestOrganizationsContract`. For every operation in the first and last rows of spec §4 (CRUD, by-name lookup, enabled connections), check:
  - response shape and both pagination wrappers;
  - 201/204/409 statuses; 400 on unknown properties and on each rule violation;
  - the `create:organization_connections` requirement when `enabled_connections` is posted;
  - 401/403 scope matrix; cross-tenant 404;
  - the `connection` summary in listings;
  - PATCH replacement semantics as frozen in Task 1;
  - `501` with an old plugin.
- [ ] Run `go test ./internal/mgmt ./internal/server -run 'TestOrganizations' -count=1`; expect FAIL.
- [ ] Implement. If Task 1 ruled `/organizations/{id}/connections` a documented GA alias, add it here with its own contract cases. Regenerate; `make check-sources`. Rerun; expect PASS. Commit `feat: manage organizations and their connections`.

## Task 6: Management API — members, roles, user organizations, client and tenant fields

**Files:**

- Create:
  - `internal/mgmt/organization_members.go`
  - `internal/mgmt/organization_members_test.go`
- Modify:
  - `internal/mgmt/clients.go` (remove the D-0039 inert handling for the three organization fields)
  - `internal/clientrules`
  - tenant settings handling of `allow_organization_name_in_authentication_api`
  - `api/management.yaml` and the generated code
  - `internal/mgmt/users.go` (route `GET /users/{id}/organizations`)

**Interfaces:**

- Handlers: `ListOrganizationMembers`, `AddOrganizationMembers`, `RemoveOrganizationMembers`, `ListOrganizationMemberRoles`, `AddOrganizationMemberRoles`, `RemoveOrganizationMemberRoles`, `ListOrganizationMemberEffectiveRoles`, `ListOrganizationRoleMembers`, `ListUserOrganizations`.
- `clientrules.ValidateOrganizationFields(usage, behavior string, methods []string) error`.

- [ ] Write `TestOrganizationMembersContract`:
  - members listing with joined user fields and `fields=roles` (needs `read:organization_member_roles`);
  - user-ID ordering in both pagination modes;
  - add/remove ≤ 10, unknown user 400, idempotent add;
  - member roles add/remove/list, non-member 400, unknown role 400, 50-role limit 400;
  - effective roles equal direct roles;
  - role members; user organizations;
  - scopes 401/403; cross-tenant 404.
- [ ] Write `TestClientOrganizationFields`:
  - each `organization_usage`/`organization_require_behavior` value round-trips;
  - `pre_login_prompt` with `allow` or `deny` → 400;
  - `organization_discovery_methods` validated (`email`, `organization_name`, both);
  - an old plugin → 501 for non-`deny` usage.

  Extend the tenant-settings test so the flag round-trips.
- [ ] Run `go test ./internal/mgmt ./internal/clientrules -run 'Test(OrganizationMembers|ClientOrganizationFields|TenantSettings)' -count=1`; expect FAIL.
- [ ] Implement; regenerate; `make check-sources`. Rerun; expect PASS. Commit `feat: manage organization members, member roles and client organization settings`.

## Task 7: Organization resolution at /authorize and PAR

**Files:**

- Create:
  - `internal/authz/organization.go`
  - `internal/authz/organization_test.go`
- Modify:
  - `internal/authz/{validate.go,request.go,handlers.go}` (remove the blanket "organizations are not supported yet" refusal; `invitation` stays refused)
  - `internal/oauth/par.go`
  - `internal/oauth/grant_client_credentials.go` (refuse `organization` with `invalid_request`)
  - `api/authentication.yaml`

**Interfaces:**

- `authz.ResolveOrganization(ctx, st store.Store, t tenant.Resolved, c *store.Client, raw string) (OrgDecision, *Error)`, where:
  - `OrgDecision{OrgID string; Mode OrgMode}`
  - `OrgMode` is `OrgNone | OrgFixed | OrgPromptBefore | OrgPickAfter`
- Transaction keys: `store.TxnParamOrgID = "za_org_id"` and `store.TxnParamOrgMode = "za_org_mode"` in `AuthTransaction.Params`.

- [ ] Write `TestResolveOrganization`, table-driven over spec §5.1 steps 1–4 and §2 item 1:
  - `deny` + organization → `invalid_request`;
  - unknown ID → `invalid_request`;
  - a name while names are off → `invalid_request`;
  - a name while on → resolved;
  - ID-first when a name equals another organization's ID (Review Focus 2);
  - third-party client + `block` → `access_denied`;
  - each usage/behavior combination without an organization;
  - an organization from another tenant → `invalid_request`;
  - old plugin → `invalid_request`.
- [ ] Write `TestOrganizationBinding`:
  - the resolved values land in the transaction, and a second `/authorize` step cannot change them;
  - a PAR-pushed `organization` binds, and `request_uri` plus a different `organization` is refused;
  - client credentials with `organization` → `invalid_request`;
  - resource owner password and device grants for a `require` client → `unauthorized_client`.
- [ ] Run `go test ./internal/authz ./internal/oauth -run 'Test(ResolveOrganization|OrganizationBinding)' -count=1`; expect FAIL.
- [ ] Implement. Rerun with `-race` plus the full `./internal/authz ./internal/oauth` packages; expect PASS. Commit `feat: resolve organizations at authorize and PAR`.

## Task 8: Hosted organization login — prompt, connections, picker, membership, signup

**Files:**

- Create:
  - `internal/login/organization.go`
  - `internal/login/organization_test.go`
  - templates for the `organization-selection` and `organization-picker` screens
- Modify:
  - `internal/login/{login.go,identifier.go,social.go}`
  - `internal/federation/service_flow.go`
  - `internal/identity` (membership in the user write tx)
  - `internal/signupactions` (organization on the event input)
  - `internal/i18n` English catalogue

**Interfaces:**

- `login.OrgContext{Org *store.Organization; Connections map[string]store.OrganizationConnection}` is loaded from the transaction on every hosted step.
- `login.EligibleConnections(clientConns []*store.Connection, oc OrgContext) []*store.Connection`.
- `login.EnsureMembership(ctx, tx store.Store, oc OrgContext, userID, connectionID string) error`, returning `ErrNotMember`.
- `login.PickerChoices(ctx, st, tid, userID, connectionID string) (orgs []store.Organization, auto *store.Organization, err error)`.

- [ ] Write `TestOrganizationLoginPage`:
  - only the intersection of client and organization connections is offered;
  - `show_as_button:false` is hidden but works with `connection=`;
  - a `connection=` outside the intersection → `invalid_request`;
  - an empty intersection behaves like today's no-connection case, including `prompt=none`;
  - database signup is shown only with `is_signup_enabled`;
  - organization branding is applied (Task 10 asserts the visual details).
- [ ] Write `TestOrganizationPrompt`: an unknown name re-renders without existence hints; a valid name continues; `email`-only discovery still shows the name field (D-0055).
- [ ] Write `TestOrganizationMembership` over the database, social (Plan 24 fixture IdP) and Microsoft (Plan 25 fixture) paths:
  - a member continues;
  - a non-member with auto-membership becomes a member in the login transaction;
  - a non-member without it → `access_denied` to the redirect URI, with the session kept;
  - organization signup creates the user and membership in one transaction, with no member row when signup fails;
  - the connection is disabled, or auto-membership turned off, between page load and submit → refused (Review Focus 4);
  - `prompt=none`, following spec §2 item 2.
- [ ] Write `TestOrganizationPicker`:
  - ≤ 20 entries sorted by display name, with logos;
  - one eligible organization auto-selects;
  - zero eligible, but exactly one with the connection and auto-membership → that organization plus membership;
  - otherwise `access_denied`;
  - a posted ineligible or cross-tenant organization re-renders (Review Focus 3);
  - an existing-session login uses the session's last connection.
- [ ] Run `go test ./internal/login ./internal/identity ./internal/federation -run 'TestOrganization' -count=1`; expect FAIL.
- [ ] Implement. Rerun with `-race` plus the full packages; expect PASS. Commit `feat: log in through organizations on hosted pages`.

## Task 9: Tokens, refresh and permissions

**Files:**

- Create:
  - `internal/oauth/organization.go`
  - `internal/oauth/organization_test.go`
- Modify:
  - `internal/oauth/{rbac.go,user_tokens.go,grant_authorization_code.go,grant_refresh_token.go,refresh.go}`
  - `internal/oidc` (userinfo)
  - `internal/actions/claims.go` (reserve `org_id`, `org_name`)
  - code issuance and refresh-token issuance, which set the `OrganizationID` fields added by Tasks 2–4

**Interfaces:**

- `authorizeUserToken(ctx, tid, uid, orgID string, rs, scopes, frozen)`: the Plan 26 signature gains `orgID`. It returns the union described in spec §6 and filters it once.
- `oauth.OrgClaims(t tenant.Resolved, org *store.Organization) map[string]any`.

- [ ] Write `TestOrganizationTokens`:
  - ID token and JWT access token carry `org_id`, plus `org_name` only with the setting;
  - third-party access token rules;
  - `/userinfo` echoes both;
  - an Action `setCustomClaim("org_id")` is refused as reserved;
  - permissions = direct ∪ tenant roles ∪ active-organization roles for all four dialects;
  - another organization's roles are never included.
- [ ] Write `TestOrganizationRefresh`:
  - a refresh keeps the organization and recomputes organization-role permissions;
  - member removed / organization deleted → `invalid_grant`, with no token issued, the refresh token not revoked, and never a token without `org_id` (Review Focus 1);
  - a renamed organization → the new `org_name`;
  - client changed to `deny` with an organization token → `invalid_grant`;
  - client changed to `require` with a non-organization token → `invalid_grant`;
  - the rotation family keeps its organization.
- [ ] Run `go test ./internal/oauth ./internal/oidc ./internal/actions -run 'TestOrganization' -count=1`; expect FAIL.
- [ ] Implement. Rerun with `-race` plus the full packages; expect PASS. Commit `feat: issue organization claims and permissions in tokens`.

## Task 10: Hosted branding, templates, custom text and Actions

**Files:**

- Modify:
  - `internal/hostedlogin/{context.go,theme.go,render.go}`
  - `internal/brandingrules/branding.go` (`organizations` prompt and its screens)
  - `internal/brandingrules` inventory JSON
  - `internal/actions` post-login and registration event builders
  - `internal/signupactions`
  - Plan 28 job envelope

**Interfaces:**

- `hostedlogin.Context` gains `Organization *OrgView{ID, Name, DisplayName string; Metadata map[string]*string; LogoURL, Primary, PageBackground string}`.
- The `actions` event builders gain `Organization *store.Organization`, rendered as `event.organization{id,name,display_name,metadata}`.

- [ ] Write `TestOrganizationBranding`: the organization logo and colors replace the tenant theme's values on login, signup, consent and error pages; other theme values are unchanged; there is no organization → no change; organization values are escaped/CSS-validated through the existing theme path.
- [ ] Write `TestOrganizationTemplates`: the Liquid `organization.*` variables listed in spec §7; empty without an organization; the `organizations` prompt's custom text accepted for both screens and rendered; unknown screens rejected.
- [ ] Write `TestOrganizationActionsEvent`: post-login, pre-user-registration and post-user-registration events carry `event.organization` (golden JSON) in organization flows and omit it otherwise; the queued post-registration job's sealed envelope carries it.
- [ ] Run `go test ./internal/hostedlogin ./internal/brandingrules ./internal/actions ./internal/login -run 'TestOrganization' -count=1`; expect FAIL.
- [ ] Implement. Rerun with `-race`; expect PASS. Commit `feat: brand hosted pages and Actions events with organizations`.

## Task 11: Per-tenant operators

**Files:** Modify `internal/mgmt/system.go`, `internal/mgmt/auth.go` (only if the existing stored-list check is missing a path), `api/management.yaml` system section, and the console tenant switcher component. Create `internal/mgmt/system_operators_test.go`.

**Interfaces:** `PATCH /api/v2/system/operators/{id}` with body `{tenants: []string}` (each an existing tenant name, or exactly `["*"]`). The response is the operator object.

- [ ] Write `TestOperatorTenants`:
  - the PATCH round-trips;
  - an unknown tenant → 400; mixing `"*"` with names → 400;
  - a non-system caller → 403;
  - a shrunk list → the operator's next Management call to a removed tenant is 403, even with a token issued before the change (Review Focus 5);
  - a PATCH or delete leaving no operator able to manage the system tenant → 409.
- [ ] Add Vitest `TenantSwitcher.test.ts`: it lists only the allowed tenants; after a 403 the tenant list refreshes.
- [ ] Run `go test ./internal/mgmt -run 'TestOperatorTenants' -count=1` and `npm --prefix console test -- TenantSwitcher`; expect FAIL.
- [ ] Implement; regenerate. Rerun; expect PASS. Commit `feat: scope operators to tenant lists`.

## Task 12: Console

**Files:**

- Create `console/src/pages/organizations/`, with these components and tests:
  - `List.vue`, `Create.vue`, `Detail.vue`
  - `SettingsTab.vue`, `BrandingTab.vue`, `ConnectionsTab.vue`, `MembersTab.vue`, `MemberRoles.vue`
- Modify:
  - router (replace the planned Organizations page)
  - user detail (Organizations tab)
  - application settings (the three fields and the `pre_login_prompt` rule)
  - `console/src/locales/en.ts`
  - `console/src/api` generated schema

**Interfaces:** the generated API client from Tasks 5–6. Reuse the existing Pager, stale-reply guard and draft-editor patterns from the roles and actions pages.

- [ ] Write Vitest cases:
  - list/create/delete, with 409 shown on the name field;
  - settings and metadata editing with limit messages;
  - branding preview swatch and validation;
  - connections tab: flags disabled per strategy, `is_signup_enabled` requiring auto-membership;
  - members: add via user search, remove, member roles;
  - user detail Organizations tab;
  - application organization fields with `pre_login_prompt` disabled unless `require`;
  - stale replies ignored on every tab.
- [ ] Run `npm --prefix console test -- src/pages/organizations src/pages/users src/pages/applications`; expect FAIL.
- [ ] Implement with existing components and localized strings. Layouts are original only.
- [ ] Run `make console`; expect lint, typecheck, tests and build to pass. Commit `feat: add Organizations to the console`.

## Task 13: Seed, Deploy CLI and end-to-end acceptance

**Files:**

- Modify:
  - `internal/seed` (an `organizations` section)
  - `docs/deploy-cli.md`
  - `tests/e2e` fixtures
  - `Makefile` (`e2e-organizations`)
- Create:
  - `tests/e2e/run-m29-organizations.sh`
  - Playwright specs under `tests/e2e/browser/organizations*.spec.ts`

**Interfaces:** the seed YAML is `organizations: [{name, display_name, branding, metadata, connections: [{name, assign_membership_on_login, show_as_button, is_signup_enabled}], members: [{user_id} | {email, connection}], member_roles: [{member: <same ref>, roles: [role names]}]}]`.

- [ ] Write `TestOrganizationsSeed`:
  - create-only restart;
  - members by ID and by email + connection;
  - an unresolvable member, connection or role fails startup with a clear error.
- [ ] Add E2E cases:
  - auth0-cli 1.37.0 `orgs` create/list/show/update/delete, members, roles;
  - each node-auth0 7.4.0 Plan 29 method (Task 1 list);
  - auth0-spa-js login with `organization`, validating `org_id`.
  - Playwright:
    - pre-login prompt;
    - post-login picker with two organizations;
    - non-member denial;
    - auto-membership;
    - organization signup;
    - organization branding on the login page;
    - console organization flows.
- [ ] Extend the Deploy CLI four-cell matrix with organizations, their connections and (if Task 1 found the tool exports them) member roles. If something is unsupported, record it as unavailable.
- [ ] Run `go test ./internal/seed -run 'TestOrganizationsSeed' -count=1`, `make e2e-organizations` and `make e2e-deploy`. Expect FAIL before the fixtures, then PASS. Record any missing tools as unavailable.
- [ ] Commit `test: verify Organizations with CLI SDK browser and Deploy CLI`.

## Task 14: Final regression, documentation and record

**Files:**

- Create:
  - `docs/organizations.md`
  - `docs/superpowers/2026-10-28-plan-29-implementation-record.md`
- Modify:
  - `docs/compat/matrix.md`
  - `docs/actions.md` (`event.organization`)
  - `docs/rbac.md` (organization roles)
  - `docs/branding.md`
  - `docs/management-api.md`
  - the roadmap (Plan 29 done; Plan 30 carries the deferred items)
  - `README.md` status line

- [ ] Document:
  - organization resources and limits;
  - client settings and every login flow (prompt, picker, membership, auto-membership, signup, `prompt=none`);
  - tokens and permissions, and refresh re-checks;
  - organization names and the tenant setting;
  - branding and templates;
  - per-tenant operators;
  - deferred items with their target plans.
- [ ] Run:
  - `go generate ./...` twice, `make check-sources`, `go vet ./...`
  - `ZA_REQUIRE_NODE=1 go test -race -timeout=50m ./...`
  - `./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/...`
  - `make console`
  - `make e2e`, `make e2e-organizations`, `make e2e-rbac`, `make e2e-actions`, `make e2e-actions-ii`, `make e2e-deploy`, `make e2e-email-accounts`, `make e2e-domains`
  - `tests/conformance/run.sh`

  Run e2e lanes sequentially (they share ports). Record actual results, skips and unavailable services.
- [ ] Final whole-branch review against Review Focus, the four spec §1 anti-goals and spec coverage. Fix with regression tests, rerun the affected checks, and append the disposition to the record.
- [ ] Commit `docs: record Organizations behavior and verification evidence`. Hand off; do not merge or push.
