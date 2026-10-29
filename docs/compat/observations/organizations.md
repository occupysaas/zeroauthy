# Organizations: observation notes

- Date: 2026-10-28
- Source: observer session, Plan 29 Task 1
- Method: documented Management API and Authentication API endpoints only, on the maintainer's own tenant, with client-credentials tokens. No hosted page or dashboard content was captured. Redirects were inspected only for the Location header (host/path class and `error` code).
- Complements:
  - https://auth0.com/docs/api/management/v2/organizations/get-organizations (and the sibling operations: post/get/patch/delete organizations, get-name, enabled_connections, members, member roles, effective-roles)
  - https://auth0.com/docs/api/management/v2/users/get-user-organizations
  - https://auth0.com/docs/api/management/v2/clients/patch-clients-by-id
  - https://auth0.com/docs/manage-users/organizations
  - https://auth0.com/docs/manage-users/organizations/configure-organizations
  - https://auth0.com/docs/manage-users/organizations/organizations-for-m2m-applications
- Availability: Organizations was available (list returned 200, creates returned 201).
- Notes are paraphrased. Error text is reduced to the `errorCode` identifier where one exists. Many 400/404/409 bodies have no `errorCode` (marked "none").
- Propagation: client settings written by PATCH `/clients/{id}` took a few seconds to take effect in `/authorize`. An immediate request after a PATCH sometimes still saw the old value. Compat tests should allow for this on the reference tenant; it is not required of zeroauthy.
- Rate limiting: 429 appeared when issuing roughly 3+ requests per second to the Management API.

## Summary by spec section 2 item

| # | Topic (spec section 2) | Status | Reason |
|---|------------------------|--------|--------|
| 1 | `/authorize` errors | partly observed | Pre-authentication errors seen as redirects: unknown organization, name while names are off (setting not altered), organization sent to `deny`, `require`+`no_prompt` without organization, junk invitation. Not reachable without a user completing hosted login: not-a-member `access_denied`, third-party client block, post-login picker, and connection-not-enabled (no pre-auth error was produced, the decision happens in the hosted flow) |
| 2 | `prompt=none` with an organization | partly observed | With no session: `login_required` (valid org) or `invalid_request` (org missing for `require`). Session-user cases need interactive login |
| 3 | Tenant roles and direct permissions in an organization login | unavailable (needs interactive login) | Needs an authorization-code login with tokens |
| 4 | Refresh with organizations | unavailable (needs interactive login) | Needs a refresh token from an organization login |
| 5 | `allow` + `post_login_prompt` without organization | unavailable (needs interactive login) | Behavior is in the hosted flow |
| 6 | `is_signup_enabled` without `assign_membership_on_login` | observed | 400 on create, and on PATCH in both directions |
| 7 | Password and device grants for a `require` client | observed | A `require` client cannot have these grants (400 at configuration). With `allow`/`deny` they work and carry no organization |
| 8 | Organization `name` format | observed | See name rules |
| 9 | Limits | partly observed | Metadata, display name and page sizes observed; per-tenant and per-organization counts not tested (no load testing) |
| 10 | Membership removal vs live sessions | unavailable (needs interactive login) | Needs a session; also observed that role assignments survive membership removal |

## 1. Organization resource

### Fields

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | prefix `org_` + 16 alphanumerics |
| `name` | string | see rules below; settable on create and also changeable by PATCH |
| `display_name` | string | defaults to `name` when omitted on create; 1 to 255 chars |
| `branding` | object | omitted from responses when empty/unset |
| `branding.logo_url` | string | HTTPS URL only (non-https rejected) |
| `branding.colors` | object | requires BOTH `primary` and `page_background` |
| `metadata` | object of strings | omitted from responses when empty/unset |
| `enabled_connections` | array | accepted on create (and echoed in the create response only); never present in GET/list responses |
| `third_party_client_access` | string | always present; value `block` on new orgs |
| `is_app_entitlement_active` | boolean | always present; `false` on new orgs |

### Create, get, list

| Endpoint | Request | Status | Observation |
|----------|---------|--------|-------------|
| POST `/organizations` | `{name}` | 201 | response has id, name, display_name, third_party_client_access, is_app_entitlement_active |
| POST | name already used | 409 | none |
| POST | no `name` / unknown field / empty `display_name` | 400 | `invalid_body` |
| POST | full body (display_name, branding, metadata, enabled_connections) | 201 | response echoes all, including `enabled_connections[]` with a `connection` summary |
| POST | enabled_connections entry with unknown property (e.g. camelCase `assignMembershipOnLogin`) | 400 | `invalid_body` (strict snake_case) |
| POST | enabled_connections unknown but well-formed connection id | 404 | `inexistent_connection` |
| POST | enabled_connections with `is_signup_enabled=true` and no `assign_membership_on_login` | 400 | `invalid_body` |
| GET `/organizations/{id}` | existing | 200 | no `enabled_connections` in body |
| GET | well-formed unknown id | 404 | none |
| GET | malformed id (not `org_...`) | 400 | `invalid_uri` |
| GET `/organizations/name/{name}` | existing | 200 | same body as by id |
| GET by name | unknown name | 404 | none |
| GET by name | upper-case/invalid-format name | 400 | `invalid_uri` (format validated before lookup) |
| DELETE `/organizations/{id}` | existing | 204 | members and connection links are removed with it |
| DELETE | already deleted / unknown | 404 | none (not idempotent) |

### Name rules (create and PATCH, same validator)

| Input | Status | Code |
|-------|--------|------|
| lower-case letters, digits, hyphen, underscore | 201 | |
| single character `a` | 201 | |
| exactly 50 characters | 201 | |
| 51 characters | 400 | `invalid_body` |
| upper-case letter | 400 | `invalid_body` |
| leading `-` | 400 | `invalid_body` |
| leading `_` | 400 | `invalid_body` |
| contains space | 400 | `invalid_body` |
| contains `.` | 400 | `invalid_body` |
| interior `_` (e.g. `obs_org`) | 201 | |
| interior `-` | 201 | |

### Metadata limits

| Case | Status | Code |
|------|--------|------|
| 25 keys | 201 | |
| 26 keys | 400 | `invalid_body` (limit is 25, not 26) |
| value of 255 chars | 201 | |
| value of 256 chars | 400 | `invalid_body` (limit 255) |
| key of 50 chars | 201 | |
| key of 256 chars | 400 | none (limit is 50) |
| key not matching `^[a-zA-Z0-9]\w*$` (e.g. contains space or `!`) | 400 | `invalid_body` |
| non-string value (number) | 400 | `invalid_body` |
| `null` value, on create or on PATCH | 400 | none (generic "invalid payload"). Not accepted as a deletion marker on this tenant |
| empty string value | 400 | none |

### Branding rules

| Case | Status | Code |
|------|--------|------|
| only `logo_url` | 201 | |
| `colors` with only one color | 400 | `invalid_body` (the other color is "missing required property") |
| `colors: {}` | 400 | `invalid_body` |
| color not a hex color (e.g. a word) | 400 | `invalid_body` |
| `logo_url` not an https URL | 400 | `invalid_body` |

### PATCH `/organizations/{id}`

| Request | Status | Result |
|---------|--------|--------|
| `{display_name}` only | 200 | other fields (branding, metadata) untouched; full organization returned |
| `{name}` valid and unused | 200 | name is changed (rename is allowed) |
| `{name}` already used | 409 | none |
| `{name}` invalid format | 400 | `invalid_body` |
| `{metadata: {...}}` | 200 | metadata is REPLACED: sending `{c}` after `{a,b}` leaves exactly `{c}` |
| `{metadata: {}}` | 200 | clears metadata (key then omitted from response) |
| `{metadata: null}` | 200 | clears metadata |
| `{metadata: {k: null}}` | 400 | none |
| `{branding: {logo_url}}` | 200 | branding REPLACED: previously stored colors are dropped |
| `{branding: {colors: {both}}}` | 200 | previously stored logo_url dropped |
| `{branding: {}}` | 200 | clears branding |
| `{branding: null}` | 200 | clears branding |
| `{branding: {colors: {one color}}}` | 400 | `invalid_body` |
| `{display_name: 256 chars}` | 400 | `invalid_body` |
| `{}` | 400 | none |
| unknown org | 404 | none |

### List: GET `/organizations`

| Mode | Request | Status | Response shape |
|------|---------|--------|----------------|
| page (default) | none, or `page`/`per_page` | 200 | bare array of organizations |
| page with totals | `include_totals=true` | 200 | `{organizations, start, limit, total}` |
| checkpoint | `take=N` (with or without `from`) | 200 | `{organizations, next?}`; `next` is an opaque cursor present only when more remain; no `start/limit/total` |
| checkpoint continue | `from=<next>&take=N` | 200 | next page; `from` without `take` also works and uses the default size |
| `from` + `page` | | 200 | `page` ignored, checkpoint mode wins |
| `per_page` or `take` over 100 | | 400 | `invalid_query_string` |
| `take=0` | | 400 | `invalid_query_string` |
| `from` not a valid cursor | | 400 | none |
| `page` beyond the 1000-record window | | 400 | `invalid_paging` |
| `sort` valid forms | `name:1`, `name:-1`, `display_name:...`, `created_at:...` | 200 | |
| `sort` other field/form | | 400 | `invalid_query_string` |

- List items omit `enabled_connections`.
- Default order: page mode returned organizations in ascending name order (case/punctuation-insensitive collation, e.g. `obs_org` before `obs-org-1`); checkpoint mode without `sort` returned creation order.
- `sort` is honored in both modes.

## 2. Enabled connections

Path: `/organizations/{id}/enabled_connections[/{connection_id}]`.

### Fields (also the shape inside create-organization responses)

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `connection_id` | string | required on add | |
| `assign_membership_on_login` | boolean | false | |
| `is_signup_enabled` | boolean | false | true only valid when `assign_membership_on_login` is true |
| `show_as_button` | boolean | true | |
| `connection` | object | | summary: `name`, `strategy` only |

### Operations

| Endpoint | Request | Status | Notes |
|----------|---------|--------|-------|
| POST | `{connection_id}` | 201 | defaults above; `connection` summary present |
| POST | same connection again | 409 | none |
| POST | well-formed unknown connection id | 404 | `inexistent_connection` |
| POST | no `connection_id` | 400 | `invalid_body` |
| POST | unknown org | 404 | none |
| GET list | | 200 | bare array; `include_totals=true` gives `{enabled_connections, start, limit, total}`; empty list with totals reports `limit: 0` |
| GET list | `per_page` over 100 | 400 | `invalid_query_string` |
| GET one | enabled | 200 | single object |
| GET one | not enabled, well-formed id | 404 | none |
| GET one | malformed connection id | 400 | `invalid_uri` |
| PATCH | `{assign_membership_on_login:true}` | 200 | full entry returned |
| PATCH | `{is_signup_enabled:true}` while assign is false | 400 | none |
| PATCH | `{assign_membership_on_login:false}` while signup is true | 400 | none (same rule enforced both directions) |
| PATCH | `{show_as_button:false}` on a database connection | 400 | `invalid_body` (only enterprise connections can hide the button) |
| PATCH | `{show_as_button:true}` | 200 | |
| PATCH | `{}` | 200 | unchanged entry returned |
| PATCH | unknown property / wrong type | 400 | `invalid_body` |
| PATCH | connection not enabled for the org | 404 | `inexistent_connection` (well-formed) or 400 `invalid_uri` (malformed) |
| DELETE | enabled | 204 | |
| DELETE | not enabled, existing connection | 204 | idempotent |
| DELETE | not enabled, unknown connection | 404 | `inexistent_connection` |

### `/organizations/{id}/connections` (alias-like)

| Endpoint | Status | Shape |
|----------|--------|-------|
| GET | 200 | same entries as enabled_connections, with three EXTRA fields per entry: `is_enabled` (boolean, true), `organization_access_level` (string, value `none` observed), `organization_member_access_level` (string, value `limited` observed) |
| GET `?include_totals=true` | 200 | `{connections, start, limit, total}` |
| POST `{connection_id}` | 409 when already enabled | same underlying link as enabled_connections (state is shared) |

## 3. Members and roles

### Members

| Endpoint | Request | Status | Observation |
|----------|---------|--------|-------------|
| POST `/organizations/{id}/members` | `{members: [user_id...]}` | 204 | no body |
| POST | member already present | 204 | idempotent |
| POST | any listed user does not exist | 404 | `inexistent_user`; nothing from the batch was added |
| POST | empty array / non-array | 400 | `invalid_body` |
| GET list | none | 200 | bare array; each item `user_id`, `email`, `picture`, `name` |
| GET list | `include_totals=true` | 200 | `{members, start, limit, total}` |
| GET list | `take=N` | 200 | `{members, next?}`; `next` only when more remain |
| GET list | `from=<next>` | 200 | works with or without `take`; `page` ignored when `from` present |
| GET list | `fields=roles` | 200 | with default include behavior returns ONLY the listed field(s) per item (`roles` array of `{id, name}`, no other member fields) |
| GET list | `fields=roles,user_id` | 200 | listed fields only |
| GET list | `fields=roles&include_fields=false` | 200 | roles excluded, other member fields present |
| GET list | `fields` with other than `user_id,email,picture,name,roles` | 400 | `invalid_query_string` |
| DELETE `/organizations/{id}/members` | `{members: [...]}` | 204 | idempotent for non-members |

- A member without roles in `fields=roles` output has `roles: []`.
- After removing a member and re-adding the same user, the member's earlier role assignments were still present (role assignments are not wiped by membership removal).

### Member roles

| Endpoint | Request | Status | Observation |
|----------|---------|--------|-------------|
| POST `/organizations/{id}/members/{user}/roles` | `{roles: [role_id...]}` | 204 | |
| POST | roles already assigned | 204 | idempotent |
| POST | user is not a member | 404 | none |
| POST | unknown role id | 404 | none |
| POST | empty array | 400 | `invalid_body` |
| GET | member | 200 | bare array of `{id, name, description}` |
| GET | `include_totals=true&per_page&page` | 200 | `{roles, start, limit, total}` |
| GET | `take` | 400 | `invalid_query_string` (checkpoint is not supported for this list) |
| GET | non-member | 404 | none |
| DELETE | `{roles: [...]}` | 204 | |
| DELETE | role not assigned | 204 | idempotent |
| DELETE | user does not exist | 404 | `inexistent_user` |

### Other

| Endpoint | Status | Shape |
|----------|--------|-------|
| GET `/organizations/{id}/members/{user}/effective-roles` | 200 | `{roles: [{id, name, description, sources: ["direct"]}]}`; wrapped object, not a bare array. `sources` is an array (only `direct` observed; other values unobserved) |
| same for non-member | 404 | none |
| GET `/organizations/{id}/roles/{role_id}/members` | 200 | `{members: [{user_id, email, picture, name}], next?}`; checkpoint style only (`take`); `include_totals` yields no totals; `page`/`per_page` ignored |
| same, unknown role id | 404 | none |
| GET `/users/{id}/organizations` | 200 | bare array of organization summaries (id, name, display_name, third_party_client_access, is_app_entitlement_active; no branding when unset); `include_totals=true` gives `{organizations, start, limit, total}`; user with no memberships gives `[]` |

## 4. Client fields (PATCH `/clients/{id}`)

| Field | Values | Notes |
|-------|--------|-------|
| `organization_usage` | `deny`, `allow`, `require` | invalid value 400 `invalid_body`; `null` unsets it (field disappears from the client; the effective default is deny). Never-set clients do not report the field |
| `organization_require_behavior` | `no_prompt`, `pre_login_prompt`, `post_login_prompt` | invalid value 400 `invalid_body`; `post_login_prompt` on a client that is not OIDC conformant: 400 `invalid_body` (the default new regular_web client had `oidc_conformant=false`) |
| `organization_discovery_methods` | array of `email` / `organization_name` | min 1 entry (empty array 400 `invalid_body`); invalid value 400 `invalid_body`; `null` unsets; only allowed while `organization_require_behavior` is `pre_login_prompt` (else 400, none) |

| Case | Status | Note |
|------|--------|------|
| `pre_login_prompt` with `organization_usage: allow` | 200 | accepted |
| `pre_login_prompt` with `deny` | 200 | accepted |
| `organization_usage: require` with grant types password, password-realm, or device_code (set in the same or an earlier request) | 400 | none; a `require` client may keep authorization_code, client_credentials, refresh_token, implicit (all four accepted) |
| device_code grant on a client | 400 unless app type is `native`, OIDC conformant and token endpoint auth method is `none` | none |
| client_credentials with `organization_usage: require` | 200 | allowed |

## 5. `/authorize` pre-authentication results

All requests: `response_type=code`, registered callback, `scope=openid`, a `state`. Result is the HTTP status and Location class. "cb error=X" means a 302 to the registered callback with query `error=X` (the `state` is returned). "hosted" means a 302 to a path on the tenant domain (login, organization prompt, or resume path); nothing was fetched.

| Client config | Query | Status | Result |
|---------------|-------|--------|--------|
| `deny` (or unset) | no org | 302 | hosted login |
| `deny` | `organization=<valid id>` | 302 | cb `error=invalid_request` |
| `allow` | `organization=<valid id>` | 302 | hosted login |
| `allow` | `organization=<well-formed unknown id>` | 302 | cb `error=invalid_request` |
| `allow` | no org | 302 | hosted login |
| `allow` | `organization=<org name>` (tenant name setting off, which is the current/default state) | 302 | cb `error=invalid_request` (the failure says an id is required) |
| `allow` | `organization=xyz` (not id-shaped) | 302 | cb `error=invalid_request` (same "must be an id" failure) |
| `allow` | `organization=` (empty) | 302 | treated as absent: hosted login |
| `require` + `no_prompt` | no org | 302 | cb `error=invalid_request` |
| `require` + `no_prompt` | unknown id | 302 | cb `error=invalid_request` |
| `require` + `no_prompt` | valid id | 302 | hosted login |
| `require` + `no_prompt` | no org, `prompt=none` | 302 | cb `error=invalid_request` (org-required check runs before the login check) |
| `require` + `no_prompt` | valid org, `prompt=none` | 302 | cb `error=login_required` |
| `require` + `pre_login_prompt` | no org | 302 | hosted organization-prompt page (path differs from the login path) |
| `require` + `pre_login_prompt` | unknown id | 302 | cb `error=invalid_request` |
| `allow` + `pre_login_prompt` | no org | 302 | hosted organization-prompt page |
| `allow` + `pre_login_prompt` | valid id | 302 | hosted login |
| `allow` | `invitation=<junk>` with or without valid org | 302 | cb `error=invalid_request` (invitation not found) |
| `allow` | `invitation=<junk>` and no org | 302 | cb `error=invalid_request` |
| `allow` | `connection=<name>` where the connection exists but is NOT enabled for the org (org has no connections) | 302 | no pre-auth error; hosted resume path |
| `allow` | `connection=<unknown name>` with or without org | 302 | no pre-auth error; hosted resume path |
| `allow` | `connection=<enabled name>` with org | 302 | hosted login |

- Every `invalid_request` here carries an `error_description`; wording varies per cause and should be written independently. Distinct causes seen: org id invalid/unknown, org not allowed for client, org required, org must be an id (name given), invitation not found.
- Tenant setting for accepting org names in the Authentication API: the tenant flags list did not contain it (default off). It was not changed. The "name accepted" behavior was not observed.
- The connection-not-enabled decision happens after the redirect (hosted flow) and could not be observed.

## 6. Password and device grants

| Grant | Client | Request | Status | Result |
|-------|--------|---------|--------|--------|
| set `organization_usage=require` | any | PATCH with password / password-realm / device_code enabled | 400 | the tenant refuses, so no `require` client with these grants can exist |
| `password` (plain ROPG) | allow or deny | token request | 500 | `server_error` here because the tenant has no default connection (tenant-specific, not an organization result) |
| password-realm | allow | valid credentials, no org / valid org / non-member's org / unknown org / org name | 200 | all succeed; organization parameter ignored; id_token has no `org_id` or `org_name` claim |
| password-realm | deny | valid credentials + valid org | 200 | success; organization ignored |
| password-realm | allow | wrong password, with or without org | 403 | `invalid_grant` |
| `/oauth/device/code` | allow or deny | with no org / valid org / unknown id / org name | 200 | all accepted, normal device response; organization not validated at this step |

- Validation of the organization for device flow (if any) would occur at the hosted activation page: unavailable.
- The password-realm grant must be present in the client's grant types (else 403 `unauthorized_client`).

## 7. Client credentials with `organization`

| Setup | Request | Status | Code |
|-------|---------|--------|------|
| no client grant to the audience | with or without `organization` | 403 | `access_denied` |
| client grant exists to the Management API audience; client usage deny / allow / require | no `organization` | 200 | normal M2M token, no organization claim |
| same | `organization=<valid id / unknown id / org name>` | 400 | `invalid_request` (client not permitted to use an organization with this audience) |
| PATCH client-grant of the Management API audience with `organization_usage` or `allow_any_organization` | | 400 | `reserved_identifier` |

- The grant-level organization settings could not be exercised because the only API available to the throwaway client was the reserved Management API audience.
- Client-level `organization_usage` does not affect the client-credentials flow here.

## Cleanup

- All organizations, users, roles, clients and the client grant created by this session were deleted; verification lists showed none remaining.
- No tenant settings were changed.
