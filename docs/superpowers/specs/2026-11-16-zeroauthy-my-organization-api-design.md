# Plan 42b — My Organization API (organization self-service)

**Date:** 2026-11-16. **Status:** design; not implemented.

**Roadmap entry:** [management roadmap, Plan 42](2026-10-19-zeroauthy-management-roadmap-design.md)
("My Organization API (organization administrators manage members,
invitations and roles; Early Access since 2026-09, with log events)");
[parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md) item **U2**
(track U, after U1 = Plan 42a). Every operation in Auth0's My Organization
OpenAPI is **Early Access**; the roadmap still includes it because the
maintainer's main Organizations use case is customer self-service of users
and access (memory: organizations use case — their app's API is granted
per customer organization, each organization manages its own users,
per-seat pricing). Read the [clean-room policy](../../../CLEAN_ROOM.md),
`AGENTS.md`, D-0055 (Organizations), the Plans 29/30 guides, the
[Plan 42a spec](2026-11-16-zeroauthy-my-account-api-design.md) and the
F-track specs (Plans 36, 37a, 37c) for Phase B.

## 1. Outcome and scope

An organization administrator, signed in to the customer's app in the
context of their organization, calls `https://<tenant host>/my-org/v1/...`
and manages their own organization: details and branding, members and
their roles, invitations, and — once the enterprise-connection plans have
landed — verified domains, the organization's own identity providers and
their SCIM provisioning. The operator controls who may do this through
organization roles carrying `my_org` permissions.

**Rule:** strict 1:1 with Auth0's machine-readable My Organization OpenAPI
(`https://auth0.com/docs/oas/myorganization/myorganization-api-oas.json`,
version 1.0.0, read 2026-11-16). Because the API is Early Access, the
implementation pins that OpenAPI version, records it in D-0220, and Task 1
re-reads the newest version before building (LR42b-1). Local rulings
**LR42b-n**, observation points **MO-1…n** in **D-0220** (U2 block
D-0220–0229).

### In scope — Phase A (members and access; needs only Plans 29/30)

| Operation | Scope |
|---|---|
| `GET /config` | `read:my_org:configuration` |
| `GET /details`, `PATCH /details` | `read:`/`update:my_org:details` |
| `GET /members` (`fields`, `include_fields`, `from`, `take`, `include_totals`; `roles` only with `read:my_org:member_roles`), `GET /members/{user_id}` | `read:my_org:members` |
| `POST /delete-memberships` | `delete:my_org:memberships` |
| `GET /member-invitations`, `POST /member-invitations`, `GET /member-invitations/{id}`, `POST /delete-member-invitations`, `GET /member-invitations/{id}/roles` | `read:`/`create:`/`delete:my_org:member_invitations`, `read:my_org:member_roles` |
| `GET /members/{user_id}/roles`, `POST /members/{user_id}/roles`, `POST /members/{user_id}/unassign-roles`, `GET /roles` | `read:`/`create:`/`delete:my_org:member_roles` |

### Phase B (self-service enterprise connections; needs F1, F2, F4)

`GET /config/identity-providers`, `GET /user-stores`, `/domains`
(list, create, get, delete, `verify`, `.../identity-providers`),
`/identity-providers` (CRUD, `update-attributes`, `detach`, domains),
`/identity-providers/{id}/provisioning` (get, create, delete,
`update-attributes`) and its SCIM tokens — built on Plan 36 (OIDC/Okta),
37a (SAML), 37c (SCIM, self-service) and Plan 30 (discovery domains).

### Not in scope

- Anything not in the pinned OpenAPI.
- Organization billing / seat limits (product logic of the maintainer's
  app; zeroauthy exposes member counts — `include_totals` — for that).

### Anti-goals

- **Cross-organization access.** Every operation acts on the
  organization in the token's `org_id`, never on a path or body
  organization; a token without `org_id` (or for another tenant) is
  `401/403`.
- **Privilege escalation.** An administrator can assign only roles the
  operator marked assignable through the My Organization API (§3), never
  a role carrying `my_org` permissions above their own unless the operator
  allows (LR42b-2, MO-1), and cannot remove their own last admin role
  (lockout guard, MO-2).
- **Tenant-wide data.** Member listings show only that organization's
  members and only the profile fields the OpenAPI lists; no `app_metadata`.
- **Domain takeover.** Phase B domain verification is a real DNS TXT check
  (unlike Plan 30's operator attestation), with the Plan 47 claim-expiry
  concern handled: unverified claims expire after 7 days (LR42b-3).
- **Secrets in logs**: invitation tickets, SCIM tokens.

## 2. Evidence

- My Organization OpenAPI 1.0.0 (read 2026-11-16): servers
  `https://{tenantDomain}/my-org/v1` and `/my-org`; the operations, scopes
  and Early Access marks listed in §1; `GET /members` description ("The
  `roles` field is only included for each member when the token also
  carries the `read:my_org:member_roles` scope").
- Auth0 My Organization guide (activation, audience, how admins receive
  the scopes — read at build time, MO-3).
- Plans 29/30 implementation (members, organization roles, invitations,
  discovery domains), D-0055.

## 3. Activation and access

- System resource server `https://<host>/my-org/` (MO-3: identifier and
  name) created by an activation switch (like Plan 42a), with the `my_org`
  permissions as its scopes, `subject_type_authorization.user:
  require_client_grant`, `client: deny_all`.
- Administrators get permissions through **organization member roles**
  (Plan 29) whose permissions include `my_org` ones; tokens for the
  audience are issued only with an `organization` in the transaction, and
  carry `org_id` and the granted `my_org` scopes (MO-4).
- `GET /config`: the organization's allowed features, assignable roles,
  invitation settings (MO-5 shape).

## 4. Phase A behaviour

- Details: only the members the OpenAPI lists for `PATCH /details`
  (expected `display_name` and `branding`; MO-6 records whether `metadata`
  is among them).
- Members: list with checkpoint paging, `roles` gated by scope, member
  detail; delete memberships (bulk `{members: [user_id]}`) removes
  membership only (not the user), with the Plan 29 role cleanup.
- Invitations: create (`invitee.email`, `roles`, `client_id` from the
  token's client unless the operator allows others, `ttl_sec`,
  `send_invitation_email`), list/get, bulk delete; reuse Plan 30's
  invitation service and email.
- Roles: `GET /roles` lists roles assignable in this organization (§3,
  MO-1); assign/unassign per member.
- Errors: the OpenAPI's error shape (problem-style like My Account, MO-7).
- Logs: the My Organization log events (logs schema, MO-8).

## 5. Phase B behaviour (summary)

- Domains: create (pending, DNS TXT record value returned), verify (TXT
  lookup with a resolver timeout; success sets verified, which Plan 30
  discovery uses), delete.
- Identity providers: organization-owned enterprise connections created
  within the operator's allowed strategies (Plan 37c self-service profile
  rules), enabled only on this organization; attributes mapping; detach;
  domain links feed HRD (Plan 36).
- Provisioning: SCIM configuration and tokens for those connections
  (Plan 37c).

## 6. Storage, console, tests

- No new tables in Phase A beyond assignable-role flags on organization
  roles; Phase B: domain verification records (TXT value, expiry) and
  organization ownership of connections; migrations numbered at merge.
- Console: activation card; organization roles editor marks
  "assignable through self-service" and shows `my_org` permissions.
- Tests: per-operation scope and org isolation tables; escalation and
  lockout guards; invitation flow end to end; DNS verification with a
  fixture resolver.
- E2E `make e2e-my-org`: Playwright organization login as an admin, then
  fetch calls listing members, inviting, assigning roles; a second
  organization's admin cannot see the first's members.

## 7. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR42b-1 | Pin the Early Access OpenAPI version; re-read at build. |
| LR42b-2 | Admins assign only operator-marked roles, never above their own `my_org` permissions. |
| LR42b-3 | Unverified Phase B domain claims expire after 7 days. |

Observe later: **MO-1** assignable-role rules; **MO-2** last-admin guard;
**MO-3** activation, audience and resource server name; **MO-4** token
requirements; **MO-5** `/config` shape; **MO-6** details members; **MO-7**
error format; **MO-8** log events.

## 8. Decisions needed from the maintainer

1. Build Phase A now despite Early Access (proposed, for the self-service
   use case), or wait for GA.
2. Whether Phase B waits for F1/F2/F4 to merge (proposed) or ships a
   domains-only slice earlier.
