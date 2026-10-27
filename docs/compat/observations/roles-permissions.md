# Roles and permissions: public contract review

Date: 2026-10-27. Evidence: public documentation and pinned open-source tool
contracts only. **No live Auth0 tenant observation was performed.** This file
contains no captured dashboard, hosted pages, credentials or personal data.

## Frozen operation contract

Machine-readable contracts and per-operation source URLs:
`internal/rbacrules/inventory.json`. These describe Plan 26's tenant-role subset.
The scope arrays are **all-of** requirements. This matters for membership APIs:

| Operation | Required scopes (all) | Success |
|---|---|---|
| GET roles; GET role; GET role permissions | read:roles | 200 |
| POST roles | create:roles | 200 |
| PATCH role | update:roles | 200 |
| DELETE role | delete:roles | 200 |
| POST role permissions | update:roles | 201 |
| DELETE role permissions | update:roles | 200 |
| GET role users; GET user roles | read:users, read:roles, read:role_members | 200 |
| POST role users | update:roles, create:role_members | 200 |
| POST user roles | update:users, create:role_members | 204 |
| DELETE user roles | update:users, delete:role_members | 204 |
| GET user permissions | read:users | 200 |
| POST user permissions | update:users | 201 |
| DELETE user permissions | update:users | 204 |

These statuses correct the draft's uniform 201/create and 204/mutation rules.
The current public API reference's embedded operation schemas include the
scope lists, even when the page's rendered authorization section omits them.
All documentation was fetched directly from Auth0 public URLs.

Roles expose id/name/description. User permissions identify API and permission,
plus current API name/description and sources. Role-user summaries contain only
user_id, picture, name and email. Offset lists support page>=0, per_page1..100
(default50), and optional totals. Empty arrays remain arrays. Role-user
checkpoint pagination uses take1..100 (default50), optional from and a
`{users,next?}` response; next is absent on exhaustion. The local cursor also
binds tenant and role and rejects mixed modes (D-0052).

The public user-permission source schema is unconstrained `any`; it does not
establish an exact source-object contract. Plan 26 locally projects DIRECT
without ID/name, and ROLE with source_id/source_name. No live parity claim is
made for that representation. Public role creation/update schemas do not pin
the local name/description limits or case-folding behavior. D-0052 records
those choices and the bounded atomic assignment contract.

## Runtime and later resources

[RBAC documentation](https://auth0.com/docs/get-started/apis/enable-role-based-access-control-for-apis)
requires requested-scope intersection when enabled; `_authz` includes current
assignments, including unrequested permissions.
[Token-profile documentation](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles)
distinguishes the legacy and RFC header/client claims.
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) additionally requires signed
access tokens, access-token type and mandatory issuer/subject/audience/client/
expiry/issuance/JWT-ID claims. Use managed RS256 keys and keep ID-token handling
separate.

Current docs also list role groups, effective-role/permission APIs and EA
organization-role ownership/checkpoint options. They are outside Plan 26.
User-permission listing covers direct and directly assigned-role permissions;
group-derived permissions are a later effective-permissions surface.

## Open-source client review

Pinned local sources reviewed without copying implementation:

- node-auth0 7.4.0, `dist/esm/management/api/resources/{roles,users}/...`:
  direct roles and permission endpoints match the public paths. The SDK itself
  labels group-derived permissions as belonging to effective-permissions.
- auth0-deploy-cli 9.1.0, `lib/tools/auth0/handlers/roles.js` and YAML/directory
  role handlers: roles are logical definitions with permission pairs, processed
  after resource servers; tenant type is used for listing and stripped from
  writes. Generated IDs cannot be the round-trip comparison identity.
- Existing auth0-cli pin remains 1.37.0. Task 9 must run actual CLI commands;
  source review is not CLI execution evidence.

## Retrieval limits

The public changelog request exceeded the web tool response-size limit. Prior
coverage remains 2026-10-26; this review does not establish 2026-10-27 coverage.
Initial guessed plural role endpoint URLs returned no content; links from the
public roles index supplied the canonical singular operation slugs now recorded
in the inventory. No behavior is inferred from failed retrievals.
