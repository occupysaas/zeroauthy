# Management API core resources review

## Summary
The core resources are in good shape for a 1.0 preview. Every operational route in `internal/server/mgmtapi.go` and `mgmt_mfa.go` is wrapped in a scope check; the only unwrapped methods are system/console routes behind `operatorOnly`. I compared all 249 scoped wrappers with the current Auth0 OAS by script. No route lets a caller in with a scope Auth0 does not list, apart from the low-impact items in F5. Tenant isolation holds everywhere I checked: SQL `UPDATE`/`DELETE`/`SELECT` use `tenant_id` keys, the memory store is keyed by `{tenant,id}`, and cross-resource references (roles, users, grants, connections, clients) are re-loaded under the tenant. User search and organization search bind every value and metadata path as SQL arguments, and metadata keys that contain `"` or `\` are refused, so I found no injection. `client_secret` is revealed only with `read:client_keys`, connection `configuration` values are returned as sealed blobs, and social/passwordless secrets are write-only.

Findings: 0 critical, 0 high, 2 medium, 6 low. **1 is fix-before-1.0** (F1: RBAC membership routes refuse tokens set up the way Auth0's documentation says). No post-coverage changelog entry touches this area.

## Findings

### F1 [medium] [parity-gap] User/role membership routes require the newer `*:role_members` scopes in addition to the documented `read:users`/`read:roles`/`update:users`
- Where: internal/server/mgmtapi.go:553-559 (`GetRoleUsers`, `PostRoleUsers`, `GetUserRoles`, `PostUserRoles`, `DeleteUserRoles` via `scopedAll`); D-0052 (docs/compat/decisions.md:1025, "Membership operation scopes are all-of"); internal/rbacrules/inventory.json (`scope_match: all`)
- What: `GET /users/{id}/roles` needs `read:users` **and** `read:roles` **and** `read:role_members`. `POST /users/{id}/roles` needs `update:users` **and** `create:role_members`. An M2M client configured exactly as Auth0's RBAC guides say gets `403 insufficient_scope` on ordinary role assignment and listing. That breaks node-auth0/Terraform/Deploy-CLI style automation that grants the classic scopes.
- Evidence: https://auth0.com/docs/manage-users/access-control/configure-core-rbac/rbac-users/view-user-roles: "Access Token for the Management API with the scopes `read:users` and `read:roles`". https://auth0.com/docs/manage-users/access-control/configure-core-rbac/rbac-users/assign-roles-to-users: "with the scopes `read:roles` and `update:users`". The OAS lists `read:users, read:roles, read:role_members` in a single array. The same file uses that convention as alternatives elsewhere (for example `GET /clients` lists `read:clients, read:client_keys, read:client_summary, read:client_credentials`), and zeroauthy treats those lists as any-of on every other route. D-0052's all-of reading therefore conflicts with Auth0's own guides.
- Verdict: CONFIRMED (code). Auth0's exact runtime rule is unobserved, but the documented token configuration is refused.
- Recommendation: fix-before-1.0 (Management auth on a core RBAC flow; small change)
- Suggested fix: accept either the documented classic pair (`read:users`+`read:roles`, `update:users`[+`read:roles`]) or the fine-grained `*:role_members` scope. Update D-0052 and the inventory to match.

### F2 [medium] [defect] Imported bcrypt hashes have no cost cap, so one sign-in attempt can burn CPU for hours
- Where: internal/passhash/parse.go:148-151 (bcrypt `custom_password_hash` checks only the `$2` prefix); internal/passhash/bcrypt.go:13-28 (`bcrypt.CompareHashAndPassword`, which accepts cost up to 31); called synchronously from internal/identity/database.go:261-265 (`importedLogin`) on every password sign-in for that user
- What: kdf.go states that "Work budgets bound the time one login can spend on an imported hash" and enforces them for pbkdf2, argon2 and scrypt, both at parse and in `Verify`. bcrypt is left out. An import containing, say, `$2b$31$…` is accepted. After that, anyone who knows the user's login triggers 2^31 bcrypt rounds per attempt, with no context cancellation, until a sign-in succeeds or the hash is replaced. The trigger is unauthenticated. The import itself needs `create:users`, so this amplifies a careless or hostile import rather than being remotely exploitable on its own.
- Evidence: kdf.go:12-26; the parse switch has caps for argon2/pbkdf2 (parse.go:153-166) but not bcrypt; `password_hash` is pinned to cost 10 by `bcryptPattern`, but `custom_password_hash` with algorithm `bcrypt` is not.
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-45 (operational hardening); it is a one-line fix and could be pulled in
- Suggested fix: read the cost with `bcrypt.Cost` at parse (`MAXIMUM`, `costTooBig("bcrypt")`) and in `verifyBcrypt` (`ErrUnusable`), capping around 16-18.

### F3 [low] [parity-gap] `PATCH /users/{id}` refuses `null` for most nullable attributes and refuses `verify_phone_number`
- Where: internal/mgmt/users.go:468-506 (`readPatchBody`: `strPtr(k, k == "given_name" || k == "family_name")`; unknown keys give `unknownUserProperty`)
- What: `{"name": null}`, `{"nickname": null}`, `{"picture": null}`, `{"phone_number": null}` and `{"username": null}` all answer `400 invalid_body`. Auth0 documents that these can be unset with `null`. `verify_phone_number` is an unknown property.
- Evidence: OAS `UpdateUserRequestContent`: `email, phone_number, given_name, family_name, name, nickname, picture, password, username` are typed `['string','null']`, and `verify_phone_number` is a boolean property. PATCH description: "Supported attributes can be unset by supplying `null` as the value."
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-45 (or a small users follow-up)
- Suggested fix: allow `null` for `name`/`nickname`/`picture`/`phone_number`/`username` and apply the same clearing rules as `given_name`. Accept `verify_phone_number`, as a no-op or by sending the phone verification.

### F4 [low] [parity-gap] `organization_id` refused on `POST /jobs/verification-email` and `POST /tickets/email-verification`
- Where: internal/mgmt/jobs.go:214-216 (stale comment "organization_id included: there are no organizations"); internal/mgmt/tickets.go:346 (allowed list without `organization_id`)
- What: Plans 29-30 shipped organizations, and the password-change ticket accepts `organization_id` (tickets.go:286-319). The two verification paths still answer 400 for it, so organization-branded verification emails and links cannot be requested.
- Evidence: the OAS request schemas for both operations list `organization_id`.
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-42 (organization self-service/branding), or record it as a deliberate deviation in D-0055
- Suggested fix: accept `organization_id`, validate membership as `PasswordResetContext` does, and carry it into the ticket/email context. Fix the stale comment.

### F5 [low] [parity-gap] Two organization reads accept a scope Auth0 does not list, while D-0055 says they "follow the public reference"
- Where: internal/server/mgmtapi.go:764 (`ListOrganizationMembers`: `read:organization_members` **or** `read:organization_member_roles`); :790 (`ListUserOrganizations`: `read:users` **or** `read:organizations`); docs/compat/decisions.md:1362-1373
- What: a token holding only `read:users` can list a user's organization memberships, and a token holding only `read:organization_member_roles` can list members. The disclosure is minor, but the recorded rationale does not match the current reference.
- Evidence: OAS `GET /users/{id}/organizations` security is `['read:organizations']`; `GET /organizations/{id}/members` is `['read:organization_members']`, and its description adds that `fields=roles` additionally needs `read:organization_member_roles`.
- Verdict: CONFIRMED (against the current OAS); PLAUSIBLE that an older docs page listed both
- Recommendation: defer-to-Plan-45
- Suggested fix: require `read:organizations` and `read:organization_members` respectively (keeping the `fields=roles` check), or cite the source for the broader set in D-0055.

### F6 [low] [parity-gap] `GET /users?connection=` filters under search engine v2/v3
- Where: internal/mgmt/users.go:203-210
- What: zeroauthy ANDs `identities.connection:<c>` into every search. Auth0 documents that `connection` applies only to `search_engine=v1`, and zeroauthy refuses v1. A client that sends both `connection` and `q` gets a narrower result than on Auth0. I found no decision recording this.
- Evidence: OAS `GET /users` parameter `connection`: "Only applies when using search_engine=v1. To filter by connection with search_engine=v2|v3, use q=identities.connection:"connection_name"".
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-45
- Suggested fix: ignore `connection` under v2/v3 (still applying `checkQueryText`), or record the deviation in D-0043 and `docs/user-search.md`.

### F7 [low] [docs-drift] Scope table in `docs/management-api.md` misstates `read:users_app_metadata`
- Where: docs/management-api.md:89 ("`app_metadata` is included with `read:users` or `read:users_app_metadata`")
- What: no code reads `read:users_app_metadata` (it appears only in internal/tenantsetup/management.go:120). The user GET routes require `read:users` (mgmtapi.go users wrappers), so `read:users_app_metadata` alone gives 403. `app_metadata` is always included for `read:users` callers. Related: the OAS also lists `read:user_idp_tokens` (and `read:current_user`) as accepted on `GET /users/{id}`, but zeroauthy requires `read:users` and uses `read:user_idp_tokens` only as an add-on (users.go:298).
- Evidence: code grep; OAS security for `GET /users/{id}`.
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-45 (docs fix can land any time)
- Suggested fix: change the cell to "`read:users` (`app_metadata` always included); `read:user_idp_tokens` additionally adds upstream tokens on the single-user GET".

### F8 [low] [parity-gap] List query parameters in the current OAS are silently ignored
- Where: api/management.yaml and handlers. Compared by script against the OAS.
- What: these documented parameters are missing:
  - `GET /clients`: `q`, `is_global`, `from`/`take`, `external_client_id`, `agent_id`
  - `GET /roles`: `from`/`take`, `owner_id`
  - `GET /users`: `primary_order` (harmless)
  - `GET /users/{id}/sessions` and `/refresh-tokens`: `include_totals`
  - `GET /client-grants`: `default_for` (already recorded in matrix.md:47)

  The generated router ignores unknown query keys, so a client that pages `/clients` by checkpoint or filters with `q` gets the first page or unfiltered results without an error.
- Evidence: OAS parameter lists for those operations.
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-38 (it collects new Management API surface)
- Suggested fix: implement `from`/`take` on `/clients` and `/roles` first (they affect correctness for large tenants). Until then, return 400 for `from`/`take`/`q` on `/clients` rather than ignoring them.

## Verified, no finding
- Scope coverage: every `/api/v2` method in my area has a `scoped`/`scopedAll` wrapper. Differences from the OAS in this area go in the stricter direction (for example `PATCH /clients` with only `update:client_keys` is limited to `client_secret`, clients.go:279-288; `PATCH /users` with only `update:users_app_metadata` is limited to `app_metadata`, users.go:757-765), except F1 and F5.
- M2M token acceptance: only `gty=client-credentials` with `sub == azp+"@clients"` and the serving issuer (auth.go:222-243). Actions cannot override `gty`/`scope` (internal/actions/claims.go:27-35).
- Client grants: the operator audience and other tenants' Management APIs are refused (client_grants.go:295-325). RBAC refuses system APIs and protocol scopes (sqlstore/rbac.go:128-139), and removed RS scopes are pruned (rbac.go:523).
- Cascades: `organization_client_grants` has FK cascades; client delete drops grants/user grants/refresh tokens; connection delete deletes or strips users and organization links.
- Import/export: 500 KB body cap and 2 concurrent imports match the bulk-import docs. Hashes are masked in error echoes, including the HMAC key. Export never emits hash fields (exporter.go:54). Download links are HMAC-bound to tenant and job, live 60 s, and are checked again against job status/expiry. Upsert replaces metadata whole, as documented.
- Search: depth-bounded parser, `(page+1)*per_page <= 1000`, values parameterized on all three SQL dialects.

## Changelog entries reviewed
Coverage in docs/compat/changelog-review.md runs through 2026-10-27. I fetched https://auth0.com/changelog/llms-full.txt (738,344 bytes) on 2026-11-03.
- 2026-10-27 — Universal Portals (Developer Preview): touches org admin self-service, not the core resources. Already deferred to Plan 42.
- 2026-10-29 — HTTP Message Signatures for Tenant Network ACLs: not this area.
- 2026-10-30 — Exponential backoff for Phone MFA SMS delivery: not this area (MFA/phone).
- No entry dated after 2026-10-30 is visible.

## Roadmap suggestions
- **Plan 38 (new Management API resources):** add the current-OAS operations in this area that no plan names:
  - `GET /clients/search`, `GET /client-grants/search`, `GET /resource-servers/search`
  - `GET /clients/{id}/connections`
  - `PATCH /sessions/{id}` and `POST /sessions/{id}/revoke` (Auth0's revoke also revokes the session's refresh tokens, unlike `DELETE`)
  - `GET /refresh-tokens`, `PATCH /refresh-tokens/{id}`, `POST /refresh-tokens/revoke`
  - `POST /users/{id}/revoke-access`
  - `GET /users/{id}/effective-roles` and `/effective-permissions` (with their `sources` sub-routes)
  - `GET/DELETE /users/{id}/consent-signing-keys`
  - `POST /users/{id}/risk-assessments/clear`
  - the F8 query parameters

  Groups routes (`/roles/{id}/groups`, `/organizations/{id}/groups…`, `/users/{id}/groups`) already sit with Plan 38 groups. `/clients/cimd/*` belongs with dynamic registration (Plan 35 or a CIMD plan). `GET /users/{id}/connected-accounts` belongs with Plan 43.
- **Plan 45 (hardening):** F2 (bcrypt cap), F3, F5, F6, F7. Also bound `usersOnConnection` (sqlstore/connections.go:186), which loads every user of the tenant into memory inside one transaction when a connection is deleted.
- **Plan 42:** F4 (organization context on verification email/ticket).
