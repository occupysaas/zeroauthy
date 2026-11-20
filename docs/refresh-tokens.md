# Refresh tokens and quotas

Refresh tokens obtain new access tokens without a new login. Configure the
application's `refresh_token` settings and the API's `allow_offline_access`,
then request `offline_access`. Refresh also rechecks current API access,
user/client/organization eligibility and scopes. Disabling offline access
prevents subsequent offline exchanges.

## Rotation and configuration changes

`rotation_type` is `rotating` or `non-rotating`; rotating tokens require
`expiration_type:expiring`. `leeway` is an overlap period in seconds. Only
the immediately previous token can be retried inside that period. Using an
older predecessor revokes its family, even if its original overlap has not
ended. Clients must serialize refresh and retain the latest response.

Enabling rotation converts an existing non-rotating token on its next valid
exchange. The new rotating family starts its configured absolute lifetime
at conversion; other non-rotating tokens for that tenant/client/user/API are
removed atomically. Disabling rotation converts the next valid rotating
presentation and revokes matching rotating families. Tokens for other APIs
are unaffected. Failed authorization never creates a replacement family.

## Multiple APIs

First-party clients can configure up to ten policies:

```json
{"refresh_token":{"policies":[{"audience":"https://billing.example","scope":["read:invoices"]}]}}
```

A refresh exchange can send `audience` for one permitted API. It must exist,
allow skipping consent for verifiable first-party clients, and be outside
the tenant Management API. Unauthorized requested scopes are dropped; API,
client-grant and RBAC restrictions still apply. An omitted audience uses the
family's original API and includes its permitted policy scopes. Unknown
configured API/scope names can round-trip but do not grant access.

An access token targets one API and uses that API's signing/lifetime policy.
Rotation retains the refresh family's original audience and scopes; a
cross-API exchange never widens that stored ceiling. Post-login Actions see
the target API and `event.client.refresh_token.policies`. Family OIDC scopes
determine ID-token eligibility. Use `null` to clear policies.

## Online refresh tokens

Request `online_access` through authorization code with PKCE and enable
`allow_online_access` on the API. The client also needs the refresh grant.
A persistent session is required unless the API explicitly allows ephemeral
sessions with `allow_online_access_with_ephemeral_sessions`. Requesting both
`online_access` and `offline_access` is `invalid_request`. Password, device
and other noninteractive grants do not issue online refresh tokens.

Public clients must use [DPoP](dpop.md) at issuance and every exchange. A
confidential client authenticates normally and retains any supplied binding.
The same online token is reused: a successful refresh does not return a new
refresh token. It resets session idle expiry, capped at the fixed absolute
session expiry. Deleted, expired or logged-out sessions cannot be restored
by an online token. Online tokens are absent from refresh-token Management
lists and cannot be individually managed there.

`/oauth/revoke` on a live online token ends its entire session and all its
online tokens. Bound presentations need a matching endpoint proof. The
post-login Action `api.refreshToken.revoke()` also ends the online session.
Revoked or expired old online tokens cannot end a later live session.
Ordinary logout/session deletion preserves offline refresh tokens; explicit
session revoke removes both types.

## Management and revocation

| Operation | Effect and scope |
|---|---|
| `GET /api/v2/refresh-tokens?user_id=…` | Offline tokens, ID-ascending checkpoint pagination (`from`, `take`), optional `client_id`, field projection; `read:refresh_tokens` |
| `POST /api/v2/refresh-tokens/revoke` | Exactly one selector: IDs (1–100), user, user+client, or user+client+audience; revokes matching offline families synchronously, returns `202`; `delete:refresh_tokens` |
| `PATCH /api/v2/refresh-tokens/{id}` | Replaces `refresh_token_metadata`; `update:refresh_tokens` |
| `PATCH /api/v2/sessions/{id}` | Replaces `session_metadata`; `update:sessions` |
| `POST /api/v2/sessions/{id}/revoke` | Ends session and revokes online and offline tokens issued in it; `202`; both `delete:sessions` and `delete:refresh_tokens` |
| Grant deletion | Revokes the grant's matching refresh tokens and invalidates in-flight mints atomically |

Metadata has at most 25 string properties, with keys and values at most
255 Unicode characters. `null` or `{}` clears it. It is readable in
post-login Actions but not writable through Actions. Token device data
contains initial/last IP and user agent independently of a surviving session;
ASN values are empty. `last_exchanged_at` is updated on successful exchanges.

`flags.revoke_refresh_token_grant:true` makes OAuth token revocation remove
matching consent and other tokens under it. Its default is false. Removing
a device through refresh-token Management routes preserves consent. UserInfo
API audiences use the token's actual issuing origin; legacy originless
records use the canonical tenant origin.

## Client-credentials quotas

Auth0 classifies these quotas as Early Access. Configure
`token_quota.client_credentials` on a client or organization, or defaults
under `default_token_quota.clients.client_credentials` and
`.organizations.client_credentials` on tenant settings. Each bucket accepts
`per_hour` and/or `per_day` integers from 1 to 2147483647, and `enforce`
(default true). At least one property is required; `null` removes a quota.
Client and organization overrides independently replace their tenant default.

UTC hour/day counters are shared in storage. A request increments every
applicable subject only if all enforced buckets permit it. Failed
client/proof/scope/Action/signing requests consume no quota. `enforce:false`
counts and reports usage without refusing. Warnings are logged once per
bucket window at 60%, 80% and 100%.

Successful and quota-refused client-credentials responses include applicable
`Auth0-Client-Quota-Limit` / `Auth0-Organization-Quota-Limit` headers, such as
`b=per_hour;q=10;r=9;t=120`. Refusal is `429 too_many_requests`, with
`X-RateLimit-*` and `Retry-After` for the earliest exhausted reset. Quota
information is never returned to unauthenticated clients.

PATCH preserves omitted nested limits. The console can clear a client/org
quota with null. Tenant defaults support one confirmed reset of the entire
object; clearing one nested subject/limit independently is not supported.
Save the desired remaining defaults after that explicit reset.

## Storage and verification

New features require plugin capability `refresh_tokens_ii.v1`. Initially
legacy plugins retain previous plain rotation/deletion behavior and warn at
startup; new configuration and operations are refused. Loss of a previously
negotiated capability or a transport failure fails closed. New tenants use
strict DPoP refresh binding; legacy absent/false settings keep documented
per-API behavior. Existing key bindings are never removed by configuration.

`make e2e-refresh-tokens` runs the production SQLite server with the pinned
Auth0 clients, real browser login/logout, DPoP proofs and local external-API
verification, Management/CLI checks and the four-cell Deploy CLI lane. It
uses generated synthetic credentials and keeps diagnostics in private local
artifacts. Full race, database and conformance verification belongs to plan
CI; current implementation verification is tracked in the
[Plan 48 record](superpowers/2026-11-16-plan-48-implementation-record.md).
