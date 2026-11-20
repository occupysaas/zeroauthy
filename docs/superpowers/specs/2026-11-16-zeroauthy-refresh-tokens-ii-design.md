# Plan 48 — Refresh tokens II (rotation conversion, strict leeway, grant cascade, MRRT, online refresh tokens, token quotas)

**Date:** 2026-11-16; amended 2026-11-18. **Status:** implementation and local review/verification complete; CI pending. Maintainer authorized DPoP support for online refresh tokens on 2026-11-18.

**Roadmap entry:** [management roadmap, Plan 48](2026-10-19-zeroauthy-management-roadmap-design.md)
("short", proposed by the pre-1.0 review); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **P2** (track P, after P1 = Plan 35, merged). Plan 35 moved
`token_quota` here. Read the [clean-room policy](../../../CLEAN_ROOM.md),
`AGENTS.md`, D-0012 (rotation and reuse detection), D-0043 (users,
sessions, refresh tokens; U8), the [Plan 35 spec](2026-11-08-zeroauthy-client-credentials-jar-token-exchange-design.md)
and `internal/oauth/grant_refresh_token.go`.

## 1. Outcome and scope

Refresh tokens behave the way Auth0 documents them across configuration
changes and revocation paths, and the newer Auth0 refresh-token features
exist:

- Turning rotation on or off converts a client's existing tokens on their
  next exchange, as documented.
- The rotation overlap period (`leeway`) lets only the immediately previous
  token be reused.
- Deleting a user grant revokes the refresh tokens issued under it; the
  tenant flag `revoke_refresh_token_grant` makes `/oauth/revoke` delete the
  grant too.
- The refresh grant re-checks the API's `allow_offline_access`.
- **Multi-resource refresh tokens (MRRT):** a client's
  `refresh_token.policies` let one refresh token obtain access tokens for
  other APIs.
- **Online refresh tokens (ORT):** an API with `allow_online_access` issues a
  session-bound refresh token for the `online_access` scope; it lives and
  dies with the login session.
- The rest of the current refresh-token and session Management API:
  `GET /refresh-tokens`, `POST /refresh-tokens/revoke`,
  `PATCH /refresh-tokens/{id}` (`refresh_token_metadata`),
  `PATCH /sessions/{id}` (`session_metadata`), `POST /sessions/{id}/revoke`,
  and refresh-token `device` details.
- **Token quotas** (Early Access on Auth0, moved here from Plan 35):
  `default_token_quota` on the tenant, `token_quota` on clients and
  organizations, enforced on the client-credentials grant with Auth0's quota
  headers.

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first). Every behaviour traces to an Auth0 docs page or the Management
OpenAPI (§2), an RFC, or a numbered local ruling (**LR48-n**, §9) recorded in
**D-0070** (the P2 block D-0070–0079). Undocumented points get a local
answer now and an observation entry (**R1–Rn**, §9).

**Size:** "short" in the roadmap; with MRRT, ORT and quotas it is medium.
This also adds a shared `internal/dpop` verifier used by OAuth and UserInfo.
The DPoP expansion is part of this active plan, not a separate roadmap item.

### In scope

1. **Rotation conversion** (§3.1).
2. **Strict leeway** (§3.2).
3. **Grant cascade** (§3.3): `DELETE /api/v2/grants/{id}` and
   `DELETE /api/v2/grants?user_id=` revoke the refresh tokens issued under
   the grant; `flags.revoke_refresh_token_grant` (stored since Plan 19)
   becomes enforced at `/oauth/revoke`.
4. **`allow_offline_access` re-check** at the refresh grant (§3.4).
5. **MRRT** (§4): `refresh_token.policies` on clients, the refresh grant's
   `audience` and `scope` against the policies, `event.client.refresh_token.policies`
   in post-login Actions.
6. **ORT** (§5): resource-server `allow_online_access` and
   `allow_online_access_with_ephemeral_sessions`, the `online_access` scope,
   session binding, `/oauth/revoke` and `api.refreshToken.revoke()` ending
   the session, `event.refresh_token.access`.
7. **Refresh-token and session Management API completion** (§6).
8. **Token quotas** (§7).
9. **Console, seed, Deploy CLI, docs, tests** (§8).

### Not in scope

- mTLS-bound tokens and upstream federation DPoP. Downstream DPoP is included by the 2026-11-18 maintainer ruling (§5.1).
- `/api/v2/device-credentials` beyond what exists today: moves to M1
  (Plan 38d) with the other legacy resources (LR48-1).
- `POST /api/v2/users/{id}/revoke-access` (the pre-1.0 review's OAS gap
  list): stays in M1, since it also ends sessions and grants for every
  application (LR48-1). `/sessions/{id}/revoke` moves from M1 to here.
- Refresh tokens for SAML/WS-Fed applications (F2/F3).
- Quotas for grants other than client credentials (Auth0 counts only
  client-credentials tokens).

### Anti-goals

- **Family escape.** No conversion, MRRT exchange or ORT path may produce a
  token outside its family's revocation reach: revoking a family, a grant,
  a session or a user still revokes everything issued from it.
- **Ceiling growth.** An MRRT exchange never stores the extra audience or
  scopes in the family; the family's stored ceiling stays what the user
  consented to at login, and policy scopes are re-derived on every exchange
  (as Plan 35 did for Action additions).
- **Silent session extension.** An ORT exchange resets the session idle
  timeout but never the absolute lifetime.
- **Quota counters as an oracle.** Quota headers are sent only to the
  authenticated client, only for the quotas that apply to it.
- **Secrets in logs.** Refresh tokens and their hashes never appear in logs,
  log streams, events or Action logs (memory: secrets never in logs);
  refresh-token IDs may.

## 2. Evidence

Read 2026-11-16:

- Rotation: `/docs/secure/tokens/refresh-tokens/refresh-token-rotation`
  (reuse revokes the family; `ferrt` log).
- Configure rotation: `/docs/secure/tokens/refresh-tokens/configure-refresh-token-rotation`
  — "Exchanging a non-rotating refresh token issues a new rotation refresh
  token and deletes all the non-rotating tokens issued for the same
  `client_id`, resource server, user and tenant"; "Only the previous token
  can be reused; if the second-to-last one is exchanged, breach detection will
  be triggered"; disabling rotation: "Exchanging a rotating refresh token
  issues a non-rotating refresh token and revokes the rotating refresh token
  family issued for the same `client_id`, resource server, user and tenant";
  rotating lifetime default 30 days, max 1 year; "The lifetime does not
  extend when tokens are rotated."
- Revoke: `/docs/secure/tokens/refresh-tokens/revoke-refresh-tokens` —
  "When a grant is revoked, so are all tokens issued in the context of that
  grant"; *Refresh Token Revocation Deletes Grant* tenant setting; unlinking
  a device keeps the grant.
- MRRT: `/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token`
  and `.../configure-and-implement-multi-resource-refresh-token`
  (first-party only; target API must allow skipping consent; Management API
  excluded; omitted `audience` → original audience plus policy scopes; new
  `audience` must be in a policy; unauthorized scopes silently ignored;
  invalid policy entries silently ignored; `event.client.refresh_token.policies`).
- ORT: `/docs/secure/tokens/refresh-tokens/online-refresh-tokens/online-refresh-tokens`
  and `.../configure-online-refresh-tokens` (Beta on Auth0; per-API
  `allow_online_access`; `online_access` scope; authorization code flow;
  not rotated, the same ORT is reused; lifetime is the session's; each
  exchange resets the session idle timeout, not the absolute lifetime;
  `/oauth/revoke` and `api.refreshToken.revoke()` end the whole session;
  `event.refresh_token.access == 'online'`, `event.session`).
- Token quotas: `/docs/fine-grained-m2m-token-quotas` (Early Access;
  precedence client → tenant default, organization → tenant default; only
  client-credentials tokens counted; UTC hour and UTC day windows;
  `enforce` default `true`; `429 {"error":"too_many_requests","error_description":"Client quota exceeded"}`;
  headers `Auth0-Client-Quota-Limit` / `Auth0-Organization-Quota-Limit`
  `b=per_hour;q=10;r=7;t=3540,b=per_day;q=50;r=47;t=43200`, plus
  `X-RateLimit-*` and `Retry-After` on 429; logs
  `token_quota_consumption_warning` at 60/80/100 % and `feccft`).
- Management OpenAPI: `ClientRefreshTokenConfiguration` (`policies`,
  1..10 items of `{audience ≤ 600, scope[] each ≤ 280}`),
  `ResourceServer.allow_online_access`,
  `allow_online_access_with_ephemeral_sessions`,
  `TenantSettingsFlags.revoke_refresh_token_grant`, operations
  `get_refresh_tokens`, `revoke_refresh_tokens`, `patch_refresh-tokens_by_id`,
  `patch_sessions_by_id`, `revoke_session`, schemas `RefreshTokenMetadata` /
  `SessionMetadata` (≤ 25 string properties, ≤ 255 characters each),
  `RefreshTokenDevice`, `TokenQuota*`, `DefaultTokenQuota`.

## 3. Rotation, leeway, grants, offline access

### 3.1 Conversion

The refresh grant compares the presented token's `Rotating` with the
client's current `refresh_token.rotation_type`:

- **Non-rotating token, client now rotating:** issue a rotating token in a
  new family (keeping `ExpiresAt` per the client's rotating lifetime from
  *now*, LR48-2), and in the same transaction delete every non-rotating
  token of the same tenant, client, audience and user (the presented one
  included). Response carries the new refresh token.
- **Rotating token, client now non-rotating:** issue a non-rotating token,
  and in the same transaction revoke the rotating family (all rotating
  tokens of the same tenant, client, audience and user, LR48-3).
- Conversion runs after every check the grant does today (reuse, expiry,
  audience, scope, user, organization, post-login), so a token that would be
  refused is never converted.

### 3.2 Strict leeway

Today any already-rotated token inside its own leeway may be exchanged
again. New rule: inside the leeway only the **immediately previous** token
(the parent of the family's newest live token) may be exchanged; any older
rotated token is reuse and revokes the family (documented). Storage gains a
`ParentID` on refresh tokens and a store method that answers "is this the
newest token's parent" atomically inside `Rotate` (§8.1). A leeway reuse
issues a new rotating token (documented) and makes it the family's newest;
the token that was newest becomes a sibling that is no longer the latest
(it stays valid until rotated or revoked, R1).

### 3.3 Grant cascade

- `DELETE /api/v2/grants/{id}` and `DELETE /api/v2/grants?user_id=` revoke
  every refresh token of that user and client (the grant's audience only,
  when the grant records one; R2) in the same transaction, and bump the
  user's version so in-flight mints fail (existing pattern).
- `/oauth/revoke` with `flags.revoke_refresh_token_grant: true`: also
  deletes the user's grant for that client and audience, which in turn
  revokes the other tokens of the same user, client and audience
  (documented). Default `false` (OpenAPI; tenants created after 2021).
- Unlinking a device (`DELETE /api/v2/refresh-tokens/{id}`,
  `DELETE /users/{id}/refresh-tokens`) keeps the grant (documented).

### 3.4 Offline access re-check

The refresh grant fails with `invalid_grant` ("the API no longer allows
offline access", LR48-4 wording) when the token's API now has
`allow_offline_access: false`. ORTs are checked against
`allow_online_access` instead (§5).

## 4. Multi-resource refresh tokens

### 4.1 Configuration

- `refresh_token.policies`: `null` or 1..10 entries (LR48-5) of
  `{audience, scope[]}`; `audience` 1–600 characters, each scope 1–280.
- Write-time validation: duplicate audiences refused (`400`); the Management
  API audience (`https://<tenant>/api/v2/`) refused (documented exclusion);
  third-party clients (`is_first_party: false`) refused (documented
  first-party only). Unknown audiences and scopes are **stored** and ignored
  at exchange (documented "silently ignore").

### 4.2 Exchange

At `grant_type=refresh_token`:

- **No `audience`, or the token's own audience:** access token for the
  token's audience; scopes = requested scopes (or the token's) ∪ the policy
  scopes for that audience, filtered by the API's definitions, RBAC
  (Plan 26 `decide`) and consent.
- **Another `audience`:** must equal a policy audience whose API exists,
  has `skip_consent_for_verifiable_first_party_clients: true` and is not the
  Management API; otherwise `invalid_request` "audience is not allowed by the
  refresh token policies" (LR48-6; today's audience-mismatch error otherwise
  stays). Scopes = requested ∩ policy scopes (or all policy scopes when
  `scope` is omitted), filtered by API definitions and RBAC; unauthorized
  requested scopes are dropped silently (documented).
- The family's ceiling is never widened (anti-goal); MRRT access tokens
  carry the other API's `aud` and its token lifetime and signing algorithm.
- Rotation proceeds as for any exchange (the new token keeps the family's
  original audience and stored scopes).
- `id_token` is issued as today when `openid` is in the family's scopes.
- On a cross-API exchange the token response also reports an explicitly
  requested, family-authorized `openid` for the issued ID token and
  `offline_access` for an offline refresh token supplied or retained. The
  target access token contains only its permitted API scopes.
- Post-login Actions run with `event.resource_server` = the target API and
  `event.client.refresh_token.policies` populated (documented member).

## 5. Online refresh tokens

- **Issuance:** at the authorization-code grant (and PKCE), when the
  requested scopes contain `online_access`, the API has
  `allow_online_access: true`, the client has the `refresh_token` grant, and
  the login session is persistent (or the API has
  `allow_online_access_with_ephemeral_sessions: true`, R3). The token is
  stored with `Access = "online"` and the login session ID. If the request
  contains both `offline_access` and `online_access`, reject it with
  `invalid_request` at authorization entry, before creating a transaction
  (LR48-7). Public clients must present a valid DPoP proof at issuance and
  every exchange. Confidential clients authenticate normally; a supplied
  DPoP proof binds their refresh token too.
- **No rotation:** the same ORT is reused on every exchange (documented),
  whatever the client's rotation setting.
- **Lifetime:** valid while the session is live; no own `ExpiresAt` or
  `IdleExpiresAt` beyond the session's. Each exchange resets the session's
  idle expiry (bounded by its absolute expiry) and records
  `last_interacted_at`.
- **Session end:** logout, session deletion (`DELETE /sessions/{id}`,
  `DELETE /users/{id}/sessions`), session expiry and `POST /sessions/{id}/revoke`
  invalidate the session's ORTs. U8 (deleting sessions does not revoke
  *offline* refresh tokens) stays true for offline tokens.
- **Revocation:** `/oauth/revoke` on an ORT ends the whole session (and all
  its ORTs); so does `api.refreshToken.revoke()` in a post-login Action
  (documented).
- **Grants:** ORT exchange outside the authorization-code family (device,
  password, token exchange, CIBA) is not offered (documented flows only,
  LR48-8).
- **Actions:** `event.refresh_token.access` is `online` or `offline`;
  `event.session` is set on ORT exchanges.
- Management API: ORTs are not listed, returned, patched or individually
  revoked through refresh-token Management routes. They are managed through
  their session. Internal storage may retain hashed ORT records to preserve
  existing transaction and revocation guarantees; this does not expose them
  as independent Management resources.

### 5.1 DPoP extension authorized 2026-11-18

Public evidence checked 2026-11-18:

- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html), especially §§4–10.
- [Auth0 DPoP](https://auth0.com/docs/secure/sender-constraining/demonstrating-proof-of-possession-dpop).
- [Sender-constraining configuration](https://auth0.com/docs/secure/sender-constraining/configure-sender-constraining).
- [Current ORT behavior](https://auth0.com/docs/secure/tokens/refresh-tokens/online-refresh-tokens/online-refresh-tokens).

The shared verifier authenticates the proof before a grant consumes a code,
rotates a token, changes a session or consumes quota. It uses existing
`go-jose/v4` and the standard library, with no dependency additions.

Local validation policy (LR48-13): accept ES256 and RS256 only; RSA modulus
2048–4096 bits and EC P-256 only. Proofs are compact JWS, at most 16 KiB,
with exactly one protected signature, `typ=dpop+jwt`, an embedded public
`jwk`, and no private/symmetric material or remote key references. Reject
unsupported critical headers and duplicate JSON members in protected header,
JWK and claims. Bound parsing before crypto. Require string `jti` 1–200,
`htm`, `htu`, and integral numeric `iat`; timestamps are accepted from
now−60s through now+5s. Proof/header/key errors are `400 invalid_dpop_proof`
at the token endpoint, with generic original wording and no proof logging.

Match the effective public endpoint from tenant resolution and trusted
proxy routing, not arbitrary forwarded headers. Compare URI without query
or fragment, with RFC 3986 case/default-port/unreserved-path normalization;
never treat another origin as equivalent. Reject URL credentials and fragments in
proof URI. Multiple DPoP header values or a comma-joined header are invalid.
JWK thumbprints use RFC 7638 SHA-256. Resource proofs additionally validate
`ath` against the exact access-token bytes and its authenticated `cnf.jkt`.

Replay prevention is store-backed and atomic: `Store.DPoP().UseProof(ctx,
tid, origin, jkt, jti, now, expiresAt)` returns `ErrConflict` on reuse.
Store only a digest of jti in a dedicated table keyed by tenant, origin,
thumbprint and digest. Retain through `iat+65s` (the last admissible replay,
including allowed future skew); expired entries may be replaced atomically.
`PurgeBefore(ctx, before, limit)` bounds sweep work. The memory store rolls
this state back with transactions; SQL and gRPC share the same contract.
The capability is included in `refresh_tokens_ii.v1`; absent capability
refuses DPoP instead of bypassing replay prevention.

For public clients sending DPoP to the token endpoint, issue a
`400 use_dpop_nonce` response with `DPoP-Nonce` before grant mutation when
the nonce is missing, expired or invalid. UserInfo challenges a request
with a missing, expired or invalid nonce using HTTP `401`,
`WWW-Authenticate: DPoP error="use_dpop_nonce"`, and `DPoP-Nonce`.
Authorization-server and UserInfo nonces have distinct authenticated
domains. A nonce contains issue time and 24 random bytes, sealed by the
existing `keys.Wrapper` with a versioned purpose specific to the domain,
tenant, issuer and thumbprint as AAD, then encoded as base64url. A nonce
is valid only in its issuing domain (RFC 9449 §9). It is reusable for 60s,
bounded to 1 KiB, and usable across replicas sharing the configured wrapper.
Nonce refresh is independent of jti replay. CORS allows request `DPoP` and
exposes response `DPoP-Nonce` for challenges and successful proof responses.
Wrapper or replay-store errors fail closed with `server_error`.

Configuration follows the published sender-constraining table:
`client.require_proof_of_possession` (default false) and API
`proof_of_possession={mechanism: none|dpop, required: boolean,
required_for: all_clients|public_clients}` (default all_clients). `null`
clears API configuration; mTLS stays refused. `required=true` with
mechanism none is invalid. UserInfo-only tokens bind when a valid proof is
supplied. API access tokens bind only when the API enables DPoP; a client
requiring PoP cannot receive an unbound API token. Refresh tokens bind to
any valid supplied proof independently of API access-token policy. For
legacy tenants with explicit `dpop_strict_refresh_token_binding=false`,
retain the documented per-audience binding; online public tokens always
bind. Both new and upgraded tenants default to strict binding when the setting is absent. An existing bound token never
loses its key when settings change. An unbound token is never silently
upgraded by presenting a proof on refresh (RFC 9449 §5).

Bound access tokens carry authenticated `cnf:{jkt:...}` and responses use
`token_type=DPoP`; unbound access tokens use Bearer even when the refresh
token is bound. Existing Action claim restrictions protect `cnf`. Bind the
refresh token's new `DPoPJKT` field at issuance and preserve it across
rotation, conversion and MRRT. Wrong/missing proof cannot revoke, convert
or otherwise mutate a legitimate family. This includes explicit
`/oauth/revoke` for a bound refresh token: check the matching proof after
the existing owner/origin checks and before any family, grant or session
mutation, including expired presentations. Unknown/cross-origin values keep
HTTP 200; the pre-existing wrong-client `invalid_grant` response is unchanged.
A valid owned proof may receive the authorization-server nonce challenge.
This interpretation was confirmed by the controller on 2026-11-19. Support `dpop_jkt` on authorize,
PAR and signed requests. PAR also accepts a `DPoP` header. Validate its
proof for the PAR endpoint under RFC 9449 §4.3 and derive the binding from
the verified public key. When both the effective `dpop_jkt` parameter and
the header are present, reject a thumbprint mismatch before storing the
pushed request. Preserve the selected thumbprint through PAR, the
authorization transaction and the code, and require the matching proof
at code redemption (RFC 9449 §10.1). Upstream enterprise DPoP configuration
is separate from this verifier.

UserInfo accepts DPoP authorization with a proof and verifies key, nonce,
method, public URI, access-token hash and replay. Bound tokens presented
as Bearer or in a form parameter are refused. Other server resource
boundaries (Management and console operator authentication) must refuse
bound tokens unless they validate DPoP; this plan keeps those Bearer-only
and does not mint unusable bound Management/operator tokens. Discovery
advertises `dpop_signing_alg_values_supported=[ES256,RS256]` only when its
storage capability is available. Update log scrubbing for DPoP/proof/nonce
fields, docs for external API `cnf.jkt` validation, and the threat model.

## 6. Management API completion

| Route | Behaviour |
|---|---|
| `GET /api/v2/refresh-tokens?user_id=&client_id=&from=&take=` | checkpoint pagination sorted by token ID ascending (documented "credential_id ascending"); `user_id` required (`400`); unknown user `404`; `read:refresh_tokens`; `fields`/`include_fields` as elsewhere |
| `POST /api/v2/refresh-tokens/revoke` | exactly one of `ids` (1–100), `user_id`, `user_id+client_id`, `user_id+client_id+audience`; other combinations `400`; `202`; revocation runs in the request (LR48-9, the `202` is kept for parity); `delete:refresh_tokens` |
| `PATCH /api/v2/refresh-tokens/{id}` | `refresh_token_metadata` only; `null`/`{}` clears; ≤ 25 properties, string values ≤ 255; `update:refresh_tokens`; returns the token |
| `GET /api/v2/refresh-tokens/{id}` | gains `device` from the token itself (§8.1), `refresh_token_metadata`, `last_exchanged_at` = last exchange time (today: first rotation time; corrected, LR48-10) |
| `PATCH /api/v2/sessions/{id}` | `session_metadata`, same limits; `update:sessions` |
| `POST /api/v2/sessions/{id}/revoke` | deletes the session and revokes every refresh token (online and offline) issued in it; scopes `delete:sessions` + `delete:refresh_tokens`; `202` |
| `GET /api/v2/sessions/{id}` and lists | gain `session_metadata` |

Refresh-token `device`: `initial_ip`, `initial_asn` (empty, R5),
`initial_user_agent`, `last_ip`, `last_asn`, `last_user_agent`, recorded on
issue and on every exchange (today copied from the session).

`refresh_token_metadata` and `session_metadata` are readable in post-login
Actions as `event.refresh_token.metadata` / `event.session.metadata` (R6:
whether the Actions `api` can set them — local: read-only).

## 7. Token quotas

- **Configuration:** tenant `default_token_quota.clients.client_credentials`
  and `.organizations.client_credentials`; client `token_quota.client_credentials`;
  organization `token_quota.client_credentials`. Each `{enforce (default
  true), per_hour?, per_day?}` with at least one property; values 1–2^31−1.
  `null` removes.
- **Counting:** every access token issued by the client-credentials grant
  (including organization-scoped ones) increments the client's buckets, and
  the organization's when the request has one. Windows are the UTC hour and
  the UTC day. Counters are store-backed (multi-instance safe): one atomic
  increment-and-read per bucket.
- **Check order:** before minting, evaluate the client quota and (when
  present) the organization quota "concurrently" (documented), i.e. both are
  checked and both are incremented only when the token is issued (LR48-11:
  a refused request does not consume quota).
- **Exceeded with `enforce: true`:** `429` `{"error":"too_many_requests",
  "error_description":"Client quota exceeded"}` (or "Organization quota
  exceeded", R7), with the quota headers, `X-RateLimit-Limit`,
  `X-RateLimit-Remaining: 0`, `X-RateLimit-Reset` (UNIX time of the earliest
  exhausted bucket's reset) and `Retry-After`; log `feccft`.
- **`enforce: false`:** never refused; counted; warnings logged.
- **Headers:** on every client-credentials response (success and 429), only
  for applying quotas: `Auth0-Client-Quota-Limit` and
  `Auth0-Organization-Quota-Limit`, buckets in `per_hour`, `per_day` order.
- **Warnings:** log type `token_quota_consumption_warning` once per bucket
  window when usage first reaches 60 %, 80 % and 100 % (R8: the log
  `description` text; local wording).
- Unlimited when no quota applies (no headers).

## 8. Storage, console, seed, Deploy CLI, tests

### 8.1 Storage

One migration (numbered at merge; next free after merged Plan 36 is 0042):

- `refresh_tokens`: `dpop_jkt`, `parent_id`, `access` (`offline`|`online`, default
  `offline`), `metadata` (JSON), `device` (JSON), `last_exchanged_at`.
- `login_sessions`: `metadata` (JSON).
- Auth transactions and authorization codes: `dpop_jkt`.
- Clients: `require_proof_of_possession`; resource servers: `proof_of_possession` JSON.
- `dpop_proofs(tenant_id, origin, jkt, jti_hash, expires_at)` replay table with composite primary key and expiry index.
- `token_quota_counters(tenant_id, subject_kind, subject_id, bucket,
  window_start, count, warned)` keyed by tenant, subject, bucket and window.
  The warning mask claims each of 60/80/100 once, including when a quota
  changes mid-window. Counters are swept after their window.
- `clients.refresh_token` JSON gains `policies` (no column change if the
  policy is stored as JSON today; check `sqlstore/clients.go`); clients,
  organizations and tenant settings gain `token_quota` JSON.
- Resource servers gain `allow_online_access`,
  `allow_online_access_with_ephemeral_sessions`.

Store contract changes (`store.RefreshTokens`):

- `Rotate` takes the strict-leeway rule: inside the leeway it succeeds only
  when `oldID` is the parent of the family's newest live token. Record insertion
  order at each successful write and find the live sibling with the greatest
  order under the same lock. Timestamp ties never change the result.
- `ConvertNonRotating(ctx, tid, presentedID, next)` and
  `ConvertRotating(ctx, tid, presentedID, next, at, leeway)` atomically
  claim the presented token and derive the conversion tuple from it. A
  previously rotated presentation must satisfy the same immediate-parent
  and leeway checks as rotation. Reuse revokes only the presented family.
- `RevokeByUserClient(ctx, tid, userID, clientID, audience string, at)`
  (audience empty = all) for grants and bulk revoke.
- `RevokeBySession(ctx, tid, sessionID, at)`.
- `ListByUserPage(ctx, tid, userID, clientID, from string, take int)`.
- `UpdateMetadata`, `RecordExchange(ctx, tid, id, device, at)`.
- `TokenQuotas` repository: `Consume(ctx, tid, subjects []QuotaSubject, now) ([]QuotaState, error)`
  — checks and increments every applying bucket in one transaction and
  returns remaining values and newly claimed warning percentages in each
  bucket’s `CrossedThresholds`. `Peek` returns counts without warning claims.
- gRPC: capability `refresh_tokens_ii.v1`. Without it: strict leeway and
  conversion fall back to the Plan 17 semantics with a startup warning;
  MRRT policies, ORT, metadata, bulk revoke and quotas are refused on write
  (`400`/`501`) (LR48-12).

### 8.2 Console

- Application → Refresh token: rotation overlap help text corrected; MRRT
  policy editor (audience picker from APIs, scope checklist), shown only
  for first-party applications.
- API → Settings: Allow Online Access, ephemeral-session switch.
- Tenant settings → Advanced: Refresh Token Revocation Deletes Grant.
- User → Sessions and Authorized Applications: session revoke (with
  refresh tokens), metadata view.
- Token quotas: tenant default (Settings), application and organization
  quota fields, marked "Early Access on Auth0".

### 8.3 Seed and Deploy CLI

- Seed: client `refresh_token.policies` and `token_quota`, organization
  `token_quota`, tenant `default_token_quota`, resource-server online
  flags.
- Deploy CLI 9.1.0: clients (`refresh_token.policies`, `token_quota`),
  resource servers, tenant flags round-trip in the four cells where the
  handler carries them; others recorded as tool-unsupported.

### 8.4 Tests and E2E

- Unit/integration: conversion both ways, strict leeway table (previous,
  second-to-last, outside leeway), grant cascade, revoke-deletes-grant
  flag, offline re-check, MRRT matrix (no audience, own audience, policy
  audience, non-policy audience, Management API audience, third-party
  client, missing API, scope intersection), ORT lifecycle (issue, reuse,
  idle reset, absolute cap, logout, session delete, revoke ends session),
  quota windows with an injected clock (hour/day boundary), concurrency
  (N parallel client-credentials requests at quota q → exactly q succeed).
- storetest for every new store method in memory, SQL and gRPC.
- E2E `make e2e-refresh-tokens` (new lane `run-m48-refresh-tokens.sh`):
  `@auth0/auth0-spa-js`/`auth0-auth-js` with rotation and MRRT
  (`getTokenSilently({ authorizationParams: { audience } })` against a
  second API), ORT through Playwright login + logout, node-auth0 7.4.0
  `refreshTokens` / `sessions` methods where it has them (raw requests
  otherwise), auth0-cli `api`, quota headers through a plain client
  credentials loop, Deploy CLI round trip.

## 9. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR48-1 | `/device-credentials` and `/users/{id}/revoke-access` stay in M1; `/sessions/{id}/revoke` moves here. |
| LR48-2 | A converted rotating token's absolute lifetime starts at the conversion. |
| LR48-3 | "Rotating family issued for the same client, resource server, user and tenant" means every rotating family matching those four. |
| LR48-4 | Offline re-check failure is `invalid_grant` with local wording. |
| LR48-5 | At most 10 MRRT policies per client, per the Auth0 configuration guide checked on 2026-11-18. |
| LR48-6 | A non-policy audience at the refresh grant is `invalid_request`. |
| LR48-7 | Combined online/offline scopes return `invalid_request` (documented; supersedes original local choice). |
| LR48-8 | ORTs only from authorization code; public clients require DPoP; ORTs are absent from refresh-token Management routes. |
| LR48-9 | Bulk revoke runs synchronously and answers `202`. |
| LR48-10 | `last_exchanged_at` is the last exchange, not the first rotation. |
| LR48-11 | A refused client-credentials request consumes no quota. |
| LR48-12 | Older plugins keep Plan 17 refresh semantics; new features refused on write. |
| LR48-13 | DPoP limits, freshness, nonce and replay policy are specified in §5.1; maintainer authorized scope expansion 2026-11-18. |

Observe later (copied into `docs/superpowers/plan-1-followups.md`):

- **R1** The sibling left valid after a leeway reuse.
- **R2** Whether a user grant without an audience revokes every audience's tokens.
- **R3** ORT with ephemeral sessions when the flag is false (local: no ORT, `online_access` dropped).
- **R4** Resolved 2026-11-18: combined scopes return `invalid_request`.
- **R5** `initial_asn`/`last_asn` (local: empty; no ASN database).
- **R6** Whether Actions can set refresh-token or session metadata.
- **R7** Organization quota error description.
- **R8** Quota warning log description.

## 10. Left to the builder

- Whether the strict-leeway "newest token" is found by a `family_head`
  column or a query on `parent_id`.
- Counter sweep cadence (the existing sweeper).
- Console component split.
