# Plan 43 — Token Vault and connected accounts

**Date:** 2026-11-16. **Status:** design; not implemented; maintainer
ruling (§9) on the token policy before Task 4.

**Roadmap entry:** [management roadmap, Plan 43](2026-10-19-zeroauthy-management-roadmap-design.md)
(full: "refresh, revocation and consent policy are product decisions");
[parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md) item **P6**
(track P, last; needs P1 = Plan 35, merged, and Plan 24's sealed upstream
tokens, merged). The My Account connected-accounts routes need U1's
`/me/v1` router (Plan 42a); if U1 has not merged, this plan adds the
router skeleton itself. Read the [clean-room policy](../../../CLEAN_ROOM.md),
`AGENTS.md`, the [Plan 24 spec](2026-10-26-zeroauthy-social-connections-design.md)
(upstream token storage), the [Plan 42a spec](2026-11-16-zeroauthy-my-account-api-design.md)
and the [Plan 48 spec](2026-11-16-zeroauthy-refresh-tokens-ii-design.md).

## 1. Outcome and scope

A user connects an external account (Google, Microsoft, GitHub, an OIDC
provider, …) to their zeroauthy profile through the **Connected Accounts**
flow of the My Account API, granting the provider scopes the app needs.
zeroauthy stores the provider's access and refresh tokens in the **Token
Vault**. Later the app (or its API) exchanges its own zeroauthy refresh
token or access token at `/oauth/token` for a fresh **provider** access
token, which zeroauthy refreshes from the stored provider refresh token
when needed — Auth0's "Token Vault" used by its AI-agent features.

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first). Local rulings **LR43-n**, observation points **T1–Tn** in
**D-0110** (P6 block D-0110–0119).

### In scope

1. Connection setting `connected_accounts {active, cross_app_access,
   allow_missing_user_id}` (GA; today stored only, Plan 24) becomes live
   for the federated strategies (`google-oauth2`, `windowslive`, `waad`,
   `oauth2`, `oidc`, `okta` from Plan 36, `apple`/social from S1/S2 as they
   land).
2. My Account API: `POST /me/v1/connected-accounts/connect`,
   `POST /me/v1/connected-accounts/complete`,
   `GET /me/v1/connected-accounts/accounts`,
   `GET /me/v1/connected-accounts/connections`,
   `DELETE /me/v1/connected-accounts/accounts/{id}` (scopes
   `create:`/`read:`/`delete:me:connected_accounts`).
3. Management API: `GET /api/v2/users/{id}/connected-accounts`
   (`read:users`, checkpoint pagination).
4. Token exchange grant
   `urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token`
   with `subject_token_type` `urn:ietf:params:oauth:token-type:refresh_token`
   (refresh token exchange) or `urn:ietf:params:oauth:token-type:access_token`
   (access token exchange), `requested_token_type`
   `http://auth0.com/oauth/token-type/federated-connection-access-token`,
   `connection`, optional `login_hint`, optional `scope` (EA subset;
   built, LR43-1).
5. Provider-token refresh, revocation on disconnect, user deletion and
   connection deletion.

### Not in scope

- **Privileged worker token exchange** (signed JWT bearer → provider token)
  and `token_vault_privileged_access` on clients: Early Access, tracked.
- `cross_app_access` behaviour beyond storing the flag (Auth0's XAA /
  ID-JAG is a separate grant profile; T1).
- Organization-shared connected accounts (Auth0: none — each member
  connects their own).

### Anti-goals

- **Token exfiltration across clients.** A provider token is released only
  to a client that (a) holds a valid zeroauthy token for the same user and
  tenant, (b) is allowed the exchange grant, and (c) — LR43-2 — is
  first-party or explicitly granted for the connection (§9.1).
- **Refreshing forever.** A provider refresh token is used only while the
  connected account exists and the connection still has
  `connected_accounts.active`; disconnect revokes upstream (best effort,
  RFC 7009 when the provider advertises it) and deletes locally at once.
- **Scope widening.** An exchange never returns more than the scopes the
  user granted in the Connected Accounts flow; a requested `scope` must be
  a subset (EA, documented).
- **Secrets in logs.** Provider tokens, authorization codes, `auth_session`
  values never logged (memory: secrets never in logs); exchange logs carry
  connection and client only.
- **Rotation confusion.** Auth0 says Token Vault does not support refresh
  token rotation: the refresh-token exchange refuses rotating zeroauthy
  refresh tokens with a clear error (LR43-3, T2) instead of consuming them.

## 2. Evidence

- Token Vault overview `/docs/secure/tokens/token-vault` (stores access and
  refresh tokens per connected account; three exchanges: refresh token,
  access token, privileged worker; supported providers: Google, Microsoft,
  Box, Slack, GitHub, custom social, Google Workspace, Entra ID, OIDC;
  organizations: each member connects their own).
- Refresh token exchange page (grant type, subject and requested token
  types, `connection`, `login_hint`, `scope` EA; response `access_token`,
  `scope`, `expires_in`, `issued_token_type`, `token_type: Bearer`; expired
  provider token refreshed with the stored refresh token keeping scopes;
  `401` when no matching user/connected account; disable rotation; any
  client authentication method).
- Access token exchange page (read at build time; same response, subject
  token = a zeroauthy access token for an API, T3).
- My Account OpenAPI 1.0: `createConnectedAccountRequest` (body
  `connection`, `redirect_uri` required; `state`, `code_challenge`,
  `code_challenge_method`, `scopes`, `authorization_params`; `201`
  `connect_uri`, `auth_session`, `connect_params`, `expires_in`),
  `completeConnectedAccountRequest` (body `auth_session`, `connect_code`,
  `redirect_uri` required, `code_verifier`; `201` `id`, `connection`,
  `access_type`, `scopes`, `created_at`, `expires_at`; `409`),
  `getConnectedAccounts`, `getConnectedAccountsConnections`,
  `deleteConnectedAccount`.
- Management OpenAPI: `GET /users/{id}/connected-accounts` (`ConnectedAccount`:
  `id`, `connection`, `connection_id`, `strategy`, `access_type` `offline`,
  `scopes`, `created_at`, …), `ConnectionConnectedAccountsPurpose`
  (`active` required, `cross_app_access`, `allow_missing_user_id` — at most
  one such account per user per connection).

## 3. Connected Accounts flow

1. App (holding a My Account token with `create:me:connected_accounts`)
   calls `connect` with `connection`, `redirect_uri` (the app's own URL,
   must be a registered callback of the token's client), `scopes`
   (provider scopes), optional PKCE pair and `state`.
2. zeroauthy creates an upstream federation attempt (Plan 24 machinery)
   with purpose "connect", returns `connect_uri` (a zeroauthy URL that
   redirects to the provider), `auth_session`, `connect_params`
   (`ticket`), `expires_in` (300 s, T4).
3. Browser → provider → `/login/callback` → zeroauthy redirects to the
   app's `redirect_uri` with `connect_code` (single use, bound to the
   attempt) and `state`.
4. App calls `complete` with `auth_session`, `connect_code`,
   `redirect_uri`, `code_verifier`. zeroauthy finishes the code exchange
   (already done at callback; the tokens wait sealed in the attempt),
   checks the upstream subject (required unless
   `allow_missing_user_id`), and stores the connected account:
   `(tenant, user, connection, upstream subject) → sealed {access_token,
   refresh_token, expires_at, scopes}`.
5. Connecting the same upstream account again replaces its tokens and
   unions its scopes (T5); connecting an upstream account already linked
   to **another** user is `409` (LR43-4).
- A connected account is not a login identity: it does not let the user
  sign in with that provider, and it does not appear in `identities`
  (Auth0 separates them, T6).

## 4. Exchanges

- Client must list the grant type in `grant_types` (T7: Auth0's exact
  client setting name) and authenticate.
- **Refresh token exchange:** `subject_token` = a non-rotating zeroauthy
  refresh token of the same client (LR43-3); the user is the token's user.
- **Access token exchange:** `subject_token` = a zeroauthy access token
  (JWT verified with the tenant keys, audience = an API of the tenant, not
  the Management API), presented by a client allowed for that API's
  exchange (T3).
- Select the connected account by `connection` (+ `login_hint` = upstream
  subject or email when several, documented); none → `401
  {"error":"unauthorized","error_description":...}` (T8 for the body).
- If the stored provider access token expires within 60 s, refresh it with
  the provider (Plan 24 token endpoint and client auth), store the new pair
  atomically (CAS on a version), then return it. Provider refresh failure
  with `invalid_grant` marks the account `unavailable` and answers `401`
  (T9).
- Response `200 {access_token, scope, expires_in, issued_token_type,
  token_type: "Bearer"}`; no zeroauthy tokens are issued.
- Logs: the logs schema's federated token exchange types (read at build
  time, T10).

## 5. Revocation and lifecycle

- `DELETE /me/v1/connected-accounts/accounts/{id}`: delete locally; revoke
  upstream when the provider's metadata has `revocation_endpoint`.
- User deletion, connection deletion, or `connected_accounts.active: false`
  (existing accounts are kept but exchanges refused, T11): handled in the
  same transactions as today's federation cleanups.
- The orphan sweep of Plan 45c covers connected-account records too.

## 6. Storage

- `connected_accounts(tenant_id, id, user_id, connection_id, subject,
  scopes, sealed_tokens, version, status, created_at, updated_at)`, unique
  `(tenant_id, connection_id, subject)`; one migration numbered at merge;
  gRPC capability `token_vault.v1`.
- Plan 24's per-identity upstream token storage is unchanged (login
  tokens readable with `read:user_idp_tokens`), separate from the vault.

## 7. Console, seed, tests

- **Console:** connection → "Connected accounts" switch and options;
  user → Connected accounts tab (list, disconnect); application → grant
  type checkbox with the first-party rule.
- **Seed:** connection `connected_accounts` options; client grant type.
- **Tests:** connect/complete state machine (expiry, replay, wrong
  `redirect_uri`, wrong PKCE, other user's `auth_session`), `409` for an
  upstream account owned by another user, exchange table (refresh vs
  access subject, rotating refused, missing account, `login_hint`
  selection, `scope` subset), provider refresh with a fixture provider and
  concurrency (two exchanges refresh once), revocation calls, deletion
  cascades, secret scan.
- **E2E** `make e2e-token-vault` (new lane): Playwright connect flow
  against the Plan 24 fixture provider through `@auth0/auth0-spa-js`
  2.28.3 tokens for My Account, then a Node backend exchanging its refresh
  token for the provider token and calling the fixture provider's API.

## 8. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR43-1 | The EA `scope` subset parameter is built. |
| LR43-2 | Exchange only for first-party clients unless the maintainer rules otherwise (§9.1). |
| LR43-3 | Rotating refresh tokens are refused as subject tokens. |
| LR43-4 | An upstream account connected to another user is `409`. |

Observe later (`docs/superpowers/plan-1-followups.md`): **T1**
`cross_app_access`; **T2** error for a rotating subject token; **T3**
access-token exchange details; **T4** `expires_in` of connect sessions;
**T5** reconnecting an account; **T6** connected accounts vs identities;
**T7** client setting name for the grant; **T8** `401` body; **T9**
provider refresh failure handling; **T10** log types; **T11** existing
accounts when `active` turns false.

## 9. Decisions needed from the maintainer

1. **Which clients may exchange** (the roadmap's "consent policy"):
   first-party only (proposed), or any client with an explicit per-connection
   client grant.
2. **Upstream revocation on disconnect:** best effort (proposed) or
   required (fail the delete when the provider refuses).
3. **Provider refresh tokens kept when a user signs in again with the same
   provider:** separate vault (proposed, as Auth0) — confirm.
