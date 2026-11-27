# Plan 41c — Client-Initiated Backchannel Authentication (CIBA), email channel

**Date:** 2026-11-16. **Status:** implemented on `plan-41c-ciba` (2026-11-26); see the [implementation record](../2026-11-16-plan-41c-implementation-record.md) and D-0100 for where the build departs from this design.

**Roadmap entry:** [management roadmap, Plan 41](2026-10-19-zeroauthy-management-roadmap-design.md)
(CIBA, `/bc-authorize`, the `async_approval` template stored since
Plan 21); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **P5** (track P, after P1). The parallel-paths brief asked "which
approval channel CIBA uses, given Guardian push is not planned": Auth0
documents an **email** channel next to Guardian push, so this plan builds
CIBA on email and keeps push stored-only. Read the
[clean-room policy](../../../CLEAN_ROOM.md), `AGENTS.md`, D-0025, the
[email guide](../../email.md), the [Plan 41a spec](2026-11-16-zeroauthy-oidc-extras-logout-design.md)
and the [Plan 35 spec](2026-11-08-zeroauthy-client-credentials-jar-token-exchange-design.md).

## 1. Outcome and scope

A first-party confidential client's backend POSTs to `/bc-authorize` with a
`login_hint` naming a user, a `binding_message` and scopes. zeroauthy
emails the user (template `async_approval`) a link to a hosted approval
page; the user signs in (or reuses their session), sees the client name
and binding message, and approves or denies. The client polls
`/oauth/token` with `grant_type=urn:openid:params:grant-type:ciba` and the
`auth_req_id` and receives tokens after approval.

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first), OpenID CIBA Core 1.0 (poll mode) where Auth0 is silent. Local
rulings **LR41c-n**, observation points **C41-1…n** in **D-0100** (P5
block D-0100–0109).

### In scope

1. `POST /bc-authorize` (client-authenticated like `/oauth/token`, including
   `private_key_jwt` and JAR `request` objects from Plan 35).
2. CIBA grant at `/oauth/token` (poll mode only — Auth0 discovery lists
   `backchannel_token_delivery_modes_supported: ["poll"]`).
3. Client settings: grant type `urn:openid:params:grant-type:ciba`,
   `async_approval_notification_channels` (`email`; `guardian-push`
   stored only), restrictions (first-party, not `none` auth,
   `oidc_conformant: true`).
4. Email channel: `async_approval` template live (Liquid variables
   `application.name`, `url`, `binding_message`, plus the standard ones),
   verified-email requirement, hosted approval page.
5. Limits: 500 requests per minute per tenant, 5000 pending per tenant
   (expired ones count up to 24 h), `requested_expiry` 1–259200 s.
6. Discovery: `backchannel_authentication_endpoint`,
   `backchannel_token_delivery_modes_supported: ["poll"]`,
   `backchannel_user_code_parameter_supported: false`,
   `backchannel_authentication_request_signing_alg_values_supported`
   (Plan 35's JAR algorithms).
7. Logs, console, seed, conformance (OIDF has no CIBA OP certification
   profile beyond FAPI-CIBA; local tests only, LR41c-1).

### Not in scope

- **Guardian push** (roadmap §5: needs Auth0's Guardian app). A client whose
  channels are only `guardian-push` gets `400` at configuration
  ("guardian-push is not available") and the request fails with
  `invalid_request` at `/bc-authorize` (LR41c-2). Mixed lists use email.
- Ping and push token delivery modes (Auth0 offers poll only).
- Rich Authorization Requests (`authorization_details`): roadmap §5 lists
  RAR for a later decision; refused with `invalid_request` (LR41c-3).
- `user_code` (not supported by Auth0's discovery).

### Anti-goals

- **Login-hint enumeration.** `/bc-authorize` answers the same way for an
  unknown user, a user without a verified email and a valid one
  (`200` with an `auth_req_id`; the unknown/unverified request silently
  expires, C41-1 for Auth0's real answer) — no oracle of account existence.
- **Approval by the wrong person.** The approval page requires the
  hinted user to be the signed-in user (fresh login if the session belongs
  to someone else) and binds the decision to the request; links are
  single use, expire with the request, and are not reusable across
  tenants.
- **Phishing through the binding message.** `binding_message` is bounded
  (≤ 64 characters, printable Unicode letters, digits, spaces and basic
  punctuation, LR41c-4) and shown escaped.
- **Token theft by polling.** Only the client that created the request can
  poll it, with the same client authentication; `auth_req_id` is 256-bit
  random and hashed at rest.
- **Secrets in logs.** `auth_req_id`, approval links and tokens never
  logged.

## 2. Evidence

- Auth0 CIBA overview `/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow`
  (channels: Guardian push default; email add-on to the user's verified
  email, authentication in the browser; no consent grant stored; 500
  requests/min, 5000 pending, expired count up to 24 h).
- Configure CIBA `/docs/get-started/applications/configure-client-initiated-backchannel-authentication`
  (grant type; first-party, not `none`, `oidc_conformant`; any client
  authentication method; `async_approval_notification_channels`;
  `requested_expiry` ≤ 300 s → push, 301–259200 s → email; fallback to
  email when not enrolled in push; `async_approval` template with
  `{{application.name}}`, `{{url}}`, `{{binding_message}}`; verified email
  required).
- Auth0 discovery (`backchannel_authentication_endpoint`,
  `backchannel_token_delivery_modes_supported: ["poll"]`).
- OpenID CIBA Core 1.0 (request parameters, `login_hint` /
  `id_token_hint` / `login_hint_token`, responses, errors
  `authorization_pending`, `slow_down`, `expired_token`, `access_denied`,
  `invalid_grant`).

## 3. `/bc-authorize`

- Client authentication as `/oauth/token` (secret, `private_key_jwt`;
  JAR signed request object optional).
- Parameters: `scope` (must contain `openid`), `login_hint` — Auth0's JSON
  form `{"format":"iss_sub","iss":"<tenant issuer>","sub":"<user_id>"}`
  (C41-2; plain user ID strings refused), `binding_message` (required by
  Auth0? C41-3; local: required), `requested_expiry` (default 300 s, C41-4),
  `audience`, `request` (JAR). `id_token_hint` and `login_hint_token`:
  `invalid_request` (LR41c-5).
- Channel selection (documented): if `requested_expiry` ≤ 300 and push
  were available → push; zeroauthy has no push, so email is used whenever
  the client lists `email` (LR41c-6), for any `requested_expiry` up to
  259200.
- Response `200 {"auth_req_id","expires_in","interval":5}`.
- Errors per CIBA Core (`invalid_request`, `invalid_scope`,
  `unauthorized_client` for a client without the grant, `access_denied`,
  `expired_login_hint_token` n/a), rate limits `429` with
  `too_many_requests` (C41-5).

## 4. Approval

- Email: `async_approval` template (tenant override or built-in) with
  `url` = `https://<host>/u/ciba?ticket=<single-use token>` (C41-6 for
  Auth0's path) on the request's origin (custom domain aware).
- Hosted page: requires sign-in as the hinted user (existing session
  accepted if it is that user; MFA per tenant policy and `acr`), shows the
  application name and binding message, Approve / Deny. Approve records
  the decision with the session's `auth_time`/`amr`; Deny marks
  `access_denied`.
- Post-login Actions run at approval (`event.transaction.protocol`
  `oauth2-ciba`? C41-7) with the requested scopes; `api.access.deny`
  denies the request.
- No consent grant is stored (documented).

## 5. Token polling

- `grant_type=urn:openid:params:grant-type:ciba`, `auth_req_id`, client
  authentication.
- Pending → `400 authorization_pending`; polling faster than `interval` →
  `400 slow_down` (interval +5 s for that request); denied →
  `400 access_denied`; expired → `400 expired_token`; already redeemed →
  `400 invalid_grant`.
- Approved → tokens (ID token for `openid`, access token for `audience`,
  refresh token with `offline_access` per Plan 48 rules), single redemption.
- Logs: the Auth0 CIBA log types from the logs schema (read at build time,
  C41-8).

## 6. Storage, console, tests

- `ciba_requests(tenant_id, id_hash, client_id, user_id, scopes, audience,
  binding_message, status, expires_at, interval, last_poll_at,
  decision_at, auth_time, amr, created_at)`; ticket hashes; sweeper
  removes rows 24 h after expiry (documented pending-limit window); one
  migration numbered at merge; gRPC capability `ciba.v1`.
- Console: application → grant type and channels; tenant email template
  editor already lists `async_approval`.
- Seed: client fields.
- Tests: request validation table, enumeration-safety (identical
  responses), rate and pending limits, approval page identity checks,
  polling state machine with an injected clock, single redemption under
  concurrency, Actions at approval, email rendering.
- E2E `make e2e-ciba` (new lane): node backend client polls; Playwright
  opens the emailed link from the local mail server (Plan 21 E2E mail
  sink), signs in, approves; deny path; expiry path.

## 7. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR41c-1 | No OIDF CIBA certification profile run (FAPI-CIBA needs mTLS/PAR combos). |
| LR41c-2 | `guardian-push` stored only; push-only clients refused. |
| LR41c-3 | `authorization_details` refused. |
| LR41c-4 | `binding_message` ≤ 64 safe characters. |
| LR41c-5 | Only the JSON `login_hint`; no `id_token_hint`/`login_hint_token`. |
| LR41c-6 | Email whenever the client lists it, any expiry up to 72 h. |

Observe later (`docs/superpowers/plan-1-followups.md`):

- **C41-1** `/bc-authorize` answer for unknown or unverified users.
- **C41-2** Accepted `login_hint` formats.
- **C41-3** Whether `binding_message` is required.
- **C41-4** Default `requested_expiry`.
- **C41-5** Rate-limit error body.
- **C41-6** Approval link path.
- **C41-7** `event.transaction.protocol` for CIBA.
- **C41-8** CIBA log types.
