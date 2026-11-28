# Plan 40 — Actions III (session and refresh-token APIs, linking, risk, newer event members)

**Date:** 2026-11-16. **Status:** implemented; merged 2026-11-28 (PR #109); see the [implementation record](../2026-11-16-plan-40-implementation-record.md) and D-0190.

**Roadmap entry:** [management roadmap, Plan 40](2026-10-19-zeroauthy-management-roadmap-design.md)
("short"); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **A1** (track A, first item; Plans 27, 28 and 22 merged). A2 (Plan 38b,
Forms and Flows, `api.prompt.render`) follows in the same track. Read the
[clean-room policy](../../../CLEAN_ROOM.md), `AGENTS.md`, D-0053/D-0054
(Actions contracts), the [Actions guide](../../actions.md),
`internal/actionsrules/inventory.json`, and the [Plan 48 spec](2026-11-16-zeroauthy-refresh-tokens-ii-design.md)
(session and refresh-token metadata storage).

## 1. Outcome and scope

The post-login trigger reaches what Auth0 documents today for sessions,
refresh tokens, account linking and risk, the event object carries the
members Auth0 now documents, `/userinfo` returns Action claims, and the
open Actions follow-ups close.

Grounded in the current post-login reference (read 2026-11-16): today
zeroauthy fails closed on `api.session.*`, `api.refreshToken.*`,
`api.authentication.recordMethod`, `api.authentication.setPrimaryUser`,
`api.prompt.render` and `api.samlResponse.*`, and omits
`event.authentication.riskAssessment`, `event.custom_domain`,
`event.security_context`, `event.transaction.linking_id` / `correlation_id`,
`event.user.last_password_reset`, `event.user.multifactor`, and the newer
`event.session` / `event.refresh_token` members.

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first). Local rulings **LR40-n** and observation points **X1–Xn** go in
**D-0190** (A1 block D-0190–0199). Early Access members are tracked, not
built, unless named below (roadmap §6 "moving target").

### In scope

1. **`api.session`** (post-login): `revoke(reason, options)`,
   `setExpiresAt(absolute)`, `setIdleExpiresAt(inactivity)`,
   `setCookieMode(mode)` (EA, cheap, built — LR40-1), `setMetadata`,
   `deleteMetadata`, `evictMetadata` (EA; built on Plan 48's
   `session_metadata`, LR40-1).
2. **`api.refreshToken`** (post-login on refresh exchanges): `revoke(reason)`,
   `setExpiresAt`, `setIdleExpiresAt`, `setMetadata`, `deleteMetadata`,
   `evictMetadata`.
3. **`api.authentication.setPrimaryUser(primary_user_id)`**: account linking
   inside post-login (§4).
4. **`api.authentication.recordMethod(provider_url)`** in
   `onContinuePostLogin` (external MFA after a redirect, §5).
5. **Event members** (§6): `authentication.riskAssessment` (local signals),
   `custom_domain`, `security_context` (`ja3`/`ja4` from a trusted header
   only), `transaction.linking_id`, `transaction.correlation_id`,
   `user.last_password_reset`, `user.multifactor`, the full documented
   `session` and `refresh_token` members on login and token grants,
   `request.asn` / `request.geoip` stay omitted (D-0053).
6. **`/userinfo` custom claims** set by `api.idToken.setCustomClaim` (the
   Plan 27 deferral, §7).
7. **Custom signup fields** (`ulp-` partial fields from Plan 22) visible to
   `pre-user-registration` as `event.request.body` entries and refusable
   through `api.validation.error` (§8).
8. **Custom database script `context`** argument behind the connection's
   `enableScriptContext` option (§9), if Auth0 documents it at build time
   (X5); otherwise recorded and skipped.
9. **The Plan 27/28 deferred-minor ledgers** (console log aggregate cap,
   sandbox probe assertions) and the Actions entries in
   `docs/superpowers/plan-1-followups.md` that need no maintainer ruling.
10. **Task 1 recheck** of the deferred triggers (`password-hash-migration`,
    `login-post-identifier`, `signup-post-identifier`,
    `post-credential-validation`) and `api.user.setUserId`: each is built in
    this plan only if Auth0 documents its event and `api` by then; on
    2026-11-16 none is documented (the trigger IDs appear only in the
    Management API enum), so they stay deferred (LR40-2).

### Not in scope

- `api.prompt.render`, `event.prompt` (A2, Forms and Flows).
- `api.samlResponse.*` (F2, SAML).
- `api.groups.*` real data (F4 directory groups); they keep returning empty.
- `event.agent`, `event.session_transfer_token`, `session.session_transfer`,
  `refresh_token.session_transfer` (Early Access; Session Transfer Tokens
  are a new follow-up recorded by Plan 41a).
- `riskAssessment.supplemental.akamai` (vendor data).
- `api.transaction.setMetadata` in `custom-token-exchange` (Early Access).
- `rules.wasExecuted` stays `false` (no Rules, roadmap §5).

### Anti-goals

- **Linking takeover.** `setPrimaryUser` links the current user into the
  primary only when the primary exists in the same tenant, is not the
  current user, is not blocked, and the current login's identity is not
  already linked elsewhere; the decision is the Action's (Auth0 leaves
  verification to the developer), but the server never links across
  tenants or into a user the Action did not name.
- **Session extension beyond policy.** `setExpiresAt` / `setIdleExpiresAt`
  may only shorten the session's lifetimes (documented: values beyond the
  tenant's limits are capped), never extend past the tenant's configured
  maximums.
- **Fingerprint spoofing.** `security_context.ja3/ja4` are read only from a
  header the operator names as trusted (`ZEROAUTHY_TRUSTED_JA3_HEADER`,
  `..._JA4_HEADER`), never from arbitrary client headers.
- **Secrets in logs.** Metadata values are not secrets but are bounded; no
  token value enters Action logs (memory: secrets never in logs).
- **Cross-tenant data.** Every new member reads only the Action's own
  tenant (memory: Actions tenant trust domain).

## 2. Evidence

Read 2026-11-16:

- Post-login event object: `/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-event-object`
  (members listed in §6, Enterprise and Early Access marks).
- Post-login API object: `.../post-login-api-object` (`api.session`
  methods with Enterprise/EA marks, `api.refreshToken` methods,
  `api.authentication.recordMethod` "only within onContinuePostLogin",
  `api.authentication.setPrimaryUser`).
- Actions triggers overview: `/docs/customize/actions/explore-triggers`
  (no page for the four newer trigger IDs).
- Management OpenAPI `ActionTriggerTypeEnum` (the four newer IDs listed
  without documentation).
- Pre-user-registration API object: `.../pre-user-registration-api-object`
  (no `api.user.setUserId` on 2026-11-16).
- Account linking in Actions: `/docs/manage-users/user-accounts/user-account-linking/link-user-accounts`
  and the `setPrimaryUser` reference (read at build time, X1).
- Adaptive MFA risk assessments: `/docs/secure/multi-factor-authentication/adaptive-mfa/customize-adaptive-mfa`
  (assessment names `NewDevice`, `ImpossibleTravel`, `UntrustedIP`,
  `AgentDetection`; `confidence` `low` | `medium` | `high` | `neutral`; codes
  such as `match`, `no_match`, `initial_login`, `unknown_device`,
  `found_on_deny_list` — read at build time, X2).

## 3. `api.session` and `api.refreshToken`

| Method | Behaviour |
|---|---|
| `session.revoke(reason, {preserveRefreshTokens})` | ends the current session after the flow; the login is denied with `access_denied` and `reason` (X3: Auth0's error); refresh tokens issued in the session are revoked unless `preserveRefreshTokens: true`; back-channel logout initiator `session-revoked` (Plan 41a) |
| `session.setExpiresAt(ms)` | sets the absolute expiry; capped at the tenant maximum and never later than the current absolute expiry (LR40-3) |
| `session.setIdleExpiresAt(ms)` | same for idle expiry |
| `session.setCookieMode('persistent'|'non-persistent')` | overrides the tenant `session_cookie.mode` for this session's cookie |
| `session.setMetadata(k, v)` / `deleteMetadata(k)` / `evictMetadata()` | Plan 48 `session_metadata` limits (25 keys, string values ≤ 255); aggregated and applied when the flow completes |
| `refreshToken.revoke(reason)` | on a refresh exchange: revoke the presented token's family and deny with `invalid_grant`; online tokens end their session (Plan 48 §5) |
| `refreshToken.setExpiresAt` / `setIdleExpiresAt` | shorten only, as for sessions |
| `refreshToken.*Metadata` | Plan 48 `refresh_token_metadata` limits |

- Availability: `api.refreshToken.*` exists only when `event.refresh_token`
  is present (refresh exchanges); calling it elsewhere throws, as Auth0's
  object is undefined there (X4).
- **Dependency:** metadata methods and `refreshToken.*` storage need Plan 48.
  If Plan 48 has not merged when this plan reaches Task 4, those members
  stay fail-closed and the rest ships (LR40-4).

## 4. `setPrimaryUser`

- Records the primary user ID during the flow. On flow completion, in one
  transaction: move the current user's identities into the primary (the
  Plan 17 link operation), delete the secondary, bump both versions, then
  continue the login as the primary user (tokens carry the primary
  `sub`).
- Refusals (the login fails with `access_denied`, X1): primary absent, same
  user, primary blocked, secondary has more than one identity (Auth0 links
  a user, not a set — local), or the identity already exists on the
  primary.
- Post-login Actions after the one that called it still see the original
  `event.user` (Auth0 applies the change after the flow, X1).
- Logs: the Plan 17 link log type.

## 5. `recordMethod`

- Allowed only in `onContinuePostLogin`; elsewhere throws.
- `provider_url`: an absolute HTTPS URL ≤ 2048 bytes identifying the
  external factor.
- Effect: the session's authentication methods gain
  `{name: provider_url, timestamp}`; the `amr` claim gains `mfa` when the
  tenant treats it as MFA (X6: Auth0's exact effect on `amr`; local:
  `mfa` added); `event.authentication.methods` in later logins of that
  session lists it.

## 6. Event members

| Member | Source in zeroauthy |
|---|---|
| `authentication.riskAssessment` | `NewDevice` from the known-device record Plan 33's `confidence-score` policy already keeps (`low` for an unknown device, `high` known); `UntrustedIP` from Plan 19's suspicious-IP state and the tenant allowlist (`low` when blocked recently, `high` otherwise); `ImpossibleTravel` `neutral` (no GeoIP, D-0053); `AgentDetection` `neutral`; overall `confidence` = the lowest non-neutral, else `neutral` (LR40-5) |
| `custom_domain` | the Plan 23 custom domain of the request (`domain`, `domain_metadata`), absent on the canonical host |
| `security_context` | `ja3`, `ja4` from the trusted headers, else `null` |
| `transaction.linking_id` | a random ID per transaction, shared by its Actions (X7) |
| `transaction.correlation_id` | the transaction's correlation ID when the request carried one (X7) |
| `user.last_password_reset` | database connections: the user's last password reset time |
| `user.multifactor` | enrolled factor names (Plan 33), as `["guardian"|"google-authenticator"|…]` per Auth0's legacy names (X8) |
| `session.*` | `id`, `actor`, `authenticated_at`, `clients`, `cookie.mode`, `created_at`, `device`, `expires_at`, `idle_expires_at`, `last_interacted_at`, `metadata`, `updated_at`, `user_id` |
| `refresh_token.*` | Plan 48's Management API shape on refresh exchanges |

The same `session`/`refresh_token` members appear on token grants that run
post-login (refresh, token exchange) where a session exists.

## 7. `/userinfo` custom claims

- `api.idToken.setCustomClaim` values from the login that issued the access
  token are returned by `/userinfo` for that token (documented Auth0
  behaviour for namespaced claims, X9).
- Storage: zeroauthy access tokens are JWTs without server state, so the
  claims are stored per (session, client) on the login session record, bounded by the
  Plan 27 claim size limit, and read back by `/userinfo` using the token's
  `sid`/`azp`. Tokens without a session (client credentials) have none.
  Refresh exchanges update the record with the latest flow's claims
  (LR40-6).

## 8. Custom signup fields in Actions

- Plan 22's transient `ulp-` fields captured on the signup page are placed
  in `event.request.body` for `pre-user-registration` (documented pattern
  for custom prompts), as strings, bounded by Plan 22's limits.
- `api.validation.error` already refuses the signup; the hosted page shows
  `errorMessage` on the field's page and keeps the fields (today it shows
  the generic error, X10).
- The fields never reach storage, tokens or logs (Plan 22 rule).

## 9. Custom database script `context`

- If Auth0 documents `enableScriptContext` at build time: scripts receive
  `context` (request IP, user agent, language, connection name and ID,
  client ID) as the last argument before `callback` when the option is
  `true`; the Node runner already passes a frozen object. Otherwise the
  option stays stored-only (LR40-7).

## 10. Storage, console, seed, Deploy CLI, tests

- **Storage:** login sessions gain `cookie_mode` override and the
  `/userinfo` claims blob (JSON, bounded); one migration numbered at merge.
  Linking uses existing user/identity operations.
- **Console:** Actions editor type hints (the bundled `.d.ts`) for the new
  members; execution log viewer shows `session.revoke` and `setPrimaryUser`
  outcomes.
- **Seed/Deploy CLI:** no new resources.
- **Tests:** runner-level tests for every new `api` method (success,
  misuse, limits), event shape snapshot tests per trigger, linking
  transaction tests (concurrency: two logins linking the same secondary →
  one wins), `/userinfo` claims round trip, risk-assessment table.
- **E2E:** extend `make e2e-actions` (Plan 27 lane) with: a post-login
  Action that revokes the session on a condition; an Action that sets the
  session expiry shorter (cookie expiry checked); `setPrimaryUser` linking a
  social user into a database user; `/userinfo` with a custom claim through
  `@auth0/auth0-spa-js` 2.28.3 `getUser()`.

## 11. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR40-1 | EA session members `setCookieMode` and metadata are built (small, on Plan 48 storage). |
| LR40-2 | The four newer trigger IDs and `setUserId` stay deferred until documented. |
| LR40-3 | Expiry setters only shorten, capped by tenant maximums. |
| LR40-4 | Metadata and refresh-token members wait for Plan 48; the rest ships. |
| LR40-5 | Local risk signals; no GeoIP or bot detection. |
| LR40-6 | `/userinfo` claims stored per session and client. |
| LR40-7 | Script `context` only if documented. |

Observe later (`docs/superpowers/plan-1-followups.md`):

- **X1** `setPrimaryUser` refusals and when the change applies.
- **X2** Risk assessment codes and confidence values.
- **X3** Error returned after `session.revoke`.
- **X4** `api.refreshToken` outside refresh exchanges.
- **X5** `enableScriptContext` documentation.
- **X6** `recordMethod` effect on `amr`.
- **X7** `linking_id` and `correlation_id` sources.
- **X8** `user.multifactor` values.
- **X9** Which Action claims `/userinfo` echoes (namespaced only?).
- **X10** Hosted-page display of `api.validation.error` on custom fields.
