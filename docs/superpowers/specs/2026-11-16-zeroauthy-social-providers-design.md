# Plan 39b — Remaining social providers, generic OAuth 1.0a, Google and Facebook native login

**Date:** 2026-11-16. **Status:** design; not implemented; provider order
(§8.1) needs a maintainer ruling.

**Roadmap entry:** [management roadmap, Plan 39](2026-10-19-zeroauthy-management-roadmap-design.md)
("short, Apple full"); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **S2** (track S, after S1 = Plan 39a Apple, whose native-login
framework this plan reuses). Read the [clean-room policy](../../../CLEAN_ROOM.md),
`AGENTS.md`, the [Plan 24 spec](2026-10-26-zeroauthy-social-connections-design.md)
and the [Plan 39a spec](2026-11-16-zeroauthy-apple-design.md).

**GitHub moved out (maintainer, 2026-11-18):** `github` is built by Plan 39c ([design](2026-11-16-zeroauthy-github-connection-design.md), [plan](../plans/2026-11-18-zeroauthy-plan-39c-github.md)) as a dedicated Go adapter. Leave it out of this plan's descriptors and Tier 1 group. Once the descriptor framework exists, decide whether to port `github` to a descriptor plus hook; Plan 39c's adapter tests are that port's acceptance tests, and public IDs and stored identities must not change (39c spec §3).

## 1. Outcome and scope

Every social strategy in Auth0's Management OpenAPI that zeroauthy lacks
becomes available, each with its documented options, scope switches and
Auth0's normalized profile; plus the generic `oauth1` strategy, Twitter/X
on both OAuth 2.0 and OAuth 1.0a, and the native exchanges for Google (ID
token) and Facebook (limited-login / session access token).

**Design:** one **provider descriptor** per strategy (data, not code) on
Plan 24's federation core — endpoints, client authentication, scope
switches → upstream scopes, PKCE support, profile endpoint and field
mapping, user ID source, email-verified rule — with a small code hook only
where a provider needs it (Facebook appsecret_proof, Twitter OAuth 1.0a,
Salesforce instance URL, Shopify shop domain, Exact base URL). Endpoints and
profile fields come from each **provider's own public documentation**; the
option names and switches from Auth0's OpenAPI.

**Rule:** strict 1:1 with Auth0's documented behaviour. Local rulings
**LR39b-n**, observation points **SP-1…n** in **D-0180** (S2 block
D-0180–0189).

### In scope

| Group | Strategies (OpenAPI `ConnectionOptions*`) |
|---|---|
| Tier 1 (proposed first) | `facebook` (48 permission switches), `linkedin` (`strategy_version`, OpenID-based v2), `twitter` (`protocol` `oauth1` / `oauth2`, `tweet_read`, `users_read`, `offline_access`), `amazon`, `paypal` (+ `paypal-sandbox`, SP-1), `salesforce`, `salesforce-community` (`community_base_url`), `salesforce-sandbox`, `yahoo`, `line`, `dropbox`, `box`, `bitbucket`, `shopify` |
| Tier 2 | `baidu`, `bitly`, `daccount`, `dwolla`, `evernote` (+ `evernote-sandbox`), `exact` (`baseUrl`), `fitbit`, `instagram`, `planningcenter`, `soundcloud`, `thirtysevensignals`, `untappd`, `vkontakte`, `weibo`, `wordpress`, `yandex` |
| Generic | `oauth1` (`requestTokenURL`, `accessTokenURL`, `userAuthorizationURL`, `signatureMethod`, `scripts.fetchUserProfile`) |
| Native | `native_social_login.google` (Google ID token exchange), `native_social_login.facebook` (Facebook session-info access token exchange) — the client fields stored since Plan 39a |

Each strategy: create/patch rules, hosted login button (Plan 22 widget),
`/authorize?connection=`, identity `<strategy>|<provider id>`
(`isSocial: true`), upstream token storage (Plan 24), Deploy CLI round
trip, a fixture provider mode for tests.

### Not in scope

- Providers Auth0 offers only through the Marketplace (Discord, Slack,
  Twitch, …): operators use the generic `oauth2` strategy (Plan 24) with a
  `fetchUserProfile` script; the docs gain ready-made examples (LR39b-1).
- Live-provider tests in CI (fixtures only; optional manual runs against
  real providers with the maintainer's credentials).
- Facebook/Instagram Graph features beyond sign-in (page management etc.):
  the permission switches only request scopes.

### Anti-goals

- **Email trust drift.** `email_verified` true only where the provider
  documents verified emails (for example, Facebook's emails are verified by
  Facebook per its docs,
  SP-2); otherwise false. No automatic linking by email (Plan 24 rule).
- **Scope inflation.** Scope switches map one-to-one to the provider's
  scopes; `freeform_scopes` are passed only where Auth0 documents them for
  that strategy.
- **OAuth 1.0a pitfalls.** Request-token secrets sealed in the attempt;
  callbacks verified with `oauth_verifier`; HMAC-SHA1 and RSA-SHA1 per
  `signatureMethod`; no PLAINTEXT over non-TLS (refused).
- **Native token confusion.** Google ID tokens verified with Google's JWKS,
  `aud` ∈ the connection's `client_id` and the client's allowed
  native audiences (SP-3); Facebook tokens verified with the debug_token
  endpoint for the connection's app (SP-4).
- **Secrets in logs** (memory: secrets never in logs): provider tokens,
  OAuth 1.0a secrets, `appsecret_proof`.

## 2. Evidence

- Management OpenAPI (read 2026-11-16): the `ConnectionOptions*` schemas
  listed above (e.g. Facebook's permission booleans such as `email`,
  `public_profile`, `user_birthday`, …; LinkedIn `strategy_version`,
  `basic_profile`,
  `full_profile`, `openid`; Twitter `protocol`, `tweet_read`, `users_read`,
  `offline_access`; Amazon `postal_code`; PayPal `address`, `phone`;
  Salesforce Community `community_base_url`; Exact `baseUrl`; OAuth1
  `requestTokenURL`, `accessTokenURL`, `userAuthorizationURL`,
  `signatureMethod`), `NativeSocialLoginGoogle` ("allow signing in natively
  using a Google ID token"), `NativeSocialLoginFacebook`.
- Auth0 social provider pages under
  `/docs/authenticate/identity-providers/social-identity-providers/*`
  (per provider, read at build time for documented profile fields and
  quirks, SP-5).
- Each provider's developer documentation for endpoints, scopes and
  profile shapes (cited per descriptor in D-0180).
- RFC 5849 (OAuth 1.0a), RFC 6749/7636.

## 3. Provider descriptor

```text
strategy, display name, icon
authorize URL, token URL, revoke URL?, userinfo/profile URL(s)
client auth: client_secret_post | client_secret_basic | custom hook
PKCE: S256 | none
scope map: option switch → upstream scope(s); default switches
profile map: provider field paths → Auth0 normalized profile fields
user id: provider field (string-encoded)
email: field + verification rule
hooks: optional Go function name (appsecret_proof, oauth1, instance URL, shop domain)
```

Descriptors live in `internal/federation/providers/*.json` validated by a
JSON schema test; the existing Google/Microsoft adapters are not migrated
(they carry Plan 24/25 logic).

## 4. Special cases

- **Facebook:** Graph API version pinned in the descriptor (SP-6),
  `appsecret_proof` on Graph calls, fields requested explicitly, limited
  login tokens for native.
- **Twitter/X:** `protocol: oauth2` (PKCE, `tweet.read users.read`
  mapping; email via `users/me?user.fields=…` only if granted) or `oauth1`
  (request token flow, `include_email` with elevated access, SP-7).
- **LinkedIn:** `strategy_version` 1 (legacy scopes), 2 (`r_liteprofile`)
  or 3 (OpenID Connect `openid profile email`, the OpenAPI's default when
  unset). Version 3 goes through the Plan 24 OIDC path. Versions 1 and 2
  are accepted and stored but refused at login, because LinkedIn retired
  those APIs (SP-8).
- **Salesforce:** identity URL from the token response's `id`; community
  base URL; sandbox host.
- **Shopify:** per-shop domain given at login (`login_hint`/connection
  option, SP-9).
- **OAuth1 generic:** the Plan 24 `fetchUserProfile` script runner with the
  OAuth 1.0a token and secret in `context`.

## 5. Native exchanges

- Google: `subject_token_type` = Auth0's Google ID-token type (SP-3: exact
  URN from the Auth0 SDKs, e.g. Auth0.Android), `subject_token` = Google
  ID token; requires `native_social_login.google.enabled` and an enabled
  `google-oauth2` connection.
- Facebook: `subject_token_type` = Auth0's Facebook session-info type
  (SP-4), plus `user_profile` JSON; requires
  `native_social_login.facebook.enabled` and an enabled `facebook`
  connection; the token is validated with Facebook's debug endpoint.
- Both reuse Plan 39a's native exchange framework (reserved token types,
  post-login Actions, MFA rules).

## 6. Storage, console, seed, Deploy CLI

- No new tables (connection options and sealed secrets, Plan 24).
- Console: Social → provider picker grouped by tier, per-provider
  settings generated from the descriptor (switch list, special fields).
- Seed: strategies via the shared rules.
- Deploy CLI four-cell round trip with one connection per Tier 1 provider.

## 7. Tests

- Descriptor schema test; one table-driven test per descriptor against the
  fixture provider (authorize URL, token exchange, profile mapping, email
  rule, user ID), OAuth 1.0a signature test vectors (RFC 5849 examples),
  Facebook `appsecret_proof`, native exchanges with fixture JWKS and debug
  endpoint, E2E `make e2e-social` extended with Tier 1 providers through
  the fixture.

## 8. Decisions needed from the maintainer

1. **Provider order:** Tier 1 then Tier 2 as listed (proposed), or a
   different order (the parallel-paths brief asks "provider order").
2. Whether Tier 2 ships in the same plan or a later one.
3. Optional manual live checks with real provider credentials (who holds
   them).

## 9. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR39b-1 | Marketplace-only providers via generic `oauth2` examples. |

Observe later: **SP-1** sandbox strategy names; **SP-2** email-verified
rules per provider; **SP-3** Google native token type and audiences;
**SP-4** Facebook native token type and validation; **SP-5** Auth0's
documented profile fields per provider; **SP-6** Graph API version;
**SP-7** Twitter email; **SP-8** whether Auth0 still serves LinkedIn versions 1 and 2;
**SP-9** Shopify shop selection.
