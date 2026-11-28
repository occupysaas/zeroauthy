# Plan 39d — Tier 2 social providers

**Date:** 2026-11-28. **Status:** design, approved approach; not implemented.

**Roadmap entry:** S2 (Plan 39b design, §1 "Tier 2"); the maintainer ruled
on 2026-11-27 that Tier 2 ships in a later plan, with fixture providers only.
Read the [Plan 39b design](2026-11-16-zeroauthy-social-providers-design.md),
D-0180, the [39b implementation record](../2026-11-16-plan-39b-implementation-record.md),
`AGENTS.md` and the [clean-room policy](../../../CLEAN_ROOM.md).

## 1. Intent

zeroauthy is a 1:1 Auth0 stand-in. Plan 39b shipped the 15 Tier 1 social
strategies on JSON descriptors. Plan 39d adds the 16 Tier 2 strategies Auth0's
Management OpenAPI still lists, so a tenant exported from Auth0 imports and
signs in without edits, and finishes S2.

**Rule:** strict 1:1 with Auth0's documented behaviour. Local rulings
**LR39d-n**, observation points **SD-n** in **D-0182**.

### Maintainer rulings (2026-11-27/28)

- Fixture providers only; no live provider checks.
- A strategy whose provider retired its sign-in API is **stored and refused
  at sign-in**, as LinkedIn `strategy_version` 1 and 2 are (D-0180 LR39b-6).
- **GitHub stays on its Plan 39c adapter.** This reverses the note added in
  PR #106 that the next batch would port it; this plan corrects the roadmap,
  plan index, D-0180 and the 39b record.
- Build approach 1 (below): a few general descriptor features plus one hook.

### Goals

1. Each Tier 2 strategy: create/patch rules, hosted login button,
   `/authorize?connection=`, identity `<strategy>|<id>` (`isSocial: true`),
   upstream tokens, Deploy CLI round trip, console, seed, fixture coverage.
2. Retired providers accept, store, return and export their connection, and
   refuse sign-in with a clear error.
3. The descriptor framework absorbs the recurring quirks as data, so Tier 2
   is mostly JSON.

### Non-goals

- Live provider tests; Fitbit's replacement (Google Health API) or
  Instagram's replacement (business accounts only) as new behaviour.
- Porting GitHub or Twitter's hard-coded OAuth 1.0a to the new features.
- Native exchanges for any Tier 2 provider.

### Anti-goals

- **Email trust drift:** `email_verified` true only where the provider
  documents verified emails or returns a verification field (LR39b-4 holds).
- **Token leaks through query strings:** providers that take the access
  token as a query parameter (Baidu, Untappd, VK, Weibo) must keep it out of
  every error and log, like headers today.
- **Open redirects of credentials:** profile URLs built from token-response
  values (Weibo's `uid`) substitute only bounded, URL-escaped values into a
  fixed template; a token response can never choose the host.
- **Arbitrary hosts:** Exact's `baseUrl` is limited to Exact's regional hosts.

## 2. The strategies

Endpoints come from each provider's own documentation, cited per descriptor
(`source`) and in the inventory, read at build time (SD-1 records any that
could not be confirmed). The table is the design's starting point, not a
frozen contract; Task 1 of the plan freezes it.

| Strategy | Status | Shape (what the descriptor must express) |
|---|---|---|
| `baidu` | live | token in query (`access_token`) on `passport/users/getInfo`; client credentials in the token request query |
| `bitly` | live | token response is form-encoded unless `Accept: application/json`; profile `/v4/user`, primary verified email from `emails[]` |
| `daccount` | live | NTT docomo d Account Connect, OpenID Connect userinfo (SD-2: endpoints) |
| `dwolla` | live, unverified | account ID in the token response, profile `/accounts/{id}` (SD-3: user sign-in still offered) |
| `evernote`, `evernote-sandbox` | live, unverified | **OAuth 1.0a**; subject `edam_userId` from the access-token response (Evernote's profile API is Thrift, not JSON); empty `oauth_token_secret` allowed; no email (SD-4: new API keys) |
| `exact` | live | `baseUrl` (regional host) + `/api/oauth2/auth`, `/token`, `/api/v1/current/Me`; OData `d.results[0]` profile; `profile` stored only |
| `fitbit` | **retired** | legacy Web API and OAuth turned off 2026-11-02 (Google Health API replaces it): stored, refused |
| `instagram` | **retired** | Basic Display API shut down 2024-12-04: stored, refused |
| `planningcenter` | live | JSON:API profile `people/v2/me` (`data.id`, `data.attributes.*`) |
| `soundcloud` | live | S256 PKCE; profile auth header `Authorization: OAuth <token>` |
| `thirtysevensignals` | live | Launchpad: fixed `type=web_server` on authorize and token; profile `authorization.json` (`identity.*`) |
| `untappd` | live, unverified | `redirect_url` instead of `redirect_uri`; token request is a GET with credentials in the query; token nested under `response`; profile token in query (SD-5) |
| `vkontakte` | live | `user_id` and `email` in the token response; API version parameter on profile calls; `response[0]` profile (SD-6: legacy oauth.vk.com vs VK ID) |
| `weibo` | live | `uid` in the token response, substituted into the profile URL `users/show.json?uid=…` |
| `wordpress` | live | profile `rest/v1.1/me`, `email_verified` field |
| `yandex` | live | profile auth header `Authorization: OAuth <token>` |

## 3. Approaches

1. **General descriptor features plus one hook (chosen).** Extend the
   descriptor format with the recurring quirks; Evernote gets an OAuth 1.0a
   hook. Providers stay data; future providers reuse the features.
2. **A Go hook per quirky provider.** About six hooks, no format change;
   more code, and every new provider needs Go.
3. Rejected: one Go adapter per provider (the Plan 39c shape) — it is what
   the descriptor framework exists to avoid.

## 4. Descriptor features (approach 1)

Each is optional, validated by the strict loader, and covered by unit tests
against the fixture:

1. **Token request shape:** `token_method` (POST default, GET), `token_client_auth`
   adds `query` (credentials as query parameters) beside post and basic,
   `token_response_path` (a Lookup path to the token object, e.g. `response`),
   and `token_accept` for providers that answer form-encoded by default.
2. **Parameter naming and fixed parameters:** `redirect_param` (default
   `redirect_uri`); `authorize_params`, `token_params`, `profile_params` as
   fixed string maps (e.g. `type=web_server`, VK's `v`).
3. **Profile authentication:** `profile_auth` adds `query:<param>` and
   `scheme:<Scheme>` (sends `Authorization: <Scheme> <token>`).
4. **Token-response values:** profile-map paths may read the token response
   with a `token:` prefix (`token:user_id`, `token:email`), and
   `profile_url` may contain `{token.<field>}`, substituted only with a
   bounded value matching `^[A-Za-z0-9._-]{1,128}$`, URL-escaped.
5. **Array index in paths:** Lookup accepts `name[N]` (e.g. `d.results[0]`).
6. **Retired providers:** `retired: {date, reason, source}`. Rules accept
   and store the connection as usual; login start refuses with
   `ErrConnectionUnusable` and the operator-safe reason (generalizing the
   LinkedIn hook); the console marks the strategy retired.
7. **Free scope (LR39d-1):** `free_scope: true` for strategies whose only
   Auth0 option is `scope`. The operator's `scope` (array or space/comma
   string, at most 20 tokens of 1–128 printable characters without spaces or
   commas) is what is requested; absent, the descriptor's base scopes. It is
   returned on read as stored.
8. **Exact `baseUrl` (LR39d-2):** an allowlist of Exact's regional hosts
   (`start.exactonline.{nl,be,co.uk,com,de,fr,es}`); `{base_url}` in the
   endpoint templates.
9. **OAuth 1.0a descriptors:** `protocol: "oauth1"` with request, access and
   authorization URLs, reusing Plan 39b's OAuth 1.0a core (sealed request
   secret, callback binding); `oauth1_empty_secret: true` for Evernote; the
   profile comes from the access-token response through `token:` paths.
   Evernote is the only user in this plan; Twitter keeps its code.

## 5. Everything else carries over from Plan 39b

Identity format and `social.v1` capability, sealed secrets, effective-scope
on read, Management API, seed, Deploy CLI preparer, the console descriptor
form (generated `descriptors.json` gains `retired`, `free_scope`, `base_url`),
the stand-in in `tests/e2e/social/provider` (which reads the descriptors and
must learn each new feature), `make e2e-social-providers` extended with
every live Tier 2 strategy, and docs.

## 6. Left to the builder

- Exact fields and names of the new descriptor keys, as long as §4's
  behaviour holds and the strict loader rejects anything else.
- Per-provider endpoint details within each provider's documentation; any
  that cannot be confirmed becomes an SD observation point, not a guess
  presented as fact.
- Whether `token:` paths and profile paths share one map or two.
- Test layout, following Plan 39b's (`TestTier1Providers` table,
  `TestDescriptorEmailRules`, the stand-in test).

## 7. Observation points (D-0182)

**SD-1** endpoints that could not be confirmed from public docs; **SD-2**
d Account endpoints; **SD-3** Dwolla user sign-in availability; **SD-4**
Evernote API key issuance; **SD-5** Untappd API status; **SD-6** VK legacy
OAuth versus VK ID; **SD-7** whether Auth0 still lists Fitbit and Instagram
and what its sign-in does now.
