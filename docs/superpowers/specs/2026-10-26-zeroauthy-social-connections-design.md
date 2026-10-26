# zeroauthy — Plan 24: Social connections and upstream federation

- **Status:** Design accepted for implementation; Task 1 compatibility inventory frozen on 2026-10-26. Provider runtime implementation remains pending.
- **Date:** 2026-10-26.
- **Predecessor:** Plan 23 and its [acceptance record](../2026-10-26-plan-23-implementation-record.md).
- **Plan:** [Implementation tasks](../plans/2026-10-26-zeroauthy-plan-24-social-connections.md).
- **Intent:** Turn the roadmap's next connection strategies into real login methods, preserving existing authorization, user, branding and custom-domain behavior.

## 1. Scope and design choices

An operator configures a provider, enables it for an application and registers the displayed callback URL upstream. A user selects that provider, authenticates there, and returns to the original application through zeroauthy's existing consent/code/session flow. Repeat login finds the same identity, including an explicitly linked or imported identity, without matching by email.

Implement `google-oauth2`, custom `oauth2`, and the minimal `oidc` strategy with `type: back_channel`. The roadmap named generic OIDC but only enumerated two social strategies. This design explicitly brings the basic `oidc` code flow forward from Plan 36; it remains an enterprise connection (`isSocial: false`). Plan 36 retains front-channel OIDC, Okta/Entra adapters, home-realm discovery, connection keys/status and enterprise extras. No invented OIDC mode inside `oauth2`.

Designer's calls, subject to review:

- Use the current Go 1.26.7, Vue/TypeScript, JOSE and storage stack; no new production OAuth framework.
- Run custom OAuth profile scripts now, using a dedicated restricted runner based on Plan 8's process lifecycle. Do not defer functional custom OAuth login to Actions.
- Store upstream access/refresh tokens encrypted for scoped Management API retrieval; do not build refresh scheduling or Token Vault.
- Require upstream S256 PKCE for generic OAuth/OIDC. Google uses S256 too. A provider without it is an explicit unsupported local subset; never silently retry without PKCE.
- Provider credentials are write-only through ordinary connection reads. Deploy migrations require explicit secret reinjection. Record the compatibility difference if upstream exposes credentials.

Non-goals: Plan 25 providers, One Tap/native token exchange, automatic linking, provider-initiated login, federated logout/revocation, organizations, MFA, Actions, Token Vault/`federated-connections-tokensets`, arbitrary npm modules, Auth0 development keys, arbitrary upstream parameter forwarding, front-channel ID tokens. Existing database/custom-database behavior must remain intact.

## 2. Evidence and compatibility contract

Read `CLEAN_ROOM.md`. Public sources used during design:

- [Auth0 custom OAuth2 connections](https://auth0.com/docs/authenticate/identity-providers/social-identity-providers/oauth2): connection configuration and callback-style profile scripting.
- [Auth0 Google connections](https://auth0.com/docs/authenticate/identity-providers/social-identity-providers/google): provider credentials and callback setup.
- [Auth0 OIDC connections](https://auth0.com/docs/authenticate/identity-providers/enterprise-identity-providers/oidc): `oidc`, back-channel discovery and `/login/callback`.
- [Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect), [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html): protocol validation and security boundaries.
- [Auth0 changelog](https://auth0.com/changelog): search was available, but direct retrieval exceeded the tool's size limit. The initial design did not advance the repository's October 22 reviewed-through date. Task 1 completed a separate full public-HTML retrieval through October 26 and advanced the review log; the earlier oversized-tool request remains unsuccessful. See [source review](../../compat/observations/social-connections.md).

No live tenant/provider observation was performed. Task 1 freezes documented options, scope gates, identity/token response placement, SDK/Deploy CLI behavior and error identifiers in a sourced inventory. An authorized separate observer may supply notes; unavailable observation must be recorded as unavailable, never passed. Do not inspect Auth0 hosted pages or dashboard assets.

The exact undocumented defaults are local decisions, recorded as such. Unsupported options may be stored only when clearly identified as inert; an option essential to successful authentication cannot be silently ignored. Task 1 may correct source-dependent wire spellings but must update this spec and plan together if doing so changes behavior.

## 3. Connection management

Extend existing `/api/v2/connections` CRUD, filtering and enabled-client operations rather than introducing parallel resources. Preserve names, IDs, pagination, scopes, API/seed ownership and patch semantics already implemented for database connections. Shared strategy dispatch lives in `connrules`; social rules live in `federation`. API, seed and console use the same validation. Connection-list take/from presence selects checkpoint mode ahead of offset parameters: `{connections:[...],next?}`, take default 50/range 1–100, next reused unchanged as from and omitted on terminal/empty pages. include_totals is ignored in checkpoint mode and no offset summary fields are returned.

| Strategy | Active input | Runtime |
|---|---|---|
| `google-oauth2` | `client_id`, `client_secret`, documented Google scope flags, profile-sync setting | Fixed Google issuer/discovery, code flow, validated ID token |
| `oauth2` | `client_id`, `client_secret`, `authorizationURL`, `tokenURL`, `scope`, `scripts.fetchUserProfile` | Code exchange and restricted profile script |
| `oidc` | `type: back_channel`, `discovery_url`, `client_id`, `client_secret`, `scopes` | Discovery, code exchange, ID token validation, optional UserInfo |

The frozen inventory supports Google boolean `email`/`profile` flags (both default true), with default `openid profile email`; extra Google API scope flags/freeform scopes are rejected. Google `scope` is an optional array consistency assertion matching the flags. OIDC `scopes` is a space-delimited string confirmed by the public PKCE configuration example; the SDK-only `scope` spelling is not accepted as an alias. OIDC requires `openid`; OAuth scope is explicitly configured. Use client_secret_post for Google and generic OAuth; OIDC selects client_secret_basic when advertised, otherwise client_secret_post when advertised (discovery omission means basic). Unsupported client-auth methods fail configuration/runtime validation. Never send two authentication methods.

PATCH preserves omitted options, but supplied options replaces nonsecret settings and must retain required immutable fields. Credential updates are the explicit exception: omitted secret preserves it; empty/null is rejected; replacement increments a monotonic `FederationRevision`. All effective auth configuration and enabled-client changes increment that revision. Issuer/client identity binding, OAuth authorization/token URLs and OAuth profile script source are immutable after creation; changing any requires a new connection. Scope, display, enablement and secret rotation remain editable. OIDC pins the discovered issuer on the first successful metadata validation using a connection-revision CAS before creating an attempt; a concurrent configuration change forces restart. Later discovery must match that durable issuer exactly. A changed discovery URL requires a new connection. Secret changes are sealed before persistence with tenant/connection/version AAD. Remove credential plaintext from Extra, DTOs, caches, diagnostics and exports. Existing database configuration sealing remains separate. Reads return public settings without placeholder secrets; console shows only a configured indicator.

Preserve unsupported, nonessential option values under existing Extra rules and report them in docs/console. `authentication.active: false` and connected-accounts-only configurations cannot authenticate. The purpose is an object with boolean `active`, matching existing connrules; scalar false/null and an invented `enabled` alias are rejected. `upstream_params`, `authParams` and `authParamsMap` are explicitly inert with diagnostics; reserved protocol overrides, domain policy and required custom authentication options are rejected. Assurance parameters `acr_values`, `max_age`, `claims` and `prompt` reject for every value (including null/empty and every prompt value), whether named as a target or dynamic alias, before inert storage. Existing ordinary connection scopes continue to expose nonsecret options locally; the additional public read:connections_options gate is a documented difference. Strategy and name stay immutable. Display name and show-as-button affect available login choices. Remote icon URLs remain stored-only; use original text buttons to avoid third-party tracking and template CSP changes.

## 4. Browser transaction and callback

`/authorize?connection=<name>` selects an enabled, usable connection by name. Without explicit selection show enabled social buttons beside the existing database widget; a social-only application still renders a working provider choice. An explicit usable hidden connection can be selected directly. `prompt=none` never initiates upstream interaction; existing qualifying sessions retain current behavior. `prompt=login` forces a new upstream attempt; do not silently satisfy it from a local session.

Use `POST /u/login/social` as a local CSRF-protected button action and `GET /login/callback` for query-mode upstream callbacks. Explicit `/authorize` selection can start the same service after creating the normal browser transaction. Never use an application-supplied redirect URI as the provider callback: callback is the transaction's active public origin plus `/login/callback`.

Create an opaque 32-byte random upstream state and nonce, plus S256 verifier. Store only a state hash and a wrapped verifier/nonce payload; never repurpose downstream `state`, nonce or PKCE. Persist tenant, connection ID/revision, original transaction ID, cookie hash, origin, exact callback, expected issuer and pinned endpoints. Expiry is the earlier of original transaction expiry and five minutes. Capture the tenant’s durable IdentityEpoch with the attempt. Multiple tabs have independent attempts. Starting again invalidates the prior attempt for that transaction atomically.

Callback order:

1. Reject duplicate parameters, oversized query (>16 KiB), missing state, both code/error, unsupported method, missing browser cookie, wrong host/tenant or expired/inactive public origin. No provider request occurs on rejection.
2. Atomically claim the attempt only if pending, unexpired and still the transaction's current attempt. Verify connection revision, enabled application and cookie binding. A valid provider error consumes the attempt and produces a safe localized error.
3. Exchange a code once. All uncertain exchanges, timeouts and invalid responses terminate the attempt; require a fresh login. Never retry a token POST after ambiguous delivery.
4. Validate provider identity, then atomically recheck current attempt/configuration/user eligibility while updating identity/profile/token data. Callback replay, concurrent callbacks and stale attempts cannot issue another local session.
5. Resume existing session/consent/authorization-code handling. Preserve origin, audience, downstream PKCE, nonce, state, max_age and device authorization semantics. Consume/cancel the original login transaction through existing completion rules. Failure after claim may require restart; no exactly-once upstream side-effect promise.

Client or connection deletion/disable, user blocking, identity unlink/delete and domain expiry during the network round trip must fail closed. Final session creation and transaction consumption must share the transaction that checks current user/version, identity ownership, IdentityEpoch, connection revision, client enablement and attempt status; refactor existing completion helpers as needed. Immediately before that transaction, revalidate origin/certificate eligibility; no external provider call occurs after this check. No network I/O occurs inside a store transaction.

### Attack protection

Apply the tenant's existing suspicious-IP pre-login budget and bot/CAPTCHA policy before redirecting upstream, using a new `social-login` flow that does not resolve email or reserve password brute-force attempts. Explicit connection selection must render the local challenge when required, rather than bypassing it. At first provisioning apply the pre-user-registration IP budget too. At callback, check current IP blocks and provider-attempt proof without charging a second pre-login attempt. Blocked local users remain denied. Provider refusal, timeout and validation errors never count as bad passwords or clear database brute-force blocks; breached-password checks are inapplicable because no local password is submitted. Extend the existing protection service with these typed flow rules and keep unavailable required CAPTCHA fail-closed. These are explicit local policy choices, not observed upstream behavior.

## 5. Provider adapters and bounded network access

One `federation.Service` coordinates attempts and adapters. Use Go HTTP for discovery, token/JWKS/UserInfo and script-broker requests. HTTPS only in production, no credentials/fragments in endpoint URLs, no redirects or environment proxy. Resolve and pin public IPs at each dial; reject loopback, link-local, private, multicast and metadata networks, including mixed DNS answers and rebinding. Allow different discovery endpoint hosts only after the same validation. Issuer equality is exact; discovery URLs cannot silently change expected issuer during an attempt.

Local test providers use a constructor-injected transport/resolver with fixture-only loopback access. No API option or production environment flag bypasses the network boundary.

Local limits: 10 seconds/request, 30 seconds total callback network/script work, 1 MiB decoded response, 64 KiB mapped profile, 64 KiB token value, 64 KiB script source, 100 JWKS keys. Discovery/JWKS cache: tenant+connection+revision+issuer key, at most five minutes TTL and 256 entries per process. One coalesced refresh on unknown `kid`; failures do not replace valid cache entries, and expired cache entries are never used. No redirects or unbounded retries.

OIDC accepts RS256 initially, with matching signing JWK use/algorithm, and rejects none/HS256 and token-header URLs. Validate signature, exact issuer (Google's two documented issuer forms are an explicit adapter exception), audience/azp, exp/iat with 60-second skew, nonempty subject and exact nonce. Reject future iat beyond skew. Validate at_hash when present. UserInfo is optional, but when requested its subject must match the ID token. Never derive identity from an unverified JWT or email. Google `hd` is a provider hint only. No Google social domain restriction option is supported in this subset; reject configured restrictions instead of allowing a successful policy bypass. No arbitrary access_type/connection_scope forwarding or Google refresh-token issuance is promised.

Generic OAuth requires the bounded script to return a nonempty stable `user_id`; absence is an authentication failure. This trusts the configured provider/script, not a client-submitted profile.

## 6. Profile scripts

Support `function fetchUserProfile(accessToken, context, callback)` with JSON context containing token response values allowed by the frozen inventory. Credentials unrelated to this connection, login partial fields, host environment and filesystem are absent. The local context allowlist is scalar token-response `access_token`, `refresh_token`, `token_type`, `scope`, `expires_in` and `id_token` when present; generic OAuth treats id_token as opaque, never as automatically verified identity. Return a normalized profile through the callback exactly once. Errors produce generic localized login failures; raw provider/script messages never reach the user.

A separate federation runner requires Node 25 or later **and** a startup capability probe proving permission-enforced denial of direct network access. Run with `--permission` without `--allow-net`; test actual forbidden socket/fetch attempts, not just flag acceptance. If the version or probe fails, only custom OAuth script login is unavailable with an operator diagnostic; Google/OIDC and database login continue. Never fall back to Node 22, VM-only isolation or the customdb network-enabled process. The runner uses Plan 8's lifecycle pattern: empty environment, Node permissions, 64 MiB heap, five-second execution deadline, maximum eight concurrent executions per tenant and 64 globally. Kill on timeout or malformed protocol and release slots on cancellation. Use a fresh execution context for every request; no shared token-bearing globals. This is a restricted compatibility runtime, not a general hostile-code sandbox claim.

Only `request.get(options, callback)` and its `request({method:'GET', ...}, callback)` equivalent are supported for profile retrieval; four calls per execution. A host-mediated broker implements those calls with §5's policy, response.statusCode/headers and a string body by default or parsed JSON when options.json is true. No direct fetch/http/net, files, subprocesses, native modules, dynamic imports or arbitrary npm. Endpoint URLs must be literal HTTPS request targets checked by the broker; never follow redirects. Authorization headers may contain the current provider token; logs are discarded. Unsupported module/API use fails with an actionable operator diagnostic. No silent script fallback.

Validate `user_id`, email, email_verified, name, nickname, given_name, family_name and picture types/limits; ignore extra claims; only an explicit user_metadata object is accepted under the local 16 KiB/depth 8 bound. No automatic non-root claim mapping is promised. Scripts cannot set app_metadata, blocked, identities, local user_id, passwords or local authorization claims. Built-in Google/OIDC bypass Node entirely. Document script compatibility restrictions and migration checks.

## 7. Identity, synchronization and linking

Add a durable identity index unique by `(tenant, immutable connection ID, upstream subject)` pointing to the owning local user. Subject is case-sensitive, nonempty, at most 1024 UTF-8 bytes. Bind OIDC identity to the configured issuer through immutable connection identity; changing issuer/client binding requires a new connection (credential rotation is permitted). Do not use email/username indexes for federated uniqueness. Different subjects sharing an email remain distinct accounts, including within a connection.

Public IDs: Google `google-oauth2|<sub>`, OAuth `oauth2|<connection-name>|<subject>`, OIDC `oidc|<connection-name>|<sub>`. These are frozen local formats; generic OAuth/OIDC serialization is not tenant-observed. Connection names reject `|`; raw subjects allow it and are parsed only after the fixed provider/connection prefixes. Subjects are valid UTF-8 without NUL, with bytes/case preserved. Public identities[].user_id is the suffix after the first provider separator (Google raw sub, OAuth/OIDC connection-name|subject). Reject ambiguous imports; do not silently remap them. On public-ID collision across connections, fail closed with a documented conflict rather than merging. Imported identities with a uniquely resolvable connection and subject are indexed; unresolved/ambiguous imports require operator correction and cannot authenticate accidentally.

A durable monotonic tenant `IdentityEpoch` starts at zero. Increment it in the same transaction as any user deletion or identity removal/ownership transfer, including linking/unlinking and replacement imports; capture it at attempt creation and require equality at completion. This intentionally cancels all pending federation attempts for that tenant on such changes. A fresh attempt after deletion may provision the subject again; an older attempt may not resurrect it. No expiring tombstone or cross-node wall-clock comparison is needed.

Backfill existing/imported/linked identities before enabling runtime, aborting migration with an actionable conflict report containing IDs but no tokens. All user create/update/delete, job imports, linking/unlinking and connection deletion maintain the index in the same transaction. The current `FindByLogin` behavior remains for database identities only. Add `Users.FindByIdentity(ctx, tenantID, connectionID, subject)`.

Provision the first login transactionally; concurrent first logins yield one user. Sync only provider-owned root profile fields. `on_each_login` refreshes present root fields, `on_first_login` and `never_on_login` keep the creation profile; a missing field does not erase it. Preserve operator metadata and local blocking. Linked secondary login updates that identity's ProfileData, never the primary user's root profile. If email changes and email_verified is absent, clear verification; never carry verification to another address. Existing version/session invalidation behavior still applies.

Only explicit existing Management API linking authorization may merge accounts. Upstream tokens are not proof for self-service linking; existing local token proof rules stay intact. Link/unlink move index ownership and encrypted token records atomically, preserving independent secondary profile data and correct login target. Unlinking an identity recreates its own user according to existing semantics. Delete user/connection removes token material/index entries; no upstream revocation is promised. Imported credentials/tokens are never trusted as current provider authentication.

## 8. Upstream token handling

Store latest successful access token, optional refresh token, token type, scopes and expiry in a separate encrypted credential record keyed by tenant/connection/subject, not unencrypted Identity or Extra JSON. AAD binds that stable identity key and format version, so explicit link/unlink need not decrypt into API DTOs. Omitted refresh token on later login preserves the previous one; new refresh token replaces it. Failed logins never update token state. User/connection deletion removes it.

Individual user GET requires read:users AND `read:user_idp_tokens` to project `identities[].access_token` and `identities[].refresh_token`, each a string. The frozen local projection is individual user GET only, never list/search/link responses, exports/jobs, userinfo, local ID/access tokens or console. No permission means omission, not ciphertext/placeholders. `isSocial` is true for oauth2/Google and false for oidc/database. Scope registration alone must not grant the permission to existing clients/operators.

Identity tokens are sensitive even when access tokens have expired. API responses exposing them use no-store; logs/traces/error messages never contain them. Do not automatically refresh, revoke, proxy provider APIs or embed upstream credentials in local tokens. Retain until replaced or identity deletion, and document backup/master-key implications.

## 9. Console and hosted pages

Activate the Social connection route with list/create/detail, strategy-specific fields, credential replacement, application enablement, profile-sync choices and callback URL instructions for canonical and active custom origins. Minimal OIDC appears in Enterprise with an explicit supported-subset explanation. Reuse connection components where appropriate, without database password/script tabs on social records. OAuth has a bounded source editor and documented script surface, not a production credential-bearing test playground.

Keep dirty drafts across read failures, reject stale tenant/connection replies, prevent duplicate submissions and report uncertain writes without pretending success. No secret/token browser persistence. Text controls, accessible labels, keyboard operation and narrow layouts follow existing console patterns. Hosted buttons and errors use the i18n catalog and Plan 22 rendering; callbacks are not embedded in preview. Preserve signup, reset, identifier-first, consent and branded/custom-domain pages. No screenshots or copied vendor UI/assets.

## 10. Storage, rollout and acceptance

Additive migration `0021_federation.sql` in SQLite/PostgreSQL/MySQL, public store aliases, shared storetest and additive protobuf/RPCs. Include monotonic configuration revision, attempt state, identity index and encrypted token records. Atomic attempt claim and user/index/token changes must work across independent SQL connections and gRPC transactions. Upgrade/backfill conflicts stop activation. Old plugin servers return capability/unimplemented errors: social login stays unavailable rather than falling back to non-atomic behavior. Drain old application writers before enabling the migrated identity policy; rollback requires draining new traffic and restoring a compatible backup, not dropping live identity data.

Acceptance:

| ID | Required evidence |
|---|---|
| AC1 | Sourced strategy/options/operation inventory; observation gaps and changelog status explicit |
| AC2 | Memory, three SQL dialects and gRPC conformance for claim/replay/index/token lifecycle, upgrade/backfill conflicts and old-plugin failure |
| AC3 | Mock Google, OAuth script and OIDC successful first/repeat login through actual code exchange; nonce/issuer/audience/JWKS/SSRF negatives |
| AC4 | Parallel callback/first-login/link/unlink/block/disable/delete races preserve identity ownership and prevent duplicate completion |
| AC5 | Token/secret encryption, scope projection and redaction, including list/job/export/console exclusions |
| AC6 | Existing database flows plus social-only, mixed, explicit connection, prompt=none, device, consent, branding and custom-origin browser paths |
| AC7 | Actual pinned SDK/CLI operations and strict Deploy CLI YAML/directory × generated/preserved client credential modes with script files and explicit provider-secret reinjection |
| AC8 | Console keyboard/narrow layout/draft/stale mutation tests, full regression gates and operator documentation |

Local provider harnesses are mandatory; real Google login is manual and optional with maintainer credentials. Never call real providers in ordinary CI. No conformance certification or live Auth0 parity claim from mocks. Record executed/deferred/unavailable checks separately. Plan 19's database hold is specific to Plan 19; no tests are run merely to write this design.
