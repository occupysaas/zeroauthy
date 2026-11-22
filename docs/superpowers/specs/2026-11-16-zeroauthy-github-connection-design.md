# zeroauthy — Plan 39c GitHub social connection

- **Status:** Approved for implementation (maintainer, 2026-11-18); implemented on branch `plan-39-github-social` (see the [implementation record](../2026-11-18-plan-39c-implementation-record.md)). Revised 2026-11-18 with the maintainer's answers, a review against GitHub's current documentation and the PR #66 rulings (§11). [Implementation plan](../plans/2026-11-18-zeroauthy-plan-39c-github.md).
- **Date:** 2026-11-16 (revised 2026-11-18).
- **Roadmap:** Plan 39c, the GitHub part of Plan 39 (additional social providers); listed as a 1.0 stretch item in the [v1 release scope](2026-11-02-zeroauthy-v1-release-scope.md). The [parallel paths design](2026-11-13-zeroauthy-parallel-paths-design.md) puts GitHub in track S2 (Plan 39b) after S1 (Apple). The maintainer approved splitting it out of S2 ahead of Apple, because the release scope wants GitHub before 1.0 and Apple after (2026-11-18). Apple (Plan 39a) has since merged, so in practice GitHub is split out ahead of the rest of Plan 39b, which no longer covers `github`.
- **Branch:** `plan-39-github-social` (maintainer, 2026-11-18). Compatibility decisions: D-0181 (from the S2 block D-0180–0189).
- **Builds on:** [Plan 24 design](2026-10-26-zeroauthy-social-connections-design.md), [Plan 24 record](../2026-10-26-plan-24-implementation-record.md), [Plan 25 design](2026-10-26-zeroauthy-email-account-connections-design.md).

## 1. Intent

An operator registers a **GitHub OAuth app**, enters its client ID and secret on a `github` connection, and their users get **Continue with GitHub**. Developers are the main audience for zeroauthy, and GitHub sign-in is the provider they ask for most.

GitHub serves two purposes here (maintainer, 2026-11-16):

1. **Sign-in.** GitHub's stable numeric account ID establishes identity through the Plan 24 flow.
2. **Acting on GitHub for the user.** The operator chooses GitHub API scopes (`repo`, `read:org`, …). zeroauthy requests them, stores the resulting token encrypted, and returns it to explicitly authorized Management API clients through Plan 24's `read:user_idp_tokens` projection. This is the main reason GitHub login matters to CI, deploy and repository tools. It is also why GitHub does **not** copy Google's rule of rejecting extra API scopes.

**OAuth apps and GitHub Apps (ruling, 2026-11-18).** The two have different permission models. OAuth apps get access from the requested `scope`. GitHub App user tokens get the intersection of the app's registered fine-grained permissions and the user's own access, and the only `scope` value a GitHub App accepts is `offline_access`. So:

- OAuth apps are the documented and tested setup. The scope flags in §5 apply only to them.
- A GitHub App's client ID and secret also work for **sign-in only**, because the authorize, token and `/user` calls are the same. zeroauthy still sends the flag scopes, and GitHub ignores them. Permissions, including email access, come from the GitHub App's registration. The console and docs say this. No `app_type` option is added, because Auth0's GitHub connection has none.

Success: a tenant migrated from Auth0 with a GitHub connection (scope flags included) imports, its users log in to the same accounts, and an authorized client can read their GitHub token.

## 2. Goals, non-goals, anti-goals

**Goals**

- Add the `github` strategy (`isSocial: true`) to connection CRUD, seed, console, Deploy CLI round trip and hosted login buttons.
- Support Auth0's documented GitHub option names, including every scope flag.
- Use public user ID `github|<numeric id>`, matching Auth0. Index imported `github|…` identities so repeat logins find them.
- Use the existing Plan 24 machinery unchanged: attempts, S256 PKCE, state, the identity index, `IdentityEpoch`, encrypted token records, profile-sync policy, attack protection and the network policy.

**Non-goals**

- GitHub Enterprise Server and GHE.com data-residency hosts: left for later (maintainer, 2026-11-18). Endpoints stay fixed at `github.com` and `api.github.com`, so no operator-supplied host reaches the outbound transport.
- GitHub's device flow (the "Enable Device Flow" option).
- GitHub App fine-grained permissions as connection options, and GitHub App installation tokens.
- Automatic token refresh, revocation or proxying of GitHub APIs, and Token Vault / connected accounts (Plan 43). Requesting `offline_access` is part of this non-goal (§6).
- Organization or team membership as an authorization rule (for example, "only members of org X may log in").
- The other Plan 39 providers and any shared "fixed OAuth provider" framework.

**Anti-goals** (these would count as failures even if login worked)

- Linking or merging accounts by email. Two GitHub accounts sharing an email stay two users. A GitHub account and a database user with the same email stay separate.
- Treating an unverified GitHub email as verified.
- Treating *missing* email evidence (permission denied, a truncated list) as proof that an email is unverified, or as proof that it is verified.
- Using the GitHub `login` (username) as identity. Users can rename, and a released name can be taken by someone else.
- GitHub login depending on Node or the profile-script runner.
- Exposing GitHub tokens anywhere Plan 24 does not already allow.

## 3. Approaches considered

| | Approach | Trade-off | Outcome |
|---|---|---|---|
| A | Dedicated built-in Go adapter (`internal/federation/github.go`) with fixed endpoints and a Go profile fetch through the existing bounded transport | Some GitHub-specific code; no new abstraction | **Chosen by the maintainer** |
| B | Preset of custom `oauth2` with a bundled profile script | Least Go code, but GitHub login would need Node 25 and the permission probe, and public IDs would become `oauth2|<connection>|<id>`, breaking imports | Rejected |
| C | Table-driven "fixed OAuth provider" layer with GitHub as its first entry | Pays off for later Plan 39 providers, but designs the shared shape from one example whose quirks (two profile calls, errors returned with HTTP 200) would distort it | Deferred: extract once a second provider exists |

Keep A's code split into three parts (token exchange, profile fetch, mapping) so that C can later be extracted by moving code rather than rewriting it.

**Why not a 39b descriptor plus a hook (follow-up, PR #66).** Plan 39b's descriptor design also allows a small Go hook per provider, so GitHub could in principle be a descriptor with an `emails` hook. It is not, for two reasons. First, the descriptor framework does not exist yet: GitHub is a 1.0 stretch item ahead of 39b, and building the framework first would put the whole of 39b's Tasks 1–2 on GitHub's critical path. Second, GitHub's hook would not be small: the second profile call, the email-evidence rule (§6), exact integer subjects, the HTTP-200 token error and refresh-token clearing are most of the adapter. So GitHub ships as approach A now, and Plan 39b, once its framework exists, decides whether to port `github` to a descriptor plus hook. GitHub's adapter tests (G2, G3) become that port's acceptance tests, and the port must keep public IDs and stored identities unchanged.

## 4. Evidence

Read `CLEAN_ROOM.md`. Public sources used for this draft:

- [Auth0 GitHub connection](https://auth0.com/docs/authenticate/identity-providers/social-identity-providers/github): setup, the purpose setting, the email and read-user permissions, and the device-flow toggle.
- [Auth0 .NET SDK `ConnectionOptionsGitHub`](https://auth0.github.io/auth0.net/api/Auth0.ManagementApi.ConnectionOptionsGitHub.html): option wire names (§5). This is an SDK source, so Task 1 must confirm it against the Management API reference or the pinned node-auth0/auth0-cli types. In particular, the semantics of `scope` and `profile` come from no documentation yet (§5).
- [GitHub PKCE changelog, 2025-07-14](https://github.blog/changelog/2025-07-14-pkce-support-for-oauth-and-github-app-authentication/): S256 PKCE is supported for OAuth apps and GitHub Apps.

GitHub documentation read on 2026-11-18 (public docs, no live calls). Task 1 records each fact with its URL in the observation note:

| Fact | Source |
|---|---|
| An OAuth app can register up to 10 callback URLs. Without wildcard matching, `redirect_uri` must match one exactly. A GitHub App also accepts several callback URLs. | "Creating an OAuth app", "Authorizing OAuth apps", "Generating a user access token for a GitHub App" |
| `code_challenge_method` must be `S256` (`plain` is refused). `code_verifier` is required at the token endpoint when a challenge was sent. | "Authorizing OAuth apps" |
| The token response is form-encoded by default and JSON with `Accept: application/json` (`access_token`, `scope`, `token_type`). | "Authorizing OAuth apps" |
| Without a `scope` parameter, an already-authorized user's flow completes with the scopes they granted earlier, so granted scopes can exceed requested ones. | "Authorizing OAuth apps" |
| OAuth apps get expiring tokens (8 h access, refresh token valid for 6 months without use) only when they request `offline_access` or the app forces expiration. Refreshing invalidates the old refresh token. | "Authorizing OAuth apps" |
| GitHub App user tokens: `scope` accepts only `offline_access` and does not set permissions. `expires_in` (28800) and `refresh_token`/`refresh_token_expires_in` are present only when the token expires. | "Generating a user access token for a GitHub App" |
| `GET /user/emails` needs `user:email` for OAuth app tokens. It is paginated: `per_page` default 30, maximum 100. Documented statuses: 200, 304, 401, 403, 404. | REST "Emails" |

Task 1 resolved most of this in the [observation note](../../compat/observations/github-connection.md): the pinned `X-GitHub-Api-Version` is `2026-03-10`; primary and secondary rate limits answer `403` or `429` with `x-ratelimit-remaining: 0` or a `retry-after` header; a GitHub App user token needs the "Email addresses" read permission for `/user/emails`. Still undocumented, so recorded as unavailable and handled defensively: an error body inside an HTTP 200 token response, and the `X-OAuth-Scopes` header. The Auth0 option semantics are likewise undocumented (D-0181).

No live GitHub or Auth0 observation was made. Any live Auth0 observation follows `CLEAN_ROOM.md`'s observer/implementer separation: the implementer of this plan does not observe Auth0 for the same area. Task 1 freezes a `github` section in `internal/federation/inventory.json`, adds an observation note in `docs/compat/observations/`, and records gaps as unavailable, never as passed. If a source contradicts this design, update the spec and the plan together before implementing.

## 5. Connection configuration

Extend `internal/federation/rules` (the single validation authority), `connrules` dispatch, the generated management API schema, seed validation (`internal/seed/validate.go` strategy list) and `IsFederated`.

| Option | Rule |
|---|---|
| `client_id`, `client_secret` | Required on create. The secret is sealed and write-only, with existing PATCH semantics (an omitted secret is preserved; empty or null is rejected). |
| `profile` | Boolean, default `true`. Stored and round-tripped only: it adds no scope (`GET /user` needs none), and login always reads `/user` and maps the same fields, because the subject comes from it. `profile: false` does **not** stop profile attributes from syncing. This is a local difference, recorded in the inventory and `docs/compat/matrix.md` (designer's call). |
| `email` (`user:email`) | Boolean, default `true`. `email: false` is allowed: no `/user/emails` call, and users are created without an email. |
| Scope flags `admin_org`, `admin_public_key`, `admin_repo_hook`, `delete_repo`, `follow`, `gist`, `notifications`, `public_repo`, `read_org`, `read_public_key`, `read_repo_hook`, `read_user`, `repo`, `repo_deployment`, `repo_status`, `write_org`, `write_public_key`, `write_repo_hook` | Booleans, default `false`. `true` adds the GitHub scope (OAuth apps only; §1). The flag-to-scope table is frozen in the inventory (for example, `repo_status` → `repo:status`, `admin_org` → `admin:org`). |
| `freeform_scopes` | Absent or an empty array only; non-empty values are rejected, as for Google. |
| `scope` | Optional array of strings. See "Imported `scope`" below. |
| `set_user_root_attributes`, `non_persistent_attrs`, display, `show_as_button`, enabled clients, `authentication.active` | Same as Google. |
| `upstream_params` | Stored only, with Plan 24's reserved and assurance-parameter rejection. |
| Device flow toggle, `connected_accounts.active: true`, any endpoint/host override (including GitHub Enterprise hosts) | Rejected. |

The effective scope is the de-duplicated union of `user:email` (when `email` is on) and the flag scopes (`read_user` → `read:user`). It never includes `offline_access`. It may be empty. It is sent space-separated. Its total length counts against the existing `maxScopeBytes`.

**Imported `scope` (ruling, 2026-11-18).** Auth0's documentation does not say whether `scope` is derived from the flags, so GitHub follows the existing Google rule: the flags are the only source of the requested scope, and `scope` is returned on read as the effective scope computed from them. An input `scope` is accepted only when it equals that effective scope as a set (order and duplicates ignored). Any other value is rejected with a 400 naming the expected value, so an import can never silently drop or add a permission. The operator fixes the export by setting the matching flags. Recorded in D-0181.

`client_id` is the immutable identity binding. Scopes, sync policy, display and secret rotation stay editable. Every effective change increments `FederationRevision`, as today.

Scope changes apply only from a user's next login: earlier stored tokens keep their old grants. The console and docs state this.

## 6. Runtime adapter

Add a `StrategyGitHub` case to `FlowService.Begin` (fixed `Endpoints`, `client_secret_post`, no issuer) and to `Providers.For`. Add a `WithGitHubFixture` constructor option that mirrors `WithGoogleFixture`, for tests and harnesses only, with no API or environment switch.

**Authorize:** `https://github.com/login/oauth/authorize` with `client_id`, the exact `/login/callback` `redirect_uri` for the attempt's origin, the scope, `state`, `code_challenge` and `code_challenge_method=S256`. Always send `redirect_uri` (GitHub otherwise falls back to the first registered callback). Send no nonce (GitHub has no ID token; the attempt's nonce goes unused). Do not send `allow_signup`, `login` or `prompt`.

**Token:** POST `https://github.com/login/oauth/access_token` with `Accept: application/json`, the client secret in the body and the `code_verifier`. A JSON body containing `error` is a provider failure **regardless of HTTP status**. A non-JSON body, or a response without a nonempty `access_token` and `token_type` `bearer` (compared case-insensitively), is invalid. Plan 24's rules apply: one attempt, no retry after ambiguous delivery. Keep `scope` (the *granted* scope, verbatim) and `expires_in` (giving `ExpiresAt`), plus `refresh_token` when present.

- zeroauthy never requests `offline_access`, so OAuth app tokens expire only when the operator has forced expiration on their app, and GitHub App tokens expire unless the app opted out. Expiring tokens are stored with their `ExpiresAt` and are **not refreshed** (Plan 43). `refresh_token_expires_in` is not stored (`TokenSet` has no field for it, and nothing uses it before Plan 43).
- GitHub omits `refresh_token` exactly when the access token does not expire, and a refresh rotates it. So for GitHub, a token response without `refresh_token` **clears** the stored refresh token instead of keeping the previous one (`storeTokens` keeps it for the other providers). A stale refresh token is never returned beside a new access token.
- **Granted versus requested scopes.** Login never fails because GitHub granted fewer or more scopes than the connection requests: earlier grants carry over (§4), and a user can revoke the app on GitHub at any time. The stored `scope` is what GitHub reported. Docs tell token consumers not to assume the configured scopes: check GitHub's `X-OAuth-Scopes` response header, and handle `401` from GitHub as an expired or revoked token that needs a new login.

**Profile:** using that token, with `Accept: application/vnd.github+json`, a pinned `X-GitHub-Api-Version` (Task 1 records the value) and a fixed `User-Agent: zeroauthy`:

1. `GET https://api.github.com/user`. Required. Non-200 or invalid JSON fails the login. `id` must be a JSON integer in 1…2⁶³−1. Decode it with `json.Decoder.UseNumber` and parse it as a base-10 integer: never through `float64`, and reject fractions, exponents, leading `+`/zeros, and strings. The subject is its canonical base-10 string.
2. `GET https://api.github.com/user/emails?per_page=100`, only when `email` is on. Exactly one page is fetched; pagination is never followed (bounded cost inside the callback budget). The result is classified:

| Response | Classification | Effect |
|---|---|---|
| 200 with an entry `primary: true, verified: true` | **verified** | That address, `email_verified: true` |
| 200 with the `primary: true` entry present but `verified: false`; 200 without a primary entry (including a full page of 100); 403 or 404 without rate-limit signals (scope not granted, GitHub App without email permission) | **no verified email** | The login is refused with the "email required" page (§8); nothing is stored |
| 401; 403 or 429 with rate-limit signals (`x-ratelimit-remaining: 0` or `retry-after`); 5xx; transport error; timeout; invalid JSON | **failure** | The login fails with the existing provider-error page; nothing is stored |

**Email required (ruling, 2026-11-18).** Auth0's GitHub documentation says only that most applications need the email permission; it does not say what happens to a GitHub user without a verified primary email. Where Auth0 documents nothing, zeroauthy refuses: when the connection's `email` option is on, a login is accepted only with a verified primary email, on first and on every later login. This makes the earlier "downgrade on negative evidence" rule unnecessary: a later login without a verified primary email is refused, so a stored verified email is never kept beside missing evidence. When `email` is off, no `/user/emails` call is made, users are created without an email, and a stored email is left alone. If Auth0 is later found to accept such users, the refusal becomes a recorded deviation. Recorded in D-0181.

Both calls go through the existing bounded transport and count toward the 30-second callback budget, with limits unchanged. No redirects are followed. Response bodies stay within the existing size limits.

**Ordering.** As in Plan 24: exchange the code, fetch and validate `/user` (and `/user/emails`), then resolve or create the user and store the sealed tokens in one store transaction. A failure at any step before that transaction leaves no user, identity or token record. The GitHub token from a failed login is discarded, never logged.

**Mapping** (to the same normalized `Profile` that Google produces):

| Profile | Source |
|---|---|
| subject | `id` |
| `email`, `email_verified` | The verified primary from `/user/emails` (`email_verified: true`); absent only when `email` is off. The public `/user` `email` field is never used: it is not verification evidence. |
| `nickname` | `login` |
| `name` | `name` when nonempty, else `login` |
| `picture` | `avatar_url` when https |
| ProfileData extras | `login`, `html_url`, `blog`, `company`, `location`, `bio`, `public_repos`, `followers`, `following`, `created_at`, `updated_at`, each bounded by the existing 64 KiB profile limit. Task 1 freezes the list against the inventory. |

Under `on_each_login`, a renamed user's `nickname` updates, while identity stays on `id`.

## 7. Identity, migration and storage

- `store.FederatedPublicID` treats `github` like Google: `github|<id>`, with `identities[].user_id` being the raw numeric ID. Update `FederatedSubject` parsing accordingly.
- Add `github` to `store.IsFederatedProvider` so that user import jobs and Management API identity paths accept and index `{provider:"github", user_id:"<id>"}` identities through the existing Plan 24 code. Reject subjects that are not canonical positive base-10 integers (same rule as §6).
- **No migration.** Today no path can store a `github` connection or identity (`connrules` refuses the strategy; imports accept only federated providers), so there is nothing to backfill.
- Older storage plugins don't recognize `github` as federated and would not index its identities. Gate GitHub connection create/update and login on a store capability (a new `GitHubFederationSupported`, following `MicrosoftFederationSupported` and its gate in `grpcstore`). With an old plugin, GitHub is unavailable rather than half-indexed.
- No new tables. Tokens use the existing encrypted `federated_tokens` record, and `isSocial` is true.
- Plan 24's linking, unlinking, deletion and epoch rules apply unchanged, including the unique identity index that makes two concurrent first logins of one GitHub account produce one user. A test proves this for GitHub (§9).
- Token access stays Plan 24's: `access_token`/`refresh_token` appear only on an individual user GET by an M2M client explicitly granted `read:user_idp_tokens`, scoped to its tenant. What happens to the token record when the user is deleted or the identity unlinked follows Plan 24 unchanged (no code outside the store calls `DeleteTokens` today, so Task 1 confirms whether SQL cascades cover it). Either way, G4 proves the token is no longer returned after either action.

## 8. Console, hosted pages and docs

- Console **Social**: GitHub in the strategy picker. The form matches the existing social forms: client ID, secret (configured indicator only), `email`, the scope flags as a flat checkbox list, sync policy, and the callback URLs for the canonical and active custom origins. A short note says the scope flags apply to OAuth apps, and a GitHub App gets its permissions from its own registration.
- **Callback origins.** zeroauthy keeps Plan 24's rule that each login returns to its own origin, and always sends that origin's exact `/login/callback` as `redirect_uri`. Both GitHub OAuth apps (up to 10 callback URLs) and GitHub Apps accept several callback URLs, so one app and one connection serve a tenant that logs in on several origins. Next to the callback URLs, the console tells the operator to register **every** listed URL exactly, without wildcard matching. The setup guide says the same. No runtime change.
  *Correction (2026-11-18):* the 2026-11-16 note said an OAuth app accepts one callback host and a multi-origin tenant needs a GitHub App or one OAuth app per origin. GitHub's documentation allows up to 10 callback URLs per OAuth app, so this replaces that note. The runtime rule (each login returns to its own origin) is unchanged.
- Hosted login: a text button ("Continue with GitHub") via the i18n catalog. No GitHub logo asset (Plan 24's no-remote-icons rule). A refused login without a verified primary email renders a new catalog message, `social.email_required` (HTTP 403): "Your GitHub account needs a verified primary email address to sign in."
- Docs: a GitHub section in `docs/social-connections.md`. It covers OAuth app setup (and GitHub App sign-in only, with its permission model), registering every callback URL, the scopes `/user/emails` needs, token retrieval through `read:user_idp_tokens`, expiring tokens not being refreshed, granted scopes possibly differing from configured ones, scope changes applying from the next login, the email-required rule, the `profile` local difference, and the unsupported list (GitHub Enterprise, device flow, refresh). Also update `docs/compat/matrix.md`, `docs/compatibility.md` (GitHub moves out of the Plan 39b row) and the roadmap's Plan 39 entry.

## 9. Acceptance

| ID | Evidence |
|---|---|
| G1 | Inventory `github` section and `TestFederationInventory`; observation note with verified/unverified GitHub facts and their URLs; Auth0 `scope`/`profile` semantics resolved (§5) |
| G2 | Rules tests: every flag→scope, `profile` adds no scope, `offline_access` never sent, `scope` accepted only when it equals the effective scope, freeform rejection, host-override rejection, other rejections, PATCH/secret/revision behavior |
| G3 | Fixture-provider adapter tests: success; token error with HTTP 200; form-encoded or non-JSON token body; missing token; wrong `token_type`; PKCE verifier sent; `redirect_uri` always sent. `/user`: 401, 5xx, timeout, invalid JSON, non-integer/zero/negative/fractional/exponent/string `id`, an `id` above 2⁵³ decoded exactly. `/user/emails`: verified primary; unverified primary, no primary, 100 entries without primary, 403 and 404 without rate-limit signals (all email required); rate-limited 403 and 429 (failure); 401; 5xx; timeout. Oversize body; redirect refused; refresh-token clearing on a non-expiring response; no user, identity or token record after any failure |
| G4 | Browser login through actual code exchange in the social E2E lane: first login, repeat login after rename, same-email second account stays separate, imported `github|<id>` user logs in to the same account, an account without a verified primary email refused on first and on repeat login, token readable only with `read:user_idp_tokens` and not by another tenant's client, token no longer returned after unlink or user deletion, two origins each returning to their own callback |
| G5 | Storetest on three SQL dialects plus memory/gRPC: GitHub identity indexing through import and link, concurrent first logins produce one user, and old-plugin capability failure |
| G6 | Deploy CLI social lane: GitHub export/import with scope flags and explicit secret reinjection, then login; an export whose `scope` differs from its flags is rejected |
| G7 | Console tests (form, OAuth-app/GitHub-App note, callback-origin note, keyboard, narrow layout), full regression gates |

Real GitHub login (an OAuth app, and sign-in with a GitHub App) is a manual, optional check with maintainer credentials, never part of CI. The implementation record says whether it was done.

## 10. Left to the builder

- Package layout inside `internal/federation` and test names.
- The exact wording of the console notes, within §8.
- E2E fixture-provider implementation details.

## 11. Rulings and open questions

Settled by the maintainer:

| Date | Ruling |
|---|---|
| 2026-11-16 | Approach A (dedicated Go adapter); GitHub serves sign-in and acting on GitHub for the user |
| 2026-11-18 | Split GitHub out of parallel-paths S2 ahead of Apple, because the release scope wants GitHub before 1.0 and Apple after |
| 2026-11-18 | GitHub Enterprise Server (and GHE.com) left for later |
| 2026-11-18 | Branch `plan-39-github-social` (plan number: see 39c below) |
| 2026-11-18 | OAuth apps are the supported setup; GitHub Apps work for sign-in only, with no new option (§1) |
| 2026-11-18 | Name the plan 39c, next to 39a and 39b |
| 2026-11-18 | Email: match Auth0; where Auth0 documents nothing, refuse a login without a verified primary email when `email` is on (§6) |
| 2026-11-18 | Imported `scope`: Auth0 documents nothing, so follow the Google rule (accepted only when it equals the flags' effective scope) (§5) |
| 2026-11-18 | Dedicated adapter versus a 39b descriptor: ship approach A; 39b decides on a port once its framework exists (§3) |

No open questions remain.

Changes in the 2026-11-18 revision, from a review against GitHub's documentation: the OAuth app / GitHub App split (§1), the callback correction (§8), the token-expiry and refresh-token rules (§6), the `/user/emails` page bound and failure classification (§6), granted versus requested scopes (§6), exact `id` decoding (§6, §7), the imported `scope` rule (§5), the `profile` local difference (§5), the failure ordering (§6), and the extra acceptance cases (§9). The stale "backfill" item in §10 is removed, because §7 needs no backfill.
