# zeroauthy — GitHub social connection

- **Status:** Draft for maintainer review.
- **Date:** 2026-11-16.
- **Roadmap:** Plan 39 (additional social providers), the GitHub part only; listed as a 1.0 stretch item in the [v1 release scope](2026-11-02-zeroauthy-v1-release-scope.md). It is split out of parallel-paths track S2 ahead of Apple, because the release scope wants GitHub before 1.0 and Apple after.
- **Branch:** `plan-39-github-social`.
- **Builds on:** [Plan 24 design](2026-10-26-zeroauthy-social-connections-design.md), [Plan 24 record](../2026-10-26-plan-24-implementation-record.md), [Plan 25 design](2026-10-26-zeroauthy-email-account-connections-design.md).

## 1. Intent

An operator registers a GitHub OAuth app (or a GitHub App), enters its client ID and secret on a `github` connection, and their users get **Continue with GitHub**. Developers are the main audience for zeroauthy, and GitHub sign-in is the provider they ask for most.

GitHub serves two purposes here (maintainer, 2026-11-16):

1. **Sign-in.** GitHub's stable numeric account ID establishes identity through the Plan 24 flow.
2. **Acting on GitHub for the user.** The operator chooses GitHub API scopes (`repo`, `read:org`, …). zeroauthy requests them, stores the resulting token encrypted, and returns it to explicitly authorized Management API clients through Plan 24's `read:user_idp_tokens` projection. This is the main reason GitHub login matters to CI, deploy and repository tools. It is also why GitHub does **not** copy Google's rule of rejecting extra API scopes.

Success: a tenant migrated from Auth0 with a GitHub connection (scope flags included) imports, its users log in to the same accounts, and an authorized client can read their GitHub token.

## 2. Goals, non-goals, anti-goals

**Goals**

- Add the `github` strategy (`isSocial: true`) to connection CRUD, seed, console, Deploy CLI round trip and hosted login buttons.
- Support Auth0's documented GitHub option names, including every scope flag.
- Use public user ID `github|<numeric id>`, matching Auth0. Index imported `github|…` identities so repeat logins find them.
- Use the existing Plan 24 machinery unchanged: attempts, S256 PKCE, state, the identity index, `IdentityEpoch`, encrypted token records, profile-sync policy, attack protection and the network policy.

**Non-goals**

- GitHub Enterprise Server or GHE.com data-residency hosts (fixed `github.com` endpoints only).
- GitHub's device flow (the "Enable Device Flow" option).
- Automatic token refresh, revocation or proxying of GitHub APIs, and Token Vault / connected accounts (Plan 43).
- Organization or team membership as an authorization rule (for example, "only members of org X may log in").
- The other Plan 39 providers and any shared "fixed OAuth provider" framework.

**Anti-goals** (these would count as failures even if login worked)

- Linking or merging accounts by email. Two GitHub accounts sharing an email stay two users. A GitHub account and a database user with the same email stay separate.
- Treating an unverified GitHub email as verified.
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

## 4. Evidence

Read `CLEAN_ROOM.md`. Public sources used for this draft:

- [Auth0 GitHub connection](https://auth0.com/docs/authenticate/identity-providers/social-identity-providers/github): setup, the purpose setting, the email and read-user permissions, and the device-flow toggle.
- [Auth0 .NET SDK `ConnectionOptionsGitHub`](https://auth0.github.io/auth0.net/api/Auth0.ManagementApi.ConnectionOptionsGitHub.html): option wire names (§5). This is an SDK source, so Task 1 must confirm it against the Management API reference or the pinned node-auth0/auth0-cli types.
- [GitHub PKCE changelog, 2025-07-14](https://github.blog/changelog/2025-07-14-pkce-support-for-oauth-and-github-app-authentication/): S256 PKCE is supported for OAuth apps and GitHub Apps. Only S256 is accepted.
- GitHub's "Authorizing OAuth apps", "Scopes for OAuth apps", REST "users" / "emails" and GitHub App user-token documentation. **Task 1 must verify** the token response format (the `Accept: application/json` requirement, error-in-200), the scopes `/user/emails` requires, and GitHub App expiring-token fields.

No live GitHub or Auth0 observation was made. Task 1 freezes a `github` section in `internal/federation/inventory.json`, adds an observation note in `docs/compat/observations/`, and records gaps as unavailable, never as passed. If a source contradicts this design, update the spec and the plan together before implementing.

## 5. Connection configuration

Extend `internal/federation/rules` (the single validation authority), `connrules` dispatch, the generated management API schema, seed validation (`internal/seed/validate.go` strategy list) and `IsFederated`.

| Option | Rule |
|---|---|
| `client_id`, `client_secret` | Required on create. The secret is sealed and write-only, with existing PATCH semantics (an omitted secret is preserved; empty or null is rejected). |
| `profile`, `email` (user:email) | Booleans, both default `true`. `profile` is the basic-profile attribute and adds no scope, because `GET /user` needs none (designer's call). Either value round-trips, and login always reads `/user`. `email: false` is allowed: users are created without an email. |
| Scope flags `admin_org`, `admin_public_key`, `admin_repo_hook`, `delete_repo`, `follow`, `gist`, `notifications`, `public_repo`, `read_org`, `read_public_key`, `read_repo_hook`, `read_user`, `repo`, `repo_deployment`, `repo_status`, `write_org`, `write_public_key`, `write_repo_hook` | Booleans, default `false`. `true` adds the GitHub scope. The flag-to-scope table is frozen in the inventory (for example, `repo_status` → `repo:status`, `admin_org` → `admin:org`). |
| `freeform_scopes` | Absent or an empty array only; non-empty values are rejected, as for Google. |
| `scope` | Optional array. It is ignored on input and recomputed from the flags on read, so Auth0 exports whose stored `scope` differs still import (designer's call; the inventory records it as a local difference). |
| `set_user_root_attributes`, `non_persistent_attrs`, display, `show_as_button`, enabled clients, `authentication.active` | Same as Google. |
| `upstream_params` | Stored only, with Plan 24's reserved and assurance-parameter rejection. |
| Device flow toggle, `connected_accounts.active: true`, any endpoint/host override | Rejected. |

The effective scope is the de-duplicated union of `user:email` (when `email` is on), and the flag scopes (`read_user` → `read:user`). It may be empty. It is sent space-separated. Its total length counts against the existing `maxScopeBytes`.

`client_id` is the immutable identity binding. Scopes, sync policy, display and secret rotation stay editable. Every effective change increments `FederationRevision`, as today.

Scope changes apply only from a user's next login: earlier stored tokens keep their old grants. The console and docs state this.

## 6. Runtime adapter

Add a `StrategyGitHub` case to `FlowService.Begin` (fixed `Endpoints`, `client_secret_post`, no issuer) and to `Providers.For`. Add a `WithGitHubFixture` constructor option that mirrors `WithGoogleFixture`, for tests and harnesses only, with no API or environment switch.

**Authorize:** `https://github.com/login/oauth/authorize` with `client_id`, the exact `/login/callback` `redirect_uri`, the scope, `state`, `code_challenge` and `code_challenge_method=S256`. Send no nonce (GitHub has no ID token; the attempt's nonce goes unused). Do not send `allow_signup` or `login`.

**Token:** POST `https://github.com/login/oauth/access_token` with `Accept: application/json` and the client secret in the body. A JSON body containing `error` is a provider failure **regardless of HTTP status**. A response without a nonempty `access_token` and `token_type` `bearer` (compared case-insensitively) is invalid. Plan 24's rules apply: one attempt, no retry after ambiguous delivery. Keep `scope` and `expires_in`, plus `refresh_token` and `refresh_token_expires_in` when present (GitHub Apps with expiring tokens).

**Profile:** using that token, with `Accept: application/vnd.github+json`, a pinned `X-GitHub-Api-Version` (Task 1 records the value) and a fixed `User-Agent: zeroauthy`:

1. `GET https://api.github.com/user`. Required. Non-200 or invalid JSON fails the login. `id` must be a positive JSON integer. The subject is its base-10 string.
2. `GET https://api.github.com/user/emails`, only when `email` is on. Take the entry with `primary: true` and `verified: true`. If there is none, or the call returns 403/404 (scope not granted, or a GitHub App without email permission), the profile has no email. Only transport and 5xx errors fail the login.

Both calls go through the existing bounded transport and count toward the 30-second callback budget, with limits unchanged. No redirects are followed.

**Mapping** (to the same normalized `Profile` that Google produces):

| Profile | Source |
|---|---|
| subject | `id` |
| `email`, `email_verified` | The verified primary from `/user/emails` (`email_verified: true`); otherwise both absent. The public `/user` `email` field is never used: it is not verification evidence. |
| `nickname` | `login` |
| `name` | `name` when nonempty, else `login` |
| `picture` | `avatar_url` when https |
| ProfileData extras | `login`, `html_url`, `blog`, `company`, `location`, `bio`, `public_repos`, `followers`, `following`, `created_at`, `updated_at`, each bounded by the existing 64 KiB profile limit. Task 1 freezes the list against the inventory. |

Under `on_each_login`, a renamed user's `nickname` updates, while identity stays on `id`.

**When GitHub stops vouching for an email** (designer's call, from the anti-goal on unverified email): if `email` is on and a later login finds no verified primary (including a 403/404 from `/user/emails`), keep the stored address but set `email_verified: false`. This tightens Plan 24's rule that an absent field changes nothing, for GitHub only. It applies under every sync policy, because it only ever removes verification. When `email` is off, the stored email is left alone.

## 7. Identity, migration and storage

- `store.FederatedPublicID` treats `github` like Google: `github|<id>`, with `identities[].user_id` being the raw numeric ID. Update `FederatedSubject` parsing accordingly.
- Add `github` to `store.IsFederatedProvider` so that user import jobs and Management API identity paths accept and index `{provider:"github", user_id:"<id>"}` identities through the existing Plan 24 code. Reject non-numeric subjects there.
- **No migration.** Today no path can store a `github` connection or identity (`connrules` refuses the strategy; imports accept only federated providers), so there is nothing to backfill.
- Older storage plugins don't recognize `github` as federated and would not index its identities. Gate GitHub connection create/update and login on a store capability (a new `GitHubFederationSupported`, following `MicrosoftFederationSupported` and its gate in `grpcstore`). With an old plugin, GitHub is unavailable rather than half-indexed.
- No new tables. Tokens use the existing encrypted `federated_tokens` record, and `isSocial` is true.
- Plan 24's linking, unlinking, deletion and epoch rules apply unchanged.

## 8. Console, hosted pages and docs

- Console **Social**: GitHub in the strategy picker. The form matches the existing social forms: client ID, secret (configured indicator only), `email`, the scope flags as a flat checkbox list, sync policy, and the callback URLs for the canonical and active custom origins.
- **Callback origins (maintainer, 2026-11-16):** a GitHub OAuth app accepts one callback host, while a GitHub App accepts several. zeroauthy keeps Plan 24's rule that each login returns to its own origin. Next to the callback URLs, the console notes that a tenant logging in on more than one origin needs a GitHub App, or one OAuth app and connection per origin. The setup guide says the same. No runtime change.
- Hosted login: a text button ("Continue with GitHub") via the i18n catalog. No GitHub logo asset (Plan 24's no-remote-icons rule).
- Docs: a GitHub section in `docs/social-connections.md`. It covers OAuth app vs GitHub App setup, the scopes `/user/emails` needs, token retrieval through `read:user_idp_tokens`, scope changes applying from the next login, and the unsupported list. Also update `docs/compat/matrix.md` and the roadmap's Plan 39 entry.

## 9. Acceptance

| ID | Evidence |
|---|---|
| G1 | Inventory `github` section and `TestFederationInventory`; observation note with verified/unverified GitHub facts |
| G2 | Rules tests: every flag→scope, `profile` adds no scope, `scope` recomputed, freeform rejection, other rejections, PATCH/secret/revision behavior |
| G3 | Fixture-provider adapter tests: success; token error with HTTP 200; missing token; non-integer/zero `id`; no verified primary; `/user/emails` 403; 5xx; oversize; redirect refused; PKCE verifier sent |
| G4 | Browser login through actual code exchange in the social E2E lane: first login, repeat login after rename, same-email second account stays separate, token readable only with `read:user_idp_tokens` |
| G5 | Storetest on three SQL dialects plus memory/gRPC: GitHub identity indexing through import and link, and old-plugin capability failure |
| G6 | Deploy CLI social lane: GitHub export/import with scope flags and explicit secret reinjection, then login |
| G7 | Console tests (form, callback-origin note, keyboard, narrow layout), full regression gates |

Real GitHub login is a manual, optional check with maintainer credentials, never part of CI.

## 10. Left to the builder

- Package layout inside `internal/federation` and test names.
- The exact wording of the console callback-origin note, within §8.
- Whether the backfill shares code with `backfillFederatedIdentities` or copies it.
- E2E fixture-provider implementation details.
