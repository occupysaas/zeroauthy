# Plan 39c GitHub Social Connection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `github` social strategy end to end: connection rules, a dedicated adapter, identity indexing, hosted login, console, seed/Deploy CLI round trip, E2E and docs.

**Architecture:** A dedicated Go adapter (`internal/federation/github.go`) on the Plan 24 federation core, split into token exchange, profile fetch and mapping. Fixed `github.com`/`api.github.com` endpoints, overridable only by a construction-time fixture (`WithGitHubFixture`). Identities are `github|<numeric id>`, indexed like Google's, behind a new store capability probe (`GitHubFederationSupported`) that follows the Microsoft one.

**Tech Stack:** Go 1.26 (stdlib `net/http`, `encoding/json`), protobuf/gRPC store plugin protocol (protoc 36.1, protoc-gen-go v1.36.12, protoc-gen-go-grpc v1.6.2), Vue console (Vitest), Playwright 1.64.0, node-auth0 7.4.0, Auth0 CLI 1.37.0, auth0-deploy-cli 9.1.0.

**Spec:** [docs/superpowers/specs/2026-11-16-zeroauthy-github-connection-design.md](../specs/2026-11-16-zeroauthy-github-connection-design.md) (Plan 39c, D-0181). Read it, `CLEAN_ROOM.md`, `SECURITY.md` and `THREAT_MODEL.md` first. The [Plan 39a Apple plan](2026-11-16-zeroauthy-plan-39a-apple.md) touched the same packages and is the template for file placement.

## Global Constraints

- Strategy name `github`; `isSocial: true`; public user ID `github|<id>`; identity `user_id` is the raw `<id>`.
- Subject: a JSON integer in 1…2⁶³−1, decoded with `UseNumber` and `strconv.ParseInt(s, 10, 64)`; reject fractions, exponents, leading `+` or zeros, and strings. Never through `float64`.
- Fixed endpoints: `https://github.com/login/oauth/authorize`, `https://github.com/login/oauth/access_token`, `https://api.github.com/user`, `https://api.github.com/user/emails?per_page=100`. No operator-supplied host reaches the transport.
- API headers: `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: <pinned in Task 1>`, `User-Agent: zeroauthy`.
- Effective scope: de-duplicated union of `user:email` (when `email` is on, default on) and the true flag scopes; never `offline_access`; may be empty; space-separated; counts against `maxScopeBytes` (4096).
- Email rule (D-0181): with `email` on, a login without a verified primary email is refused (`ErrEmailRequired`, HTTP 403, `zeroauthy.error.social-email-required`), on first and every later login. With `email` off, no `/user/emails` call and no email.
- Imported `scope`: accepted only when it equals the effective scope as a set; otherwise 400 naming the expected value.
- No retries of the token request; one `/user/emails` page; no redirects; existing response-size limits and the 30-second callback budget.
- Tokens: stored sealed as today; a GitHub token response without `refresh_token` clears the stored refresh token. Tokens are never logged; extend `internal/logscrub` only if a new secret-bearing field appears (none is planned).
- Every commit `git commit -s`. Say in the PR that security-sensitive packages changed (`internal/federation`, `internal/store`, `internal/login`, `internal/mgmt`, `internal/ui`).

## Review Focus

1. A GitHub `id` above 2⁵³ (for example `9007199254740993`) must round-trip exactly to `github|9007199254740993` → Task 4 `TestGitHubProfileLargeID`.
2. A user who revoked `user:email` on GitHub but still has an account here must be refused on repeat login, with the stored user unchanged → Task 4 `TestGitHubEmailRequiredOnRepeatLogin`.
3. A rate-limited `/user/emails` (403 with `x-ratelimit-remaining: 0`) is a provider failure (502), not "email required" (403) → Task 4 `TestGitHubEmailsRateLimited`.
4. An imported `github|<id>` user whose `user_id` is non-canonical (`github|0123`, `github|1e3`) is rejected at import rather than indexed under a subject login can never produce → Task 3 `TestGitHubImportRejectsNonCanonicalSubject`.
5. A storage plugin built before this plan must refuse GitHub connection writes and logins instead of storing unindexed identities → Task 3 `TestGRPCGitHubCapabilityOldPlugin`.

---

### Task 1: Evidence, inventory and decision record (G1)

**Files:**
- Create: `docs/compat/observations/github-connection.md`
- Modify: `internal/federation/inventory.json` (add `github` to `strategies`, a `provider_protocol.github` object, a `github_profile` object), `internal/federation/inventory_test.go`, `docs/compat/decisions.md` (new `## D-0181 — Plan 39c GitHub social connection (2026-11-18)`)

**Interfaces:**
- Produces: inventory keys later tests read: `provider_protocol.github.scope_flags` (object, flag → GitHub scope, 18 entries plus `email` → `user:email`, `read_user` → `read:user`), `provider_protocol.github.api_version` (string), `provider_protocol.github.rate_limit_signals` (array of `{status, header, value}`), `github_profile.provider_data` (array of the 11 extra field names from spec §6).

- [ ] **Step 1:** Read the public GitHub docs listed in spec §4 and record each fact with its URL in the observation note. Resolve the "still unverified" list: error-in-200 token responses, the `X-GitHub-Api-Version` to pin (the newest version GitHub lists as supported), the GitHub App permission `/user/emails` needs, and the rate-limit response shape. Record Auth0's GitHub page findings: email handling, `email_verified`, `scope` semantics and the user ID format are **not documented** (read 2026-11-18); record them as unavailable, never as confirmed. No live Auth0 or GitHub calls.
- [ ] **Step 2:** Write `TestFederationInventoryGitHub` in `inventory_test.go`: asserts `github` is in `strategies`, `scope_flags` has exactly the 20 keys from spec §5 with the mapped scopes (`admin_org`→`admin:org`, `admin_public_key`→`admin:public_key`, `admin_repo_hook`→`admin:repo_hook`, `delete_repo`→`delete_repo`, `follow`→`user:follow`, `gist`→`gist`, `notifications`→`notifications`, `public_repo`→`public_repo`, `read_org`→`read:org`, `read_public_key`→`read:public_key`, `read_repo_hook`→`read:repo_hook`, `read_user`→`read:user`, `repo`→`repo`, `repo_deployment`→`repo_deployment`, `repo_status`→`repo:status`, `write_org`→`write:org`, `write_public_key`→`write:public_key`, `write_repo_hook`→`write:repo_hook`, `email`→`user:email`, `profile`→`""`), `api_version` is nonempty, and `github_profile.provider_data` equals the spec §6 list. If Step 1's sources map a flag differently, the docs win: update the spec table and this test together.
- [ ] **Step 3:** Run `go test ./internal/federation -run 'TestFederationInventory' -count=1` → FAIL; add the inventory sections → PASS.
- [ ] **Step 4:** Write D-0181: email-required rule, imported `scope` rule, `profile: false` local difference, no refresh, OAuth app vs GitHub App, GitHub Enterprise unsupported, adapter-not-descriptor (spec §3).
- [ ] **Step 5:** Commit `docs(github): evidence, inventory and D-0181`.

### Task 2: Connection rules (G2)

**Files:**
- Create: `internal/federation/rules/github.go`, `internal/federation/rules/github_test.go`, `internal/server/mgmt_github_connections_test.go`
- Modify: `internal/federation/rules/rules.go` (const `GitHub = "github"`; `IsFederated`, `IsSocial`; `case GitHub` in `Parse`; the `freeform_scopes` exemption stays Apple-only, GitHub handles the empty-array case itself), `internal/federation/types.go` (`StrategyGitHub = rules.GitHub`), `internal/connrules/connrules.go:340` (supported list), `internal/seed/validate.go:363` (strategy list text and check), `internal/resourceview/resources.go` (strategy listed as social, following Apple's line)

**Interfaces:**
- Produces: `rules.GitHub`; `rules.GitHubScopeFlags []struct{Option, Scope string}` (inventory order); `func parseGitHub(o map[string]any, out *Settings) []error` setting `out.Scopes` and fixed `out.AuthorizationURL = GitHubAuthorizationURL`, `out.TokenURL = GitHubTokenURL`; consts `GitHubAuthorizationURL`, `GitHubTokenURL`, `GitHubAPIBase = "https://api.github.com"`; `func GitHubEmailEnabled(o map[string]any) bool`.

- [ ] **Step 1: Write failing rules tests** in `rules/github_test.go`:
  - `TestGitHubScopeFlags`: table over every flag: `{flag: true}` → `Scopes` contains the mapped scope exactly once; `email` default → `["user:email"]`; `{email:false}` → empty `Scopes`; `{profile:false}` changes nothing; `{read_user:true, email:true}` → `["user:email","read:user"]` (inventory order, deduplicated).
  - `TestGitHubScopeInput`: `scope: ["read:user","user:email"]` with matching flags → no error; `scope: ["repo"]` with `repo:false` → error containing `options.scope must match`; `scope: "repo"` (string) → error.
  - `TestGitHubRejections`: `freeform_scopes: ["x"]` → error; `freeform_scopes: []` → ok; non-bool flag → error; any of `authorizationURL`, `tokenURL`, `api_host`, `github_enterprise_url`, `device_flow`, `connected_accounts: {active: true}` → error; `offline_access` never appears in `Scopes` for any flag combination.
  - `TestGitHubRequiredOptions`: missing `client_id` → error; missing `client_secret` without sealed secret → error; sealed secret and no plaintext → ok.
- [ ] **Step 2:** `go test ./internal/federation/rules -run GitHub -count=1` → FAIL (undefined).
- [ ] **Step 3:** Implement `rules/github.go`. Flag parsing mirrors `parseGoogle`'s `flag` closure; scope comparison reuses `sameSet`. Keys outside the GitHub option set that `Parse` does not already reject fall through to connrules' unknown-option rule; add the host/device-flow keys to an explicit GitHub reject list so the message names them.
- [ ] **Step 4:** Rules tests → PASS.
- [ ] **Step 5: Management API test** `TestMgmtGitHubConnections` in `internal/server/mgmt_github_connections_test.go` (copy the Apple test's setup, memory store): create with flags → 201, `options.scope` returned as the effective scope, `client_secret` never returned; PATCH without secret keeps it (revision unchanged when nothing effective changed); PATCH `repo:true` bumps `FederationRevision`; PATCH `client_id` → 400 immutable; `options.client_secret: ""` → 400. Run `go test ./internal/server -run TestMgmtGitHubConnections -count=1` → PASS after wiring connrules and seed.
- [ ] **Step 6:** `go test ./internal/federation/... ./internal/connrules/... ./internal/seed/... -count=1` → PASS.
- [ ] **Step 7:** Commit `feat(federation): github connection option rules`.

### Task 3: Identity, import and the store capability (G5)

**Files:**
- Modify: `internal/store/federation.go` (`FederatedSubject`, `FederatedPublicID`, `ResolveFederatedKeys` canonical-integer check for `rules.GitHub`; `GitHubFederationSupporter` interface), `internal/federation/identity.go:99` (`identityUserID`: GitHub uses the raw subject), `internal/federation/preflight.go` (`RequireGitHubFederation`), `internal/federation/identity.go:56` (call it for GitHub), `internal/store/memory/federation.go`, `internal/store/sqlstore/federation.go` (`GitHubFederationSupported` returns nil), `internal/events/capabilities.go` (pass-through like Microsoft), `proto/store/v1/store.proto` (`rpc GitHubFederationSupported(GitHubFederationCapabilitiesRequest) returns (Result);` and `message GitHubFederationCapabilitiesRequest { string tx_id = 1; }`), regenerated `proto/store/v1/store.pb.go` and `store_grpc.pb.go`, `internal/store/grpcstore/federation.go` (client + server methods), `internal/store/grpcstore/client_repos.go` (gate `Connections().Create/Update` for `github` strategy and `Users().Create/Update` for users with a `github` identity, next to the Microsoft gates), `internal/mgmt/user_identities.go` (link/unlink accept `github`, following Apple)
- Create: `internal/store/github_test.go`, `internal/store/sqlstore/github_test.go`, `internal/store/grpcstore/github_capability_test.go`, `internal/jobs/github_import_test.go`

**Interfaces:**
- Produces: `store.GitHubFederationSupporter{ GitHubFederationSupported(context.Context) error }`; `federation.RequireGitHubFederation(ctx context.Context, st store.Store) error` (fails closed with `store.ErrFederationUnavailable` when the probe is absent); `rules.ValidGitHubSubject(s string) bool` (canonical positive base-10 int64, in `rules/github.go`).

- [ ] **Step 1: Failing tests:**
  - `internal/store/github_test.go` `TestGitHubPublicID`: `FederatedPublicID("github","gh","12345") == "github|12345"`; `Identity{Provider:"github",Connection:"gh",UserID:"12345"}.FederatedSubject()` → `"12345", true, nil`.
  - `TestGitHubImportRejectsNonCanonicalSubject` (same file, through `ResolveFederatedKeys`): `"0123"`, `"1e3"`, `"+1"`, `"-1"`, `"0"`, `"9223372036854775808"`, `"gh|12"` → `ErrInvalid`; `"9007199254740993"` → accepted with that exact subject.
  - `internal/jobs/github_import_test.go` `TestGitHubUserImportIndexes`: importing `{identities:[{provider:"github",connection:"gh",user_id:"42"}]}` makes `FindByIdentity(tenant, ghConnID, "42")` return the user (memory store).
  - `internal/store/grpcstore/github_capability_test.go` `TestGRPCGitHubCapabilityOldPlugin`: a server whose backing store lacks `GitHubFederationSupporter` (wrap memory in a struct that hides the method, as the Microsoft tests do) → `Connections().Create` of a `github` connection and `Users().Create` with a `github` identity both fail with `store.ErrFederationUnavailable`; a `google-oauth2` connection still succeeds. Also an `Unimplemented` RPC (older plugin binary) maps to `ErrFederationUnavailable`.
  - `internal/store/sqlstore/github_test.go` `TestSQLGitHubIdentityIndex`: put/find/delete identity for a `github` key and concurrent `Users().Create` of the same `github|42` → exactly one succeeds, the other `ErrConflict`. This is a database test: compile it now and run it in Step 5.
- [ ] **Step 2:** `go test ./internal/store ./internal/jobs ./internal/store/grpcstore -run GitHub -count=1` → FAIL.
- [ ] **Step 3:** Implement. Regenerate protobufs with the pinned generators from the module cache:
  ```bash
  GOBIN=/dev/shm/zeroauthy-protoc go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
  GOBIN=/dev/shm/zeroauthy-protoc go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
  cd proto/store/v1 && PATH=/dev/shm/zeroauthy-protoc:$PATH protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative store.proto
  ```
  Check that `git diff --stat proto/` touches only the new RPC and message (no unrelated regeneration drift); if the header versions change, stop and match the committed generator versions.
- [ ] **Step 4:** In-memory tests → PASS.
- [ ] **Step 5:** `./scripts/test-sql.sh -run 'GitHub'` (SQLite, PostgreSQL, MySQL via containers; see the databases-via-containers note) → PASS; record actual results.
- [ ] **Step 6:** Commit `feat(store): github identities and federation capability`.

### Task 4: GitHub adapter (G3)

**Files:**
- Create: `internal/federation/github.go` (provider, endpoints, fixture, token exchange), `internal/federation/github_profile.go` (`/user`, `/user/emails`, mapping), `internal/federation/github_test.go`
- Modify: `internal/federation/discovery.go` (`Providers.githubFix *GitHubOverride`; `For`: `case StrategyGitHub: return githubProvider{ps}`), `internal/federation/service_flow.go:148` (`case StrategyGitHub: endpoints = s.Providers.github()`; Begin calls `RequireGitHubFederation` for GitHub; `ButtonLabel` returns `"GitHub"`), `internal/federation/config.go` (nothing new is immutable beyond `client_id`; confirm `EffectiveChange` covers `Scopes`), `internal/federation/identity.go` (`storeTokens`: for `rules.GitHub`, an empty `RefreshToken` clears instead of keeping), `internal/federation/identity.go` errors (`ErrEmailRequired = errors.New("federation: provider returned no verified primary email")`)

**Interfaces:**
- Consumes: `rules.GitHubAuthorizationURL`, `rules.GitHubTokenURL`, `rules.GitHubAPIBase`, `rules.GitHubEmailEnabled`, `rules.ValidGitHubSubject` (Tasks 2–3); `authorizationURL`, `exchangeCode`, `readAll` (existing).
- Produces: `type GitHubOverride struct{ Endpoints Endpoints; APIBase string }`; `func (ps *Providers) WithGitHubFixture(o GitHubOverride) *Providers`; `func GitHubEndpoints() Endpoints` (`TokenAuthMethod: authPost`, `UserInfoURL: rules.GitHubAPIBase + "/user"`); `federation.ErrEmailRequired`.

- [ ] **Step 1: Failing adapter tests** in `github_test.go`, each against an `httptest.Server` wired through `WithGitHubFixture` and a test network policy that allows loopback (as `google_test.go` does):
  - `TestGitHubAuthorizationURL`: query has `client_id`, exact `redirect_uri`, `scope` = effective scope, `state`, `code_challenge`, `code_challenge_method=S256`; no `nonce`, `prompt`, `login`, `allow_signup`.
  - `TestGitHubTokenExchange`: request body has `client_secret`, `code_verifier`, `redirect_uri`; `Accept: application/json`. Cases: success; `{"error":"bad_verification_code"}` with HTTP 200 → `ErrProviderResponse`; form-encoded body → `ErrProviderResponse`; missing `access_token`; `token_type: "mac"` → error; `token_type: "Bearer"` → ok.
  - `TestGitHubProfile`: `/user` → `Subject "583231"`, `Nickname "octocat"`, `Name` falls back to `login` when `name` is `""`/null, `Picture` only for https, `ProviderData` has exactly the inventory fields present; request headers include `X-GitHub-Api-Version`, `User-Agent: zeroauthy`, `Authorization: Bearer <token>`.
  - `TestGitHubProfileLargeID`: `"id": 9007199254740993` → subject `"9007199254740993"`; `"id": 1.5`, `1e3`, `"42"`, `0`, `-1`, `9223372036854775808` → `ErrProfile`.
  - `TestGitHubEmails`: verified primary → `Email`, `EmailVerified=true`; unverified primary, no primary, 100 entries without primary, 403 without rate-limit headers, 404 → `ErrEmailRequired`; `email:false` → no request to `/user/emails` (handler counts calls) and `Email == nil`; the public `/user` `email` is never used.
  - `TestGitHubEmailsRateLimited`: 403 with `x-ratelimit-remaining: 0`, 403 with `retry-after: 60`, 429, 401, 500, timeout (handler sleeps past the client deadline), invalid JSON → `ErrProviderResponse`, not `ErrEmailRequired`.
  - `TestGitHubRedirectRefused` and `TestGitHubOversizeBody`: a 302 from `/user` and a body over the existing limit → error.
  - `TestGitHubRefreshTokenCleared` (Service-level, memory store): first login stores `refresh_token: "r1"`; second login's token response has none → `OpenTokens` shows empty `RefreshToken`. A Google login in the same test keeps its previous refresh token (unchanged behavior).
  - `TestGitHubEmailRequiredOnRepeatLogin` (FlowService, memory store): first login with a verified primary creates `github|583231`; second login whose `/user/emails` returns 403 → `ErrEmailRequired`, and the stored user, identity and token record are byte-identical to before.
  - `TestGitHubNoRecordsAfterFailure`: for token error, `/user` 500 and `ErrEmailRequired`, no user, identity or token record exists afterwards.
- [ ] **Step 2:** `go test ./internal/federation -run GitHub -count=1` → FAIL.
- [ ] **Step 3:** Implement. `githubProvider.Exchange`: `exchangeCode(ctx, endpoints.TokenURL, authPost, in)`, then case-insensitive `bearer` check, then `githubUser`, then (if `rules.GitHubEmailEnabled`) `githubEmails`. Use one helper `githubGET(ctx, url, token) (status int, header http.Header, body []byte, err error)` over `ps.client` and `readAll`; classify statuses in `githubEmails` per spec §6 (rate-limit signals from the inventory). Discard the token on any error path; no error text includes the token or response body.
- [ ] **Step 4:** Tests → PASS. Then `go test ./internal/federation/... -count=1` → PASS (no regressions in Google/OAuth2 token storage).
- [ ] **Step 5:** Commit `feat(federation): GitHub provider`.

### Task 5: Hosted login wiring (G4 server side)

**Files:**
- Modify: `internal/login/social.go:222` (`case errors.Is(err, federation.ErrEmailRequired): ui.RenderError(w, http.StatusForbidden, view, view.L.T(i18n.KeyErrSocialEmailRequired))`), `internal/i18n/keys.go` (`KeyErrSocialEmailRequired = "zeroauthy.error.social-email-required"`), `internal/i18n/locales/en.json` ("Your GitHub account needs a verified primary email address to sign in."), `internal/i18n/locales/fr.json` (the French catalog has no `social-*` errors today; follow whatever `catalog_test.go` requires — add a French string only if the test enforces parity), `internal/oauth/grant_native_social.go:180` (add `ErrEmailRequired` to the mapped list so it cannot become a 500)
- Create: `internal/login/github_test.go`

- [ ] **Step 1: Failing test** `TestGitHubLoginFlow` (memory store, fixture provider via `httptest`): the hosted login page shows a "Continue with GitHub" button for an enabled `github` connection; begin → 303 to the fixture authorize URL; callback → session and redirect to the client; second-origin login (custom domain) sends that origin's `/login/callback`; `ErrEmailRequired` → 403 with the catalog text; a blocked user → 403 `KeyUserBlocked`.
- [ ] **Step 2:** `go test ./internal/login ./internal/i18n -run 'GitHub|Catalog' -count=1` → FAIL, implement, → PASS.
- [ ] **Step 3:** Commit `feat(login): GitHub hosted login and email-required page`.

### Task 6: Management schema, seed and Deploy CLI migration (G6 server side)

**Files:**
- Modify: `api/management.yaml` (add `github` to the connection `strategy` enum and a `ConnectionOptionsGitHub` schema with the spec §5 options; `x-source` = the Auth0 GitHub connection page and the node-auth0 `ConnectionOptionsGitHub` type), regenerate `internal/gen/mgmtapi/mgmtapi.gen.go` and `console/src/api/schema.d.ts` with the repo's existing generate targets (`make generate` or the target `api/spec_test.go` names), `internal/deploymigration/federation.go` and `bootstrap.go` (GitHub uses `client_secret` reinjection like Google; confirm and add a test), `internal/seed/seed.go` (seeded `github` connection accepted)
- Create: `internal/deploymigration/github_test.go`, `internal/seed/github_test.go`

- [ ] **Step 1: Failing tests:** `TestDeployMigrationGitHub`: an exported `github` connection with `client_secret: "********"` requires reinjection; flags round-trip; mismatched `scope` → error naming the expected scope. `TestSeedGitHub`: a seed file with a `github` connection and flags creates it with the effective scope; `options.authorizationURL` → seed error.
- [ ] **Step 2:** `go test ./internal/deploymigration ./internal/seed ./api -count=1` → FAIL, implement, regenerate, → PASS. `./scripts/check-sources.sh api/management.yaml` reaches every new `x-source`.
- [ ] **Step 3:** Commit `feat(mgmt): github connection schema, seed and deploy migration`.

### Task 7: Console (G7)

**Files:**
- Modify: `console/src/pages/connections/social/social.ts` (`github` in `federatedStrategies` and `socialStrategies`; `githubScopeFlags` list in inventory order), `console/src/pages/connections/social/Create.vue`, `Settings.vue` (GitHub form: client ID, secret with configured indicator, `email` toggle, flat scope-flag checkbox list, sync policy, callback URLs from `callbackURLs`, the OAuth app / GitHub App note and the "register every listed URL exactly" note), `console/src/locales/en.ts` (and other console locales present), rebuilt `console/dist`
- Create: `console/src/test/github.ts`; extend `Create.test.ts`, `Settings.test.ts`, `List.test.ts`

- [ ] **Step 1: Failing tests:** create GitHub with `repo` checked sends `options: {client_id, client_secret, email: true, repo: true}` and no `scope`; settings shows the effective scope read-only, the two notes, one callback URL per tenant host and custom domain; checkboxes are keyboard-operable (`Space` toggles); at 360 px width the form has no horizontal scroll (existing layout test helper).
- [ ] **Step 2:** `cd console && npx vitest run src/pages/connections/social` → FAIL, implement, → PASS.
- [ ] **Step 3:** `make console`; commit source and `console/dist` together. (No dependency changed, so one build is enough; CI's clean-build check verifies it.)
- [ ] **Step 4:** Commit `feat(console): GitHub social connection`.

### Task 8: E2E acceptance (G4, G6)

**Files:**
- Create: `tests/e2e/social/provider/github.go` (fixture upstream: `/github/login/oauth/authorize`, `/github/login/oauth/access_token`, `/github/api/user`, `/github/api/user/emails`, with modes selected by the test through a control endpoint: `verified`, `unverified`, `no-scope-403`, `rate-limited`, `rename`), `tests/e2e/social/provider/github_test.go`, `tests/e2e/m39c-github.spec.mjs`, `tests/e2e/m39c-github-deploy.mjs`, `tests/e2e/run-m39c-github.sh`
- Modify: `tests/e2e/social/provider/provider.go` (register the flavor), `tests/e2e/social/harness/main.go` (`WithGitHubFixture` from an env-provided base URL, as Apple does), `Makefile` (`e2e-github:` target running `tests/e2e/run-m39c-github.sh`), `.github/workflows/ci.yml` (add `e2e-github` to the e2e `suite` matrix only; no other workflow change), `tests/e2e/playwright.config.mjs` (isolate the new spec like the Apple one)

- [ ] **Step 1:** Write the Playwright spec covering spec §9 G4: first login creates `github|<id>`; repeat login after the fixture renames `login` updates `nickname` under `on_each_login`, same `user_id`; a second GitHub account with the same email is a separate user; an imported `github|<id>` user (Management API import job) logs into the same account; `unverified` and `no-scope-403` modes show the email-required page on first and repeat login; `rate-limited` shows the provider-failure page; the token is returned by `GET /api/v2/users/{id}` only to an M2M client with `read:user_idp_tokens`, not to one without it nor to another tenant's client; after unlink and after user deletion the token is no longer returned; two origins each return to their own callback.
- [ ] **Step 2:** Write the Deploy CLI lane (`m39c-github-deploy.mjs`, G6): export a tenant with a GitHub connection with flags, import into a fresh tenant with explicit secret reinjection, log in; an export edited so `scope` differs from its flags fails the import with the expected-scope message.
- [ ] **Step 3:** `make e2e-github` with `TMPDIR`/`GOTMPDIR` on `/dev/shm/zeroauthy-e2e` → PASS. Also `go test ./tests/e2e/social/... -count=1` → PASS.
- [ ] **Step 4:** `uvx zizmor .` → no findings (only the matrix entry changed).
- [ ] **Step 5:** Commit `test(e2e): GitHub acceptance and Deploy CLI lanes`.

### Task 9: Documentation, local verification and final review

**Files:**
- Modify: `docs/social-connections.md` (GitHub section per spec §8), `docs/compat/matrix.md`, `docs/compatibility.md` (GitHub out of the 39b row), `CHANGELOG.md`, `docs/superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md` (39c implemented), `docs/superpowers/README.md`
- Create: `docs/superpowers/2026-11-18-plan-39c-implementation-record.md` (commands, snapshot SHA, actual exit codes, skips, whether the optional real-GitHub check was done)

- [ ] **Step 1:** Write the docs. `docs/social-connections.md` covers: OAuth app setup; GitHub App sign-in only; registering every callback URL; `user:email` and the email-required rule; token retrieval through `read:user_idp_tokens`; tokens not refreshed; granted scopes may differ (check `X-OAuth-Scopes`, treat 401 as revoked); scope changes apply from the next login; `profile: false` difference; unsupported list (GitHub Enterprise, device flow, refresh).
- [ ] **Step 2:** Fast local tier: `TMPDIR=/dev/shm/zeroauthy-39c GOTMPDIR=/dev/shm/zeroauthy-39c go test ./...` (no `-race`) plus `make e2e-github`, run once with output to a log; `govulncheck ./...`; `git diff --check origin/main`.
- [ ] **Step 3:** Final whole-branch review (superpowers:requesting-code-review) against this plan and the spec; fix findings; record them in the implementation record.
- [ ] **Step 4:** Commit `docs(github): operator guide, compatibility and implementation record`; push `plan-39-github-social`, open the PR (`Closes #66`, lists the security-sensitive packages), and hand CI monitoring to the developer.
