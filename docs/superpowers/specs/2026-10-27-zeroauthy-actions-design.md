# zeroauthy — Plan 27: Actions I (post-login, credentials exchange, npm)

- **Status:** Draft for maintainer review; implementation is not started.
- **Date:** 2026-10-27
- **Roadmap:** [Plan 27](2026-10-19-zeroauthy-management-roadmap-design.md#plan-27--actions-i-full-design).
- **Predecessor:** [Plan 26 implementation record](../2026-10-27-plan-26-implementation-record.md).
- **Implementation plan:** [Plan 27](../plans/2026-10-27-zeroauthy-plan-27-actions.md).

## 1. Intent and scope

Let a tenant's own engineers run JavaScript at the two most-used Auth0
extension points, so Actions copied from Auth0 tenants, docs and blog posts
work as written. The motivating uses, from the maintainer:

- custom claims in ID and access tokens;
- reading the user's roles at login ("dynamic roles") and turning them into
  claims or scope decisions;
- changing user and app metadata during login;
- redirecting to an external page with extra query parameters, and reading
  query/body parameters when the browser comes back (`/continue`).

Each trigger ("step") is its own extension point with its own `event` and
`api` objects. Plan 27 implements **post-login** and **credentials-exchange**,
the Actions Management API, versioning and deployment, ordered trigger
bindings, the test endpoint, execution records, **npm dependencies** (moved
here from Plan 28 by the maintainer, 2026-10-27, so common Actions run on day
one), console editing, seed and Deploy CLI migration.

Excluded (Plan 28 or later): every other trigger, Action Modules
(`/actions/modules`), Marketplace integrations, MFA/`api.authentication`
and `api.multifactor` (Plan 33), custom prompts/forms (`api.prompt`), SAML
responses, Enterprise session and refresh-token controls, groups (none exist
in zeroauthy), private npm registries and tenant logs/log streams.

**Anti-goals.** A failing, timing-out or unsupported Action must never let a
login or token through silently. One tenant's Actions must never see or slow
down another tenant. Actions must never grant role assignments through a
side door: the `api` object reads roles; it does not assign them.

## 2. Trust model

Maintainer ruling (2026-10-27): Action authors are trusted. They are the
Management API user created on first run, Management API clients granted the
Actions scopes, people with a role that manages the tenant, and the tenant's
operators. In a multi-tenant install each tenant belongs to a different
software owner or team, so the requirement is **tenant isolation**, not
hostile-code containment within a tenant:

- each tenant's Actions run in that tenant's own Node process(es), never shared;
- secrets, cache, dependency trees, execution records and runtime state are
  tenant-bound and unreadable from another tenant's process;
- a crash, hang, timeout or memory blow-up in one tenant affects only that
  tenant's in-flight executions;
- Action code inherits D-0022's process controls (empty environment,
  `--permission`, blocked process-signalling methods). Outbound network stays
  open, as on Auth0, and remains an operator egress concern.
- **No access to zeroauthy's environment** (maintainer requirement,
  2026-10-27). Neither Action code nor the npm dependency build may read the
  server's environment variables (master key, database DSN, provider
  secrets) or its files. Both run as sandboxed Node processes: empty
  environment, `--permission` with file reads limited to their own
  directories, no child processes, workers, addons or WASI, so
  `process.env`, `/proc/self/environ`, `/proc/<ppid>/environ` and
  `/proc/1/environ` are all empty or denied. A canary-secret test proves this
  for both paths. Running zeroauthy itself in a container or under a dedicated
  uid stays the documented extra hardening (D-0022 addendum).

## 3. Evidence and constraints

Read `CLEAN_ROOM.md` first. Public sources consulted 2026-10-27 (no live
tenant contacted):

- [Post-login `api`](https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-api-object) and [`event`](https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-event-object).
- [Credentials-exchange `api`](https://auth0.com/docs/customize/actions/explore-triggers/machine-to-machine-trigger/credentials-exchange-api-object) and [`event`](https://auth0.com/docs/customize/actions/explore-triggers/machine-to-machine-trigger/credentials-exchange-event-object).
- [Redirect with Actions](https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/redirect-with-actions), [Handling scopes](https://auth0.com/docs/customize/actions/handling-scopes-in-actions), [Limitations](https://auth0.com/docs/customize/actions/limitations), [Dependencies](https://auth0.com/docs/customize/actions/manage-dependencies), [Custom claims](https://auth0.com/docs/secure/tokens/json-web-tokens/create-custom-claims).
- Management API reference for `actions` (create, bindings, executions, test) and the Apache-2.0 OpenAPI description.

Task 1 inventories every operation and `api`/`event` member, freezes exact
schemas, statuses and error envelopes, and records gaps as compatibility
decisions (next free: **D-0053**). Optional live observation uses a separate
observer session; missing evidence is recorded as unavailable.

Global constraints:

- Go 1.26.7, existing Vue/TypeScript, SQL, protobuf stacks. Node ≥ 22.13 is
  already required for custom databases; npm (bundled with Node) becomes a
  requirement only when Actions with dependencies are deployed.
- SQL migrations are additive; next number **0023**.
- Every runtime or store failure fails closed: no token, no metadata write
  beyond what §6 specifies, no silent skip of a bound Action.
- Tests never contact the public npm registry or Auth0; they use local
  fixtures and a local registry.

## 4. Management contract

| Operation | Scope | Notes |
|---|---|---|
| `GET /api/v2/actions/actions` | `read:actions` | filters `triggerId`, `actionName`, `deployed`, `installed`; `page`/`per_page`; envelope `{actions,total,page,per_page}` |
| `POST /api/v2/actions/actions` | `create:actions` | 201; `deploy: true` deploys after create |
| `GET/PATCH/DELETE /api/v2/actions/actions/{id}` | read/update/delete | DELETE of a bound Action needs `?force=true`, which also removes its bindings |
| `POST /api/v2/actions/actions/{id}/deploy` | `create:actions` | creates the next immutable version from the draft |
| `GET /api/v2/actions/actions/{id}/versions[/{versionId}]` | `read:actions` | paged list, single version |
| `POST /api/v2/actions/actions/{id}/versions/{versionId}/deploy` | `create:actions` | roll back: redeploys an old version as a new version number |
| `POST /api/v2/actions/actions/{id}/test` | `create:actions` | runs the **built draft** against a supplied `payload`; `400` if the draft build is not `built` |
| `GET /api/v2/actions/triggers` | `read:actions` | supported triggers only (§10) |
| `GET/PATCH /api/v2/actions/triggers/{triggerId}/bindings` | read/update | PATCH replaces the ordered list |
| `GET /api/v2/actions/executions/{id}` | `read:actions` | 10-day retention |

Exact shapes follow the public schema: Action fields `id`, `name`,
`supported_triggers` (exactly one trigger), `code`, `dependencies`
(`name`, `version`), `runtime`, `secrets` (responses: `name`, `updated_at`;
values write-only), `deployed_version`, `all_changes_deployed`, `status`,
`built_at`, timestamps. Unknown properties are `400`. The Actions scopes join
tenant bootstrap/upgrade without expanding existing restricted client grants
(same rule as Plan 26).

Local limits where Auth0 publishes none (each a D-0053 entry): name 1–128
code points, unique per tenant (case-sensitive); code ≤ 100 kB (Auth0's);
runtime `node22` only, default `node22` (it labels the API contract; the host's
Node ≥ 22.13 executes it); ≤ 64 secrets, name `[A-Za-z0-9_]{1,128}`, value
≤ 4096 bytes (Auth0's per-secret limits); ≤ 50 dependencies; ≤ 20 bindings per
trigger; `registry_url` and binding `secrets` (Marketplace-only) are refused
with `400`. Binding refs accept `action_id`, `action_name` and `binding_id`;
binding an Action with no deployed version is `400`. Secret updates apply the
Auth0 rule that values are write-only; whether a secret change requires a
redeploy is frozen in Task 1 (default: secrets are snapshotted into a
version at deploy, so rollbacks are self-consistent).

Test endpoint semantics (author's call): it uses the same flow engine in a
dry-run mode. Real `fetch` runs (as on Auth0); metadata writes, redirects and
denials are **recorded, not applied**; the cache is a throwaway per-test
cache; `api.roles.*` reads the real tenant user's roles when the payload's
user exists in the tenant, otherwise empty results. The response payload
returns recorded commands, logs (secrets masked), error and timing; nothing
is written to the execution store.

## 5. Build, dependencies and versions

Saving a draft (create/PATCH) queues a **build**: `status` goes `pending` →
`building` → `built` or `failed`, with `errors` describing failures. Deploy
requires a `built` draft (otherwise `400`) and creates an immutable version
`number` n+1 referencing the same build. Rollback redeploys an older version's
build as a new version. Bindings always execute the Action's currently
deployed version.

Dependencies: `version` must be an exact semver or empty/`latest` (resolved
and recorded as the exact version at build). Ranges are refused; scoped
packages are allowed. The build runs `npm install` (operator-configured npm
binary and registry; default public registry, with a mirror/offline-registry
setting for air-gapped installs) in a private temp dir with an empty
environment, a private HOME/cache, `--ignore-scripts`, no lockfile from the
author, a time limit and an installed-size cap. npm's own CLI runs as
`node --permission` with file reads limited to the npm installation and the
build dir, writes limited to the build dir, and no child processes; a build
that npm cannot complete under these limits fails. Git, file, URL and
tarball dependency specs are refused (only registry packages), so npm never
needs to spawn helpers. Native addons cannot load
under `--permission`; Auth0 also refuses them (build or first execution fails
with a clear error). Build output lives in a content-addressed, per-tenant
cache directory keyed by the resolved dependency set; identical sets within
one tenant share it. A tenant's runner process may read only its own tenant's
cache directories. Builds survive restart: a missing cache entry is rebuilt
Concurrency of builds is bounded per server.

**Replicas (author's call).** A successful build is packed into a tarball
(≤ 50 MB, configurable) and stored through the store with its content hash,
so `status: built` means the same thing on every node. A node that lacks the
extracted tree extracts it from the store before first use. Extraction is a
local, bounded operation inside the flow's 20 s budget; npm and the registry
are needed only by the node that runs the build, never at login. Nodes also
pre-extract deployed builds at startup and after a deploy, in the background.
A missing or corrupt artifact fails the flow closed.

## 6. Runtime semantics

**Runner.** Generalize `internal/customdb`'s Node runner into a shared
package used by both custom databases and Actions (no behavior change for
custom databases). Actions and custom databases use **separate** processes
(author's call), so killing one tenant's Action process on timeout never
aborts that tenant's custom-database logins, and vice versa. The Actions
process may read only its own tenant's extracted-build root (fixed
`--allow-fs-read` path, so new deploys need no restart). Actions get one process per tenant with a `vm` context per
deployed version, module `require` resolved inside that version's dependency
tree only, `fetch`, `console` capture (masked like D-0023's addendum), and
`exports.onExecutePostLogin` / `onContinuePostLogin` /
`onExecuteCredentialsExchange` handlers (`async` or not). The total execution
of one trigger flow is limited to 20 s (Auth0's limit); exceeding it kills the
tenant process as custom databases do. Per-tenant in-flight and memory limits
reuse the custom-database configuration shape under a new `actions` config
section.

**Flow.** Bound Actions run in order. Each sees `event` reflecting effects of
earlier Actions where Auth0 documents it (Task 1 freezes which, e.g.
`event.user.app_metadata`, `event.transaction.metadata`); effects accumulate
in Go, never trusted from the runner as raw token contents. `api.access.deny`
stops the flow; later Actions do not run. An uncaught error, timeout, unknown
or unsupported `api` call, or invalid argument fails the flow closed.

Metadata commit rules (author's call; Auth0 documents only the deny case):
accumulated `setAppMetadata`/`setUserMetadata` changes commit once when the
flow ends in success or `deny`/`validation.error`. They are discarded when the
flow fails with an error, timeout or unsupported call, so a broken Action
leaves no partial state. Across a redirect they are held in the continue
state and commit only when the resumed flow ends; an abandoned or expired
redirect discards them.

Execution IDs (author's call; tenant logs arrive in a later plan): the ID
appears in the operator log line for every failed or denied flow (with tenant,
trigger and Action name, secrets masked), in test-endpoint responses, and as a
"reference" on the hosted error page so a user can report it. It is never put
in OAuth `error_description`. Every
flow writes an execution record (`id`, `trigger_id`, `status`, per-Action
`action_name`, `started_at`, `ended_at`, `error`), purged after 10 days.

**Post-login** runs after authentication **and after the consent screen**
(Auth0's login pipeline order; Task 1 confirms), and before any token or code is
issued. Declining consent means the flow never runs. A consented scope set is
the input to `transaction` edits; target-scope additions are filtered by API
definition, client policy and RBAC but are not shown on a consent screen. It runs for authorization code (hosted and federated login), implicit/hybrid
where supported, device-code approval, password and password-realm grants,
and refresh-token exchange (where `api.redirect.canRedirect()` is false).
`event` covers `user`, `client`, `connection`, `request` (`ip`, `hostname`,
`method`, `query`, `body`, `user_agent`, `language`; `geoip` omitted with a
D-0053 entry), `transaction` (`id`, `protocol`, `redirect_uri`, `state`,
`locale`, `requested_scopes`, `target_scopes`, `metadata`),
`authorization.roles` (role names), `resource_server`, `stats.logins_count`,
`secrets`, `tenant`, `session` and `refresh_token` where available. Absent
features (organizations, MFA factors) are omitted, not faked.

Supported post-login `api`:

| Member | Behavior |
|---|---|
| `access.deny(reason)` | authorize flows redirect to the client with `error=access_denied`, `error_description=reason`; token endpoint returns `403 access_denied`. Metadata changes made before deny still apply (Auth0 rule) |
| `accessToken.setCustomClaim`, `idToken.setCustomClaim` | §7 claim rules |
| `accessToken.addScope/removeScope` | edit the final access-token scope **after** RBAC/consent, bypassing those checks, exactly as Auth0 documents |
| `transaction.add/remove/set/clearTargetScope(s)` | edit the target set **before** RBAC/client policy; unauthorized scopes are dropped |
| `transaction.setMetadata` | shared with later Actions in the same transaction, survives redirect |
| `user.setAppMetadata/setUserMetadata` | batched, merged once at flow end through existing user-metadata validation |
| `roles.getUserEffectiveRoles`, `…ByIds`, `…ByNames` | read-only; effective = direct roles (no groups); checkpoint paging `take ≤ 100`, ids ≤ 100, names ≤ 50; served from the Plan 26 snapshot taken when the flow starts |
| `groups.getUserGroups`, `groups.hasGroupMembership` | empty results (zeroauthy has no groups) |
| `redirect.sendUserTo/encodeToken/validateToken/canRedirect` | §8 |
| `cache.get/set/delete` | per tenant and trigger, in memory, 20 entries, key ≤ 64 B, value ≤ 4 kB, ≤ 8 kB total, default TTL 15 min, max 24 h; not shared across server nodes and may be evicted (Auth0 also promises no consistency) |
| `validation.error(code, message)` | denies with that error code and message |
| `rules.wasExecuted` | always `false` (zeroauthy has no Rules) |

`session.*`, `refreshToken.*`, `authentication.*`, `multifactor.*`,
`prompt.*`, `samlResponse.*` exist but throw a clear "not supported by
zeroauthy" error, which fails the flow closed and is visible in the execution
record and test endpoint. Copied Actions therefore never silently skip a
security check.

**Credentials-exchange** runs inside the client-credentials grant after
client authentication and client-grant checks, before minting. `event`:
`client`, `request` (incl. `body`), `resource_server`, `tenant`, `secrets`,
`transaction` (`requested_scopes`, `target_scopes`), `accessToken`
(`scope`, `customClaims`). `api`: `access.deny(code, reason)` (OAuth error
response; allowed codes frozen in Task 1, default `invalid_request`,
`invalid_scope`, `server_error`), `accessToken.setCustomClaim`,
`transaction.*TargetScope*` (intersected with the client grant afterwards),
`cache.*`. No `addScope`, as on Auth0.

**Dynamic roles.** Actions read roles; they cannot assign them through `api`.
Auth0's documented "assign a default role" recipe calls the Management API
from the Action using the `auth0` npm package and Machine-to-machine
credentials stored as secrets. zeroauthy supports this unchanged: such
assignments affect the **next** issuance (the current flow's RBAC snapshot is
already taken). E2E proves it.

## 7. Token effects

Order for a user token: requested scopes → consent (already given) →
`transaction` target-scope edits → existing API-definition/client-policy/RBAC
filtering (Plan 26) → `accessToken.addScope/
removeScope` → mint. Refresh-family ceilings stay Plan 26's pre-RBAC
authorized set and never include Action-added scopes; post-login re-runs on
refresh and must re-add them. Token response `scope` equals the minted JWT
`scope`. `permissions` (for `_authz`) is not editable by Actions.

Custom claims: reserved names in Auth0's published list (`sub`, `aud`,
`scope`, `permissions`, `roles`, `azp`, `client_id`, `jti`, etc.) and claims
the token already carries are silently not added (Auth0 rule: transaction
succeeds, claim dropped). Namespaces using `auth0.com`, `webtask.io`,
`webtask.run` or `urn:auth0` are dropped. Access tokens for the tenant's
Management API audience drop non-namespaced claims. Total custom-claim payload
≤ 100 kB per token, else the flow fails closed. ID tokens and `/userinfo`
follow Auth0's documented rules (Task 1 freezes whether `/userinfo` echoes
ID-token custom claims; default yes, as Auth0 documents namespaced claims
appearing there).

## 8. Redirect and continue

`sendUserTo(url, {query})` is allowed only when `canRedirect()` is true
(interactive browser authorize/hosted-login flows, not `prompt=none`, not
token-endpoint grants). Otherwise: `prompt=none` returns
`interaction_required`; other flows fail closed. After the calling Action
returns, the flow suspends: Go stores the accumulated effects, the remaining
binding list (pinned to the version numbers that were executing) and the
Action position under a random `state`, bound to the login transaction and
browser session cookie, single-use, expiring after 15 minutes (local
choice). The browser goes to `url` with the extra query parameters plus
`state`.

`GET` and `POST /continue?state=…` on canonical and custom domains resume:
missing/wrong/expired/replayed `state` → `invalid_request`. The same Action's
`onContinuePostLogin` runs with a fresh `event.request` (the `/continue`
request's query/body), then the remaining Actions. A second redirect is
allowed (bounded, local limit 5 per login).

`encodeToken({payload, secret, expiresInSeconds=900})` produces an HS256 JWT
with `sub` (user ID), `iss` (tenant hostname), `iat`, `exp`, `ip` plus the
payload. `validateToken({secret, tokenParameterName='session_token'})`
verifies HS256 signature, expiry and a `state` claim equal to the current
`state`, reading the parameter from the `/continue` query or form body.

## 9. Storage and plugins

Repository `Actions()` on `store.Store` with memory, SQL (migration 0023:
actions, versions, secrets sealed with the master-key envelope and bound to
tenant+action, builds/dependency sets, bindings, executions, continue states)
and gRPC plugin support with an explicit capability check like Plan 26. Old
plugins fail startup when Actions are configured. Deleting a tenant removes
everything; deleting an Action removes its versions, secrets and (with
`force`) bindings. Execution and continue-state purges run on the existing
jobs worker. Concurrency rules: bindings PATCH and Action delete serialize per
tenant; an in-flight flow uses the binding list and versions it started with.

## 10. Console, seed, Deploy CLI

Console replaces the planned Actions page: Library (list/create/delete),
editor (existing script editor component) with dependencies, write-only
secrets, build status/errors, save draft, deploy, versions with rollback,
test panel (JSON event in, commands/logs/errors out, secrets masked), and a
Triggers page per supported trigger with an ordered binding list using
up/down controls (no drag). Look up an execution by ID. Original layouts only,
localized, accessible.

`GET /actions/triggers` lists `post-login` and `credentials-exchange` (local
choice: unsupported triggers are not advertised; creating an Action for one
is `400` until Plan 28).

Seed supports Actions (code, dependencies, secrets, deploy flag) and trigger
bindings with create-only ownership. Deploy CLI round trips cover `actions`
and `triggers` in YAML and directory formats × generated/preserved credentials,
comparing by Action name; secret values are supplied by keyword replacement,
never exported.

## 11. Acceptance

- Every operation, scope, 401/403/404 cross-tenant, malformed body and limit.
- Memory/SQLite/PostgreSQL/MySQL/gRPC conformance including rollback,
  cleanup and concurrency; migration from pre-0023 data.
- Runner: tenant isolation (secrets, cache, dependencies, crash/timeout
  containment), timeouts, unsupported methods, custom-database regression.
- Builds against a local npm registry fixture: exact/latest/scoped packages,
  refused ranges, `--ignore-scripts`, size/time limits, restart rebuild.
- Token matrix over all grants × triggers: claims, reserved-claim dropping,
  scope order with RBAC and `addScope` bypass, refresh ceiling, deny and
  error paths, response scope equals JWT scope, nothing issued on failure.
- Redirect/continue: query params, `state` binding, replay/expiry,
  `prompt=none`, `encodeToken`/`validateToken`, custom domains.
- E2E: auth0-cli `actions` commands; node-auth0 SDK for every operation; a
  post-login Action adding a namespaced claim read by auth0-spa-js; roles
  read into a claim; a deny shown on the error page; a redirect round trip;
  credentials-exchange claim and deny; an Action using the `auth0` npm
  package (served by the local registry) to assign a default role that
  appears on the next login; console Playwright flows; Deploy CLI four-cell
  matrix with post-import login.
- Full regression lanes, SQL script and OpenID conformance as in Plan 26.

Record actual results in a Plan 27 implementation record; update the
matrix, decisions, operator guide (`docs/actions.md`) and roadmap only to the
demonstrated degree. Plan 28 keeps the remaining triggers and Action Modules.
