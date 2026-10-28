# Actions

zeroauthy runs tenant JavaScript for `post-login` and `credentials-exchange`.
Use the console's Actions library to save a draft, wait for its build, deploy
it, then add it to an ordered trigger flow. Saving alone does not change the
running version. The Management API exposes fourteen operations under
`/api/v2/actions`; see [the compatibility decision](compat/decisions.md#d-0053--plan-27-actions-contract-2026-10-27)
and [verification record](superpowers/2026-10-27-plan-27-implementation-record.md).
Other triggers and Action Modules are deferred to Plan 28.

## Handlers and events

```js
exports.onExecutePostLogin = async (event, api) => {
  api.idToken.setCustomClaim('https://app.example.com/roles', event.authorization.roles);
  api.accessToken.setCustomClaim('https://app.example.com/customer', event.user.app_metadata.customer);
};
```

Post-login runs after authentication and before consent and code/token
issuance, for browser authorization, device approval, password,
password-realm and refresh grants. Authorization-code and device exchanges
apply the sealed approval effects without rerunning the flow. Refresh runs
it again. Credentials exchange uses `exports.onExecuteCredentialsExchange`
after client authentication and client-grant validation, before minting.
Redirects resume in `exports.onContinuePostLogin`.

The post-login event includes user, client, connection, request, transaction,
resource server, role names, login count, tenant and secrets. Session and
refresh-token fields appear when available. `request.geoip`, `asn`,
organization, MFA, prompt, agent and Enterprise data are omitted. Earlier
Actions' target scopes, transaction metadata and user/app metadata overlays
are visible to later Actions. Absent features are not synthesized.

Protocols are `oidc-basic-profile`, `oauth2-device-code`, `oauth2-password`
(plain password), `oauth2-resource-owner` (password-realm),
`oauth2-refresh-token` and `oauth2-client-credentials`. Browser authorization
passes the authorization query and an empty body. Internal `za_*` query keys
are omitted. Token request bodies omit password, client secret/assertion,
PKCE verifier, refresh token, device code and authorization code credentials.

## API support

| Post-login member | Behavior |
|---|---|
| `access.deny(reason)` | Stop the flow with `access_denied` |
| `accessToken.setCustomClaim`, `idToken.setCustomClaim` | Add filtered custom claims |
| `accessToken.addScope`, `accessToken.removeScope` | Edit final access-token scopes after policy/RBAC/consent |
| `transaction.addTargetScope`, `removeTargetScope`, `setTargetScopes`, `clearTargetScopes` | Edit target scopes before policy filtering |
| `transaction.setMetadata` | Share scalar metadata within this transaction, including continuation |
| `user.setAppMetadata`, `user.setUserMetadata` | Batch validated metadata patches |
| `roles.getUserEffectiveRoles`, `getUserEffectiveRolesByIds`, `getUserEffectiveRolesByNames` | Read the flow's direct-role snapshot; no group roles |
| `redirect.canRedirect`, `sendUserTo`, `encodeToken`, `validateToken` | Browser redirect and signed continuation tokens |
| `cache.get`, `set`, `delete` | Best-effort cache per tenant and trigger, local to this server |
| `validation.error(code, message)` | Stop the flow with the supplied error |
| `groups.getUserGroups`, `groups.hasGroupMembership` | Empty groups / false membership |
| `rules.wasExecuted` | Always false |

The `session.*`, `refreshToken.*`, `authentication.*`, `multifactor.*`,
`prompt.*` and `samlResponse.*` APIs throw "not supported by zeroauthy" and
fail the flow closed, including when the Action catches that exception.
Unknown methods and invalid arguments also fail closed.

Credentials-exchange supports only `access.deny(code, reason)`,
`accessToken.setCustomClaim`, the four target-scope methods, and cache methods.
Its deny codes are `invalid_request` (400), `invalid_scope` (400) and
`server_error` (500). It has no `accessToken.addScope` or user/ID-token APIs.
Target edits are intersected with the client grant.

## Scopes, roles and claims

The user-token order is requested scopes → Action target edits → API
and application policy/RBAC filtering → consent → `addScope`/`removeScope` →
mint. Consent lists the filtered target scopes. **`addScope` bypasses those
policy, RBAC and consent filters**, as Auth0 documents; grant that API to
trusted Action authors. The response `scope` equals the JWT's `scope`, even
when empty. Final edits affect only the access token: they cannot enable an
ID token or issue a refresh token by adding `offline_access`.

A refresh family's ceiling is the issued, consented target set intersected
with the authorized set before Action edits. Neither target additions nor
`addScope` additions enlarge it. Actions rerun on refresh and must re-add
those scopes each time. Target additions are rechecked against current
policy/RBAC; for clients requiring consent, stored audience grants also cap
them. Refresh target edits can restore scopes inside the family even when
the individual refresh request downscoped them. Removing final
`offline_access` with `removeScope` suppresses refresh-token return/rotation;
removing it only from target scopes does not by itself prevent rotation of
an existing family.

Roles read by an Action are fixed at flow start. A bound post-login flow
for an RBAC-enabled API also freezes effective permission assignments before
execution, carrying that snapshot through consent, code/device exchange and
redirects. Assigning a default role through `require('auth0')` and M2M secrets
therefore affects the next issuance. Current API definitions, RBAC settings
and application policy still apply at mint: captured permissions are
intersected with current declared API permissions. With no bound flow or no
captured RBAC snapshot, the normal issuance-time lookup remains in use.
RBAC-disabled APIs omit `permissions`; Actions cannot replace it.

Reserved JWT names (including `sub`, `aud`, `scope`, `permissions` and
`roles`) and claims already carried by the token are silently dropped.
Namespaces at `auth0.com`, `webtask.io`, `webtask.run`, `zeroauthy.dev` and their
subdomains, and prefixes `urn:auth0` / `urn:zeroauthy`, are dropped. Management
API access tokens also drop non-namespaced claims. Custom claims must fit
100,000 JSON bytes per token; oversize fails the flow. **Plan 27 does not
return Action ID-token custom claims from `/userinfo`**; read them from the
ID token. This is a deferred parity gap.

## Redirect and continue

Check `api.redirect.canRedirect()` before `sendUserTo(url, {query})`.
Redirects are available only for interactive browser authorization, never
for device approval or token-endpoint grants. With `prompt=none`, an attempted
redirect returns `interaction_required`; other unavailable redirects fail
closed. The URL must be absolute HTTP(S).

The calling Action finishes, then the flow suspends. The redirect URL gets a
random `state` overriding any caller-supplied state. Return the browser to
`GET /continue?state=…` or form `POST /continue` on the same canonical/custom
origin. State is encrypted at rest, bound to tenant, browser session and
origin, single-use and valid for 15 minutes. Missing, expired, replayed or
mismatched state returns `400 invalid_request`. POST forms are limited to
64 KiB. The original client, callback, grant and connection are revalidated
before resumed code runs.

`onContinuePostLogin` receives fresh continuation query/body, then the pinned
remaining versions run. Binding, deploy and role changes during suspension
do not replace the captured flow. Five redirects are allowed per login;
the sixth fails closed. The cumulative execution budget remains 20 seconds;
browser waiting time is excluded.

`encodeToken({payload, secret, expiresInSeconds: 900})` creates HS256 with
user `sub`, tenant-hostname `iss`, `iat`, `exp` and request `ip`.
`validateToken({secret, tokenParameterName: 'session_token'})` reads the
continuation query/form, verifies HS256 and expiry, and requires a `state`
claim equal to the current continuation state. Include that state in the
signed payload returned by the redirect service.

## Metadata, failures and execution references

User/app metadata merges once at flow end on success, deny or
`validation.error`, atomically with the execution record. Errors, timeouts,
invalid arguments and unsupported calls discard patches. Redirects hold
patches until the final phase; abandonment/expiry discards them. Concurrent
unrelated metadata is retained by a reload under lock. Metadata committed
before consent remains even if the user later declines consent or issuance
fails. Transaction metadata expires with the transaction.

Post-login deny and `validation.error` return 403 at the token endpoint;
authorization uses the original client's redirect/error-page policy.
Validation codes are 1–128 bytes in RFC 6749's error charset (printable ASCII
excluding quote and backslash). Reasons/messages replace disallowed bytes
with `?` and truncate at 512 bytes. Throws/timeouts/internal errors yield
generic `server_error`, issuing no code/token.

Failed/denied flows log tenant, trigger, Action name and execution ID.
Hosted error pages show a reference; OAuth `error_description` never includes
it. Look up persisted IDs in the console or
`GET /api/v2/actions/executions/{id}` with `read:actions`. Each suspended or
resumed phase has its own record; correlate phase IDs separately. Records
contain per-Action timings and masked errors. Flows without bindings create
no execution, and pre-execution store failures may have no reference.
Executions are retained ten days and swept hourly; expired continuation
states are swept every minute by the jobs worker.

The draft test endpoint returns `{payload: {commands, logs, error?,
duration_ms, execution_id}}`. It requires a built draft (400 otherwise).
It uses real `fetch`, records rather than applies metadata/redirects/denials,
and uses a throwaway cache. Roles come from the real tenant user when found,
otherwise empty. Its execution ID is ephemeral: **no execution lookup record
is written**. Secrets are write-only, envelope-encrypted and snapshotted at
deploy; responses expose names/update times. Known secret values are masked
in output/errors, but arbitrary tokens fetched or printed by code are not
automatically known to the redactor.

## Dependency builds, replicas and configuration

`runtime: node22` is the API label; the host executes Node ≥22.13. Pure
JavaScript registry dependencies support exact semver, empty version or
`latest`; the latter two resolve to exact versions at build. Ranges, git,
file, URL/tarball specs, per-dependency `registry_url`, binding secrets and
modules are refused. Native addons cannot load.

Saving queues `pending → building → built|failed`. Deploy requires a built
draft, creates an immutable version, and snapshots code, resolved dependencies
and secrets. Redeploying an old version creates a new version number;
`update_draft` optionally restores its draft. Bound Action deletion requires
`force=true`, which removes its bindings. Lists default to 20 per page, max
100. Read/create/update/delete use the corresponding `*:actions` scopes;
deploy, rollback and test require `create:actions`.

Builds install with `--ignore-scripts`, no supplied lockfile, no bin links,
private HOME/cache and empty private user/global npm configs. Registry
authentication through operator `.npmrc` is not supported. npm's installation
root, including its built-in npmrc, is readable: keep that installation free
of credentials. Resolver processes have a 15-second limit and a separate
semaphore of the configured build concurrency; waiting for a slot is bounded
by the caller context. Resolver timeout maps to 503; other registry failures
produce failed builds. Registry access is needed only for builds, never at
login. Use `actions.registry` for a mirror containing metadata and tarballs.

Build IDs address runtime plus resolved dependencies within a tenant. The
store holds packed artifacts and SHA-256 hashes. A replica extracts a missing
local tree under the flow's budget and verifies the artifact; missing/corrupt
artifacts fail closed. Startup/deploy prewarm deployed artifacts. Pending or
building records recover when saved, viewed, deployed or tested; there is no
startup scan of all unfinished builds. Concurrent replica rebuilds are
allowed. Nodes require compatible Node installations and the same master
key/store; npm is needed only where builds run. Existing extracted trees
are trusted, so protect the cache from outside modification.

Configure YAML `actions` or `ZEROAUTHY_ACTIONS__*` (see also
[configuration](../README.md#configuration)):

| Key | Default | Meaning |
|---|---|---|
| `node` | `node` | Node ≥22.13 executable |
| `npm_cli` | npm beside Node | Absolute path to `bin/npm-cli.js`, executed through Node |
| `registry` | `https://registry.npmjs.org/` | HTTP(S) registry or offline mirror |
| `cache_dir` | user cache dir + `/zeroauthy/actions-cache` | Absolute private extraction/build directory; set explicitly in services |
| `max_memory_mb` | 256 | Runner JavaScript heap, minimum 32 |
| `idle_timeout` | `5m` | Idle runner lifetime |
| `build_timeout` | `2m` | npm install time limit |
| `max_artifact_mb` | 50 | Installed/packed cap in decimal MB, range 1–50 |
| `max_concurrent_builds` | 2 | Concurrent builds and, separately, resolvers per server |

On Linux the default cache base is `$XDG_CACHE_HOME` or `$HOME/.cache`. Without
either, startup warns and builds fail until `cache_dir` is set. Missing Node
or npm does not prevent ordinary server startup; affected execution/builds
fail rather than silently skipping Actions.

## Isolation and limits

Actions and custom databases share the sandbox implementation but own separate
per-tenant processes. An Action timeout kills that tenant's Actions process,
including its other in-flight calls, while other tenants/custom databases
continue. A version gets its own VM context; the process/tenant is the trust
boundary. Node permissions restrict reads to the runner and that tenant's
build root; execution has no writes, child processes, workers, addons or
WASI. Builds can read npm and their private work directory and write only
there. Execution inherits no server environment; builds receive only their
private HOME. Process signalling methods are locked out. VM isolation alone
is not the security boundary.

For untrusted tenants, run under a dedicated uid or in a container. Apply
network egress policy (including internal/link-local metadata services),
cgroup/container memory limits and disk quotas. Network access is open;
`max_memory_mb` caps the runner heap, not Buffers or total RSS, and npm has no
heap cap. Install size monitoring polls every 250 ms and can overshoot before
termination; the final artifact cap is exact. This is not a hard disk quota.

| Limit | Value |
|---|---|
| Name / source | 1–128 Unicode code points, case-sensitive unique per tenant / 100,000 bytes |
| Secrets | 64; names `[A-Za-z0-9_]{1,128}`; values 4096 bytes |
| Dependencies / bindings | 50 per Action / 20 per trigger |
| Flow / process concurrency | 20 seconds cumulative / 64 in-flight calls per tenant process |
| Artifact | 50,000,000 bytes maximum, configurable downward |
| Cache | 20 entries; key 64 bytes; value 4096 bytes; total 8192 bytes |
| Cache expiry | Default 15 minutes; earlier of TTL/expiry; maximum 24 hours; node-local and evictable |
| Transaction metadata | Key 64 characters; scalar value 8192 JSON bytes; total 16,384 JSON bytes |
| Role lookups | Page `take` ≤100; IDs ≤100; names ≤50 |
| Custom claims | 100,000 JSON bytes per token |
| Continuation / retention | 15 minutes, five redirects / ten-day executions |

Runtime console capture currently keeps up to 100 entries of 2048 characters
per message (plus level prefix). The inventory's declared 256 characters per
Action is not enforced; this drift is recorded for follow-up.

## Seed and migration

Seed Actions use the public-style code/dependencies/secrets/deploy fields and
ordered trigger bindings by Action name or ID; see
[the working seed](../tests/e2e/seed.yaml). Named Actions and initialized
trigger lists are create-only in both seed modes. A durable tenant/trigger
marker preserves management replacement with `[]` across restart. Atomic
initialization keeps an interrupted first seed retryable; existing unmarked
nonempty lists are preserved. `seed.ApplyWithActions` applies ordinary seed
data in one transaction, then builds outside it and atomically creates/deploys
each ready Action. A failed build can leave ordinary data applied; retry the
seed. Legacy `Apply` rejects Action-bearing seeds.

Memory, SQLite, PostgreSQL, MySQL and gRPC storage support Actions. Plugins
must advertise Actions capability **2**; older plugins refuse startup.
Upgrade all plugin writers before running this server. Deleting a tenant
removes its stored Actions, artifacts, executions, states and binding markers.
Deleting an Action retains shared build artifacts until tenant deletion.
Deploy CLI round trips cover Actions/triggers in YAML and directory formats
with generated/preserved credentials and secret keyword replacements;
exported secret values are never required. Database connection migration is
excluded from that demonstrated matrix.
