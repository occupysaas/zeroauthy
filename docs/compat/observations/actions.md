# Actions I: public contract review

Date: 2026-10-27. Evidence: public documentation and the public Management API
reference only. **No live Auth0 tenant observation was performed and no observer
session exists; every live-behavior item below is "unavailable".** Machine
readable form: `internal/actionsrules/inventory.json`.

## Management operations (14)

Sources (Management API reference, each fetched 2026-10-27): [get-actions](https://auth0.com/docs/api/management/v2/actions/get-actions), [post-action](https://auth0.com/docs/api/management/v2/actions/post-action), [get-action](https://auth0.com/docs/api/management/v2/actions/get-action), [patch-action](https://auth0.com/docs/api/management/v2/actions/patch-action), [delete-action](https://auth0.com/docs/api/management/v2/actions/delete-action), [post-deploy-action](https://auth0.com/docs/api/management/v2/actions/post-deploy-action), [get-action-versions](https://auth0.com/docs/api/management/v2/actions/get-action-versions), [get-action-version](https://auth0.com/docs/api/management/v2/actions/get-action-version), [post-deploy-draft-version](https://auth0.com/docs/api/management/v2/actions/post-deploy-draft-version), [post-test-action](https://auth0.com/docs/api/management/v2/actions/post-test-action), [get-triggers](https://auth0.com/docs/api/management/v2/actions/get-triggers), [get-bindings](https://auth0.com/docs/api/management/v2/actions/get-bindings), [patch-bindings](https://auth0.com/docs/api/management/v2/actions/patch-bindings), [get-execution](https://auth0.com/docs/api/management/v2/actions/get-execution). The 202 (deploy, version deploy), 204 (delete) and 200 (test) statuses were re-checked against these pages.

| Operation | Scope | Success |
|---|---|---|
| GET actions (filters triggerId, actionName, deployed, installed; page from 0, per_page default 20) | read:actions | 200 `{actions,total,page,per_page}` |
| POST actions | create:actions | 201 action |
| GET / PATCH / DELETE action | read / update / delete | 200 / 200 / **204** (`force` detaches bindings) |
| POST action deploy | create:actions | **202** version |
| GET versions (paged), GET version | read:actions | 200 `{versions,total,page,per_page}` |
| POST version deploy (rollback, body `update_draft?`) | create:actions | **202** new version |
| POST test (`{payload}` required) | create:actions | **200 `{payload}`** |
| GET triggers | read:actions | 200 `{triggers}` (id, version, status, runtimes, default_runtime, compatible_triggers, binding_policy) |
| GET / PATCH trigger bindings | read / update | 200 `{bindings,total,page,per_page}` / `{bindings}` |
| GET execution | read:actions | 200 `{id,trigger_id,status,results[],created_at,updated_at}` |

Public create schema: `name`, `supported_triggers` (>=1 item, one trigger),
`code`, `dependencies` (`name`, `version`, optional `registry_url`), `runtime`
(default node22), `secrets`, `modules`, `deploy`; no extra properties. Build
`status` enum on the wire: pending, building, packaged, built, retrying,
failed. Binding refs: `type` binding_id, action_id or action_name (default
action_name). Execution `status`: unspecified, pending, final, partial,
canceled, suspended; each result has `action_name`, `started_at`, `ended_at`,
optional `error{id,msg,url}`. Retention 10 days. Docs say updating an action
does not affect flows until deployed, and that deploy of a bound action starts
running at once. 400/401/403/429 appear on all; 404 where a resource id exists.

## Runtime facts frozen from public documentation

Sources: [limitations](https://auth0.com/docs/customize/actions/limitations), [post-login api](https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-api-object), [post-login event](https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-event-object), [credentials-exchange api](https://auth0.com/docs/customize/actions/explore-triggers/machine-to-machine-trigger/credentials-exchange-api-object), [credentials-exchange event](https://auth0.com/docs/customize/actions/explore-triggers/machine-to-machine-trigger/credentials-exchange-event-object), [redirect]( https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/redirect-with-actions), [handling scopes](https://auth0.com/docs/customize/actions/handling-scopes-in-actions), [dependencies](https://auth0.com/docs/customize/actions/manage-dependencies), [custom claims](https://auth0.com/docs/secure/tokens/json-web-tokens/create-custom-claims). Bullets below follow those pages in that order of topic: limits and api (limitations, api pages), scopes (handling scopes), claims (custom claims), redirect (redirect page), dependencies (dependencies page).

- Limits (limitations page): code 100 kB; secret name 128, value 4096; cache 20
  entries per trigger, key 64 B, value 4 kB, 8 kB combined, items up to 24 h
  (default 15 min, earlier of ttl/expires_at wins); 20 s per trigger
  execution; console output persisted 256 chars per Action; transaction
  metadata key 64, value 8 KB, total 16 KB, string/number/boolean values;
  executions retained 10 days; a new `event.request` is issued whenever a
  trigger resumes.
- Post-login `api` members: access.deny; accessToken.{setCustomClaim, addScope,
  removeScope}; idToken.setCustomClaim; transaction.{setMetadata and four
  target-scope methods}; user.{setAppMetadata,setUserMetadata}; roles.{three
  getUserEffectiveRoles*}; groups.{two}; redirect.{four}; cache.{three};
  validation.error; rules.wasExecuted; plus authentication, multifactor,
  prompt, samlResponse, session (Enterprise) and refreshToken (Enterprise).
- Deny stops later Actions and does not cancel earlier metadata requests.
  Metadata is aggregated and written before the flow completes.
  `canRedirect()` is false for oauth2-resource-owner, oauth2-refresh-token and
  prompt=none. `validation.error` blocks login with the supplied code/message.
- Credentials-exchange `api`: access.deny(code, reason?) with codes
  `invalid_scope`, `invalid_request`, `server_error`; accessToken.setCustomClaim;
  cache.*; four target-scope methods (early access); no addScope/removeScope.
  Target scopes are intersected with the client grant after all Actions.
  Event: accessToken{customClaims,scope}, client, custom_domain, organization,
  request{body,geoip,hostname,ip,language,method,user_agent}, resource_server,
  secrets, tenant, transaction{correlation_id,requested_scopes,target_scopes}.
- Post-login event top-level: authorization.roles, client, connection,
  request (adds asn, query), resource_server, secrets, session, refresh_token
  (Enterprise), stats.logins_count, tenant, transaction (id, protocol,
  redirect_uri, state, locale, requested_scopes, target_scopes, metadata,
  and more), user, plus organization/prompt/authentication/agent members that
  zeroauthy omits.
- Scopes ([handling scopes](https://auth0.com/docs/customize/actions/handling-scopes-in-actions): "When consent is required, all scopes remaining after authorization filtering are included in the consent prompt ... including scopes added by Actions"; addScope results are not displayed on the consent screen): target-scope edits are visible to later Actions and are evaluated
  against client access policy and RBAC after all Actions; unauthorized
  additions are silently dropped. **Consent shows the scopes remaining after
  that filtering including Action-added target scopes**, but not `addScope`
  results, which bypass RBAC, access policy and consent and win over target
  removals regardless of Action order.
- Custom claims: OIDC/Auth0 reserved names (about 70) and claims already in the
  token are dropped without failing the transaction; `auth0.com`, `webtask.io`,
  `webtask.run` and `urn:auth0` namespaces are refused; http(s) namespaces
  must start with http:// or https://; urn namespaces only for custom APIs;
  payload <= 100 KB; `/userinfo` is excluded from the non-namespaced-claim
  restriction on API access tokens.
- Redirect: `/continue?state=...` resumes the same Action's
  `onContinuePostLogin`; missing/invalid state is `invalid_request`;
  `prompt=none` with a redirect yields `interaction_required`. encodeToken
  claims: sub, iss, exp, ip + payload, HS256, default 900 s; validateToken
  checks signature, expiry and `state` claim against the redirect `state`.
- Dependencies: public npm registry only in the docs; blank version means
  latest; native modules fail with "Cannot find module".

## Unavailable (not invented)

- Live statuses and bodies for error delivery: how deny, uncaught error and
  timeout reach `/authorize` redirects and `/oauth/token` (HTTP status per
  credentials-exchange code, hosted error page reference).
- Whether secret changes require a redeploy (limitations page is silent; PATCH
  prose says values are set only at creation).
- Exact point of post-login relative to the consent screen beyond the scope
  doc above; behavior when consent is then declined.
- Which `event` fields reflect earlier Actions beyond `transaction.target_scopes`
  and `transaction.metadata` (documented as visible to later Actions); app/user
  metadata reflection is unverified.
- Whether `/userinfo` echoes ID-token custom claims; Management API audience
  claim handling; the exact trigger list payload values; /continue GET vs POST
  rules (docs show GET with state; POST only for token return); cache eviction.
- Test endpoint behavior beyond `{payload}` in and `{payload}` out; 400 on
  an unbuilt draft is unsourced.
- Open-source SDK/CLI source was not re-read this task; E2E tasks will.

## Corrections made to the spec

1. DELETE success is 204; deploy and version deploy are 202; test is 200 with a
   `payload`; version deploy accepts `update_draft`.
2. Build status wire enum has six values; zeroauthy emits a subset (D-0053).
3. Consent: post-login runs before the consent screen; target-scope additions are shown on consent, `addScope` is not; spec order rewritten.
4. Transaction metadata limits and cache key/value rules added.
5. `canRedirect()` false cases, console log persistence limit, `modules` and
   `registry_url` handling recorded.

## Changelog

See `changelog-review.md` (https://auth0.com/changelog, reviewed 2026-10-27).

## Actions II contract review (2026-10-28)

This section extends the dated Actions I review above. Machine-readable
contracts now cover 24 operations and seven supported triggers. Task 1 freezes
contracts; later tasks supply runtime and Management API implementation.
Public documentation and open-source source review were performed by the
implementer; any live evidence is supplied separately under CLEAN_ROOM.md.

Public sources fetched successfully on 2026-10-28:

| Surface | References |
|---|---|
| Trigger scope and timing | [Catalogue](https://auth0.com/docs/customize/actions/explore-triggers), [pre-registration overview](https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/pre-user-registration-trigger), [post-registration overview](https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/post-user-registration-trigger), [password change overview](https://auth0.com/docs/customize/actions/explore-triggers/password-reset-triggers/post-change-password-trigger), [reset challenge overview](https://auth0.com/docs/customize/actions/explore-triggers/password-reset-post-challenge) |
| Pre-registration | [event](https://auth0.com/docs/customize/actions/reference/pre-user-registration/pre-user-registration-event-object), [api](https://auth0.com/docs/customize/actions/reference/pre-user-registration/pre-user-registration-api-object) |
| Post-registration | [event](https://auth0.com/docs/customize/actions/reference/post-user-registration/post-user-registration-event-object), [api](https://auth0.com/docs/customize/actions/reference/post-user-registration/post-user-registration-api-object) |
| Password change | [event](https://auth0.com/docs/customize/actions/reference/post-change-password/post-change-password-event-object), [api](https://auth0.com/docs/customize/actions/reference/post-change-password/post-change-password-api-object) |
| Reset challenge | [event](https://auth0.com/docs/customize/actions/reference/password-reset-post-challenge/password-reset-post-challenge-event-object), [api](https://auth0.com/docs/customize/actions/reference/password-reset-post-challenge/password-reset-post-challenge-api-object) |
| Custom email | [event](https://auth0.com/docs/customize/actions/reference/custom-email-provider/custom-email-provider-event-object), [api](https://auth0.com/docs/customize/actions/reference/custom-email-provider/custom-email-provider-api-object) |
| Modules/runtime | [Modules](https://auth0.com/docs/customize/actions/modules), [tutorial](https://auth0.com/docs/customize/actions/modules/write-your-first-action-module), [limitations](https://auth0.com/docs/customize/actions/limitations), [Action create schema](https://auth0.com/docs/api/management/v2/actions/post-action) |
| Module CRUD | [list](https://auth0.com/docs/api/management/v2/actions/get-action-modules), [create](https://auth0.com/docs/api/management/v2/actions/post-action-module), [get](https://auth0.com/docs/api/management/v2/actions/get-action-module), [update](https://auth0.com/docs/api/management/v2/actions/patch-action-module), [delete](https://auth0.com/docs/api/management/v2/actions/delete-action-module) |
| Module usage/versioning | [used by](https://auth0.com/docs/api/management/v2/actions/get-action-module-actions), [rollback](https://auth0.com/docs/api/management/v2/actions/post-action-module-rollback), [versions](https://auth0.com/docs/api/management/v2/actions/get-action-module-versions), [publish](https://auth0.com/docs/api/management/v2/actions/post-action-module-version), [get version](https://auth0.com/docs/api/management/v2/actions/get-action-module-version) |

The web retrieval tool could not open one reset reference and rejected the
large changelog HTML. Direct HTTPS retrieval succeeded for every reference
above and for the official full changelog text. An initially guessed reset
overview URL under `password-reset-triggers` returned 404; the catalogue links
to the successful URL listed above. No hosted login or dashboard was captured.

Facts confirmed in our words:

- Pre-registration blocks; post-registration/password-change are asynchronous
  and their outcome does not change the transaction. Pre-registration API has
  deny with a user message, metadata setters, cache and validation error;
  post-registration/password-change have cache only.
- Reset handlers are exactly `onExecutePostChallenge` and
  `onContinuePostChallenge`, in the reset overview's examples. Reset API has
  deny, two authentication challenges, three redirect methods, cache, prompt
  render and result URL. `redirect.canRedirect` is absent from this reference;
  zeroauthy retains it as a local helper (D-0054). Challenges and Forms remain
  unsupported and fail closed.
- Custom email API has cache, retry and drop. Last notification call wins;
  retry allows five retries, and reasons truncate to 1024 characters. The
  exact delay sequence and thrown-error behavior remain D-0054 choices.
- Event references contain optional fields beyond zeroauthy's current flows:
  organization, GeoIP, authentication/risk, security_context and Forms. Their
  absence is explicit local scope. Pre-registration receives a prospective
  user, post-registration an existing user, password change includes
  `last_password_reset`, and email includes the rendered notification.
- Modules have independent secrets/npm dependencies, run in the importing
  Action's runtime, cannot import another Action module, and use
  `require('actions:<name>')` and `actions.secrets`. Publishing snapshots an
  immutable numbered version. Rollback copies an older version into the draft.
  An Action explicitly pins a module version, with no automatic upgrade.
- Public schemas give module name/code bounds 255/65536 characters and immutable
  name on update; create/publish/delete succeed with 201/200/204. Duplicate
  creation and unchanged publish are 409; in-use delete/version limit are 412.
  Public used-by prose speaks of deployed Action versions; extending the
  in-use definition to drafts and retaining tombstones for old pins are local
  safety choices. Module counts and queue constraints are D-0054 defaults.

### Pinned open-source client provenance

Only publicly released, MIT-licensed sources were studied. No source was
copied or closely adapted; this is a capability/protocol review.

| Repository/version | Files inspected | Exposed support |
|---|---|---|
| [auth0/auth0-deploy-cli v9.1.0](https://github.com/auth0/auth0-deploy-cli/tree/v9.1.0) | `src/tools/auth0/handlers/actionModules.ts`, `src/tools/auth0/handlers/actions.ts`, `src/context/yaml/handlers/actionModules.ts`, `src/context/directory/handlers/actionModules.ts` | `actionModules` YAML and directory import/export, external `action-modules/<name>/code.js`, dependencies/secrets and publish state; Action references by module name/version number resolved to IDs. Publication follows draft changes with `all_changes_published:true`. Source supports the required four-cell Deploy matrix. |
| [auth0/auth0-cli v1.37.0](https://github.com/auth0/auth0-cli/tree/v1.37.0) | `internal/cli/actions_modules.go`, `internal/cli/actions_modules_versions.go`, `internal/cli/actions.go`, `internal/cli/api.go` | Native `actions modules` list/show/create/update/delete/actions; versions list/show/rollback/publish. Create/update accept code, dependencies, secrets, publish; create also API version. Actions create/update accept repeatable `--module` ID/version-ID pairs. Generic `api` remains an alternative. |
| [auth0/node-auth0 v7.4.0](https://github.com/auth0/node-auth0/tree/v7.4.0) | `src/management/api/resources/actions/client/Client.ts`, `src/management/api/resources/actions/resources/modules/client/Client.ts`, `src/management/api/resources/actions/resources/modules/resources/versions/client/Client.ts` | `actions.modules.{list,create,get,update,delete,listActions,rollback}` and `actions.modules.versions.{list,create,get}`: all ten module operations, including 409/412 error mappings. |

The current tutorial says auth0-cli has no module commands/flag; pinned
1.37.0 source exposes both. We record this discrepancy and use documented
Management API payloads; no undocumented server behavior is inferred from the
client's stricter lowercase module-name validation. Source capability does not
prove a local or upstream client round-trip; those are later verification.

### Live observation availability

Observer credentials were detected through `fish -c` using a presence-only
check; no values were printed or consumed by the implementer. The controller
assigned a separate observer. The final sanitized observation disposition is
recorded below; until an observation succeeds, spec §2 defaults remain local
D-0054 decisions rather than claims of Auth0 parity.

The separate observer completed the 2026-10-28 attempt using documented
Management API endpoints with auth0-cli and sufficient scopes. Initial and
final reads of pre-registration, post-registration and post-change-password
bindings were empty. Isolated client/connection creation succeeded, but Action
creation returned HTTP 400 (`validation` / `invalid_request`) for explicit
`node22` with both v1 and v2; the exact validation cause was not established.
No Action was created/deployed/bound, and no binding write occurred. Cleanup
of only the newly created client/connection resources succeeded; original
binding state was confirmed unchanged. Credentials stayed with the observer;
no credentials, tenant/resource identifiers or personal data enter these notes.

| Spec §2 item | Live result |
|---|---|
| 1: Management API creation fires registration | **Unavailable:** no bound observer Action; no execution conclusion. Default remains signup only. |
| 2: Password change sources | **Unavailable:** no bound observer Action; no password-change execution observed. Default source matrix remains D-0054. |
| 3: Signup deny/validation response | **Unavailable:** no deny/validation Action; no signup error body observed. Default 400 body remains D-0054. |

This is a setup failure, not a passing behavior test or an observation of the
proposed default behavior. Public rollback reference supports draft-only
replacement (§2 item 6); thrown-email-error retries and module count limits
(items 4–5) remain local defaults, with no live confirmation.

The successful documented trigger catalogue read reported `v2` current and
`v1` deprecated for pre-/post-user-registration and post-change-password, and
listed `node22`. Their inventory `version` records that observed metadata;
other trigger versions remain unspecified here. This does not demonstrate
execution, deployment, or wire-error parity. Task 1 does not change existing
runtime/Management API trigger-version handling.
