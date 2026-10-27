# Actions I: public contract review

Date: 2026-10-27. Evidence: public documentation and the public Management API
reference only. **No live Auth0 tenant observation was performed and no observer
session exists; every live-behavior item below is "unavailable".** Machine
readable form: `internal/actionsrules/inventory.json`.

## Management operations (14)

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
- Scopes: target-scope edits are visible to later Actions and are evaluated
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

The public changelog was not re-fetched for this task (see
`changelog-review.md`); no later coverage is claimed.
