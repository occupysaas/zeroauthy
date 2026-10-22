# Management API attack protection, user blocks and IP anomalies — A1–A6

- Research/observation: 2026-10-22 UTC; separate observer, documented API only, requests paced >=1 second.
- Credential exchange succeeded. All required tenant/attack/user/anomaly scopes were granted; no scope-isolated denial experiments were performed. No paid-feature denial was encountered on GET. Successful reads do not prove paid runtime entitlements.
- Only field names/types, nonidentifying policy values, statuses and short error identifiers are retained. No dashboard/hosted-page inspection, credential output, load/fuzz traffic or proprietary assets.

## Reference operations and scopes (A1/A4)

| Method/path | Scope | Reference page | Success |
|---|---|---|---|
| GET `/api/v2/attack-protection/bot-detection` | `read:attack_protection` | https://auth0.com/docs/api/management/v2/attack-protection/get-bot-detection | 200 object |
| GET `/api/v2/attack-protection/breached-password-detection` | `read:attack_protection` | https://auth0.com/docs/api/management/v2/attack-protection/get-breached-password-detection | 200 object |
| GET `/api/v2/attack-protection/brute-force-protection` | `read:attack_protection` | https://auth0.com/docs/api/management/v2/attack-protection/get-brute-force-protection | 200 object |
| GET `/api/v2/attack-protection/captcha` | `read:attack_protection` | https://auth0.com/docs/api/management/v2/attack-protection/get-captcha | 200 object |
| GET `/api/v2/attack-protection/suspicious-ip-throttling` | `read:attack_protection` | https://auth0.com/docs/api/management/v2/attack-protection/get-suspicious-ip-throttling | 200 object |
| PATCH `/api/v2/attack-protection/bot-detection` | `update:attack_protection` | https://auth0.com/docs/api/management/v2/attack-protection/patch-bot-detection | 200 object |
| PATCH `/api/v2/attack-protection/breached-password-detection` | `update:attack_protection` | https://auth0.com/docs/api/management/v2/attack-protection/patch-breached-password-detection | 200 object |
| PATCH `/api/v2/attack-protection/brute-force-protection` | `update:attack_protection` | https://auth0.com/docs/api/management/v2/attack-protection/patch-brute-force-protection | 200 object |
| PATCH `/api/v2/attack-protection/captcha` | `update:attack_protection` | https://auth0.com/docs/api/management/v2/attack-protection/patch-captcha | 200 object |
| PATCH `/api/v2/attack-protection/suspicious-ip-throttling` | `update:attack_protection` | https://auth0.com/docs/api/management/v2/attack-protection/patch-suspicious-ip-throttling | 200 object |
| DELETE `/api/v2/anomaly/blocks/ips/{id}` | `delete:anomaly_blocks` | https://auth0.com/docs/api/management/v2/anomaly/delete-ips-by-id | 204 empty |
| GET `/api/v2/anomaly/blocks/ips/{id}` | `read:anomaly_blocks` | https://auth0.com/docs/api/management/v2/anomaly/get-ips-by-id | 200 empty when blocked |
| DELETE `/api/v2/user-blocks/{id}` | `update:users` | https://auth0.com/docs/api/management/v2/user-blocks/delete-user-blocks-by-id | 204 empty |
| DELETE `/api/v2/user-blocks` | `update:users` | https://auth0.com/docs/api/management/v2/user-blocks/delete-user-blocks | 204 empty |
| GET `/api/v2/user-blocks/{id}` | `read:users` | https://auth0.com/docs/api/management/v2/user-blocks/get-user-blocks-by-id | 200 object |
| GET `/api/v2/user-blocks` | `read:users` | https://auth0.com/docs/api/management/v2/user-blocks/get-user-blocks | 200 object |

Use structured OAuth security scopes, not the anomaly reference's stale prose `get:anomaly_block` / `delete:anomaly_block` wording. Common documented failures are 401, 403 and 429. Validation failures use 400 where specified; user-ID lookup/delete also has 404. Brute/breach/suspicious GET does not document 404; bot/CAPTCHA GET/PATCH does.

## A1: defaults, validation, partial patches

Observed tenant policy (not necessarily new-tenant defaults):

| Feature | Observed GET facts |
|---|---|
| Brute force | enabled true; shields block + user_notification; mode count_per_identifier_and_ip; max_attempts 10; form_submission_mode auto; empty allowlist |
| Suspicious IP | enabled true; shields admin_notification + block; empty allowlist; pre-login capacity 100/rate 864000; pre-user-registration 50/1200; pre-custom-token-exchange 10/600000 |
| Breach | disabled; empty shields/frequencies; method standard; empty shields in both nested stages |
| Bot | password/passwordless/reset policies never; sensitivity medium; monitoring false; empty allowlist |
| CAPTCHA | active auth_challenge; all seven provider objects present; secret/API-key fields absent |

Same-value partial PATCHes of brute threshold, breach method, bot sensitivity and suspicious-IP nested pre-login capacity each returned 200 and the exact original policy. Omitted nested siblings were preserved in those responses. This establishes those specific omission cases, not arbitrary clear semantics. All final GET snapshots matched originals. CAPTCHA was read only because GET cannot recover a saved credential for restoration.

Documented defaults differ from this existing tenant: suspicious-IP schema defaults are pre-login 100/864000, registration 50/1728000, custom-token-exchange 10/8640000. Breach `enabled` schema annotation is true, but the milestone's explicit safe local default is false until a checker is configured (D-0045), matching this observed tenant rather than claiming universal Auth0 default. Brute threshold default is 10, range 1–100; mode defaults count_per_identifier_and_ip. Bot sensitivity medium is described in the behavior guide; “never” and false above are existing-tenant observations, adopted local defaults. Local CAPTCHA default is auth_challenge stored/unavailable; no challenge is required while policies are never.

Patch fallback for untested cases: validate the full feature-specific schema, recursively merge objects, replace arrays (including empty shields/allowlists), preserve omitted fields, refuse null unless schema allows it. Unknown properties fail 400 invalid_body on closed objects. Monitoring is enabled protection without a blocking shield, or bot monitoring_mode_enabled; do not apply every feature's shield enum everywhere. Allowlist scope/limits follow the schemas below (the suspicious-IP behavior guide separately states 100 entries). All provider credential properties are write-only and encrypted locally; GET and PATCH responses never contain them.

The following tables freeze nested schemas without copying documentation prose. Required children apply when the containing provider object is supplied. The schemas, rather than a generic arbitrary JSON object, own validation.

### brute-force-protection

Root constraints: `{"type":"object","additionalProperties":false}`.

| PATCH path | Constraints | Presence |
|---|---|---|
| `enabled` | `{"type":"boolean"}` | optional |
| `shields` | `{"type":"array","items":{"type":"string","enum":["block","user_notification"]}}` | optional |
| `allowlist` | `{"type":"array","items":{"type":"string","anyOf":[{"type":"string","format":"ipv4"},{"type":"string","format":"cidr"},{"type":"string","format":"ipv6"},{"type":"string","format":"ipv6_cidr"}]}}` | optional |
| `mode` | `{"type":"string","default":"count_per_identifier_and_ip","enum":["count_per_identifier_and_ip","count_per_identifier"]}` | optional |
| `max_attempts` | `{"type":"integer","default":10,"minimum":1,"maximum":100}` | optional |
| `form_submission_mode` | `{"type":"string","enum":["auto","manual"]}` | optional |

### suspicious-ip-throttling

Root constraints: `{"type":"object","additionalProperties":false}`.

| PATCH path | Constraints | Presence |
|---|---|---|
| `enabled` | `{"type":"boolean"}` | optional |
| `shields` | `{"type":"array","items":{"type":"string","enum":["block","admin_notification"]}}` | optional |
| `allowlist` | `{"type":"array","items":{"type":"string","anyOf":[{"type":"string","format":"ipv4"},{"type":"string","format":"cidr"},{"type":"string","format":"ipv6"},{"type":"string","format":"ipv6_cidr"}]}}` | optional |
| `stage` | `{"type":"object","additionalProperties":false}` | optional |
| `stage.pre-login` | `{"type":"object","additionalProperties":false}` | optional |
| `stage.pre-login.max_attempts` | `{"type":"integer","default":100,"minimum":1,"maximum":2500}` | optional |
| `stage.pre-login.rate` | `{"type":"integer","default":864000,"minimum":34560,"maximum":86400000}` | optional |
| `stage.pre-user-registration` | `{"type":"object","additionalProperties":false}` | optional |
| `stage.pre-user-registration.max_attempts` | `{"type":"integer","default":50,"minimum":1,"maximum":72000}` | optional |
| `stage.pre-user-registration.rate` | `{"type":"integer","default":1728000,"minimum":1200,"maximum":86400000}` | optional |
| `stage.pre-custom-token-exchange` | `{"type":"object","additionalProperties":false}` | optional |
| `stage.pre-custom-token-exchange.max_attempts` | `{"type":"integer","default":10,"minimum":1,"maximum":2500}` | optional |
| `stage.pre-custom-token-exchange.rate` | `{"type":"integer","default":8640000,"minimum":34560,"maximum":86400000}` | optional |

### breached-password-detection

Root constraints: `{"type":"object","additionalProperties":false}`.

| PATCH path | Constraints | Presence |
|---|---|---|
| `enabled` | `{"type":"boolean","default":true}` | optional |
| `shields` | `{"type":"array","items":{"type":"string","enum":["block","user_notification","admin_notification"]}}` | optional |
| `admin_notification_frequency` | `{"type":"array","items":{"type":"string","enum":["immediately","daily","weekly","monthly"]}}` | optional |
| `method` | `{"type":"string","default":"standard","enum":["standard","enhanced"]}` | optional |
| `stage` | `{"type":"object","additionalProperties":false}` | optional |
| `stage.pre-user-registration` | `{"type":"object","additionalProperties":false}` | optional |
| `stage.pre-user-registration.shields` | `{"type":"array","items":{"type":"string","enum":["block","admin_notification"]}}` | optional |
| `stage.pre-change-password` | `{"type":"object","additionalProperties":false}` | optional |
| `stage.pre-change-password.shields` | `{"type":"array","items":{"type":"string","enum":["block","admin_notification"]}}` | optional |

### bot-detection

Root constraints: `{"type":"object","additionalProperties":false}`.

| PATCH path | Constraints | Presence |
|---|---|---|
| `bot_detection_level` | `{"type":"string","enum":["low","medium","high"]}` | optional |
| `challenge_password_policy` | `{"type":"string","enum":["never","when_risky","always"]}` | optional |
| `challenge_passwordless_policy` | `{"type":"string","enum":["never","when_risky","always"]}` | optional |
| `challenge_password_reset_policy` | `{"type":"string","enum":["never","when_risky","always"]}` | optional |
| `allowlist` | `{"type":"array","items":{"type":"string","oneOf":[{"type":"string","format":"ipv4"},{"type":"string","format":"ipv6"},{"type":"string","format":"cidr"},{"type":"string","format":"ipv6_cidr"}]}}` | optional |
| `monitoring_mode_enabled` | `{"type":"boolean"}` | optional |

### captcha

Root constraints: `{"type":"object","additionalProperties":false}`.

| PATCH path | Constraints | Presence |
|---|---|---|
| `active_provider_id` | `{"type":"string","maxLength":36,"enum":["arkose","auth_challenge","friendly_captcha","hcaptcha","recaptcha_v2","recaptcha_enterprise","simple_captcha"]}` | optional |
| `arkose` | `{"type":"object","additionalProperties":false,"required":["site_key","secret"]}` | optional |
| `arkose.site_key` | `{"type":"string","maxLength":100}` | required within parent |
| `arkose.secret` | `{"type":"string","maxLength":100}` | required within parent |
| `arkose.client_subdomain` | `{"type":"string","maxLength":100}` | optional |
| `arkose.verify_subdomain` | `{"type":"string","maxLength":100}` | optional |
| `arkose.fail_open` | `{"type":"boolean"}` | optional |
| `auth_challenge` | `{"type":"object","additionalProperties":false,"required":["fail_open"]}` | optional |
| `auth_challenge.fail_open` | `{"type":"boolean"}` | required within parent |
| `hcaptcha` | `{"type":"object","additionalProperties":false,"required":["site_key","secret"]}` | optional |
| `hcaptcha.site_key` | `{"type":"string","maxLength":100}` | required within parent |
| `hcaptcha.secret` | `{"type":"string","maxLength":100}` | required within parent |
| `friendly_captcha` | `{"type":"object","additionalProperties":false,"required":["site_key","secret"]}` | optional |
| `friendly_captcha.site_key` | `{"type":"string","maxLength":100}` | required within parent |
| `friendly_captcha.secret` | `{"type":"string","maxLength":100}` | required within parent |
| `recaptcha_enterprise` | `{"type":"object","additionalProperties":false,"required":["site_key","api_key","project_id"]}` | optional |
| `recaptcha_enterprise.site_key` | `{"type":"string","maxLength":100}` | required within parent |
| `recaptcha_enterprise.api_key` | `{"type":"string","maxLength":100}` | required within parent |
| `recaptcha_enterprise.project_id` | `{"type":"string","maxLength":100}` | required within parent |
| `recaptcha_v2` | `{"type":"object","additionalProperties":false,"required":["site_key","secret"]}` | optional |
| `recaptcha_v2.site_key` | `{"type":"string","maxLength":100}` | required within parent |
| `recaptcha_v2.secret` | `{"type":"string","maxLength":100}` | required within parent |
| `simple_captcha` | `{"type":"object","additionalProperties":true}` | optional |

## A2: brute-force runtime gate

Public behavior source: https://auth0.com/docs/secure/attack-protection/brute-force-protection . It defines failed attempts by identifier/IP, optional identifier-only account lockout, threshold 1–100 and 30 days from the last failed attempt as a block removal event. Raising the threshold, administrative unblock, user unblock email and successful password change are other removal events. Tenant-administrator `User.Blocked` is separate. Connection `brute_force_protection: false` bypasses this feature, not independent protection. Empty response shields monitor instead of denying. Notifications are deferred to Plan 21.

No runtime threshold was triggered. A temporary database connection was created (201); creating its temporary user returned 400, so no user, login or password test followed. The temporary connection was deleted in cleanup (202). This is a setup gap, **not** proof of unavailable user scopes or paid entitlement. No user/connection identifier is retained. Live connection-scope/normalization/reset claims therefore remain unobserved.

Explicit local fallback for Tasks 4/6/7: key by tenant + stable connection ID + resolved normalized identifier, plus canonical IP in count_per_identifier_and_ip. Identifier-only aggregates IPs within that connection. Normalize known email/username aliases through existing user resolution, retain a stable normalized key for nonexistent identifiers, never cross tenants. Successful password authentication resets its own unblocked failure bucket; a different connection or linked social success does not. Threshold N permits N failed credential evaluations and denies the next attempt, including correct credentials while blocked. Persist blocks until 30 days since the last qualifying failure; threshold increase invalidates matching brute generations. Lowering threshold does not erase failures. Other policy-edit reset details remain local; stale receipts must never revive blocks. Password change clears corresponding database-identity state; all linked applicable identities must change/clear before all blocks disappear. Administrator password replacement clears only that identity's automatic state and leaves administrative blocked untouched. These connection/alias/concurrency choices are local deterministic fallbacks, not observed parity.

## A3: suspicious-IP units, refill and expiry gate

Sources: the GET/PATCH reference above and https://auth0.com/docs/secure/attack-protection/suspicious-ip-throttling . API `rate` is an **interval in milliseconds per new attempt**, not attempts/second or attempts/day. Example: 864000 gives one new attempt every 14.4 minutes. Schema defaults/bounds are in the table; the narrative's signup-per-minute/per-day explanations are inconsistent, so the operation schema's explicit interval wins. Do not replace this with a fixed window or multiply brute threshold.

Local executable algorithm: independent per-tenant canonical-IP token buckets for login and registration; capacity=max_attempts, start full, replenish one token per rate milliseconds up to capacity. Retain fractional elapsed refill time without truncating away credit. Login counts valid failed password evaluations; success refunds its reservation without resetting other failures; valid registration submissions consume regardless of outcome. Structurally malformed requests do not count (behavior guide). custom-token-exchange round-trips but is inert until Plan 35. A request blocked by another protection refunds any reserved suspicious-IP budget. No long-running transaction spans credential checks.

No threshold/refill/expiry experiment was run; full-recovery cleanup at capacity × rate after last activity is the local state-retention policy, not a documented fixed lockout. A bucket is currently blocked when it has no available whole token; it stops blocking once one token refills. IP anomaly GET is 200 with no documented body for any exhausted suspicious-IP stage, otherwise 404; use empty successful body as documented fallback. DELETE clears the IP's suspicious-IP stages (local stage selection), preserving brute/user/reset-mail state. Observed GET of a reserved documentation IPv4 address was 404; DELETE was 204; malformed IP GET was 400 invalid_uri. IPv4 and IPv6 are admitted by the current reference.

## A4: user blocks gate

GET response schema is `{blocked_for: [...]}`. Each item may contain string `identifier`, string `ip` and string `connection`; `ip` may be absent for identifier-only lockout. No pagination/list-all-user semantics. A known user is resolved to relevant identities, with connection **name** in public rows and stable IDs internally. The linked-identity union and normalized-alias behavior are local fallbacks, not observed live.

Observed: nonexistent identifier GET 200 `{blocked_for:[]}`; its DELETE 204 empty. Missing identifier GET 400 invalid_query_string. Unknown well-formed user-ID GET and DELETE both **404 inexistent_user**. Do not make unknown user-ID delete 204. Default `consider_brute_force_enablement` is not specified by the schema; local fallback false exposes saved live blocks even when policy is disabled; true filters according to tenant/connection brute enablement. Invalid boolean query syntax is 400 invalid_query_string. Malformed user ID uses existing 400 invalid_uri rules (unobserved here). Deleted users answer unknown-user status; invalid IP is distinct from unknown user.

Deleting automatic blocks leaves `User.Blocked`, sessions and tokens intact (public separation plus local preservation rule). The intended temporary-user administrative-block experiment could not run because user creation failed; this preservation is not claimed as a new observation. Unblock deletes applicable brute generations atomically; linked identities use the A2 local scope. Expired entries are excluded; no cross-tenant clearing.

## A5: breached-password gate

Source: https://auth0.com/docs/secure/attack-protection/breached-password-detection . Login shields allow block/user_notification/admin_notification; registration and password-change stages permit block/admin_notification only. Frequencies immediately/daily/weekly/monthly; methods standard/enhanced. Enhanced designates Credential Guard, not a second locally reproducible corpus. Auth0's test passwords/corpus must not become a fake local checker.

No password or breach-runtime requests were made. Error and authenticated Management API behavior not established by the reference remains local fallback: only evaluate a proved login password; use 401 `password_leaked` for direct login refusal and 400 `password_leaked` for signup/password completion, preserving existing endpoint error envelopes. These selected statuses/codes are local compatibility fixtures, not observed Authentication API responses. Management API create/update plaintext password fields are checked by the corresponding registration/change stage before writing; local Management envelope is 400 invalid_body on confirmed breach. Hash imports cannot be checked until first verified plaintext login. No notification delivery before Plan 21.

Checker unavailable or off is unavailable, not clean: blocking stage fails temporarily without user/password/ticket mutation; monitoring can proceed with a redacted event. Mode off is the server default; outbound range lookup requires explicit server configuration. The checker corpus is local and does not claim enhanced Credential Guard parity. Exact upstream per-endpoint leak error parity remains an acknowledged limitation; do not label fallback assertions observed. Range implementation source: https://haveibeenpwned.com/API/v3#PwnedPasswords .

## A6: direct challenge and credential gate

Source: https://auth0.com/docs/secure/attack-protection/bot-detection (Flow limitations), and https://auth0.com/docs/secure/attack-protection/bot-detection/configure-captcha . ROPG has no interactive CAPTCHA completion protocol: `requires_verification` directs callers to a web login. **Do not invent required CAPTCHA parameters or an inline proof protocol for `/oauth/token`.** For direct signup/reset APIs where no documented supported completion mechanism is established, return the existing endpoint's `requires_verification` error on a required challenge; proof verification belongs to the local hosted transaction/reset form. Local status selection is 401 for direct refusal; upstream signup/reset statuses were not observed. There are no challenge endpoint probes or hosted-page captures in this work.

Provider GET/PATCH response schemas omit `secret` and Enterprise `api_key`; observed GET also omitted all credentials. The observed provider objects exposed only site_key and, where applicable, project_id/client_subdomain/verify_subdomain/fail_open. Omitted provider objects preserve saved configuration. When a provider object is supplied, require every child in its request schema, including secret/api_key: a partial provider object lacking its credential is not a supported masked-secret PATCH. Never echo a masked placeholder as a credential. Local clear fallback: an explicit empty credential in a structurally complete provider object clears it; refusing activation of an external provider without nonempty required credentials is local validation, not observed upstream behavior. Null is not a provider reset operator. Console forms retain no saved secret: leave the provider object omitted unless replacing it, and require new credentials when editing site/project keys. Credential writes/clears were not observed because readback cannot restore an original secret.

No vendor account credentials were available or requested, so actual third-party verification was not attempted. Public vendor protocols reviewed:

| Provider | Verification contract and source |
|---|---|
| recaptcha_v2 | POST form `secret`, `response`, optional `remoteip` to `https://www.google.com/recaptcha/api/siteverify`; require success true and expected hostname. Tokens expire in two minutes and are single-use. https://developers.google.com/recaptcha/docs/verify |
| recaptcha_enterprise | POST JSON event.token + event.siteKey to `https://recaptchaenterprise.googleapis.com/v1/projects/{project_id}/assessments?key={api_key}`; API-key authentication is explicitly supported for assessment create. Require tokenProperties.valid, expected hostname/site and expected action when used. Never send API key as a bearer token or to legacy siteverify. https://cloud.google.com/recaptcha/docs/authentication and https://cloud.google.com/recaptcha/docs/create-assessment-website |
| hcaptcha | URL-encoded POST secret/response and configured sitekey to `https://api.hcaptcha.com/siteverify`; remoteip recommended. Require success true; supplied sitekey binds site ownership (hostname alone is not authentication). https://docs.hcaptcha.com/ and https://docs.hcaptcha.com/api/ |
| friendly_captcha | **Local version choice: v1**. POST solution/secret/sitekey to `https://api.friendlycaptcha.com/api/v1/siteverify`; require success true; sitekey binds the puzzle. https://developer.friendlycaptcha.com/docs/v1/api/ . Auth0's configuration page links the older Friendly installation site but does not explicitly freeze a verification version, so this is not an observed Auth0 version. |

Friendly v2 is a different protocol: `https://global.frcapi.com/api/v2/captcha/siteverify`, response/sitekey plus X-API-Key, documented at https://developer.friendlycaptcha.com/docs/v2/api/siteverify . Do not combine v2 widget responses with v1 secret/solution verification. Supporting v2 needs an explicit internal version choice and matching widget/fixtures, with no invented public field. V1 is frozen for this milestone. Neither Friendly version permits accepting HTTP 200 alone as success. Vendor availability recommendations may favor fail-open; this server's required-challenge fail-closed policy is an explicit local difference.

Arkose/auth_challenge/simple_captcha are stored but have no verifier in Plan 19; required challenge fails closed with localized actionable error. Provider fail_open is stored-only for those unavailable verifiers. Bot local risk is an explicit approximation: preceding 15 minutes of failed qualifying operations per tenant/IP; low=10, medium=5, high=1, independent of blocking settings. Monitoring never denies. No vendor intelligence parity is claimed. Apply a two-second verifier deadline, bounded response body, fixed vendor HTTPS endpoint and no redirects; validate provider-specific binding before consuming a globally shared opaque proof hash. A5/A6 availability and local risk choices are D-0045.

## Pinned clients and validation ownership

Current pins remain auth0-cli v1.37.0 (`tests/e2e/run-m3.sh`) and node-auth0 7.4.0 (`tests/e2e/package.json`/lock). No dependencies were upgraded. Installed SDK methods were inspected without network calls: `tenants.settings.get/update`, `attackProtection.{bruteForceProtection,suspiciousIpThrottling,breachedPasswordDetection,botDetection,captcha}.get/update`, `userBlocks.listByIdentifier/deleteByIdentifier/list/delete`, `anomaly.blocks.checkIp/unblockIp`. SDK provenance: https://github.com/auth0/node-auth0/tree/v7.4.0 ; MIT license already present with the package. This confirms method names, not behavior or missing wire fields.

CLI public source v1.37.0: https://github.com/auth0/auth0-cli/blob/v1.37.0/internal/cli/tenant_settings.go , `attack_protection.go`, `attack_protection_bot_detection.go`, `api.go` (same directory). Commands: `tenant-settings show`, `tenant-settings update`, `tenant-settings set/unset`; `protection` (aliases attack-protection/ap), per-feature show/update; generic `api <method> <url-path>` covers missing dedicated operations. The 2026-10-21 changelog announces newer Agent Mode; it does not change this pin's interface.

Task 2 asserts schema enums/bounds/merge and provider required children; Task 3 secret storage/read omission; Tasks 4/6 A2–A3 units/expiry/generations; Task 7 A4 status/scope/identity boundaries; Task 8 A5 unavailability/stages; Task 9 A6 provider HTTP protocols and direct requires_verification with no invented proof transport. Task 11 asserts actual pinned methods. Broader source/parity regressions are the primary implementer's responsibility; the observer did not rerun baseline tests.

## Cleanup and limitations

Snapshot/readback equality was true for all five attack feature objects and the tenant after same-value writes. No credential was changed. The throwaway connection was deleted in finally cleanup (202); a subsequent documented connection-list GET returned 200 and confirmed zero remaining connections with this observer run prefix. No temporary user was successfully created. Documentation-only unknown-ID/identifier/IP deletes were idempotent where described. No remaining owned remote artifact is known. Runtime threshold, linked-account, breach refusal, active-provider credential-validation and vendor verification were not observed; each has a marked documented/local fallback above. No long-lived secrets or personal data were written to the repository or these notes.
