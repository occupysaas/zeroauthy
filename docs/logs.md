# Tenant logs, streams and statistics

Tenant logs record authentication outcomes, Management writes, protection
choices and Action failures. Open **Logs** in the console to search a tenant,
inspect one event or follow new events. **Actions logs** lists executions;
**Log streams** configures outbound delivery and shows delivery health.
Home shows daily activity and active users. These pages require a current
operator grant for the selected tenant.

The contract is [api/management.yaml](../api/management.yaml), with local
choices in [D-0057](compat/decisions.md#d-0057--tenant-logs-streams-and-statistics-contract-2026-10-30).
The [inventory](../internal/logrules/inventory.json) owns codes, categories,
fields and limits. This guide describes the implementation; Plan 31 remains
in acceptance until the [implementation record](superpowers/2026-10-30-plan-31-implementation-record.md)
records the full regression and review. The prior CLI selector failure has a
scoped compatibility fix; client acceptance must still be rerun and recorded.

## Troubleshoot an Action denial

1. Bind and deploy a post-login Action that calls `console.log` and then
   `api.access.deny('Blocked by policy')`. Sign in as a normal application user.
2. In a separate operator session select that tenant, open **Logs**, clear
   filters and enable **Live**. The failed login appears as `f` after the
   settlement delay. Open its detail to read the scrubbed description.
3. Follow the execution ID in `details.actions.executions`. The execution
   shows the immutable Action ID/name, timings, console lines and a separate
   **Denial reason**. An explicit denial is a normal Action outcome; thrown
   errors have a separate error ID/message. Stored denial display text is
   masked before bounding to 512 characters. Both text and console lines are
   escaped by the console. Older executions or peers may omit denial metadata.
4. Open the Action from the execution, repair the code, save/build/deploy,
   then start a fresh login. The completed authorization emits `s` with its
   execution link. Password-grant success instead emits `sepft`; silent
   authorization emits `ssa`.

The local operator endpoints
`GET /api/system/tenants/{tenant}/actions/executions[/{id}]` expose immutable
console lines and optional `denial_reason`; list accepts `trigger`, immutable
`action`, `after` and `take` (maximum 100). They require `read:actions` and
the path tenant grant. The public
`GET /api/v2/actions/executions/{id}` keeps its existing response shape,
without console or denial display metadata. Draft test IDs are ephemeral and
cannot be looked up. See [Actions](actions.md).

Live polls every two seconds and removes duplicate IDs. Filters disable Live
because checkpoint mode deliberately ignores search criteria. Failure-only
view examines at most 1,000 newest events with at most ten requests; it is a
bounded window, not an unlimited historical failure count. Clear filters to
resume Live, or narrow the date/search range for historical work.

## Read logs and statistics

| Operation | Required scopes |
| --- | --- |
| `GET /api/v2/logs`, `GET /api/v2/logs/{id}` | `read:logs` |
| `GET /api/v2/users/{id}/logs` | `read:logs` and `read:logs_users` |
| `GET /api/v2/log-streams[/{id}]` | `read:log_streams` |
| `POST /api/v2/log-streams` | `create:log_streams` |
| `PATCH /api/v2/log-streams/{id}` | `update:log_streams` |
| `DELETE /api/v2/log-streams/{id}` | `delete:log_streams` |
| `GET /api/v2/stats/daily`, `GET /api/v2/stats/active-users` | `read:stats` |

All reads and IDs are tenant scoped; a foreign or malformed lookup ID is 404.
A missing/deleted user returns 404 on its user-log route; its retained events
can still be found through the global tenant-log route. Missing Logs v1 plugin
support returns `501 logs_unavailable` on logs/streams/stats and these local
execution diagnostics. Other existing plugin functionality keeps working.

Page mode accepts `q`, `page`, `per_page`, date sort, field projection and
`include_totals`. Global tenant-log pages also accept exactly one
`search_engine=v3` selector, using the same bounded query subset; unsupported
values and duplicates return 400. This selector does not extend the user-log
route or imply full upstream search-engine parity. Default page size is 50, maximum 100; pages cannot extend
past 1,000 results, and totals are capped there. With totals, the envelope is
`{logs,start,limit,length,total}`; otherwise it is an array. Projection can
omit fields. A full GET-by-ID retains the complete event shape.

For example, `q=type:f AND user_id:"auth0|123"` selects failed logins for
one user. The bounded Lucene subset supports AND/OR/NOT, parentheses, quoted
phrases, trailing wildcards and date ranges. `log_id` supports ranges with
56-digit decimal bounds. Leading/infix wildcards, regex, fuzzy matching,
unknown fields and `.raw` are rejected. Queries are limited to 4,000 bytes,
1,000 characters, 16 nesting levels and five terms. Supported fields are
listed in the inventory. Log IDs are opaque 56-digit strings; `_id` is an
optional authoritative alias of `log_id`, subject to projection.

For checkpoint reads use `from=<last log_id>&take=100`, then keep the last
returned ID. `from` overrides every parameter other than `take`, including
`q`, sort, projection and totals. `take` alone selects recent settled events.
Default take is 50; maximum is 100. Results ascend by stored sequence, which
can have gaps and need not follow event date. A well-formed checkpoint need
not still exist in retention. Invalid cursor/take returns 400. Checkpoint
and stream reads expose commits at least two seconds old; SQL also serializes
sequence assignment through commit so a late lower sequence is not skipped.
Page reads have no settlement delay.

Daily bounds are inclusive `YYYYMMDD`, defaulting independently to a seven-day
UTC window including today, with a 366-day maximum and zero-filled missing
days. `date` is midnight UTC. `s`, `ssa` and `sepft` increment logins, `ss`
increments signups, and the breach codes increment leaked passwords. A flow
records its matching login success once; code/refresh exchanges do not add
another login. Active users is a bare integer based on existing users'
successful `last_login` within 30 days. Daily counters survive log retention;
active-user counts are not reconstructed from retained log rows.

## Storage, retention and request behavior

```yaml
logs:
  retention: 720h
  queue_size: 10000
  streams:
    allow_insecure_http: false
    allow_private_networks: false
```

Retention is deployment wide: default 30 days, minimum 24 hours. An hourly
sweeper deletes expired events in bounded batches under a fenced shared lease.
Tenant deletion removes its logs, streams and daily counters. Action executions
and their console lines retain the existing ten-day retention, independently
of log retention. An event can therefore outlive the execution it links to.
The memory store retains at most 10,000 events per tenant and is lost on
restart; SQL/shared plugins provide persistence.

Recording uses a process-local queue of 10,000 events by default. Queue
admission does not wait for a database write or make authentication fail.
The writer batches at most 100 events, normally after at most 250 ms; event
and daily-stat writes commit together. Queue overflow, storage failure or
shutdown admission can drop events. Failed writes are not retried by the
recorder. The recorder's dropped counter records these losses and a safe
warning is rate limited to once a minute. Accepted requests therefore do not
prove that every log or daily increment was persisted. Stream retries apply
to stored events, not to dropped queue entries.

## Privacy boundaries

Sources allowlist safe body properties; unknown properties and arbitrary
metadata/scripts/templates/provider configuration are hidden. The recursive
scrubber checks original property names, at any depth, including JSON strings,
for password, passwd, pwd, secret, token, authorization, API key, private key,
credential, OTP and recovery-code names (ignoring case, `_`, `-` and `.`).
Their values become `[REDACTED]`. Dynamic names and known credential values
are masked too, including nonempty short credentials and encoded forms.
Scrubbing happens before capture truncation and before persistence, stream
payload construction, console responses and diagnostic output. Configured
Action/module values may retain the existing solid-block mask style.

Already-opened Action/module credentials are shared only within the request's
bounded outcome trace: at most 256 distinct values and 64 KiB. Saturation
clears that trace and drops subsequent source events for the request rather
than recording with an incomplete mask. These privacy drops occur before
queue admission and do not increment the recorder queue-drop counter.

A custom-database runner retains the union of credentials needed for its
process diagnostics, bounded to 256 distinct values, 64 KiB and 60 seconds.
Hitting any bound permanently mutes captured console/stderr for that process
and clears its retained masks until process retirement. Script business
responses continue normally. This deliberately trades diagnostic availability
for privacy; it is not an unbounded credential history.

Console capture is bounded to 64 KiB per Action result including a truncation
marker. Display metadata is separate from business commands and never changes
claims, metadata or redirect values. Arbitrary secrets freshly fetched by user
code are not automatically known free-text credentials: do not print them.
IP, user agent and user identity are personal data; only present trusted
signals are recorded. No GeoIP data or invented location/security signals are
added.

Automatic first-operator bootstrap delivers its one-hour setup link in a unique
0600 file in the server host's temporary directory. Server logs contain only the
`setup_file` path, operator email and validity. This private credential-delivery
file is separate from logging sinks: read it on the host and delete it after use.
Server shutdown preserves it so delivery remains possible. Later starts against
the same persistent operator create no new file. The explicit `admin create`
CLI stdout link and authenticated operator-invitation response remain private
delivery channels; do not forward them into logging systems.

## Streams and delivery

Create an `http`, `datadog`, `splunk`, `sumo`, `segment` or `mixpanel` stream
in the console or API. `eventbridge` and `eventgrid` configurations are stored
permanently suspended and are never delivered. Vendor mappings are local
adapters, not claims of identical private Auth0 delivery behavior.

HTTP defaults to JSONLINES; JSONARRAY sends one array, and JSONOBJECT sends
one request per event. Every HTTP item is `{log_id,data}`. An empty category
filter means all events; filters match inventory categories. PII processing
applies only to outgoing copies, supports recursive field masking or xxhash
hashing, and leaves stored events unchanged. Default PII method/algorithm are
mask/xxhash. Authorization, entire custom-header arrays and Sumo source URLs
are sealed at rest and read back as the marker. Omitted PATCH credentials
preserve them; a marker preserves an existing secret, but is not a new secret.

Creation returns 200. `startFrom` is an optional create-only RFC3339 timestamp,
omitted from reads; omission starts after the current latest commit. Its
initial checkpoint and subsequent date guard handle event-date/sequence skew.
The exact Go zero instant is rejected locally; other supported RFC3339 dates
remain valid. Type and startFrom cannot be patched.

Workers acquire unique fenced 60-second leases and read at most 100 settled
events. Delivery succeeds on HTTP 2xx with a ten-second timeout. Failures retry
with exponential delay from one second to five minutes; 24 hours of continuous
failure suspends the stream. Paused/suspended streams preserve their checkpoint.
Resume by PATCHing `status:active`; this resets retry state, preserves progress
and retries pending work. Administrative changes invalidate existing leases.
Restart or a lost checkpoint write can replay a batch; receivers must deduplicate
by `log_id`. Partial JSONOBJECT success can replay earlier objects. Retention
can remove undelivered events; streaming is at least once for retained events
while delivery can succeed, not an archive or a promise beyond retention.

The console health view exposes only stream ID/status, failure count, safe
error class and timing through the local operator status endpoint. It exposes
no sink credentials, response bodies or lease ownership.

HTTPS and public destinations are required by default. Each connection resolves
DNS, validates every selected address and pins the dialed public address;
loopback, private and link-local destinations are refused. Redirects are not
followed. Local development may explicitly opt into insecure HTTP and private
network delivery using the two deployment settings above. TLS certificate
verification remains enabled, including when `splunkSecure:false` is stored.

## Compatibility and acceptance limits

The pinned node-auth0 7.4.0 modern methods and its bundled legacy
`logs.getAll`/`users.getLogs` cover page/checkpoint/user reads and statistics
in the local production fixture. The modern SDK exposes `search`; use its
`queryParams.q` pass-through for the frozen wire `q` parameter. No `search`
alias is promised.

Pinned auth0-cli 1.37.0 unfiltered list and HTTP stream CRUD worked in the
fixture. Its filtered list and `logs tail` previously failed because page
requests included `search_engine=v3`. A separate permitted
[independent observation](compat/observations/2026-11-01-logs-search-selector.md)
now confirms upstream acceptance of that value, and global tenant-log page mode
accepts it locally with the existing bounded query semantics. Tail polls log-ID
range pages rather than checkpoint mode. The final CLI/E2E rerun passed filtered list/tail and stream CRUD; the earlier failed result is retained in the implementation record. See the [final validation record](superpowers/2026-11-01-plan-31-final-validation.md) for actual results and skips.

The local primary-source contract and code catalog do not assert complete
Auth0 equivalence. The implementer used only the sanitized independent selector observation; no
tenant contact or vendor delivery endpoint was used for this implementation. See the [compatibility matrix](compat/matrix.md) for the current
boundary and the implementation record for actual tests and unrun checks.

## Event inventory

The frozen inventory has **60 emitted implementation targets** and **120 not
emitted yet**. The [source → emitted-event test audit](superpowers/2026-10-31-plan-31-task-16a2-audit.md)
maps all 60 to real business outcome boundaries and event assertions. That
audit is source/test evidence, not a claim that this guide freshly ran every
test or completed full branch acceptance. `fapi` is an explicit local legacy
compatibility code. `sdu` is deletion and `ublkdu` is unblock; phone-change
`scpn` is deferred. Hook failure codes are not used for Action job failures;
those use `actions_execution_failed`. Deferred owners must recheck public
semantics before enabling a code.

### Emitted code coverage

| Code | Meaning |
| --- | --- |
| `actions_execution_failed` | An Action stopped with an execution error. |
| `api_limit` | An API request exhausted its rate budget. |
| `custom_domain_verification_failed` | A custom-domain ownership check failed. |
| `f` | Authentication was refused for a reason without a more specific login code. |
| `fapi` | A Management mutation failed (local legacy compatibility code). |
| `fce` | An account email update failed. |
| `fcp` | An account password update failed. |
| `fcpr` | A password-reset initiation failed. |
| `fcu` | An account username update failed. |
| `fdeac` | A device activation could not complete. |
| `fdeaz` | A device authorization request was refused. |
| `fdecc` | The user declined the device authorization prompt. |
| `fdu` | An account removal failed. |
| `feacft` | An authorization code could not issue tokens. |
| `feccft` | A client-credentials request could not issue tokens. |
| `fede` | A device-code grant could not issue tokens. |
| `fepft` | A resource-owner password grant was refused. |
| `ferrt` | A rotating refresh credential was rejected, including reuse detection. |
| `fertft` | A refresh credential could not issue tokens. |
| `fi` | An organization invitation could not be accepted. |
| `flo` | The requested local sign-out could not complete. |
| `fn` | An email notification could not be dispatched. |
| `fp` | The supplied password did not validate. |
| `fpar` | A pushed authorization request was refused. |
| `fs` | Account registration was refused or failed. |
| `fsa` | Authentication without interaction was refused. |
| `fu` | No valid account matched the supplied login identifier. |
| `fui` | A background account import failed. |
| `fv` | A verification email could not be dispatched. |
| `fvr` | A verification-email initiation failed. |
| `limit_mu` | An IP triggered suspicious authentication or registration throttling. |
| `limit_sul` | An account-and-IP login frequency budget was exhausted. |
| `limit_wc` | Repeated bad credentials triggered an account block. |
| `mgmt_api_read` | An authorized Management read returned protected credential data. |
| `organization_access_denied` | Application policy refused the requested organization. |
| `organization_member_added` | An account gained membership in an organization. |
| `pwd_leak` | A login presented a password found in a breach corpus. |
| `reset_pwd_leak` | A reset presented a password found in a breach corpus. |
| `s` | An interactive authentication completed. |
| `sapi` | A Management mutation completed successfully. |
| `sce` | An account email address changed. |
| `scp` | An account password changed. |
| `scpr` | A password-reset request was accepted. |
| `scu` | An account username changed. |
| `sdu` | An account was removed. |
| `seacft` | An authorization code issued tokens. |
| `seccft` | A client-credentials request issued tokens. |
| `sede` | A device-code grant issued tokens. |
| `sepft` | A resource-owner password grant issued tokens. |
| `sertft` | A refresh credential issued tokens. |
| `si` | An organization invitation was accepted. |
| `signup_pwd_leak` | A registration presented a password found in a breach corpus. |
| `slo` | The local sign-out completed. |
| `srrt` | A refresh credential was revoked. |
| `ss` | A new account was registered. |
| `ssa` | Authentication without interaction completed. |
| `sui` | A background account import completed. |
| `sv` | An email-verification bearer was consumed. |
| `svr` | A verification-email request was queued. |
| `ublkdu` | An automatic account block was removed. |

### Not emitted yet

These rows are searchable catalog/filter vocabulary; listing a code does not
cause an event to be synthesized. The owner is a deferred review plan, not a
promise that the corresponding plan is already implemented. `w` and `fco`
remain deferred within Plan 31 because safe source classifications are absent.

| Code | Meaning | Review owner |
| --- | --- | --- |
| `acls_summary` | A reporting window summarized network access policy matches. | Plan 45 |
| `acul_sdk_notice` | The advanced login SDK produced a diagnostic notice. | Plan 44 |
| `admin_update_launch` | A platform update was announced. | Plan 47 |
| `api_limit_warning` | API request traffic approached its rate budget. | Plan 45 |
| `appi` | An API peak-traffic performance interval began. | Plan 45 |
| `ciba_exchange_failed` | A CIBA token request was refused. | Plan 41 |
| `ciba_exchange_succeeded` | A CIBA token request issued tokens. | Plan 41 |
| `ciba_start_failed` | A CIBA authentication request could not begin. | Plan 41 |
| `ciba_start_succeeded` | A CIBA authentication request began. | Plan 41 |
| `cls` | A passwordless sign-in message containing a link or code was dispatched. | Plan 34 |
| `coff` | An AD/LDAP connector became unavailable. | Plan 36 |
| `con` | An AD/LDAP connector became available. | Plan 36 |
| `connected_accounts_connection_failed` | A third-party account could not be connected. | Plan 43 |
| `connected_accounts_connection_succeeded` | A third-party account was connected. | Plan 43 |
| `connected_accounts_delete_failed` | A third-party account connection could not be removed. | Plan 43 |
| `connected_accounts_delete_succeeded` | A third-party account connection was removed. | Plan 43 |
| `cs` | A passwordless sign-in code was dispatched. | Plan 34 |
| `depnote` | A request exercised a deprecated feature. | Plan 45 |
| `directory_sync_completed` | A directory synchronization run completed. | Plan 36 |
| `directory_sync_failed` | A directory synchronization run stopped with an error. | Plan 36 |
| `directory_sync_started` | A directory synchronization run began. | Plan 36 |
| `failed_on_behalf_of_token_exchange` | An on-behalf-of grant could not issue tokens. | Plan 35 |
| `fc` | An enterprise connector authentication failed. | Plan 36 |
| `fco` | The application origin policy refused a request. | Plan 31 |
| `fcoa` | The cross-origin authentication flow did not complete. | Plan 44 |
| `fcph` | An asynchronous password-change hook ended with an error. | Plan 38 |
| `fcpn` | An account phone update failed. | Plan 34 |
| `fcpro` | An AD/LDAP connector could not be provisioned. | Plan 36 |
| `fd` | A delegation credential could not be created. | Plan 38 |
| `fdeleacft` | A delegated authorization code could not issue tokens. | Plan 38 |
| `fdelsa` | Delegated authentication without interaction was refused. | Plan 38 |
| `fecte` | A custom token grant could not issue tokens. | Plan 35 |
| `federated_logout_failed` | The external identity provider could not complete sign-out. | Plan 41 |
| `fens` | A native social provider exchange was refused. | Plan 44 |
| `feoobft` | A password grant with an out-of-band challenge was refused. | Plan 33 |
| `feotpft` | A password grant with a one-time challenge was refused. | Plan 33 |
| `fepotpft` | A passwordless one-time grant was refused. | Plan 34 |
| `fercft` | A password grant with an MFA recovery credential was refused. | Plan 33 |
| `feta` | Token Vault could not exchange the supplied credential. | Plan 43 |
| `flows_execution_completed` | A configured Flow reached completion. | Plan 38 |
| `flows_execution_failed` | A configured Flow stopped with an error. | Plan 38 |
| `forms_submission_failed` | A submitted Form was refused or failed. | Plan 38 |
| `forms_submission_succeeded` | A submitted Form was processed. | Plan 38 |
| `fpurh` | An asynchronous registration hook ended with an error. | Plan 38 |
| `fscim` | A SCIM provisioning operation failed. | Plan 38 |
| `gd_auth_email_verification` | The MFA email verification step completed. | Plan 33 |
| `gd_auth_failed` | An MFA challenge did not validate. | Plan 33 |
| `gd_auth_rejected` | The user declined an MFA push challenge. | Plan 33 |
| `gd_auth_succeed` | An MFA challenge validated. | Plan 33 |
| `gd_email_settings_update` | The MFA email factor configuration changed. | Plan 33 |
| `gd_enrollment_complete` | An account completed its first MFA enrollment. | Plan 33 |
| `gd_otp_rate_limit_exceed` | Too many incorrect MFA one-time codes triggered throttling. | Plan 33 |
| `gd_phone_settings_update` | The MFA phone factor configuration changed. | Plan 33 |
| `gd_recovery_failed` | An MFA recovery credential did not validate. | Plan 33 |
| `gd_recovery_succeed` | An MFA recovery credential validated. | Plan 33 |
| `gd_send_email` | An MFA challenge email was dispatched. | Plan 33 |
| `gd_send_email_verification` | An MFA enrollment verification email was dispatched. | Plan 33 |
| `gd_send_pn` | An MFA push challenge was dispatched. | Plan 33 |
| `gd_send_pn_failure` | An MFA push challenge could not be dispatched. | Plan 33 |
| `gd_send_sms` | An MFA text challenge was dispatched. | Plan 33 |
| `gd_send_sms_failure` | An MFA text challenge could not be dispatched. | Plan 33 |
| `gd_send_voice` | An MFA voice challenge was dispatched. | Plan 33 |
| `gd_send_voice_failure` | An MFA voice challenge could not be dispatched. | Plan 33 |
| `gd_start_auth` | An MFA authentication challenge began. | Plan 33 |
| `gd_start_enroll` | An MFA enrollment began. | Plan 33 |
| `gd_start_enroll_failed` | An MFA enrollment could not complete. | Plan 33 |
| `gd_tenant_update` | Tenant MFA configuration changed. | Plan 33 |
| `gd_unenroll` | A second-factor device registration was removed. | Plan 33 |
| `gd_update_device_account` | A second-factor device registration changed. | Plan 33 |
| `gd_webauthn_challenge_failed` | The browser could not complete a WebAuthn assertion. | Plan 33 |
| `gd_webauthn_enrollment_failed` | The browser could not complete WebAuthn registration. | Plan 33 |
| `idjag_exchange_failed` | An identity assertion authorization grant was refused. | Plan 35 |
| `idjag_exchange_succeeded` | An identity assertion authorization grant issued tokens. | Plan 35 |
| `jwt_bearer_exchange_failed` | A JWT assertion grant was refused. | Plan 35 |
| `kms_key_management_failure` | A managed encryption-key operation failed. | Plan 38 |
| `kms_key_management_success` | A managed encryption-key operation completed. | Plan 38 |
| `kms_key_state_changed` | An encryption key moved to another lifecycle state. | Plan 38 |
| `limit_delegation` | Delegation request traffic exhausted its rate budget. | Plan 38 |
| `limit_phone` | Phone challenge traffic exhausted its send budget. | Plan 34 |
| `limit_signup_otp` | Signup verification traffic exhausted its identifier send budget. | Plan 34 |
| `mfar` | The flow requested a second authentication factor. | Plan 33 |
| `my_account_authentication_method_failed` | A My Account authentication-method operation failed. | Plan 42 |
| `my_account_authentication_method_succeeded` | A My Account authentication-method operation completed. | Plan 42 |
| `oidc_backchannel_logout_failed` | An OIDC logout notification could not be delivered. | Plan 41 |
| `oidc_backchannel_logout_succeeded` | An OIDC logout notification was delivered. | Plan 41 |
| `passkey_challenge_failed` | A native passkey assertion could not complete. | Plan 33 |
| `passkey_challenge_started` | A native passkey assertion challenge began. | Plan 33 |
| `pla` | Bot-detection signals were sampled before authentication. | Plan 40 |
| `resource_cleanup` | Limit enforcement removed excess stored resources. | Plan 45 |
| `rich_consents_access_error` | A rich-consent record could not be read. | Plan 38 |
| `scoa` | The cross-origin authentication flow completed. | Plan 44 |
| `scpn` | An account phone number changed. | Plan 34 |
| `scv` | The submitted credential passed validation. | Plan 40 |
| `sd` | A delegation credential was created. | Plan 38 |
| `sdel` | A delegated sign-in completed. | Plan 38 |
| `sdeleacft` | A delegated authorization code issued tokens. | Plan 38 |
| `sdelsa` | Delegated authentication without interaction completed. | Plan 38 |
| `secte` | A custom token grant issued tokens. | Plan 35 |
| `sens` | A native social provider exchange completed. | Plan 44 |
| `seoobft` | A password grant passed an out-of-band challenge. | Plan 33 |
| `seotpft` | A password grant passed a one-time challenge. | Plan 33 |
| `sepkoobft` | A passkey grant passed an out-of-band challenge. | Plan 33 |
| `sepkotpft` | A passkey grant passed a one-time challenge. | Plan 33 |
| `sepkrcft` | A passkey grant passed an MFA recovery challenge. | Plan 33 |
| `sercft` | A password grant passed an MFA recovery challenge. | Plan 33 |
| `seta` | Token Vault exchanged the supplied credential. | Plan 43 |
| `ss_sso_failure` | A self-service SSO operation failed. | Plan 38 |
| `ss_sso_info` | A self-service SSO operation produced informational output. | Plan 38 |
| `ss_sso_success` | A self-service SSO operation completed. | Plan 38 |
| `sscim` | A SCIM provisioning operation completed. | Plan 38 |
| `success_on_behalf_of_token_exchange` | An on-behalf-of grant issued tokens. | Plan 35 |
| `sys_os_update_end` | A platform operating-system update finished. | Plan 47 |
| `sys_os_update_start` | A platform operating-system update began. | Plan 47 |
| `sys_update_end` | A platform application update finished. | Plan 47 |
| `sys_update_start` | A platform application update began. | Plan 47 |
| `universal_logout_failed` | A universal sign-out operation could not complete. | Plan 41 |
| `universal_logout_succeeded` | A universal sign-out operation completed. | Plan 41 |
| `w` | Authentication completed a step with a warning. | Plan 31 |
| `wn` | A general warning notification was produced. | Plan 38 |
| `wum` | A user-management operation produced a warning. | Plan 38 |
