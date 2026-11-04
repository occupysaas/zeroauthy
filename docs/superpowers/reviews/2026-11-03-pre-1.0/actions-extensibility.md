# Extensibility (Actions, custom database scripts, Node runner) review

## Summary
The Actions engine fails closed as documented. I traced throws, timeouts, unsupported or invalid API calls, a missing runtime, metadata commit failures and runner crashes through `internal/actions/engine.go` and its callers in `internal/oauth` and `internal/authz`. Each one ends as `server_error` or the hosted error page, and no code or token is issued. Several other controls also held up: secrets are sealed per tenant, Action and Module; Management responses show only secret names; phone OTPs are masked; each tenant has its own process with an empty environment; and file reads are limited to the tenant's directory (checked on Node 26.8.1, including a sibling-directory prefix and `..`).

The weak point is the unix-domain-socket boundary, which is part of the hard line. The Actions lockout can be bypassed with a property getter: I reproduced a connection on Node 26.8.1. The custom-database runner has no lockout at all, also reproduced. Through either one, tenant code can reach peer-authenticated database sockets or container-runtime sockets that the server's uid owns, and from there every tenant's data.

Counts: 2 high, 3 medium, 2 low. **Fix-before-1.0: 4** (F1, F2, F3, F4).

## Findings

### F1 [high] [defect] The Actions unix-socket lockout can be bypassed with an accessor on `path` (time-of-check/time-of-use)
- Where: internal/actions/runner.mjs:46-58. The claim is made in docs/actions.md:267-272 and decisions.md:1124 (D-0053).
- What: `socketPath()` reads `options.path` once (`a.path != null`), then hands the same object to Node's real `connect`, which reads `path` again. Action code can pass an options object whose `path` getter returns `undefined` only on the read the check makes and the socket path on every other read. The check passes and Node connects to the unix socket. `http.get({socketPath})` and `tls.connect` go through the same `Socket.prototype.connect`, so the same trick applies to them. This reopens the hole Plan 27's final review closed: Action code running as the server's uid can reach a peer-auth PostgreSQL or MySQL socket (all tenants' data) or a rootless Podman/Docker API (the host).
- Evidence: Reproduced with the exact lockout code from runner.mjs under `node --permission --allow-net` (Node 26.8.1). A plain `net.connect(sock)` throws. `net.connect({ get path(){ return ++n === 2 ? undefined : sock } })` prints `CONNECTED`, and the listener accepted 1 connection. Getters that return `undefined` on read 1, 3 or 4 are refused, so read 2 is the check.
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0
- Suggested fix: In the wrapper, copy the arguments into fresh plain data before checking, and pass the copy, not the caller's object, to the original `connect`. Refuse options objects whose `path` is an accessor or a Proxy, or whose `path` is not an own data property. Add the getter case to `TestEngineNoUnixSockets`. In the longer term, document an OS-level control (dedicated uid or network namespace) as the real boundary.

### F2 [high] [defect] The custom-database runner has no unix-domain-socket lockout
- Where: internal/customdb/runner.mjs (no `net.Socket.prototype.connect` guard; compare internal/actions/runner.mjs:40-58). Docs: docs/custom-db.md:150-168.
- What: Custom DB scripts are tenant-authored through `options.customScripts`, run as the server's uid, and get the real `require('net')`. On Node 25+ `--allow-net` is passed, which permits pipes. On Node 22/24 there is no network permission at all. A script can therefore connect to any unix socket the server's uid can open. The Plan 27 implementation record (docs/superpowers/2026-10-27-plan-27-implementation-record.md:205) noted this gap as "outside Plan 27", but it was never added to plan-1-followups.md or to custom-db.md's Security section.
- Evidence: I ran the real `internal/customdb/runner.mjs` under `node --permission --allow-net --allow-fs-read=<dir>` with a `login` script that calls `require("net").connect("<unix sock>")`. The Python listener printed `ACCEPTED unix connection`, and the runner answered `{"ok":true,...}`.
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0
- Suggested fix: Move the hardened guard from F1 into one shared prelude that both runner scripts use, and add a customdb counterpart of `TestEngineNoUnixSockets`. Add a unix-socket line to custom-db.md's Security section.

### F3 [medium] [defect] Captured console output and runner diagnostics go permanently silent after a process's first 60 s (or 256 distinct masked values). This includes the Action Test endpoint and custom-DB script logs
- Where: internal/actions/runnerjs.go:36-100 (`procState.add/scrub/capture`, with `until` set once and `mute()` permanent); internal/customdb/masks.go:16-59,149-159 (the same policy); internal/actions/engine.go:578 (`step` → `executed.capture`), which `Engine.Test` also uses.
- What: The mask window starts at a runner process's first call and is never renewed. Once it ends, `capture` returns nil and stderr is dropped until the process retires. Retirement happens only after 5 idle minutes, so a tenant with steady traffic never gets a new window. In practice:
  - On a busy tenant, execution records lose their console lines.
  - A developer who uses the console's **Test** button repeatedly gets logs for the first minute and none after that.
  - For custom DBs, each login's password is a new distinct masked value, so script logs disappear after 256 logins on a busy tenant.

  The Plan 31 final review accepted "diagnostics unavailable after cap/window on busy process" as a privacy trade-off. But docs/actions.md ("persisted console lines (64 KiB per result)") and docs/custom-db.md promise the logs without that caveat. The maintainer relies on these logs for troubleshooting Actions (memory note).
- Evidence: Code path above; `TestActionConsoleExpiredCapturePermanentlyClearsState` asserts this behaviour; docs/superpowers/2026-11-01-plan-31-final-review.md:63.
- Verdict: CONFIRMED (from code and tests; not run at 60 s wall time)
- Recommendation: fix-before-1.0. It breaks the documented first-run debugging path, and the fix is small.
- Suggested fix: When the window or cap runs out, retire the tenant's process (let in-flight calls finish, then the next call starts a fresh process with a clean mask set) instead of muting it forever. This keeps the privacy guarantee, because a fresh process holds no cached values. If that is not done, at least document the limit in actions.md and custom-db.md.

### F4 [medium] [docs-drift] docs/actions.md still describes the Plan 27/28 catalogue: seven triggers, and MFA/authentication APIs that "throw"
- Where: docs/actions.md:3 ("seven supported triggers"), :25-28 ("MFA ... omitted"), :73-76 ("`authentication.*`, `multifactor.*` ... throw 'not supported by zeroauthy'"), :469-471 ("MFA ... await their own plans; the seven-trigger catalogue").
- What: The code has ten triggers (internal/actions/triggers.go:10-21: it adds `custom-phone-provider`, `send-phone-message` and `event-stream`). `api.multifactor.enable` and `api.authentication.challengeWith*/enrollWith*` are supported under Plan 33 (inventory.json:750-789; mfa.go; runner.mjs `api.multifactor = ns(...)`). `event.user.enrolledFactors` and `event.authentication.methods` are now populated. A first-time user reading actions.md will conclude that MFA from Actions does not work, although it is a 1.0 scope item (v1 release scope, Plan 33 row).
- Evidence: Files above; the 1.0 scope doc lists "Actions `multifactor.enable`/`challengeWith*`".
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0
- Suggested fix: Update the trigger count and the API table, add the phone triggers to the trigger table, and link docs/mfa.md and docs/phone-providers.md.

### F5 [medium] [parity-gap] `event.authentication.methods` never contains the first factor (`pwd`, `federated`, `sms`, `email`)
- Where: internal/actions/event.go:312-317 (only `{name:"mfa"}` when `Session.MFAAt` is set; otherwise `[]`).
- What: Auth0 records the completed primary method, for example `{name:"pwd", timestamp}` for a database login, and Actions commonly branch on `methods[0].name`. In zeroauthy, password, passwordless and social logins all produce an empty array, so such Actions take the wrong branch. Password grants show the same gap.
- Evidence: Auth0 passwordless-on-database docs (https://auth0.com/docs/authenticate/database-connections/passwordless-authentication-for-db-connect): "const firstFactor = event.authentication.methods[0]; ... else if (firstFactor.name === 'pwd')". The same values are documented for `context.authentication.methods`: "`federated` ... `pwd` ... `sms` ... `email` ... `mfa`".
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-40 (Actions III)
- Suggested fix: Record the first-factor method and time on the login session (database → `pwd`, social/enterprise → `federated`, passwordless → `email`/`sms`) and emit it ahead of `mfa`.

### F6 [low] [docs-drift] `event.refresh_token` is claimed but never emitted; `event.session` is missing on token-endpoint grants
- Where: docs/actions.md:23-24 ("Session and refresh-token fields appear when available"); internal/actionsrules/inventory.json:531 (lists `refresh_token`); internal/actions/event.go:286-330 (no `refresh_token`; `Session` is set only by internal/authz/actions.go:62, never by internal/oauth/actions.go:63-66).
- What: No path builds `event.refresh_token`, and refresh-grant Actions never see `event.session`. Auth0 documents `event.refresh_token` as Enterprise-only ("[Enterprise Customers] The current refresh token") and `event.session` as "The current login session".
- Evidence: Code above; https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-event-object
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-40
- Suggested fix: Remove the docs and inventory claim, or emit both fields on the refresh grant. Also add the missing `event.user.last_password_reset` and `multifactor`, which the same Auth0 page lists among the user properties.

### F7 [low] [parity-gap] The custom-database script `context` object (Organizations data) is not supported
- Where: internal/customdb/client.go:125-200 (fixed argument lists); there is no `enableScriptContext` option anywhere in the repo.
- What: Auth0 lets a database connection enable a `context` argument just before `callback`, carrying `organization {id,name,display_name,metadata}` (and `identifierType` for passkeys). Scripts written in the 4-argument form, `login(email, password, context, callback)`, receive the callback in the `context` slot and break. This deviation is not recorded in D-0022.
- Evidence: https://auth0.com/docs/authenticate/database-connections/custom-db/create-db-connection: "Doing so passes an additional `context` argument to custom database scripts containing Organization data ... This parameter directly precedes the `callback` parameter."
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-40 (or a new short plan: "custom DB `enableScriptContext` with organization context"). Record the deviation in D-0022 now.
- Suggested fix: Support `options.enableScriptContext` (one-way, as in Auth0) and pass `{organization}` before the callback (an empty object for `delete`).

## Notes (checked, no finding)
- **Fail closed.** `Engine.run` returns `*ErrFlow` on any step error, and the runner records `unsupported`/`invalid_api_call` before throwing, so a caught exception still fails the flow. Every caller (oauth token grants, client credentials, authz browser/device, signup, reset) maps the failure to `server_error` or the error page. Signup with a bound pre-registration Action and no engine also fails closed (signupactions/signup.go:22-35).
- **Timeouts.** The per-flow 20 s budget is shared across Actions. A timeout kills only that tenant's Actions process. Event-stream calls use isolated processes that are killed and reaped on every return.
- **Cross-tenant file reads.** Each tenant can read only `<cache>/<tenantID>`, and the tenant ID regex prevents traversal. I checked prefix siblings and `..` against Node 26's permission model; both were denied. Symlink and hardlink tar entries are refused (build/manager_test.go:529-531).
- **Secrets.** They are sealed with `{tenant, action|module, name}` binding, and Management views return only `name`/`updated_at`. Masking covers execution records, Test output, deny/validation text and stderr. Phone codes, including spoken forms, are masked and carried into retry jobs as `SensitiveValues`.
- **Storage plugin channel.** It uses go-plugin `AutoMTLS`, so a runner reaching its socket cannot talk to it.
- **Within a tenant.** Code can forge stdout responses for other in-flight requests and read other Actions' secrets in the same tenant. This is accepted as one trust domain (D-0054) and documented.

## Changelog entries reviewed
Last recorded coverage in docs/compat/changelog-review.md: 2026-10-27 (Plan 29 Task 1). I fetched https://auth0.com/changelog/llms-full.txt on 2026-11-03.
- 2026-10-30 — Multi-Factor Authentication: Exponential Backoff for Phone MFA SMS Delivery. Not relevant to Actions (it covers phone MFA delivery and `limit_phone` logs, which belong to the MFA/phone area). Not covered; for the MFA/phone reviewer.
- 2026-10-29 — HTTP Message Signatures Added to Tenant Network ACLs. Not relevant.
- 2026-10-27 — Universal Portals Developer Preview. Not relevant; already recorded under Plan 42.
- No Actions or custom-database entries are dated after 2026-10-27.

## Roadmap suggestions
- Plan 40 (Actions III): add F5 (first-factor `authentication.methods`), F6 (`refresh_token`/`session` on refresh, plus `user.last_password_reset`/`multifactor`) and F7 (custom DB `enableScriptContext`).
- Plan 45 (Operational hardening): an OS-level sandbox for both runners, for example an optional dedicated runner uid, a network namespace or egress allowlist, or a Landlock/seccomp profile. The in-process JS guards (F1/F2) and Node's permission model are documented by Node as not a boundary against malicious code. Also add a single shared runner prelude so Actions and custom-DB hardening cannot drift apart again.
- plan-1-followups.md: record the customdb unix-socket gap until F2 lands. Today it exists only in the Plan 27 implementation record.
