# Attack protection and automatic blocks

The console and `GET/PATCH /api/v2/attack-protection/{feature}` manage
`brute-force-protection`, `suspicious-ip-throttling`,
`breached-password-detection`, `bot-detection` and `captcha`. Reads need
`read:attack_protection`; writes need `update:attack_protection`. Each patch
changes only its feature, preserving omitted nested settings. See the
[complete contracts](compat/observations/management-attack-protection.md).

## Shared storage and migration

Every server must use the same SQL database or shared storage plugin for
shared protection. Independent memory stores do not share limits. Migration
0016 and the current plugin protocol persist policies, reservations, counters,
risk events and replay hashes. Old plugins fail explicitly; there is no
process-local fallback. Keep the master key available to decrypt CAPTCHA
credentials. A store failure refuses protected authentication temporarily.

Explicit legacy `security.login_max_attempts` / `login_lockout_seconds`
initialize an absent policy once, transactionally, with a compatibility warning
and legacy IP semantics. Unspecified defaults select the new policy defaults.
Seed/API policies win; restarting never overwrites them. Editing brute-force
settings exits the legacy brute-force duration/threshold mode; editing
suspicious-IP settings exits the legacy IP fixed-window override while retaining
the brute-force duration until that policy is edited. Legacy markers are not
public API fields.

Brute force defaults to ten failures and a 30-day block. Keys use normalized
identity, stable connection and (unless identifier-only mode) canonical IP.
The connection opt-out skips only brute force. Suspicious IP uses independent
login/registration token buckets: defaults are 100 tokens / 864000 milliseconds
per token and 50 / 1728000 respectively. Rates are **milliseconds per token**.
Reset-email sends share a separate three-per-hour budget. Atomic reservations
prevent concurrent overspending; stale completions cannot undo unblock or newer
failures. Abandoned reservations become failures after 60 seconds.

IPv4-mapped IPv6 shares its IPv4 key. Invalid addresses use one non-allowlisted
unknown key. Existing single-trusted-proxy rules apply. Public clients cannot
spoof `auth0-forwarded-for`; confidential password clients retain the existing
trusted forwarding rule. Do not expose a trusted-proxy listener directly.

## Request rate limits

Besides the per-feature limits above, every tenant Authentication API route
(`/oauth/token` for every grant, `/authorize`, `/userinfo`, `/oauth/par`,
`/oauth/device/code`, `/oauth/revoke`, `/dbconnections/*`,
`/passwordless/start`, `/mfa/*`, `/.well-known/*` including the JWKS, logout
and the hosted pages) sits behind a token bucket keyed by tenant, client IP
and endpoint group (`token`, `authorize`, `userinfo`, `discovery`, `other`).
The client IP follows the same proxy rules as every other throttle, and IPv6
addresses share a bucket per /64. Configure it under `security.rate_limit`
(defaults: 50 requests per second, burst 200, per group, IP and tenant; see the
README's configuration section). The Management API, the console and export
downloads are not limited here.

Over the limit, the server answers like Auth0
([custom rate-limit policies](https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy/custom-rate-limit-policies)):
HTTP 429 with `{"error":"too_many_requests","error_description":"Rate limit exceeded."}`
and `Retry-After` in seconds. Every response on a limited route carries
`X-RateLimit-Limit` (the burst), `X-RateLimit-Remaining` and
`X-RateLimit-Reset` (UNIX time, in seconds, when the bucket is full again).
The limiter runs before CORS, so a browser may report a throttled
cross-origin request as a network error.

Legacy client secrets are checked with argon2id (19 MiB each). At most
`security.rate_limit.max_concurrent_secret_verifications` such checks run at
once per process; a request that finds no free slot within 100 ms gets the
same 429 instead of queueing.

The limiter is **per process**: N replicas allow N times the configured rate.
Each group tracks at most `max_tracked_keys` buckets and drops the least
recently used one when full, so a flood of distinct addresses cannot grow
memory without bound (it can only reset other buckets to full). Shared
counters across replicas are deferred to Plan 45.

## Breached passwords

Server configuration is required before any outbound lookup:

```yaml
security:
  breached_passwords:
    mode: file # off (default), range, or file
    file: /srv/zeroauthy/pwned-sha1.txt
```

File mode requires an immutable, sorted corpus with one 40-hex SHA-1
hash (case-insensitive, ordered by normalized uppercase hash) and positive count per line (`HASH:COUNT`), no plaintext, duplicates or
zero counts. Startup refuses unreadable/corrupt files. Sparse indexed lookup
avoids loading or scanning the whole corpus per request. Replace the corpus
and restart the process to change it.

Range mode uses the fixed HTTPS Pwned Passwords endpoint, sending only the
five-character SHA-1 prefix and requesting padding. It has a two-second limit,
no redirects, a 2-MiB response limit and a 1024-prefix/five-minute cache.
SHA-1 is only a lookup key; stored password hashing is unchanged.

Default tenant breach protection is disabled. Imported enabled policy remains
enabled even when the checker is off. An unavailable checker is never a clean
verdict: a blocking stage returns `503 temporarily_unavailable`; monitoring
continues with a redacted event. Confirmed breach returns `password_leaked`
(401 password grant, 400 signup), or Management `400 invalid_body`; hosted
forms display localized errors. These error choices are explicit local
fallbacks. Checks precede password/user mutation and reset-ticket consumption,
and login checks follow credential verification but precede token/session
issuance. Existing imported hashes may still upgrade after verification.

Notification shields/frequencies and proprietary detection methods round-trip;
notification delivery, unblock email links and Credential Guard equivalence
are not implemented. Plan 21 owns delivery. Current notification requests
produce rate-limited warnings. Only the configured corpus verdict is enforced.

## Bot policy and CAPTCHA

The local risk classifier counts qualifying failures per tenant/IP in the
preceding 15 minutes: low/medium/high sensitivity means 10/5/1 failures.
Wrong credentials, rejected registration/password replacement and invalid
required proofs count at most once per attempt. Success does not erase history;
normal reset-email requests, infrastructure outages and already-throttled
requests do not add risk. This deterministic rule differs from Auth0's
proprietary classifier. Policies support never/always/when_risky, monitoring
and allowlists; custom-token-exchange stages remain inert
until Plan 35.

Supported verifiers/widgets: reCAPTCHA v2, reCAPTCHA Enterprise (API-key
assessments), hCaptcha and Friendly Captcha v1. Arkose, Auth Challenge and
Simple CAPTCHA settings are stored but unavailable; `fail_open` is inert.
A required unavailable/misconfigured verifier fails closed. Direct password,
signup and reset-send APIs return `401 requires_verification` when challenged;
there is no inline proof parameter. Use interactive hosted login.

Provider calls have two-second deadlines, no redirects and 256-KiB response
limits. Provider/site and supported hostname/action bindings are validated;
HTTP 200 alone is insufficient. Provider credential/service errors are
unavailable, not user failures. Proof hashes are consumed globally for five
minutes, preventing reuse across servers, flows and tenants. Except for
provider-supported action binding, an unused proof cannot establish its first
local transaction: the guarantee is valid local context, site validation and
at-most-once use, not universal cryptographic transaction binding.

Secrets/API keys are encrypted at rest and omitted from API responses and
console inputs. Omit an unchanged provider object; supplying one requires its
complete required credential children. Provider scripts load only on required
hosted challenge pages. Real provider assets/accounts remain an optional
operator smoke test; automated verification uses local mocks.

## Inspect, unblock and recover

`GET/DELETE /api/v2/user-blocks?identifier=…` and `/user-blocks/{user_id}`
require `read:users` / `update:users`. IP anomaly GET/DELETE at
`/api/v2/anomaly/blocks/ips/{ip}` require `read:anomaly_blocks` /
`delete:anomaly_blocks`. Unknown identifiers delete with 204; unknown user IDs
read/delete with 404 `inexistent_user`. An unblocked IP reads 404 and deletes
with 204. User lookups include applicable linked identities.

Automatic unblock does not change administrative `blocked`, revoke sessions,
or clear unrelated IP/reset-mail state. A successful password reset clears the
corresponding brute-force block; a refused reset clears nothing. The console
shows automatic blocks separately from its administrative Block action.

Prepare a separately authorized Management client on the **system tenant**
before changing policies that could lock out console operators. To recover,
obtain its client-credentials token for that tenant's Management API audience
(the grant needs `read:users`, `update:users`, and, if necessary,
`read:anomaly_blocks`, `delete:anomaly_blocks`, `update:attack_protection`).
Use that token against the system host to inspect and DELETE the operator's
URL-encoded `/api/v2/user-blocks/{user_id}`, then inspect/delete the source IP
anomaly separately. If required CAPTCHA or an unavailable blocking breach
checker caused the denial, repair the server-side configuration. The reserved
system tenant rejects settings/protection PATCH; the recovery client can clear
automatic blocks but cannot override those protected policies. On an ordinary
tenant, an authorized client can PATCH the specific policy. Retry sign-in. Administrative blocks
require a separate authorized user update; automatic unblock will not remove
them. Never print the token or provider credentials in logs.

General Authentication API rate limiting, device activation counters and
custom-script Try limits remain separate follow-ups; Plan 19 does not claim
to make those limits shared.

## Tenant log evidence

Use the console's **Logs** page to inspect committed protection decisions.
`limit_wc`, `limit_sul` and `limit_mu` record applicable denied admissions;
`pwd_leak`, `signup_pwd_leak` and `reset_pwd_leak` record the corresponding
confirmed breach outcomes. `ublkdu` records an actual unblock write. Existing
members/cleared blocks and rolled-back changes do not manufacture events;
older plugins without optional mutation-outcome reporting omit uncertain
outcomes. Management 429 responses can emit `api_limit`.

The [logging guide](logs.md) documents privacy, the bounded failure-only
window, retention and the complete code inventory. Recording is asynchronous
and can drop events under queue/storage pressure, so absent log evidence is
not proof that an enforcement decision did not occur. Logs do not change
protection enforcement, counter reservations or notification availability.

## Phone-provider protection

`GET` and `PATCH /api/v2/attack-protection/phone-provider-protection` expose
`type: default` or `type: exponential`. The latter adds send backoff to the
existing IP, identifier and per-user budgets. Limits are enforced before
provider delivery across passwordless, signup and MFA phone sends. A provider
failure does not trigger an alternate route or disclose credentials. Tenant
configuration can be provisioned alongside the existing attack-protection
settings. Review [phone-provider routing](phone-providers.md) when diagnosing
throttled or unsupported voice requests.
