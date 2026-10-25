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
Seed/API policies win; restarting never overwrites them. Editing the relevant
policy exits legacy semantics. Legacy markers are not public API fields.

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
and allowlists; passwordless and custom-token-exchange stages remain inert
until Plans 34/35.

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
