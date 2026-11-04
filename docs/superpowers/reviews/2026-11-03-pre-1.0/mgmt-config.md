# Management API tenant configuration, logs and streams review

## Summary
Overall this area is in good shape. Every OAS route for Plans 19/20/21/23/31/32/34 is implemented except `/keys/encryption*` (BYOK) and the EA `/keys/network-acls*`. The checks the brief singled out mostly passed:
- **SSRF:** every outbound path dials through a resolve-then-check guard: log streams, event streams, email HTTP/SMTP, phone gateway/Twilio/SNS and custom-domain diagnostics. Redirects and proxies are disabled on all of them.
- **Credential leakage:** stream and provider credentials are sealed, and reads return either a marker or nothing.
- **Signing keys:** rotation and revocation are transactional; only `previous` keys can be revoked, and revoked keys leave the JWKS.
- **Attack protection:** the brute-force and suspicious-IP counters really block. Reservation and outcome are atomic, and the breached-password check runs at login, signup and reset.
- **Logs and events:** the log-type inventory is a superset of the logs schema (171/171), and the event catalog matches the events schema (25/25).

The main defect: tenants can set `phone-provider-protection` to `exponential`, but it does nothing, while the docs say it adds send backoff. Counts: 0 critical, 0 high, 2 medium, 4 low. One finding is fix-before-1.0.

## Findings

### F1 [medium] [defect|docs-drift] `phone-provider-protection` `type: exponential` is stored but never enforced
- Where: internal/mgmt/phone_protection.go:23-49; internal/tenantrules/phone.go:16,36,84. Consumers: internal/passwordless/start.go:247-248, internal/mfa/phone.go:120-122, internal/login/phone_codes.go:44-46, internal/mgmt/phone_providers.go:577-579.
- What: PATCH saves `default|exponential`, but nothing outside the GET handler ever reads `ProviderProtection`. Every SMS/voice send path uses fixed-window budgets only. The D-0060 ruling (3 immediate sends, then waits doubling from 60 s to 1920 s with ±10% jitter, reset after 24 h idle) has no code anywhere: grep for exponential/backoff finds only validation strings.
- Evidence:
  - docs/attack-protection.md:164-167 says "The latter adds send backoff to the existing IP, identifier and per-user budgets. Limits are enforced before provider delivery".
  - docs/compat/decisions.md:2320-2322 gives the backoff parameters.
  - Auth0 changelog, Oct 30 2026, "SMS Fraud Protection with Exponential Backoff": "Increases required wait times between consecutive requests for a user identifier, starting at 1 minute and scaling up to a maximum cooldown of 32 minutes"; throttled sends are logged as `limit_phone`.
  - https://auth0.com/docs/secure/multi-factor-authentication/multi-factor-authentication-factors/exponential-backoff-for-sms
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0. At minimum correct the docs: this is a toll-fraud control a tenant would rely on. Implementing it can defer to Plan 45.
- Suggested fix: either add a backoff limit to the protection store, keyed per identifier, that the three send paths consult when `type=exponential` (emitting `limit_phone` with the remaining cooldown), or change attack-protection.md, matrix and deploy-cli.md to say "stored only; fixed budgets apply".

### F2 [medium] [defect] Unproven custom-domain claims are never released, so one tenant can squat another tenant's domain
- Where: internal/customdomain/service.go:134-151 (Create writes host bindings for a pending domain); service.go:461-467 (when proof fails after `initialPause`, the domain becomes `LifecycleFailed` and its bindings stay).
- What: any tenant admin can POST `/custom-domains` for a hostname they do not control. The deployment-wide registry then rejects every other tenant with 409 `custom_domain_conflict` (docs/custom-domains.md:6-7). Nothing expires the claim: it lasts until the squatting tenant deletes it, even after verification has permanently failed. On a shared deployment this blocks the real owner indefinitely.
- Evidence: the code path above. No sweep deletes `LifecycleFailed` rows or their `HostBinding`s, and the operator has no Management route to override another tenant's claim.
- Verdict: CONFIRMED (the cross-tenant impact only matters on multi-tenant deployments with untrusted tenant admins)
- Recommendation: defer to Plan 47 (Hosted zeroauthy). Note it in docs/custom-domains.md for 1.0 multi-tenant operators.
- Suggested fix: let a proven claim pre-empt an unproven one, or release bindings of domains that are `failed` / unproven past N days. Add an operator override.

### F3 [low] [docs-drift] Attack-protection docs and matrix still say notification delivery is not implemented
- Where: docs/attack-protection.md:74-76 ("notification delivery, unblock email links … are not implemented. Plan 21 owns delivery"); docs/compat/matrix.md:61 ("Notification shields do not deliver mail").
- What: Plan 21 shipped user notifications. internal/protection/service.go:136-147 sends `blocked_account`, internal/protection/breach.go:195-197 sends `stolen_credentials`, and internal/email/notifications.go:51-96 delivers both, deduplicated per user per day. matrix.md:20 and plan-1-followups.md:337 already say so. Only admin notices and unblock links remain unimplemented.
- Evidence: the code above.
- Verdict: CONFIRMED
- Recommendation: defer to Plan 45 (cheap; can also be fixed alongside F1)
- Suggested fix: reword both places to "user notifications delivered (daily dedupe, no unblock link); admin notifications not delivered".

### F4 [low] [parity-gap] Brute-force denials log both `limit_wc` and `limit_sul`, on every refused attempt
- Where: internal/protection/service.go:219-238 (`blockEvents`)
- What: in `count_per_identifier_and_ip` mode, every denied login records `limit_wc` and also `limit_sul`. The schema describes `limit_sul` as a different signal: a login-frequency limit, not failed-credential blocking. The two events are also re-emitted on every subsequent refused attempt, not once when the block happens, which inflates tenant logs and log-stream traffic.
- Evidence: logs-schema.json: `limit_wc` "An IP address is blocked because it reached the maximum failed login attempts into a single account"; `limit_sul` "A user is temporarily prevented from logging in because they reached the maximum logins per time period from the same IP address".
- Verdict: PLAUSIBLE. The schema text supports it; Auth0's runtime emission was not observed.
- Recommendation: defer to Plan 45
- Suggested fix: emit only `limit_wc` for brute-force blocks. Consider emitting it once per block transition (the bucket's first denial) rather than per attempt.

### F5 [low] [parity-gap] `GET /logs` and `/users/{id}/logs` only accept `sort=date:±1`
- Where: internal/mgmt/logs.go:99-105
- What: any other sort field returns 400 `Invalid sort`. The OAS describes `sort` as "Field to use for sorting appended with :1 … e.g. date:-1" and points to Searchable Fields for the list of sortable fields. `/users/{id}/logs` says "Use `fieldname:1`". This restriction is not listed among the inventory gaps (internal/logrules/inventory.json `gaps`).
- Evidence: https://auth0.com/docs/oas/management/v2/management-api-oas.json (`/logs` and `/users/{id}/logs` `sort` parameters); https://auth0.com/docs/deploy-monitor/logs/log-search-query-syntax
- Verdict: CONFIRMED (code). Exactly which fields Auth0 accepts is unverified.
- Recommendation: defer to Plan 45
- Suggested fix: allow sorting on the indexed searchable fields, or record the restriction as a gap in the inventory and the matrix.

### F6 [low] [parity-gap] `GET /emails/provider` drops the non-secret `credentials` fields and ignores `fields`/`include_fields`
- Where: internal/emailrules/provider.go:162-177; internal/mgmt/email_provider.go:31-42
- What: the response schema (`EmailProviderCredentials`) returns `credentials` with only non-secret members: `api_user`, `region`, `smtp_host`, `smtp_port`, `smtp_user`. D-0047 makes all credentials write-only, which also hides the SMTP host, port and user, so a Deploy CLI or console round trip cannot show the configured SMTP endpoint. The OAS `fields`/`include_fields` query parameters are not applied.
- Evidence: OAS `GET /emails/provider` (parameters `fields`, `include_fields`; schema `EmailProviderCredentials`, which has no secret members).
- Verdict: CONFIRMED. D-0047's reasoning holds for secrets but is broader than needed for these five fields.
- Recommendation: defer to Plan 45
- Suggested fix: return the five non-secret credential members (they are not secrets; they can live in PublicConfig) and apply `Fields(r)` projection as tenant settings does.

### Checked, no finding
- **SSRF:**
  - `httpx.GuardedDialer` (internal/httpx/guarded_dialer.go:24-58) rejects the whole DNS answer if any address is non-public.
  - Used by log streams (internal/logstream/sink_http.go:62-107, which also checks literal IPs; vendor sinks go through the same `post`), event streams (internal/eventstream/webhook.go:19-44) and phone (internal/phone/gateway.go:45, testendpoints.go:38).
  - Email HTTP providers and SMTP use their own policy dialer (internal/email/providers/outbound.go). SMTP requires STARTTLS before AUTH.
  - Custom-domain diagnostics pin to checked addresses (internal/customdomain/diagnostics.go:80-128).
  - SNS region is regex-validated (internal/mgmt/phone_providers.go:124,187).
  - No redirects followed and no response bodies stored.
- **Credentials:**
  - Log stream secrets read back as `[REDACTED]`, and PATCH treats the marker as "retain" (internal/logstream/config.go:181,230).
  - Event stream views project only allowlisted public fields (internal/mgmt/event_streams.go:52-81).
  - CAPTCHA is redacted via `keys.PublicCAPTCHA`.
  - Delivery diagnostics hold status classes only.
  - Email subject CR/LF is rejected (internal/email/providers/transport.go:289).
- **Signing keys:** the rotation transaction (internal/store/sqlstore/signing_keys.go:95-160) and revoke-only-`previous` (162-195) are correct. JWKS and Verify use current/next/previous. The signer cache is evicted on rotation and revocation, and signing always reads the current key from the store. Custom JWKS not being published is recorded (matrix.md:65).
- **Counters:** `protection.Service.Begin` (internal/protection/service.go:54-150) is called on hosted login, the password/realm grant, signup (hosted and `/dbconnections`), reset-send, social, org discovery and passwordless. The token bucket refunds non-failures (login), while signup is always charged as a failure, matching `limit_mu` "whether successful or failed". Brute-force success clears prior failures and the lockout is extended on each failure, matching Auth0's "30 days since last failed attempt".
- **Breached passwords:** with the server checker off (the default), enabling `block` fails closed with 503. This is recorded in D-0045, so it is not a finding. It would be worth showing the capability warning in the console.

## Changelog entries reviewed
(after the last logged coverage date, 2026-10-27, plus area-relevant entries just before it)
- 2026-10-30 — Exponential Backoff for Phone MFA SMS Delivery — relevant — **missing**: the setting is stored but has no runtime effect (F1). `limit_phone` itself is emitted.
- 2026-10-29 — HTTP Message Signatures added to Tenant Network ACLs — relevant to `/keys/network-acls` (not implemented) and `acls_summary` (inventory: not emitted) — deferred to Plan 38 (network ACLs).
- 2026-10-27 — Universal Portals Developer Preview — not this area (Plan 42, already recorded).
- 2026-10-26 — Identity Conversion Suite EA — not relevant.
- 2026-10-22 — Configurable unblock mode for brute-force protection — relevant — deferred (open Plan 19 follow-up, changelog-review.md:72). It depends on unblock links, which are also deferred. No API field is documented.
- 2026-10-20 — Bot Detection IPv6 signal analysis — proprietary classifier; already covered by the recorded local risk difference.

## Roadmap suggestions
- Plan 45: implement the exponential phone-send backoff (F1), or explicitly keep it stored-only; tidy brute-force log emission (F4); log sort fields (F5); email provider read projection (F6); refresh the attack-protection docs (F3).
- Plan 47: custom-domain claim arbitration across tenants (F2): proven claims pre-empt unproven ones, failed claims expire, plus an operator override.
- Plan 21 follow-up (admin notifications, unblock links): add the Oct 22 automatic/manual unblock behavior in the same plan, since it only matters once unblock links exist.
- `/keys/encryption*` (BYOK, GA in the OAS) has no owning plan in 35–47. Add it to Plan 38 ("remaining resources") or list it explicitly as out of scope.
