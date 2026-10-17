# zeroauthy — Design: Device Authorization Flow (Plan 11)

- **Status:** Draft, awaiting review
- **Date:** 2026-10-17
- **Scope:** milestone 10, part 3 of 3 (spec §13). Plan 9 shipped consent, Plan 10 shipped PAR. This plan ships the RFC 8628 device authorization flow with Auth0 parity, server side only.

## 1. Goal

An input-constrained device (a TV app, a set-top box, a CLI) asks zeroauthy for a code, shows the user a short URL and a short code, and polls the token endpoint. The user opens the URL on a phone or computer, enters the code, confirms it matches the device, signs in, approves on the consent page, and the device receives tokens. The maintainer's motivating case is a video streaming site whose TV app signs viewers in this way and keeps them signed in with refresh tokens.

**Success:**
- The unmodified `auth0.net` Authentication API client (`StartDeviceFlowAsync`, then `GetTokenAsync(DeviceCodeTokenRequest)` in a poll loop) receives an access token, an ID token and a refresh token from zeroauthy while Chromium plays the user: `/activate`, code entry, confirmation, login, consent, success page.
- The refresh token rotates and revokes like any other (Plan 3). Revoking it forces the device to sign in again.
- A bot cannot guess a live user code in practice (§5).

**Anti-goals:**
- Anything that makes the code-entry URL hard to type by hand. `verification_uri` stays a short, fixed path.
- Weakening the protections against phishing: the confirmation screen ("does your device show this code?") always shows, and every page in the browser path names the client. When the consent page itself appears follows Auth0 (D4), not a stricter rule of our own.
- Building a second rate-limit mechanism next to `identity.Throttle`.

## 2. Sources (clean room)

Auth0 public documentation:
- Device Authorization Flow (overview, browser path, reauthorization by revoking the refresh token)
- Call Your API Using the Device Authorization Flow (requests, responses, errors, prerequisites, limitations, log event codes)
- Configure Device User Code Settings
- Advanced Customization for Universal Login (ACUL) screen references: `device-code-activation`, `device-code-confirmation`, `device-code-activation-allowed` (and the matching denied screen), used for screen and `custom_text` names only

Also RFC 8628 (OAuth 2.0 Device Authorization Grant), RFC 8414 (`device_authorization_endpoint` metadata), the Management API tenant settings schema as published in the open-source SDKs (`device_flow: { charset: "base20" | "digits", mask: string }`), the `auth0.net` Authentication API client source (MIT), and observations on the maintainer's trial tenant (§7), under `CLEAN_ROOM.md` "Behavior testing against the maintainer's own tenant".

Documented facts this design follows:
- `POST /oauth/device/code`, form-encoded, parameters `client_id`, `scope`, `audience`.
- `200` with `device_code`, `user_code`, `verification_uri`, `verification_uri_complete` (the same URL with `?user_code=…`), `expires_in` (900), `interval` (5).
- `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id`.
- Polling errors: `authorization_pending` (403), `slow_down` (429), `expired_token` returned once and then `invalid_grant` on every later poll, `access_denied` (403) when the user declines or a policy refuses.
- Success: `access_token`, `id_token` only with `openid`, `refresh_token` only with `offline_access` and an API with `allow_offline_access`.
- Clients must be Native, use token endpoint authentication `none`, have the device code grant enabled, and must not be dynamically registered. Confidential clients are not supported.
- User code: character set and mask are tenant settings. Minimum length 8 for base20, 9 for digits; maximum 20 including separators. The code expires after 15 minutes.
- The browser path: enter the code (skipped when it arrives through `verification_uri_complete`), confirm the device shows that code, log in, consent if needed.
- Auth0 rate-limits this flow but publishes no numbers.

## 3. Data model

Seed YAML uses Auth0 Management API property names.

| Entity | Additions (default) |
|---|---|
| `Tenant` | `device_flow.charset` (`base20`, D2), `device_flow.mask` (`****-****`, D2). |
| `Client` | The grant type `urn:ietf:params:oauth:grant-type:device_code` in `grant_types` (already accepted by the seed; Plan 9 refuses it for strict third-party clients). |
| `DeviceCode` (new) | `TenantID`, `DeviceCodeHash`, `UserCodeHash` (`secrets.HashToken` of the normalized user code), `ClientID`, `Scope`, `Audience`, `Status` (`pending`, `approved`, `denied`, `consumed`), `UserID`, `SessionID`, `GrantedScope`, `Interval` (seconds, grows with `slow_down`), `LastPolledAt`, `ExpiredReportedAt`, `ExpiresAt`, `CreatedAt`. |

Both codes are stored only as SHA-256 hashes (core spec §4). A user code is normalized before hashing: separators removed, letters upper-cased. That makes entry case-insensitive and lets separators be typed or skipped.

New repository `DeviceCodes`, keyed by (`TenantID`, `DeviceCodeHash`), with `UserCodeHash` unique among live codes in a tenant:
- `Create` returns `ErrConflict` if either hash exists. The caller regenerates the user code and retries a few times.
- `GetByUserCode(tenantID, userCodeHash)` for the browser path.
- `Decide(tenantID, deviceCodeHash, status, userID, sessionID, grantedScope)` moves `pending` to `approved` or `denied` atomically. Any other starting status returns `ErrAlreadyUsed`.
- `Poll(tenantID, deviceCodeHash, at)` atomically records the poll and returns the record together with whether it came too early. Too early (less than `Interval` after `LastPolledAt`) also adds 5 seconds to `Interval` (RFC 8628 §3.5). For an `approved` record that is not too early, the status moves to `consumed` in the same step, so exactly one poll receives tokens. For an expired record, the first poll sets `ExpiredReportedAt`.
- `DeleteExpired(before)` removes expired records in every tenant. The sweeper calls it with a 24-hour retention, as it does for authorization codes (`codeRetention`), so a device polling an expired code still gets `expired_token` once instead of a premature `invalid_grant`.

It is implemented in the memory, sqlite, postgres and mysql drivers (migration 0005) and the gRPC plugin protocol (new `DeviceCodes` RPCs; new tenant proto fields). storetest covers it on all five.

Seed validation:
- A client with the device code grant must be `app_type: native` and use `token_endpoint_auth_method: none` (documented prerequisites). A seed that breaks this is rejected at startup, like every other seed rule; nothing is dropped silently. Existing seeds in the repo (tests, examples, E2E) are updated in the same task. Permissive third-party clients may have the grant unless D11 shows otherwise; strict ones stay refused (Plan 9).
- `device_flow.charset` is `base20` or `digits`. `device_flow.mask` contains only `*` placeholders and the separators D2 confirms (default: `-` and space). Placeholder count is at least 8 (base20) or 9 (digits), and total length is at most 20.

The base20 alphabet is `BCDFGHJKLMNPQRSTVWXZ` (consonants without easily confused letters, as RFC 8628 §6.1 suggests), unless D2 shows otherwise. Code lifetime (900 s) and starting interval (5 s) are constants, as on Auth0.

## 4. Behaviour

### 4.1 `POST /oauth/device/code` (`internal/oauth`)

1. Form-encoded body. Repeated parameters are refused with `400 invalid_request`.
2. `client_id` must name a client with the device code grant. Unknown client: `401 invalid_client`. Grant not enabled, or a confidential client: D3 (default `400 unauthorized_client`).
3. `scope` and `audience` are validated the way `/authorize` validates them before login: default audience, unknown audience, offline access. Checks that need the user (access policies, user grants, blocked users) run after login, as at `/authorize` (§4.2 step 5). Refusals here are `400` JSON with the code `/authorize` uses for the same case (D3).
4. Generate a 43-character random `device_code` (`secrets.RandomString`) and a user code from the tenant's charset and mask, then store both hashed.
5. Respond `200` with `Cache-Control: no-store`: `device_code`, `user_code` (formatted with the mask), `verification_uri` (`https://<tenant host>/activate`), `verification_uri_complete` (`…/activate?user_code=<formatted code>`), `expires_in: 900`, `interval: 5`.

### 4.2 Browser path (`internal/login`)

`GET /activate` starts a device transaction: a new `AuthTransaction` bound to the browser cookie, the same single-use `state` mechanism the login pages use, then a redirect to the code-entry page. With `?user_code=…` the code is checked straight away and the user goes to confirmation. The exact paths and redirect shape follow D1; the working names are `/u/device` (entry) and `/u/device/confirm`.

1. **Code entry.** The user types the code. The submit runs the rate limits (§5) before looking the code up. An unknown, expired or already-decided code shows an error on the same page and counts as a miss.
2. **Confirmation.** The page shows the code and asks the user to confirm their device displays it. Declining marks the device code `denied` and shows the denied page. Confirming stores the device code hash in the transaction and continues.
3. **Login.** The normal hosted login. Whether an existing browser session is reused silently, as at `/authorize`, or the user must sign in again or pick the account follows D10 (default: silent reuse, as at `/authorize`). The device flow runs through the same login page, connections and custom DB scripts as `/authorize`.
4. **Consent.** Plan 9's `internal/access.Decide` decides whether consent or confirmation is needed, with a new device flow kind. A device transaction has no redirect URI, so the device kind needs its own rules rather than the redirect-URI verifiability check. Its defaults, which D4 confirms or replaces: the client counts as non-verifiable, an existing user grant covering the scopes skips consent, and a first-party client with no audience gets no consent. Declining marks the device code `denied`.
5. **Done.** The device-code repository's `Decide` marks the code `approved` with the user, session and granted scope, and the user sees the success page. Policy refusals (access policies, blocked user) mark it `denied` and show the denied page.

**Completing the flow.** Today `login.complete` calls `authz.Resume`, and `ConsentSubmit` calls `authz.Consent`. Both validate the request again as an `/authorize` request and end with a redirect: either `issueCode` or `deny`. The plan refactors this so the transaction records its flow kind (`authorize` or `device`). The shared steps (session reuse, login, the access decision, consent, recording user grants) are written once. Only the last step differs: `/authorize` issues a code or redirects with an error, and the device flow calls `Decide` on the device code and renders the success or denied page. `/u/consent` keeps its handler and template. For a device transaction, the template shows the client's name and logo and drops the callback-domain line, since there is no callback.

The new pages (entry, confirmation, success, denied) are server-rendered like the existing ones and use the Plan 4 i18n catalog. `i18n.ValidateCustomText` rejects keys missing from the English catalog, so the catalog must hold Auth0's exact prompt name and each screen's key names. A plan task takes them from Auth0's public docs (the ACUL screen references and the custom text docs), records the source in the catalog commit, and adds English text for each key in our own words.

### 4.3 Token endpoint

`grant_type=urn:ietf:params:oauth:grant-type:device_code` with `client_id` and `device_code`. The client must be the one the code was issued to (`invalid_grant` otherwise) and still have the grant.

| State at `Poll` | Response |
|---|---|
| Too early | `429 slow_down` |
| `pending` | `403 authorization_pending` |
| `denied` | `403 access_denied` |
| Expired, first poll after expiry | `expired_token` (status per D5) |
| Expired again, consumed, or unknown | `invalid_grant` (status per D5) |
| `approved` | `200` tokens, built by the same token issuer as the authorization code grant, for the stored user, session and granted scope |

Refresh tokens issued here are ordinary Plan 3 refresh tokens: rotation, reuse detection and revocation apply unchanged.

### 4.4 Discovery

The discovery document lists `device_authorization_endpoint` and includes the device code grant in `grant_types_supported`, as D6 confirms.

## 5. Abuse protection

Guessing a user code does not leak tokens: tokens go only to the poller holding the 43-character `device_code`, which is never displayed. A successful guess would sign the guesser's own account into a stranger's device. The serious device-flow attack is phishing in the other direction (a victim enters an attacker's code), and the confirmation screen and consent page address that. Guessing is still prevented, in layers:

- **Code space.** At least 20⁸ ≈ 2.6 × 10¹⁰ (base20) or 10⁹ (digits) codes.
- **Lifetime.** 15 minutes. Slow users are unaffected because only misses count.
- **Per transaction.** A miss counter stored on the device transaction. After 5 misses the transaction is deleted, and the user must start again from `/activate`. This is a counter, not a throttle.
- **Per IP.** After 10 misses within 15 minutes, code entry from that IP is locked for 15 minutes.
- **Per tenant.** After 1,000 misses within 10 minutes, code entry for the whole tenant is locked for 1 minute, which slows a bot spread over many IPs. This lets an attacker delay legitimate activations, so the ceiling is high and the lockout short. Operators can raise it or switch it off.

The per-IP and per-tenant limits use `identity.Throttle`, so they are in-process: each server instance counts separately, as for login throttles today. `Attempt` runs before the lookup, as `Throttle` requires, and a successful lookup calls `Refund`, so only misses count. `Throttle` gains a disabled mode (a nil or zero-max throttle always allows). Config validation accepts 0 for the device thresholds to mean "off", and keeps rejecting negatives. Today `NewThrottle` turns a max below 1 into 1, which must not happen for these settings. Thresholds live in server config next to the login throttles (`security.device_activation_*`), not per tenant. They are zeroauthy's own defaults, recorded as a deliberate decision, because Auth0 publishes no numbers and the clean-room rules forbid probing the tenant with load.

Polling has its own protection through `slow_down` (§4.3). `POST /oauth/device/code` has no limit beyond the general follow-up for an Authentication API rate limiter (Plan 10 recorded the same gap).

## 6. Defaults for undocumented points

Each point has a default from RFC 8628 and the docs. Observation (§7) confirms or replaces it, and every outcome gets a decision (D-0031 onward) and a matrix note.

| # | Point | Default |
|---|---|---|
| D1 | Path and redirect shape of `/activate`, the entry and confirmation pages; whether `verification_uri_complete` still shows confirmation | `/activate` → `/u/device?state=…`; confirmation always shows |
| D2 | Default charset and mask; base20 alphabet; allowed separators; case-insensitive entry | `base20`, `****-****`, alphabet as in §3, `-` and space, case-insensitive |
| D3 | `/oauth/device/code` with a client lacking the grant, a confidential client, an unknown audience, an audience refused by an access policy | `unauthorized_client`; `unauthorized_client` (both with the token endpoint's existing 403); unknown audience `403 access_denied`; access policies checked only after login |
| D4 | Consent in the device flow: a first-party client on an API that skips consent for verifiable first-party clients; a returning user with a grant; a first-party client with no audience | Consent shows (device clients are non-verifiable); no consent (grant covers it); no consent |
| D5 | HTTP status of `expired_token` and later `invalid_grant` | `400` for both |
| D6 | Discovery fields | `device_authorization_endpoint` present; grant in `grant_types_supported` |
| D7 | Wrong code, expired code, reused code, empty submit on the entry page | Same page with Auth0's documented message keys: `invalid-code`; `invalid-expired-code`; `invalid-expired-code`; `no-code` |
| D8 | Declining at confirmation vs at consent: device poll result | `access_denied` in both cases |
| D9 | The `interval` returned after `slow_down`, and whether polls between `pending` responses are measured from the last response | +5 s per `slow_down`; measured from the last poll |
| D10 | Code entered in a browser that already has a session | Silent reuse, as at `/authorize` (confirmation still shows) |
| D11 | A permissive third-party Native client with the device grant | Allowed; consent always shows |

## 7. Tenant observation (first task)

The first task writes `docs/compat/observations/device-flow.md` with exact steps: a curl script for `/oauth/device/code` and polling, and browser steps for `/activate`. The maintainer creates a Native client with the device grant on the trial tenant, runs the steps, and reports only status codes, `error` values, URL paths and shapes, screen types and the order they appear in. No messages, credentials, tenant identifiers or personal data are recorded. Later tasks use the observed values. No load: at most a handful of wrong codes, and polling at a normal pace with one deliberate early poll for D9.

## 8. Testing

- **Unit:** user code generation (charset, mask, normalization, length limits), `/oauth/device/code` validation table, the token-endpoint state table in §4.3, the three throttles, seed validation, discovery fields.
- **storetest:** `DeviceCodes` conformance on memory, sqlite, postgres, mysql and gRPC, including concurrent `Poll` on an approved code (exactly one caller gets `consumed`), concurrent `Decide`, user code uniqueness, `slow_down` interval growth, `ExpiredReportedAt` set once, `DeleteExpired`.
- **E2E (new m10-device suite):**
  - `auth0.net` (pinned version, run in a podman .NET SDK container) starts the flow and polls; Chromium opens `verification_uri`, enters the code, confirms, logs in, accepts consent. The test asserts the access, ID and refresh tokens, then refreshes once.
  - Chromium through `verification_uri_complete`: entry is skipped, confirmation shows.
  - Negative: decline at confirmation gives `access_denied` to `auth0.net`; a wrong code shows the entry error; six misses kill the transaction.
- `docs/compat/blackbox-clients.md` gains the `auth0.net` row.

## 9. Documentation

- `docs/device-flow.md` guide: client setup, tenant code format, the browser path, refresh tokens for TV apps, abuse protection settings.
- Matrix rows for the endpoint, the grant, the tenant setting and the screens; decisions D-0031 onward, including the rate-limit defaults as a deliberate deviation.
- Core spec §6 and §13 updated: milestone 10 complete.
- Changelog review log row for this plan.
- Follow-ups in `plan-1-followups.md`:
  - A sample Android TV app (Android Studio TV emulator, then a Fire TV) as its own plan.
  - `auth0-cli` as a device-flow client. Its login is hardcoded to `auth0.auth0.com`, its own client ID and issuer, so testing it means pointing that host at zeroauthy inside a container with a trusted test certificate.
  - An Authentication API rate limiter covering `/oauth/device/code`.
  - Shared (cross-instance) throttle state.

## 10. Out of scope

The Android TV app, `auth0-cli` as a client, confidential device clients, Management API endpoints for `device_flow` (sub-project 3; seed only for now), Actions and Rules hooks (`oauth2-device-code` protocol), tenant log events (`fdeaz`, `fdeac`, `fdecc`, `fede`, `sede`) until logs exist, and account linking.
