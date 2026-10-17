# Device authorization flow

zeroauthy supports the OAuth 2.0 device authorization grant (RFC 8628) the way Auth0 does, for TVs, consoles, CLIs and other input-limited devices. The device asks `POST /oauth/device/code` for a short user code, shows it, and polls `/oauth/token`. The user opens `/activate` on a phone or computer, enters or confirms the code, signs in, and the device's next poll receives tokens. The design decisions are D-0031 (endpoint and grant), D-0032 (browser path), D-0033 (settings and discovery) and D-0034 (activation limits) in [compat/decisions.md](compat/decisions.md); the observed values are in [compat/observations/device-flow.md](compat/observations/device-flow.md). The design is in `docs/superpowers/specs/2026-10-17-zeroauthy-device-flow-design.md`.

## Setting up a device client

A device client must be a first-party native application that uses no client secret. The seed refuses any other combination at startup.

```yaml
tenants:
  - name: acme
    domains: [auth.example.com]
    clients:
      - client_id: living-room-tv
        name: Living Room TV
        app_type: native
        token_endpoint_auth_method: none
        grant_types: ["urn:ietf:params:oauth:grant-type:device_code", refresh_token]
    connections:
      - name: Username-Password-Authentication
        enabled_clients: [living-room-tv]
```

Add `refresh_token` to `grant_types` if the device should stay signed in, and request `offline_access`. Give the client a client grant (or an API that allows it) for any `audience` it asks for.

## The `device_flow` tenant setting

Both fields are optional. Without them user codes look like `BCDF-GHJK`.

```yaml
tenants:
  - name: acme
    device_flow:
      charset: base20      # base20 (default) or digits
      mask: "****-****"    # * is one character; "-" and " " are separators
```

- `base20` is the 20 letters `BCDFGHJKLMNPQRSTVWXZ`, chosen to avoid easily confused characters. `digits` is `0`-`9`.
- The mask needs at least 8 placeholders for `base20` or 9 for `digits`, and may be at most 20 characters long. Anything else is refused at startup.
- Codes are matched without regard to case or separators, so `bcdfghjk` works for `BCDF-GHJK`.

## What the user sees

1. The device receives `user_code`, `verification_uri` (`https://{host}/activate`), `verification_uri_complete` (the same with `?user_code=` filled in), `expires_in` (900 seconds) and `interval` (5 seconds).
2. The user opens `/activate`, or scans a QR code of the complete URI, which skips typing.
3. A confirmation page shows the code and asks the user to confirm that it matches the device. This page always appears, even with a live session and even through the complete URI, so a link from a stranger cannot sign anyone in silently.
4. The user signs in. An existing browser session is reused without a login page.
5. A consent page appears when the audience needs one, following the same rules as `/authorize` (see [consent.md](consent.md)).
6. A success page tells the user to return to the device. Declining at the confirmation or consent page shows a denied page, and the device's next poll is `access_denied`.

The four screens use the usual hosted-page language catalog and the `device-code-activation`, `device-code-confirmation`, `device-code-activation-allowed` and `device-code-activation-denied` custom text prompts.

## Polling and tokens

The device polls `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code` and `client_id`.

| Answer | Meaning |
|---|---|
| `403 authorization_pending` | The user has not finished. Poll again after `interval`. |
| `429 slow_down` | The poll came less than 1 second after the last poll that was not answered `slow_down`. |
| `403 access_denied` | The user declined. Reported once; later polls are `invalid_grant`. |
| `403 expired_token` | The code expired. Reported on the first poll after expiry; later polls are `invalid_grant`. |
| `403 invalid_grant` | Unknown, wrong-client or already-used code. |
| `200` | Tokens, once. |

Device tokens are not tied to the browser session: the ID token has no `sid` or `auth_time` (and no `at_hash`), and logging out in the browser does not sign the device out.

Browser-based device software (for example a TV app built on web technology) can call `/oauth/device/code` and `/oauth/token` cross-origin if one of the tenant's clients lists the page's origin in `web_origins` or `allowed_origins`, as with Auth0's Allowed Web Origins.

## Refresh tokens for TV apps

With `offline_access` and the `refresh_token` grant, the device receives a rotating refresh token and can renew its access token without the user. Store it in the device's secure storage. To force a device to sign in again, revoke its refresh token with `POST /oauth/revoke`; the next refresh fails and the device must start a new device flow. There is no listing of tokens yet; that arrives with the Management API (sub-project 3).

## Activation limits

A user code is only a pointer to a login the guesser would have to complete as themselves, and tokens go only to the poller holding the long `device_code`. The limits below still stop code guessing at `/activate`. Only wrong, unknown or expired codes count: a successful entry and an empty submission are refunded, and a request refused because of the IP limit does not count against the tenant. All state is in-process, so each server instance counts on its own.

| Limit | Default | Config keys under `security` |
|---|---|---|
| Wrong codes per sign-in attempt (the transaction is then discarded) | 5 | `device_activation_txn_max_misses` |
| Wrong codes per IP, then that IP is locked | 10 per 900 s, lockout 900 s (the window equals the lockout) | `device_activation_ip_max_misses`, `device_activation_ip_lockout_seconds` |
| Wrong codes per tenant, then the tenant is locked | 1,000 per 600 s, lockout 60 s | `device_activation_tenant_max_misses`, `device_activation_tenant_window_seconds`, `device_activation_tenant_lockout_seconds` |

Set an IP or tenant maximum to 0 to switch that limit off. The transaction limit must be at least 1, and the other values must be positive while their limit is on. Behind a proxy, make sure the server sees the real client IP, or the IP limit counts everyone together.

The IP limit counts IPv6 clients by their /64 prefix, since one host usually holds a whole /64 and could otherwise rotate addresses without limit; IPv4 addresses (including IPv4-mapped IPv6) count one by one. The tenant limit trades availability for guess resistance: many sources together can keep `/activate` locked for the whole tenant for the lockout period. Operators who prefer availability can switch it off with `device_activation_tenant_max_misses: 0` and rely on the per-IP and per-transaction limits. These numbers are zeroauthy's own (D-0034); Auth0 does not publish its.

## Using it from auth0.net

`Auth0.AuthenticationApi` (tested with 7.49.0) works unchanged:

```csharp
var client = new AuthenticationApiClient(new Uri("https://auth.example.com"));
var start = await client.StartDeviceFlowAsync(new DeviceCodeRequest {
    ClientId = "living-room-tv", Audience = "https://api.example.com", Scope = "openid offline_access" });
// show start.UserCode and start.VerificationUri, then:
var tokens = await client.GetTokenAsync(new DeviceCodeTokenRequest {
    ClientId = "living-room-tv", DeviceCode = start.DeviceCode });  // repeat every start.Interval seconds
```

The repository's end-to-end test (`tests/e2e/dotnet-device`, driven by `tests/e2e/m10-device.spec.mjs`) runs this client in a container against a real server with Chromium doing the browser half. It needs podman on the host.

## Differences from Auth0

- The activation limits are zeroauthy's own numbers (D-0034).
- `expired_token` is answered on the first poll after expiry at any time while the record is kept (24 hours). Auth0 stops answering it after a window of seconds to minutes (D-0031).
- `slow_down` is decided by a fixed 1-second gap; Auth0's exact algorithm is not observable without load testing, which the clean-room rules forbid (D-0031).
- Not yet supported: Management API access to `device_flow`, the tenant log events for the device flow, Actions and Rules for the `oauth2-device-code` protocol, a rate limiter on `/oauth/device/code`, and throttle state shared between instances. See "Plan 11 follow-ups" in `docs/superpowers/plan-1-followups.md`.
