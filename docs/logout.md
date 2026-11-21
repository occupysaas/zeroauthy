# OIDC logout and upstream revocation

Applications can end a browser SSO session through `/oidc/logout` or the
existing `/v2/logout` endpoint. Register allowed post-logout URLs on the
application; an unregistered URL never becomes a redirect target. RP-initiated
logout accepts a verified `id_token_hint`, with the existing confirmation and
CSRF rules when no trustworthy hint is available. Repeating logout is safe.

Configure an application's **OIDC and logout** tab, seed or Management API
`oidc_logout` object to notify its own session store:

```json
{
  "oidc_logout": {
    "backchannel_logout_urls": ["https://app.example.com/backchannel-logout"],
    "backchannel_logout_initiators": {
      "mode": "custom",
      "selected_initiators": ["rp-logout", "idp-logout", "session-revoked"]
    },
    "backchannel_logout_session_metadata": {"include": false}
  }
}
```

Only one receiver is supported, at most 2,048 UTF-8 bytes. It must be HTTPS
without credentials or a fragment. Delivery refuses tenant hosts, Auth0
subdomains, redirects and, by default, private or otherwise non-public
addresses. DNS is checked at each connection. The operator's existing
`logs.streams.allow_private_networks` setting also governs this delivery;
it never disables TLS verification. Use it only for a controlled network.
There is no tenant API switch to relax outbound network checks.

The default subscription is `rp-logout` and `idp-logout`. Custom lists must
include both; `all` selects every implemented trigger, including future
ones. Current additional triggers are `password-changed`, `session-expired`,
`session-revoked`, `account-deleted` and `email-identifier-changed`. The API
also accepts `mfa-phone-unenrolled`, `account-deactivated` and
`profile-changed` as stored subscriptions; their triggers are not implemented.

`{organization_name}` and `{organization_id}` templates resolve from the
latest successfully authorized organization for that client and session.
An authorization without an organization clears that context. Missing or
deleted organization context fails delivery closed; session metadata never
selects the destination. A local session ends even when its eventual
receiver cannot be reached.

Session termination and durable job creation commit together. Delivery runs
asynchronously through the durable job workers, once per participating
session/client pair. Every attempt mints a fresh tenant RS256 logout token,
regardless of the client's ID token algorithm. Tokens have `iss`, `aud`,
`sub`, `sid`, `iat`, an expiry two minutes later, a unique `jti` and the
standard back-channel logout event; no nonce. Their default type is
`logout+jwt`. Opting into session metadata includes the sealed termination
snapshot, or `{}` when empty. Metadata may contain sensitive application
values: include it only for receivers that need it.

A receiver should verify the signature with tenant JWKS, issuer, audience,
times, event and session/user binding before invalidating its session. Return
200 or 204 when accepted. Redirects and 4xx responses end delivery; network
errors and 5xx responses retry for at most ten minutes, with five seconds
allowed per attempt. Terminal logs are `oidc_backchannel_logout_succeeded`
and `oidc_backchannel_logout_failed`; they include the client, initiator and
receiver hostname, never the signed token or full URL. At-least-once job
delivery means receivers must handle duplicate notifications.

The tenant setting `oidc_logout.rp_logout_end_session_endpoint_discovery`
defaults to true. False hides `end_session_endpoint` in discovery while the
endpoint continues to answer. Storage plugins must support `oidc_logout.v1`;
unsupported settings writes fail rather than silently disappearing. Plugin
implementations must also expose the expiry snapshot, organization participant
recording and atomic global-revocation replay/identity interfaces exported by
`pkg/store`; the gRPC RPCs preserve transaction views for these operations.

## Upstream global token revocation

Enterprise OIDC and Okta connections accept
`POST /oauth/global-token-revocation/connection/{connectionName}`. Authenticate
with a Bearer JWT signed using the selected connection's pinned upstream
JWKS. The JWT type must be `global-token-revocation+jwt`, `iss` must match the
pinned issuer, `sub` must equal its configured integration client ID, and
`aud` must be the exact connection-specific revocation endpoint URL without
query or fragment. Include `iat`, an unexpired `exp` no more than five
minutes ahead, and a unique `jti`. Ordinary ID tokens are refused. This
follows the [Auth0-linked Okta profile](https://auth0.com/docs/authenticate/login/logout/universal-logout)
and the [work-in-progress draft](https://www.ietf.org/archive/id/draft-parecki-oauth-global-token-revocation-06.html).

```json
{"sub_id":{"format":"iss_sub","iss":"https://idp.example.com/","sub":"upstream-user-id"}}
```

The optional email form is `{"sub_id":{"format":"email","email":"fixture@example.com"}}`.
Both resolve only identities owned through that connection's federated
identity index. Email never selects an unrelated root account; an ambiguous
match selects nobody. Known and unknown subjects both return 204. Malformed
bodies return 400, invalid/replayed authentication 401, and unknown or
unsupported connections 404. The transaction consumes the replay ID, bumps
the user's version, revokes every refresh token and ends all local sessions,
enqueuing `idp-logout` notifications. Self-contained access tokens continue
until expiry. Outcomes use `universal_logout_succeeded` and
`universal_logout_failed`.

## Explicit compatibility switches

These environment-only switches default off. Set a value to `1` or `true`
to enable; empty, `0` and `false` disable. Other values fail startup. Each
enabled switch produces a startup warning naming the switch.

| Environment variable | Effect |
| --- | --- |
| `ZEROAUTHY_COMPAT__NONCOMPLIANT_IGNORE_CLAIMS_PARAMETER` | Ignore `claims` and omit its discovery support flag. |
| `ZEROAUTHY_COMPAT__NONCOMPLIANT_OPTIONAL_REDIRECT_URI` | When omitted, use the client's sole registered callback only if it contains no wildcard or placeholder. |
| `ZEROAUTHY_COMPAT__NONCOMPLIANT_LOGOUT_TOKEN_TYP_JWT` | Use `JWT` instead of `logout+jwt` in outgoing logout tokens. |

Keep these switches off for conformance runs. See
[D-0080](compat/decisions.md) for the compatibility decisions and
[the implementation record](superpowers/2026-11-16-plan-41a-implementation-record.md)
for actual verification status; implementation is not a certification claim.

Expiry retains the notification snapshot when a browser returns with an expired
cookie; the sweeper drains successive bounded batches with cancellation between
batches. Retired or reassigned session issuer domains suppress only those
notifications, so local account/session changes still commit. Online refresh-token
revocation (including an Action) and operator removal use `session-revoked`.
Replacing the browser's session cookie during a new login is session rotation;
it does not emit logout notifications for the previous authorization session.
