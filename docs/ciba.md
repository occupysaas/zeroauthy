# Client-Initiated Backchannel Authentication (CIBA)

CIBA lets a backend ask a user to approve a sign-in on another device, as
Auth0 does (OpenID CIBA Core 1.0, poll mode). The application's backend
calls `/bc-authorize`. zeroauthy emails the user a link, and the user opens
it, signs in and approves or denies. Meanwhile the backend polls
`/oauth/token` until it receives tokens.

zeroauthy delivers requests by **email** only. Auth0's default channel, Guardian
push, needs Auth0's Guardian app and is stored but not delivered. The
decisions are D-0100 in [compat/decisions.md](compat/decisions.md); the open
questions about Auth0's behaviour are C41-1…8 in the
[plan 1 follow-ups](superpowers/plan-1-followups.md#plan-41c-observation-points).

## Configuring an application

CIBA is for **first-party, confidential** applications (any authentication
method except `none`: client secret or `private_key_jwt`). Give the
application the grant and the email channel:

```yaml
tenants:
  - name: acme
    clients:
      - client_id: agent-backend
        app_type: regular_web
        client_secret: change-me
        grant_types: [authorization_code, refresh_token, "urn:openid:params:grant-type:ciba"]
        async_approval_notification_channels: [email]
```

In the Management API, `PATCH /api/v2/clients/{id}` with the same fields.
In the console, use the application's **Advanced** tab. A CIBA
application whose channels do not include `email` is refused, because
`guardian-push` and `my-account` are stored only.

The user must have a **verified email**. The email uses the tenant's
`async_approval` template when it is enabled (Liquid variables
`application.name`, `url`, `binding_message`, plus the standard ones), and
otherwise a built-in one. Set up an email provider as for any other email
(see [email](email.md)).

## Starting a request

```sh
curl -sS https://auth.example.com/bc-authorize \
  -d client_id=agent-backend -d client_secret=change-me \
  --data-urlencode 'login_hint={"format":"iss_sub","iss":"https://auth.example.com/","sub":"auth0|65f0c2"}' \
  -d scope='openid email' -d binding_message=ORDER-42 -d requested_expiry=600
```

```json
{"auth_req_id": "…", "expires_in": 600, "interval": 5}
```

| Parameter | Rule |
|---|---|
| `login_hint` | Auth0's JSON form; `iss` is this tenant's issuer on the host you call, `sub` the user ID. `id_token_hint` and `login_hint_token` are refused. |
| `scope` | Must contain `openid`. `offline_access` adds a refresh token (if the application has the refresh grant). |
| `binding_message` | Required, 1 to 64 letters, digits and `+-_.,:#`. The user sees it in the email and on the approval page and checks that it matches what the application shows. |
| `requested_expiry` | Seconds. Email needs 301 to 259200 (72 hours), as on Auth0. The default, 300, is Auth0's push window, so without push you must send a longer expiry. |
| `audience` | An API identifier; the tenant's default audience when absent. |
| `request` | A signed request object (JAR) carrying the parameters, verified with the application's `signed_request_object` credentials. |

`authorization_details` and `user_code` are refused. Every request gets
the same answer, whether the user exists, has no verified email, or is
valid. A request that cannot be delivered is simply never approved and
ends as `access_denied` when it expires, so the endpoint does not reveal
which user IDs exist.

Limits are 500 requests per minute and 5000 pending per tenant (an expired
request counts for 24 hours), and 5 requests per minute per user. Beyond
them the answer is `429 too_many_requests`. Counters are per process.

## Approval

The email links to `https://<the host you called>/bc-verify?consent=…`.
The page shows the application, the binding message and the scopes:

- **Approve** signs the user in. An existing session counts only if it
  belongs to the requested user; a session of someone else starts a new
  login. Then MFA (per the tenant's policy) and post-login Actions run.
  Actions see `event.transaction.protocol` `oidc-ciba-web-link`, and
  `api.access.deny` denies the request. Signing in as anyone other than
  the requested user decides nothing.
- **Deny** records the denial.

The link works until the request is decided or expires. No consent grant
is stored, and existing grants are not checked.

## Polling

```sh
curl -sS https://auth.example.com/oauth/token \
  -d grant_type=urn:openid:params:grant-type:ciba \
  -d client_id=agent-backend -d client_secret=change-me -d auth_req_id=…
```

| Answer (HTTP 400) | Meaning |
|---|---|
| `authorization_pending` | The user has not decided yet. |
| `slow_down` | You polled within `interval`; the body's `interval` is the new one (5 seconds more each time). |
| `access_denied` | The user denied the request, or it expired (Auth0 uses one error for both). |
| `invalid_grant` | Unknown, already redeemed, or another application's request. |

After approval the poll returns the tokens once: an ID token, an access
token for the request's audience with the scopes approved, and a refresh
token when `offline_access` was requested.

`auth_req_id` and the link value are stored only as hashes and never
logged. The log events are `ciba_start_succeeded`, `ciba_start_failed`,
`ciba_exchange_succeeded` and `ciba_exchange_failed`.

## Not supported

Guardian push and My Account delivery, ping and push token delivery,
Rich Authorization Requests and `user_code`. The OpenID Foundation has no
CIBA OP certification profile except FAPI-CIBA, which zeroauthy does not
run.
