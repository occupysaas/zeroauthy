# My Account API

The My Account API lets a signed-in user manage their own authentication
methods from your application: list them, enroll a passkey, a security
key, a TOTP app, an email or phone second factor or a recovery code,
rename them, change their password, and delete them (Plan 42a, D-0210). It
follows Auth0's My Account API (OpenAPI 1.0) at `https://{host}/me/v1`;
zeroauthy's contract is [`api/myaccount.yaml`](../api/myaccount.yaml).

Served: `GET /factors`, `GET|POST /authentication-methods`,
`GET|PATCH|DELETE /authentication-methods/{id}` and
`POST /authentication-methods/{id}/verify`. Not served: connected accounts
(Token Vault, Plan 43), consents and consent signing keys (Early Access at
Auth0) and the profile routes (beta).

## Activate it

Activation creates the tenant's system API `https://{canonical host}/me/`,
named `Auth0 My Account API`, with user access `require_client_grant` and
machine-to-machine access `deny_all`:

- **Console:** APIs → **My Account API** → **Activate**. Deactivate it from
  the API's **Danger zone**.
- **Management API:** `POST /api/v2/resource-servers` with
  `{"identifier": "https://{canonical host}/me/"}` (other fields are
  ignored); `DELETE /api/v2/resource-servers/{id}` deactivates.
- **Seed:** `my_account_api: {active: true}` on the tenant (a local
  shorthand; `false` removes it).

While it is not active, `/me/v1` answers `404`.

Its name, scopes and user policy are fixed. Token lifetimes and consent
skipping can change, as for the Management API; the Deploy CLI's system-API
updates are accepted.

## Give an application access

Each application needs a **user** client grant for the API with the
scopes it may request:

| Scope | Operations |
|---|---|
| `read:me:authentication_methods` | `GET /authentication-methods`, `GET /authentication-methods/{id}` |
| `create:me:authentication_methods` | `POST /authentication-methods`, `POST .../{id}/verify` |
| `update:me:authentication_methods` | `PATCH /authentication-methods/{id}` |
| `delete:me:authentication_methods` | `DELETE /authentication-methods/{id}` |
| `read:me:factors` | `GET /factors` |

In the console, open the application's **APIs** tab → **My Account API** →
**Allow user access**, then choose the scopes. With the Management API:

```sh
curl -X POST https://$TENANT/api/v2/client-grants \
  -H "authorization: Bearer $MGMT_TOKEN" -H 'content-type: application/json' \
  -d '{"client_id":"'$CLIENT_ID'","audience":"https://'$TENANT'/me/","subject_type":"user","scope":["read:me:authentication_methods","create:me:authentication_methods"]}'
```

In a seed:

```yaml
client_grants:
  - {client_id: my-spa, audience: "https://login.example.com/me/", subject_type: user, scopes: [read:me:authentication_methods, create:me:authentication_methods]}
```

Browser applications call the API cross-origin: list their origin in the
application's `web_origins` or `allowed_origins`.

## Get a token

Request the audience `https://{host}/me/` with the authorization code flow
(with or without PKCE), the password grants or the native passkey grant.
Client credentials and custom token exchange are refused (`access_denied`).
Use one host throughout: a token issued on the canonical host is refused on
a custom domain and the reverse, because each host's audience is its own.

```js
const client = new auth0.Auth0Client({
  domain: 'login.example.com', clientId: 'my-spa',
  authorizationParams: {redirect_uri: location.origin, audience: 'https://login.example.com/me/',
    scope: 'openid profile read:me:authentication_methods create:me:authentication_methods'},
});
const token = await client.getTokenSilently();
const r = await fetch('https://login.example.com/me/v1/authentication-methods', {headers: {authorization: 'Bearer ' + token}});
```

Requiring a recent MFA for these tokens, as Auth0's Early Access
"Authentication Assurance" policy does, is done with a post-login Action
(`api.authentication.challengeWith`) when the audience is the My Account
API.

## Enroll a method

`POST /authentication-methods` starts an enrollment and answers `202` with
an `auth_session`; `POST /authentication-methods/{id}/verify` finishes it
with that value and answers `201` with the method. An `auth_session` is
single use, belongs to the user, the application and the method, and
expires after five minutes; a wrong code spends it (start again).

| `type` | Start returns | Verify sends |
|---|---|---|
| `totp` | `id`, `barcode_uri`, `manual_input_code` | `otp_code` |
| `email` | `id` (a code is sent to `email`, which must be the user's verified email) | `otp_code` |
| `phone` | `id` (a code goes to `phone_number` by `preferred_authentication_method` `sms` or `voice`) | `otp_code` |
| `recovery-code` | `id`, `recovery_code` (shown once; replaces an earlier one at verify) | `auth_session` only |
| `passkey` | `authn_params_public_key` (Location `passkey|new`) | `authn_response` (the registration credential) |
| `webauthn-roaming`, `webauthn-platform` | `id`, `authn_params_public_key` | `authn_response` |
| `password` | `id` `password|new`, the connection's `policy` | `new_password` |

- A factor the tenant has not enabled, and `push-notification`, answer
  `400` with `type` `factor_not_enabled`.
- Passkeys need passkeys enabled on the user's database connection (see
  [Passkeys](passkeys.md)); `connection` and `identity_user_id` choose the
  identity when the user has several. The RP ID is the host's; the
  ceremony may run on the host or on an application origin listed in
  `web_origins` under the RP ID. The per-user passkey limit answers `409`.
- A platform authenticator needs another usable factor first, as in
  hosted MFA.
- A password change runs the connection's complete password policy,
  history and breached-password checks, then ends the user's sessions and
  refresh tokens, drops open reset links and runs post-change-password
  Actions, as a reset does. Custom-database (non-import) connections
  answer `400`.

## Rename and delete

`PATCH` sets `name` (at most 100 characters) on passkeys, WebAuthn keys and
TOTP, email and phone methods, and `preferred_authentication_method` on
phone methods. `DELETE` removes a method; the user's last way to sign in
(their only password without a passkey, or their only passkey without a
password) answers `409`. Second factors can always be deleted; a user
under an "always" MFA policy enrolls again at the next login.

Method IDs are the Management API's (`/api/v2/users/{id}/authentication-methods`),
so both APIs name a method alike; passwords, which the Management API does
not list, are `password|{base64url(identity user ID)}`.

## Errors

Errors carry `type`, `status`, `title`, `detail` and, for invalid fields,
`validation_errors`, with the `x-correlation-id` header (your request's,
or zeroauthy's request ID). `401`: no or invalid token, another host's
token, a client token. `403`: the token lacks the operation's scope.

OTP codes, TOTP secrets, recovery codes, attestations, `auth_session`
values and passwords are never logged.

## Logs

Enrollments record the MFA log types (`gd_start_enroll`,
`gd_enrollment_complete`, `gd_unenroll`, `gd_update_device_account`) with
the application's client ID; a password change records `scp`.
