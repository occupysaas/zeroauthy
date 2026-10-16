# Consent, third-party applications and API access policies

zeroauthy follows Auth0's model for who may get tokens for an API and when the user has to agree first. Applications are first-party or third-party; each API has an access policy for users and for machines; users consent to what an application receives and the choice is remembered; and logins to callbacks that cannot be verified ask for a confirmation. Settings use Auth0's option names, so seed files written from Auth0's Management API objects load as they are. The design decisions are D-0025 (third-party modes and access policies), D-0026 (consent and user grants) and D-0027 (confirmation, `prompt=none` and redirection policy) in [compat/decisions.md](compat/decisions.md); the values come from [compat/observations/consent.md](compat/observations/consent.md). The design is in `docs/superpowers/specs/2026-10-16-zeroauthy-consent-design.md`.

## First- and third-party applications

`is_first_party` defaults to `true`. Set it to `false` for an application that another organization runs. A third-party client cannot be turned into a first-party one, or the other way round, and its `third_party_security_mode` cannot change either; applying a seed that does so fails with "cannot change after creation". Use a new `client_id`.

Third-party clients have a security mode:

| | `strict` (default) | `permissive` |
|---|---|---|
| Grant types | Only `authorization_code`, `refresh_token`, `client_credentials` (the seed refuses others) | Any except `password` and password-realm |
| PKCE | Required, for every client type | As for first-party clients |
| `claims`, `id_token_hint`, `login_ticket`, `request`, `request_uri`, `screen_hint` on `/authorize` | `invalid_request` | Accepted |
| Audience on `/authorize` | Required (`invalid_request` without it) | Optional |
| OIDC scopes (`openid`, `profile`, `email`) | Dropped, so no ID token is issued | Issued |
| Client grant | A `user` client grant is always required | Follows the API's policy (see below) |
| Refresh tokens | Must expire; native apps default to rotating | As for first-party clients |
| `client_credentials` | Needs a confidential client | |

Strict clients default to expiring refresh tokens; an explicit `refresh_token.expiration_type: non-expiring` is rejected by the seed, even for a client without the `refresh_token` grant.

A stored third-party client whose mode is empty or unknown is treated as `strict`. Permissive mode could not be observed on Auth0 (the maintainer's account cannot create such clients), so its behaviour follows Auth0's permissive-mode page; strict behaviour was observed.

All third-party clients:

- cannot use the `password` or password-realm grants. The seed refuses them in `grant_types`, and the token endpoint answers `unauthorized_client` if one gets through;
- cannot be listed in a connection's `enabled_clients` (the seed refuses it, as Auth0's Management API does) and log in only through domain connections (see "Domain connections");
- are refused `organization` and `invitation` on `/authorize` like every other client, until Organizations exist.

### Redirection policy

`redirection_policy` is `open_redirect_protection` or `allow_always`. The default is `open_redirect_protection` for third-party clients and `allow_always` for first-party clients.

Under `open_redirect_protection`, every `/authorize` error that happens after the client and redirect URI are validated is shown on an error page with HTTP 400 and is not sent to the application. That includes `login_required`, `consent_required`, `invalid_request` and a declined consent. Under `allow_always` the error goes back to the redirect URI as `error` and `error_description`.

This is why silent authentication (`prompt=none` in an iframe) cannot work for a protected client: the iframe would show an error page rather than receive `login_required`. Operators who need silent authentication for a third-party client set `redirection_policy: allow_always` on it.

## API access policies

Each resource server has `subject_type_authorization`, one policy for users and one for machines:

```yaml
resource_servers:
  - identifier: https://api.example.com
    subject_type_authorization:
      user:   {policy: allow_all}              # default
      client: {policy: require_client_grant}   # default
```

| | `allow_all` | `require_client_grant` | `deny_all` |
|---|---|---|---|
| `user` (authorization code, password and refresh flows) | Allowed | Needs a client grant with `subject_type: user` | Refused |
| `client` (client credentials) | Not available: a stored `allow_all` is treated as `require_client_grant`, because Auth0 offers only the other two | Needs a client grant with `subject_type: client` | Refused |

The seed accepts `allow_all`, `require_client_grant` and `deny_all` for `user`, and `require_client_grant` and `deny_all` for `client`. Unknown stored values fail closed (they act as `require_client_grant`).

Under a user `allow_all` policy a first-party client needs no grant. A third-party client still needs a `user` grant when it is strict; a permissive client needs none. A client-credentials request always needs a client grant.

### Client grants

A client grant allows a client to use an API with a set of scopes. `subject_type` is `user` or `client` and defaults to `client`; the seed allows one grant per (client, audience, subject type). The flow decides which grant is used: a machine request looks for a `client` grant, everything that involves a user for a `user` grant.

```yaml
client_grants:
  - {client_id: partner, audience: https://api.example.com, subject_type: user, scopes: [read:things]}
```

### How scopes are capped

A token carries the requested scopes that the API defines and, when a client grant applies, that the grant lists. Scopes outside the grant are dropped without an error (observed); a request for nothing but such scopes succeeds with an empty scope. `offline_access` is not limited by the grant, but the existing rules still decide whether a refresh token is issued. The refresh grant checks the policy and the client grant again, so withdrawing a grant stops the next refresh.

## Consent

Consent is the screen where the user allows an application to receive scopes for an API. It is shown after login (or for an existing session) when all of these hold:

- the client is third-party; or the client is first-party, the request names an audience, and that API's `skip_consent_for_verifiable_first_party_clients` is `false`. That setting defaults to `false`, as on Auth0. A first-party client of an API that skips consent never sees consent, whatever the callback, and neither does a first-party request without an audience;
- and the user has no stored grant covering every scope the request would receive, or the request has `prompt=consent`.

A third-party request without an audience asks for consent too; its grant is stored under the audience `https://{domain}/userinfo`.

`prompt=consent` forces the screen, with one exception: it does not force consent for a first-party client whose API skips consent. Auth0's behaviour for that combination was not observed, so this is an assumption.

### User grants

The remembered approvals are user grants, keyed by client, user and audience (the API identifier, or `https://{domain}/userinfo` without an audience). Accepting consent adds the accepted scopes to the grant, so a later request for a subset skips consent; declining leaves the grant unchanged and returns `access_denied`. The screen lists every scope the request will receive, not only the new ones.

zeroauthy stores a grant only when the user accepts a consent screen. Auth0 was observed storing one for a first-party client after a login that showed no screen (D-0026); this is a recorded difference until the Management API exposes grants.

There is no way to list or revoke grants yet; that arrives with the Management API (sub-project 3).

### Scope descriptions

`use_scope_descriptions_for_consent: true` on a tenant shows each scope's `description` from the resource server instead of its name. A scope without a description is shown by name.

### Customizing the text

The consent screen reads its text from the locale files. Override it per tenant with `custom_text` (see [i18n.md](i18n.md)). Auth0's keys, prompt `consent`, screen `consent`:

| Key | Default |
|---|---|
| `consent.consent.pageTitle` | Authorize application |
| `consent.consent.title` | Allow ${clientName}? |
| `consent.consent.acceptButtonText` | Allow |
| `consent.consent.declineButtonText` | Deny |

zeroauthy's own keys, under the `zeroauthy` prompt:

| Key | Default |
|---|---|
| `zeroauthy.consent.description` | ${clientName} is asking for permission to: |
| `zeroauthy.consent.externalApp` | ${clientName} is not operated by ${companyName}. If you allow it, you will be sent to ${callbackDomain}. |
| `zeroauthy.consent.confirmTitle` | Continue to ${clientName}? |
| `zeroauthy.consent.confirmDescription` | Continue only if you started this sign-in. You will be sent to ${callbackDomain}. |
| `zeroauthy.consent.confirmButtonText` | Continue |
| `zeroauthy.consent.cancelButtonText` | Cancel |
| `zeroauthy.error.access-denied` | The application was not given access to your account. |

`${callbackDomain}` is the host of the redirect URI, or its scheme (for example `com.example.app:`) for a custom scheme. The screen shows the API's name (its identifier when it has none), the scope list, and for a third-party client the external-application notice.

The consent page is `/u/consent`. It completes only transactions that `/authorize` started for it, and it checks the browser's session again: if the session has ended or its user is blocked, the user is sent to log in again instead.

## The confirmation prompt

Since 2026-04-28 Auth0 asks users to confirm a login whose callback it cannot verify. zeroauthy follows (changelog entry 2025-10-28, D-0027).

A callback is non-verifiable when its scheme is anything other than `http` or `https`, or its host is `localhost`, `127.0.0.1` or `::1`.

The confirmation is a variant of the consent page: it names the callback domain and offers Continue and Cancel; Cancel is `access_denied`. It appears when:

- the callback is non-verifiable, and
- the client's `skip_non_verifiable_callback_uri_confirmation_prompt` is not true. The client's setting overrides the tenant's; with neither set the prompt is on (tenant default `false`), and
- no other screen was shown in the same transaction: the login or signup page or the consent page just before. A fresh login therefore goes straight back, whereas reusing an existing session shows the confirmation.

`prompt=none` fails with `consent_required` when consent or the confirmation would be needed (observed for both), and with `login_required` when there is no session. Silent authentication therefore fails for clients with non-verifiable callbacks while the prompt is on, as it does on Auth0.

Accepting the confirmation stores no user grant.

```yaml
tenants:
  - name: acme
    skip_non_verifiable_callback_uri_confirmation_prompt: false   # tenant default
    clients:
      - client_id: dev-spa
        callbacks: ["http://localhost:3000/"]
        skip_non_verifiable_callback_uri_confirmation_prompt: true  # this client only
```

### Local development

Applications that develop against `http://localhost:…` get the confirmation on every request that reuses a session, and silent authentication stops working for them. Set the client flag on development clients only. Leaving the tenant-wide flag on `false` keeps production clients, and any custom-scheme native apps, on the safe default. The tenant flag is for tenants that are entirely development.

## Domain connections

A third-party client cannot be added to a connection's `enabled_clients`. It uses connections with `is_domain_connection: true` (default `false`), which are available to every third-party client of the tenant. First-party clients keep using the connections that list them in `enabled_clients`; the flag does not change that.

```yaml
connections:
  - {name: Username-Password-Authentication, is_domain_connection: true, enabled_clients: [web]}
```

Hosted login, the `connection` parameter of `/authorize`, and the check that a session's connection is still usable all use this rule. The `/dbconnections/*` endpoints and the password grants still check `enabled_clients` only, so a third-party client cannot call them (third-party clients have no password grant in any case).

## Errors

`/authorize` errors reach the application as `error` and `error_description` on the redirect URI, or on an error page with HTTP 400 under `open_redirect_protection`.

| Where | Code | When |
|---|---|---|
| `/authorize` | `invalid_request` | A strict client sends `claims`, `id_token_hint`, `login_ticket`, `request`, `request_uri` or `screen_hint`, omits PKCE, or omits the audience |
| `/authorize` | `invalid_request` | The API's user policy is `deny_all`, or the policy needs a client grant that the client lacks (observed) |
| `/authorize` | `consent_required` | `prompt=none` and consent or the confirmation is needed (observed) |
| `/authorize` | `login_required` | `prompt=none` and there is no usable session |
| `/authorize` | `access_denied` | The user declined consent or the confirmation |
| `/oauth/token` | HTTP 400 `invalid_request` | Password or refresh grant refused by the API's user policy (observed) |
| `/oauth/token` | HTTP 403 `access_denied` | Client credentials refused: the client policy is `deny_all` or there is no `client` grant (observed) |
| `/oauth/token` | HTTP 403 `unauthorized_client` | A third-party client tries the password grant |

Errors raised before the client and redirect URI are validated are error pages in every case, as before this feature. A consent form posted without `accept` or `decline` is a server error today (see the follow-ups).

## Example seed

```yaml
tenants:
  - name: acme
    skip_non_verifiable_callback_uri_confirmation_prompt: false   # default false
    use_scope_descriptions_for_consent: false                      # default false
    resource_servers:
      - identifier: https://api
        skip_consent_for_verifiable_first_party_clients: true      # default false, as on Auth0
        subject_type_authorization:
          user: {policy: allow_all}
          client: {policy: require_client_grant}
        scopes:
          - {value: read:things, description: "Read your things"}
    clients:
      - client_id: partner
        is_first_party: false
        third_party_security_mode: strict                          # default for third-party clients
        redirection_policy: open_redirect_protection               # default for third-party clients
        skip_non_verifiable_callback_uri_confirmation_prompt: true # optional; unset = tenant value
        app_type: regular_web
        client_secret: change-me
        grant_types: [authorization_code, refresh_token]
        callbacks: ["https://partner.example.com/callback"]
    client_grants:
      - {client_id: partner, audience: https://api, subject_type: user, scopes: [read:things]}
    connections:
      - {name: Username-Password-Authentication, is_domain_connection: true}
```

## Upgrading

- Migration 0003 adds the consent columns and the user grants table. Databases migrated to schema 3 keep `skip_consent_for_verifiable_first_party_clients = true` on existing resource servers, but a seed apply sets `false` unless the seed names the field.
- Storage plugins must be rebuilt against this version to serve `UserGrants`; an older plugin fails a consent decision with a server error (D-0021 addendum).
