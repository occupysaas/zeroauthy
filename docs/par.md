# Pushed authorization requests (PAR)

zeroauthy supports pushed authorization requests (RFC 9126) the way Auth0 does. Instead of putting every authorization parameter in the browser URL, a confidential application sends them to `POST /oauth/par` over a direct connection, authenticated with its client secret, and receives a short-lived `request_uri`. The browser is then sent to `/authorize` with only `client_id` and that `request_uri`. The design decisions are D-0028 (the endpoint), D-0029 (`request_uri` at `/authorize` and required PAR) and D-0030 (settings and discovery) in [compat/decisions.md](compat/decisions.md); the observed values are in [compat/observations/par.md](compat/observations/par.md). The design is in `docs/superpowers/specs/2026-10-16-zeroauthy-par-design.md`.

## When to use it

- The parameters travel on the back channel, so a user or a browser extension cannot change `scope`, `redirect_uri` or the PKCE challenge on the way.
- The client proves who it is before the user sees a login page.
- There is no URL length limit to worry about, which helps with long `scope` values and `ext-` parameters.

PAR is for confidential clients only. A single-page or native application that cannot keep a secret cannot use it.

## Enabling it

Turn the feature on for the tenant first, then require it for the clients that should always use it.

```yaml
tenants:
  - name: acme
    domains: [auth.example.com]
    pushed_authorization_requests_supported: true    # default false
    clients:
      - client_id: webapp
        app_type: regular_web
        client_secret: change-me
        grant_types: [authorization_code, refresh_token]
        callbacks: ["https://app.example.com/callback"]
        require_pushed_authorization_requests: true  # default false
```

- `pushed_authorization_requests_supported` is a tenant setting. While it is off, `/oauth/par` answers `400 invalid_request`, `request_uri` at `/authorize` is refused, and discovery lists no PAR endpoint (it still lists `request_uri_parameter_supported: false`).
- `require_pushed_authorization_requests` is a client setting. The seed refuses it when the tenant setting is off, on public clients, and on third-party clients, because those cannot push.
- A client without the setting may still push; the setting only forbids the plain `/authorize` request.

If stored data (a plugin or a migration) ends up with a required-PAR client under a tenant that has the setting off, every `/authorize` request from that client is refused. The seed cannot express that state.

## Using it

### With an SDK

Set `pushedAuthorizationRequests: true` in the configuration of express-openid-connect, @auth0/nextjs-auth0 or @auth0/auth0-auth-js. The SDK does the push and the redirect for you. Discovery advertises the endpoint, which is what the SDKs look for.

### By hand

```sh
curl -s https://auth.example.com/oauth/par \
  -u webapp:change-me \
  -d response_type=code \
  -d redirect_uri=https://app.example.com/callback \
  -d scope='openid profile' \
  -d state=abc \
  -d code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM \
  -d code_challenge_method=S256
```

```json
{"request_uri": "urn:ietf:params:oauth:request_uri:q7Hn2WcX9bLr4TgYd1VzKf8MsPa3JuEo6NiRxA0CtBhZw5GyDeQkS2lUvOjF1mPb", "expires_in": 30}
```

The opaque part after the prefix is 64 characters.

The response is `201` with `Cache-Control: no-store`. Then send the browser to:

```
https://auth.example.com/authorize?client_id=webapp&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A...
```

The rest of the flow (login, consent, code exchange) is unchanged.

## Rules and limits

At `/oauth/par`:

- The client must be a first-party confidential client authenticating with `client_secret_basic` or `client_secret_post`. A wrong secret is `401 invalid_client`. A public client or any third-party client (strict or permissive) gets `400 invalid_request`.
- The body must be form-encoded; JSON is `400 invalid_request`. It may be at most 10 KB (`413 payload_too_large`), may not repeat a parameter and may not contain `request_uri`.
- At most 10 parameters starting with `ext-` are kept; an 11th is `400 invalid_request`. Other unknown parameters are dropped.
- The request is validated like an `/authorize` request. Errors keep the `/authorize` error code, returned as JSON with the status for that code: `invalid_request` 400, `unauthorized_client` 403, `access_denied` 403, `unsupported_response_type` 501. Nothing is redirected.
- The `request_uri` lives 30 seconds and works once.

At `/authorize`:

- With a `request_uri`, only the pushed parameters count. Every query parameter except `client_id` and `request_uri` is ignored, never an error.
- An unknown, used, expired or wrong-client `request_uri`, or one sent while the tenant setting is off, shows an HTTP 400 error page. There is no redirect. An attempt by an existing, non-strict client that finds the request uses it up, including one with the wrong `client_id`; an unknown `client_id` or a strict third-party client never touches it.
- A client with `require_pushed_authorization_requests` that sends a plain request is redirected back with `error=invalid_request` and its `state` (subject to `redirection_policy`).
- The login and consent pages remember that the request was pushed, so a client that requires PAR is not refused after them.

Discovery shows `pushed_authorization_request_endpoint` only while the tenant setting is on. `request_uri_parameter_supported` is always `false`, because `request_uri` is accepted only for pushed requests.

## Storage plugins

Plugins built before this version cannot store pushed requests. Their expiry sweep is tolerated, but a push fails. A plugin built before Plan 10 also drops `require_pushed_authorization_requests` and `pushed_authorization_requests_supported` on write, so the settings silently read back as false until the plugin is rebuilt. Rebuild plugins against this version before turning PAR on. The built-in memory, SQLite, PostgreSQL and MySQL drivers need no action beyond migration 0004, which runs automatically.

## Differences from Auth0

- `response_type=token` at PAR is `501 unsupported_response_type`. Auth0 answers `403 unauthorized_client` for a client without the implicit grant; zeroauthy has no implicit grant for any client (D-0028).
- zeroauthy checks `response_mode` and `prompt` when the request is pushed. Auth0 accepts unknown values there and checks them at `/authorize` (D-0028).
- Strict third-party clients keep refusing `request_uri` at `/authorize` (D-0025, D-0029).
- Not yet supported: `private_key_jwt` and mTLS client authentication, signed request objects (JAR), `authorization_details` (RAR), the RFC 9207 `iss` response parameter, and Actions access to `ext-` parameters. See "Plan 10 follow-ups" in `docs/superpowers/plan-1-followups.md`.
