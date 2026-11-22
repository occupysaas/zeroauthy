# Client authentication with keys and signed requests

Plan 35 adds three things that rest on a public key registered on an
application: `private_key_jwt` client authentication, signed authorization
requests (JAR) and, for APIs, `HS256` and `PS256` access tokens. This guide
covers setup and the places where zeroauthy decides something Auth0's
documentation leaves open. Each such local ruling has an `LR35` number
recorded in
[D-0063](compat/decisions.md#d-0063-client-credentials-private_key_jwt-jar-and-custom-token-exchange-contracts-and-local-rulings),
with what it would cost if Auth0 behaves differently. For trading an external
token for zeroauthy tokens, see [Custom token exchange](token-exchange.md).

## Requirements

- A storage backend with the `client_credentials.v1` capability. Memory,
  SQLite, PostgreSQL and MySQL have it. A storage plugin that does not
  negotiate it answers the credential and profile routes with `501`, never
  advertises `private_key_jwt` or request-object support in discovery, and
  refuses a seed that uses any of it at startup.
- Applications for `private_key_jwt` must be able to keep a private key:
  confidential application types. Strict third-party applications do not get
  request-object processing (they keep the earlier refusal); custom token
  exchange is for first-party applications only.

## Credentials

A credential is a public key or certificate registered on one application.
An application holds at most **two**, so a key can be rotated by adding the
new one before removing the old one.

| Field | Meaning |
|---|---|
| `credential_type` | `public_key` or `x509_cert`. `cert_subject_dn` (and mutual TLS) is refused. |
| `pem` | An SPKI or PKCS#1 RSA public key, or an X.509 certificate. One PEM block, RSA modulus of 2048 to 4096 bits. |
| `alg` | `RS256` (the default), `RS384` or `PS256`. The credential fixes the algorithm; a JWT whose header says otherwise is refused. |
| `kid` | 10 to 64 characters from `0-9a-zA-Z-_`. Defaults to the key's RFC 7638 thumbprint (base64url SHA-256), which is also returned as `thumbprint_sha256`. |
| `name` | Up to 128 characters, free text. |
| `expires_at` or `parse_expiry_from_cert` | Optional, and not both. With neither the credential never expires (LR35-2). `parse_expiry_from_cert` needs a certificate. |

The Management API has `GET` and `POST /api/v2/clients/{id}/credentials` and
`GET`, `PATCH` and `DELETE .../credentials/{credential_id}`. Only
`expires_at` can be changed afterwards. The response never contains the PEM
(C1). Deleting a credential also detaches it from the application's settings;
an application left with `private_key_jwt` and no usable key cannot
authenticate (C3). A third credential is `400` (C2).

```sh
curl -sS -X POST https://$HOST/api/v2/clients/$CLIENT_ID/credentials \
  -H "Authorization: Bearer $MGMT_TOKEN" -H 'Content-Type: application/json' \
  -d '{"credential_type":"public_key","name":"ci key","alg":"PS256","pem":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"}'
```

The console's application page has a **Credentials** tab for the same
operations (see [the console guide](console.md)). The PEM is never shown
again after it is added.

## The three application settings

All three are accepted on application create and update, and returned on
read. A setting can add a credential inline by giving the fields of a new
credential (instead of an `id`) in its list.

- `client_authentication_methods`:
  `{"private_key_jwt": {"credentials": [{"id": "cred_..."}]}}`, or `null`.
  `tls_client_auth` and `self_signed_tls_client_auth` are refused.
  `private_key_jwt` replaces the secret-based method, so the request must
  also set `token_endpoint_auth_method` to `null` (or it is already null);
  keeping both is `400` (C4). To go back, set `client_authentication_methods`
  to `null` and give a `token_endpoint_auth_method`.
- `signed_request_object`: `{"required": true, "credentials": [{"id": ...}]}`.
  A PATCH that omits `credentials` keeps the stored list.
- `token_exchange`: `{"allow_any_profile_of_type": ["custom_authentication"]}`;
  see [Custom token exchange](token-exchange.md).

Every credential a setting names must belong to the application. The two
credential lists are separate: a key listed only for signed requests never
verifies a client assertion, and the other way round. Auth0 advises against
using one key for both; zeroauthy allows it.

## `private_key_jwt`

An application sends `client_assertion_type` =
`urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and a
`client_assertion` (a compact JWS) in place of a secret. The endpoints that
accept it are:

- `/oauth/token`, for every grant that authenticates a confidential client;
- `/oauth/revoke`;
- `/oauth/par` (not on Auth0's list of supported endpoints; LR35-1);
- `/mfa/challenge`;
- `/passwordless/start`;
- the native passkey endpoints.

After authentication the application is handled exactly like a
secret-authenticated one: grants, organizations and rate limits are unchanged.

### What the assertion must contain

| Part | Rule |
|---|---|
| Size | At most 2048 bytes. `iss`, `sub` and `jti` are at most 64 characters, and the header `alg` at most 16. |
| Header | `alg` is `RS256`, `RS384` or `PS256` and equals the credential's `alg`. `kid` selects the credential; without it every unexpired key of the application with that `alg` is tried. `none`, `HS*` and `ES*` are refused. |
| `iss`, `sub` | Both the `client_id`. |
| `aud` | The issuer URL with its trailing slash for the host that received the request (the canonical host or a custom domain), or the exact URL of the endpoint (LR35-3). |
| `exp` | Required, at most 5 minutes after `iat` (or after now when `iat` is absent). |
| `iat`, `nbf` | Optional; clock leeway is 10 seconds. |
| `jti` | Required, and single-use. |

A `jti` is recorded per tenant and application until the assertion expires
(plus leeway), in the shared store, so a second request with the same `jti` is
refused on any replica. The recording happens even when a later check
fails, so a refused assertion cannot be retried.

### Errors

- An assertion combined with another authentication method (Basic, or
  `client_secret`), or with a `client_id` that differs from the assertion's
  subject, is `400 invalid_request`.
- Every other failure is `401 invalid_client` with one description shared by
  all reasons, including an assertion whose `iss` alone does not match. The
  reason goes to the server log, never the assertion itself.

Client assertions, request objects and signing secrets are never written to
the log, to log streams or to Action logs.

### Example

A client that builds the assertion itself signs a JWT with the claims above
using the private half of a registered key and sends it as `client_assertion`.
SDKs that take a signing key for client authentication, such as
`@auth0/auth0-auth-js` with `clientAssertionSigningKey`, do this for you.

## Signed authorization requests (JAR)

An application can send the authorization parameters as a signed JWT in the
`request` parameter of `/authorize` (`GET` or `POST`) or of `/oauth/par`.

- `alg` is one of the application's `signed_request_object` credentials'
  algorithms. `typ` may be absent, `JWT`, `jwt` or `oauth-authz-req+jwt`
  (LR35-5). An unsigned object (`alg` `none`) is refused with
  `request_not_supported` (LR35-4).
- Claims: `iss` is the `client_id`; a `client_id` claim is required and equals
  the query's `client_id`; `aud` is the issuer URL (only that form, LR35-10);
  `exp` and `nbf` are checked with 10 seconds of leeway; the lifetime is at most
  60 minutes (C7); a `jti` is at most 64 bytes and single-use (LR35-7).
- Parameters inside the object win over the query string. The merged set is
  then checked like any authorization request, including the registered
  `redirect_uri`. Claims whose value is an object or an array are dropped.
- A `request` value over 16384 bytes, or one that cannot be decoded or is
  empty, is `invalid_request_object` (LR35-11). A bad signature or bad claims
  give the same error: delivered to the registered `redirect_uri` with `state`
  when the redirect can be trusted, and shown as an error page otherwise. At
  PAR it is `400`.
- With `signed_request_object.required`, an authorize or PAR request without
  a valid signed `request` is `invalid_request`. A `request_uri` from PAR
  satisfies it only when the pushed request was itself signed. Passwordless
  magic links through `/passwordless/verify_redirect` carry no signed mark, so
  they fail closed for such an application (LR35-12).
- A `request_uri` that did not come from PAR stays unsupported.

Discovery lists `request_parameter_supported: true`,
`request_object_signing_alg_values_supported` and, for `private_key_jwt`,
`token_endpoint_auth_signing_alg_values_supported` with the three algorithms,
only when the store supports client credentials. See
[Pushed authorization requests](par.md) for PAR itself.

## HS256 and PS256 access tokens

An API's `signing_alg` is `RS256` (the default), `HS256` or `PS256`.

- `PS256` signs with the tenant's RSA key, the same key RS256 tokens use. The
  JWKS publishes that key without an `alg` member, so verifiers that match a
  JWK's `alg` against the token header (jose, and so
  `express-oauth2-jwt-bearer`) accept both RS256 and PS256 tokens (C19).
  Configure such a verifier for a PS256 API with `issuer`, `jwksUri` and
  `tokenSigningAlg: 'PS256'`. Given only `issuerBaseURL`,
  `express-oauth2-jwt-bearer` also limits algorithms to discovery's
  `id_token_signing_alg_values_supported`, which lists HS256, RS256 and PS256
  with Plan 41a. Explicitly configure the algorithm expected by your API.
- `HS256` signs with the API's `signing_secret`: generated when absent (32
  random bytes, 43 base64url characters) or supplied with at least 32
  characters on new writes (D-0080). The secret is sealed at rest and returned when the API is read
  (C16). The HS256 token is built inside zeroauthy because the JOSE library
  refuses keys under 32 bytes; existing stored shorter secrets keep signing,
  and a strict verifier may reject those legacy tokens (LR35-13). A token for an HS256 API has no `{issuer}userinfo`
  audience, so it cannot call `/userinfo` (LR35-9). HS256 needs the store
  capability (`501` without it).
- The algorithm may be changed by a patch (LR35-8, C17): tokens are signed
  with the value current at issue time. Moving to HS256 generates a secret and
  moving away discards it. The system APIs keep RS256.

Reads of `signing_secret` are not audit-logged the way `client_secret` reads
are (a follow-up).

## In the seed

```yaml
tenants:
  - name: acme
    resource_servers:
      - identifier: https://api.acme.test
        signing_alg: HS256            # RS256 (default), HS256 or PS256
        signing_secret: change-me-to-something-long   # optional; HS256 only
    clients:
      - client_id: backend
        name: Backend
        app_type: non_interactive
        credentials:                   # at most two
          - name: ci
            alg: PS256                 # optional; default RS256
            kid: ci-key-2026-11        # optional; default is the thumbprint
            pem: |
              -----BEGIN PUBLIC KEY-----
              ...
              -----END PUBLIC KEY-----
        client_authentication_methods:
          private_key_jwt:
            credentials: [ci]          # credentials are named by `name`
        signed_request_object:
          required: true
          credentials: [ci]
        token_exchange:
          allow_any_profile_of_type: [custom_authentication]
```

- The settings name credentials by `name`, and only credentials of the same
  client. `private_key_jwt` implies an omitted `token_endpoint_auth_method`;
  naming one is an error. The seed checks everything with the Management
  API's rules.
- Only `public_key` PEMs (SPKI or PKCS#1 RSA public keys) are accepted in the
  seed; a certificate is refused.
- **Re-applying** (the default mode) makes a seed-owned application match the
  seed: a key is kept when its `kid`, algorithm, name and public key are
  unchanged, any other stored key is deleted (including one added through the
  API), and a missing one is created. An application whose seed has no
  `credentials` key keeps its stored keys, but its three settings follow the
  seed, so omitting them detaches the keys. In `create_only` mode, and for an
  application created through the API, the seed changes nothing about an
  existing application.
- An HS256 API seeded without `signing_secret` keeps its stored secret on
  re-apply instead of rotating it; with one, the secret is replaced only when
  it differs. A seeded API without `signing_alg` is RS256.
- A store without `client_credentials.v1` refuses a seed that uses
  credentials, the three settings, token exchange profiles or an HS256 API,
  with an error at startup, before anything is applied.


## Client ID-token signing algorithms

`jwt_configuration.alg` selects RS256 (default), PS256 or HS256 for ID
tokens. PS256 and RS256 use the tenant signing key and the same published
JWKS; its optional alg property remains absent. API access tokens retain
the API's independent signing algorithm.

HS256 requires a confidential application using client-secret authentication
and a usable sealed secret. Public and private_key_jwt-only clients cannot
select it. Its signing key is the client secret's UTF-8 bytes;
secret_encoded is a legacy ignored option. The token has no kid. Rotation
replaces that signing key for subsequent issuance. RP-initiated logout can
validate an HS256 ID-token hint against that client's selected algorithm
and current secret, including an expired hint as the logout specification
allows. A hint cannot select HMAC for an asymmetric client.

## ID token signing algorithms

Application `jwt_configuration.alg` selects RS256 (default), PS256 or HS256
for ID tokens. RS256 and PS256 use the tenant's managed signing key and JWKS.
HS256 uses the application's newest active retrievable sealed client secret,
with no `kid`; it requires confidential client-secret authentication and a
secret of at least 32 characters. Public/native/SPA, hash-only and
private-key-only applications cannot select it. Rotating the secret changes
subsequent ID token signatures; verifiers must use the matching client
secret. Logout notifications always use tenant RS256. The application
console, seed and Deploy CLI preserve the choice. New API HS256 signing
secret writes also require at least 32 characters; existing stored values
retain their previous behavior. See [logout](logout.md).
