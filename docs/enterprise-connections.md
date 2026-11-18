# Enterprise OpenID Connect connections

Create enterprise connections in **Enterprise** in the console, through
`POST /api/v2/connections`, or in the seed file. Enable each connection for
the applications allowed to use it. Register each tenant callback origin's
`/login/callback` URL with the provider.

`oidc` supports authorization-code (`back_channel`) and ID-token form-post
(`front_channel`) login. An omitted `type` creates a front-channel
connection. Existing stored OIDC connections without a type are migrated to
`back_channel` by migration 0041. `okta` is back-channel only: `domain` is a
DNS host without a scheme, path or port. Its issuer and discovery URL are
normally `https://<domain>` and
`https://<domain>/.well-known/openid-configuration`. Custom authorization
servers can use explicit issuer and endpoint settings.

```json
{
  "name": "workforce",
  "strategy": "oidc",
  "enabled_clients": ["your-application-id"],
  "options": {
    "type": "back_channel",
    "client_id": "your-upstream-client-id",
    "discovery_url": "https://idp.example/.well-known/openid-configuration",
    "scope": "openid profile email",
    "token_endpoint_auth_method": "private_key_jwt",
    "domain_aliases": ["corp.example"]
  }
}
```

For secret authentication, supply the provider's `client_secret` securely.
It is encrypted at rest and never returned. Front-channel connections
refuse an unused client secret. Signed client assertions do not require a
secret. Discovery chooses Basic or POST authentication when
`token_endpoint_auth_method` is absent; explicit values are
`client_secret_post` and `private_key_jwt`.

## Endpoints, PKCE and tokens

Supply `discovery_url`, nonempty `oidc_metadata`, or a complete explicit
endpoint set. Metadata takes precedence over discovery. Explicit settings
include `issuer`, `authorization_endpoint`, `jwks_uri` and, for the back
channel, `token_endpoint`; `userinfo_endpoint` is optional. Metadata and
discovery documents are limited to 128 KiB. Endpoints use the guarded HTTPS
client, with the deployment's outbound network policy and no redirects.
Issuer, discovery URL, client ID and Okta domain are immutable bindings.

`connection_settings.pkce` accepts `auto`, `S256` (also `s256`), `plain` and
`disabled`. Auto selects S256, then plain, from provider metadata and sends
no PKCE if neither is advertised. Plain and disabled provide weaker
protection. Front-channel login uses a nonce and form post, with a Secure,
HttpOnly, SameSite=None attempt cookie; it never uses PKCE. Setting
`send_back_channel_nonce: false` omits the back-channel nonce check only.

`id_token_signed_response_algs` restricts ID-token signatures to the supplied
subset of `RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512`; absent or
null accepts this supported set. Unsigned and symmetric ID tokens are
refused. The issuer, audience, times, subject and required nonce are checked
against the pinned attempt.

`enable_pushed_authorization_requests` enables upstream PAR on back-channel
connections. Set `pushed_authorization_request_endpoint` or advertise it in
metadata. Failure ends the attempt without falling back to an ordinary
request. The same client authentication applies to PAR and token requests.

## Public connection keys

The Keys tab and API manage connection-specific signing and encryption keys:

| Operation | Scope |
|---|---|
| `GET /api/v2/connections/{id}/keys` | `read:connections_keys` |
| `POST /api/v2/connections/{id}/keys` | `create:connections_keys` |
| `POST /api/v2/connections/{id}/keys/rotate` | Both `create:connections_keys` and `update:connections_keys` |

Creation accepts `key_use` (`signing`, the default, or `encryption`) and
`signing_alg` or `encryption_alg`. A second creation of the same use returns
409. Public responses include a PEM certificate, PKCS#7 PEM, key ID,
algorithm, use, current/next/previous flags, and certificate identifiers.
Private keys are sealed and never returned. SHA-1 fingerprints identify the
public certificate for API compatibility; they are not signing algorithms.
Register the public certificate with the provider; there is no connection
JWKS endpoint.

Signing algorithms are `RS256 RS384 RS512 PS256 PS384 ES256 ES384`.
`token_endpoint_auth_signing_alg` defaults to RS256.
`token_endpoint_jwtca_aud_format` selects `issuer` (default) or
`token_endpoint` for the assertion audience. Assertions last 60 seconds and
carry a fresh request identifier. RSA keys are 2048 bits; EC signing uses
P-256 or P-384.

Configure `id_token_encrypted_response_alg` to require encrypted ID tokens:
`RSA-OAEP-256`, `RSA-OAEP-384`, `RSA-OAEP-512`, `ECDH-ES`, or
`ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`.
`id_token_encrypted_response_encs` can restrict content encryption to a
subset of `A128CBC-HS256 A192CBC-HS384 A256CBC-HS512 A128GCM A192GCM A256GCM`.
The decrypted signed token still undergoes normal signature and claim
validation. Plain ID tokens are refused when encryption is configured.
Current and previous encryption keys support rotation.

Keys are created lazily on first use if not provisioned first. Rotation
promotes next to current, retains the old current as previous, and creates
a new next. Signing rotation requires `private_key_jwt`; encryption rotation
requires encrypted-token configuration. Register certificates before
switching the provider. Keys are never seeded or migrated by Deploy CLI;
create them on the destination. Storage plugins need `connection_keys.v1`:
the keys API returns 501 without it, and writes requiring keys are refused.

## Claim mapping and userinfo

Default mapping retains the standard provider profile. Okta also accepts
`basic_profile`. `bind_all` copies permitted claims for OIDC; `use_map`
selects attributes with templates:

```json
{
  "attribute_map": {
    "mapping_mode": "use_map",
    "userinfo_scope": "openid profile groups",
    "attributes": {
      "name": "${context.tokenset.name}",
      "nickname": "employee|${context.tokenset.sub}",
      "federated_groups": "${context.userinfo.groups}"
    }
  }
}
```

References can read validated token claims, userinfo claims, and
`context.connection.id` or `.strategy`. Claim names may contain dots and
URL characters; dots are part of a claim name, not object traversal. No
functions, arbitrary expressions or nesting are evaluated. A whole-value
missing claim omits the attribute; a missing part of a concatenation is
empty. Limits are 100 attributes and 1024 bytes per template, plus bounded
profile output. `email_verified` requires a boolean upstream value.

Userinfo is fetched only when referenced, or for `bind_all` with a userinfo
scope. Its subject must match the ID token. Userinfo references are refused
for front-channel connections, which have no access token. Reserved claims
and server-owned fields cannot be mapping targets; bind-all drops them.
Custom attributes appear in identity `profileData`, independent of account
linking. Profile synchronization follows `set_user_root_attributes`.
Identity ownership always uses connection plus upstream subject; email
never automatically links accounts. Front-channel login stores no upstream
tokens and clears historical tokens from an earlier back-channel login.

## Home realm discovery and other routes

Identifier-first login compares the email's exact lower-case IDNA domain
with `domain_aliases` on enabled OIDC, Okta and Entra (`waad`) connections.
There are at most 1000 aliases per connection, each at most 256 characters.
No wildcard or subdomain matching is performed. Client, purpose and
organization filters apply first; organization discovery retains priority.
Matching needs no user lookup and forwards the email as `login_hint`.
Multiple matches use the available connection name order. Single-screen
username/password login does not use this routing.

`GET /api/v2/connections/{id}/status` is an AD/LDAP-only online check. The
current strategies answer 404. `DELETE /api/v2/connections/{id}/users?email=`
requires `delete:users`, supports database connections, and uses the same
cleanup and operator protections as deleting a user by ID. Unknown emails
answer 204; all matching users on the connection are removed.

## Stored options and compatibility observations

`tenant_domain` on OIDC/Okta, `useOauthSpecScope`, `non_persistent_attrs`,
`id_token_session_expiry_supported` and `upstream_params` are stored without
runtime enforcement. DPoP (`dpop_signing_alg`) is refused when non-null.
Entra Graph groups and WS-Federation are separate roadmap items. Keys are
currently available for OIDC/Okta; SAML support belongs to Plan 37a.

The local rulings and follow-up observations are in D-0120 and the
[Plan 36 observation points](superpowers/plan-1-followups.md). They track
Okta custom-server and identity formatting (V1–V2), the `scopes` alias (V3),
auto PKCE without metadata (V4), assertion defaults (V5), custom-attribute
projection and restricted claims (V6–V7), dotted claim names (V8), HRD
matching and ordering (V9), key errors and subject names (V10–V11), lazy
creation (V12), and multiple/unknown email deletion (V13). Acceptance uses
local providers, pinned SDKs/CLI and Chromium; it does not establish live
provider or Auth0-tenant equivalence.
