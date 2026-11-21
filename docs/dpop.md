# DPoP token binding

DPoP binds a token to an application's public key. A stolen token needs a
fresh proof signed by that key before it can be used. The protocol follows
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html).

Generate a P-256/ES256 or 2048–4096-bit RSA/RS256 key locally. Keep its private
part in the application. For `/oauth/token`, send a compact signed JWT in
`DPoP` with `typ=dpop+jwt`, an embedded public `jwk`, unique `jti`, integral
`iat`, `htm=POST`, and the public token endpoint in `htu` without query or
fragment. Proofs are limited to 16 KiB, accepted for 60 seconds with five
seconds of future skew, and accepted only once across server instances.

Public applications first receive `400 use_dpop_nonce` and `DPoP-Nonce`.
Generate a new proof containing that nonce and a new `jti`, then retry. The
challenge does not consume the code or refresh token. Nonces last 60 seconds
and can be reused with fresh proofs. CORS exposes `DPoP-Nonce` to permitted
application origins. Private key, proof and nonce values must not be logged.

Configure an API with `proof_of_possession`:

```json
{"mechanism":"dpop","required":true,"required_for":"public_clients"}
```

`required_for` defaults to `all_clients`. `required:false` allows optional
binding. `mechanism:none` disables access-token binding; `null` clears the
configuration. mTLS remains unsupported. A client can independently require
sender constraints using `require_proof_of_possession:true`.

A bound access token carries `cnf.jkt`, the SHA-256 JWK thumbprint, and its
response reports `token_type:DPoP`. Each target API must verify the token's
signature, issuer, audience, expiry and scopes, then validate a fresh DPoP
proof's signature, method, public URI, replay state and `ath` (base64url
SHA-256 of the exact access token), and compare its key to `cnf.jkt`.
Reject a bound token sent through the Bearer scheme. Application API servers
are responsible for these checks; token issuance does not install them.

`/userinfo` enforces those checks and requires its own nonce. Its challenge
uses HTTP 401, `WWW-Authenticate: DPoP error="use_dpop_nonce"`, and
`DPoP-Nonce`. A token-endpoint nonce cannot be reused at UserInfo, or vice
versa. Management and console operator resources remain Bearer-only and
reject bound tokens.

Refresh-token binding is independent of access-token binding. New tenants
bind refresh tokens whenever a valid proof accompanies issuance, even if
the API's access token remains Bearer. The same key is required on every
refresh, including rotation, settings conversion and MRRT exchanges.
Revoking a bound refresh token at `/oauth/revoke` also requires a proof
signed for that endpoint with the matching key. An expired bound presentation
still needs proof before its family can be revoked. Unknown or cross-origin
tokens keep the existing successful empty response; wrong-client behavior
remains `invalid_grant`.

Presenting a proof with an already unbound refresh token does not upgrade
that family's binding. New and upgraded tenants use strict refresh binding
when the setting is absent. An explicit `dpop_strict_refresh_token_binding: false`
applies per-API binding to newly issued offline credentials. Existing bound
credentials keep their key when settings change.

To bind the authorization code, send `dpop_jkt` through `/authorize`, JAR,
or PAR. PAR also accepts a proof signed for `/oauth/par`. If both are sent,
they must identify the same key. Missing or wrong-key proofs at redemption
leave a bound code unused. Storage plugins must negotiate
`refresh_tokens_ii.v1`; unavailable or lost support never falls back to
unprotected DPoP processing.
