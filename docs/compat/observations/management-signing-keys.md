# Management API: signing keys

- **Reviewed:** 2026-10-25
- **Evidence boundary:** public documentation only. No separate observer report or disposable-tenant authorization was available to this implementation session; no live key operation was attempted.
- **Docs:**
  - https://auth0.com/docs/api/management/v2/keys/get-signing-keys
  - https://auth0.com/docs/api/management/v2/keys/get-signing-key
  - https://auth0.com/docs/api/management/v2/keys/post-signing-keys
  - https://auth0.com/docs/api/management/v2/keys/put-signing-keys
  - https://auth0.com/docs/api/management/v2/keys/get-custom-signing-keys
  - https://auth0.com/docs/api/management/v2/keys/put-custom-signing-keys
  - https://auth0.com/docs/api/management/v2/keys/delete-custom-signing-keys
  - https://auth0.com/docs/get-started/tenant-settings/signing-keys/rotate-signing-keys
  - https://auth0.com/docs/get-started/tenant-settings/signing-keys/revoke-signing-keys
  - https://auth0.com/docs/get-started/tenant-settings/signing-keys/customer-signing-keys

## Documented contract (K1–K3)

| Operation | Scope | Documented behavior | Not established here |
|---|---|---|---|
| `GET /api/v2/keys/signing` | `read:signing_keys` | Returns tenant application signing key metadata and public certificate representations. | Ordering, history cap, omission defaults, exact malformed/missing-scope errors. |
| `GET /api/v2/keys/signing/{kid}` | `read:signing_keys` | Reads a key by ID. | Unknown and foreign ID response identifiers. |
| `POST /api/v2/keys/signing/rotate` | `create:signing_keys` | Documented success is 201 with a certificate and key ID; documentation refers to the next key. | Which lifecycle key the response identifies; successive rotation history and timestamp transitions. |
| `PUT /api/v2/keys/signing/{kid}/revoke` | `update:signing_keys` | Revokes a previously used key; success is documented as 200 with certificate and key ID. Revocation is irreversible. | Current/next rejection status, repeated revoke behavior and exact errors. |
| `GET /api/v2/keys/custom-signing` | `read:signing_keys` | Reads the custom public-key set. | No-set response shape/status and entitlement-dependent behavior. |
| `PUT /api/v2/keys/custom-signing` | `update:signing_keys` | Creates or replaces a custom public JWKS. The guide documents a maximum of ten public keys and custom-domain distribution. | Exact accepted key matrix, duplicate/private field errors and request size. |
| `DELETE /api/v2/keys/custom-signing` | `update:signing_keys` | Deletes the custom set. | Absent-set status and exact response body. |

Public docs describe custom keys as public-key distribution; they do not authorize those keys to sign for this service. They are stored-only in Plan 20 and excluded from canonical JWKS and internal token verification. This is the explicit local compatibility/security policy, not a claim about every upstream entitlement.

## Local decisions pending live evidence

- Preserve every unrevoked previous key across rotations. Revoke only eligible previous keys; current/next are not eligible. Repeated revoke is idempotent and preserves the first `revoked_at`. These are the design's safe local defaults, not observed Auth0 behavior.
- Certificates are stable, self-signed RSA/SHA-256 X.509 representations with a positive random serial, neutral subject, five-minute clock allowance and ten-year validity. SHA-1 is used only if required for the compatibility fingerprint. No historical lifecycle time is synthesized during backfill.
- Custom input is an RFC 7517 public JWKS with 1–10 uniquely identified RSA/EC signing keys, no private/symmetric members, no unsupported URL retrieval, and no managed-key ID collisions. Exact accepted algorithms are frozen by shared local validation tests; live behavior remains unverified.
- Public certificate fields, list ordering, omitted nullable times and error identifiers follow the checked-in OpenAPI contract and local tests until a separate observer supplies sanitized notes.

The authorized observer may add dated results after testing a disposable tenant. No credentials, tenant identifiers, raw responses, hosted UI data or personal data belong here.

## Local client verification (2026-10-25)

The installed node-auth0 7.4.0 signing client confirms the revoke path is
`keys/signing/{kid}/revoke`; the initial local OpenAPI path lacking `/revoke`
was corrected before completion. The full local SDK/CLI runner exercises all
seven operations, missing scopes, wrong tenants and retired collections.
Pinned jwks-rsa 4.1.0 coverage distinguishes unknown-key refresh from a cached
old key: the cached key still verifies its mathematical signature after local
revocation, while zeroauthy rejects that token and omits the key from canonical
JWKS. This is local evidence, not an Auth0 tenant observation.
