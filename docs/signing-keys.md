# Tenant signing keys

Each ordinary tenant has an RS256 current key and a queued next key. Key
private material is envelope-encrypted with the configured master key. Public
certificates are available through the Management API and Settings console;
private keys are never returned or downloadable.

## Lifecycle

The signing manager creates missing keys without changing an existing `kid`,
key pair, or certificate. Startup backfills a certificate for older managed
keys with compare-and-set semantics. Rotation atomically promotes the queued
key, creates a new queued key, and retains all unrevoked previous keys. There
is no automatic time-based pruning or rotation.

Revoke only a previous key after confirming that dependent tokens may stop
working. New validation calls load the current trusted managed keys, so a
revoked key is rejected across server instances. A request already in flight
or a verifier that cached a remote JWKS may continue to accept a token until
its own cache expires. Rotation and revocation are separate operations; a
timed-out mutation must be followed by a list refresh and must not be retried
automatically.

## Management API

All key operations require `read:signing_keys`, `create:signing_keys`, or
`update:signing_keys` as shown below. System tenants reject signing-key
management.

| Operation | Scope |
|---|---|
| `GET /api/v2/keys/signing`, `GET /api/v2/keys/signing/{kid}` | `read:signing_keys` |
| `POST /api/v2/keys/signing/rotate` | `create:signing_keys` |
| `PUT /api/v2/keys/signing/{kid}/revoke` (revoke eligible previous key) | `update:signing_keys` |
| `GET /api/v2/keys/custom-signing` | `read:signing_keys` |
| `PUT`, `DELETE /api/v2/keys/custom-signing` | `update:signing_keys` |

Managed responses contain public certificate encodings and lifecycle metadata.
Unknown timestamps are omitted. Audit records identify the actor, tenant and
affected key IDs; they do not include key material, application secrets, or
bearer tokens.

## Custom public keys

Custom JWKS are validated and stored separately. They do not sign tokens,
appear in the tenant's canonical JWKS, or authorize tokens presented to
zeroauthy. Import only public JWKs. Public-key publication for custom domains
is a later milestone.

The Settings page has separate **Signing keys** and **Custom signing keys**
tabs. Rotation, revocation, replacement and deletion require confirmation.
After an uncertain managed-key result, refresh the list before making another
change.

## Rotation and recovery

Before a planned rotation, let relying applications retrieve the canonical
JWKS, which includes the queued next public key. Rotate once and confirm the
promoted `kid` using the list endpoint. Leave previous keys unrevoked while
their existing tokens remain valid; revoke them explicitly when that overlap
is no longer needed. Rotation does not delete sessions or refresh tokens.
A valid refresh subsequently issues a token with the current key.

For emergency rotation, promote the next key, obtain a fresh Management API
access token, then revoke the compromised previous key. Zeroauthy rejects its
tokens on subsequent validations. Independent remote verifiers may retain
its public key in their cache, so coordinate their cache expiry or invalidation
separately. A stale Management API token signed by the revoked key receives
401; obtain another through `/oauth/token` using the management application's
client credentials. Revoking a signing key does not revoke that application
secret.

Backfill failures stop startup rather than changing a key's identity or
falling back to rotation. Preserve the database and configured wrapping key,
inspect the structured error, and repair the storage/wrapper fault before
retrying startup. Do not delete stored keys or reseed the tenant to bypass a
certificate problem. Root-key encryption management and algorithm expansion
remain outside this milestone.
