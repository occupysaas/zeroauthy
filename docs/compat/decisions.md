# Compatibility Decisions

Behaviors not specified by public documentation, and how zeroauthy resolves
them. Each entry: context, sources consulted, decision, rationale.

<!-- Template:
## D-0001: <title>
- **Context:**
- **Sources:**
- **Decision:**
- **Rationale:**
-->

## D-0001: Access tokens carry `jti`

- **Context:** Public Auth0 docs list the standard access token claims but do not say whether a token ID is included.
- **Sources:** RFC 9068 §2.2 (JWT access token profile requires `jti`); RFC 7519 §4.1.7.
- **Decision:** Every access token has a random 24-character `jti`.
- **Rationale:** It follows the JWT access token standard and enables future revocation lists. Clients that ignore unknown claims are unaffected.

## D-0002: client_credentials without an audience

- **Context:** A client_credentials request omits `audience` and the tenant has no default audience.
- **Sources:** RFC 6749 §5.2; Auth0 public docs describe `audience` as the target API and a tenant-level default audience.
- **Decision:** `400 invalid_request` with a description naming the missing audience.
- **Rationale:** The request lacks a required parameter, which is the definition of `invalid_request`.

## D-0003: Requested scopes that are not granted

- **Context:** The `scope` parameter names scopes the client grant does not include.
- **Sources:** RFC 6749 §3.3 (the server may issue a narrower scope and must then return `scope`), §5.2 (`invalid_scope`).
- **Decision:** Ungranted scopes are dropped and the response's `scope` lists what was issued. If none of the requested scopes are granted, respond `400 invalid_scope`.
- **Rationale:** Narrowing is standard; issuing a token with no requested permission is more likely a client bug than intent.

## D-0004: Strict token endpoint client authentication

- **Context:** A client authenticates with a method other than its registered `token_endpoint_auth_method`, or with two methods at once.
- **Sources:** RFC 6749 §2.3 ("MUST NOT use more than one authentication method in each request"); RFC 7591 §2 (`token_endpoint_auth_method`).
- **Decision:** A mismatched method → `401 invalid_client`. Two methods → `400 invalid_request`. The server log records the registered and used methods.
- **Rationale:** It follows the RFCs and avoids ambiguity about which credential was checked.

## D-0005: Session lifetime defaults

- **Context:** The spec requires absolute and idle session timeouts but does not give defaults.
- **Sources:** https://auth0.com/docs/manage-users/sessions/configure-session-lifetime-settings (public docs on tenant session lifetime settings).
- **Decision:** Default absolute lifetime 7 days and idle lifetime 3 days, overridable per tenant (`session_lifetime`, `idle_session_lifetime`, seconds). Every authenticated request slides the idle expiry, never past the absolute expiry.
- **Rationale:** These are conservative defaults for a hosted login session. Making them configurable covers deployments that need other values.
