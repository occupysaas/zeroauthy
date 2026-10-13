# Compatibility Matrix

Status of Auth0-compatible surfaces in zeroauthy.

| Surface | Status | Notes |
|---------|--------|-------|
| Discovery (`/.well-known/openid-configuration`) | Implemented | Advertises only implemented grants; `authorization_endpoint` returns 404 until hosted login lands |
| JWKS (`/.well-known/jwks.json`) | Implemented | current, next, previous keys |
| `/oauth/token`: `client_credentials` | Implemented | Verified with @auth0/auth0-auth-js 1.16.1, auth0/legacy 7.4.0, express-oauth2-jwt-bearer 1.11.0 |
| Other Authentication API endpoints | Planned (sub-project 1, later milestones) | |
| Hosted login | Planned (sub-project 1) | |
| Passwordless, MFA, social connections, Actions | Planned (sub-project 2) | |
| Management API v2 | Planned (sub-project 3) | |
| SAML, WS-Federation | Planned (sub-project 4) | |
| Deprecated endpoints (`/oauth/ro`, `/delegation`, `/tokeninfo`, `/oauth/access_token`, impersonation) | Not planned | Deprecated by Auth0 |
