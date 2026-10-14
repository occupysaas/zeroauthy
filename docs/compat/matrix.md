# Compatibility Matrix

Status of Auth0-compatible surfaces in zeroauthy.

| Surface | Status | Notes |
|---------|--------|-------|
| Discovery (`/.well-known/openid-configuration`) | Implemented | Advertises only implemented grants; `/authorize` is now served |
| JWKS (`/.well-known/jwks.json`) | Implemented | current, next, previous keys |
| `/oauth/token`: `client_credentials` | Implemented | Verified with @auth0/auth0-auth-js 1.16.1, auth0/legacy 7.4.0, express-oauth2-jwt-bearer 1.11.0 |
| `/authorize`: `response_type=code`, PKCE (S256), `response_mode` query / fragment / form_post / web_message, `prompt` none / login, `max_age`, `connection`, `screen_hint=signup`, `login_hint` | Implemented | Verified with @auth0/auth0-spa-js 2.28.3 (login, silent auth, reload) |
| `/oauth/token`: `authorization_code` | Implemented | ID token with `at_hash`, `sid`, `nonce` |
| `/userinfo` (GET, POST) | Implemented | |
| Hosted login: `/u/login`, `/u/signup` | Implemented | Database connections only |
| Logout, refresh tokens, implicit/hybrid flows, password reset, `/dbconnections/*`, password grants | Planned (milestones 5–6) | |
| Passwordless, MFA, social connections, Actions | Planned (sub-project 2) | |
| Management API v2 | Planned (sub-project 3) | |
| SAML, WS-Federation | Planned (sub-project 4) | |
| Deprecated endpoints (`/oauth/ro`, `/delegation`, `/tokeninfo`, `/oauth/access_token`, impersonation) | Not planned | Deprecated by Auth0 |
