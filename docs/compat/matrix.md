# Compatibility Matrix

Status of Auth0-compatible surfaces in zeroauthy.

| Surface | Status | Notes |
|---------|--------|-------|
| Discovery (`/.well-known/openid-configuration`) | Implemented | Advertises only implemented grants; `/authorize` is now served; advertises `end_session_endpoint` (`/oidc/logout`) and `revocation_endpoint` (`/oauth/revoke`) |
| JWKS (`/.well-known/jwks.json`) | Implemented | current, next, previous keys |
| `/oauth/token`: `client_credentials` | Implemented | Verified with @auth0/auth0-auth-js 1.16.1, auth0/legacy 7.4.0, express-oauth2-jwt-bearer 1.11.0 |
| `/authorize`: `response_type=code`, PKCE (S256), `response_mode` query / fragment / form_post / web_message, `prompt` none / login, `max_age`, `connection`, `screen_hint=signup`, `login_hint` | Implemented | Verified with @auth0/auth0-spa-js 2.28.3 (login, silent auth, reload) |
| `/oauth/token`: `authorization_code` | Implemented | ID token with `at_hash`, `sid`, `nonce` |
| `/userinfo` (GET, POST) | Implemented | |
| Hosted login: `/u/login`, `/u/signup` | Implemented | Database connections only |
| `/oauth/token`: `refresh_token` (rotation, reuse detection, leeway) | Implemented | Verified with @auth0/auth0-react 2.28.2 and @auth0/nextjs-auth0 4.32.0 |
| `/oauth/revoke` | Implemented | Refresh tokens (whole family); JWT access tokens are not revocable |
| `/v2/logout`, `/oidc/logout` (RP-Initiated Logout with confirmation) | Implemented | Verified with @auth0/auth0-react 2.28.2 and @auth0/nextjs-auth0 4.32.0; `federated` ignored; no back-/front-channel logout |
| Implicit/hybrid flows, password reset, `/dbconnections/*`, password grants | Planned (milestone 6) | |
| Passwordless, MFA, social connections, Actions | Planned (sub-project 2) | |
| Management API v2 | Planned (sub-project 3) | |
| SAML, WS-Federation | Planned (sub-project 4) | |
| Deprecated endpoints (`/oauth/ro`, `/delegation`, `/tokeninfo`, `/oauth/access_token`, impersonation) | Not planned | Deprecated by Auth0 |
