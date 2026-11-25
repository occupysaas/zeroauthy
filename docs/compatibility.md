# Compatibility

zeroauthy aims to be a drop-in replacement for Auth0's Authentication API and
Management API: point an Auth0 SDK or tool at a zeroauthy tenant domain and it
should work unchanged. Version 1.0 is an **early preview** and does not cover
everything yet. This page lists the gaps first. The detailed, evidence-backed
status of every surface is in the [compatibility matrix](compat/matrix.md),
and deliberate differences are recorded in
[decisions](compat/decisions.md). Plan numbers refer to the
[roadmap](superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md).

zeroauthy is an independent, clean-room project and is not affiliated with
Auth0 or Okta.

## Not supported in 1.0

| Area | Missing | Planned |
|---|---|---|
| MFA | WebAuthn (security keys, device biometrics) and passkeys | Plan 33b |
| MFA | Push notifications (Guardian app) and Duo: settings are stored, not enforced | not planned yet |
| Enterprise login | SAML 2.0 identity provider add-on and `samlp` connections implemented; artifact binding, SOAP and ECP are not | [Guide](saml.md) |
| WS-Federation | WS-Fed Web App add-on (SAML 1.1 tokens, metadata, sign-out) and `adfs` connections implemented; WS-Trust active endpoints and JWT tokens are not | [Guide](ws-federation.md) |
| SCIM and groups | Inbound SCIM 2.0 provisioning of enterprise connections; directory groups with tenant and organization group roles | [Guide](scim.md) |
| Self-service SSO | Self-service profiles, SSO tickets and the hosted assistant for `samlp`, `oidc`, `okta`, `waad` and `adfs`; connection profiles stored | [Guide](self-service-sso.md) |
| Google Workspace | `google-apps` connections bound to one Workspace (`hd`); directory provisioning of users and groups with administrator consent, on demand and every 40 minutes | [Guide](directory-provisioning.md) |
| Enterprise login | Directory provisioning (Google Workspace) | Plan 37c phase C |
| Enterprise login | OIDC/Okta front/back channel, mapping, PAR, JWE, connection keys and domain routing implemented; Entra Graph extras remain deferred | [Guide](enterprise-connections.md) |
| Enterprise login | `ad` connections through Auth0's AD/LDAP Connector implemented (password login, Kerberos, password change, status, several replicas); a native LDAP bind and the hosted forgot-password flow for `ad` users are not | [Guide](ad-ldap.md) |
| Social login | Providers beyond Apple, Google, Microsoft, GitHub and generic OAuth 2 / OIDC (Facebook, ...) | Plan 39b |
| Social login | GitHub: OAuth app sign-in and token retrieval implemented; GitHub Enterprise, device flow and token refresh are not | [Guide](social-connections.md#github) |
| Native social login | Google and Facebook exchanges (switches are stored only); Apple is implemented | Plan 39b |
| Protocol | Front-channel logout, CIBA, Dynamic Client Registration | Plan 41 |
| Protocol | Implicit and hybrid flows (`response_type=token`, `id_token`) | Plan 41, only where Auth0's behaviour passes the OIDF profiles |
| Universal Login | Advanced Customizations (ACUL) and the Classic and WebAuthn-first modes; arbitrary page JavaScript | Plan 44 |
| Actions | Newer triggers (password-hash migration, credential validation), `/userinfo` custom claims, `event.authentication.methods` lists only the MFA step | Plan 40 |
| My Account API | `/me/v1` authentication methods (passkeys, WebAuthn keys, TOTP, email, phone, recovery code, password) and factors; connected accounts, consents and profile are not | [Guide](my-account-api.md) |
| Other APIs | My Organization API | Plan 42b |
| Other APIs | Token Vault and connected accounts | Plan 43 |
| Other APIs | Forms and Flows, network ACLs, user groups and group roles | Plan 38 |
| Attack protection | Phone-provider protection `exponential` backoff is stored, not enforced | Plan 45 |
| Attack protection | Administrator notification emails and unblock links in user notices | not scheduled |
| Event streams | Group events | Plan 38 |
| Event streams | Amazon EventBridge delivery (configurations are stored disabled) | not scheduled |
| Custom domains | Relying Party ID is stored only | Plan 33b |
| Legacy | Rules, Hooks, rules configs (retired by Auth0), deprecated endpoints (`/oauth/ro`, `/delegation`, `/tokeninfo`) | not planned |

Some fields are accepted and stored so that exports and tools round-trip, but
have no effect yet; the feature guides label them "stored only".

## Supported

| Area | What works | Guide |
|---|---|---|
| OpenID Connect | Discovery, JWKS, authorization code with PKCE, `form_post` and `web_message`, refresh token rotation, `/userinfo`, scope-bound `claims` requests, RP-initiated and back-channel logout. OpenID Certified (Basic, Config and Form Post OP, 2026-10-30) | [conformance](conformance.md), [logout](logout.md) |
| Refresh tokens and sender constraints | Rotation conversion, strict overlap, MRRT, session-bound online tokens, metadata, grant/session revocation, client-credentials quotas and downstream DPoP | [refresh tokens](refresh-tokens.md), [DPoP](dpop.md) |
| OAuth grants | Client credentials, password and password-realm, device authorization, pushed authorization requests (PAR), MFA grants, passwordless OTP grant, custom token exchange, revocation | [device flow](device-flow.md), [PAR](par.md), [token exchange](token-exchange.md) |
| Client authentication | Client secrets, `private_key_jwt` (RS256, RS384, PS256 keys, two per application), JWT-secured authorization requests (JAR), `HS256` and `PS256` API access tokens | [client authentication](client-authentication.md) |
| Hosted login | Login, signup, password reset, consent, identifier-first, organization prompts, MFA prompts, passwordless codes, languages, branding and page templates | [branding](branding.md), [consent](consent.md) |
| Connections | Database, custom database (Auth0 scripts, import mode), Google, Microsoft personal and work accounts, generic OAuth 2, back-channel OIDC, passwordless email and SMS | [custom DB](custom-db.md), [social](social-connections.md), [passwordless](passwordless.md) |
| MFA | One-time passwords, email, SMS and voice, recovery codes, policies, remember browser, Guardian and authentication-method APIs | [MFA](mfa.md) |
| Management API | Applications, APIs and grants, connections, users (search, linking, sessions, tickets, import and export with password hashes), roles and permissions, organizations and invitations, tenant settings, attack protection, signing keys, email and phone providers and templates, branding and custom text, custom domains, Actions and Modules, logs, log streams, stats, event streams | [Management API](management-api.md) |
| Actions | Eleven triggers, including custom token exchange, post-login with MFA control, registration, password, custom email and phone providers and event streams | [Actions](actions.md) |
| Operations | SQLite, PostgreSQL, MySQL, gRPC storage plugins; automatic certificates for custom domains; admin console | [deployment](deployment.md), [console](console.md) |

## Tested clients

These Auth0 SDKs and tools run unmodified against zeroauthy in the test
suites: auth0-spa-js, auth0-react, nextjs-auth0, express-openid-connect,
auth0-auth-js, node-auth0, Auth0.NET, the Auth0 CLI and the Auth0 Deploy CLI.
The Deploy CLI cannot export Guardian factor providers because of a bug in the
tool itself ([MFA guide](mfa.md#deploy-cli-and-troubleshooting)).

Found something that behaves differently from Auth0's documentation? Please
open an issue with the Auth0 documentation link.

Plan 41a adds standard phone/address/profile claims, bounded claims requests,
requested MFA ACR, client OIDC restrictions, ID token algorithm selection,
back-channel logout and connection-scoped global revocation. The default
resource profile continues to use `audience`; the tenant compatibility profile
maps one `resource` to audience and rejects conflicts or multiple targets.
Claims requests cannot widen granted scopes or expose user/app metadata.
The environment-only exceptions, receiver requirements and actual implemented
initiators are documented in [logout](logout.md). Certification and full-plan
verification are recorded separately from feature availability.
