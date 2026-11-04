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
| Enterprise login | SAML and WS-Federation, SCIM, self-service SSO | Plan 37 |
| Enterprise login | Okta and generic front-channel OIDC connections, Entra ID extras, connection keys | Plan 36 |
| Enterprise login | Active Directory / LDAP connector | Plan 38 |
| Social login | Providers beyond Google, Microsoft and generic OAuth 2 / OIDC (Apple, GitHub, Facebook, ...) | Plan 39 |
| Protocol | Back-channel and front-channel logout, CIBA, Dynamic Client Registration, the `claims` parameter | Plan 41 |
| Protocol | Implicit and hybrid flows (`response_type=token`, `id_token`) | Plan 41, only where Auth0's behaviour passes the OIDF profiles |
| Client authentication | `private_key_jwt`, JWT-secured authorization requests (JAR), token exchange | Plan 35 |
| Universal Login | Advanced Customizations (ACUL) and the Classic and WebAuthn-first modes; arbitrary page JavaScript | Plan 44 |
| Actions | Newer triggers (password-hash migration, credential validation, custom token exchange), `/userinfo` custom claims, `event.refresh_token`; `event.authentication.methods` lists only the MFA step | Plans 35, 40 |
| Other APIs | My Account API, My Organization API | Plan 42 |
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
| OpenID Connect | Discovery, JWKS, authorization code with PKCE, `form_post` and `web_message`, refresh token rotation, `/userinfo`, RP-initiated logout. OpenID Certified (Basic, Config and Form Post OP, 2026-10-30) | [conformance](conformance.md) |
| OAuth grants | Client credentials, password and password-realm, device authorization, pushed authorization requests (PAR), MFA grants, passwordless OTP grant, revocation | [device flow](device-flow.md), [PAR](par.md) |
| Hosted login | Login, signup, password reset, consent, identifier-first, organization prompts, MFA prompts, passwordless codes, languages, branding and page templates | [branding](branding.md), [consent](consent.md) |
| Connections | Database, custom database (Auth0 scripts, import mode), Google, Microsoft personal and work accounts, generic OAuth 2, back-channel OIDC, passwordless email and SMS | [custom DB](custom-db.md), [social](social-connections.md), [passwordless](passwordless.md) |
| MFA | One-time passwords, email, SMS and voice, recovery codes, policies, remember browser, Guardian and authentication-method APIs | [MFA](mfa.md) |
| Management API | Applications, APIs and grants, connections, users (search, linking, sessions, tickets, import and export with password hashes), roles and permissions, organizations and invitations, tenant settings, attack protection, signing keys, email and phone providers and templates, branding and custom text, custom domains, Actions and Modules, logs, log streams, stats, event streams | [Management API](management-api.md) |
| Actions | Ten triggers, including post-login with MFA control, registration, password, custom email and phone providers and event streams | [Actions](actions.md) |
| Operations | SQLite, PostgreSQL, MySQL, gRPC storage plugins; automatic certificates for custom domains; admin console | [deployment](deployment.md), [console](console.md) |

## Tested clients

These Auth0 SDKs and tools run unmodified against zeroauthy in the test
suites: auth0-spa-js, auth0-react, nextjs-auth0, express-openid-connect,
auth0-auth-js, node-auth0, Auth0.NET, the Auth0 CLI and the Auth0 Deploy CLI.
The Deploy CLI cannot export Guardian factor providers because of a bug in the
tool itself ([MFA guide](mfa.md#deploy-cli-and-troubleshooting)).

Found something that behaves differently from Auth0's documentation? Please
open an issue with the Auth0 documentation link.
