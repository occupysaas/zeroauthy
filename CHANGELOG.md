# Changelog

All notable changes to zeroauthy are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Dynamic Client Registration and Client ID Metadata Documents (Plan 41b):
  open RFC 7591 registration at `/oidc/register` creates third-party `tpc_`
  applications; an HTTPS metadata document URL can be a `client_id`, with
  `POST /api/v2/clients/cimd/preview` and `/register` for administrators
  and the seed's `cimd_clients`; client grants accept `default_for:
  third_party_clients`. Migration 0052 adds the client fields and the
  external client ID index (storage plugins need `cimd.v1`). See
  [Dynamic Client Registration](docs/dynamic-client-registration.md).
- My Organization API (Phase A): `/my-org/v1` lets organization
  administrators manage their organization's details, members, member
  roles and invitations, scoped by the token's organization. Activation
  creates the system API `https://{canonical host}/my-org/`;
  administrators' permissions come from organization roles; applications
  carry `my_organization_configuration`; roles carry
  `my_organization_visible`. Migration 0050 adds its storage (storage
  plugins need `my_org.v1`). See
  [My Organization API](docs/my-organization-api.md).
- My Organization API Phase B: organization administrators claim domains
  and verify them through DNS, create and manage their organization's
  enterprise identity providers (connections linked to the organization),
  link verified domains for home realm discovery, and set up SCIM
  provisioning with tokens. The system API gains 18 scopes (added at
  startup to activated APIs). Migration 0051 adds domain claims. Domain
  verification uses `server.custom_domains.dns_resolver`. See
  [My Organization API](docs/my-organization-api.md).
- My Account API: `/me/v1` lets signed-in users list, enroll, verify,
  rename and delete their own passkeys, WebAuthn keys, TOTP, email and phone
  factors, recovery codes and passwords, and list the factors the tenant
  offers. Activation creates the system API `https://{canonical host}/me/`
  (console, Management API or seed `my_account_api`); applications get
  access through user client grants; each host has its own audience. See
  [My Account API](docs/my-account-api.md).
- WS-Federation: the WS-Fed Web App add-on (`addons.wsfed`, with realms in
  the new `client_aliases`) makes zeroauthy a WS-Fed identity provider with
  signed SAML 1.1 tokens, federation metadata and sign-out, and `adfs`
  enterprise connections sign users in through ADFS or any WS-Fed identity
  provider. Migration 0045 adds `client_aliases` (unique per tenant) and
  `form_template`; storage plugins need the `wsfed.v1` capability. Console,
  seed and Deploy CLI support accompany it. See
  [WS-Federation](docs/ws-federation.md).
- SAML 2.0: the SAML2 Web App add-on (`addons.samlp`) makes zeroauthy a
  SAML identity provider, with `api.samlResponse` in post-login Actions, and
  `samlp` enterprise connections sign users in through upstream SAML
  identity providers. Both directions support the Redirect and POST bindings
  and signed single logout. Migration 0044 adds client add-ons, session SAML
  participants and the assertion replay table; storage plugins need the
  `saml.v1` capability. Console, seed and Deploy CLI support accompany it.
  See [SAML](docs/saml.md).

- OIDC claims requests, phone/address/profile claims, requested MFA step-up,
  per-client ID token algorithms, back-channel logout with durable delivery,
  and enterprise upstream global revocation. Console, seed and Deploy CLI
  support accompany the settings. See [logout](docs/logout.md).
  Global revocation tolerates an upstream clock up to 60 seconds ahead and
  accepts a one-element `aud` array.

- Refresh Tokens II: strict rotation overlap and conversion, multi-resource
  and session-bound online tokens, downstream DPoP, grant/session revocation,
  token/session metadata and device history, and client-credentials quotas.
  Console, seed and Deploy CLI support accompany the new Management routes.
  See [refresh tokens](docs/refresh-tokens.md) and [upgrade notes](docs/upgrading.md).

- Enterprise OIDC and Okta login: front-channel form post, explicit endpoints,
  PKCE modes, claim mapping and userinfo, signed client assertions, encrypted
  ID tokens, upstream PAR, public connection keys and home realm discovery.
  Migration 0041 preserves existing back-channel connections and stores sealed
  connection keys. See [enterprise connections](docs/enterprise-connections.md).

- GitHub social connection (`github`): OAuth app sign-in with S256 PKCE, the
  Auth0 scope flags, a numeric `github|<id>` identity and a verified primary
  email required when `email` is on. GitHub Enterprise, device flow and token
  refresh are not supported. See [the guide](docs/social-connections.md#github).

- Sign in with Apple web login and native iOS authorization-code exchange,
  operator-owned signing keys, private-relay profiles and first-login names.
  Console, seed and Deploy CLI support include stored native-social switches;
  Google and Facebook native exchanges remain deferred to Plan 39b. Migration
  0037 adds native-social client persistence. See [the guide](docs/social-connections.md).

### Changed

- Hosted login now completes MFA before showing consent. Accepting an invitation,
  assigning membership, creating a session and recording the login commit with
  authorization. Abandoning a fresh login at either prompt leaves those changes
  unapplied. Post-login Actions retain their position.
- Management clients listing a user's organizations need `read:organizations`.
  Listing organization members requires `read:organization_members`, plus
  `read:organization_member_roles` when including roles. User search on v2/v3
  ignores the legacy `connection` parameter. See [upgrading](docs/upgrading.md).
- Console Management calls for custom-host tenants and passwordless test sends
  use the system host. The admin CSP derives its connection sources from server
  configuration.
- User updates can clear eight nullable profile attributes and request phone
  verification. Verification jobs and tickets accept an organization for a
  member. Email-provider reads expose configured public credential members and
  support field projection.
- New signup codes last 900 seconds. Send limits distinguish connection and
  purpose. Brute-force protection records the first refused attempt in each
  settled block. PostgreSQL and MySQL lock the affected counters in key order.
- The MFA sweep removes stale unconfirmed authenticators. User lists batch MFA
  lookups and authorization codes capture MFA evidence at issue time.
- The tenant JWKS (`/.well-known/jwks.json`) no longer includes `alg` on the
  signing keys, for every tenant and for keys created earlier. One key signs
  both RS256 and PS256 tokens, and jose-based verifiers such as
  `express-oauth2-jwt-bearer` refused PS256 tokens against a key marked
  `RS256`. Verifiers that select keys by `kid` are unaffected (D-0063, C19).

## [1.0.0-rc.1]

The first public release: an **early preview** for people to try. It covers
what most Auth0 tenants use, but not everything; the
[compatibility matrix](docs/compat/matrix.md) lists the gaps, and the
[roadmap](docs/superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md)
lists what comes next (Plans 35 onward).

### Added

- **Authentication API and hosted Universal Login.** Authorization code with
  PKCE, client credentials, refresh tokens with rotation, password and
  password-realm grants, `/dbconnections` signup and password change, logout,
  consent and third-party applications, pushed authorization requests (PAR),
  and the device authorization flow. OpenID Foundation certified for the Basic,
  Config and Form Post OP profiles (commit `38b4229`).
- **Multi-factor authentication.** One-time passwords (any authenticator app),
  email, SMS and voice, recovery codes, MFA policies, remember-browser, hosted
  MFA prompts, `mfa_required` and the MFA grants, Actions `multifactor` and
  `challengeWith*` APIs, Guardian and user authentication-method APIs.
- **Passwordless and phone.** Email and SMS passwordless connections, magic
  links and the OTP grant, phone identifiers on database connections, phone
  password reset, Twilio and Amazon SNS senders, and custom phone providers
  through Actions.
- **Management API.** Applications, APIs and client grants, connections
  (database, custom database, Google, Microsoft, generic OAuth 2 and OIDC,
  email accounts, passwordless), users with search, sessions, tickets and
  import/export including password hashes, tenant settings, attack protection,
  signing keys, email providers and templates, phone providers and templates,
  branding and custom text, custom domains with automatic certificates, roles
  and permissions, Actions and Modules, organizations with invitations, logs,
  log streams, stats and event streams.
- **Admin console** for all of the above.
- **Storage.** SQLite, PostgreSQL 14+ and MySQL 8.0.17+, an in-memory store,
  and gRPC storage plugins (protocol `store.v1` with negotiated capabilities).
- **Tooling compatibility.** Tested as a black box with node-auth0, the Auth0
  CLI, the Auth0 Deploy CLI, Auth0 SPA JS, auth0-react, nextjs-auth0,
  auth0-auth-js, express-openid-connect and Auth0.NET.
- **Releases.** Static binaries for linux/amd64, linux/arm64 and darwin/arm64
  with SHA-256 checksums, and a multi-arch container image on GHCR.
- **Testing kit.** Run zeroauthy as a disposable, seeded login server for
  local and CI end-to-end tests with real logins: `server.tls_self_signed`
  generates a throwaway CA and certificate at startup, and
  [docs/testing.md](docs/testing.md) with `examples/testing/` provides a seed,
  docker compose, a GitHub Actions job and sample tests.
- **Configuration reference.** [docs/configuration.md](docs/configuration.md)
  lists every setting with its `ZEROAUTHY_*` environment variable and
  default, generated from the code.
- **Request rate limits** on the Authentication API (`security.rate_limit`).

### Known limitations

- WebAuthn, passkeys, SAML, WS-Federation, enterprise directories, CIBA, JAR
  and token exchange are not implemented yet (Plans 33b and 35–44).
- Auth0 Deploy CLI 9.x cannot export Guardian factor providers because of a
  bug in the tool itself; the server's provider API works (D-0059).

[Unreleased]: https://github.com/occupysaas/zeroauthy/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/occupysaas/zeroauthy/releases/tag/v1.0.0-rc.1
