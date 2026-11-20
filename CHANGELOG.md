# Changelog

All notable changes to zeroauthy are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
