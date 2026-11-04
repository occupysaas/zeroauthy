# Changelog

All notable changes to zeroauthy are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

### Known limitations

- WebAuthn, passkeys, SAML, WS-Federation, enterprise directories, CIBA, JAR
  and token exchange are not implemented yet (Plans 33b and 35–44).
- Auth0 Deploy CLI 9.x cannot export Guardian factor providers because of a
  bug in the tool itself; the server's provider API works (D-0059).

[Unreleased]: https://github.com/occupysaas/zeroauthy/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/occupysaas/zeroauthy/releases/tag/v1.0.0-rc.1
