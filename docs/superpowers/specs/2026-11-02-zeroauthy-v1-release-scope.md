# zeroauthy v1.0 — Release scope proposal

**Date:** 2026-11-02. **Status:** accepted by the maintainer 2026-11-02 (three tiers as written,
including WebAuthn after 1.0). Target: release within days. §6 items 2–4
are still open.

**Why now:** the project is getting public attention (maintainer, 2026-11-02),
so v1.0 should ship soon. Plans 33–47 in the
[management roadmap](2026-10-19-zeroauthy-management-roadmap-design.md) are
too much to finish first. This document sorts them into three groups:
**v1.0** (must ship), **v1.0 if ready** (ships only if done in time, never
waited for) and **after 1.0**.

## 1. What a v1.0 user can already do

Plans 1–32 are done locally:

- Authentication API and hosted Universal Login (password, signup, reset,
  consent, PAR, device flow), OIDF-certified Basic, Config and Form Post OP.
- Management API parity for applications, APIs and grants, connections
  (database, custom database, Google, Microsoft, generic OAuth 2/OIDC),
  users with import/export of password hashes, tenant settings and attack
  protection, signing keys, email providers and templates, branding and
  custom text, custom domains with automatic certificates, RBAC, Actions
  (post-login, signup, reset, credentials exchange, custom email, Modules),
  organizations with invitations, logs, log streams, stats, and event streams.
- Console for all of the above; SQLite, PostgreSQL, MySQL and plugin
  storage; Deploy CLI round trip; node-auth0, auth0-cli, Auth0 SPA and other
  SDKs tested as black-box clients.

That already covers what most Auth0 tenants use. The biggest gap a new user
would hit is MFA.

## 2. v1.0 — must ship

| Item | Scope for 1.0 | Source |
| --- | --- | --- |
| **MFA (Plan 33, trimmed)** | OTP (any authenticator app), email, recovery codes, policies, remember browser, hosted prompts, `mfa_required` and MFA grants, Actions `multifactor.enable`/`challengeWith*`, Guardian and user authentication-method APIs, console. **WebAuthn moves to 1.x with passkeys (Plan 33b).** That cuts Plan 33 Tasks 2 and 10 and the WebAuthn parts of 4–8 and 16. | Plan 33 spec |
| **Security hardening (Plan 45, subset)** | General Authentication API rate limiting and shared counters (open since Plans 2, 11, 19); custom-script Try limiting; a whole-repository security review (`/security-review` plus a manual pass over token, session and secret handling) with findings fixed; `SECURITY.md` with a disclosure contact. | Plan 45, follow-ups |
| **Release (Plan 46, core)** | Semantic versioning and a `v1.0.0` tag; reproducible builds for linux/amd64, linux/arm64 and darwin/arm64 with checksums; a multi-arch container image; migrations tested from a fresh database and from the oldest supported schema; upgrade and rollback notes; the conformance run as the last release gate; a CHANGELOG. | Plan 46 |
| **First-run documentation** | README quickstart (container in 5 minutes: first tenant, first app, log in with an Auth0 SDK); deployment guide (TLS, master key, backups, SQL choice, reverse proxy); a public "what's compatible" page generated from `docs/compat/matrix.md` that lists the gaps plainly; "migrating from Auth0" (Deploy CLI export/import, user export with hashes). | new |
| **Stability promise** | Name what 1.0 promises won't break: the Auth0-compatible HTTP APIs, the configuration file, the storage plugin protocol (store v1 plus negotiated capabilities) and database upgrade paths. The console UI and internal Go packages are explicitly not covered. | new |

**Exit criteria for 1.0:**

- All of the above are merged.
- The full Go race suite, the three SQL drivers, the console tests, the E2E
  lanes and local OIDF conformance pass on the release commit, with actual
  results recorded.
- The security review has no open high or critical findings.
- A clean-machine quickstart passes, run by someone other than the author
  of the docs.

## 3. v1.0 if ready (never waited for)

| Item | Why it might make it |
| --- | --- |
| GitHub social connection (part of Plan 39) | Short (profile mapping plus a fixture on Plan 24's core) and popular with the developer audience. Apple needs a full design and comes after 1.0. |
| Console translations beyond English | No dependency; can land any time. |
| `private_key_jwt` client authentication (part of Plan 35) | Short. It also unlocks more conformance profiles later. |

## 4. After 1.0

Ordered by expected demand. Each keeps its roadmap design:

1. **Plan 34:** passwordless and SMS, with native multi-provider SMS (maintainer ruling 2026-11-02), and MFA by SMS/voice.
2. **Plan 33b:** passkeys as a first factor and WebAuthn MFA (security keys, biometrics).
3. **Plan 39:** remaining social providers, including Apple.
4. **Plan 41:** OIDC extras, front- and back-channel logout, CIBA, more certification profiles.
5. **Plan 35 (rest):** JAR, token exchange.
6. **Plans 36–37:** enterprise OIDC, SAML, WS-Federation, SCIM.
7. **Plan 42:** My Account API and My Organization API.
8. **Plan 40:** Actions III (real risk signals replace the confidence-score stand-in).
9. **Plans 38, 43, 44:** AD/LDAP, Forms and Flows, Token Vault, ACUL.
10. **Plan 45 (rest), observation follow-ups** (Plans 32–33), **Plan 47** hosted zeroauthy.

## 5. Suggested order of work

1. Trim Plan 33 (WebAuthn out) and execute it. In parallel, as an
   independent worktree, do the Plan 45 subset: rate limiting first.
2. Plan 46 core and the first-run docs, written against the MFA-complete build.
3. Security review and fixes, then the release-candidate tag `v1.0.0-rc.1`.
   A short public RC period collects install feedback.
4. `v1.0.0`.

## 6. Decisions needed from the maintainer

1. Confirm the three tiers above, especially WebAuthn moving after 1.0.
2. Supported platforms and artefacts: binaries, container image, and
   whether Homebrew or packages count for 1.0.
3. Release channel: GitHub Releases plus GHCR? Is a public RC period wanted?
4. Licence and trademark check before press. The repository is LICENSE +
   NOTICE; confirm that README wording around "Auth0-compatible" uses
   Auth0's name only descriptively.
