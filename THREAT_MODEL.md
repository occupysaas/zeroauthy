# Threat model

What zeroauthy protects, where untrusted input crosses into it, what could
go wrong there, and what stops it. It covers the server, the admin console
and the release pipeline, and lists only behaviour that is already public in
the docs. [SECURITY.md](SECURITY.md) defines what is in scope for reports;
[INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) says what we do when something
goes wrong.

Last reviewed: 2026-11-15

## What we protect

- **Signing keys:** each tenant's RS256 keys. Whoever holds one can mint
  tokens that every relying party of that tenant accepts.
- **The master key:** it decrypts every tenant's sealed secrets (signing
  keys, client secrets, connection and provider credentials, MFA secrets,
  TLS material). It can't be rotated in 1.0 ([deployment](docs/deployment.md#master-key)).
- **Users' credentials and sessions:** password hashes (argon2id), MFA
  secrets, recovery codes, sessions, authorization codes and refresh tokens
  (stored as hashes), and users' personal data, including what lands in
  tenant logs.
- **Tenant isolation:** one tenant's users, tokens, settings, secrets and
  code must never reach another tenant.
- **Operator access:** operator tokens manage every tenant, or a listed set,
  through `/admin/` and `/api/system/`.
- **The release pipeline:** the GitHub Releases archives, the GHCR image,
  their provenance attestations, the release workflow and the maintainers'
  accounts.

## Trust boundaries

| Boundary | Untrusted side | Main controls |
| --- | --- | --- |
| Internet → tenant hosts | Anyone: browsers, apps, attackers on the Authentication API, hosted login and Management API | Tenant chosen by host name; PKCE (S256 only); per-transaction CSRF tokens on hosted forms; nonce-based CSP; CORS allow-lists; request rate limits and [attack protection](docs/attack-protection.md) |
| Tenant administrators → their tenant | Management API clients | Client-credentials tokens only for the tenant's own Management API; Auth0 scopes; unknown fields refused; every write logged with its actor ([Management API](docs/management-api.md)) |
| Operators → all tenants | Console users | System tenant only; authorization code with PKCE; operator re-checked on every request; per-tenant operator lists ([console](docs/console.md)) |
| Tenant code → the server host | Actions, custom-database and social profile scripts | Separate Node process per tenant, Node permission model, empty environment, timeouts; **not a boundary for hostile code** on its own ([Actions](docs/actions.md), [custom databases](docs/custom-db.md)) |
| Tenant content → parsers and renderers | Templates, branding CSS, user imports, search queries, WebAuthn data | Bounded Liquid subset, HTML and CSS validators, size and nesting limits, parameterized SQL, fuzz targets |
| zeroauthy → the network | Log streams, event-stream webhooks, email and SMS providers, social and OIDC connections, ACME, CAPTCHA and breached-password checks | HTTPS, connections pinned to public addresses, no redirects; operators can relax some of these |
| Reverse proxy → zeroauthy | `X-Forwarded-*` headers | Trusted only from `trusted_proxy_cidrs` ([deployment](docs/deployment.md)) |
| zeroauthy → storage | SQL databases and gRPC storage plugins | Tenant-scoped queries; plugins never receive the master key and see sealed values only as ciphertext, but are trusted with data integrity |
| Contributors and dependencies → releases | Pull requests, Go modules, npm packages, GitHub Actions, base images | DCO sign-off and maintainer review (CODEOWNERS); go.sum, lockfiles, SHA-pinned actions, Dependabot with a cooldown, dependency review, govulncheck, npm install scripts off; releases only from a tagged commit on `release` after the `production` approval, with provenance |

## Threats (STRIDE)

Status: **Mitigated** (controls in place), **Partial** (controls with known
limits), **Operator** (depends on deployment configuration), **Gap**
(documented, not addressed yet).

| Threat | Where | Mitigation | Status |
| --- | --- | --- | --- |
| **Spoofing:** forged tokens from a stolen signing key | Signing keys | Sealed under the master key; per-tenant keys; manual rotation and revocation ([signing keys](docs/signing-keys.md)) | Partial: remote JWKS caches can trust a revoked key until they refresh |
| **Spoofing:** password guessing and credential stuffing | Login, password grants | Brute-force blocking, suspicious-IP throttling, CAPTCHA, bot detection, optional breached-password check | Partial: request rate limits are per process ([attack protection](docs/attack-protection.md)) |
| **Spoofing:** picking a tenant or client address with forwarded headers | Proxy headers | Headers trusted only from listed proxies | Operator: without `trusted_proxy_cidrs` every peer is trusted (a warning is logged) |
| **Spoofing:** maintainer account takeover | GitHub | Code owner review for CI and release files, `production` approval for releases | Partial: TODO(maintainer): confirm the organization requires two-factor authentication |
| **Tampering:** tampered release archive or image | CI, GitHub Releases, GHCR | Actions pinned to commit SHAs, no caches in release runs, read-only tokens by default, approval gate, `SHA256SUMS`, provenance attestations | Mitigated |
| **Tampering:** malicious dependency | Go modules, npm, Actions, base images | go.sum and lockfiles, install scripts off, cooldown, dependency review, govulncheck | Partial: `console/dist` is committed, so review its diffs; base images are referenced by tag |
| **Tampering:** script or markup injection in hosted pages | Branding, templates, CSS | Validators reject scripts, dangerous elements and unknown CSS; substitutions escaped; CSP | Partial: email templates need explicit `escape` for user text ([email](docs/email.md)) |
| **Repudiation:** unattributed Management API changes | Tenant logs | Every write logged with its actor | Partial: log recording is asynchronous and can drop events ([logs](docs/logs.md)) |
| **Information disclosure:** database copy plus master key | Storage, backups | Envelope encryption; tokens and codes stored as hashes; key kept apart from backups | Gap: the master key can't be rotated in 1.0; a leak means reinstalling |
| **Information disclosure:** secrets in logs | Server and tenant logs, log streams | Log scrubbing of secret-like fields and registered values | Partial: encoded or split secrets aren't caught |
| **Information disclosure:** cross-tenant reads | Management API, storage | Tenant-scoped queries; sealed values bound to their tenant; tokens limited to their tenant | Mitigated |
| **Information disclosure:** server-side request forgery | Outbound requests | HTTPS, public addresses only, no redirects | Mitigated by default; Operator: opt-outs exist, and tenant code has open TCP egress |
| **Information disclosure:** tenant code reading host data | Actions, custom databases | Empty environment, file reads limited to the runner and the tenant's build root | Operator: egress (including cloud metadata services) is open; isolate untrusted tenants ([Actions](docs/actions.md)) |
| **Denial of service:** request floods | Authentication API | Per-tenant, per-address token buckets with bounded memory | Partial: per process; the Management API and console aren't rate limited; volume floods are out of scope |
| **Denial of service:** expensive input | Search, CBOR/COSE, templates, imports, PAR | Size, term and nesting limits; bounded templates; fuzz targets | Mitigated |
| **Denial of service:** tenant code exhausting the host | Actions, custom databases | Timeouts, heap limit, per-tenant processes | Operator: Buffers, total memory and disk aren't capped; use cgroups and quotas |
| **Elevation of privilege:** tenant code escaping to the server or other tenants | Node runner | Node permission model, no child processes, workers or addons, per-tenant processes | Operator: run untrusted tenants under a dedicated uid or container |
| **Elevation of privilege:** a tenant token reaching other tenants or the system API | Management and system APIs | Audience bound to the tenant's own API; system API takes operator tokens only | Mitigated |
| **Elevation of privilege:** pull requests gaining CI privileges | GitHub Actions | `pull_request` only (no `pull_request_target`), least-privilege tokens, no persisted credentials, zizmor in CI | Mitigated |
| **Elevation of privilege:** access kept after a block or password change | Sessions, tokens | Refresh and password grants refused for blocked users; sessions and refresh tokens can be revoked through the Management API | Gap: neither a password change nor a block ends sessions or refresh tokens by itself, and issued access tokens stay valid until they expire ([Management API](docs/management-api.md)) |

## Other documented gaps

- No `Strict-Transport-Security` header; add it at the proxy
  ([deployment](docs/deployment.md)).
- Request rate limits and device-flow counters are per process; shared
  counters are planned (Plan 45).
- Passkey registration doesn't verify attestation and has no authenticator
  allow-list ([passkeys](docs/passkeys.md)).
- Event-stream webhooks are not signed; authenticate them with the
  configured authorization ([event streams](docs/event-streams.md)).
- A tenant's Actions, modules and dependencies form one trust domain and can
  read each other's secrets ([Actions](docs/actions.md)).

## The user's and operator's responsibilities

These are out of scope for vulnerability reports (SECURITY.md) when ignored:

- Keep the master key secret, backed up and stored apart from database
  backups.
- Put exactly one trusted proxy in front, list it in
  `trusted_proxy_cidrs`, and never trust proxy headers when clients can reach
  zeroauthy directly.
- For untrusted tenants: a dedicated uid or container, an egress policy
  that covers metadata services, memory limits and disk quotas, and password
  authentication for the database ([Actions](docs/actions.md),
  [custom databases](docs/custom-db.md)).
- Use verified TLS to the database, add HSTS at the proxy, and divide rate
  limits by the number of replicas ([deployment](docs/deployment.md)).
- Only install storage plugins you trust.

## Review triggers

Revisit this file when you add a protocol, grant or input format (for
example SAML, JAR, `private_key_jwt` or token exchange), an outbound
integration, a change to the tenant-code sandbox or the storage plugin
protocol, a new release channel or registry, or an AI feature; and after
every security advisory, adding what it taught us.
