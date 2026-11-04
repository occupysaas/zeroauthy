# Admin console and first-run/user documentation review

## Summary

The console is in good shape on security. Tokens stay in memory only, sign-in uses PKCE with state and nonce, the CSP is strict (`script-src 'self'`, no inline code), there is no `v-html`, previews render in `sandbox=""` srcdoc iframes, secret inputs are write-only and cleared after save, Management CORS allows only the system origin, and the system tenant has signup disabled. One console feature is broken: the passwordless test send (F7). One low information leak: the unauthenticated `/admin/` CSP header lists every tenant's domains (F8).

The documentation is the weak part, and it does not yet meet the 1.0 scope:
- There is no container image and no quickstart that reaches an SDK login.
- `SECURITY.md`, `CHANGELOG`, a stability promise, and upgrade, rollback and backup guidance are all missing.
- README, `docs/compat/matrix.md` and `docs/console.md` contain stale claims that would mislead a first-time user.

Trademark use is descriptive throughout. NOTICE has a nominative-use disclaimer, and README says "not affiliated with Auth0 or Okta".

**Counts:** 0 critical, 3 high, 4 medium, 3 low. **Fix-before-1.0: 6** (F1–F6).

## Findings

### F1 [high] [docs-drift] No zero-to-SDK-login path; quickstart depends on a Go toolchain and the E2E test config
- Where: README.md:173-245 (Quick start); no `Dockerfile`/`Containerfile` anywhere in the repo; `.github/workflows` has only `ci.yml` and `conformance.yml`; tests/e2e/config.yaml
- What: The 1.0 scope requires a "container in 5 minutes: first tenant, first app, log in with an Auth0 SDK" quickstart. Today's quickstart builds from source (it does not say Go 1.26.7 is needed) and runs `tests/e2e/config.yaml`. That config uses memory storage, debug logging, `email.driver: dir` writing to `/tmp/zeroauthy-e2e-mail`, and the E2E seed with published test secrets. The quickstart ends at curl and an `/authorize` URL that redirects to `https://localhost:3443/`, where nothing is listening.
- Missing steps for a first-time user:
  1. Get the software: a container image (none exists) or a release binary (`scripts/dist.sh` exists but nothing is published), plus the prerequisites: Go version, openssl, and Node ≥22.13 only for Actions and custom DB.
  2. Write a minimal production config file. No example config ships; README refers to `zeroauthy.yaml` without showing one. It needs `server.listen`, `base_domain` vs `system_host`, TLS cert and key, or ACME, `storage.dsn`, `security.master_key`, email driver, and `seed_mode`.
  3. DNS and hosts: tenant hosts as `<name>.<base_domain>` or explicit `domains`, a wildcard certificate, and trust in a self-signed CA for Node SDKs (`NODE_EXTRA_CA_CERTS`).
  4. `zeroauthy migrate` (or `auto_migrate`) for SQL, then `admin create`.
  5. Create the first tenant in the console. Explain what the "Domains" field means when `base_domain` is empty (CreateTenantDialog.vue:67).
  6. Create a database connection, or confirm the default one exists, and enable it for the app. Without this no user can sign in (console.md:139-141 only mentions it in passing).
  7. Create the first application: callback, logout and web-origin URLs, and where to read the domain and client ID.
  8. Create a user, or enable signup.
  9. A runnable SDK sample (for example auth0-spa-js or express-openid-connect) with `domain` including the port, plus the expected result.
  10. How to get a Management API M2M token for the tenant.
  11. "Migrating from Auth0": Deploy CLI export/import (deploy-cli.md exists) and user export with hashes (user-import.md covers import, but there is no end-to-end migration page).
- Evidence: v1 scope §2, "First-run documentation" row; README.md:176-178 and :188-196.
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0
- Suggested fix: Add a Containerfile and image, `docs/quickstart.md` (container, tenant, app, SDK login), `examples/zeroauthy.yaml`, `docs/deployment.md` and `docs/migrating-from-auth0.md`. Move the E2E-config quickstart under "Development".

### F2 [high] [docs-drift] `SECURITY.md` does not exist
- Where: repository root (`ls SECURITY*` finds no matches)
- What: 1.0 must ship a disclosure contact. The project is getting press attention and has no private vulnerability-reporting channel.
- Evidence: v1 scope §2, Security hardening row: "`SECURITY.md` with a disclosure contact".
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0
- Suggested fix: Add `SECURITY.md` with the contact, or GitHub private advisories, supported versions (1.0.x), and the response window. Link it from README.

### F3 [high] [docs-drift] No CHANGELOG, stability promise, or upgrade, rollback and backup story
- Where: repository root (no CHANGELOG); README.md:307-315 (migrate is the only upgrade text); `grep -i backup` finds no hit in README or any operator guide outside per-feature notes
- What:
  - Nothing names what 1.0 promises won't break: the HTTP APIs, the config file, store v1 plus negotiated capabilities, and database upgrade paths, with the console and Go packages excluded.
  - Nothing explains backups. A database backup is useless without the master key, because signing keys, client secrets and provider credentials are envelope-encrypted (README.md:281-285). Losing the key is unrecoverable, and that is not stated anywhere.
  - Nothing explains rollback. Migrations go forward only, and `serve` refuses a schema that is ahead of the binary (README.md:310-312), so rolling back means restoring a backup. That is undocumented.
  - The MySQL partial-DDL note (README.md:313-315) is the only failure guidance.
- Evidence: v1 scope §2, "Release" row (upgrade and rollback notes, a CHANGELOG) and "Stability promise" row.
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0
- Suggested fix: Add `CHANGELOG.md` and `docs/stability.md`. In `docs/deployment.md`, add "Backups" (database plus master key, stored separately, with a restore drill) and "Upgrades and rollback" (back up, migrate, restart; roll back only by restore).

### F4 [medium] [docs-drift] README status and roadmap omit MFA and passwordless and list Plans 33 and 34 as "Later"
- Where: README.md:20-35 (Status), :49 ("**Done** (Plans 1–32)"), :139-142 (Later table rows 33 and 34)
- What: HEAD is `d23dfad Merge Plan 34`. MFA, the headline 1.0 feature, and passwordless and phone are merged, but README presents them as future work. Its status paragraph still says "early" and lists only Plans ≤32. README is the first page press and new users read.
- Evidence: git log; docs/mfa.md and docs/passwordless.md exist; matrix.md:190-215.
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0
- Suggested fix: Rewrite Status as a short "What works in 1.0" list, move 33 and 34 to Done (noting WebAuthn moves to 33b), and link the compatibility page.

### F5 [medium] [docs-drift] `docs/compat/matrix.md` is stale in places and is not a plain gap list
- Where (all in docs/compat/matrix.md):
  - :72-75: "certification: pending". README.md:15-17 says certified on 2026-10-30.
  - :13: hosted login "Database connections only". Social (Plan 24), passwordless (Plan 34) and MFA prompts exist.
  - :62: "custom-text Management API planned (sub-project 3)". Plan 22 shipped it.
  - :19: "no grants API until sub-project 3". `/api/v2/grants` exists, per matrix.md:50.
  - :216-225: Plan 34 is "(in progress)" and "`/passwordless/start` … answer `501 passwordless_unavailable` until Task 10". The plan is merged.
  - :40: Passwordless row says "acceptance/regression in progress".
  - :35: "Implicit/hybrid flows | Planned | Not part of Plan 5". No roadmap plan is named.
- What: The page reads as a development log, with plan-record prose and phrases like "four-cell Deploy evidence". It has no plain "Not supported in 1.0" section, although the v1 scope asks for a public page that "lists the gaps plainly". Gaps a user needs listed: WebAuthn and passkeys, SAML and WS-Fed, enterprise OIDC extras, AD/LDAP, social providers beyond Google, Microsoft and generic (Apple, GitHub, Facebook), back- and front-channel logout, CIBA, `private_key_jwt`, JAR, token exchange, implicit and hybrid flows, push and Duo MFA, Forms and Flows, the My Account and My Organization APIs, Token Vault, ACUL, Rules and Hooks (not planned), and custom-domain stored-only fields. The console Home page links users to this file (console/src/links.ts:14).
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0
- Suggested fix: Correct the stale rows. Add a user-facing `docs/compatibility.md`: per-area Supported / Partial / Not supported tables, with the gap list first and roadmap plan numbers. Keep matrix.md as the evidence log.

### F6 [medium] [docs-drift] `docs/console.md` misdescribes bootstrap, operator scope and the sections
- Where:
  - docs/console.md:30-33: "the server creates that one and logs the link once". The code writes the link to a 0600 file and logs only its path (internal/app/app.go:460, `"setup_file"`), as README.md:216-224 says correctly. A first-time user following console.md will search the log for a link that is not there.
  - :38-39: "every operator manages every tenant for now". Per-tenant operators exist (docs/organizations.md:211-226; internal/mgmt/auth.go:290-300).
  - :78: "Actions is a placeholder only". The Actions console is live (sections.ts:39).
  - :54-62: the sidebar list leaves out Passwordless email and SMS, Enterprise, Phone providers and templates, Log streams, Event streams and Actions logs (sections.ts:23-47). It also describes "Planned" tags, but no section is planned any more.
  - There are no screen sections for Roles, Organizations, MFA, Actions, Logs, Event streams or Passwordless.
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0 for the bootstrap and operator-scope lines (they mislead a first-run user); the screen inventory can follow, under Plan 46 docs.
- Suggested fix: Replace the bootstrap paragraph with README's setup-file wording. Describe scoped operators. Regenerate the sidebar list from `sections.ts` and link each feature guide.

### F7 [medium] [defect] Passwordless "send test" in the console calls `/passwordless/start` cross-origin and is blocked by CORS
- Where: console/src/pages/connections/PasswordlessSettings.vue:192-212; internal/server/cors.go:23,35-40,59-71; internal/server/server.go:241
- What:
  - The test send POSTs JSON with `Authorization: Bearer <operator token>` from the system origin to `https://<tenant host>/passwordless/start`. That route uses the Authentication API `cors()`, which allows only origins listed in the tenant's clients' `allowed_origins` or `web_origins`, not `mgmtCORS`.
  - The request needs a preflight (JSON plus Authorization). With default data, that preflight gets 403 and the browser fails the call.
  - It also sends the operator's Management token to an endpoint that does not use it.
  - The phone provider and template test sends use Management "try" routes and are not affected.
  - The unit test (phone.test.ts:150) mocks fetch, and no browser E2E exercises this button.
- Evidence: Code path above. The preflight result depends on data (it passes only if some app lists the system origin).
- Verdict: CONFIRMED in code; user impact PLAUSIBLE (not run in a browser)
- Recommendation: defer-to-Plan-45. If the button stays in 1.0, hide it, because it fails with "Failed to fetch".
- Suggested fix: Add an operator-only system route (`/api/system/tenants/{t}/passwordless/try`) that runs the start service server-side, as the phone "try" routes do. Never send the operator token to Authentication API routes.

### F8 [low] [defect] Unauthenticated `/admin/` CSP header lists every tenant's domains
- Where: internal/server/admin.go:68-80
- What: `csp()` adds `https://<d>` for every domain of every tenant to `connect-src`. It does this on every response, before any sign-in, and for every operator whatever their tenant scope. Anyone who can reach the system host can list all tenants' hosts. In multi-customer setups with per-tenant operators (the Plans 29, 30 and 47 vision), customers learn about each other.
- Evidence: admin_test.go:41 asserts the tenant domains appear in the header.
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-45 (or Plan 47 before hosting)
- Suggested fix: Rely on `https://*.<base_domain>`. For explicit domains, accept `https:` in `connect-src`, or serve the console on the system host only and proxy tenant Management calls through it.

### F9 [low] [docs-drift] Console links point at `main`, not the shipped version's docs
- Where: console/src/links.ts:7-18 (`tree/main/docs`, `blob/main/...`)
- What: After 1.0, the embedded console will link to documentation for unreleased behaviour.
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-46
- Suggested fix: Inject the build version and link to `/blob/v<version>/docs/...`, falling back to `main` for `dev` builds.

### F10 [low] [docs-drift] Stray development report tracked at the repository root
- Where: task-12-report.md (tracked, added in commit e554004; describes Plan 32 Task 12 with local worktree paths)
- What: It will ship in the 1.0 source archive and confuse readers.
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-46 (release hygiene; trivial)
- Suggested fix: Move it to `docs/superpowers/` or delete it.

### Notes (not findings)
- Trademark: README, NOTICE and the console strings use "Auth0" only to describe compatibility. The built-in API's name, "Auth0 Management API" (matrix.md:46, Plan 20), is a wire-compat value. That is acceptable, but the maintainer should confirm it in the §6.4 licence and trademark check. The press-facing README line "drop-in replacement for Auth0's Authentication API and Management API" is a goal statement; F4's rewrite should qualify it with "aims to be" plus a link to the gap list.
- Console secrets: the application client secret is masked, revealed only on request, and shown only when the API returns it. Social, email, log-stream, event-stream, MFA, CAPTCHA and passwordless gateway secrets are never pre-filled and are cleared after save. No issue found.
- Admin session and CSRF: bearer tokens only, with no cookies sent to the Management API, so CSRF does not apply. The callback's `returnTo` comes only from the browser's own sessionStorage transaction and is used as an in-app route. No open redirect.
- `docs/console.md` "Security" bullets match admin.go and cors.go.
- Known follow-ups: none in plan-1-followups.md cover these docs; none are re-reported here.

## Changelog entries reviewed
Last recorded coverage was 2026-10-27 (docs/compat/changelog-review.md). I read the newer entries on https://auth0.com/changelog:
- 2026-10-27 — Universal Portals, Developer Preview — already logged against Plan 42; touches no console or docs surface.
- 2026-10-29 — HTTP message signatures for tenant Network ACLs — not relevant to this area; belongs with Plan 38 (network ACLs).
- 2026-10-30 — Exponential backoff for phone MFA SMS delivery — not relevant to the console or docs; the Plan 34 reviewer should check it (SMS-pumping protection in the phone MFA send path).

Dashboard-only entries are out of scope: the console look is deliberately original.

## Roadmap suggestions
- Add a **"First-run docs" workstream to Plan 46 (or a new docs plan)** with these deliverables: Containerfile and multi-arch image, `docs/quickstart.md`, `examples/zeroauthy.yaml`, `docs/deployment.md` (TLS and ACME, reverse proxy and `trust_proxy_headers`, master key custody, backups and restore, SQL choice, scaling job workers), `docs/upgrading.md`, `docs/stability.md`, `docs/compatibility.md` (generated from matrix.md, gaps first), `docs/migrating-from-auth0.md`, `SECURITY.md` and `CHANGELOG.md`. Exit gate: the clean-machine quickstart run by a non-author (already in the 1.0 exit criteria).
- Plan 45: the server-side passwordless "try" route (F7), the admin CSP tenant enumeration (F8), and a decision on whether MFA can be enforced for console operators on the system tenant (I did not verify this; the docs say nothing about it).
- Plan 46: versioned docs links in the console (F9), and a `docs/README.md` index so the 28 guides can be found.
