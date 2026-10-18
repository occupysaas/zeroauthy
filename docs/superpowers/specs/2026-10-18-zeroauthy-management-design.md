# zeroauthy — Design: Management API and admin console (sub-project 3)

- **Status:** Approved for planning (2026-10-18)
- **Date:** 2026-10-18
- **Scope:** sub-project 3 of the core spec (§1 table, §7.1): Auth0's Management API v2 and the admin console, delivered as thin slices. This document fixes the program and designs **slice 1** in detail; later slices get their own short designs.
- **Inputs:**
  - core spec §7.1 (console technology and rules)
  - the maintainer's review notes (`2026-10-17-zeroauthy-management-ui-review-notes.md`)
  - a read-only inventory of the maintainer's dev tenant (2026-10-18; not committed)
  - the conversation of 2026-10-18

## 1. Why

The maintainer's goal: **anyone can move off Auth0 and never pay seat pricing again.** zeroauthy already speaks Auth0's Authentication API. What blocks a move is everything around it:
- getting the tenant's configuration across;
- getting the users across;
- having somewhere to look at and fix the result.

The project is for everyone, not one migration, so features are ordered by what a typical migrating tenant uses first. Simple first (KISS, MVP); harder features are documented and pushed down the road.

**What success looks like:**
- An operator installs zeroauthy, creates the first admin with one command, and signs in to the console at `/admin`.
- `auth0-deploy-cli` exports an Auth0 tenant and imports it into a zeroauthy tenant. Applications, APIs, client grants, connections and tenant settings arrive, and apps keep working with only a domain change.
- An Auth0 user export is imported. Password users receive one forced password-reset email. Social users keep signing in with their existing Google, Apple, Facebook or Microsoft accounts once those connections exist.
- Everything the console can do, a script can do through the same Management API.

**Anti-goals:**
- **Importing password hashes.** The maintainer ruled this out: Auth0 only exports hashes on request, and a five-minute reset beats the cost.
- **Private console endpoints.** The console uses only public APIs: Auth0's Management API, plus zeroauthy's small system API for tenants (§4.3).
- **A console that looks like Auth0's dashboard.** The look is original (CLEAN_ROOM.md). The review notes say what to build, not how it looks.
- **Building the long tail before the basics.** No marketplace, integration catalogues, Actions, Forms or event streams in the MVP slices.

## 2. The program: thin slices

Each slice delivers one resource end to end:
- **Management API endpoints** in Auth0's shape (paths, fields, errors, pagination, scopes), in zeroauthy's own spec-first contract `api/management.yaml`;
- **console screens** for the resource;
- **tests:** unit and contract tests, `auth0-cli` as the black-box E2E client, and from slice 5 an `auth0-deploy-cli` round trip.

| Slice | Contents | Why here |
|---|---|---|
| 1 | Console shell and admin sign-in (`system` tenant, bootstrap command, operator tokens), Management API foundation (auth, scopes, errors, pagination), **Applications** (`/api/v2/clients`, client secrets, console list/create/detail/edit/delete) | Everything else stands on it. Applications are the first thing anyone touches. |
| 2 | **APIs** (`/api/v2/resource-servers`) and **client grants** (`/api/v2/client-grants`) | Applications are useless without the APIs they call. |
| 3 | **Connections** (`/api/v2/connections`): the database connection and its settings, enabling clients, the existing custom-DB options | Third most used. It covers the "advanced settings" the maintainer wants explained. |
| 4 | **Users** (`/api/v2/users`: search, create, edit, block, delete) and **user import** (`/api/v2/jobs/users-imports`, accepting Auth0's user-export format, no passwords) plus **forced reset** (`/api/v2/tickets/password-change` and a bulk "send reset emails" action) | Moving users is the point of the migration. |
| 5 | **Tenant settings** (`/api/v2/tenants/settings`), then an `auth0-deploy-cli` export-and-import E2E against an Auth0 tenant export | After this slice, a config migration works end to end. |
| 6 | **Social connections:** a generic OAuth 2 / OIDC social connection, then Google, Apple, Facebook and Microsoft in that order, matched to imported users by provider user ID | Social users then need no reset. Order from public usage data: Facebook leads social-login share, while Google and Apple are offered most and Apple is required on iOS alongside other social logins. Google first because it is the most offered and the simplest. |

**Pushed down the road** (listed in the follow-ups, not designed here):
- passwordless and phone reset (SMS provider)
- organizations, roles and permissions (RBAC)
- MFA
- branding and email-template editors, custom domains
- logs, log streams, event streams
- Actions and Forms
- enterprise connections (SAML, LDAP/AD, Entra, Okta)
- per-tenant admin accounts
- the marketplace and integration catalogues

Each needs its own design when its turn comes.

## 3. Sources and clean room

Management API behaviour comes from:
- Auth0's public Management API documentation;
- the Apache-2.0 OpenAPI description at github.com/aminya/auth0-openapi (already in CLEAN_ROOM.md "Permitted sources");
- the open-source SDKs and tools: `auth0-cli`, `auth0-deploy-cli`, `go-auth0`, `node-auth0`;
- **firewalled observation** on the maintainer's own tenant where the docs are silent. The observer and the implementer are different sessions, and notes go to `docs/compat/observations/` in our own words (CLEAN_ROOM.md).

The console is original work. It is never modelled on captures of Auth0's dashboard.

## 4. Architecture

### 4.1 The `system` tenant and operators

- **Creation:** on first start zeroauthy creates a reserved tenant named `system`, with a database connection and a first-party SPA client `zeroauthy-console` (callback `<base>/admin/callback`). The name is reserved: the seed and the tenant API refuse it for other tenants.
- **Operators:** users of the `system` tenant. Signing in to the console is an ordinary authorization-code-with-PKCE login on the `system` tenant's hosted login pages. Any login method zeroauthy gains later works for operators too, such as Google Workspace or Entra via slice 6, or LDAP and AD when enterprise connections exist. An organisation can turn off password login for operators once SSO works.
- **Reaching the `system` tenant:** through the configured `server.base_domain` as `system.<base_domain>`, or an explicit `server.system_host` setting.
  - `server.system_host` is required when `base_domain` is empty (local development, tests). It is stored as one of the `system` tenant's domains.
  - No other tenant may claim that host: the seed and the system API refuse it, and so does a collision in `domains`.
  - `/admin` and `/api/system/` are served only when the resolved tenant is `system`.
- **Bootstrap:** `zeroauthy admin create --email <addr>` creates the operator in the `system` tenant and prints a one-time setup link valid for one hour. The link uses the existing password-reset ticket flow. The command runs against the same storage as the server (the same config file), so only someone with shell access to the server can create the first admin.
  - **Automated installs** may set only `ZEROAUTHY_BOOTSTRAP__ADMIN_EMAIL`. On a start that finds no operator, the server creates that user and logs the one-time link once. No password is ever taken from configuration.
- **Operator scope:** in the MVP every operator manages every tenant. The data model stores, per operator, a list of tenants or `*`, defaulting to `*`, so per-tenant admins can be added later without a migration.

### 4.2 The Management API (`/api/v2/`)

- **Where:** served on every host of the tenant at `https://<host>/api/v2/`, as on Auth0, so tools pointed at a domain work unchanged. Discovery and the Authentication API are unaffected.
- **Audience:** each tenant has one **canonical Management API identifier**, `https://<name>.<base_domain>/api/v2/`, or `https://<first entry of domains>/api/v2/` when there is no base domain. This mirrors Auth0, where the identifier stays on the tenant's own domain even when a custom domain is used. Tokens are checked against that identifier, whichever of the tenant's hosts receives the request.
- **Two kinds of caller:**
  - **Machine-to-machine clients of the tenant** (Auth0 parity). A client-credentials token whose audience is the tenant's Management API identifier `https://<tenant host>/api/v2/`, with scopes from a client grant. Each tenant gets a system resource server for that identifier, carrying Auth0's Management API scope names (`read:clients`, `create:clients`, …). It is created on demand, like Auth0's built-in "Auth0 Management API" entry. This is what `auth0-cli` and `auth0-deploy-cli` use.
  - **Console operators.** An access token from the `system` tenant with audience `urn:zeroauthy:management`, accepted on every tenant's `/api/v2/` with all scopes, limited by the operator's tenant list. This is a deliberate, explicit exception to "one tenant, one issuer":
    - The verifier accepts the `system` tenant's issuer and keys, and nothing else, as the second trust anchor.
    - The `system` tenant gets a resource server for `urn:zeroauthy:management` at creation.
    - The minter adds an operator claim, `https://zeroauthy.dev/operator` listing the operator's tenants, only for users flagged as operators, and only for that audience. A user's operator status is a stored flag, not a client grant.

    The console calls each tenant's API directly with this token, so CORS on `/api/v2/` allows only the `system` host's origin.
- **Shared behaviour:**
  - errors in Auth0's management error shape (`statusCode`, `error`, `message`, `errorCode`);
  - page and offset pagination (`page`, `per_page`, `include_totals`) and checkpoint pagination where Auth0 uses it;
  - `fields` and `include_fields`;
  - rate-limit headers when a limiter exists (follow-up).
- **Contract:** `api/management.yaml`, generated into `internal/gen/mgmtapi` with the same oapi-codegen setup as the Authentication API. A contract test checks that responses match the schema.

### 4.3 The system API (`/api/system/`)

Tenant names follow DNS-label rules (lower case, digits and hyphens, at most 63 characters), because they become subdomains. Creating a tenant reuses the seed's tenant set-up: signing keys, and a default database connection. `Tenants.Delete` is added to the store, and deleting a tenant removes all its data.


Auth0 has no API to create or list tenants. zeroauthy needs one for the console's tenant switcher and "create tenant", so it gets a small API of its own on the `system` host:
- `GET`, `POST`, `PATCH` and `DELETE` on `/api/system/tenants`;
- `GET /api/system/operators`, plus invite and remove.

It accepts operator tokens only, and is in `api/management.yaml` under its own tag.

### 4.4 The console

- **Stack:** Vue 3, Vite and TypeScript, in `console/` at the repo root.
- **Build and embedding:**
  - The production build goes to `console/dist`, which is committed, so `go build` and `go install` work without Node.
  - CI rebuilds it and fails on a diff, as with generated code.
  - The binary embeds it with `go:embed` and serves it at `/admin` on the `system` host, with history-mode fallback to `index.html`.
  - The console gets its own CSP, separate from the hosted pages: no inline scripts, hashed assets, `connect-src` limited to the zeroauthy hosts it calls.
- **API client:** a TypeScript client generated from `api/management.yaml` (openapi-typescript or similar), committed and checked in CI like the Go generation.
- **Sign-in:** authorization code with PKCE against the `system` tenant. The access token is kept in memory only, and refresh uses a rotating refresh token in memory (no localStorage), as auth0-spa-js does.
- **Layout:**
  - a header with the product name, tenant switcher, docs link, source link and account menu;
  - a sidebar whose sections appear only when their slice ships: in slice 1, Home and Applications;
  - light and dark themes;
  - fully keyboard-accessible, with WCAG 2.2 AA as the target.
- **Components:** a small set of our own components on a headless library (Radix Vue or similar) rather than a full design system, to keep the look original and the bundle small. Tables are server-paginated.
- **Language:** English only in the MVP, with strings in one catalog file so translation can follow.
- **Tests:** Vitest for components, and Playwright E2E for the console flows, reusing `tests/e2e/run-browser.sh`.

## 5. Slice 1 in detail: console shell, admin sign-in, applications

### 5.1 Management API: applications

Auth0's `/api/v2/clients` surface, limited to fields zeroauthy supports:
- `GET /api/v2/clients` (list, filtered by `app_type` and `is_first_party`, with pagination and fields);
- `POST /api/v2/clients`;
- `GET`, `PATCH` and `DELETE /api/v2/clients/{id}`;
- `POST /api/v2/clients/{id}/rotate-secret`.

**Fields:** those the store already has, with Auth0 names (`name`, `app_type`, `token_endpoint_auth_method`, `grant_types`, `callbacks`, `allowed_logout_urls`, `web_origins`, `allowed_origins`, `is_first_party`, `third_party_security_mode`, `refresh_token`, `jwt_configuration.lifetime_in_seconds`, `require_pushed_authorization_requests`, …). Fields zeroauthy does not support yet are accepted where Auth0's tools always send them, then ignored and listed in a compat decision. Otherwise they are refused with a clear error. Which tools send which fields is settled by running `auth0-deploy-cli` against slice 1 (§7).

**Writes:**
- `client_secret` may be supplied on `POST` and `PATCH`, as on Auth0. `auth0-deploy-cli` imports use this to keep existing secrets.
- `rotate-secret` replaces the secret immediately, with no overlap.
- `is_first_party` and `third_party_security_mode` cannot be changed after creation (the seed's existing rule).
- Deleting a client also:
  - revokes its refresh tokens;
  - deletes its client grants and user grants;
  - removes it from connections' enabled clients.

  Login sessions stay.
- **Listing** pages and filters in memory over `Clients.List` for the MVP; tenants rarely have more than hundreds of clients. Store-level pagination arrives with users in slice 4.

**Rules:** the same validation as the seed (`internal/seed/validate.go`), moved into a shared package, so the seed, the Management API and the console enforce one set of rules.

**Defaults** for a new client follow Auth0's documented defaults per `app_type`.

**Client secrets** are encrypted at rest and returned to callers with `read:client_keys`, as on Auth0 (§8, decision 1).

### 5.2 Console screens

- **Applications list:** server-paginated, filterable by type, with a create button.
- **Create application:** name and type (native, SPA, regular web, machine to machine). Defaults per type. Creating a client opens its detail page.
- **Application detail and edit:**
  - **Settings:** domain, client ID, secret (shown on demand; "rotate to reveal" for clients created before this change), name, URLs.
  - **Grant types and token settings.**
  - **Advanced:** first-party versus third-party, PAR.
  - A delete action with confirmation by typing the name.
- **Home:** the tenant's domain, discovery URL, counts of applications (and more as slices land), and links to zeroauthy's docs.
- **Tenant switcher:** lists tenants from `/api/system/tenants`; "create tenant" asks for a name.

### 5.3 Storage changes

- Operators: a user flag or table in the `system` tenant, plus a tenant list.
- Clients: a `Delete` method if missing. Client listing with filters and pagination.
- The `system` tenant: reserved name, auto-created.

All of this lands in the memory, SQL (a new migration) and gRPC drivers with storetest coverage, as in earlier plans.

### 5.4 Compatibility with existing seeds

The seed stays supported, and on start it applies over the database as today, with two changes in slice 1 so the console and the seed can coexist:
- **Secrets:** a seeded client with no `client_secret` in the seed keeps its stored secret. Today a restart wipes it.
- **Ownership:** clients and tenants created through the Management API or the console are never touched by the seed.

Other edits made in the console to entities that the seed defines are overwritten at the next start. Tenants record whether the seed defines them, and the console shows a banner on those tenants. Making the seed "create only" is a follow-up.

## 6. Security

- Management API tokens are checked for issuer, audience, expiry and signature with the tenant's keys (M2M) or the `system` tenant's keys (operators). Scopes are enforced per endpoint.
- CORS on `/api/v2/` and `/api/system/` allows only the `system` host's origin.
- The console sets `frame-ancestors 'none'`.
- The bootstrap link is single-use and short-lived. The bootstrap env var takes an email only.
- Every Management API write is logged with the actor (client ID or operator user ID), in the tenant log when logs exist. Until then, in the server log.

## 7. Testing

- **Go:** unit and contract tests per endpoint, and storetest for the new store methods.
- **`auth0-cli`** (pinned) as the black-box E2E client:
  - log in with client credentials against a zeroauthy tenant;
  - `apps list/create/show/update/delete`;
  - `auth0 api get clients`.
- **Console:** Vitest, and Playwright flows (bootstrap admin, sign in, create an app, edit, rotate the secret, delete).
- **Observation on the maintainer's tenant** is the plan's first task, before any code (as in Plans 9–12), with the field list provisional until then. It covers undocumented points, for undocumented points: create defaults per type; what `GET` returns with and without `read:client_keys`; which fields `auth0-deploy-cli` sends on import.

## 8. Decisions by the maintainer

1. **Client secrets are encrypted, not hashed** (2026-10-18, option b). Secrets are encrypted at rest with AES-256-GCM under the master key, like signing keys (core spec §8), so they can be shown in the console and returned to callers with `read:client_keys`, as on Auth0. This replaces core spec §8's "stored hashed (argon2id)".
   - **Existing clients:** their stored hashes keep working for authentication. Their plaintext is unknown, so the API returns no `client_secret` and the console offers "rotate to reveal". Seeded clients get the encrypted form the next time the seed applies, since the seed carries the plaintext.
   - **Verification:** constant-time comparison against the decrypted value, falling back to the hash for clients not yet converted.
   - **Records:** a compat decision records the change.

## 9. Out of scope

Everything in "pushed down the road" (§2). Slices 2–6 get short designs of their own before their plans.
