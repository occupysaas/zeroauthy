# zeroauthy Plan 13: Management API and console, slice 1 (shell, admin sign-in, applications)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** an operator creates the first admin with `zeroauthy admin create`, signs in to the console at `/admin`, switches between tenants, and lists, creates, edits, rotates and deletes applications. The same operations work through Auth0's Management API at `/api/v2/clients`, and `auth0-cli` manages a zeroauthy tenant's applications unchanged.

**Architecture:**
- **Storage:** client secrets are encrypted with the master key, replacing the hashes (decision 1 of the design). There is a reserved `system` tenant, and operators are flagged users of it with a tenant list. `Tenants.Delete` is added. All of this goes into every driver: memory, SQL migration 0006, and gRPC.
- **`internal/mgmt` (new):**
  - Management API middleware: token verification for two trust anchors, scopes, Auth0's error shape, pagination and `fields`;
  - handlers generated from `api/management.yaml` into `internal/gen/mgmtapi`;
  - `/api/v2/clients` and the system API `/api/system/{tenants,operators}`.
- **`internal/clientrules` (new):** the client validation the seed has today, shared by the seed, the Management API and (through the API) the console.
- **`console/` (new):**
  - Vue 3, Vite and TypeScript, with a client generated from `api/management.yaml`;
  - built into `console/dist`, which is committed, embedded with `go:embed` and served at `/admin` on the `system` host.
- **Task 1 settles undocumented Auth0 behaviour first,** on the maintainer's non-live dev tenant, by observation (CLEAN_ROOM.md).

**Tech Stack:**
- Go 1.26+, no new Go dependencies beyond what oapi-codegen already pulls.
- Console: Vue 3, Vite, TypeScript, Vue Router, a headless component library (Radix Vue or equivalent; the implementer picks one with a permissive license), openapi-typescript for types, Vitest, Playwright (already pinned).
- Pin every npm package to an exact version at least two weeks old.
- E2E: the pinned `auth0-cli` (`tests/e2e`).

**Spec:** `docs/superpowers/specs/2026-10-18-zeroauthy-management-design.md` (approved 2026-10-18). Also core spec §7.1, §8, and the maintainer's review notes `docs/superpowers/specs/2026-10-17-zeroauthy-management-ui-review-notes.md` (feature inventory only).

## Global Constraints

- **Wire shape is Auth0's.**
  - Paths: `/api/v2/clients`, `/api/v2/clients/{id}`, `/api/v2/clients/{id}/rotate-secret`.
  - Field names as in Auth0's Management API. Error body `{statusCode, error, message, errorCode}`. Pagination `page`, `per_page`, `include_totals`; projection `fields`, `include_fields`.
  - Scopes `read:clients`, `create:clients`, `update:clients`, `delete:clients`, `read:client_keys`, `update:client_keys`.
  - Exact defaults, statuses and error codes come from Task 1's observations.
- **Management API audience:** one canonical identifier per tenant, `https://<name>.<base_domain>/api/v2/`, or `https://<first domains entry>/api/v2/` without a base domain. It is accepted on every host of the tenant.
- **Operator tokens:**
  - issued by the `system` tenant, audience `urn:zeroauthy:management`, claim `https://zeroauthy.dev/operator` (the operator's tenant list, `["*"]` in the MVP);
  - accepted on every tenant's `/api/v2/` with all scopes;
  - the only cross-tenant trust anchor.
- **`system` tenant:**
  - The name is reserved, and so is its host: `system.<base_domain>`, or `server.system_host`, which is required without a base domain.
  - `/admin` and `/api/system/` are served only there.
  - CORS on `/api/v2/` and `/api/system/` allows only the `system` host's origin.
- **Bootstrap:**
  - `zeroauthy admin create --email <addr>` prints a one-time setup link valid for 1 hour.
  - The optional `ZEROAUTHY_BOOTSTRAP__ADMIN_EMAIL` takes an email only, never a password.
- **Client secrets:**
  - encrypted at rest with AES-256-GCM under the master key, sealed with the existing `internal/keys` envelope, with the AAD binding tenant and client;
  - existing hash-only secrets keep authenticating;
  - returned only with `read:client_keys` (operators have it).
- **Seed coexistence:**
  - A seeded client whose seed has no `client_secret` keeps its stored secret.
  - Entities created through the API are never touched by the seed.
  - Tenants record `seeded` so the console can show a banner.
- **Console:**
  - original look, not modelled on Auth0's dashboard;
  - light and dark themes, keyboard accessible, WCAG 2.2 AA target;
  - its own CSP, with no inline scripts and `connect-src` limited to zeroauthy hosts;
  - tokens kept in memory only.
- **Clean room:**
  - Task 1 is an observation by the controller session, with notes in `docs/compat/observations/management-clients.md` in our own words.
  - Implementers work from the docs and those notes, never from Auth0's dashboard.
- **Earlier constraints still apply:**
  - `go test -race ./...`, `go vet ./...`, `gofmt -l .` and `go generate ./...` with no diff;
  - SQL via `./scripts/test-sql.sh`;
  - the browser E2E stays green;
  - `make conformance` stays at exit 0 (run it once at the end).

## Review Focus

1. **A token for one tenant used on another tenant's API:**
   - an M2M token from tenant A presented at tenant B's `/api/v2/`;
   - an operator token with a tampered `iss`;
   - an operator token whose claim omits tenant B (in a later per-tenant world).

   All must be 401 or 403. Pinned in Task 4 (`TestMgmtAuthCrossTenant`).
2. **Secrets through the seed after migration 0006:**
   - A server with existing hashed secrets restarts with a seed that names those clients without `client_secret`. Authentication must keep working, and nothing may be wiped.
   - A seed that does carry a secret converts the client to the encrypted form.

   Pinned in Task 2 (`TestSeedKeepsHashedSecret`, `TestSeedEncryptsSeedSecret`).
3. **Deleting a client that is in use:** refresh tokens are revoked, client grants and user grants are removed, and it is dropped from connections' enabled clients. Its live sessions don't crash `/authorize`, or logout for other clients. Pinned in Task 5 (`TestDeleteClientCascades`).
4. **`auth0-cli` against a zeroauthy tenant:** it logs in with client credentials using the canonical audience, pages through `apps list` with more than one page, and `apps show --reveal-secrets` returns the secret. Pinned in Task 9.
5. **The console in a fresh install:**
   - no base domain, so `server.system_host` must be set;
   - the bootstrap link opened in a new browser;
   - sign-in, then a hard refresh on a deep link like `/admin/tenants/acme/applications/xyz`, which must load through the history fallback.

   Pinned in Task 9's Playwright flow.

---

## File Structure

| File | Responsibility |
|---|---|
| `docs/compat/observations/management-clients.md` (new), `docs/compat/decisions.md` | Task 1 facts; D-0038 onward |
| `internal/store/{types,store}.go`, memory, sqlstore (+ `0006_management.sql` ×3), grpcstore, proto, storetest | Encrypted secrets, operators, `Tenants.Delete`, `Tenant.Seeded`, client `Origin` (seed or API) |
| `internal/keys/clientsecret.go` (new) | Seal and open client secrets |
| `internal/oauth/clientauth.go` | Verify against the encrypted or the hashed secret |
| `internal/clientrules/` (new) | Client validation and per-type defaults (moved from `internal/seed/validate.go`) |
| `internal/seed/{apply,validate}.go` | Uses clientrules; secret and ownership coexistence; reserves `system` |
| `internal/system/` (new) | `system` tenant creation, operators, bootstrap |
| `cmd/zeroauthy/admin.go` (new) | `zeroauthy admin create` |
| `internal/config/config.go` | `server.system_host`, `bootstrap.admin_email` |
| `internal/tenant/` | System host resolution; canonical Management API identifier |
| `api/management.yaml` (new), `internal/gen/mgmtapi` (generated) | The contract |
| `internal/mgmt/` (new) | Auth middleware, errors, pagination, clients handlers, system API handlers |
| `internal/oauth/minter.go`, `user_tokens.go` | The operator claim for the `urn:zeroauthy:management` audience |
| `internal/server/{server,cors}.go` | Routes `/api/v2`, `/api/system`, `/admin`; CORS |
| `console/` (new): `package.json`, `vite.config.ts`, `src/…`, `dist/` (committed), `embed.go` | The console |
| `tests/e2e/{seed.yaml,m13-*.spec.mjs,run-browser.sh}`, `tests/e2e/auth0-cli/` | E2E |
| `docs/console.md` (new), `docs/management-api.md` (new), matrix, follow-ups, core spec §8 | Docs |

---

### Task 1: Observe Auth0's Management API for clients (controller, inline)

This task is run by the controller session as the observer. The implementers of Tasks 2–10 never see raw responses, only the notes. The tenant is `turbojobapply-dev` (not live). `auth0-cli` must be logged in to it (`auth0 login`, run by the maintainer if the session has expired).

**Files:**
- Create: `docs/compat/observations/management-clients.md`
- Modify: `docs/compat/decisions.md` (D-0038: client secrets encrypted, the maintainer's decision; D-0039: Management API for clients, as observed); this plan's Observed column

| # | Question | How | Observed |
|---|---|---|---|
| M1 | Defaults per `app_type` for a `POST /api/v2/clients` with only `name` and `app_type` (grant types, auth method, `is_first_party`, `oidc_conformant`, `jwt_configuration`, `refresh_token`, `token_endpoint_auth_method`) | create one each of `native`, `spa`, `regular_web`, `non_interactive`; record the field names and values that matter; delete them || same defaults for every app_type (grants auth_code, implicit, refresh, client_credentials; is_first_party true; oidc_conformant false; jwt lifetime 36000; non-rotating RT); no per-type defaults from the API → **console applies per-type defaults** (D-0039) |
| M2 | Is `client_secret` present in `POST` and `GET` responses with and without `read:client_keys`? | A user token from `auth0-cli` (all scopes) versus an M2M token with only `read:clients` || secret only with `read:client_keys`; 64 chars |
| M3 | Is a caller-supplied `client_secret` accepted on `POST` and on `PATCH`? Minimum length? | try both; record statuses || accepted on POST; PATCH needs `update:client_keys`; min length 48 (`400 invalid_body`) |
| M4 | `rotate-secret`: status, response, and whether the old secret stops working immediately | rotate, then a client-credentials call with the old secret || 200 with the client and a new secret; old secret refused immediately |
| M5 | Errors: unknown client ID; bad `app_type`; unknown field; malformed callback URL; missing scope | record `statusCode`, `error`, `errorCode` || 404 `inexistent_client`; 400 `invalid_body` for validation, unknown properties **refused**; 403 `insufficient_scope`; 401 no or bad token |
| M6 | Pagination: the shape with `include_totals=true`; maximum `per_page`; the default page size; the ordering | `GET` with variations || bare array without totals; `{clients,start,limit,total}` with; per_page max 100 (`400 invalid_query_string`); creation order |
| M7 | `fields` and `include_fields=false` behaviour | `GET` with variations || `fields` with `include_fields` true/false; `tenant` always present |
| M8 | Changing `is_first_party` or `third_party_security_mode` by `PATCH` | try it || both refused with 400 (immutable) |
| M9 | `DELETE` status, and a second `DELETE` | record || 204, and 204 again for a missing ID |
| M10 | Which client fields `auth0-deploy-cli` exports and sends on import | run `a0deploy export` (pinned version) on the tenant; record field names only || export drops `client_secret` and other read-only fields; Auth0 refuses a supplied `client_id` (403 `operation_not_supported`) → keeping IDs and secrets needs a slice-5 decision |
| M11 | The Management API's audience and token `iss` when a custom domain exists | from the docs, and from the tenant's resource-server identifier || `https://<tenant domain>/api/v2/`, a system API |

- [ ] **Step 1:** Run M1–M11 with `auth0 api` and `a0deploy`, keeping all output in the scratchpad.
- [ ] **Step 2:** Write the observation note: facts only, no secrets, IDs or tenant names. Then D-0038 and D-0039.
- [ ] **Step 3:** Fill the Observed column. Commit with `docs(compat): observe the Management API for clients`.

---

### Task 2: Encrypted client secrets

**Files:** `internal/store/types.go` (`ClientSecret` gains `Sealed []byte`), memory, sqlstore `0006_management.sql` (column `secret_sealed`), grpcstore and proto (field), storetest, `internal/keys/clientsecret.go`, `internal/oauth/clientauth.go`, `internal/seed/apply.go`, tests.

**Interfaces:**
- Produces:
  - `keys.SealClientSecret(w Wrapper, tenantID, clientID, secret string) ([]byte, error)`
  - `keys.OpenClientSecret(w Wrapper, tenantID, clientID string, sealed []byte) (string, error)`
  - `ClientSecret{Hash string; Sealed []byte; CreatedAt; ExpiresAt}`, where exactly one of `Hash` and `Sealed` is set
  - `oauth` verification: open `Sealed` and compare in constant time, or fall back to `secrets.Verify(Hash, …)`

- [ ] **Step 1: Tests.**
  - seal and open round-trip; the AAD binds the tenant and the client, so the wrong tenant fails;
  - client authentication with a sealed secret and with a legacy hashed secret;
  - `TestSeedKeepsHashedSecret`: the seed client has no `client_secret`, so the stored hash stays and authentication works;
  - `TestSeedEncryptsSeedSecret`: the seed carries a secret, so it is stored sealed with no hash;
  - storetest round-trip of `Sealed` on all drivers;
  - a gRPC codec test.
- [ ] **Step 2: Implement.** The seed sets `Sealed` when it carries a secret. When it carries none, it leaves `Secrets` untouched, which changes the current behaviour that wipes them. Migration 0006 adds the nullable column.
- [ ] **Step 3: Run** `go test -race ./...` and `./scripts/test-sql.sh ./internal/store/sqlstore/ ./pkg/storetest/...`. Expected: PASS.
- [ ] **Step 4: Commit** with `feat: client secrets encrypted with the master key (D-0038)`.

---

### Task 3: The `system` tenant, operators and bootstrap

**Files:**
- `internal/store`: `Tenant.Reserved`, `Tenant.Seeded`, an `Operators` repository (`Get`, `Upsert`, `List`, `Delete`, keyed by `system`-tenant user ID, holding `Tenants []string`), and `Tenants.Delete` (cascades all tenant data). Every driver, with SQL in the same migration 0006, the proto, and storetest.
- `internal/system/` (new), `internal/config/config.go`, `internal/tenant/resolver.go`, `cmd/zeroauthy/admin.go` (new), `internal/app/app.go`, `internal/seed/validate.go`.

**Interfaces:**
- Produces:
  - `system.Ensure(ctx, st store.Store, cfg) (*store.Tenant, error)`: idempotent. It creates the `system` tenant with signing keys, a database connection `Operators`, the SPA client `zeroauthy-console` (callbacks `https://<system host>/admin/callback`, web origins, logout URL `https://<system host>/admin/`), and the resource server `urn:zeroauthy:management`.
  - `system.CreateOperator(ctx, st, email string) (setupURL string, err error)`: creates the user (no password) and the operator record `["*"]`, and returns a password-reset ticket URL valid for 1 h, through the existing reset-ticket code.
  - Config: `server.system_host`, required when `server.base_domain` is empty, and `bootstrap.admin_email`.
  - CLI: `zeroauthy admin create --email <addr> [--config …]` prints the URL.
- Rules:
  - the seed and the system API refuse the tenant name `system` and any domain equal to the system host;
  - the server runs `system.Ensure` at start;
  - with `bootstrap.admin_email` set and no operators, the server creates that operator and logs the setup URL once.

- [ ] **Step 1: Tests.**
  - `Ensure` is idempotent;
  - `CreateOperator` returns a working link, and setting the password through it leaves a user who can log in on the `system` tenant;
  - the seed refuses `system` and a clashing domain;
  - the config refuses an empty base domain with no `system_host`;
  - the bootstrap env var creates an operator once and never again;
  - `Tenants.Delete` cascades (storetest);
  - the resolver resolves the system host.
- [ ] **Step 2: Implement.** Reuse the seed's tenant set-up code for keys and connections; do not duplicate it.
- [ ] **Step 3: Run** the Go suite and the SQL suite. **Step 4: Commit** with `feat: system tenant, operators and admin bootstrap`.

---

### Task 4: Management API foundation

**Files:** `api/management.yaml` (new; for now only shared schemas, the error type, pagination parameters and security schemes), `internal/gen/mgmtapi` (generated through a new `go:generate` in `api/`), `internal/mgmt/{auth,errors,paging}.go` (new), `internal/tenant` (canonical identifier), `internal/oauth/{minter,user_tokens}.go` (the operator claim), `internal/server/{server,cors}.go`, tests.

**Interfaces:**
- Produces:
  - `tenant.ManagementAudience(t *store.Tenant, baseDomain string) string`
  - `mgmt.Auth` middleware putting `mgmt.Caller{Kind: M2M|Operator, ClientID, UserID string, Scopes []string, Tenants []string}` in the context, and `mgmt.Require(scope string)`
  - `mgmt.WriteError(w, status int, errorCode, message string)` in Auth0's shape
  - `mgmt.Page(r) (page, perPage int, includeTotals bool, err error)`
  - `mgmt.Project(v any, fields []string, include bool) map[string]any`
  - A per-tenant system resource server for the canonical identifier with Auth0's scope list, created on first use or with `system.Ensure` for new tenants, and visible to the client-grant logic, so a client credentials grant for that audience works.
- **Operator claim:** when the `system` tenant mints an access token for `urn:zeroauthy:management` for a user who is an operator, it adds `https://zeroauthy.dev/operator: [tenants]`. Non-operators get `access_denied` at the token step, as for any policy refusal.

- [ ] **Step 1: Tests.**
  - an M2M token with the canonical audience passes on every host of the tenant;
  - the wrong audience, wrong tenant (`TestMgmtAuthCrossTenant`), expired token, bad signature, or missing scope fails with 401 or 403 in Auth0's error shape;
  - an operator token passes on any tenant, and an operator token with a forged `iss` or missing claim fails;
  - the error shape;
  - paging parameters and their limits (from M6);
  - projection (from M7);
  - CORS only from the system origin.
- [ ] **Step 2: Implement.** Verification uses `keys.Manager.Verify` with the resolved tenant (M2M) or the `system` tenant (operator).
- [ ] **Step 3: Run** `go test -race ./...` and `go generate ./... && git diff --exit-code`. **Step 4: Commit** with `feat(mgmt): Management API foundation: tokens, scopes, errors, paging`.

---

### Task 5: Applications endpoints and shared client rules

**Files:** `api/management.yaml` (the client schemas and five operations), `internal/mgmt/clients.go` (new), `internal/clientrules/` (new, moved from `internal/seed/validate.go` and the seed's defaults), `internal/seed`, `internal/store` (client `Origin`: `seed` or `api`), tests.

**Interfaces:**
- Produces:
  - `clientrules.Validate(t *store.Tenant, c *store.Client) error`
  - `clientrules.Defaults(appType store.AppType) store.Client` (from M1)
  - Handlers for `GET /clients` (filters `app_type`, `is_first_party`; in-memory paging over `Clients.List`), `POST /clients`, `GET`, `PATCH` and `DELETE /clients/{id}`, and `POST /clients/{id}/rotate-secret`.
- Rules:
  - `client_secret` is accepted on `POST` and `PATCH` (per M3);
  - rotation replaces the secret immediately (M4);
  - `is_first_party` and `third_party_security_mode` are immutable (M8);
  - unknown fields follow M5 and M10: fields `auth0-deploy-cli` always sends are accepted and ignored, each listed in D-0039;
  - a delete cascades (Review Focus 3);
  - the seed skips clients with `Origin == api`.

- [x] **Step 1: Tests:** per operation and field, from the M1–M9 table values; `TestDeleteClientCascades`; the seed skipping API-created clients; and the existing seed tests passing unchanged against clientrules.
- [x] **Step 2: Implement.**
- [x] **Step 3: Run** the Go suite, `go generate` with no diff, and the SQL suite if store methods changed. **Step 4: Commit** with `feat(mgmt): /api/v2/clients`.

---

### Task 6: The system API

**Files:** `api/management.yaml` (tag `system`: tenants and operators), `internal/mgmt/system.go` (new), tests.

**Interfaces:**
- Produces:
  - `GET /api/system/tenants` (name, domains, seeded, created at);
  - `POST /api/system/tenants` (name under DNS-label rules, at most 63 characters, optional domains; set up through the seed's tenant code);
  - `PATCH /api/system/tenants/{name}` (friendly name, domains);
  - `DELETE /api/system/tenants/{name}` (refuses `system`; requires `?confirm=<name>`);
  - `GET /api/system/operators`;
  - `POST /api/system/operators` (email, which creates the operator and returns the setup URL);
  - `DELETE /api/system/operators/{id}` (refuses the last operator).

  Operator tokens only.

- [ ] **Step 1: Tests** for each, including refusing `system`, an invalid name, a clashing domain and the last operator, and rejecting M2M tokens.
- [ ] **Step 2: Implement. Step 3: Run. Step 4: Commit** with `feat(mgmt): system API for tenants and operators`.

---

### Task 7: The console scaffold, sign-in and shell

**Files:**
- `console/`: `package.json` and lockfile (exact pins), `vite.config.ts`, `tsconfig.json`, `index.html`, `src/main.ts`, `src/router.ts`, `src/auth/` (PKCE against the `system` tenant, tokens in memory, rotating refresh token in memory), `src/api/` (generated types plus a thin fetch wrapper taking the tenant's host), `src/ui/` (theme tokens, the components it needs), `src/layout/`, `src/pages/{Home,Callback,NotFound}.vue`, `dist/` (committed), `embed.go`.
- `internal/server/admin.go` (new: serves `/admin` with history fallback and its own CSP, only on the system host).
- `Makefile` (`console` target).
- `.github/workflows/ci.yml` (one console job: `npm ci`, lint, typecheck, Vitest, build, `git diff --exit-code console/dist`). This is the one sanctioned change to ci.yml.

**Interfaces:**
- **Layout:**
  - **Header:** product name, tenant switcher (from `/api/system/tenants`, plus a "create tenant" dialog), docs link, source link (the project's GitHub), account menu (operator email, sign out).
  - **Sidebar:** Home and Applications in this slice. The sections of later slices are not shown.
- **Routes:** `/admin/` (Home), `/admin/callback`, and `/admin/t/:tenant/…` for tenant-scoped pages.
- **Home:** the tenant's domains, discovery URL, application count, seeded-tenant banner, and links to `docs/`.

- [ ] **Step 1: Tests** (Vitest): the auth module (PKCE parameters, refresh, no storage writes); the router guards (unauthenticated → login); the tenant switcher (lists, creates, and the API error path).
- [ ] **Step 2: Implement.** Generate the types from `api/management.yaml`, and add a check that the generated file is current. Build `dist/`. Serve it from Go.
- [ ] **Step 3: Run** `make console` (lint, typecheck, test, build), `go test ./internal/server/`, and a manual smoke (bootstrap an admin, sign in, switch tenant).
- [ ] **Step 4: Commit** with `feat(console): scaffold, sign-in and shell`.

---

### Task 8: The console's application screens

**Files:** `console/src/pages/applications/{List,Create,Detail}.vue` and components, tests, `console/dist`.

**Screens:**
- **List:** server-paginated, filter by type, empty state, and a create button.
- **Create:** name and type (native, SPA, regular web, machine to machine) with a one-line explanation of each. It opens the detail page.
- **Detail:**
  - **Settings tab:** domain, client ID (copy), secret (masked; reveal and copy; "rotate to reveal" when the API returns none), name, callbacks, logout URLs, web origins, allowed origins. Save with validation errors shown per field from the API's message.
  - **Advanced tab:** grant types, token endpoint auth method, ID token lifetime, refresh token rotation, PAR requirement, first-party versus third-party (read-only after creation).
  - **Danger zone:** rotate the secret (confirm), delete (type the name to confirm).

- [ ] **Step 1: Tests** (Vitest) for each screen's states: loading, empty, error, validation and success.
- [ ] **Step 2: Implement.** Rebuild `dist/`.
- [ ] **Step 3: Run** `make console`. **Step 4: Commit** with `feat(console): applications`.

---

### Task 9: E2E: `auth0-cli` and the console in Chromium

**Files:** `tests/e2e/seed.yaml` (a tenant with an M2M client granted the Management API audience and all client scopes), `tests/e2e/m13-mgmt-cli.mjs` (new, driving the pinned `auth0-cli` with `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID` and `AUTH0_CLIENT_SECRET` against zeroauthy), `tests/e2e/m13-console.spec.mjs` (new), `tests/e2e/run-browser.sh` (config `server.system_host`, bootstrap admin), `docs/compat/blackbox-clients.md`.

- [ ] **Step 1: The `auth0-cli` flow** (Review Focus 4):
  - `auth0 apps create` for each type;
  - `auth0 apps list` across more than one page (`--number`);
  - `auth0 apps show --reveal-secrets`;
  - `auth0 apps update`;
  - `auth0 apps delete`;
  - `auth0 api get clients`.

  Assert the exit codes and key fields.
- [ ] **Step 2: Playwright** (Review Focus 5):
  - run `zeroauthy admin create`, open the link, set a password, sign in;
  - create an application, edit its callbacks, reveal and rotate its secret, delete it;
  - do a hard refresh on a deep link;
  - switch tenant;
  - sign out.
- [ ] **Step 3: Run** `./tests/e2e/run-browser.sh` and `make e2e`. Expected: all suites pass.
- [ ] **Step 4: Commit** with `test(e2e): Management API with auth0-cli and the console`.

---

### Task 10: Documentation and final verification

**Files:** `docs/console.md` (new: install, first admin, sign-in, the screens), `docs/management-api.md` (new: endpoints, tokens, scopes, M2M setup, what's supported), `docs/compat/matrix.md` (rows), core spec §8 (secrets encrypted; points to D-0038), `docs/superpowers/plan-1-followups.md` ("Plan 13 follow-ups": slices 2–6, everything pushed down the road from design §2, per-tenant admins, a create-only seed mode, store-level client pagination), README.

- [ ] **Step 1: Write the docs.**
- [ ] **Step 2: Verify:** gofmt, vet, `go test -race ./...`, `go generate` with no diff, `make console`, the SQL suite, `./tests/e2e/run-browser.sh`, and `make conformance` (exit 0).
- [ ] **Step 3: Commit** with `docs: console and Management API guides; Plan 13 records`.
