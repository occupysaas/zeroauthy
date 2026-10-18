# zeroauthy Plan 14: Management API and console, slice 2 (APIs and client grants)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** an operator creates an API in the console, defines its permissions, grants it to a machine-to-machine application with chosen scopes, and copies a working `curl` from the application's quick-start panel that gets a token for it. The same works through Auth0's Management API at `/api/v2/resource-servers` and `/api/v2/client-grants`, and `auth0 apis …` and `auth0 api … client-grants` work unchanged. Operators are managed in the console.

**Architecture:**
- **Storage:** `ResourceServers.List` and `ClientGrants.List` with a filter (`client_id`, `audience`, `subject_type`) and store-level paging, in every driver (memory, SQL, gRPC) with storetest coverage. This is the paging pattern users (slice 4) will reuse. Resource servers and client grants gain `Origin`, like clients and tenants in Plan 13, so the seed never touches what the API created.
- **`internal/apirules` (new):** the resource-server rules the seed has today (`internal/seed/validate.go`), shared by the seed and the API, as `internal/clientrules` is for clients.
- **`internal/mgmt`:** `resource_servers.go` and `client_grants.go`, generated from `api/management.yaml` as in Plan 13.
- **Console:** an APIs section (list, create, detail with Settings, Permissions and Machine-to-machine applications), an APIs tab on application detail, a quick-start panel on application detail, and an Operators screen on the system tenant.
- **Task 1 settles undocumented Auth0 behaviour first,** by observation (CLEAN_ROOM.md), with a documented fallback when the dev tenant cannot be reached from the session.

**Tech stack:** as Plan 13. No new Go or npm dependencies expected; any new npm package is pinned to an exact version at least two weeks old.

**Spec:** `docs/superpowers/specs/2026-10-18-zeroauthy-management-design.md` §2 (slice 2), §4, §5 (patterns from slice 1). This plan is slice 2's short design.

**Decided with the maintainer (2026-10-18):**
- **Enabling connections for applications waits for slice 3.** An application created in the console still logs no user in until then; the quick-start panel says so.
- **The audit log waits.** Writes stay in the server log.
- **The create-only seed mode** (`seed.mode: create_only`) goes in only if it fits with little effort (Task 9, optional).

## Global Constraints

- **Wire shape is Auth0's.**
  - Paths: `/api/v2/resource-servers`, `/api/v2/resource-servers/{id}`, `/api/v2/client-grants`, `/api/v2/client-grants/{id}`.
  - Field names as in Auth0's Management API; error body, pagination (`page`, `per_page`, `include_totals`) and `fields` as in slice 1 (D-0039).
  - Scopes `read:resource_servers`, `create:resource_servers`, `update:resource_servers`, `delete:resource_servers`, `read:client_grants`, `create:client_grants`, `update:client_grants`, `delete:client_grants` (already in `tenantsetup.ManagementAPIScopes`).
  - Exact defaults, statuses and error codes come from Task 1.
- **System APIs are protected:** each tenant's "zeroauthy Management API" (`is_system: true`) can be read and granted and never deleted; its name, scopes and the settings zeroauthy depends on never change (D-0041 lists which). The system tenant's `urn:zeroauthy:management` likewise.
- **One set of rules:** the seed, the API and the console enforce the same resource-server and client-grant validation (scope names, policies, Management API scopes for grants to it, subject types).
- **Seed coexistence:** resource servers and client grants created through the API are never touched by the seed.
- **Console:** as Plan 13 (original look, light and dark, keyboard accessible, its own CSP, tokens in memory, strings in the catalog).
- **Earlier constraints still apply:** `go test -race ./...`, `go vet ./...`, gofmt, `go generate ./...` with no diff, the SQL suite, `make console` with no diff in `console/dist`, `make e2e`, and `make conformance` at exit 0 once at the end.

## Review Focus

1. **Granting the Management API:** a client grant to a tenant's Management API identifier may carry only Management API scopes, `subject_type` client only, and only for that tenant's own identifier. A grant to another tenant's identifier, or to `urn:zeroauthy:management`, is refused. Pinned in Task 4 (`TestClientGrantManagementAPI`).
2. **Deleting an API in use:** its client grants, and the user grants (consents) for its audience, go with it per Task 1's observation; outstanding access tokens stay valid until they expire (they are JWTs). Refresh tokens issued for that audience stop refreshing. Pinned in Task 3 (`TestDeleteResourceServerCascades`).
3. **Changing scopes under existing grants:** removing a scope from an API removes it from the client grants that carry it (or is refused, per Task 1), so no grant names a scope its API no longer defines.
4. **Store paging:** `ClientGrants.List` pages and filters identically in every driver, including a page past the end and a filter that matches nothing. Pinned in storetest.
5. **The quick-start `curl`** works as copied, against a tenant without a base domain and one with.

---

### Task 1: Observe Auth0's Management API for resource servers and client grants

Run by the controller session as the observer; implementers see only the notes. **How it runs from a cloud session** (pick one, in this order):

- **A. Credentials in the environment.** The maintainer creates, on the non-live dev tenant, an M2M application authorized for the Auth0 Management API with `read/create/update/delete:resource_servers` and `read/create/update/delete:client_grants`, and adds `OBS_AUTH0_DOMAIN`, `OBS_AUTH0_CLIENT_ID` and `OBS_AUTH0_CLIENT_SECRET` as environment secrets, with the tenant's domain allowed by the environment's network policy. The observer runs the pinned `auth0-cli` with `AUTH0_CLI_AUTH_MODE=env` (no `auth0 login` needed). The application is deleted afterwards.
- **B. The maintainer runs a script.** The observer writes `scripts/observe/slice2.sh` (curl and `auth0 api` calls only, printing statuses, `errorCode`s and field names, never values or secrets); the maintainer runs it locally against the dev tenant and pastes the output.
- **C. Fallback:** public documentation, the Apache-2.0 OpenAPI description, and the `auth0-deploy-cli` and `go-auth0` sources only. Every value that would have come from observation is marked provisional in D-0041.

**Files:** `docs/compat/observations/management-apis.md` (new), `docs/compat/decisions.md` (D-0041), this plan's Observed column.

| # | Question | Observed |
|---|---|---|
| A1 | Defaults of `POST /resource-servers` with only `identifier` (and `name`): `token_lifetime`, `token_lifetime_for_web`, `signing_alg`, `allow_offline_access`, `skip_consent_for_verifiable_first_party_clients`, `scopes`, `subject_type_authorization` || 86400 / 7200; `RS256`; both flags false; no scopes; client `require_client_grant`, user `allow_all`; `name` absent |
| A2 | Is `name` required? Identifier rules (must be a URL? length?) and the error for a duplicate identifier || `name` optional (1–200, no `<>`); identifier any string 1–600, case-sensitive; duplicate `409 resource_server_conflict`; Management API identifier `400 reserved_identifier` |
| A3 | `PATCH` of `identifier`: refused? Which other fields are immutable? || `identifier`, `id`, `is_system` are unknown properties on `PATCH` (`400 invalid_body`) |
| A4 | `PATCH` / `DELETE` of the system Management API: statuses and `errorCode`s || `PATCH name` `400 invalid_body`; other settings patchable; `DELETE` `400 delete_system_resource_server` |
| A5 | `scopes` on `PATCH`: replaced whole or merged? Removing a scope that client grants carry: refused, or removed from the grants? || replaced whole; removing a scope removes it from the grants |
| A6 | `DELETE` of an API with client grants: are the grants deleted? Second `DELETE`? Unknown ID? || grants deleted; `204`, also for a second `DELETE` and unknown IDs |
| A7 | `GET /resource-servers`: order, paging shape (`resource_servers` key), `identifiers` filter || creation order; `{total,start,limit,resource_servers}`; `identifiers` repeated param; no checkpoint paging |
| A8 | `POST /client-grants`: defaults (`subject_type`), an unknown `client_id` or `audience`, a scope the API does not define, a duplicate || `subject_type` `client`; `404 inexistent_client` / `inexistent_resource_server`; undefined scope accepted on create (refused on `PATCH`); `409 client_grant_conflict` |
| A9 | `GET /client-grants`: filters (`client_id`, `audience`, `subject_type`), paging shape, checkpoint paging (`from`/`take`)? || all three filters (`subject_type` alone `400`); `client_grants` key; checkpoint paging yes (`take` ≤100, `next`), used by auth0-cli |
| A10 | `PATCH /client-grants/{id}`: which fields may change; `DELETE`: status, unknown ID || `scope`, `allow_all_scopes`, organization fields; unknown `404 inexistent_client_grant` on `PATCH`, `204` on `DELETE` |
| A11 | Which fields `auth0-deploy-cli` exports and sends for resource servers and client grants (field names only, from its source) || see the note: matched by ID then identifier / (client, audience, subject type); read-only fields stripped |

- [x] **Step 1:** Pick A, B or C with the maintainer; run A1–A11 (or read the sources for C).
- [x] **Step 2:** Write the observation note (facts in our own words, no secrets, IDs or tenant names), then D-0041.
- [x] **Step 3:** Fill the Observed column. Commit with `docs(compat): observe the Management API for APIs and client grants`.

---

### Task 2: Store listing and paging

**Files:** `internal/store/{store,types}.go`, memory, sqlstore (migration 0010: `origin` on `resource_servers` and `client_grants`, indexes for the filters), grpcstore and proto (new RPCs `ResourceServersList`, `ClientGrantsList`; plugins that lack them answer Unimplemented, reported as "plugin too old"), `pkg/store`, `pkg/storetest`.

**Interfaces:**
- `ResourceServers.List(ctx, tenantID string) ([]*ResourceServer, error)`: ordered by `CreatedAt`, then `ID`. Tenants hold tens of APIs, so no store paging.
- `ClientGrants.List(ctx, tenantID string, f ClientGrantFilter, p Page) ([]*ClientGrant, int, error)`: filter on any of `ClientID`, `Audience`, `SubjectType`; `Page{Offset, Limit}`; returns the page and the total; ordered by grant `ID` in byte order (D-0041: Auth0 lists grants by ID, and checkpoint cursors in Task 4 name the last ID).
- `ResourceServer.Origin`, `ClientGrant.Origin` (`store.OriginAPI` or empty).

- [x] **Step 1: Tests** (storetest): ordering; every filter alone and combined; a page past the end; `Limit` 0 meaning none; tenant isolation; `Origin` round trip; gRPC codec round trips.
- [x] **Step 2: Implement** in every driver. **Step 3: Run** the Go suite and the SQL suite. **Step 4: Commit** with `feat(store): list resource servers and client grants`.

---

### Task 3: `/api/v2/resource-servers` and shared API rules

**Files:** `api/management.yaml` (schemas and five operations), `internal/apirules/` (new, moved from `internal/seed/validate.go`), `internal/mgmt/resource_servers.go`, `internal/seed`, tests.

**Interfaces:**
- `apirules.Spec`, `apirules.Normalize(*Spec) []error`, `apirules.Apply`, `apirules.FromResourceServer` (the pattern of `clientrules`).
- `GET /resource-servers` (paging, `fields`, `identifiers` if A7 shows it), `POST`, `GET /{id}`, `PATCH /{id}`, `DELETE /{id}`. `{id}` is the resource server's ID; per Auth0's docs, the identifier is accepted too (to be confirmed in A4/A7).
- Rules: identifier fixed after creation (A3); system APIs protected (A4, D-0041); scope removal per A5; delete cascades per A6 (Review Focus 2), plus user grants and refresh tokens for the audience; the seed skips `Origin == api`; the identifiers `urn:zeroauthy:management` and the tenant's Management API identifier are reserved.

- [x] **Step 1: Tests:** per operation and field from A1–A7; `TestDeleteResourceServerCascades`; the seed skipping API-created APIs; the existing seed tests unchanged against `apirules`; the contract test extended to the new operations.
- [x] **Step 2: Implement. Step 3: Run** the Go suite, `go generate` with no diff. **Step 4: Commit** with `feat(mgmt): /api/v2/resource-servers`.

---

### Task 4: `/api/v2/client-grants`

**Files:** `api/management.yaml`, `internal/mgmt/client_grants.go`, `internal/seed` (grant rules shared through `apirules`), tests.

**Interfaces:**
- `GET /client-grants` (filters `client_id`, `audience`, `subject_type` per A9, store paging), `POST`, `PATCH /{id}` (scopes, per A10), `DELETE /{id}`.
- Rules: the client and the audience must exist in the tenant; every scope must be defined by the API, or be a Management API scope for the tenant's own Management API (Review Focus 1); `subject_type` user is refused for the Management API; duplicates per A8; the seed skips `Origin == api`.

- [x] **Step 1: Tests:** per operation from A8–A10; `TestClientGrantManagementAPI`; filters and paging through the API; a grant created through the API makes `/oauth/token` client credentials succeed with exactly its scopes.
- [x] **Step 2: Implement. Step 3: Run. Step 4: Commit** with `feat(mgmt): /api/v2/client-grants`.

---

### Task 5: Console: APIs

**Files:** `console/src/pages/apis/{List,Create,Detail}.vue` and tabs, `console/src/api/client.ts`, router, sidebar, strings, tests, `console/dist`.

**Screens:**
- **List:** server-paginated, the system Management API marked "System" and read-only.
- **Create:** name and identifier (with the hint that it is the `audience` and cannot change), signing algorithm fixed to RS256. Opens the detail page.
- **Detail:**
  - **Settings:** name, identifier (read-only, copy), token lifetime, allow offline access, skip consent for verifiable first-party clients, user and client access policies.
  - **Permissions:** add (value, description) and remove scopes, with the API's answer to removing one in use shown per A5.
  - **Machine-to-machine applications:** every M2M application of the tenant with a switch (grant or revoke) and, when granted, a scope picker that saves per application.
  - **Danger zone:** delete by typing the name; hidden for system APIs.
- **Application detail** gains an **APIs** tab: the APIs this application may call (client grants for it), with their scopes, editable, and "Authorize another API".

- [ ] **Step 1: Tests** (Vitest): each screen's loading, empty, error, validation and success states; the grant switch and scope picker; system APIs read-only.
- [ ] **Step 2: Implement.** Rebuild `dist/`. **Step 3: Run** `make console`. **Step 4: Commit** with `feat(console): APIs and their machine-to-machine applications`.

---

### Task 6: Console: quick start and operators

**Files:** `console/src/pages/applications/QuickStart.vue`, `console/src/pages/operators/List.vue`, router, sidebar (Operators only on the system tenant), strings, tests, `console/dist`.

- **Quick start** (first tab of application detail): per type, ready-to-copy snippets with the tenant's host and the client ID filled in.
  - Machine to machine: a `curl` client-credentials call for each API the application is granted (the secret shown only after "reveal"), and how to call the API with the token.
  - Single-page and native: the `/authorize` URL and the configuration for auth0-spa-js / auth0-react (`domain`, `clientId`, `authorizationParams.redirect_uri`, `audience`).
  - Regular web: the configuration for nextjs-auth0 / express-openid-connect.
  - A note while connections cannot be enabled from the console (slice 3): which connection the application can use today, or that it can use none.
- **Operators:** list (email, tenants, created), invite (shows the one-time setup link once, with copy and the one-hour expiry), remove (confirm; the last operator cannot be removed, and the console says so).

- [ ] **Step 1: Tests** (Vitest): the snippets for each type and for hosts with and without a port; the invite link shown once; removal states.
- [ ] **Step 2: Implement.** Rebuild `dist/`. **Step 3: Run** `make console`. **Step 4: Commit** with `feat(console): application quick start and operators`.

---

### Task 7: E2E

**Files:** `tests/e2e/seed.yaml` (the `e2ecli` admin client gains the resource-server and client-grant scopes), `tests/e2e/m14-mgmt-cli.mjs` (new), `tests/e2e/m14-console.spec.mjs` (new), `tests/e2e/run-m3.sh`, `docs/compat/blackbox-clients.md`.

- [ ] **Step 1: `auth0-cli`** (pinned v1.37.0, through `connect-proxy.mjs` as in Plan 13): `apis create/list/show/update/delete`, `apis scopes list`, `apis update --scopes`, `client-grants create/list/show/update/delete` (if v1.37.0 has them; otherwise `auth0 api post/get/patch/delete client-grants`). Then a client-credentials token for the new API through `/oauth/token` with exactly the granted scopes.
- [ ] **Step 2: Playwright:** sign in; create an API with two permissions; create an M2M application; grant it the API with one scope; copy the quick-start `curl` and run its request from the test (Node `fetch`) to get a token whose `scope` is that one scope; remove a permission; delete the API; invite an operator and remove them.
- [ ] **Step 3: Run** `make e2e`. **Step 4: Commit** with `test(e2e): APIs and client grants with auth0-cli and the console`.

---

### Task 8: Documentation and final verification

**Files:** `docs/management-api.md` (resource servers, client grants, setting up M2M without the seed), `docs/console.md` (APIs, quick start, operators), `docs/compat/matrix.md`, `docs/superpowers/plan-1-followups.md` ("Plan 14 follow-ups"), README.

- [ ] **Step 1: Write the docs.**
- [ ] **Step 2: Verify:** gofmt, vet, `go test -race ./...`, `go generate` with no diff, `make console` with no diff, the SQL suite, `make e2e`, `make check-sources`, `make conformance` (exit 0).
- [ ] **Step 3: Commit** with `docs: APIs and client grants; Plan 14 records`.

---

### Task 9 (optional): Create-only seed mode

Only if Tasks 1–8 leave room; otherwise it stays a follow-up.

**Files:** `internal/config/config.go` (`seed.mode`: `apply`, the default, or `create_only`), `internal/seed/apply.go`, tests, README.

- With `create_only`, the seed creates tenants, clients, APIs, grants, connections and users that do not exist and changes nothing that does; tenants it would have created are still marked `seeded` only when created. The console's seeded banner says which mode is on (from a new `seed_mode` field of `GET /api/system/tenants`, or by not showing the banner in `create_only`).

- [ ] **Step 1: Tests:** a second apply after console edits changes nothing; new entities in the seed are created. **Step 2: Implement. Step 3: Run. Step 4: Commit** with `feat(seed): create-only mode`.
