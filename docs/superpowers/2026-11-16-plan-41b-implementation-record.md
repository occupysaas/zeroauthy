# Plan 41b implementation record

Status: **implemented and verified locally**, on `plan-41b-dcr` (worktree
`/mnt/nvme2/code/zeroauthy-plan41b`), based on `main` after the roadmap
update of PR #101. Plan-branch CI and maintainer approval govern
integration.

Plan: [Plan 41b](plans/2026-11-16-zeroauthy-plan-41b-dynamic-client-registration.md).
Spec: [Dynamic Client Registration and Client ID Metadata Documents](specs/2026-11-16-zeroauthy-dynamic-client-registration-design.md).
Decisions: D-0090 (LR41b-1…11, R41-1…8), amending D-0025 and D-0063.
Operator guide: [Dynamic Client Registration](../dynamic-client-registration.md).
Sources: Auth0's Management OpenAPI (SHA-256 in D-0090), the DCR,
client-grant and third-party application guides read 2026-11-26, RFC 7591
and the CIMD draft.

Maintainer request (2026-11-26): start on 41b and 41c (41b first; 41c
follows once 41b is pushed for CI).

## What was built

1. Task 1: contracts: `POST /oidc/register` in the Authentication API; the
   two CIMD routes, client `external_*` fields and `default_for` grants in
   the Management API; D-0090.
2. Task 3 (before Task 2, which persists its fields): client external
   metadata and default grants in every store, migration 0052, `cimd.v1`.
3. Task 2: `/oidc/register` (`internal/dcr`), discovery.
4. Task 4: `internal/cimd` fetcher, validator, mapper;
   `clientcred.ParseJWK`.
5. Task 5: Management preview and register; `cimd.Registrar`.
6. Task 6: CIMD resolution at `/authorize` and client authentication.
7. Task 7: `default_for: third_party_clients` client grants, applied where
   grants are read.
8. Task 8: console settings, list badges and CIMD form; seed
   `cimd_clients`; `make e2e-dcr`; docs.

## Rulings beyond the plan

- Default third-party permissions are Auth0's `default_for` client grants
  (R41-8 resolved), not a tenant setting; they apply at decision time to all
  third-party clients, as on Auth0.
- No `cimd_documents` table: the fetch state lives in the client's external
  metadata.
- Migration 0052 (main's latest + 1), not 0047.
- `external_client_id` up to 200 characters (OpenAPI), not 120.
- CIMD fetches refuse every redirect (the federation transport).
- CIMD clients get an internal `tpc_` ID; flows accept the URL; the ID
  token's `aud` is the URL; access tokens name the internal ID.
- CIMD clients are always strict; DCR clients take the tenant's mode.
- `logo_uri` is accepted and ignored (clients have no logo field).
- An empty grant intersection gives `authorization_code`.
- DCR redirect URIs refuse wildcards and script or file schemes.
- No tenant log event for registrations (Auth0 documents none); a server
  log line instead.
- Network ACL scope `dynamic_client_registration` waits for Plan 38c.
- `409` on register when a user's flow created the client (Auth0's
  "dynamically registered client").
- CIMD clients hold up to 10 credentials; refetches replace them.
- DCR and CIMD clients get their callback origins as `allowed_origins`
  (found by the E2E lane, LR41b-10).
- The OIDF Dynamic OP profile is not run (LR41b-11): it needs
  `private_key_jwt` registration, `request_uri` and sector identifiers.
- Final review: CIMD dynamic registration at `/authorize` is limited like
  `/oidc/register` (5 per second per tenant).

## Verification

Local toolchain: Go `1.27.4-X:nodwarf5`; Node 26.8.1; Chromium.

| Check | Result |
|---|---|
| Focused tests per task (ledger) | passed |
| Store conformance `ExternalClients`, `DefaultClientGrants` on memory, SQLite, gRPC (memory, SQLite) and the plugin process | passed |
| Mutation checks | the memory URL uniqueness check, DCR grant filtering, the CIMD identity binding, the 64 KiB cap, the concurrent-register retry, the assertion's presented client ID and the default-grant fallback each fail a test |
| `-race -count=5` on the CIMD Management tests | passed (after giving the concurrency test a fixed clock) |
| Console: Vitest, `vue-tsc`, ESLint | passed |
| `make e2e-dcr` | first run: the spa-js token request failed CORS (LR41b-10 fix); then passed, and passed again after the review fix and the dist rebuild |
| `console/dist` | built in a clean clone |
| `./scripts/check-sources.sh api/authentication.yaml` | passed |
| Fast tier `TMPDIR=/dev/shm/za41b GOTMPDIR=/dev/shm/za41b go test -p 4 ./...` | 116 packages ok; 5 failed because `/dev/shm` ran out of space (SQLite `disk I/O error`, linker `disk quota exceeded`); after clearing old plan scratch directories the 5 (sqlstore, storeplugin, three E2E harness packages) reran green with `internal/cimd` and `internal/server` |
| Final review | self-review (no reviewer subagent dispatched) |

## Deferred minors

- A refetch reapplies the document over the whole client spec, so an
  administrator's changes to a CIMD client's other settings (refresh token
  policy, organization usage) are reset at the next refetch.
- `/oidc/logout?client_id=` does not resolve a document URL.
- A CIMD lookup over a gRPC plugin lists all of the tenant's clients (as
  the WS-Fed alias lookup does).
- The DCR and CIMD rate limits count per process.
