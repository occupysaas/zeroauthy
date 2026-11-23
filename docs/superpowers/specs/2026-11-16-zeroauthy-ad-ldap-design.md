# Plan 38a — AD/LDAP connections through Auth0's AD/LDAP Connector protocol

**Date:** 2026-11-16. **Status:** design; not implemented; the protocol
choice (§9.1) needs a maintainer ruling before Task 2.

**Roadmap entry:** [management roadmap, Plan 38](2026-10-19-zeroauthy-management-roadmap-design.md)
("the `ad` strategy … the design decides whether zeroauthy speaks that
connector's protocol (so existing connectors keep working) or ships its
own LDAP bind"); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **F5** (track F, after F4). Plan 36 (F1) left
`GET /api/v2/connections/{id}/status` for this plan. Read the
[clean-room policy](../../../CLEAN_ROOM.md) (Auth0's MIT
`auth0/ad-ldap-connector` may be read and studied; provenance recorded),
`AGENTS.md`, the [Plan 37b spec](2026-11-16-zeroauthy-ws-federation-design.md)
(WS-Fed RP core) and the [Plan 36 spec](2026-11-16-zeroauthy-enterprise-oidc-design.md)
(HRD).

## 1. Outcome and scope

An operator creates an `ad` connection, gets a **provisioning ticket URL**,
and installs Auth0's open-source AD/LDAP Connector (unchanged) inside the
corporate network with that ticket. The connector dials out to zeroauthy
over a WebSocket ("AD hub"); zeroauthy then authenticates users with
username/password through the connector, can also send browsers to the
connector's WS-Fed sign-in (for Kerberos / Windows integrated auth), and
shows the connector's status. Existing Auth0 customers can repoint their
installed connectors at zeroauthy by provisioning them again.

**Recommended approach (§9.1):** speak the connector protocol (this
spec). The alternative — a native LDAP bind from zeroauthy — needs a new
LDAP client module, requires zeroauthy to reach the directory directly,
and breaks the connector migration story.

**Rule:** strict 1:1 with Auth0's documented behaviour; the connector's
source (MIT, `auth0/ad-ldap-connector`, read 2026-11-16) defines the wire
protocol; every message learned from it is recorded with provenance and
confirmed by running the real connector in E2E. Local rulings **LR38a-n**,
observation points **D38-1…n** in **D-0160** (F5 block D-0160–0169).

### In scope

1. `ad` strategy options (OpenAPI `ConnectionOptionsAD`): `tenant_domain`,
   `domain_aliases`, `ips`, `agentIP`, `agentMode`, `agentVersion`
   (connector-managed), `certAuth`, `certs`, `thumbprints`,
   `thumbprints_sha384`, `kerberos`, `disable_cache`,
   `disable_self_service_change_password`, `brute_force_protection`,
   `signInEndpoint` (connector-managed), `set_user_root_attributes`,
   `icon_url`, `non_persistent_attrs`, `upstream_params` (stored-only).
2. **Provisioning:** ticket URL per connection
   (`https://<tenant host>/p/ad/<ticket>`, D38-1), `GET <ticket>/info`
   (returns the `adHub` WebSocket URL and connection details the connector
   reads), `POST <ticket>` (the connector posts its certificate,
   `signInEndpoint`, `agentMode`, `agentVersion`; zeroauthy stores certs,
   thumbprints, endpoint, version and returns `signingKey` if documented,
   D38-2).
3. **AD hub WebSocket:** the connector connects, sends
   `{n:"authenticate", p:{jwt}}` signed with its private key (verified with
   the provisioned certificate); zeroauthy answers `authenticated` or
   `authentication_failure`; then zeroauthy sends requests
   (`authenticate_user`, `search_users`, `change_password`, `list_groups`)
   with a request id and receives `<pid>_result` replies; WebSocket ping/pong
   keep-alive.
4. **Login:** database-like username/password on the hosted login page for
   an `ad` connection → `authenticate_user` over the hub → profile via the
   connector's profile mapper output → identity `ad|<connection>|<id>`
   (D38-3); errors mapped (wrong username/password, account disabled,
   expired, locked, password expired, password change required — the
   connector's error classes) to Auth0's login errors.
5. **Kerberos / WS-Fed path:** when `kerberos` is on and the request comes
   from `ips`, the browser is sent to the connector's `signInEndpoint`
   (WS-Fed), and the token returns to zeroauthy's WS-Fed RP endpoint
   (Plan 37b) validated against the provisioned `certs`/`thumbprints`.
6. **Password reset / change:** `change_password` through the hub
   (unless `disable_self_service_change_password`).
7. **Groups:** `list_groups` results populate the user's `groups` profile
   attribute (connector behaviour) and, when Plan 37c is merged, directory
   groups (D38-4).
8. **`GET /api/v2/connections/{id}/status`:** `200` when a connector is
   connected and authenticated for that connection, `404` with the
   OpenAPI message otherwise (documented).
9. **Caching:** last successful credential result cached for offline login
   only if `disable_cache` is false and the connector documents it
   (D38-5); default no zeroauthy-side credential caching (LR38a-1).
10. Console, seed, Deploy CLI, docs, tests.

### Not in scope

- A native LDAP bind (alternative of §9.1).
- Running or bundling the connector (operators install Auth0's release).
- Connector auto-update and the connector's own admin UI (they stay the
  connector's).

### Anti-goals

- **Connector impersonation.** The hub accepts a connector only with a JWT
  signed by the private key whose certificate was provisioned through a
  valid, unexpired, single-use ticket for that connection; a second
  provisioning rotates the certificate and closes the old socket.
- **Credential exposure.** Passwords travel only over the authenticated
  WebSocket (TLS required on the public listener, LR38a-2), are never
  logged, never stored, and request ids are random.
- **Hub as an open relay.** zeroauthy sends only the four request types;
  replies are matched to pending ids with a timeout (10 s, D38-6) and an
  in-flight cap per connection.
- **Multi-replica routing.** A login on replica A can reach a connector
  connected to replica B (§6), without exposing the hub to other tenants.

## 2. Evidence

- Management OpenAPI (read 2026-11-16): `ConnectionOptionsAD` fields and
  descriptions ("managed by the AD Connector agent" for `agentIP`,
  `agentVersion`, `signInEndpoint`, `thumbprints`), `get_status`
  ("Retrieves the status of an ad/ldap connection … `200 OK` … when the
  connection is online, otherwise a `404`").
- `auth0/ad-ldap-connector` (MIT, pushed 2026-11-12): `lib/provisioningTicket.js`
  (`GET <ticket>/info`, expects `adHub`), `lib/configureConnection.js`
  (`POST <ticket>` with `certs`, `signInEndpoint` = `<SERVER_URL>/wsfed`,
  `agentMode`, `agentVersion`; reads `signingKey`), `ws_validator.js`
  (WebSocket to `AD_HUB` with `http→ws`; messages `{n, p}`; `authenticate`
  with `{jwt}`; events `authenticated`, `authentication_failure`,
  `authenticate_user`, `search_users`, `change_password`, `list_groups`;
  replies `<pid>_result`; ping/pong), `lib/errors/*` (error classes).
- Auth0 AD/LDAP connector docs (install, provisioning, Kerberos) read at
  build time (D38-7).

## 3. Protocol details (built from the connector source; confirmed by E2E)

| Step | Direction | Message |
|---|---|---|
| Ticket info | connector → zeroauthy | `GET /p/ad/<ticket>/info` → `{adHub: "wss://<host>/ad-hub", connectionName, …}` (fields per source, D38-8) |
| Configure | connector → zeroauthy | `POST /p/ad/<ticket>` JSON `{certs:[base64 DER], signInEndpoint, agentMode, agentVersion}` → `200 {signingKey?}` |
| Connect | connector → zeroauthy | WebSocket `wss://<host>/ad-hub` |
| Authenticate | connector → zeroauthy | `{n:"authenticate", p:{jwt}}` (claims per source; signed RS256 with the connector key) |
| Accept | zeroauthy → connector | `{n:"authenticated"}` or `{n:"authentication_failure"}` |
| Login | zeroauthy → connector | `{n:"authenticate_user", p:{pid, username, password, …}}` → `{n:"<pid>_result", p:{err?, profile?}}` |
| Search | zeroauthy → connector | `search_users` (used by password reset lookups, D38-9) |
| Change password | zeroauthy → connector | `change_password` |
| Groups | zeroauthy → connector | `list_groups` |

Exact payload members are captured in `internal/adhub/protocol.go` with
source line references in D-0160.

## 4. Login behaviour

- The hosted login page shows the `ad` connection like a database
  connection (username/password); HRD by `domain_aliases`/`tenant_domain`
  (Plan 36).
- `brute_force_protection` uses Plan 19 buckets keyed by connection and
  username.
- Connector errors map to the hosted messages and log types Auth0 uses for
  AD failures (logs schema, D38-10).
- When no connector is online: the login fails with a "connection not
  available" message and log, never falls back.

## 5. Kerberos

- `kerberos: true` and the client IP in `ips` → redirect to the
  connector's `signInEndpoint` (`/wsfed` on the connector) with WS-Fed
  parameters; the connector answers to zeroauthy's WS-Fed RP endpoint for
  `ad` connections; tokens validated against provisioned `certs`.
- Outside `ips`: the username/password form.

## 6. Multi-replica hub

- Each replica accepts connector sockets; a store table
  `ad_hub_sessions(tenant_id, connection_id, replica_id, connected_at,
  last_ping_at)` records where each connector is.
- A login on another replica forwards the request to the owning replica
  through an internal authenticated channel (replica-to-replica HTTPS
  with a shared secret derived from the master key, LR38a-3, D38-11 for an
  alternative such as the job queue), or fails over to the next connected
  connector of the connection when several are installed (connectors are
  stateless; Auth0 supports several per connection, D38-12).

## 7. Storage

- Ticket hashes and expiry; connector certificates and thumbprints in the
  connection's options (sealed private parts none — only public certs);
  hub sessions; one migration numbered at merge; gRPC capability
  `ad_hub.v1`.

## 8. Console, seed, Deploy CLI, tests

- Console: Enterprise → Active Directory/LDAP: create, show ticket URL,
  connector status (online, version, last ping), settings (IPs, Kerberos,
  cache, change password), login experience.
- Seed: the strategy (tickets are created on the destination).
- Deploy CLI: `ad` connections round trip (connector-managed fields
  preserved).
- Tests: protocol unit tests with recorded frames; hub authentication
  (wrong key, expired ticket, replayed JWT); request/response matching,
  timeouts, in-flight caps; error mapping table; multi-replica forwarding
  with two servers; status endpoint.
- **E2E** `make e2e-ad`: run the real connector (pinned release, Node) in
  a container against `mock-ldap/mock-ldap-server.js` from its own repo
  (or an OpenLDAP container), provision with a ticket, log in through
  Playwright, change password, read status — the pin needs approval
  (§9.2).

## 9. Decisions needed from the maintainer

**Ruled 2026-11-22 (maintainer): the recommended options** — the
connector protocol (1), the connector release with its mock LDAP server as
the E2E pin (2), and internal HTTPS between replicas (3).

1. **Connector protocol (recommended) or native LDAP bind** (the roadmap
   question).
2. **E2E pin** of the connector release and its mock LDAP server (or an
   OpenLDAP container image).
3. **Replica forwarding** design (§6): internal HTTPS between replicas
   (proposed) or routing through the store/job queue (higher latency).

## 10. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR38a-1 | No zeroauthy-side credential cache. |
| LR38a-2 | The hub requires TLS on public listeners. |
| LR38a-3 | Replica-to-replica forwarding with a master-key-derived secret. |

Observe later (`docs/superpowers/plan-1-followups.md`): **D38-1** ticket
URL path; **D38-2** `signingKey` in the configure response; **D38-3** AD
user ID format; **D38-4** groups mapping; **D38-5** connector-side cache;
**D38-6** request timeout; **D38-7** Kerberos docs; **D38-8** ticket info
fields; **D38-9** when `search_users` is used; **D38-10** AD log types;
**D38-11** alternative forwarding; **D38-12** several connectors per
connection.
