# Plan 38a implementation record

Status: **implementation and local verification complete**, starting from
`main` commit `953ee03e` (PR #85 merged; Plan 37c's PR #87 not yet merged).
Branch: `plan-38a-ad-ldap`; worktree: `/mnt/nvme2/code/zeroauthy-plan38a`.
Plan-branch CI passed (run 45293348939, 52 jobs; the first run failed
`e2e-ad` because CI runners have no OS keychain, fixed in `2a0fec94`). Main
(with Plan 37c) was merged in and migration 0046 renumbered to 0049; the
maintainer approved the merge on 2026-11-23.

Spec: [AD/LDAP design](specs/2026-11-16-zeroauthy-ad-ldap-design.md).
Plan: [Plan 38a](plans/2026-11-16-zeroauthy-plan-38a-ad-ldap.md).
Decisions: D-0160 (LR38a-1…14, D38-1…12). Operator guide:
[AD/LDAP](../ad-ldap.md).

Maintainer rulings (2026-11-22): §9.1 speak the connector protocol; §9.2
E2E with the pinned connector release and its mock LDAP server; §9.3
replica forwarding over internal HTTPS.

## Progress

1. Task 1: contracts (`ad` strategy, `ConnectionOptionsAD`,
   `provisioning_ticket_url`, status route, ticket and hub routes), D-0160
   with the connector wire protocol and source references, inventory block.
2. Task 2: options rules, provisioning tickets and signing keys
   (`store.ADHubStore`, `ad_hub.v1`, migration `0049_ad_hub`, conformance
   suite `ADHub`), ticket routes, connector-managed options read-only,
   status route, logscrub and request-log hiding of the ticket.
3. Task 3: the WebSocket hub: TLS only, RS256 connector tokens verified
   against provisioned certificates, single use, session rows, eviction,
   idle timeout.
4. Task 4: request multiplexing (pid and op matching, timeouts, in-flight
   cap, disconnects, failover).
5. Task 5: hosted login through the connector, error mapping, brute-force
   protection, home realm discovery, user provisioning
   (`federation.DirectLogin`), password change through `PATCH /users/{id}`.
6. Task 6: replica forwarding over HTTPS (`server.replica_url`,
   `server.replica_ca_file`).
7. Task 7: Kerberos through the connector's WS-Fed endpoint, seed, Deploy
   CLI round trip, console, `make e2e-ad`, docs, verification.

## Rulings made during implementation

- **LR38a-4 (spec deviation):** the ticket is reusable for the
  connection's life, not single use: the connector reads `{ticket}/info`
  and posts its certificate at every start (`server.js`). Accepted by the
  maintainer (2026-11-23): Auth0's connector needs the same, so there is no
  Auth0 or OIDC drift.
- **LR38a-12:** directory passwords change through the Management API; the
  hosted forgot-password flow is not offered for `ad` connections. Ruled
  final by the maintainer (2026-11-23): the directory owns the password.
- **Migration 0049:** renumbered from 0046 when Plan 37c (0046–0048)
  merged first (maintainer, 2026-11-23).
- **gRPC:** one `ADHubCall` JSON RPC behind `ad_hub.v1`, like Plan 37c's
  `DirectoryCall`.
- **Forwarding key:** derived per connection from its sealed signing key
  (`keys.Wrapper` does not expose the master key).

## Found by the real connector

- The connector exits unless `GET /test` (its start-up latency test)
  answers 2xx: now served on tenant hosts.
- The hub left a write deadline on the socket after each frame, so the pong
  answering a later connector ping failed and the socket dropped after 10
  seconds; fixed, with `TestHubKeepsPingingConnector` (fails without the
  fix).
- The connector replaces Node's CA list with the system store or
  `SSL_CA_PATH`; documented for private CAs.

## Verification

Local toolchain: Go `1.27.4-X:nodwarf5`; Node 26.8.1; podman.

| Check | Result |
|---|---|
| Focused Go tests per task (ledger) | passed |
| `ADHub` conformance on memory, SQLite, gRPC (memory, SQLite) and the plugin process | passed |
| `go test -race -count=5 ./internal/adhub` | passed |
| Mutation checks | removing the reply op check fails `TestHubMultiplexer`; skipping the forward signature check fails `TestForwardAuthentication`; logging the password unscrubbed fails `TestADLoginNoSecretsInLogs`; dropping the write-deadline reset fails `TestHubKeepsPingingConnector` |
| Console: Vitest 750 tests, `vue-tsc`, ESLint; `make console` | passed; `console/dist` committed |
| `make e2e-ad` (`tests/e2e/run-m38a-ad.sh`) | first runs found the two connector gaps above and two harness problems (Playwright does not route redirect targets; a log check raced the log follower); final run: SDK setup, connector online, Playwright 3 + 2 passed, Deploy CLI round trip, password change through the connector, status offline, log audit (no skips) |
| Fast tier `TMPDIR=/dev/shm/za38a GOTMPDIR=/dev/shm/za38a-go go test -p 4 ./...` | passed (exit 0, 112 packages ok, no failures) |
| `make check-sources` | every x-source URL reachable |

## Not verified locally

PostgreSQL and MySQL for `ADHub` (plan-branch CI runs them), a live Auth0
tenant (observation points D38-1…12), Kerberos with a real Windows
domain (the Kerberos path is covered by Go tests with a signing fixture),
and the hosted forgot-password flow for `ad` users (not offered by design,
LR38a-12).
