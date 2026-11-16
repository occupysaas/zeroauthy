# Plan 38a — AD/LDAP through the connector protocol Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `ad` connections served through Auth0's open-source AD/LDAP
Connector: provisioning tickets, the AD hub WebSocket, password login,
password change, groups, Kerberos via WS-Fed, connection status, and
multi-replica routing.

**Architecture:**
- **`internal/adhub`** (new): ticket service, WebSocket hub (`golang.org/x/net/websocket`,
  already in `go.mod`), connector authentication, request multiplexer,
  replica registry and forwarding.
- **`internal/federation/rules/ad.go`** and an `ad` authenticator used by
  the hosted login like a database connection.
- WS-Fed return path from Plan 37b for Kerberos.

**Tech Stack:** Go 1.26.10 (`golang.org/x/net` v0.62.0 already a
dependency; no new module), Vue/TypeScript console, Playwright 1.64.0,
the real connector in E2E (pin per ruling §9.2).

**Spec:** [Plan 38a design](../specs/2026-11-16-zeroauthy-ad-ldap-design.md). § refers to it.

**Gates:** Task 2+ after ruling §9.1; Task 7 E2E after §9.2; Task 6 design
per §9.3. **Depends on:** Plans 36 (HRD), 37b (WS-Fed RP).

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Clean room.** Connector source provenance per message in D-0160.
- **Parity.** LR38a-1…3 and D38-1…12 in **D-0160**; follow-ups.
- **Security:** single-use tickets; connector JWT verified with the
  provisioned cert; TLS required for the hub on public listeners;
  passwords never logged or stored; request timeout 10 s; in-flight cap 64
  per connection.
- **Migration.** One forward-only migration in three dialects written as
  `0054_ad_hub.sql`; renamed to main's latest + 1 at merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za38a GOTMPDIR=/dev/shm/za38a go test -p 4 ./...` plus
  `make e2e-ad`; push `plan-38a-ad-ldap`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan38a`, branch
  `plan-38a-ad-ldap`; record in
  `docs/superpowers/2026-11-16-plan-38a-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Connector impersonation:** a socket with a JWT signed by an
   unprovisioned key, a replayed JWT, or a reused ticket → refused; the
   real connector still connects. Task 3 `TestHubAuthentication`.
2. **Reply confusion:** a `<pid>_result` for another pid or connection is
   ignored; late replies after timeout are dropped. Task 4
   `TestHubMultiplexer`.
3. **Password never logged** (log-capture test over a full login). Task 5
   `TestADLoginNoSecretsInLogs`.
4. **Cross-replica login** reaches the connector on another replica.
   Task 6 `TestHubForwarding`.

---

### Task 1: Contracts and decisions
- [ ] `api/management.yaml` (`ad` options, status route), `api/authentication.yaml` (ticket routes, hub route), inventory `ad` block, D-0160 with the protocol provenance table, follow-ups → commit `docs: freeze Plan 38a contracts and D-0160`. Ask for §9 rulings.

### Task 2: Options and tickets
**Files:** `internal/federation/rules/ad.go`, `internal/adhub/ticket.go`, ticket routes, storage + migration, tests.
- [ ] Tests: options rules (connector-managed fields read-only through the Management API); ticket create on connection create/rotate; `GET info` shape; `POST` stores certs/thumbprints/endpoint/version; single use; expiry → implement → commit `feat(adhub): provisioning tickets`.

### Task 3: Hub and connector authentication
**Files:** `internal/adhub/hub.go`, `auth.go`, `protocol.go`, tests with recorded frames.
- [ ] Tests: `TestHubAuthentication` (Review Focus 1); ping/pong; close on re-provisioning; per-tenant isolation → implement → commit `feat(adhub): connector WebSocket hub`.

### Task 4: Request multiplexer
- [ ] Tests: `TestHubMultiplexer` (Review Focus 2); timeouts; in-flight cap; connector disconnect fails pending requests → implement → commit `feat(adhub): request multiplexing`.

### Task 5: Login, change password, groups, status
**Files:** `internal/login` (ad authenticator), error mapping, brute-force keys, `internal/mgmt/connections.go` status, tests.
- [ ] Tests: success and each connector error class; brute force; no connector online; `TestADLoginNoSecretsInLogs` (Review Focus 3); change password; groups attribute; status `200`/`404` → implement → commit `feat(login): AD/LDAP logins through the connector`.

### Task 6: Multi-replica forwarding (design per §9.3)
- [ ] Tests: `TestHubForwarding` (Review Focus 4) with two servers on one store; failover between two connectors → implement → commit `feat(adhub): route requests to the replica holding the connector`.

### Task 7: Kerberos, console, seed, Deploy CLI, E2E, docs, final verification
- [ ] Kerberos redirect for `ips` with the Plan 37b WS-Fed return; console pages; seed; Deploy CLI round trip; `make e2e-ad` with the approved connector pin and mock LDAP; docs `docs/ad-ldap.md`; fast tier + E2E; push; review; maintainer approval.
