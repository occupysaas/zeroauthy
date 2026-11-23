# Plan 37b implementation record

Status: **implementation and local verification complete**, starting from
`main` commit `179b0fc6` (PR #84 merged). Branch: `plan-37b-wsfed`; worktree:
`/mnt/nvme2/code/zeroauthy-plan37b`. Full plan-branch CI and maintainer
approval govern integration.

Spec: [WS-Federation design](specs/2026-11-16-zeroauthy-ws-federation-design.md).
Plan: [Plan 37b](plans/2026-11-16-zeroauthy-plan-37b-ws-federation.md).
Decisions: D-0140 (LR37b-1…14). Operator guide:
[WS-Federation](../ws-federation.md).

## Progress

1. Task 1: contracts (OpenAPI `addons.wsfed`, `client_aliases`,
   `form_template`, `adfs` options and the four WS-Fed routes; D-0140 with
   node-wsfed provenance; W1–W5) frozen.
2. Task 2: client rules and storage: `client_aliases` unique per tenant
   (migration 0045 index table), `wsfed.v1` capability, conformance suite
   `ClientAliases`.
3. Task 3: `samlcore` SAML 1.1 assertions, RSTR, WS-Fed token verification
   (fuzzed); WS-Fed sign-in through the authorization flow.
4. Task 4: federation metadata (tenant and application) and sign-out.
5. Task 5: `adfs` connections: rules, metadata fetch, thumbprint rotation,
   login, replay, HRD, upstream sign-out, inventory, Deploy migration.
6. Task 6: seed, preserved-ID bootstrap, console, `make e2e-wsfed`, docs,
   verification.

## Verification

Local toolchain: Go `1.27.4-X:nodwarf5`; Node 26.8.1.

| Check | Result |
|---|---|
| Focused Go tests per task (`task-done` ledger) | passed |
| SQLite, memory and gRPC conformance (`ClientAliases`, area oauth) | passed |
| Fuzz `FuzzVerifyWSFedToken` 30 s (`internal/samlcore`) | passed, 1,253,696 executions |
| Console: Vitest 747 tests, `vue-tsc`, ESLint | passed |
| `make console` twice | identical `console/dist`; committed |
| `make e2e-wsfed` (`tests/e2e/run-m37b-wsfed.sh`) | first run: server refused the seed (an intranet ADFS sign-in endpoint was required to be public; fixed with a regression test). Second run: Playwright 3 passed (relying-party fixture sign-in and `wsignout1.0`; `wreply` outside callbacks refused; ADFS stand-in login, ID token claims and upstream `wsignout1.0`), secret scan passed, Deploy CLI four cells passed |
| `make e2e-saml` (regression for shared SAML code) | Playwright 3 passed, secret scan passed, Deploy CLI four cells passed |
| Fast tier `go test -count=1 -p 4 ./...` (no `-race`, tmpfs), commit `dde15c87` | exit 0, 111 packages ok, no failures |
| Fast tier rerun after the final-review fix | PENDING |
| PostgreSQL and MySQL | not run locally (containers); plan-branch CI runs the SQL databases |

## Findings during the plan

- **PATCH replaces `addons`.** Enabling one add-on from the console would
  have dropped the other; both console tabs now send the other add-on
  (console test).
- **Intranet ADFS.** The sign-in endpoint from the metadata was validated
  as a server-side fetch target (public host); it is only a browser
  redirect, so private hosts are allowed. Found by `make e2e-wsfed`.

- **`wresult` in logs.** The final self-review found that `wresult`, a
  bearer token, was not a sensitive log key, so callback failures before the
  flow registered the value would log it unmasked. Fixed with
  `TestWSFedTokenKeys`.

## Final review

Self-review of the whole branch (no reviewer agent was dispatched). Deferred
minors: a `client_aliases` entry may equal another application's client ID,
and realm-only `/wsfed` then picks the client-ID owner (tokens still go only
to that application's callbacks); no front-channel sign-out of other WS-Fed
relying parties.

## Rulings

The ledger's rulings, with their cost if wrong:

- Task 1: `signInEndpoint`, `thumbprints`, `thumbprints_sha384` and
  `prev_thumbprints` are read-only on `adfs` (spec: computed from the
  metadata) — a Deploy CLI import carrying them has them replaced.
- Task 2: a new `wsfed.v1` store capability gates `client_aliases` and
  `form_template` writes (an older `saml.v1` plugin would drop them) — one
  extra capability probe per plugin.
- Task 2: alias uniqueness by a `(tenant, SHA-256 of alias)` primary key in
  SQL; gRPC alias lookup lists the tenant's clients and filters — O(clients)
  per realm-only sign-in on plugins.
- Task 2: PATCH still replaces the whole `addons` object (Plan 37a
  behaviour) — clients must send both add-ons; the console does.
- Task 3: the WS-Fed IdP lives in `internal/samlidp`, not a new
  `internal/wsfedidp`, to share the mapper, Actions effects, signer and
  error pages — a less clean package boundary.
- Task 3: `wreply` uses the `redirect_uri` callback matcher (spec: Auth0
  callback wildcard rules), http(s) only — a wildcard callback admits more
  replies than an exact list (LR37b-11).
- Task 3: on `/wsfed/{client_id}`, a present `wtrealm` must be the client ID
  or an alias (spec realm-confusion anti-goal) — relying parties with an
  unregistered `wtrealm` must add it to `client_aliases`.
- Task 3: missing `wreply` → the first plain callback; audience `wtrealm`,
  else `wreply`, `urn:`-prefixed (node-wsfed) — may differ from Auth0 for
  realm-less requests (W5).
- Task 3: failures after validation end at an error page (LR37b-8) — relying
  parties see zeroauthy's page instead of their own error.
- Task 3: WS-Fed claims use the Plan 37a mapper with an empty add-on plus
  `api.samlResponse` effects; `setRelayState` has no effect (LR37b-12) — W2
  may differ.
- Task 4: `wsignout1.0` goes through `/v2/logout`, so `wreply` must be an
  allowed logout URL (LR37b-9, W6) — relying parties listing it only as a
  callback get the logout URL error.
- Task 4: no WS-Fed session participants and no front-channel
  `wsignoutcleanup1.0` to other relying parties (node-wsfed has none;
  deviates from spec §3) — other relying parties keep their local sessions.
- Task 4: `wsignoutcleanup1.0` shows the signed-out page (200) and ignores
  `wreply` — a relying party expecting a redirect or image sees HTML.
- Task 5: `adfs_server` is fetched on create and on options writes, no daily
  refresh (LR37b-13) — a certificate rollover needs an options write.
- Task 5: thumbprint trust (`thumbprints` ∪ `prev_thumbprints`,
  `thumbprints_sha384`); SHA-1 signatures refused (LR37b-13) — ADFS trusts
  set to SHA-1 fail until switched to SHA-256 (the ADFS default).
- Task 5: the sign-in request sends `wreply` = `/login/callback` — an IdP
  that refuses `wreply` would need it removed.
- Task 5: ADFS user ID order (LR37b-7, W3) — a different `user_id` for some
  claim setups.
- Task 5: only root profile claims are mapped from ADFS tokens — custom
  claims do not reach profiles (follow-up).
- Task 5: ADFS sign-out redirects to `wa=wsignout1.0` with `wreply` =
  `returnTo` and no return leg (LR37b-10) — logout ends at ADFS's page if it
  ignores `wreply`.
- Task 5: no unsolicited WS-Fed login (LR37b-14) — ADFS IdP-initiated
  sign-on to zeroauthy fails.

Follow-ups are listed in
[plan-1-followups.md](plan-1-followups.md#plan-37b-observation-points).
