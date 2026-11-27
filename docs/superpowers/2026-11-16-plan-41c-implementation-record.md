# Plan 41c implementation record

Status: **implemented and verified locally**, on `plan-41c-ciba` (worktree
`/mnt/nvme2/code/zeroauthy-plan41c`), based on `main` after PR #101 and
merged with `main` after Plan 41b (PR #102): the migration is renumbered
0053 (41b is 0052), and the protobuf keeps 41b's client field 38 and this
plan's 39.

Plan: [Plan 41c](plans/2026-11-16-zeroauthy-plan-41c-ciba.md). Spec:
[CIBA, email channel](specs/2026-11-16-zeroauthy-ciba-design.md).
Decisions: D-0100 (LR41c-1…9, C41-1…8), amending D-0025. Operator guide:
[CIBA](../ciba.md). Sources: Auth0's CIBA flow, configuration and email
notification guides read 2026-11-26, the Management OpenAPI, the tenant log
schemas and OpenID CIBA Core 1.0.

Maintainer request (2026-11-26): start on 41b and 41c.

## What was built

1. Task 1: contracts (`/bc-authorize`, the CIBA grant, discovery members,
   client `async_approval_notification_channels`), D-0100.
2. Task 2: `store.CIBAStore` (`ciba.v1`) in memory, SQL (migration 0053)
   and gRPC (JSON dispatch); the client channels field; client rules.
3. Task 3: `/bc-authorize` (`internal/ciba`, `internal/oauth`), the
   `async_approval` email, limits, discovery.
4. Task 4: `/bc-verify` approval pages on the hosted stack, reusing the
   device flow's `flowReq` machinery.
5. Task 5: the poll grant.
6. Task 6: console, seed, `make e2e-ciba`, docs.

## Rulings beyond the plan

- Email only for `requested_expiry` 301–259200 s (Auth0's documented
  window); the default 300 s is refused without push.
- `binding_message` uses Auth0's documented alphabet (no spaces).
- Expired requests answer `access_denied`, as Auth0 documents.
- The link is Auth0's `/bc-verify?consent=`; Actions see
  `oidc-ciba-web-link`; 5 requests per minute per user (Auth0).
- Unknown and unverified users get the same answer and the email is sent
  off the request path, so neither content nor timing tells them apart;
  Auth0 says it "rejects" them (C41-1 stays open).
- Page order is confirm → sign in → decide (device-flow precedent);
  Auth0 signs in first. Deny needs no sign-in.
- Poll errors are `400` (CIBA Core); an approval collected after expiry
  still redeems.
- MFA and Actions at approval come from the shared login path; no
  CIBA-only unit test (E2E and the shared tests cover them).
- `auth_req_id` is stripped from Actions bodies and hidden by name in
  logs (found by `TestActionsBodyStripsEveryGrant`, then extended to
  `logscrub`).
- The E2E lane uses the dir mail driver; no expiry path there.
- The CIBA log types were inventoried as not emitted; the E2E lane found
  it and they are now emitted.
- Final review: expired requests are swept 24 hours after expiry; the
  poll checks the origin before it can consume an approval.

## Verification

Local toolchain: Go `1.27.4-X:nodwarf5`; Node 26.8.1; Chromium.

| Check | Result |
|---|---|
| Focused tests per task (ledger) | passed |
| Store conformance `CIBA` on memory, SQLite, gRPC (memory, SQLite) and the plugin process | passed |
| Mutation checks | the memory poll's client check, the no-oracle answer, the wrong-user guard, single redemption and the poll's origin check each fail a test |
| `-race -count=3` on the redemption and other-client tests | passed |
| Console: Vitest, `vue-tsc`, ESLint | passed |
| `make e2e-ciba` | first runs: loopback SMTP refused (switched to the dir driver), then the CIBA log events missing (inventory fixed); then passed |
| Fast tier `TMPDIR=/dev/shm/za41c GOTMPDIR=/dev/shm/za41c go test -p 4 ./...` | 120 packages ok, none failed |
| `console/dist` | built in a clean clone |
| Final review | self-review (no reviewer subagent dispatched) |

## Deferred minors

- The CIBA limits count per process.
- Deny on `/bc-verify` needs no sign-in.
