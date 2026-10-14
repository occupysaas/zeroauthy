# Plan 1 follow-ups

Deferred findings from the Plan 1 reviews (2026-10-13). Items under
"Prerequisites" must be resolved before the named milestone starts.

## Prerequisites

| Before | Item |
|---|---|
| SQL drivers (milestone 7) | `keys.Manager.Ensure` returns early if any key exists, so a half-created key set (current without next) can never rotate; it is also only serialized in-process. Create whichever of current/next is missing and enforce one current/one next at the store level. |
| SQL drivers (milestone 7) | `storetest` gaps: tenant `Update` name collision and stale-domain checks; read-side copy checks for clients/resource servers/grants; Rotate wrong-status guard; single next/current invariant. Add `Store.WithTx`; make `seed.Apply` transactional. |
| Management API (sub-project 3) | Tenants created at runtime need `keys.Manager.Ensure`; domains must be normalized with `tenant.NormalizeHost` and must not fall under `server.base_domain`. |

## Nice to have

- `oauth`: verify errors are logged as "bad secret" (log `secrets.Verify` errors separately); unknown-client timing differs from known-client; no-store not asserted on every error case; no nil-`Minter` guard.
- `keys`: signer cache never evicts revoked keys; tests index keys by position; missing tamper / wrong-master / version / concurrent-Sign tests.
- `config`: `MasterKey` would leak if the config struct were ever logged with `%+v` (it is not today).
- `oidc`: JWKS leak test checks only `d` (also check `p`, `q`, `dp`, `dq`, `qi`).
- `contract`: nil `r.Body` panics; `TestUndeclaredStatusIsReported` counts across a shared recorder.
- `seed`: empty file reports `seed: EOF`; `Load` and update paths untested.
- `tests/e2e/run-m3.sh`: readiness loop doesn't fail fast; port 8443 hardcoded in three files.
- Spec §1.2 item 3 sub-bullets still name node-auth0 methods.

## Plan 2 follow-ups

| Before | Item |
|---|---|
| SQL drivers (milestone 7) | Expired login transactions, authorization codes and sessions are never purged; add `DeleteExpired` to those stores and a periodic sweeper. |
| Multi-instance deployments | Login throttling is in-process; move counters to the store or a shared cache. |
| Large tenants | CORS origin checks list all clients per cross-origin request; index origins. |
| Hosted login (spec §7) | Template override directory; bcrypt hash verification and upgrade for imported users. |
| Refresh tokens (milestone 5) | On authorization-code replay, revoke refresh tokens issued from that code. |
