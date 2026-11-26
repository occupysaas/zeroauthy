# Plan 42a implementation record

Status: **implementation and local verification complete**, starting from
`main` commit `7b506a2a` (PR #88 merged). Branch: `plan-42a-my-account`;
worktree: `/mnt/nvme2/code/zeroauthy-plan42a`. Plan-branch CI and
maintainer approval govern integration.

Spec: [My Account API design](specs/2026-11-16-zeroauthy-my-account-api-design.md).
Plan: [Plan 42a](plans/2026-11-16-zeroauthy-plan-42a-my-account-api.md).
Decisions: D-0210 (LR42a-1…17, Y1–Y10). Operator guide:
[My Account API](../my-account-api.md). Contract: `api/myaccount.yaml`,
from Auth0's My Account OpenAPI 1.0 (read 2026-11-25).

## Progress

1. Task 1: contract (`api/myaccount.yaml`, seven operations, `x-source`),
   `TestMyAccountContracts`, D-0210, observation points Y1–Y10.
2. Task 2: activation (system API `https://{canonical host}/me/` through
   `POST /resource-servers`, tenantsetup, deletable), the per-host
   audience at every token entry point and `/authorize`, the user-flow
   decision for its tokens, client credentials and token exchange refused;
   `internal/myaccount` router, bearer checks and `ErrorResponse`.
3. Task 3: `internal/authmethods` (the listing both APIs use), list, read,
   `GET /factors`.
4. Task 4: `auth_session` in the MFA challenge store, sealed and bound.
5. Task 5: TOTP, email, phone and recovery-code enrollment;
   `mfa.WithoutAutomaticRecovery`.
6. Task 6: passkey (native ceremony), WebAuthn roaming and platform (MFA
   ceremony with an API binding that keeps application origins), password
   change through the reset path's checks and effects.
7. Task 7: `PATCH` (name, phone preference) and `DELETE` with the
   last-sign-in-method guard.
8. Task 8: CORS for `/me/v1`; seed `my_account_api` and user grants;
   console activation card, deactivation and application user access;
   `make e2e-my-account`; docs.

## Rulings made during implementation

LR42a-8…17 in D-0210. Also:

- `MyAccountIdentifier` uses only the canonical host (every tenant gets
  one at startup); `authz.ValidateRequestOn` (host-aware) replaces
  `ValidateRequest` in the four production callers.
- The Management API's listing is unchanged (authenticators only).
- The E2E lane uses the passkey `challenge_ui: button`: with `both`, the
  hosted login page re-navigated to `/u/login/passkey` repeatedly in
  headless Chromium without an authenticator (follow-up: check Plan 33b's
  autofill without credentials).

## Verification

Local toolchain: Go `1.27.4-X:nodwarf5`; Node 26.8.1; Chromium.

| Check | Result |
|---|---|
| Focused Go tests per task (ledger) | passed |
| Mutation checks | dropping the WebAuthn binding's first-origin check fails `TestWebAuthnBindingOrigins`; allowing the last password/passkey to be deleted fails `TestDeleteLastFirstFactor` |
| Console: Vitest, `vue-tsc`, ESLint | passed (761 tests); `console/dist` built in a clean clone |
| `make e2e-my-account` | first run: the hosted-login passkey autofill loop above (lane switched to `challenge_ui: button`); then passed: setup, raw requests (401/403 bodies, `x-correlation-id`, client credentials `access_denied`, CORS), Playwright 1 test (spa-js login, factors, TOTP, passkey with a virtual authenticator, rename, delete, the last-method guard), log audit of 11 private values; passed again after the review fix |
| Fast tier `TMPDIR=/dev/shm/za42a GOTMPDIR=/dev/shm/za42a go test -p 4 ./...` | passed (exit 0, 116 packages ok) before the review fix; the packages the fix touches (`tenant`, `oauth`, `authz`, `server`, `passwordless`, `myaccount`) passed again after it |
| `make check-sources` | `api/myaccount.yaml` all reachable; two Plan 37c URLs in `api/management.yaml` now answer 404 (`.../get-connections-directory-provisionings`, `.../get-connections-scim-configurations`), already on `main` |
| Final review | self-review against the code-reviewer checklist (no reviewer subagent was dispatched); found and fixed the custom-domain code flow (`TestMyAccountCodeFlowOnAlias` RED→GREEN) |

## Not verified locally

PostgreSQL and MySQL (plan-branch CI runs them; the plan adds no
migration: `auth_session` rows use the MFA challenge table), a live Auth0
tenant (observation points Y1–Y10), and a custom domain in the browser
lane (covered by Go tests on a second host).

## Deferred minors

- A deployment without the MFA service would refuse passkey and password
  enrollment too (`createMethod` checks it first); production always wires it.
- Changing the password of a linked identity answers `404`; a clearer
  `400` would help.
- `tenant.APIIdentifier`'s `ok` result is now always true; its callers'
  refusal branches are dead code.
- The API detail page's system note still says system APIs cannot be
  deleted, which is not true of the My Account API.
