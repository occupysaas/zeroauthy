# Plan 35 implementation record: client credentials, JAR and token exchange

Plan: `docs/superpowers/plans/2026-11-08-zeroauthy-plan-35-client-credentials-jar-token-exchange.md`.
Spec: `docs/superpowers/specs/2026-11-08-zeroauthy-client-credentials-jar-token-exchange-design.md`.
Decision: D-0063 (LR35-1 to LR35-14, C1 to C22). Guides:
`docs/client-authentication.md`, `docs/token-exchange.md`.
Executor: subagent-driven (one implementer and one reviewer per task).
Branch `plan-35-client-auth`, worktree `/mnt/nvme2/code/zeroauthy-plan35`,
from main `b6a39ec`.

## Commits

`git log --oneline b6a39ec..HEAD` before the Task 16 commit:

```
8769e0f fix(keys): publish signing JWKs without alg so PS256 tokens verify
f49bc6b refactor: Plan 33b MFA cleanups
cbf72bb docs: PAR, seed and organization pages after Plan 35
e3a5cbd docs: Plan 35 operator guides and D-0063
d51dca3 feat(seed): client credentials and token exchange profiles
e3dbfe6 feat(console): credentials, JAR and token exchange profiles
4f91f71 fix(oauth): resolve the exchange organization before the user; CTE throttle default
b5be684 feat(oauth): custom token exchange grant
5d90504 fix(actions): refuse secret deny codes; align CTE attributes and actor limits
90e32ba feat(actions): custom-token-exchange trigger
b019628 test(conformance): expect the unsigned request-object redirect module to be skipped
1b90d53 feat(mgmt): token exchange profiles
a26b105 feat: HS256 and PS256 API signing
4a1f1ec feat(authz): signed request objects (JAR)
030772b fix(oauth): one-method refusals and capability-gated discovery
121bda9 feat(oauth): private_key_jwt client authentication
fb6790e fix(clientcred): accept compact JWS only
68a662f feat(mgmt): client credentials API and private_key_jwt client settings
8bcc006 feat(grpcstore): negotiate client_credentials.v1
2bc483e fix(sqlstore): byte-order the token exchange profile cursor
716580c feat(sqlstore): migration 0036 for client credentials and token exchange
39ea50e feat(store): client credentials, assertion jtis and token exchange profiles
67115dd feat(clientcred): parse client credentials and verify signed client JWTs
4ee2a62 docs: freeze Plan 35 contracts and D-0063
```

Task 16 adds `test: verify Plan 35 client authentication, JAR and token
exchange end to end` on top.

## What each task built

- **Task 1, contracts (4ee2a62).** API YAML for the credential and profile
  routes (`501` stubs), the nullable `token_endpoint_auth_method`, the
  `custom-token-exchange` trigger inventory (version `v1`), D-0063 with the LR35
  rulings and C points, and the follow-up list.
- **Task 2, `internal/clientcred` (67115dd, fb6790e).** PEM parsing (SPKI,
  PKCS#1, X.509; RSA 2048 to 4096), RFC 7638 `kid`s, and verification of
  signed client JWTs (algorithm pinned by the credential, compact JWS only).
- **Task 3, store contract and memory (39ea50e).** Credentials, single-use
  assertion `jti`s, token exchange profiles, `PushedAuthRequest.Signed`, the
  `store.ClientCredentialsAvailable` capability helper (R3), and the storetest
  suite.
- **Task 4, migration 0036 and SQL (716580c, 2bc483e).** Three dialects,
  forward only. Expired `jti` rows join the sweeper. A byte-ordered profile
  cursor.
- **Task 5, plugin capability (8bcc006).** `client_credentials.v1` is
  negotiated and latched like `webauthn.v1`. Without it the new routes answer
  `501` and the new client fields are not sent.
- **Task 6, Management API credentials (68a662f).** Credential CRUD (at most
  two, PEM never returned) and the client settings
  `client_authentication_methods`, `signed_request_object` and
  `token_exchange`, including inline credential creation.
- **Task 7, `private_key_jwt` (121bda9, 030772b).** Client assertions at
  `/oauth/token`, `/oauth/revoke`, `/oauth/par`, `/mfa/challenge`,
  `/passwordless/start` and the native passkey endpoints. Replay refusal,
  one-method refusals and discovery gated on the capability.
- **Task 8, JAR (4a1f1ec).** Signed request objects at `/authorize` (GET and
  POST) and `/oauth/par`, `signed_request_object.required`, signed PAR marks,
  inner parameters winning, and `none` refused with `request_not_supported`
  (D-0035 lifted for signed objects).
- **Task 9, API signing (a26b105).** `HS256` with a sealed `signing_secret`
  (generated or at least 16 characters) and `PS256` with the tenant key. HS256
  tokens carry no `/userinfo` audience (LR35-9).
- **Task 10, profiles API (1b90d53).** `/api/v2/token-exchange-profiles` with
  checkpoint paging, the reserved prefixes, a limit of 100 per tenant, and
  bound Actions protected from deletion.
- **Task 11, trigger (90e32ba, 5d90504).** `onExecuteCustomTokenExchange`
  with `setUserById`, `setUserByConnection`, `setOrganization`, `setActor`,
  `deny`, `rejectInvalidSubjectToken`, metadata and cache. Secret-bearing deny
  codes are refused, and the attribute and actor limits are aligned with
  Auth0's api-object page.
- **Task 12, grant (b5be684, 4f91f71).** The RFC 8693 grant: profile, API
  consent-skip, the `pre-custom-token-exchange` throttle (default 10 attempts
  and 600000 ms), the Action, user resolution through the passwordless sign-up
  path, post-login, tokens with `act`, and the `secte`/`fecte` logs. The
  organization is resolved before any user is created.
- **Task 13, console (e3dbfe6).** The Credentials tab, the Private Key JWT
  picker, the JAR and token exchange toggles, Actions > Token exchange
  profiles, the API algorithm choice and the HS256 secret.
- **Task 14, seed and docs (d51dca3, e3a5cbd, cbf72bb).** Seed credentials,
  the three settings, `token_exchange_profiles`, HS256 APIs, the two guides,
  and D-0063 text.
- **Task 15, Plan 33b MFA cleanups (f49bc6b).** `store.WebAuthnAvailable`
  replaces four of seven copies, plus browser error names, the native timeout
  constant and a no-write test for the login page view.
- **Task 16, acceptance (8769e0f and the Task 16 commit).** The E2E suite,
  the C19 product fix, the Deploy CLI classification, this record and the
  roadmap update (below).

## Task 16

### C19 fix (8769e0f, a separate commit for review)

The pinned strict verifier refused PS256 against the tenant JWK, as checked
by a standalone script against jose: jose 4.15.9 (inside
`express-oauth2-jwt-bearer` 1.11.0) and jose 6.2.12 return
`ERR_JWKS_NO_MATCHING_KEY` for a PS256 token against a JWK marked
`alg: RS256`, and accept the same JWK without `alg`. The controller applied
spec §6's fallback:

- New signing keys are stored without `alg`, and keys stored earlier are
  rendered without it. `kty`, `use`, `kid`, `n` and `e` are unchanged.
- The JWK schema in `api/authentication.yaml` no longer requires `alg`; the
  generated `authapi.JWK` lost its `Alg` field.
- Tests were written first: `TestSignWithAlgPS256` and
  `TestJWKSFollowsRotation` now require no `alg`, and the new
  `TestJWKSOmitsStoredAlg` covers a key stored with `alg`. The RED run failed
  on all three before the fix.
- D-0063 C19, the client-authentication and signing-keys guides, the matrix
  row and the changelog (Unreleased > Changed) were updated.

Operator-supplied custom JWKS (Plan 20) are not published and were not
touched. No existing E2E assertion or conformance expectation reads the JWK
`alg`. The m20 lanes put `alg` only on operator custom JWKS they upload, and
m10's `jwks-rsa` selects keys by `kid`. The OIDF conformance job runs in CI
only.

### Suite `make e2e-client-auth`

Files: `tests/e2e/run-m35-client-auth.sh`, `m35-node.mjs`, `m35-cli.mjs`,
`m35-client-auth.spec.mjs`; Makefile target `e2e-client-auth`; added to the
`ci.yml` e2e matrix (which `plan-branch.yml` runs). It uses the production
app on SQLite (memory, PostgreSQL and MySQL through `E2E_M35_BACKENDS`) and
these lanes:

- **browser** (Playwright, SQLite):
  - On a JAR-required application, a plain authorize is `invalid_request`,
    and auth-js's unsigned PAR push is refused.
  - A signed request object on GET `/authorize` leads through the hosted
    login. auth-js (`clientAssertionSigningKey`, PS256) redeems the code and
    then the refresh token.
  - A replayed object and an object signed with a non-JAR key both show the
    request-object error page.
  - A signed PAR push, with a hand-built PS256 assertion carrying a `kid`,
    leads to a code redeemed by auth-js.
  - Console: the two keys of the web application are listed. On another
    application a key is added, checked through the API, and removed. The
    token exchange profile is listed.
- **sdk**:
  - auth-js client credentials with key A (no `kid`).
  - A replayed `jti` gets `401 invalid_client`. The endpoint-URL audience is
    accepted. An assertion plus a secret is `400 invalid_request`. The old
    secret alone is `401`. A lifetime over 5 minutes is `401`.
  - Rotation without `kid`: key B (PS256) is added and both keys work. A third
    credential is `400`. List and get never return the PEM, and patching
    `expires_at` works. Deleting A stops it authenticating and detaches it
    from the client (C3).
  - The live JWKS has no `alg`. `express-oauth2-jwt-bearer` accepts the RS256,
    PS256 and HS256 access tokens, and refuses a wrong secret, a crossed
    algorithm and a tampered signature.
  - The node-auth0 profiles manager runs list, create, update, get and delete.
    Reserved prefixes get `400` and a duplicate type gets `409`.
- **exchange**:
  - auth-js `exchangeToken`: `setUserByConnection` creates the user and the
    second exchange reuses it (one user). The refresh token works.
  - An actor chain yields `act: {sub, act}` and no refresh token.
  - The ID token passes the strict verifier.
  - An unknown `subject_token_type` and a rejected token are both
    `400 invalid_request`. A client without `token_exchange` is
    `403 unauthorized_client`.
  - With `pre-custom-token-exchange` set to 2 attempts, two rejected tokens
    from one end-user address (`auth0-forwarded-for`) lead to
    `429 too_many_attempts`, while another address still exchanges.
  - The logs record `secte` with the actor, `fecte` and `limit_mu`.
- **deploy**: the pinned Deploy CLI 9.1.0 handlers, run unmodified.
  - `tokenExchangeProfiles` imports a profile that names its Action, exports
    it with the Action name, renames it, re-imports it unchanged and deletes
    it with `AUTH0_ALLOW_DELETE`.
  - `clients` carries `token_exchange`.
  - `clientAuthCredentials` creates a key from a PEM and wires it in. The
    export carries names only, and re-importing it is a no-op. Rotation to a
    new key with deletion of the old one works, and the new key
    authenticates.
  - The `clientAuthCredentialsPre` pre-pass clears all keys.
- **cli** (auth0-cli 1.37.0):
  - `token-exchange list/create/show/update/delete`.
  - `apis create/update/show/delete --signing-alg` PS256, then HS256 (secret
    generated), then RS256 (secret discarded).
  - Credentials only through the raw `auth0 api`: 1.37.0 has **no client
    credentials command**.
- **audit**:
  - The fetch wrapper records every `client_assertion`, `request`,
    `subject_token`, `actor_token` and `client_secret` that leaves (including
    those auth-js builds itself), plus the HS256 secrets, passwords, private
    keys and management tokens. 65 representative secrets of 9 kinds were
    recorded.
  - Sinks scanned (12 files, 683325 bytes): `server.log`, the log export
    (`/api/v2/logs`), the log-stream receiver, the SQLite `tenant_logs` and
    `action_executions` (Action logs), our API, CLI and console captures,
    proxy, migrate and bootstrap output.
  - The Action deliberately `console.log`s the subject and actor tokens, and
    the stored Action log shows them masked (positive control).

Observation (not a product defect): given only `issuerBaseURL`,
`express-oauth2-jwt-bearer` refuses the PS256 token ("Unexpected 'alg'
value"), because it restricts algorithms to discovery's
`id_token_signing_alg_values_supported` (`["RS256"]`; ID tokens are RS256
only). The suite configures the PS256 verifier with `issuer`, `jwksUri` and
`tokenSigningAlg`, and `docs/client-authentication.md` says so.

### Deploy CLI classification (controller ruling)

Both manifest entries stay `excluded` from the four-cell export/import
matrix, with precise reasons:

- `clientAuthCredentials` is deploy-only by design, because the PEM is never
  exported.
- `tokenExchangeProfiles` works through its handler, but wiring it into the
  matrix (m20 fixtures, seed scopes, `internal/deploymigration`) is a follow-up
  in `plan-1-followups.md`.

`docs/deploy-cli.md` and the matrix row say the same.

## Local rulings and deferrals

- D-0063: LR35-1 to LR35-14 and C1 to C22. C19 was resolved by test
  (2026-11-15).
- `verify_email` is accepted by `setUserByConnection` but sends nothing yet
  (LR35-14; follow-up).
- The tenant MFA policy is not applied to custom token exchanges (C20,
  controller ruling; flagged to the maintainer as fail-open).
- Task 15 deferrals:
  - `mfa.Decide` stays per request, because its inputs change between
    requests.
  - Three `WebAuthnAvailable` copies remain: session, seed and events.
  - The hosted passkey retry snapshot stays in the challenge table, because
    moving it needs a schema change.
- Reads of `signing_secret` are not audit-logged (follow-up).
- The Deploy CLI matrix does not yet carry token exchange profiles
  (follow-up).

## Local verification (Task 16)

The snapshot of the passing E2E run is HEAD `8769e0f` plus the uncommitted
Task 16 files (`source.patch` in the artifacts). The harness SHA-256 values
match the committed files.

- `TMPDIR=/dev/shm/za35 GOTMPDIR=/dev/shm/za35 go test ./internal/keys/`
  failed before the fix (RED: 3 tests). After the fix
  `go test ./internal/keys/ ./internal/oidc/ ./internal/oauth/ ./internal/mgmt/`
  was ok, except one `internal/oidc` contract failure (`TestJWKS`: schema
  required `alg`). That was fixed in the YAML, and both packages were then
  ok.
- `TMPDIR=/dev/shm/za35 make e2e-client-auth` (SQLite, all lanes):
  - Runs 1 to 4 failed on harness issues:
    - Run 1: an untrusted-redirect error is shown as a page, not a redirect.
    - Run 2: PAR was not enabled on the tenant.
    - Run 3: the throttle address was taken from `X-Forwarded-For`, but the
      server uses `auth0-forwarded-for` for confidential clients.
    - Run 4: the Deploy CLI handler always PATCHes matched profiles, so the
      comparison now ignores `updated_at`.
  - None of the four was a product change.
  - **Run 5: exit 0**, all lanes passed: browser 2/2, sdk, exchange, deploy,
    cli, and the audit (12 sinks, 65 secrets absent).
- `mkdir -p /dev/shm/za35 && TMPDIR=/dev/shm/za35 GOTMPDIR=/dev/shm/za35 go test -p 4 ./...`
  on the same snapshot (no Go change since `8769e0f`): **exit 0**, 98
  packages ok, no failures.

Not run locally (CI only, per AGENTS.md): `-race`, PostgreSQL, MySQL, the
other E2E suites and conformance.

## CI

- Run 43701767767 failed on a gofmt slip.
- Run 43678724817 failed on the gRPC codec guard before Task 5, and on an
  e2e-logs flake that passed when the suite was rerun in the next run.
- Run 43726077115 (head 4a1f1ec) failed in conformance: an expected-skips
  gap for `oidcc-ensure-request-object-with-redirect-uri`, fixed in b019628.
- Run 43728533639 on 5d90504 passed every job (Tasks 1 to 11).
- Run 43754757189 on 4f91f71 failed in the console job on a stale console
  bundle, fixed by the Task 13 rebuild.

Final CI run: pending (controller fills in).
