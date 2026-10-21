# Plan 1 follow-ups

Deferred findings from the Plan 1 reviews (2026-10-13). Items under
"Prerequisites" must be resolved before the named milestone starts.

## Prerequisites

| Before | Item |
|---|---|
| Management API (sub-project 3) | Tenants created at runtime need `keys.Manager.Ensure`; domains must be normalized with `tenant.NormalizeHost` and must not fall under `server.base_domain`. |
| Management API (sub-project 3) | Use a pinned auth0-cli as a black-box E2E client against zeroauthy, and run the same commands against the maintainer's own Auth0 tenant to compare behavior (CLEAN_ROOM.md, "Behavior testing against the maintainer's own tenant"). Record differences as observation notes or fact-only assertions. Its MIT source may be read (CLEAN_ROOM.md, "Open-source Auth0 code"); confirm anything learned only from it before building. |

## Nice to have

- `oauth`: verify errors are logged as "bad secret" (log `secrets.Verify` errors separately); unknown-client timing differs from known-client; no-store not asserted on every error case; no nil-`Minter` guard.
- `keys`: signer cache never evicts revoked keys; tests index keys by position; missing tamper / wrong-master / version / concurrent-Sign tests.
- `config`: `MasterKey` would leak if the config struct were ever logged with `%+v` (it is not today).
- `seed`: `Load` and update paths untested.
- `tests/e2e/run-m3.sh`: port 8443 hardcoded in three files.
- Spec §1.2 item 3 sub-bullets still name node-auth0 methods.

## Plan 2 follow-ups

| Before | Item |
|---|---|
| Multi-instance deployments | Login throttling is in-process; move counters to the store or a shared cache. |
| Large tenants | CORS origin checks list all clients per cross-origin request; index origins. |
| Hosted login (spec §7) | Template override directory; bcrypt hash verification and upgrade for imported users. |

## Plan 2 deferred review findings

- Login throttle pruning is O(n) and in-process.
- CORS: OPTIONS/CORS are not in the OpenAPI contract.
- Untested branches: fragment/form_post error delivery; `Resume` re-validation failure; public client without PKCE; deleted audience; default ID token lifetime; `auth_time` value; store-error throttle refund; signup error re-render CSP.

## Plan 3 follow-ups

| Before | Item |
|---|---|
| Multi-instance deployments | The sweeper runs in every `serve` process; harmless (deletes are idempotent) but redundant. |

## Plan 3 deferred review findings

- `sweepLoop` is untested and not awaited on shutdown; SQL drivers must honour context cancellation in `DeleteExpired`.
- No test for sweep error aggregation.
- `session.Manager.AddClient` returns `ErrNotFound` when a logout races `/authorize`: a 500 and no code, which fails safe.
- `RefreshTokens.Rotate` checks for a conflict before checking for reuse, so a malformed successor skips reuse revocation; only a caller bug can reach this.
- The `form_post` check uses a case-sensitive `https://` prefix; this fails closed.
- Seed validation does not tie the `refresh_token` policy to the `refresh_token` grant type.
- `newRefreshToken` reads its own clock rather than the grant's `now`.
- `refreshLifetimes` and the idle clamp have no direct unit tests; the seed accepts an `idle_token_lifetime` above the 31557600 default when `token_lifetime` is 0, and the value is then silently capped.
- Refresh tests: no deleted-user case; the leeway test does not assert the second successor's family or its revocation; test setup discards errors; the "family revoked" log line also fires on the already-revoked race.
- The refresh grant does not re-check `allow_offline_access`, so tokens survive the API disabling offline access; undecided.
- Revoked tokens that never expire are never purged; the memory store's hash lookups scan all tokens under the write lock.
- Revoke tests: no `OPTIONS /oauth/revoke` CORS test.
- Repeated query parameters on the logout endpoints get a JSON 400 from the generated wrapper rather than the HTML error page.
- A single `za_logout` confirmation cookie per browser means two tabs confirming at once fail closed.
- `idTokenHint` accepts any tenant-signed single-audience JWT, including an access token; harmless, but token type is not checked.
- The logout confirmation page has no "stay logged in" action.
- `/oidc/logout` tests do not cover a hint with multiple `aud` values, a GET carrying `confirm=yes`, or a confirmed POST after the session is gone.
- Flow test gaps: it does not check that logout leaves refresh tokens valid; it does not drive `/oidc/logout` through `server.New`; revoke asserts only the status code; there is an unchecked type assertion.
- The nextjs E2E uses `AUTH0_DOMAIN=https://localhost:8443` with `allowInsecureRequests` because the SDK rejects a domain with a port or localhost; the documented production setup (port 443 with a real hostname) is not exercised.
- A code replayed mid-exchange without `offline_access` still returns the first exchange's access and ID tokens (JWTs are not revocable); the `ReplayedAt` re-check runs only when a refresh token is issued.
- The `server_error` branch for a failed `AuthCodes().Get` after the refresh token is stored has no test.

## Plan 4 follow-ups

- `PUT /prompts/{prompt}/custom-text/{language}` and `GET /prompts/{prompt}/custom-text/{language}` are planned for sub-project 3; storage is ready.
- RTL layout needs a visual review once an RTL catalog exists.
- Email templates must use the catalog in milestone 6.

## Plan 4 deferred review findings

- No tests for Accept-Language q ties, or for a key-specific variable (such as `${min}`) used in an override of a different key.
- `i18n.New` iterates custom-text languages in map order, so if duplicates that differ only by case ever bypassed validation, the winner would be arbitrary.
- Invalid `enabled_locales` also produce noisy duplicate errors from custom-text validation.
- No re-apply test for the seed's locale and custom-text update branch.
- The catalog test treats "used" as "present in keys.go", and keys written in template pipeline form are invisible to its regex.
- `login.load` does not log non-NotFound errors from `Clients().Get`.
- The custom-text escape test lacks a positive assertion that the escaped text is present.
- No negative test for a bad `state` combined with `ui_locales`.
- The POST no-connection localization test lacks a status assertion.
- `load`'s `(flow, err)` contract (flow returned alongside errNoConnection) is documented only by an inline comment.
- The store-error `fail` paths in the login package have no dedicated test.
- `${clientName}` renders empty on the logout and error pages.
- Languages are matched only exactly or by base language; there is no `zh-TW` → `zh-Hant` style matching.
- The password-policy alias (`signup.signup.password-policy-not-conformant`) is not variable-checked; a value made only of unknown variables renders an empty alert. Fall back to the specific key when the rendered alias is blank.
- The strict-key check for the `zeroauthy` prompt is case-sensitive, so `Zeroauthy`/`ZEROAUTHY` typos are accepted and ignored.

## Plan 5 follow-ups

- Email verification emails. **Closed in Plan 17** (signup and user creation send the verification email; `/u/email-verification` consumes the ticket).
- MFA (`mfa_required`).
- Breached-password detection.
- The `organization` parameter on `change_password`.
- Move the `change_password` send limit into the store; it is per-process today, which multi-instance deployments need fixed.

## Plan 5 deferred review findings

- Access tokens issued before a reset stay valid until they expire (stateless JWT).
- **Fixed in Plan 17 Task 11 (`fix: user version closes the reset, block and import-login races`):** a password grant that verified the old password just before a reset could still mint a refresh token after `RevokeByUser`. Grants now mint inside a transaction that re-reads the user and refuses a changed `Version`.
- SMTP implicit TLS (port 465) is not supported.
- Background reset sends are untracked goroutines; sends in flight at shutdown are lost (documented in D-0018/D-0019).
- No storetest mutates a returned ticket's `UsedAt` to prove the driver returns a copy; memory `cloneJSON` shares non-JSON container types.
- Email tests lack coverage of dir-driver file modes, credential withholding on non-TLS non-localhost SMTP, and the STARTTLS success path; `TestBodyCRLFNotDoubled` is vacuous (the old bug shows as a doubled blank line, not `\r\r`).
- SMTP accepts a username without a password, does not honour context cancellation after dialing, and the dir driver does not tighten permissions on an existing directory.
- Password grants call `RecordLogin` before the audience check, look up the identifier twice, and duplicate the code grant's refresh-token issuance block.
- Password grants lack edge tests: realm not enabled for the client, no default directory, non-database connection, `offline_access` without the refresh grant; `auth0-forwarded-for` is described only in prose, not as an OpenAPI header parameter.
- `SignupFormRequest` duplicates the `SignupRequest` schema; `parseBody` has a redundant `dec.More()` check; no test for `picture` rune counting.
- `change_password` lacks tests for a non-database connection and for the detached send context; import grouping in `server_test.go`; `KeyEmailResetSubject` placement in `keys.go`.
- E2E: the node reset-email check does not assert the recipient or link; the auth-js `signUp` result is unasserted; the browser reset spec uses an opaque `match()[0]`, is not retry-safe, and picks the newest email by mtime.

## Plan 6 follow-ups

- MariaDB support (it lacks the `utf8mb4_0900_bin` collation that MySQL 8.0.17+ provides).
- Down-migrations; today migrations only move forward.
- Move the login throttles and the `change_password` send limit into the store, for multi-instance deployments.
- MySQL stores several user-supplied values in `VARCHAR(255)` columns (wider or `TEXT` elsewhere), so a longer value fails only on MySQL. Email addresses are now capped at 254 bytes (D-0020); add validation-layer length limits for the rest so every driver accepts the same values: `resource_servers.identifier` and `client_grants.audience` (`TEXT` on SQLite and PostgreSQL), the seed's `client_id`, connection names and tenant names.
- Tenant reads (`Tenants().Get`/`GetByName`/`GetByDomain` and `List`) take separate statements for the tenant rows and their domains, outside a transaction, so a read concurrent with `Update` can see the new row with the old domains (a torn read).
- `storetest.Suites` and `RunSuites` are unused in the repository since the SQL drivers run the full suite; keep them for plugin authors bringing suites up one at a time, or unexport them.
- Concurrent `SigningKeys.Rotate` calls for a tenant that does not exist are not serialized (the lock is the tenant row); acceptable because keys are only rotated for existing tenants.

## Plan 7 follow-ups

- Automatic plugin restart with backoff; today a plugin crash fails storage calls until the server restarts.
- Binary checksum pinning for plugins (go-plugin `SecureConfig`).
- Plugin-side schema migration hooks (plugins are not `storage.Migrator`s).
- A reference plugin in a language other than Go.
- A closed plugin client reports `context.Canceled` for calls made after `Close`; a dedicated "store closed" error would be clearer.
- Theoretical lost-`BeginTx`-response window: if the response is lost after the plugin registered the transaction, the host cannot name it, so it waits for the idle timer. Client-proposed transaction ids would close it; decide before protocol v1 is frozen.
- Route plugin logs through `slog` instead of go-plugin's stderr logger, so levels and format match the host.
- `storeplugin.Serve` reads the parent pid inside its watcher goroutine; read it synchronously before starting the goroutine so a host that dies during plugin startup is still detected.

## Plan 8 follow-ups

- **Closed in Plan 17:** the callers for the stored `verify`, `delete` and `change_email` scripts exist. `verify` runs when a verification ticket is opened, `delete` on a Management API delete and `change_email` on an email change; `customdb.Client` now exposes them. (The runner `Executor.Execute` could already execute any of the seven scripts.)
- `mfa_factors` in profiles (MFA, sub-project 2).
- Custom signup prompt fields passed to `create` (changelog 2026-04-02, sub-project 2).
- Custom user IDs at signup (changelog 2026-09-17, early access).
- Passkeys on custom databases.
- Bcrypt hashes from bulk import.
- An egress allowlist for scripts. Network access is open; operators firewall it.
- Pinning the Node version through a config option; today any Node 22.13 or later is accepted.

## Plan 8 deferred review findings

- **Fixed in Plan 17 Task 11 (`fix: user version closes the reset, block and import-login races`):** a late first import login could overwrite a password hash that a concurrent reset completion just set (it now uses `SetPasswordHashIfEmpty` and checks the password against the hash that won), and two concurrent submits of one reset ticket could both run `change_password` (the ticket is now used before the script runs).
- Import mode: the length check uses the normalized login while the script receives the trimmed form; `profileUser` reads the clock separately from `upsertProfile`; a comment in `importLogin` should say the script can still run for a migrated user reached through a changed login (the local hash wins).
- Legacy mode: usernames from a legacy store must match the local username pattern; a legacy sign-up that lands on a locally blocked user returns a bare `ErrUserBlocked` (a 500); a `ValidationError` with an empty message renders a doubled period.
- Scripts that hang or crash the runner are refunded: per tenant, up to 64 concurrent attempts per 20 s, immediately for a runner crash; cancelled requests are refunded while the script keeps running. Suggested fix: count cancellations and timeouts against the IP throttle only.
- Runner hardening left open (D-0022 addendum): Buffers are not bounded by `max_memory_mb`; `os.hostname`, `userInfo` and `networkInterfaces` are readable; per-process script caches and console output are unbounded and unthrottled; a script can forge response and log lines within its own tenant; the compile cache ignores the script name on the fallback path and fallback globals are shared; a last stderr line without a newline is dropped at EOF; `PDEATHSIG` is tied to the forking OS thread; a cancelled request holds its concurrency slot until the 20 s limit.
- The `require` denylist can be bypassed through `process.getBuiltinModule`; only `--permission` is a control, and it must not be described as one.
- Minors: the seed does not require `get_user`/`create`/`change_password` on legacy connections (runtime-only failure); store plugins built before proto fields 10-14/18 drop them (fails closed); `pkg/store.ScriptNames` is an exported mutable slice; script failures are logged twice; client disconnects are logged at Error.
- The seed re-seals the configuration and updates the connection on every apply, even when nothing changed.
- Test gaps: `Apply` with no wrapper plus a configuration (the error must not leak the value); exact boundary accepts (102400 bytes, 64 keys, 4096 bytes) and the config checks for an empty `node` and `idle_timeout <= 0`; `TestRunnerRequireAllowlist` accepts any error kind; `process._linkedBinding` is not probed by the isolation test; `TestImportConcurrentFirstLogin` does not assert that the conflict path ran; `TestLatestVersionIsTwo` hard-codes 2.
- Cosmetic: an overlong comment line in `store.proto`; the constant `maxConfigValueBy` should be `maxConfigValueBytes`; the comment on `TestRunnerEscapedContextStillIsolated` overstates what it proves; a last stderr line without a newline.
- E2E (m9): `LEGACY_PORT` is used throughout `run-m3.sh` but stays 8099, because `seed.yaml`, `m9-custom-db.mjs` and `m9-import.spec.mjs` hard-code it; the spec cannot be re-run against the same server; a missing legacy-store field prints "undefined"; the 409 check does not isolate the `get_user` path.

## Plan 9 follow-ups

- Organizations: `third_party_client_access` and consent per organization.
- `default_for: third_party_clients` default permissions, which arrive with dynamic client registration.
- `allow_all_scopes` and `authorization_details_types` on client grants.
- RBAC and its intersection with granted scopes.
- `/api/v2/grants` and `/api/v2/client-grants`, and revoking refresh tokens when a grant is deleted (sub-project 3).
- The `tpc_` client ID prefix for generated strict client IDs (sub-project 3).
- Device flow (`/activate`, which will reuse the consent page) and PAR, which strict clients reject (Plans 10 and 11).
- Auth0 stored a user grant for a first-party client after a login that showed no screen (observation check 1). zeroauthy stores grants only on accepted consent (D-0026); revisit once the grants Management API exists. **Closed in Plan 17 (U9):** Auth0 stores the grant in this case and so does zeroauthy.
- Re-check the Management API defaults (O1) with a machine (client-credentials) login of auth0-cli; the observations used a user login. **Closed in Plan 17 (O1):** a client-credentials login gives the same defaults.

## Plan 9 deferred review findings

- Storage: `UserGrants.Upsert` inside an outer transaction cannot recover from a PostgreSQL unique violation (nothing calls it inside a transaction today). The MySQL `grant_key` column joins its parts with a newline, so identifiers containing newlines could collide. `TestMigration0003Defaults` does not check the tenant and connection defaults or the uniqueness constraint after migration.
- Plugin protocol: no test covers the server mapping an empty `subject_type` to `client` (a host from before Plan 9). The signing-keys section banner in `client_repos.go` lost its title.
- Seed: `TestApplyRefusesPartyChange` covers only first-party to third-party; a security-mode change, the reverse flip and re-applying a tenant flag are untested.
- Decision table (`internal/access`): no rows cover partial user-grant coverage, an empty `ThirdPartySecurityMode`, an unknown policy, a permissive client with a grant, client credentials under a stored `allow_all`, `prompt=none` with a screen shown, or empty scopes; the O4 expectations are derived from the constant rather than written as literals. `ShowErrorPage` redirects for an unknown `RedirectionPolicy` string (unreachable, because the seed validates it). `Decide` always passes `offline_access` through and relies on callers to gate it (`userScopes`, `offlineAllowed`); confirm this in a review of the token handlers.
- Hosted login: protected error pages are all titled "access denied"; map the error code to a title key. `TestThirdPartySessionOnNonDomainConnectionLogsInAgain` does not tell old logic from new, the protected-page tests do not assert the description, and no login test covers domain-connection resolution for a third-party client. `ConsentView` sets `Confirmation` when nothing at all is needed. The scope-merge test requests the same scope twice (weak), and there is no `max_age` re-check test for the consent page.
- Domain connections: `/dbconnections/signup`, `/dbconnections/change_password` and the password grant still check `enabled_clients` directly, so a third-party client on a domain connection is refused there. Auth0's behaviour is unknown; decide before the Management API.
- Consent page: `postedFlow` now checks the CSRF token before the connection (an order change), and `TestConsentDeclineProtected`, `TestConsentWrongCookie` and the grant-absence check use weak assertions (any error passes).
- Token endpoint: the client-credentials path repeats the client-grant lookup instead of calling `h.decide`; the `partner` fixture is unused; `TestRefreshGrantRechecksPolicy` needs a comment on rotation; `TestClientCredentialsDenyAll` does not assert the description; the `store` import in `token_test.go` sits in the standard-library group.
- E2E (m10): the decline assertion cannot fail (the URL `/u/consent` with the main element visible is also true of the consent page); assert the error text, a 400 and no callback. The confirmation check only counts `ul.scopes` items (zero); add a positive assertion. `blackbox-clients.md` lists node-auth0 under m10 although its check runs in m3. The suite uses fixed port 3001, does not await `server.close` and leaves its `framenavigated` listener attached. Run evidence is a summary only.

## Plan 10 follow-ups

- `private_key_jwt` client authentication, with the 2025-10-10 changelog item (issuer string as the assertion `aud`).
- JAR: signed `request` objects at `/authorize` and in PAR; the client's `signed_request_object` settings.
- RAR: `authorization_details` and the resource server's `authorization_details` types.
- mTLS client authentication and `mtls_endpoint_aliases`.
- PAR for public clients (Auth0 does not support it today).
- Actions access to `ext-*` parameters (sub-project 2).
- A general Authentication API rate limiter covering `/oauth/par` (zeroauthy has per-identity throttles only).
- The `iss` authorization response parameter (RFC 9207), which Auth0 sends (tenant setting `authorization_response_iss_parameter_supported`; observations/par.md).
- Repeated query parameters on `/authorize` get a JSON 400 from the generated wrapper (existing item; it also applies to `request_uri`).

## Plan 11 follow-ups

- A sample Android TV app: the Android Studio TV emulator reaching zeroauthy at `10.0.2.2`, then a sideloaded Fire TV.
- `auth0-cli` as a device-flow client. It hardcodes `auth0.auth0.com`, its client ID and issuer, so testing it needs that host mapped to zeroauthy in a container with a trusted test certificate.
- Management API for `device_flow` (sub-project 3). Tenant log events `fdeaz`, `fdeac`, `fdecc`, `fede`, `sede`. Actions/Rules `oauth2-device-code` protocol.
- An Authentication API rate limiter covering `/oauth/device/code`, and throttle state shared across instances.
- Running `m10-device` with `E2E_IN_CONTAINER=1` (it needs podman on the host to start the .NET client).
- OpenID Foundation certification: a local dry run of the open-source OIDF conformance suite against zeroauthy (Basic OP, Config OP, Form Post OP and RP-initiated logout; not Implicit, Hybrid or Dynamic, which zeroauthy lacks), then a fee-waiver request to certification@oidf.org under https://openid.net/certification/open-source-project-certification-policy/ (decided case by case; maintainers must not be paid by an employer for the project). Any Auth0-copied behaviour that fails a spec test becomes a parity-versus-spec decision for the maintainer. Planned as its own plan after Plan 11.

## Plan 11 deferred review findings

- Storage: `DeviceCodes.Decide` does not validate `dec.Status` (callers pass only approved or denied). The memory driver looks user codes up by scanning. The SQL `Poll` returns full-precision times while the stored values are microseconds. No 4→5 upgrade test checks the new tenant columns' `''` default. The gRPC client does not validate a decoded `DeviceCode.status`, and no gRPC-level test covers `Decide` returning the record with `ErrAlreadyUsed` or an unknown poll outcome over the wire.
- User codes and seed: the default-mask logic in seed validation duplicates `devicecode.Settings`. A strict third-party device client gets several overlapping errors. `devicecode.Normalize` keeps any Unicode letter or digit; restricting it to ASCII `A-Z0-9` would avoid surprises such as full-width digits or `ß` becoming `SS`.
- `/oauth/device/code`: any `Authorization` header gives `403 unauthorized_client` (inferred, not observed). `TestDiscoveryDeviceEndpoint` only calls `TestDiscovery`. The stored `UserCodeHash` is only checked to differ from the plaintext. The no-default-audience branch is untested.
- Device grant: a non-rotating device refresh token is untested, and so is the deleted-user case (it shares the blocked-user path).
- Access and authz: `TestDecideDeviceDenyAll` cannot tell `codeAuthorizeDenied` from `codeTokenDenied` (both `invalid_request`). `Decide` on the device code does not recheck expiry after `validateFlow`, leaving a window of milliseconds. A device consent that fails on a server error ends the transaction, so the user starts again.
- Throttle: under concurrent requests from one IP bucket, a `Refund` can lift a lockout that a parallel miss just set, letting one extra miss through per race. The `ClientIP` value from a trusted `X-Forwarded-For` that carries a port or brackets does not parse, so it is keyed raw rather than by /64.
- E2E (`m10-device`): the spec pins `interval` and `expires_in`. A failed .NET build does not print the server logs. The container-branch skip message always prints. The wrong-codes test uses 6 of the 10 per-IP misses. The `za-e2e-device-` cleanup filter applies to the whole host. The `afterAll` `podman rm` has no timeout.

## Plan 12 follow-ups

- Release pipeline: a conformance gate (`make conformance` must exit 0) as the last milestone, after the management UI.
- A `client_secret_post` variant run of Basic and Form Post (the certification runs use `client_secret_basic`).
- Future profiles once the features exist: Implicit and Hybrid, Dynamic OP (client registration), front-channel and back-channel logout.
- Recertify when the suite or zeroauthy changes significantly.
- Request objects (JAR), together with `private_key_jwt` client authentication. Until then `request` is refused with `request_not_supported` (D-0035).
- The extra `profile` attributes (`website`, `zoneinfo`, `birthdate`, and so on); accepted warning in `oidcc-scope-profile` (D-0036).
- The `claims` request parameter; accepted warning in `oidcc-claims-essential`.
- `acr` and `acr_values`; accepted warning in `oidcc-ensure-request-with-acr-values-succeeds`.
- The `address` and `phone` scopes and claims; accepted skips of `oidcc-scope-address`, `-phone` and `-all`.
- `run.sh` robustness: apply the expected-file filtering earlier (before the suite starts), and make the `PLANS` input safe against newlines.

## Plan 13 follow-ups

- **Slices 2–6** of the Management API and console (design §2): APIs and client grants, connections (including enabling applications on them: an application created in the console or through the API is enabled on no connection until slice 3), users with import and forced reset, tenant settings with an `auth0-deploy-cli` round trip, social connections.
- **Pushed down the road** (design §2), each needing its own design: passwordless and phone reset, organizations and RBAC, MFA, branding and email-template editors, custom domains, logs and log streams, event streams, Actions and Forms, enterprise connections, the marketplace and integration catalogues.
- **Per-tenant admins:** operators carry a tenant list already (`["*"]` today); the system API cannot set it yet, and tenant-scoped operator tokens need a design.
- **Store-level client pagination and filtering:** `GET /api/v2/clients` pages in memory over `Clients.List`; users (slice 4) need it in the store. **Closed in Plan 17:** `Clients.List` filters and pages in the store.
- **Keeping client IDs and secrets on migration:** `auth0-deploy-cli` exports no secrets and Auth0 refuses a supplied `client_id` (D-0039, open for slice 5).
- **Client fields** accepted and ignored today (`description`, `client_metadata`, `logo_uri`, organizations and others, D-0039) could be stored and returned.
- **Rate-limit headers** on the Management API once a limiter exists.
- **Tenant log** for Management API writes; they go to the server log today.
- **Console:** translations beyond English; a Playwright accessibility audit (axe); `auth0 login` (device flow) against zeroauthy needs Auth0's host mapped and stays a follow-up.
- **E2E:** m13-console cannot reach `cli.e2e.test` from the browser, so it switches to the system tenant.

## Plan 14 follow-ups

- **SQL suite and conformance:** the cloud session ran the Postgres suite for migrations 0010 to 0012 (from installed binaries) but not MySQL, and could not run `make conformance` (no container runtime). Run `scripts/test-sql.sh` and `make conformance` where containers exist.
- **Store plugins:** the `ResourceServers.Delete` cascade (client grants, user grants, refresh tokens for the audience) is part of the store contract; third-party store plugins must implement it.
- **System API name:** the system Management API is "zeroauthy Management API" while `auth0-deploy-cli` excludes Auth0's by name, so a deploy-cli export includes it. Matching Auth0's name is a maintainer decision (D-0041).
- **Signing algorithms:** `HS256` and `PS256` (and `signing_secret`) are not supported.
- **Fields accepted but inert:** the organization, rich authorization, `consent_policy`, `proof_of_possession` and `token_encryption` fields; `token_lifetime_for_web`.
- **Connections** for new applications: still slice 3; a console-created application logs no user in until then.
- **E2E environment:** the browser specs need `E2E_CHROMIUM` (path to a Chromium) in a container without Playwright's own. `scripts/test-sql.sh` (now with `ZEROAUTHY_TEST_PG_PORT` and `ZEROAUTHY_TEST_MYSQL_PORT`) and the podman branch of `m10-device` were not run in the cloud session.

## Next: Plan 15 kickoff (slice 3, connections)

Notes for the session that writes Plan 15 (design §2 slice 3: `/api/v2/connections`, the database connection and its settings, enabling clients, the custom-DB options). Slices 2–6 get a short design before their plan (design §9), so start with superpowers brainstorming, then writing-plans, in the format of Plans 13 and 14.

- **Observation (CLEAN_ROOM.md):** the observer M2M application on the maintainer's dev tenant already holds the connection scopes (`read/create/update/delete:connections`, `read/update:connections_options`, `read:connections_keys`) and `read/update:tenant_settings`, and its credentials are the `OBS_AUTH0_*` environment secrets, so the observation task can run with option A as in Plan 14. Pace requests (a burst gave `429`), restore anything changed, and keep the observer session separate from the implementers.
- **Black-box client:** `auth0-cli` v1.37.0 has `connections list/show/create/update/delete` and `connections enabled-clients show/update`; the E2E should cover them as m13/m14 do, plus `auth0 api` for anything those commands do not reach.
- **Starting points:** `internal/store` connections and enabled clients, the seed's connection rules (`internal/seed/validate.go`), custom databases (Plan 8, D-0022), consent and domain connections (Plan 9), the console's application detail (an application is enabled on no connection until this slice).
- **Open maintainer decisions carried over:** the system API name (D-0041), `HS256`/`PS256` support.

## Plan 15 follow-ups

- **SQL suite and conformance:** the cloud session ran the Postgres suite for the connection migrations but not MySQL, and could not run `make conformance` (no container runtime). Run `scripts/test-sql.sh` and `make conformance` where containers exist.
- **Stored, not enforced** (D-0042): `authentication_methods` and `passkey_options`, `attributes` and `precedence`, `mfa`, `disable_self_service_change_password`, `non_persistent_attrs`, `display_name`, `show_as_button`, `metadata`, `realms` beyond the default, `connected_accounts`, `authentication`, unknown option keys, and `set_user_root_attributes: never_on_login` (behaves as `on_each_login`). Each becomes work when the feature behind it exists (passwordless and passkeys, MFA, attributes, social and enterprise connections).
- **Attack protection (slice 5):** `brute_force_protection` only switches zeroauthy's existing login throttle; thresholds and tenant-level attack protection settings wait for slice 5.
- **Users API (slice 4):** `/api/v2/users` would let the E2E checks confirm that deleting a connection deleted its users through the API instead of through sign-in.
- **Seed vs API rules:** seeded connections keep the seed's defaults (minimum length 8) and skip the API-only checks (name pattern, 72-character cap, the `set_user_root_attributes` rule). Tightening the seed is open.
- **Connection delete:** the cascade scans all users (O(users), several statements each) and the scan is not locked, so a user created while a delete runs can be left behind. Authorization codes, transactions, device codes and pushed requests for the connection's users are not deleted (they expire).
- **Name ordering:** names with non-ASCII characters can sort differently between store drivers (Unicode in memory, ASCII `LOWER` in SQLite), and the checkpoint cursor uses Go's lower-casing against SQL's, so page boundaries can differ. The checkpoint list also reads the whole set into memory.
- **Unrelated `PATCH`:** a `PATCH` that does not send `options` still re-validates the stored options under the API's limits, which a seeded connection might not meet.
- **Explicit empty lists:** `blocked_fields` or `custom` sent empty come back as the defaults.
- **Console:** The application quick start shows its connection note whether or not a connection is enabled.
- **Connection option scopes:** `read:connections_options` and `update:connections_options` are not enforced by any operation yet; enforce them (connection routes that touch `options`).
- **Script try:** a missing script runtime (503) still uses a rate-limit slot; console output is lost on a timeout.
- **Masking:** matching is by exact substring (encoded or split secrets pass), and a long line ending in the first byte of a value may be over-masked.

## Plan 16 follow-ups

- **Second language:** only English ships. A second catalog (`console/src/locales/<tag>.ts`) plus an entry in `console/src/i18n.ts` adds one; locale display names stay endonyms outside the catalog. The tenant settings preview lists languages from the same list.
- **More themes:** only light, dark and system exist; further themes are new token sets in `app.css`.
- **Actions design:** Actions is a placeholder. Triggers, the code editor and the deploy flow need their own design before a slice.
- **Preview fields:** the previews follow spec section 7; none were trimmed. Confirm field names against Auth0's reference as each slice ships.
- **Font name:** the WOFF2 files keep the family name "Glacial Indifference", which the OFL's Reserved Font Name clause may cover for a modified version; maintainer to decide whether to rename the family. `OFL.txt` now ships in `dist/assets`.
- **Brand contrast:** closed. The red AUTHY in the header is a logotype, which WCAG 1.4.3 exempts from the contrast minimum. Toggle track contrast: closed (1px ink border, checked in the browser).
- **Disabled radios (Multi-factor policy):** the disabled radios are very faint, and the fieldset legend sits on the border.
- **Disabled text contrast:** `--disabled-text` `#5f5f5f` on `--disabled` `#d6d6d6` is about 4.4:1; accepted because WCAG exempts inactive controls.
- **Planned tooltip case:** the `plannedWhen` catalog values are lowercase, so the sidebar tooltip reads "slice 4: ..." where the banner reads "Planned · slice 4".
- **Mobile breakpoint:** the drawer starts below 768px (Tailwind `md`), not the spec's 720px.
- **Deferred minors:** the theme radio lacks a component test; `typeLabel` and `strategyLabel` are duplicated in the List and Detail pages; `activeI18n()` is a module singleton, so the store locale and `i18n.global.locale` are two sources of truth; `main.ts` applies the theme twice (also in the preferences store); the CSS URL check in `build.test.ts` matches only `url(http...)`.
- **Locale persistence (fixed in the final review):** startup no longer saves the detected language; only an explicit choice in the language menu does (saved, then browser, then `en`).
- **E2E:** the console specs use the section links by text (`Database`); the sidebar now has more items, and the E2E does not yet cover the planned pages or the language menu.

## Plan 17 follow-ups

Closed from the users design section 7: verification emails, the store-level user version (closes the reset, block and import-login races), the set-if-empty hash write, callers for the `delete`, `change_email` and `verify` scripts, store-level client paging, the Plan 9 grant re-check (U9 confirmed), the O1 re-check, and the Plan 15 check that deleting a connection deletes its users (m17-mgmt-cli, through `/api/v2/users`). Still open: "bcrypt hash verification and upgrade for imported users" is Plan 18.

- **Hosted login is not version-guarded:** `/u/login` creates the session without the grants' version check, so a login whose password check finished before a reset completed can still create a session after the reset revoked the others. The code grant that follows checks only that the user exists and is not blocked (D-0043).
- **Jobs (Plan 18):** user import with Auth0's hash formats and first-sign-in upgrade, export, `jobs/verification-email`, and the console's email-sending action (the Users detail only creates the link today).
- **Search and store:**
  - Metadata numbers above 2^53 compare differently in the memory driver and the SQL drivers; MySQL's Unicode 9.0 case mapping differs from Go's for rare characters; the MySQL `JSON_TABLE` column for identity values is `VARCHAR(1024)`, so longer values fail to match.
  - `users_last_login` cannot serve the default order (the order is a `CASE` expression); there is no `(tenant_id, email)` index for `FindByEmail`; the list's `COUNT` and `SELECT` do not share a snapshot.
  - Parser edge cases without a test: the `!` escape, a lone backslash before a glob, metadata keys containing a space, `'` or `[`. A literal backslash is not escaped in the bare-term email globs. A leading `-` or `!` inside a field group negates.
  - `user_metadata: null` empties the metadata (not observed on Auth0). The store has two near-identical client filters (`grpcstore.filterClients` and the memory predicate), and `pageClause` is not used by `client_grants.go` or `userquery.go`; a `WritePage` helper would replace the hand-written totals envelopes (users, clients).
- **Data hygiene:**
  - `last_ip` stores the raw `X-Forwarded-For` text (parse it with `netip`); the session user agent is stored unbounded; the MySQL `phone_number` column is `VARCHAR(255)` while the others are `TEXT`; MySQL 0014 has a `LONGTEXT NOT NULL` without a default.
  - Old storage plugins silently ignore `Version` bumps, `ProfileData`, the new password-reset ticket fields and the session device fields; a plugin must add them (Go SDK note).
  - `users-by-email` does not check its `email` and `connection` parameters for NUL or invalid UTF-8.
- **Management API users:**
  - A legacy custom-database create has no local `FindByLogin` pre-check (an orphan can stay in the legacy store) and `ErrBadProfile` answers 500; a script failure is logged twice; the `Info` line for a sent verification email is noisy; `userConnection` blocks a metadata `PATCH` for a non-database identity; `GetUsers` writes its own totals envelope.
  - `mark_email_as_verified` that fails after the password change is only logged; a password-change ticket ignores `email` when `user_id` is also sent.
  - `link_with` does not check `typ`, `nbf` or `iat`; an import-mode linked identity with an empty hash strands its login; `OwnIdentityOn` is unused.
  - Link scanners in email clients consume verification tickets on `GET`, as on Auth0 (D-0043).
- **Races and tests:**
  - A token session swallows store errors; an `invalid_grant` message is not asserted; reuse detection is skipped on a version race; an import profile upsert whose re-read finds nothing answers 500.
  - The memory driver deep-copies the store per grant and its non-transaction writes wait on the transaction mutex without honouring cancellation (it is for tests and demos).
  - `TestImportLoginRacingReset` has a weak assertion, and three tests call `t.Fatal` or `f.call` off the test goroutine; `GetForUpdateSerializesRevocation` sleeps 200 ms instead of synchronizing.
- **Console users:**
  - The actions menu keeps a stale error banner; the Metadata and Details tabs drop unsaved edits when the user refreshes; Show more uses a short-page heuristic and its error replaces the table; the ticket dialog can race a close and reopen; the TTL is hard-coded (send `ttl_sec`); clearing a profile field sends an empty string; tests lack the ticket dialog error, Escape and focus, and show-more error cases.
  - The search help examples are static, the popover does not close on an outside click or return focus, and the sort headers are duplicated.
- **E2E:** the seed grants `create:users_app_metadata` it does not need; the auth0-cli script leaks the `cli-users-web` client and a temporary `HOME`; the request helper is copied from m15; one selector uses DOM order (`nth(1)`); the "emailed" assertion is trivial; the blocked check accepts any alert.
