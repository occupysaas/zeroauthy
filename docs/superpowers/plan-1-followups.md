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
- `oidc`: JWKS leak test checks only `d` (also check `p`, `q`, `dp`, `dq`, `qi`).
- `contract`: nil `r.Body` panics; `TestUndeclaredStatusIsReported` counts across a shared recorder.
- `seed`: empty file reports `seed: EOF`; `Load` and update paths untested.
- `tests/e2e/run-m3.sh`: readiness loop doesn't fail fast; port 8443 hardcoded in three files.
- Spec §1.2 item 3 sub-bullets still name node-auth0 methods.

## Plan 2 follow-ups

| Before | Item |
|---|---|
| Multi-instance deployments | Login throttling is in-process; move counters to the store or a shared cache. |
| Large tenants | CORS origin checks list all clients per cross-origin request; index origins. |
| Hosted login (spec §7) | Template override directory; bcrypt hash verification and upgrade for imported users. |

## Plan 2 deferred review findings

- Login throttle pruning is O(n) and in-process.
- Cap `password_policy.min_length`; a value over 256 makes signup impossible.
- No test that `Verify` rejects `alg=none` and HS256 tokens.
- CORS: negative-path tests and `Vary: Origin` are missing; OPTIONS/CORS are not in the OpenAPI contract.
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
- Revoke tests: the unknown-token case does not assert an empty body; no test for HTTP Basic or a JSON body; no `OPTIONS /oauth/revoke` CORS test.
- `/v2/logout` has no negative tests for a two-label wildcard, http against an https wildcard, a port, `//evil`, or a backslash host (all rejected today).
- Repeated query parameters on the logout endpoints get a JSON 400 from the generated wrapper rather than the HTML error page.
- A single `za_logout` confirmation cookie per browser means two tabs confirming at once fail closed.
- `idTokenHint` accepts any tenant-signed single-audience JWT, including an access token; harmless, but token type is not checked.
- The logout confirmation page has no "stay logged in" action.
- `/oidc/logout` tests do not cover a hint with multiple `aud` values, a GET carrying `confirm=yes`, or a confirmed POST after the session is gone.
- Flow test gaps: it does not check that logout leaves refresh tokens valid; it does not drive `/oidc/logout` through `server.New`; revoke asserts only the status code; there is an unchecked type assertion.
- E2E runner: failures in `npm ci` or esbuild exit before the logs are dumped; `spa-server` crashes when `E2E_REACT_BUNDLE` is unset; `next start` is wrapped by `npx`, so its process may be orphaned on cleanup.
- The nextjs E2E uses `AUTH0_DOMAIN=https://localhost:8443` with `allowInsecureRequests` because the SDK rejects a domain with a port or localhost; the documented production setup (port 443 with a real hostname) is not exercised.
- A code replayed mid-exchange without `offline_access` still returns the first exchange's access and ID tokens (JWTs are not revocable); the `ReplayedAt` re-check runs only when a refresh token is issued.
- The `server_error` branch for a failed `AuthCodes().Get` after the refresh token is stored has no test.

## Plan 4 follow-ups

- `PUT /prompts/{prompt}/custom-text/{language}` and `GET /prompts/{prompt}/custom-text/{language}` are planned for sub-project 3; storage is ready.
- RTL layout needs a visual review once an RTL catalog exists.
- Email templates must use the catalog in milestone 6.

## Plan 4 deferred review findings

- No tests for Accept-Language q ties, or for a key-specific variable (such as `${min}`) used in an override of a different key.
- `i18n.Enabled` returns the tenant's own `EnabledLocales` slice rather than a copy.
- `i18n.New` iterates custom-text languages in map order, so if duplicates that differ only by case ever bypassed validation, the winner would be arbitrary.
- Seed apply shares the parsed `CustomText` map with the stored tenant instead of copying it.
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
- Spaces around `q =` in Accept-Language are not tolerated.
- The password-policy alias (`signup.signup.password-policy-not-conformant`) is not variable-checked; a value made only of unknown variables renders an empty alert. Fall back to the specific key when the rendered alias is blank.
- The strict-key check for the `zeroauthy` prompt is case-sensitive, so `Zeroauthy`/`ZEROAUTHY` typos are accepted and ignored.

## Plan 5 follow-ups

- Email verification emails.
- MFA (`mfa_required`).
- Breached-password detection.
- The `organization` parameter on `change_password`.
- Move the `change_password` send limit into the store; it is per-process today, which multi-instance deployments need fixed.

## Plan 5 deferred review findings

- Access tokens issued before a reset stay valid until they expire (stateless JWT).
- A password grant that verified the old password just before a reset can still mint a refresh token after `RevokeByUser` (needs a store-level user version).
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
- Test nits: `TestAtomicRetry` sleeps through the real retry backoff; a stray `TestSchemaTables` doc comment sits in `internal/store/sqlstore/migrate_test.go`; the `LatestVersion` panic path is untested.

## Plan 7 follow-ups

- Automatic plugin restart with backoff; today a plugin crash fails storage calls until the server restarts.
- Binary checksum pinning for plugins (go-plugin `SecureConfig`).
- Plugin-side schema migration hooks (plugins are not `storage.Migrator`s).
- A reference plugin in a language other than Go.
- `pkg/storetest` does not pin the nil-versus-empty policy for list results (an empty list may come back as nil or as an empty slice, and the plugin path normalizes one way); decide the policy and pin it.
- A closed plugin client reports `context.Canceled` for calls made after `Close`; a dedicated "store closed" error would be clearer.
- Theoretical lost-`BeginTx`-response window: if the response is lost after the plugin registered the transaction, the host cannot name it, so it waits for the idle timer. Client-proposed transaction ids would close it; decide before protocol v1 is frozen.
- Route plugin logs through `slog` instead of go-plugin's stderr logger, so levels and format match the host.
- `storeplugin.Serve` reads the parent pid inside its watcher goroutine; read it synchronously before starting the goroutine so a host that dies during plugin startup is still detected.

## Plan 8 follow-ups

- Callers for the stored `verify`, `delete` and `change_email` scripts: `verify` needs verification emails; `delete` and `change_email` are called by the Management API (sub-project 3). The runner (`Executor.Execute`) can already execute any of the seven scripts; `customdb.Client` exposes only `Login`, `GetUser`, `Create` and `ChangePassword`.
- `mfa_factors` in profiles (MFA, sub-project 2).
- Custom signup prompt fields passed to `create` (changelog 2026-04-02, sub-project 2).
- Custom user IDs at signup (changelog 2026-09-17, early access).
- Passkeys on custom databases.
- Bcrypt hashes from bulk import.
- An egress allowlist for scripts. Network access is open; operators firewall it.
- Pinning the Node version through a config option; today any Node 22.13 or later is accepted.

## Plan 8 deferred review findings

- Import mode: a late first import login can overwrite a password hash that a concurrent reset completion just set, and then get a session after the reset revoked them; fixing it needs a store-level set-if-empty for the password hash. Two concurrent submits of one reset ticket can both run `change_password`.
- Import mode: the length check uses the normalized login while the script receives the trimmed form; `profileUser` reads the clock separately from `upsertProfile`; a comment in `importLogin` should say the script can still run for a migrated user reached through a changed login (the local hash wins).
- Legacy mode: usernames from a legacy store must match the local username pattern; a legacy sign-up that lands on a locally blocked user returns a bare `ErrUserBlocked` (a 500); a `ValidationError` with an empty message renders a doubled period.
- Scripts that hang or crash the runner are refunded: per tenant, up to 64 concurrent attempts per 20 s, immediately for a runner crash; cancelled requests are refunded while the script keeps running. Suggested fix: count cancellations and timeouts against the IP throttle only.
- Runner hardening left open (D-0022 addendum): Buffers are not bounded by `max_memory_mb`; `os.hostname`, `userInfo` and `networkInterfaces` are readable; per-process script caches and console output are unbounded and unthrottled; a script can forge response and log lines within its own tenant; the compile cache ignores the script name on the fallback path and fallback globals are shared; a last stderr line without a newline is dropped at EOF; `PDEATHSIG` is tied to the forking OS thread; a cancelled request holds its concurrency slot until the 20 s limit.
- The `require` denylist can be bypassed through `process.getBuiltinModule`; only `--permission` is a control, and it must not be described as one.
- Minors: the seed does not require `get_user`/`create`/`change_password` on legacy connections (runtime-only failure); store plugins built before proto fields 10-14/18 drop them (fails closed); `pkg/store.ScriptNames` is an exported mutable slice; script failures are logged twice; client disconnects are logged at Error.
- The seed re-seals the configuration and updates the connection on every apply, even when nothing changed.
- Test gaps: `Apply` with no wrapper plus a configuration (the error must not leak the value); exact boundary accepts (102400 bytes, 64 keys, 4096 bytes) and the config checks for an empty `node` and `idle_timeout <= 0`; `TestRunnerRequireAllowlist` accepts any error kind; `process._linkedBinding` is not probed by the isolation test; `TestImportConcurrentFirstLogin` does not assert that the conflict path ran; `TestLatestVersionIsTwo` hard-codes 2.
- Cosmetic: an overlong comment line in `store.proto`; the constant `maxConfigValueBy` should be `maxConfigValueBytes`; the comment on `TestRunnerEscapedContextStillIsolated` overstates what it proves; a last stderr line without a newline.
- E2E (m9): `LEGACY_PORT` is unused (8099 is hard-coded); the spec cannot be re-run against the same server; a missing legacy-store field prints "undefined"; the 409 check does not isolate the `get_user` path.

## Plan 9 follow-ups

- Organizations: `third_party_client_access` and consent per organization.
- `default_for: third_party_clients` default permissions, which arrive with dynamic client registration.
- `allow_all_scopes` and `authorization_details_types` on client grants.
- RBAC and its intersection with granted scopes.
- `/api/v2/grants` and `/api/v2/client-grants`, and revoking refresh tokens when a grant is deleted (sub-project 3).
- The `tpc_` client ID prefix for generated strict client IDs (sub-project 3).
- Device flow (`/activate`, which will reuse the consent page) and PAR, which strict clients reject (Plans 10 and 11).
- Auth0 stored a user grant for a first-party client after a login that showed no screen (observation check 1). zeroauthy stores grants only on accepted consent (D-0026); revisit once the grants Management API exists.
- Re-check the Management API defaults (O1) with a machine (client-credentials) login of auth0-cli; the observations used a user login.
- `scripts/test-sql.sh` binds fixed host ports (55432 for PostgreSQL, 53306 for MySQL), which collide with other local containers. Make the ports overridable (for example `ZEROAUTHY_TEST_PG_PORT` and `ZEROAUTHY_TEST_MYSQL_PORT`).

## Plan 9 deferred review findings

- Storage: `ClientGrants.Create` stores an empty `SubjectType` literally instead of normalizing it to `client` (the seed always sets it). `UserGrants.Upsert` inside an outer transaction cannot recover from a PostgreSQL unique violation (nothing calls it inside a transaction today). The MySQL `grant_key` column joins its parts with a newline, so identifiers containing newlines could collide. `TestMigration0003Defaults` does not check the tenant and connection defaults or the uniqueness constraint after migration.
- Plugin protocol: the server's `UserGrantsUpsert` passes a nil grant to the store when the request has no value; it should answer with a domain error. No test covers the server mapping an empty `subject_type` to `client` (a host from before Plan 9). The signing-keys section banner in `client_repos.go` lost its title.
- Seed: `TestApplyRefusesPartyChange` covers only first-party to third-party; a security-mode change, the reverse flip and re-applying a tenant flag are untested.
- Decision table (`internal/access`): no rows cover partial user-grant coverage, an empty `ThirdPartySecurityMode`, an unknown policy, a permissive client with a grant, client credentials under a stored `allow_all`, `prompt=none` with a screen shown, or empty scopes; the O4 expectations are derived from the constant rather than written as literals. `ShowErrorPage` redirects for an unknown `RedirectionPolicy` string (unreachable, because the seed validates it). `Decide` always passes `offline_access` through and relies on callers to gate it (`userScopes`, `offlineAllowed`); confirm this in a review of the token handlers.
- Hosted login: protected error pages are all titled "access denied"; map the error code to a title key. `TestThirdPartySessionOnNonDomainConnectionLogsInAgain` does not tell old logic from new, the protected-page tests do not assert the description, and no login test covers domain-connection resolution for a third-party client. `ConsentView` sets `Confirmation` when nothing at all is needed. The scope-merge test requests the same scope twice (weak), and there is no `max_age` re-check test for the consent page.
- Domain connections: `/dbconnections/signup`, `/dbconnections/change_password` and the password grant still check `enabled_clients` directly, so a third-party client on a domain connection is refused there. Auth0's behaviour is unknown; decide before the Management API.
- Consent page: a consent POST without a valid `action` is a generic failure that answers 500; it should be a 400 session-expired or invalid-request page. `postedFlow` now checks the CSRF token before the connection (an order change), and `TestConsentDeclineProtected`, `TestConsentWrongCookie` and the grant-absence check use weak assertions (any error passes).
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
- Store failures during `/authorize` request validation or `request_uri` resolution render a 400 error page; they should be 500. This applies to the existing non-redirectable server errors at `/authorize` too.
- `scripts/test-sql.sh` hardcodes host ports 55432 (PostgreSQL) and 53306 (MySQL), which collide with other local containers. Make them configurable (this repeats the Plan 9 item and is still open).

## Plan 11 follow-ups

- A sample Android TV app: the Android Studio TV emulator reaching zeroauthy at `10.0.2.2`, then a sideloaded Fire TV.
- `auth0-cli` as a device-flow client. It hardcodes `auth0.auth0.com`, its client ID and issuer, so testing it needs that host mapped to zeroauthy in a container with a trusted test certificate.
- Management API for `device_flow` (sub-project 3). Tenant log events `fdeaz`, `fdeac`, `fdecc`, `fede`, `sede`. Actions/Rules `oauth2-device-code` protocol.
- An Authentication API rate limiter covering `/oauth/device/code`, and throttle state shared across instances.
- Running `m10-device` with `E2E_IN_CONTAINER=1` (it needs podman on the host to start the .NET client).
- OpenID Foundation certification: a local dry run of the open-source OIDF conformance suite against zeroauthy (Basic OP, Config OP, Form Post OP and RP-initiated logout; not Implicit, Hybrid or Dynamic, which zeroauthy lacks), then a fee-waiver request to certification@oidf.org under https://openid.net/certification/open-source-project-certification-policy/ (decided case by case; maintainers must not be paid by an employer for the project). Any Auth0-copied behaviour that fails a spec test becomes a parity-versus-spec decision for the maintainer. Planned as its own plan after Plan 11.

## Plan 11 deferred review findings

- Storage: `DeviceCodes.Decide` does not validate `dec.Status` (callers pass only approved or denied). The memory driver looks user codes up by scanning. The SQL `Poll` returns full-precision times while the stored values are microseconds. No 4→5 upgrade test checks the new tenant columns' `''` default. The gRPC client does not validate a decoded `DeviceCode.status`, and no gRPC-level test covers `Decide` returning the record with `ErrAlreadyUsed` or an unknown poll outcome over the wire.
- User codes and seed: the default-mask logic in seed validation duplicates `devicecode.Settings`. A strict third-party device client gets several overlapping errors. `devicecode.Generate` silently uses base20 for an unknown charset. `devicecode.Normalize` keeps any Unicode letter or digit; restricting it to ASCII `A-Z0-9` would avoid surprises such as full-width digits or `ß` becoming `SS`.
- `/oauth/device/code`: a repeated `client_id` is recognised by matching `parseTokenRequest`'s error text (add a sentinel). Any `Authorization` header gives `403 unauthorized_client` (inferred, not observed). `TestDiscoveryDeviceEndpoint` only calls `TestDiscovery`. The stored `UserCodeHash` is only checked to differ from the plaintext. The no-default-audience branch is untested.
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
- `413` for oversized `POST /authorize` and `POST /userinfo` bodies (a 64 KB limit exists today; its error status should become 413).
- `run.sh` robustness: apply the expected-file filtering earlier (before the suite starts), and make the `PLANS` input safe against newlines.
