# Plan 1 follow-ups

Deferred findings from the Plan 1 reviews (2026-10-13). Items under
"Prerequisites" must be resolved before the named milestone starts.

## Prerequisites

| Before | Item |
|---|---|
| Management API (sub-project 3) | Tenants created at runtime need `keys.Manager.Ensure`; domains must be normalized with `tenant.NormalizeHost` and must not fall under `server.base_domain`. |
| Management API (sub-project 3) | Use a pinned auth0-cli as a black-box E2E client against zeroauthy only (CLEAN_ROOM.md: open-source tools as black-box clients). Never run it against live Auth0 to diff behaviour; Management API observation of a real tenant stays under the firewalled observation rules. |

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

- A late `login` script result can overwrite a password hash that a concurrent reset completion just set; fixing it needs a store-level set-if-empty.
- Import mode: the length check uses the normalized login while the script receives the trimmed form; `profileUser` reads the clock separately from `upsertProfile`; a comment in `importLogin` should say the script can still run for a migrated user reached through a changed login (the local hash wins).
- Legacy mode: usernames from a legacy store must match the local username pattern; a legacy sign-up that lands on a locally blocked user returns a bare `ErrUserBlocked` (a 500); a `ValidationError` with an empty message renders a doubled period.
- `scriptErr` treats unknown error types as "unavailable" (refunded), which fails open for future error types; consider defaulting to "raised". Scripts that hang or crash the runner are also refunded, so guessing is bounded but unthrottled at about one attempt per 20 s per connection.
- Runner hardening left open (D-0022 addendum): Buffers are not bounded by `max_memory_mb`; `os.hostname`, `userInfo` and `networkInterfaces` are readable; per-process script caches and console output are unbounded and unthrottled; a script can forge response and log lines within its own tenant; the compile cache ignores the script name on the fallback path and fallback globals are shared; a last stderr line without a newline is dropped at EOF; `PDEATHSIG` is tied to the forking OS thread; a cancelled request holds its concurrency slot until the 20 s limit.
- The `require` denylist can be bypassed through `process.getBuiltinModule`; only `--permission` is a control, and it must not be described as one.
- The seed re-seals the configuration and updates the connection on every apply, even when nothing changed.
- Test gaps: `Apply` with no wrapper plus a configuration (the error must not leak the value); exact boundary accepts (102400 bytes, 64 keys, 4096 bytes) and the config checks for an empty `node` and `idle_timeout <= 0`; `TestRunnerRequireAllowlist` accepts any error kind; `process._linkedBinding` is not probed by the isolation test; `TestImportConcurrentFirstLogin` does not assert that the conflict path ran; `TestLatestVersionIsTwo` hard-codes 2.
- Cosmetic: an overlong comment line in `store.proto`; the constant `maxConfigValueBy` should be `maxConfigValueBytes`; the comment on `TestRunnerEscapedContextStillIsolated` overstates what it proves; a last stderr line without a newline.
- E2E (m9): `LEGACY_PORT` is unused (8099 is hard-coded); the spec cannot be re-run against the same server; a missing legacy-store field prints "undefined"; the 409 check does not isolate the `get_user` path.
