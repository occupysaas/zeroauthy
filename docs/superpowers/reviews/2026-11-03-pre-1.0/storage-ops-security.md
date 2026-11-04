# Storage, plugins, configuration, operations and security baseline review

## Summary
The storage layer is in good shape. The SQL drivers bind every value. Identifiers that get interpolated come from fixed lists, and metadata JSON paths are character-restricted (`internal/store/userquery.go:148`). Tenant-scoped queries filter on `tenant_id`, and tenant deletion covers every tenant table, either directly or through a cascade. Single-use tokens are consumed atomically: auth codes with a conditional UPDATE, refresh tokens with a `FOR UPDATE` lock and a revoke-until-stable pass. DSN and plugin-argument secrets never reach error text. The plugin child process gets a filtered environment, and secrets are scrubbed by key name at slog and at the tenant-log, log-stream and event-stream sinks.

Two 1.0 problems:
- **General Authentication API rate limiting does not exist.** The 1.0 scope lists it as must-ship.
- **The client-IP helper can be spoofed** behind proxies that add their own `X-Forwarded-For` header line. That lets an attacker bypass per-IP throttles and attack-protection allowlists.

`SECURITY.md` is also missing, and so is a test that upgrades a populated database from the oldest schema. Both are 1.0 scope items. There is no master-key rotation; that can defer if it is documented. `govulncheck` is not installed, so the dependency scan was **not run**.

Findings by severity: 0 critical, 2 high, 3 medium, 4 low. **Fix-before-1.0: 4** (F1, F2, F3, F5).

## Findings

### F1 [high] [parity-gap] No general Authentication API rate limiting; several counters are per process only
- Where: there is no limiter middleware in `internal/server/server.go` or `internal/app/app.go`. The throttles that exist are per feature: `internal/identity/throttle.go:15-17` ("It is in-process; each server instance counts separately"), the device throttles at `internal/app/app.go:430-433`, and the Try throttle at `internal/mgmt/system_scripts.go:76`. No code anywhere sets `X-RateLimit-*` headers.
- What: limits exist only for password login and the password grant (shared, Plan 19), signup per IP, social registration, passwordless start/OTP, change-password email and device activation. These have no limit at all:
  - `/oauth/token` for client_credentials, refresh_token and authorization_code
  - `/userinfo`
  - `/authorize`, which writes an `auth_transactions` row per request, so an attacker can grow storage without bound (PLAUSIBLE)
  - `/oauth/par`
  - `/oauth/device/code`
  - `/.well-known/jwks.json`
  - legacy client secrets, which are checked with argon2id at 19 MiB per attempt (`internal/oauth/clientauth.go:102`). That makes unauthenticated `/oauth/token` calls a cheap CPU and memory DoS on tenants that still have legacy secrets.
  
  The device-activation and script-Try counters are in-process, so with N replicas the limit is N times the configured value. The 1.0 scope (§2, "Security hardening") lists "General Authentication API rate limiting and shared counters" as must-ship. This review is not reporting a new problem: it records that the item is still entirely open.
- Evidence: Auth0's Free-tier rate-limit configuration (https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy/rate-limit-configurations/free-public) lists an overall Authentication API limit ("burst 300, sustained 300/minute") and per-endpoint limits: `/userinfo` 5/min per user ID, `/oauth/token` 30/sec, `/passwordless/start` 50/hr per IP, `/.well-known/jwks.json` 20/sec. The policy page says "Auth0 limits the number of requests to a specific API, regardless of the API endpoint" (https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy).
- Verdict: CONFIRMED (the limiter is absent). The `/authorize` storage-growth impact is PLAUSIBLE.
- Recommendation: fix-before-1.0 (Plan 45 subset, as the 1.0 scope already states).
- Suggested fix: add one store-backed token-bucket middleware with per-tenant and per-endpoint keys. Key `/userinfo` by `sub` and the other endpoints by IP or client. Return 429 `too_many_requests` with `X-RateLimit-Limit/Remaining/Reset`. Make the limits configurable, and move the device and Try throttles onto the same shared store. Do not reuse the attack-protection pattern of locking the tenant row (see F8).

### F2 [high] [defect] `ClientIP` reads only the first `X-Forwarded-For` header line, so throttles and allowlists can be spoofed
- Where: `internal/httpx/clientip.go:30` (`r.Header.Get("X-Forwarded-For")`). It feeds the attack-protection brute-force and suspicious-IP allowlists (`internal/protection/service.go:89,103`), every per-IP throttle, session IP and `last_ip`.
- What: `Header.Get` returns only the first field line. Some proxies, HAProxy `option forwardfor` among them, add a new `X-Forwarded-For` line instead of appending to the client's line. Behind such a proxy with `trust_proxy_headers: true`, the first line is the client's own header. The "rightmost entry" logic then picks a value the attacker chose. An attacker can name an allowlisted IP to skip brute-force protection, or rotate fake IPs to escape per-IP limits. Nothing checks that the value is an IP address, so arbitrary strings also become throttle keys. Nearby, `X-Forwarded-Host` takes the leftmost entry (`internal/customdomain/proxy.go`, `legacy`), which is client-controlled when a proxy appends rather than overwrites.
- Evidence: Go's `Header.Get` returns only the first value. RFC 9110 §5.3 says multiple field lines are equivalent to one comma-joined line. The function's own comment says the intent is "rightmost non-empty entry: that is the address the single trusted proxy appended".
- Verdict: CONFIRMED in code. Whether it can be exploited depends on how the operator's proxy writes the header.
- Recommendation: fix-before-1.0. It is a security bypass of attack protection on a core flow, and the fix is small.
- Suggested fix: join `r.Header.Values("X-Forwarded-For")` with commas before taking the rightmost entry. Ignore entries that do not parse as an IP and fall back to `RemoteAddr`. Add a two-line-header test.

### F3 [medium] [docs-drift] `SECURITY.md` and a disclosure contact are missing
- Where: repository root (no `SECURITY.md`).
- What: the 1.0 scope §2 requires "`SECURITY.md` with a disclosure contact". Press attention is expected (v1 urgency), so there needs to be a private reporting channel before the tag.
- Evidence: `ls SECURITY.md` → no such file.
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0
- Suggested fix: add `SECURITY.md` with a contact address or GitHub private advisory link, supported versions (1.0.x), a response target, and the scope (server versus console versus plugins).

### F4 [medium] [defect] No master-key rotation, and sealed blobs use two formats with no key identifier
- Where: `internal/keys/wrapper.go:20-41` (a single AES-GCM key, output `nonce||ct`) and `internal/keys/envelope.go:12-16` (a versioned envelope with a wrapped data key). Blobs wrapped directly under the master key: email-provider credentials (`internal/keys/emailprovider.go:17`), TOTP secrets (`internal/mfa/seal.go:22`), and TLS material (`internal/certificates/secrets.go:79`). Separately, `secrets.DeriveKey` derives purpose keys from the master key.
- What: the only way to replace a leaked master key is to start over. Nothing accepts an old key alongside a new one, and no command re-seals existing data. The envelope format (signing keys, client, action and module secrets) could rotate by re-wrapping its data keys. The direct-wrap blobs have no version or key-id byte, so a future rotation needs trial decryption or a format migration. And migrations cannot get at the master key (`Migrate(ctx)` takes no wrapper). Freezing "database upgrade paths" in the 1.0 promise freezes these formats.
- Evidence: the code above. A `rekey`/`rotate` search found no rotation code or docs. README §"Master key" says nothing about rotation or backups.
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-45. For 1.0, the deployment guide must say plainly that the master key cannot be rotated yet and must be backed up with the database.
- Suggested fix: add a one-byte format/key-id prefix to the direct-wrap blobs, and accept `security.previous_master_keys` for decryption. Then add a `zeroauthy rekey` command that re-seals everything under the new key.

### F5 [medium] [defect] No upgrade test from the oldest schema with data; most MySQL migrations cannot resume
- Where: `internal/store/sqlstore/migrate_test.go` has per-migration data tests for 0003, 0004, 0013, 0016, 0019 and signing, but no run from 0001 with populated data through 0034 on each dialect. In `internal/store/sqlstore/migrate.go:223-225`, only MySQL migrations 20, 21 and 29-34 are resumable. 1-19 and 22-28 commit DDL statement by statement, with no recovery.
- What: the 1.0 scope (Release) requires "migrations tested from a fresh database and from the oldest supported schema". Without that test, there is no evidence that a database created at 0001 (SQLite table rebuilds, MySQL index and collation changes, Go backfills at 20, 21 and 29) upgrades without loss. If a MySQL upgrade fails part-way through one of the non-resumable migrations, the operator has to clean up by hand. The README documents that, but it is the riskiest path for anyone upgrading an early MySQL install.
- Evidence: the code above, and README lines 299-301.
- Verdict: CONFIRMED (the test is absent). Data loss is not shown; it is untested.
- Recommendation: fix-before-1.0 (1.0 Release gate; Plan 46 core).
- Suggested fix: add a `storetest`-style upgrade test that migrates to 1, inserts representative rows, migrates to latest and asserts reads, for all three dialects in `scripts/test-sql.sh`. Either make the remaining MySQL migrations resumable, or state "back up before migrate" in the upgrade notes.

### F6 [low] [parity-gap] No `Strict-Transport-Security` header when zeroauthy terminates TLS
- Where: there is no HSTS anywhere in `internal/` (grep). Other security headers are set (`internal/server/admin.go:34-37`, `internal/ui/ui.go:437-442`).
- What: in direct-TLS and ACME modes, browsers are never told to pin HTTPS for the login and console hosts. Behind a reverse proxy, the proxy can add the header.
- Evidence: grep result. Auth0 sends HSTS on its domains (observed industry practice; I did not find a public Auth0 doc sentence for this). PLAUSIBLE as parity, CONFIRMED as absent.
- Verdict: CONFIRMED (absent)
- Recommendation: defer-to-Plan-45
- Suggested fix: set `Strict-Transport-Security: max-age=31536000` in the top-level handler when the request arrived over TLS. Make it configurable for operators using preload.

### F7 [low] [docs-drift] TLS to the database is opt-in and only the PostgreSQL example shows it
- Where: README storage table (lines 265-271) and `internal/store/sqlstore/sqlstore.go:139-165`.
- What: the PostgreSQL DSN goes to pgx unchanged, and pgx defaults to `sslmode=prefer`, which a network attacker can downgrade. The MySQL example has no `tls=` parameter and the driver defaults to plaintext. A first-time operator copying the MySQL example sends DB credentials and password hashes in the clear.
- Evidence: the code above (no default injected).
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-46 (deployment guide), and mention it in the 1.0 deployment guide.
- Suggested fix: add `?tls=true` to the MySQL example (or `preferred`, explained), and say "use `sslmode=verify-full` in production" for PostgreSQL.

### F8 [low] [defect] Attack-protection counters serialize every attempt on the tenant row
- Where: `internal/store/sqlstore/protection.go:30-36` (`SELECT 1 FROM tenants WHERE id=? FOR UPDATE` before loading buckets).
- What: this is correct, but every login, signup and passwordless admission in a tenant queues on one row lock, together with tenant updates. Under load or attack on PostgreSQL or MySQL, that becomes a per-tenant throughput ceiling and a lock-contention DoS against the whole tenant. It matters because F1's limiter must not copy the pattern.
- Evidence: the code above.
- Verdict: PLAUSIBLE (performance impact not measured)
- Recommendation: defer-to-Plan-45
- Suggested fix: lock bucket rows (`INSERT ... ON CONFLICT` / `SELECT ... FOR UPDATE` per bucket) instead of the tenant row, or shard the counters.

### F9 [low] [defect] Plugin log output bypasses logscrub
- Where: `pkg/storeplugin/storeplugin.go:108` (`fmt.Fprintf(os.Stderr, "... panic in %s: %v", ...)` on the plugin side) and `:178` (hclog to `os.Stderr` on the host).
- What: panic values and go-plugin log lines from a plugin reach stderr without the key-name scrub. A panic carrying a request value (a token hash or a sealed blob) would be logged as-is. This is related to the known follow-up "Route plugin logs through slog". That follow-up does not mention the scrub, which is why this is listed.
- Evidence: the code above, and the maintainer rule "secrets never in logs (key-name scrub at every sink)".
- Verdict: PLAUSIBLE (no secret-bearing panic found)
- Recommendation: defer-to-Plan-45
- Suggested fix: send the hclog output through an adapter into the host's scrubbed `slog`, and log only the method name and panic type.

## Other checks (no finding)
- **SQL injection**: `Sprintf` is never used to build SQL. Dynamic fragments are placeholders, fixed column or table lists, `identityKeys` map values, or JSON paths whose keys refuse `"`, `\` and control characters. Offset and limit are integers.
- **Tenant scoping**: every query on a tenant table filters `tenant_id` or uses a globally unique hash key (`proof_hash`, `asset_key`). `operators.Delete` clears `email_notifications` by `subject_id` across tenants for preview/test purposes only (`operators.go:97`). That appears deliberate, since operators preview mail for other tenants. A script compared `tenantTables` with every `CREATE TABLE ... tenant_id`; the 11 tables missing from the list are all removed by FK cascade, by `removeTLSAssets`, or are the transient `client_grants_new`.
- **Timeouts and limits**: `ReadHeaderTimeout` 10s, `ReadTimeout`/`WriteTimeout` 30s, `IdleTimeout` 120s (`internal/app/app.go:492-499`). The SSE and event-delivery handlers extend deadlines through `ResponseController`. JSON bodies are capped with `MaxBytesReader`, and imports are capped at 512000 bytes. `MaxHeaderBytes` is the Go default (1 MiB): acceptable.
- **TLS**: the ACME `TLSConfig` sets `MinVersion` TLS 1.2. Static-certificate mode uses Go 1.26 defaults (TLS 1.2 minimum).
- **Cookies**: every `http.Cookie` sets `HttpOnly` and `Secure`, with an explicit `SameSite` that matches each cookie's role.
- **Master key**: required for every non-memory DSN, including `plugin://` (`internal/app/app.go:145-160`). The base64 key must decode to 32 bytes, and setting both `master_key` and `master_key_file` is rejected. Plugin and Node child processes do not inherit `ZEROAUTHY_*` or the server's environment.
- **Log scrubbing**: `logscrub.Handler` wraps the app logger (`app.go:96`), the logs recorder and purger, and the client handlers. Tenant logs, log streams, event streams, Actions and custom-DB output are scrubbed. Storage-open errors never quote the DSN, which is tested in `internal/storage/redact_test.go`.
- **Dependency vulnerabilities**: `govulncheck` is not installed, so this was not run. Go is 1.26.7. Run `govulncheck ./...` in CI before tagging.

## What a 1.0 stability promise must freeze
- **Configuration**: every `koanf` key in `internal/config/config.go` and the `ZEROAUTHY_` + `__` environment mapping. Unknown keys fail startup (`ErrorUnused`), so 1.x can never remove or rename a key: deprecated keys must stay accepted with a warning. Exclude `ZA_TEST_MODE`/`ZA_TEST_PHONE_ENDPOINTS` (test-only) and anything marked deprecated (`trust_proxy_headers` without CIDRs).
- **DSN grammar**: the `memory|sqlite|postgres(ql)|mysql|plugin` schemes, the `plugin:///abs?arg=` form, and the pragmas and session variables the SQL drivers force.
- **Plugin protocol**: the `proto/store/v1` package (373 RPCs), handshake `ProtocolVersion 1` / cookie `5b0f7c1e-store-v1`, the per-feature `*Capabilities` version RPCs, and the rule that a missing RPC means 501 or fail-closed. Settle the open "client-proposed transaction ids" question from the Plan 7 follow-ups **before** the freeze, because changing it later breaks v1.
- **Database**: forward-only numbered migrations, with no down-migrations (rollback = restore a backup; say so in the upgrade notes). The refusal to start on a newer schema. Tested upgrade from 0001 (F5).
- **Sealed-data formats**: envelope v1 plus the raw wrapped blobs (F4). Either add version prefixes before 1.0, or promise only that future versions will read the current format.
- **Not covered**: console UI, internal Go packages, `pkg/storetest` internals, and log line formats.

## Changelog entries reviewed
Last reviewed through 2026-10-26 (`docs/compat/changelog-review.md`). Newer entries:
- 2026-10-27 — Universal Portals (Developer Preview) — not relevant to this area.
- 2026-10-29 — HTTP Message Signatures added to Tenant Network ACLs — relevant to security. zeroauthy has no Tenant ACL feature. Deferred: new plan, or Plan 45 scope ("Tenant ACL rules including HTTP message signature conditions").
- 2026-10-30 — MFA: exponential backoff for phone MFA SMS delivery — relevant to rate limits, but owned by Plan 34 (phone/MFA reviewer). Not covered here.

## Roadmap suggestions
- Plan 45: add master-key rotation (`previous_master_keys` plus a `rekey` command and versioned direct-wrap blobs, F4), HSTS (F6), per-bucket locking for protection counters (F8), plugin log scrub routing (F9), and Tenant ACL / HTTP message signatures (changelog 2026-10-29) or a new plan for them.
- Pull these out of Plan 45 into a "1.0 security gate" slice, so they don't wait for the full sweep: the F1 limiter with shared device and Try counters, the F2 XFF fix, `SECURITY.md` (F3) and a `govulncheck` CI step.
- Plan 46: the oldest-schema upgrade test across three dialects (F5), "back up before migrate / rollback = restore" notes, finishing or documenting the remaining non-resumable MySQL migrations, deployment-guide DB TLS guidance (F7), and a documented stability-promise page (section above).
