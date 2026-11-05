# Plan 33b implementation record — passkeys and WebAuthn MFA

Plan: `docs/superpowers/plans/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn.md`.
Spec: `docs/superpowers/specs/2026-11-05-zeroauthy-passkeys-webauthn-design.md`.
Executor: inline (maintainer chose native execution, 2026-11-05). Branch
`plan-33b-passkeys`, worktree `/mnt/nvme2/code/zeroauthy-plan33b`, from main
`42c1258`.

## Task 1: Contracts, decisions and the virtual-authenticator spike

- `internal/webauthnrules` freezes rules (with source URLs), screens, text
  keys, log detail fields and `Limits`. Ten log codes now name owner Plan 33b;
  `gd_auth_rejected` is `not_planned`. Actions MFA members list the factors
  they accept, including `webauthn-roaming` and `webauthn-platform`. Branding
  gains the two `reset-password-mfa-webauthn-*-challenge` screens.
- D-0062, changelog review (coverage 2026-10-30), matrix row, follow-ups
  W1–W12, roadmap (Plan 40 loses the first-factor methods, K11).
- Playwright `testMatch` now matches `m33b-*` specs.
- Spike: `ignoreHTTPSErrors` alone is enough for create, button get and
  conditional get with the CDP virtual authenticator.
- Rulings: no source re-fetch (one-day-old research); API YAML route
  additions move to Tasks 14/15 (generated interfaces would break the build).

## Task 7: RP IDs, origin policy and passkey prerequisites

- Snapshot: worktree `/mnt/nvme2/code/zeroauthy-plan33b`, branch
  `plan-33b-passkeys`, starting commit
  `77708b260a00003a5d7532d75f7594acc5ba9ca8`. Preserved and finished the
  existing untracked RP ID resolver, resolver tests and connection-policy
  tests. Included the existing Task 6 wrapper capability regression test;
  its production methods were already committed.
- Added the per-request RP ID resolver, canonical/custom/operator host
  classification, strict shared-host restriction and exact native-origin
  allowlist. Hosts lose case, trailing DNS dot and port for the RP ID;
  origins retain the request port. Inactive bindings and invalid stored
  values fail closed with one WARN containing tenant and host.
- Added `connrules.Passkeys` and operator-only prerequisites route, including
  target-tenant checks for both signed and persisted operator grants.
  Added the deployment setting and regenerated `docs/configuration.md`.
  Management custom-domain POST/PATCH and seeded alias RP IDs use R1.
  The application passes the deployment setting to both paths.
- Seed `domains` accepts strings and `{host, relying_party_identifier}`.
  Existing Go `[]string` callers remain compatible; YAML objects are
  normalized before strict decoding and their overrides persist separately
  in `Tenant.DomainRPIDs`. Omitted domains and create-only mode retain
  overrides; explicit string domains remove overrides.
- Ruling: validate seeded overrides after all aliases in the transaction
  have been reconciled, so a later tenant participates in R1. Cost if wrong:
  a seed transaction fails before commit rather than allowing an ambiguous
  shared RP ID.
- Ruling: a create-time null custom-domain RP ID falls back to the domain,
  as specified in §3.2; removed the older test that forbade null. PATCH null
  validates the resulting full-domain RP ID too. Cost if wrong: callers may
  use null in POST where earlier zeroauthy releases rejected it.
- Ruling: native `web_origins` entries must already be serialized HTTPS
  origins; userinfo, paths (including `/`), queries, fragments, malformed
  ports and unnormalized DNS names are rejected rather than rewritten.
  Android fingerprints must have 32 colon-separated hex bytes. Cost if
  wrong: an incorrectly formatted client configuration needs correction.
- Ruling: extend the Tasks 4/5 `HostTenantsUnder` contract to compare the
  hostname without an operator alias's port. Memory and SQL implementations
  now do so; SQL retains literal SUBSTR matching instead of LIKE. This
  closes the demonstrated strict-policy bypass. Cost if wrong: none for
  DNS bindings; privileged aliases with ports now participate in R1.
- Ruling: failure to read the strict host ownership registry, including
  unavailable WebAuthn storage, propagates as an error rather than accepting
  the RP ID. Cost if wrong: strict-policy writes need a capable store.
- TDD: initial focused run failed on missing policy/config/seed APIs.
  Concrete red tests then demonstrated permissive non-origin URLs, inactive
  custom bindings, missing target-tenant authorization, create-null refusal,
  strict PATCH-null bypass, ignored host ports in memory and SQLite, and
  ignored strict-registry unavailability. The final focused run passed.
- Verification (all Go commands set `GOTOOLCHAIN=go1.26.10`, `TMPDIR` and
  `GOTMPDIR=/mnt/nvme2/tmp/plan33b-task7`):
  - `go generate ./internal/config`: exit 0.
  - `go test ./internal/rpid ./internal/connrules ./internal/config
    ./internal/customdomain ./internal/mgmt ./internal/seed ./internal/server
    -run 'RPID|NativeOrigins|PasskeyPolicy|PasskeyPrereq|WebAuthnRestrict|Reference|Domain'
    -count=1`: exit 0, all seven packages passed.
  - `go test ./internal/store/memory ./internal/store/grpcstore
    -run '^TestConformance$/^WebAuthn$/^HostTenantsUnder' -count=1`:
    exit 0, both packages passed.
  - `./scripts/test-sql.sh -v -timeout=15m ./internal/store/sqlstore
    -run '^TestConformance$/.*/^WebAuthn$/^HostTenantsUnder'`: exit 0;
    both host-ownership subtests passed on PostgreSQL, MySQL and SQLite
    with `-race` (six leaf subtests; SQL package 8.128s).
  - Focused seed parser, transaction and retry regressions: exit 0.
    Wrapper capability regression: exit 0. Application compile with
    `go test ./internal/app -run '^$' -count=1`: exit 0; no tests selected.
  - `git diff --check`: exit 0.
- An initial SQL command contained a space in its selector and selected no
  tests (exit 0); it is not counted as validation. The corrected verbose
  command above proved all six subtests ran. The initial mixed memory/SQL
  red command also selected no SQL tests; a separate SQLite red run proved
  the database regression before the SQL fix.
- No full regression suite ran; Task 19 owns it. No tests were skipped in
  the selected successful runs. Detailed commands, failure history and logs:
  `.superpowers/sdd/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn/task-7-report.md`.
  One implementer monitored each command; no additional agents were spawned.
