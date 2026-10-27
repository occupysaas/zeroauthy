# Plan 25 implementation record

Microsoft personal and work/school account sign-in, with retained Google
account coverage. Implemented on `plan-25-email-account-connections`;
baseline `12400ea`. This record lists observed results, not prospective checks.

| Task | State / evidence |
|---|---|
| 1 inventory | Complete, reviewed; inventory missing-file RED then GREEN. Explicit SDK/local identity deviations and retrieval limitations recorded. |
| 2 configuration | Complete, reviewed; Microsoft API/seed/config and predecessor memory selections PASS; `go build ./...` PASS; generation twice stable. |
| 3 metadata/keys | Complete, reviewed; Microsoft discovery/key and predecessor OIDC/Google/OAuth/transport focused race selection PASS (6.610s). Generic raw/escaped issuer-template rejection RED→GREEN. |
| 4 adapters | Complete, reviewed; Microsoft Adapter/Claims/Profile/Discovery/SigningKey, Google personas and predecessor focused race selection PASS (10.217s). Raw x5c and malformed azp checks strengthened with regression tests. |
| 5 storage/import | Complete, reviewed after restoring Task 4 profile/claims tests overwritten by an interrupted worker; focused restored tests PASS (2.248s). Memory/gRPC conformance PASS (gRPC 76.147s, includes SQLite); three-dialect SQL race script exit 0 (554.785s). Generation twice stable. |
| 6 shared browser/application gates | Complete (`b8ec415`, `8b9d320`). Its per-task focused log was not retained; evidence is the whole-branch verification below. Whole-branch run found a test-only import cycle introduced by `8b9d320` (`authz` tests → `seed` → `federation` → `authz`); fixed in `88332dd` by sharing the device-flow transaction keys from `store`. |
| 7 console | Complete (`cf6f72c`). `make console` exit 0 (Vitest and production build) in final verification. |
| 8 browser/SDK/CLI/Deploy CLI | Complete (`b5f1fe4`). `make e2e-email-accounts` exit 0: 14/14 Chromium cases (nine personas first+repeat: Microsoft work, school, no-email, any-organization work, Outlook, Hotmail; Gmail, Workspace, non-Gmail; tenant mismatch; key-issuer mismatch; denial; disable and secret rotation during an attempt; custom-domain callback), node-auth0 7.4.0 setup/verify (nine distinct identities, no merges, scoped token projection) and auth0-cli 1.37.0 CRUD/filter/enablement/redaction. `make e2e-deploy` exit 0 for all four cells (YAML/directory × generated/preserved): `connections` 6/6 source/target over all five federated strategies; missing-credential staging and an un-injected import both rejected; 12 post-import provider logins per cell (first and repeat) with canonical identities keyed by migrated connection names. `make e2e-social` exit 0 (6/6). Unit: `TestFederationSecretReinjection`, inline/materialized OAuth script handling and federation comparator negatives pass. |
| 9 final regression and documentation | Complete; results below. |

Defects found and fixed during Task 8/9 (each with a regression test or lane):

- Explicit `/authorize?connection=<federated>` showed the identifier page when
  the tenant enabled identifier-first (transaction starts at the `identifier`
  step). Found by the Deploy CLI login lane, whose prompts fixture enables
  identifier-first. RED/GREEN in `TestSocialIdentifierFirst`; commit `6ea19d1`.
- `windowslive` `strategy_version` was rejected by the shared database-option
  gate before Microsoft rules ran
  (`TestMicrosoftPersonalStrategyVersionThroughConnectionRules`).
- Deploy export validation treated inline `fetchUserProfile` JavaScript as a
  file path (key contains "file").
- The gRPC client's Microsoft pre-check surfaced raw `Unimplemented` from
  plugins without `ConnectionsGet` instead of `ErrFederationUnavailable`
  (`TestOldPluginFederationUnavailable`, a Plan 24 test that regressed in Task 5).

## Final verification (2026-10-27)

| Command | Result |
|---|---|
| `go generate ./...` twice | Stable; no diff between runs |
| `make check-sources` | exit 0 |
| `go vet ./...` | exit 0 (after the import-cycle fix; it failed before) |
| `go test -race -timeout=30m ./...` | exit 0, 66 packages ok (after both fixes; first run had the two failures above). Includes SQLite-backed store/gRPC packages. |
| `./scripts/test-sql.sh ./internal/store/sqlstore/...` | Not rerun: no SQL store code changed after Task 5's three-dialect run (exit 0). PostgreSQL/MySQL evidence is Task 5's. |
| `make console` | exit 0 |
| `make e2e` | exit 0; Playwright 24 passed, 29 skipped (lane-gated specs run by their own targets) |
| `make e2e-email-accounts` | exit 0 (rerun after fixes) |
| `make e2e-social` | exit 0 |
| `make e2e-deploy` | exit 0, four cells |
| `make e2e-domains` | exit 0 |
| `tests/conformance/run.sh` | exit 0, no failures (not a certification claim). basic 35: 21 passed, 6 warning, 4 review, 4 skipped; config 1: 1 passed; formpost 35: 21 passed, 6 warning, 4 review, 4 skipped; RP-initiated logout 11: 3 passed, 8 review |

Review Focus outcomes: (1) distinct identities across tenants and
consumer/key-issuer denial — adapter/claims unit tests plus browser
tenant-mismatch and key-mismatch cases; (2) missing email / email-shaped
`preferred_username` — no-email persona succeeds with no invented email or
verification and no merge; (3) multitenant connection is not pinned —
`TestMicrosoftFlow` sequential organizations; (4) legacy identities —
read-only preflight tests; no automatic conversion; (5) Deploy CLI credential
or script loss fails — staging and import rejections in all four cells.


Live Microsoft, Google and Auth0 observations: **not run**. No fixture result
is represented as live account evidence.

Decisions made during implementation:

- Use an in-place feature branch to preserve approved documents/dependencies.
- Retain Microsoft JWK issuer beside its JOSE key using an internal selector;
  enforce it after signature verification.
- Keep historical migration 0021 behavior limited to the three Plan 24
  providers, even though shared identity resolution now recognizes Microsoft.
- Add an additive federation-unavailable protobuf error kind so capability
  denial survives the plugin boundary.
- Existing bulk imports discarded `identities`. Extend database-destination
  imports with bounded canonical secondary federated identities, preserving
  password/destination rules, rejecting ownership conflicts and identity-set
  changes on upsert. Federated bulk destinations remain unsupported.

Open minor from Task 2 review: domain-isolation OAuth2/OIDC test baselines
were invalid independently of forbidden domain options. Production rejection
is correct; valid-baseline regression assertions remain to be improved.
