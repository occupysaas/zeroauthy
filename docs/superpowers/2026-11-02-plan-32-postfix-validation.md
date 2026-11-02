# Plan 32 post-fix validation evidence

The fresh required twelve-command matrix completed with exit 0 on `474cf753f46d1e620020ba26fac160e93aa516d8`. Every command ran once, sequentially, against the same clean tracked source. Full Go explicitly used `-count=1`; no Go package result came from the test cache. This report records execution evidence. Task 14 completion, final integration and merge remain the controller's gate; no commit was made by the monitor.

## Snapshot and protocol

Worktree `/mnt/nvme2/code/zeroauthy-plan32`, branch `implement-plan-32`; tree `0ea79da3e38316d0489de60e7afc66d4cf6498e9`. Tracked-file manifest SHA-256 `07b591538b010476311d838a56640c5bfa3ea2893d82a3e70675e9ff3380440f` was identical before and after all twelve commands. Each of the 24 snapshots records clean status and fixed HEAD; each stage has before/after tracked-file maps, binary patches and command metadata. Generation and console build produced no tracked drift. Reports were written only after the sequence completed. Ignored local `node_modules` dependency directories were retained and were not committed.

The prior matrix at `82b00df73b1ff2d37e06d076dae77b02fab81b75` remains baseline evidence only. Its 82 cached Go package outcomes are not attributed to this run. The original artifacts in `/tmp/zeroauthy-plan32-validation-wco4isyf` were not changed. The accepted I1–I3 fixes are committed in this run's fixed HEAD; the scoped re-review approved advancing to this validation.

One designated sole monitor used durable supervisor PID `25310`, retained tool session `48315` (final exit 0), `supervisor.py`, `state.json` and `events.jsonl` in private root `/tmp/zeroauthy-plan32-postfix-z__an_zq` (0700). Each child was started once and waited to completion; no quiet suite was rerun, no other agent polled the process/logs and waiting was not filled with review or audits. Commands, child PIDs, fractional UTC start/end times, environments and actual exits are in each `command.json`. The supervisor stopped on nonzero exit or source drift; neither occurred.

Command environment: `GOTOOLCHAIN=go1.26.7 ZA_REQUIRE_NODE=1 E2E_KEEP_WORK=1 AUTH0_CLI_ANALYTICS=false NO_COLOR=1`. Verified `go version go1.26.7 linux/amd64` and Node `v26.8.1` (>=22.13). Repository dependency pins remained unchanged. SQL used free ports `ZEROAUTHY_TEST_PG_PORT=45761 ZEROAUTHY_TEST_MYSQL_PORT=57937`; its script adds `-race -count=1`. The controller authorized `-timeout=90m` because historical full SQL race exceeded the plan's former 30m; actual completion was 55m45s without timeout.

All table timestamps are UTC on **2026-11-02**. Each artifact directory is relative to the private root above; its `output.log` is exact combined stdout/stderr.

| Artifact directory | Exact command | Start–end UTC | Duration | Exit |
| --- | --- | --- | --- | --- |
| `01-go-race` | `go test -json -race -count=1 -timeout=50m ./...` | 03:32:13–04:08:57 | 2204.463s | 0 |
| `02-sql-race` | `./scripts/test-sql.sh -json -timeout=90m ./internal/store/sqlstore/...` | 04:08:58–05:04:43 | 3344.914s | 0 |
| `03-console` | `make console` | 05:04:44–05:05:23 | 39.927s | 0 |
| `04-check-sources` | `make check-sources` | 05:05:24–05:06:35 | 71.409s | 0 |
| `05-e2e-events` | `make e2e-events` | 05:06:35–05:08:19 | 103.788s | 0 |
| `06-e2e` | `make e2e` | 05:08:20–05:10:14 | 114.421s | 0 |
| `07-e2e-logs` | `make e2e-logs` | 05:10:15–05:10:36 | 21.320s | 0 |
| `08-e2e-actions` | `make e2e-actions` | 05:10:36–05:10:48 | 11.385s | 0 |
| `09-e2e-actions-ii` | `make e2e-actions-ii` | 05:10:48–05:11:29 | 41.142s | 0 |
| `10-e2e-organizations-ii` | `make e2e-organizations-ii` | 05:11:29–05:11:39 | 9.484s | 0 |
| `11-e2e-deploy` | `make e2e-deploy` | 05:11:39–05:30:06 | 1107.060s | 0 |
| `12-conformance` | `make conformance` | 05:30:06–05:32:29 | 142.430s | 0 |

## Go and SQL actual outcomes

**Fresh full Go race:** 83 tested packages passed; 11,070 passing test/subtest outcomes, including **9,798 passing leaf executions**, four actual skipped leaves, zero failed tests or packages. Twenty-four packages had no test files and are recorded separately, including the ignored local `console/node_modules/flatted/golang/pkg/flatted` package selected by Go's traversal. Zero cached-package outputs were present; `-count=1` forced execution. Test-node totals include parent/subtest outcomes and must not be read as unique leaf counts.

The permanent I1/I2/I3 regressions actually executed in the full run: issued-empty-cursor resume and configured seed quota passed; `TestSlowTestResponseWithinServerTimeout` passed in 47.78s with the real four-attempt HTTP path. The full run also selected gRPC floor/capability, transaction/ring and cancellation coverage. The dedicated SQL command below exercised all three real SQL drivers, including the new migration.

Actual full-Go skipped leaves (exact reasons/output retained in `01-go-race/summary.json`):

- `github.com/zeroauthy/zeroauthy/tests/e2e/deploy-cli.TestE2EPrivateEmailProviderCredentialAfterImport`: email_secret_test.go:20: only runs from the isolated Plan 21 deploy lane
- `github.com/zeroauthy/zeroauthy/tests/e2e/deploy-cli.TestE2EPrivateLogStreamSecretsAfterImport`: log_stream_secret_test.go:21: only runs in isolated deploy CLI lane
- `github.com/zeroauthy/zeroauthy/pkg/storeplugin.TestConformanceThroughPluginProcess/Organizations/Limits`: organizations.go:748: store cannot override Organizations limits
- `github.com/zeroauthy/zeroauthy/internal/store/grpcstore.TestOrganizationsPluginRoundTrip/Organizations/Limits`: organizations.go:748: store cannot override Organizations limits

**Dedicated uncached full SQL race:** one package passed, **3,167 passing test/subtest outcomes / 2,816 passing leaves**, zero failures and **zero skips**. SQLite, PostgreSQL and MySQL each ran and passed. The three `TestConformance` backend parents passed in 1484.83s, 150.69s and 601.80s respectively. `TestEventsWatermarkUpgradeFrom31` passed on SQLite/PostgreSQL/MySQL (6.17s/0.61s/2.87s), and actual MySQL `TestEventsWatermarkMySQLResume32/mysql` passed (1.47s). No backend was substituted or reported as passing from an absent driver. `02-sql-race/test-results.json` preserves all backend tests; `summary.json` includes every backend-parent result, no cached outputs and no skips.

## Console and local acceptance

| Command | Actual selected results |
| --- | --- |
| `make console` | API type generation, lint, typecheck, 75 test files / 604 tests and production build completed. No tracked build change. Existing >500 kB bundle-size advisory remains. |
| `make check-sources` | Both API source-link checks exited 0; no failure waived or rerun. |
| `make e2e-events` | Browser 1 passed / 0 skipped; SDK 7.4.0 CRUD/test/deliveries/get/single+batch redelivery, pinned CLI, SSE resume, retries and privacy acceptance completed. |
| `make e2e` | Baseline SDK/CLI completed; browser 24 passed / **57 lane-gated skipped**, zero failed. Exact skip names retained below and in `06-e2e/browser-skips.json`. |
| `make e2e-logs` | Browser 1 passed / 0 skipped; SDK/CLI local logging acceptance completed. |
| `make e2e-actions` | Browser 5 passed / 0 skipped; SDK/CLI Actions lane completed. |
| `make e2e-actions-ii` | Browser 4 passed / 0 skipped; all ten SDK module operations and CLI new-trigger/module operations completed. |
| `make e2e-organizations-ii` | Browser 6 passed / 0 skipped; SDK invitation/application/discovery/search, CLI invitations and 48 real M2M configurations plus six omitted-organization requests completed. |
| `make e2e-deploy` | All four final local cells: YAML/directory × generated/preserved. Each passed import/repeat/credentials/update/target-only/runtime; required negative checks detected failures. |

Events privacy scanner checked **12 artifacts / 543,976 bytes** and found the actual source hash/token and representative password/upstream/webhook/Action secret markers absent, including common encodings. The event-specific table/receiver/console/log artifact scope remains the implemented fixture scope: protected source credential storage is a positive control, not a claim that every raw database field is empty. The browser acceptance used production app/SQLite and local HTTPS; it does not establish four-store browser coverage. No Auth0 tenant observation or real upstream provider exchange was performed.

Every Deploy cell reported Plan 32 webhook/Action public configuration, strict field-loss negatives, Action ownership, fresh credential reinjection, explicit token rotation, omitted-secret CLI import and actual runtime delivery passed; `eventStreams` source/target counts were 2/2 each time. Existing tool limits were reported: databases excluded; attackProtection/phone-provider-protection unavailable; x-azure-clientip/empty-header CLI rejection; ACUL excluded. The upstream observer lane was unavailable because no observer credentials were supplied; no upstream call was made. These limits are not passes.

## Conformance actual module outcomes

The local pinned OpenID conformance suite (`release-v5.3.3`, existing container harness) returned exit 0, with **82 actual module rows: 46 PASSED, 0 FAILED, 12 WARNING, 16 REVIEW, 8 SKIPPED**. Warnings, review results and skips are not passes. The runner's separate “ran” bookkeeping totals are not substituted for actual module rows. All full module names/configurations/IDs/outcomes and emitted warning-condition details are preserved in `12-conformance/module-results.json`; exported ZIPs and runner/server/application logs are copied into `12-conformance/exported-results`.

| Plan | Passed | Failed | Warning | Review | Skipped |
| --- | --- | --- | --- | --- | --- |
| oidcc-basic-certification-test-plan | 21 | 0 | 6 | 4 | 4 |
| oidcc-config-certification-test-plan | 1 | 0 | 0 | 0 | 0 |
| oidcc-formpost-basic-certification-test-plan | 21 | 0 | 6 | 4 | 4 |
| oidcc-rp-initiated-logout-certification-test-plan | 3 | 0 | 0 | 8 | 0 |

Non-passing actual module names (full response-mode configuration retained):

- **WARNING** `oidcc-scope-profile[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **WARNING** `oidcc-scope-email[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **SKIPPED** `oidcc-scope-address[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **SKIPPED** `oidcc-scope-phone[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **SKIPPED** `oidcc-scope-all[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **WARNING** `oidcc-alternate-happy-flow[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **REVIEW** `oidcc-prompt-login[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **REVIEW** `oidcc-max-age-1[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **WARNING** `oidcc-ensure-request-with-acr-values-succeeds[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **WARNING** `oidcc-codereuse-30seconds[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **REVIEW** `oidcc-ensure-registered-redirect-uri[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **SKIPPED** `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **WARNING** `oidcc-claims-essential[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **REVIEW** `oidcc-ensure-request-object-with-redirect-uri[client_auth_type=client_secret_basic][response_mode=default][response_type=code]` (oidcc-basic-certification-test-plan).
- **WARNING** `oidcc-scope-profile[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **WARNING** `oidcc-scope-email[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **SKIPPED** `oidcc-scope-address[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **SKIPPED** `oidcc-scope-phone[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **SKIPPED** `oidcc-scope-all[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **WARNING** `oidcc-alternate-happy-flow[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **REVIEW** `oidcc-prompt-login[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **REVIEW** `oidcc-max-age-1[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **WARNING** `oidcc-ensure-request-with-acr-values-succeeds[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **WARNING** `oidcc-codereuse-30seconds[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **REVIEW** `oidcc-ensure-registered-redirect-uri[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **SKIPPED** `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **WARNING** `oidcc-claims-essential[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **REVIEW** `oidcc-ensure-request-object-with-redirect-uri[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]` (oidcc-formpost-basic-certification-test-plan).
- **REVIEW** `oidcc-rp-initiated-logout-bad-post-logout-redirect-uri[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]` (oidcc-rp-initiated-logout-certification-test-plan).
- **REVIEW** `oidcc-rp-initiated-logout-modified-id-token-hint[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]` (oidcc-rp-initiated-logout-certification-test-plan).
- **REVIEW** `oidcc-rp-initiated-logout-no-id-token-hint[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]` (oidcc-rp-initiated-logout-certification-test-plan).
- **REVIEW** `oidcc-rp-initiated-logout-no-params[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]` (oidcc-rp-initiated-logout-certification-test-plan).
- **REVIEW** `oidcc-rp-initiated-logout-no-post-logout-redirect-uri[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]` (oidcc-rp-initiated-logout-certification-test-plan).
- **REVIEW** `oidcc-rp-initiated-logout-only-state[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]` (oidcc-rp-initiated-logout-certification-test-plan).
- **REVIEW** `oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]` (oidcc-rp-initiated-logout-certification-test-plan).
- **REVIEW** `oidcc-rp-initiated-logout-bad-id-token-hint[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]` (oidcc-rp-initiated-logout-certification-test-plan).

The twelve warning results emit six warning cases per basic/form-post mode, using these condition names: `VerifyScopesReturnedInUserInfoClaims`, `EnsureIdTokenDoesNotContainEmailForScopeEmail` (email and alternate-happy-flow), `ValidateIdTokenACRClaimAgainstAcrValuesRequest`, `EnsureHttpStatusCodeIs4xx` (access token after code reuse), and `EnsureUserInfoContainsName`. All eight skips are explicitly reported “skipped as expected.” Review outcomes remain review outcomes without a manual-pass claim.

## Baseline browser skipped names

These selected baseline cases were gated and skipped. Specialized required lanes above ran their own selections; their success does not relabel any baseline skip.

- `m19-console.spec.mjs:5:1 › settings, automatic blocks, breach refusal and hosted challenge replay`
- `m20-console.spec.mjs:5:1 › operator rotates and revokes a tenant signing key and sees custom-key limits`
- `m21-console.spec.mjs:34:1 › email delivery stays tenant-local and console edits keep safe uncertainty behavior`
- `m22-console.spec.mjs:22:1 › branded combined and identifier login retain authentication and transient field behavior`
- `m22-console.spec.mjs:62:1 › branding reaches localized signup, reset, verification, consent, logout and device pages`
- `m22-console.spec.mjs:103:1 › identifier login keeps custom database and CAPTCHA behavior`
- `m22-console.spec.mjs:133:1 › console edits, sandbox preview and narrow/wide layouts stay isolated`
- `m23-domains.spec.mjs:16:1 › domain console: keyboard, narrow/wide, one-time secret, lost reply and stale tenant response`
- `m23-domains.spec.mjs:61:1 › public proxy domain: branding, PKCE issuer/audience, cross-host code and refresh rejection`
- `m24-social.spec.mjs:27:3 › social federation through real code exchange › google-oauth2: explicit selection, first and repeat login`
- `m24-social.spec.mjs:27:3 › social federation through real code exchange › acme-oauth: explicit selection, first and repeat login`
- `m24-social.spec.mjs:27:3 › social federation through real code exchange › corp: explicit selection, first and repeat login`
- `m24-social.spec.mjs:37:2 › social federation through real code exchange › login page buttons on a mixed application`
- `m24-social.spec.mjs:45:2 › social federation through real code exchange › keyboard: social buttons follow the password form`
- `m24-social.spec.mjs:56:2 › social federation through real code exchange › provider denial and callback replay fail safely`
- `m25-email-accounts.spec.mjs:10:56 › email account code and PKCE flows › work via microsoft-directory: first and repeat`
- `m25-email-accounts.spec.mjs:10:56 › email account code and PKCE flows › school via microsoft-directory: first and repeat`
- `m25-email-accounts.spec.mjs:10:56 › email account code and PKCE flows › outlook via microsoft-personal: first and repeat`
- `m25-email-accounts.spec.mjs:10:56 › email account code and PKCE flows › hotmail via microsoft-personal: first and repeat`
- `m25-email-accounts.spec.mjs:10:56 › email account code and PKCE flows › gmail via google-oauth2: first and repeat`
- `m25-email-accounts.spec.mjs:10:56 › email account code and PKCE flows › workspace via google-oauth2: first and repeat`
- `m25-email-accounts.spec.mjs:10:56 › email account code and PKCE flows › nongmail via google-oauth2: first and repeat`
- `m25-email-accounts.spec.mjs:10:56 › email account code and PKCE flows › noemail via microsoft-directory: first and repeat`
- `m25-email-accounts.spec.mjs:10:56 › email account code and PKCE flows › work via microsoft-organizations: first and repeat`
- `m25-email-accounts.spec.mjs:13:59 › email account code and PKCE flows › Microsoft tenant-mismatch fails without provisioning`
- `m25-email-accounts.spec.mjs:13:59 › email account code and PKCE flows › Microsoft key-mismatch fails without provisioning`
- `m25-email-accounts.spec.mjs:18:2 › email account code and PKCE flows › Microsoft provider denial is sanitized`
- `m25-email-accounts.spec.mjs:19:2 › email account code and PKCE flows › disable and secret rotation invalidate pending Microsoft attempts; reenable succeeds`
- `m25-email-accounts.spec.mjs:28:2 › email account code and PKCE flows › Microsoft custom-domain callback keeps origin and downstream issuer`
- `m26-rbac.spec.mjs:12:2 › Plan26 real RBAC tokens and console › database PKCE issues current scope and revokes roles on refresh`
- `m26-rbac.spec.mjs:21:2 › Plan26 real RBAC tokens and console › federated PKCE gets permissions only after tenant role assignment`
- `m26-rbac.spec.mjs:29:2 › Plan26 real RBAC tokens and console › custom domain keeps RBAC profile and issuer through PKCE exchange`
- `m26-rbac.spec.mjs:37:2 › Plan26 real RBAC tokens and console › operator creates a role, grants a permission, assigns a user and deletes it`
- `m27-actions.spec.mjs:11:1 › auth0-spa-js reads namespaced ID/access claims and roles from actual PKCE tokens`
- `m27-actions.spec.mjs:18:1 › Action denial renders on the hosted error page`
- `m27-actions.spec.mjs:21:1 › throwing Action renders a persisted execution readable through node-auth0`
- `m27-actions.spec.mjs:25:1 › redirect fixture adds a=1 and POSTs state-bound encodeToken token to continue`
- `m27-actions.spec.mjs:29:1 › console creates edits builds deploys binds and tests an Action`
- `m28-actions-ii.spec.mjs:12:1 › hosted signup denial shows Action user message`
- `m28-actions-ii.spec.mjs:13:1 › hosted signup metadata, async registration sink and custom verification delivery with retry`
- `m28-actions-ii.spec.mjs:19:1 › reset challenge redirects and continues to Action result URL, then runs post-change Action`
- `m28-actions-ii.spec.mjs:22:1 › console module publish inspect rollback and custom email provider settings`
- `m29-organizations.spec.mjs:12:2 › Plan29 organization browser acceptance › pre-login organization prompt continues to branded login and issues organization tokens`
- `m29-organizations.spec.mjs:18:2 › Plan29 organization browser acceptance › post-login picker presents two memberships and chooses the selected organization`
- `m29-organizations.spec.mjs:23:2 › Plan29 organization browser acceptance › non-member receives access_denied without an authorization code`
- `m29-organizations.spec.mjs:27:2 › Plan29 organization browser acceptance › automatic membership is persisted after real login`
- `m29-organizations.spec.mjs:31:2 › Plan29 organization browser acceptance › organization signup creates both user and membership`
- `m29-organizations.spec.mjs:35:2 › Plan29 organization browser acceptance › auth0-spa-js loginWithRedirect validates org_id and returns the organization user`
- `m29-organizations.spec.mjs:39:2 › Plan29 organization browser acceptance › operator manages organization settings branding connections members roles and application settings`
- `m30-organizations.spec.mjs:14:1 › captured invitation follows application signup, normal email verification, retry, Actions and PKCE exchange; replay rejected`
- `m30-organizations.spec.mjs:31:1 › wrong account leaves invitation usable by intended verified account`
- `m30-organizations.spec.mjs:37:1 › application entitlement removal blocks code exchange and refresh`
- `m30-organizations.spec.mjs:48:1 › console administrator attests domain ownership and tenant navigation isolates organization state`
- `m30-organizations.spec.mjs:58:1 › verified email domain routes login without enrolling an unknown account; pending and disabled domains do not route`
- `m30-organizations.spec.mjs:72:1 › organization password reset preserves organization in actual custom email Action context`
- `m31-logs.spec.mjs:8:1 › Action deny → Logs Live failure → masked execution → console redeploy → successful retry`
- `m32-event-streams.spec.mjs:7:1 › browser signup → metadata update → delete; console test/failure/redelivery and Action repair`

## Retained artifacts and limits

Private root `/tmp/zeroauthy-plan32-postfix-z__an_zq` contains durable supervisor/state/events, per-stage exact `output.log`, `command.json`, `summary.json`, `test-results.json`, source snapshots/manifests/patches, transcribed browser results and final report-verification metadata. No commands remain running; sequence state is complete and retained tool session exited 0.

Retained acceptance work directories (all verified/restricted to 0700):

- e2e-events: `/tmp/plan32-eoTIRp`.
- e2e-logs: `/tmp/plan31-DM20jB`.
- e2e-actions: `/tmp/tmp.N1bIH4PUCb`.
- e2e-actions-ii: `/tmp/tmp.MIEHJelTg3`.
- e2e-organizations-ii: `/tmp/plan30-FPq0sR`.
- e2e-deploy: `/tmp/tmp.2cIixoZIyc`.
- Conformance original exports: `tests/conformance/results/20261102T053006Z` (also copied under stage 12).

Baseline `tests/e2e/run-browser.sh` ignores `E2E_KEEP_WORK` and deletes its private server/database temp directory. Fixed source was retained as instructed. Full stdout/stderr, all selected browser outcome names and surviving Playwright results are retained (`06-e2e/playwright-test-results`); deleted baseline private temp artifacts are unavailable. Other acceptance lanes retain their work directories. Raw artifacts can contain credentials and were not printed in reports.

This fresh matrix verifies the durable removal watermark/new 0032 migration, fail-closed floor RPC, bounded synchronous HTTP response and effective seed quota fixes on the fixed commit. Residual documented behavior is unchanged: unknown pre-0032 purge history; timestamp replay of retained rows below an accepted removal floor may require timestamp fallback after offset-resume 410; Events-v1 plugins missing the floor RPC receive SSE 501; the synchronous test route has a finite 60-second budget. Earlier accepted limits include unavailable upstream E1–E8 evidence, EventBridge stored-only, groups deferred, the unmet relative 10% memory capture-overhead target and dormant organization-role synchronization. Deferred M1–M9 were not changed.

The monitor made no production changes, no commits and no Task 14 completion or merge declaration. The requested reports are the only workspace writes after validation; all implementation tests retain their actual snapshot identities and outcomes.
