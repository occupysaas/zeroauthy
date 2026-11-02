# Plan 32 final validation evidence

The required twelve-command final matrix completed with exit 0 on `82b00df73b1ff2d37e06d076dae77b02fab81b75`, after one authorized test-fixture correction and full Go retry. This report records execution evidence only; Task 14 completion and whole-branch review remain the controller's gate. Warnings, reviews, skips and unavailable upstream evidence below are not passes.

## Snapshot and execution protocol

Worktree `/mnt/nvme2/code/zeroauthy-plan32`, branch `implement-plan-32`.
Initial snapshot `a9ca2ed8a110a893fe87d02e4fd6a4ef8d42d527`, tracked-file manifest SHA-256 `bf11d1c2c8b2b95ca7cdd9dbaacfb2e3f2c9a35147309aa5a13925d27d16828d`.
Final snapshot `82b00df73b1ff2d37e06d076dae77b02fab81b75`, manifest `42eb1e927b3c3dd9b0acded0e9b82a318e6105be069da1017bdc818606e6f469` before and after every final stage. The manifests hash a sorted JSON mapping of tracked filenames to SHA-256 contents; per-stage maps and HEAD/status/patch snapshots are retained. The fix changes only `internal/eventstream/worker_test.go` and the implementation record; production source is identical between these two commits. No stage changed tracked files, including console generation/build. The pre-existing untracked `tests/e2e/node_modules` symlink was not committed. The baseline npm install replaced it with an ignored local dependency directory; the tracked source remained unchanged.

One designated monitor started each invocation once, retained its process/session and actual exit code, and used automatic blocking completion waits. No other agent polled the commands/logs, no quiet suite was restarted, and waiting was not filled with audits. The sequence stopped after the first recorded Go failure; it resumed only after controller authorization of the committed fixture fix. No source fixes or production edits were made by the monitor.

Global command environment: `GOTOOLCHAIN=go1.26.7 ZA_REQUIRE_NODE=1 E2E_KEEP_WORK=1 AUTH0_CLI_ANALYTICS=false NO_COLOR=1`. Preflight confirmed Go 1.26.7 and Node v26.8.1; existing repository dependency pins were retained. SQL additionally used free ports `ZEROAUTHY_TEST_PG_PORT=56759 ZEROAUTHY_TEST_MYSQL_PORT=59115`. The SQL script adds `-race -count=1`. Its authorized `-timeout=90m` replaces the plan's historical 30m because Plan 31's full SQL race run took 34.17m and had a recorded 30m timeout; coverage was unchanged across all three drivers.

All timestamps below are UTC on **2026-11-02**. Exact fractional timestamps, environment, PID, source state and command arrays are in each stage's `command.json`.

| Stage/artifact directory | Exact command (global environment above) | Start–end UTC | Duration | Exit |
| --- | --- | --- | --- | --- |
| 01-go-race | `go test -json -race -timeout=50m ./...` | 00:01:40–00:31:23 | 1783.021s | 1 |
| 01-go-race-retry1 | `go test -json -race -timeout=50m ./...` | 00:35:32–00:35:51 | 19.268s | 0 |
| 02-sql-race | `./scripts/test-sql.sh -json -timeout=90m ./internal/store/sqlstore/...` | 00:35:51–01:14:32 | 2320.604s | 0 |
| 03-console | `make console` | 01:14:33–01:15:08 | 35.666s | 0 |
| 04-check-sources | `make check-sources` | 01:15:09–01:17:15 | 126.779s | 0 |
| 05-e2e-events | `make e2e-events` | 01:17:16–01:18:46 | 90.101s | 0 |
| 06-e2e | `make e2e` | 01:18:46–01:20:29 | 103.706s | 0 |
| 07-e2e-logs | `make e2e-logs` | 01:20:30–01:20:49 | 19.885s | 0 |
| 08-e2e-actions | `make e2e-actions` | 01:20:50–01:20:59 | 9.627s | 0 |
| 09-e2e-actions-ii | `make e2e-actions-ii` | 01:20:59–01:21:38 | 38.560s | 0 |
| 10-e2e-organizations-ii | `make e2e-organizations-ii` | 01:21:38–01:21:46 | 7.896s | 0 |
| 11-e2e-deploy | `make e2e-deploy` | 01:21:46–01:38:57 | 1031.314s | 0 |
| 12-conformance | `make conformance` | 01:38:58–01:41:44 | 165.925s | 0 |

## Go failure, correction and final outcomes

The original full Go run failed in `internal/eventstream` after 54.766s with `panic: close of closed channel` during `TestSlowReceiverDoesNotBlockSignups`, in its transport callback at `worker_test.go:501`. The full command returned exit 1 after 29m43.021s. JSON retained 9,756 passing leaf outcomes, four skipped leaves, 82 passed packages and one failed package. An unhandled panic did not emit a normal failed-test event, so zero normal test-failure events cannot be read as success. The panic also interrupted the remaining eventstream tests. No SQL or later stage had started.

The task owner reproduced the panic deterministically by exercising all four timeout attempts. Commit `82b00df` guards the fixture's first-entry signal with `sync.Once`; every attempt still blocks until its own context ends. The 1,000-signup assertions remain intact. Owner evidence is in workspace `task-14-go-fix1-report.md`: deterministic RED exit 1, focused race two leaves PASS, full eventstream race count=3 with 150 passing leaf executions and zero skips/race reports. Those focused checks are separate from this matrix.

The authorized full Go retry returned exit 0: 11,036 passing test nodes / **9,769 passing leaf outcomes**, four skipped leaves, 83 passed packages, no failed package, and 24 packages with no test files. **82 packages replayed Go test cache from the original full run; only the changed eventstream package executed afresh.** The cache list is retained in `01-go-race-retry1/cached-packages.json`. Do not describe all 9,769 outcomes as new executions on the retry. No test-cache bypass or extra full run was authorized or performed.

Actual Go test skips, retained with their reasons in both Go JSON summaries:

- `tests/e2e/deploy-cli.TestE2EPrivateEmailProviderCredentialAfterImport`: isolated Plan 21 deploy helper.
- `tests/e2e/deploy-cli.TestE2EPrivateLogStreamSecretsAfterImport`: isolated deploy CLI helper.
- `pkg/storeplugin.TestConformanceThroughPluginProcess/Organizations/Limits`: store cannot override Organizations limits.
- `internal/store/grpcstore.TestOrganizationsPluginRoundTrip/Organizations/Limits`: same store limitation.

The 24 no-test-file packages are recorded separately in `no_test_files_packages`; they are not 24 additional executed tests. The final SQL command explicitly used `-count=1` and was uncached: **2,806 passed leaves / 3,155 passed nodes, zero failures, zero skips, one passed package**. `TestConformance/postgres`, `/mysql` and `/sqlite` all passed (127.25s, 416.79s and 929.42s respectively). Every backend-parent result and all test results are retained, not only these representative parents. Total SQL command duration was 38m40.604s; it did not time out.

## Console, source links and acceptance

| Command | Actual selected results |
| --- | --- |
| `make console` | npm install, API type generation, lint, typecheck, 75 test files / 604 tests and production build completed; no tracked output changes. |
| `make check-sources` | Authentication and Management source-link checks both exited 0; no network failure was waived or retried. |
| `make e2e-events` | Browser 1 passed / 0 skipped; pinned SDK CRUD/test/history/single+batch redelivery, native CLI operations, SSE resume, retries and privacy acceptance passed. |
| `make e2e` | Baseline SDK/CLI checks completed; browser 24 passed / **57 lane-gated skipped**, zero failed. All skip names follow below. |
| `make e2e-logs` | Browser 1 passed / 0 skipped; 17 logging/monitoring artifacts, 487,418 bytes and eight representative secrets checked absent. |
| `make e2e-actions` | Browser 5 passed / 0 skipped; SDK/CLI lane completed. |
| `make e2e-actions-ii` | Browser 4 passed / 0 skipped; selected lane completed. |
| `make e2e-organizations-ii` | Browser 6 passed / 0 skipped; SDK invitation/application/discovery/search checks completed. |
| `make e2e-deploy` | All four local cells: YAML/directory × generated/preserved. Each passed import, repeat, credential, update, target-only and runtime checks; required negative checks detected the expected failures. |

Events privacy checked **12 artifacts / 538,267 bytes** for the actual source hash/token and representative password, upstream-token, webhook and Action secrets, including common encodings. Full fixture scope/rulings remain in workspace `task-14-implementation-report.md`: every column of event-specific `tenant_events`, `event_streams` and `event_deliveries` is scanned; legitimate protected source-credential storage is a positive control, not an assertion that all raw DB credential storage is empty. No Auth0 tenant or real upstream provider OAuth exchange was used. The production app/SQLite browser lane does not claim four-store browser coverage.

Each Deploy cell passed Plan 32 webhook/Action public configuration, strict field-loss negatives, target Action ownership, fresh credential reinjection, explicit token rotation, omitted-secret CLI import and actual runtime delivery; `eventStreams` source/target counts were 2/2 in each. Existing Deploy limits remain: database export was excluded; phone-provider-protection/attackProtection was tool-unavailable; the CLI rejected x-azure-clientip/empty-header cases; ACUL was excluded. The upstream observer lane was unavailable because no credentials were supplied, and no upstream calls were made. These are not passes.

## Conformance module outcomes

`make conformance` returned exit 0. The local suite reported **82 actual module results: 46 PASSED, 0 FAILED, 12 WARNING, 16 REVIEW and 8 SKIPPED**. Runner exit 0 does not turn warnings, reviews or skips into passed modules. The per-plan result sections below count actual module rows; the runner's separate “ran” totals include its own bookkeeping and are not substituted for these rows.

| Plan | Passed | Failed | Warning | Review | Skipped |
| --- | --- | --- | --- | --- | --- |
| Basic | 21 | 0 | 6 | 4 | 4 |
| Configuration | 1 | 0 | 0 | 0 | 0 |
| Form-post basic | 21 | 0 | 6 | 4 | 4 |
| RP-initiated logout | 3 | 0 | 0 | 8 | 0 |

Every module's full name/configuration and outcome is retained in `12-conformance/module-results.json` and the exported runner artifacts. Non-passing module names:

- WARNING: `oidcc-basic-certification-test-plan` / `oidcc-scope-profile[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- WARNING: `oidcc-basic-certification-test-plan` / `oidcc-scope-email[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- WARNING: `oidcc-basic-certification-test-plan` / `oidcc-alternate-happy-flow[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- WARNING: `oidcc-basic-certification-test-plan` / `oidcc-ensure-request-with-acr-values-succeeds[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- WARNING: `oidcc-basic-certification-test-plan` / `oidcc-codereuse-30seconds[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- WARNING: `oidcc-basic-certification-test-plan` / `oidcc-claims-essential[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- WARNING: `oidcc-formpost-basic-certification-test-plan` / `oidcc-scope-profile[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- WARNING: `oidcc-formpost-basic-certification-test-plan` / `oidcc-scope-email[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- WARNING: `oidcc-formpost-basic-certification-test-plan` / `oidcc-alternate-happy-flow[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- WARNING: `oidcc-formpost-basic-certification-test-plan` / `oidcc-ensure-request-with-acr-values-succeeds[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- WARNING: `oidcc-formpost-basic-certification-test-plan` / `oidcc-codereuse-30seconds[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- WARNING: `oidcc-formpost-basic-certification-test-plan` / `oidcc-claims-essential[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- REVIEW: `oidcc-basic-certification-test-plan` / `oidcc-prompt-login[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- REVIEW: `oidcc-basic-certification-test-plan` / `oidcc-max-age-1[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- REVIEW: `oidcc-basic-certification-test-plan` / `oidcc-ensure-registered-redirect-uri[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- REVIEW: `oidcc-basic-certification-test-plan` / `oidcc-ensure-request-object-with-redirect-uri[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- REVIEW: `oidcc-formpost-basic-certification-test-plan` / `oidcc-prompt-login[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- REVIEW: `oidcc-formpost-basic-certification-test-plan` / `oidcc-max-age-1[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- REVIEW: `oidcc-formpost-basic-certification-test-plan` / `oidcc-ensure-registered-redirect-uri[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- REVIEW: `oidcc-formpost-basic-certification-test-plan` / `oidcc-ensure-request-object-with-redirect-uri[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- REVIEW: `oidcc-rp-initiated-logout-certification-test-plan` / `oidcc-rp-initiated-logout-bad-post-logout-redirect-uri[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]`
- REVIEW: `oidcc-rp-initiated-logout-certification-test-plan` / `oidcc-rp-initiated-logout-modified-id-token-hint[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]`
- REVIEW: `oidcc-rp-initiated-logout-certification-test-plan` / `oidcc-rp-initiated-logout-no-id-token-hint[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]`
- REVIEW: `oidcc-rp-initiated-logout-certification-test-plan` / `oidcc-rp-initiated-logout-no-params[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]`
- REVIEW: `oidcc-rp-initiated-logout-certification-test-plan` / `oidcc-rp-initiated-logout-no-post-logout-redirect-uri[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]`
- REVIEW: `oidcc-rp-initiated-logout-certification-test-plan` / `oidcc-rp-initiated-logout-only-state[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]`
- REVIEW: `oidcc-rp-initiated-logout-certification-test-plan` / `oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]`
- REVIEW: `oidcc-rp-initiated-logout-certification-test-plan` / `oidcc-rp-initiated-logout-bad-id-token-hint[client_auth_type=client_secret_basic][response_mode=default][server_metadata=discovery]`
- SKIPPED: `oidcc-basic-certification-test-plan` / `oidcc-scope-address[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- SKIPPED: `oidcc-basic-certification-test-plan` / `oidcc-scope-phone[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- SKIPPED: `oidcc-basic-certification-test-plan` / `oidcc-scope-all[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- SKIPPED: `oidcc-basic-certification-test-plan` / `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported[client_auth_type=client_secret_basic][response_mode=default][response_type=code]`
- SKIPPED: `oidcc-formpost-basic-certification-test-plan` / `oidcc-scope-address[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- SKIPPED: `oidcc-formpost-basic-certification-test-plan` / `oidcc-scope-phone[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- SKIPPED: `oidcc-formpost-basic-certification-test-plan` / `oidcc-scope-all[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- SKIPPED: `oidcc-formpost-basic-certification-test-plan` / `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`

## Baseline browser skips

These 57 results were selected but skipped by the baseline lane. Specialized required lanes above ran their own selected fixtures; this list is preserved without treating skipped baseline fixtures as passes.

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

## Retained evidence and limitations

Private validation root: `/tmp/zeroauthy-plan32-validation-wco4isyf` (mode 0700). Original runner session `11474` / Go PID `10776` ended with exit 1. Authorized retry runner session `90071` ended with exit 0. Persistent `supervisor.py`, `state.json`, `events.jsonl` and the separate retry variants preserve original failure and resumed history. Every stage directory in the command table contains `command.json`, `output.log`, `summary.json`, `test-results.json`, before/after source snapshots, tracked manifests and patches. Go summaries retain exact failure/skip output and SQL backend parents; completed browser stages additionally have `browser-results.json` with exact selected test names/outcomes. The original package panic is extracted in `01-go-race/eventstream-output.log`; `failure-incident.md` preserves the stop and remaining-stage list as it stood at that time.

Retained acceptance work directories:

- Events: `/tmp/plan32-D0n2QZ`.
- Logs: `/tmp/plan31-Q3o7SD`.
- Actions: `/tmp/tmp.gNOI76rMoJ`.
- Actions II: `/tmp/tmp.TK0EeDGJpz`.
- Organizations II: `/tmp/plan30-ceInGr`.
- Full Deploy: `/tmp/tmp.Xu3Qa5vWXm`.
- Conformance: `tests/conformance/results/20261102T013858Z`.

The baseline `tests/e2e/run-browser.sh` ignores `E2E_KEEP_WORK` and unconditionally deletes its private temp directory. The controller requested fixed source and explicit disclosure instead of a preemptive retention change. Its full stdout/stderr, JSON-transcribed browser results and surviving Playwright result state are retained; its deleted private server/DB temp artifacts are unavailable. Other requested lanes honor artifact retention. Raw private inputs/state may contain credentials and are not printed in reports.

No deferred or unavailable check is labelled passing. Earlier documented limitations remain unchanged: upstream E1–E8 observations unavailable, EventBridge stored-only, groups deferred, the relative 10% capture-overhead target not met, and empty-ring SSE cursor expiry limited by the available watermark interface. Whole-branch review/fixes and the controller's final completion decision remain outside this execution report. No production commit or Task 14 completion claim was made by the validation monitor.
