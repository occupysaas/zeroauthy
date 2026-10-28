# Task 12 report

Task 12 is implemented and verified. Base `8d94517`; implementation `eba3b0a`; reviewed permission-filter fix `7543ea4`. The controller approved the scoped fix review. No implementation ledger was edited by this task.

Implemented `make e2e-actions`, pinned Auth0 CLI 1.37.0 CRUD/binding/execution checks, node-auth0 7.4.0 coverage of all fourteen Actions operations, and five real-browser cases: auth0-spa-js namespaced ID/access claims and roles, hosted denial, persisted execution lookup, signed redirect token/POST continuation with `a=1`, and console create/edit/build/deploy/test/bind. Credentials-exchange claim and denial run through actual grants. A real `require('auth0')` ManagementClient Action authenticates with M2M secrets and assigns the default role; the test asserts absence on that issuance and presence on the next login.

The registry fixture packages the installed lockfile-pinned auth0 dependency closure into private static tarballs and serves metadata/tarballs on loopback. It runs no package scripts or network install. The Actions build uses that registry and a fresh private cache; unknown dependencies fail locally. The closure contains auth0 7.4.0 and alias 4.37.1, uuid 11.1.1, jose 5.10.0/4.15.9, and undici-types 6.29.0. Tools are required explicitly; missing tools fail as unavailable.

Deploy CLI 9.1.0 now includes Actions and triggers in the actual YAML/directory × generated/preserved matrix. Comparisons match Action names, load and compare referenced code, preserve binding order, reject missing Action/binding/code, dangling references and exported secret values, and assert the claim after real post-import federated logins. Private target configuration supplies secret keyword mappings; staged imports contain placeholders, and public exports are scanned recursively for credentials/masks.

The strict default-role test found that minting reloaded RBAC after the Action. The compatibility fix captures effective permissions before a bound RBAC-enabled flow, carries audience+permissions in sealed effects through consent/code/device/continuation, and reuses them at mint. API definition and client policy remain current. Without a captured flow, existing mint-time RBAC lookup remains unchanged. RBAC-disabled APIs retain Plan 26's omission of `permissions`. Seal binding remains tenant/purpose/code-or-session bound, and mint validates the snapshot audience.

Review found one Important issue: the captured assignments initially bypassed subsequent API-scope deletion. The reviewed fix intersects captured assignments with the current API's declared non-protocol permission names. Its regression captures read+write, revokes write assignment and deletes the read API definition before code exchange, and proves that only the captured write permission remains. This preserves assignment snapshot semantics while applying the current API definition.

Actual verification:

| Check | Result |
| --- | --- |
| `make e2e-actions` after review fix | PASS, SDK fourteen operations/grants/default-role first+next issuance, 5/5 browser cases (5.8s), CLI operations including successful persisted execution read and missing-execution 404 |
| `make e2e-deploy`, generated/YAML | PASS, import/repeat/credentials/update/target-only/negative/runtime; Actions and triggers each source=1, target=1 |
| `make e2e-deploy`, generated/directory | PASS, same checks and nonempty counts |
| `make e2e-deploy`, preserved/YAML | PASS, same checks and nonempty counts |
| `make e2e-deploy`, preserved/directory | PASS, same checks and nonempty counts |
| Initial affected race suite including deploymigration/comparator | PASS: Actions/build/OAuth/authz/deploymigration/comparator; OAuth 193.398s |
| Whole Actions/build/OAuth/authz race suite after review fix | PASS: Actions 14.276s, build 13.908s, OAuth 133.741s, authz 20.007s |
| Permissions-only sealed-effects roundtrip and HasTokenEffects | PASS under race |
| Comparator regenerated IDs, missing resources/code, equal dangling references and secret-valued exports | PASS |
| Offline registry metadata/latest/legacy alias/tarball/local 404 | PASS |
| Shell/JavaScript syntax; `git diff --check` | PASS |

Logs: `/tmp/za-m27-actions-review-final.log`, `/tmp/za-m27-deploy.log`, `/tmp/za-m27-affected-race.log`, `/tmp/za-m27-review-affected-race.log`, `/tmp/za-m27-review-green.log`.

RED evidence: the initial Actions target did not exist; new comparator tests failed identical-resource identities and directory recognition; actual Deploy CLI failed empty Actions/triggers before populated fixtures (`/tmp/za-m27-deploy-red.log`); password/code/device/refresh all failed strict first-issuance permission assertions before snapshot capture (`/tmp/za-m27-rbac-red.log`); the API-definition regression failed before the reviewed intersection fix (`/tmp/za-m27-review-red.log`). Initial browser callback-routing/CORS fixture failures and temporary compile/test expectation failures were corrected before the passing runs.

Self-review checked task coverage, no public npm installation in tests, credential scans, missing-code rejection, Action-name identity, current API policy with fixed permissions, no-bound-flow cost, and code/device/continuation sealing. The controller deferred one Minor coverage finding: the single-Action Deploy fixture does not demonstrate reordering multiple bindings; the comparator preserves array order and the actual fixture verifies binding presence/reference migration.

Database connection migration is excluded/not demonstrated, correcting the obsolete assertion that Actions API absence blocks it. Attack protection remains tool-unavailable because of phone-provider-protection APIs; x-azure-clientip/empty-header imports retain actual pinned-tool rejections; ACUL remains excluded. The upstream observer lane is unavailable without credentials and makes no upstream call. These are not counted as passing coverage. No SQL lane was rerun by this task; controller SQL/full-regression results are recorded separately.
