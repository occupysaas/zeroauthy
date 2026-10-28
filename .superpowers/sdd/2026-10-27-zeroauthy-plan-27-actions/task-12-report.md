# Task 12 report (verification pending Deploy matrix)

Base: `8d94517`. Implementation is committed for independent review. Task completion is pending the final four-cell Deploy CLI result.

Implemented `make e2e-actions`, pinned Auth0 CLI 1.37.0 CRUD/binding/execution checks, node-auth0 7.4.0 coverage of all fourteen Actions operations, and five real-browser cases: auth0-spa-js namespaced ID/access claims and roles, hosted denial, persisted execution lookup, signed redirect token/POST continuation with `a=1`, and console create/edit/build/deploy/test/bind. Credentials-exchange claim and denial run through actual grants. A real `require('auth0')` ManagementClient Action authenticates with M2M secrets and assigns the default role; the test asserts absence on that issuance and presence on the next login.

The registry fixture packages the installed lockfile-pinned auth0 dependency closure into private static tarballs and serves metadata/tarballs on loopback. It runs no package scripts or network install. The Actions build uses that registry and a fresh private cache; unknown dependencies fail locally. Tools are required explicitly; missing tools fail as unavailable.

Deploy CLI 9.1.0 now includes Actions and triggers in the YAML/directory × generated/preserved matrix. Comparisons match Action names, load and compare referenced code, preserve binding order, reject missing Action/binding/code, dangling references and exported secret values, and assert the claim after real post-import federated logins. Private target configuration supplies secret keyword mappings; staged imports contain placeholders, and public exports are scanned recursively for credentials/masks. Database connection migration is excluded/not demonstrated, correcting the obsolete assertion that Actions API absence blocks it. Existing actual attack-protection/tool-header and upstream-observer limitations remain reported.

The strict default-role test found that minting reloaded RBAC after the Action. The minimal compatibility fix captures effective permissions before a bound RBAC-enabled flow, carries audience+permissions in sealed effects through consent/code/device/continuation, and reuses them at mint. API definition and client policy remain current. Without a captured flow, existing mint-time RBAC lookup remains unchanged. RBAC-disabled APIs retain Plan 26's omission of `permissions`. Seal binding remains tenant/purpose/code-or-session bound, and mint validates the snapshot audience.

RED evidence:
- Initial `make e2e-actions` failed because the target did not exist.
- New comparator tests failed identical Actions/triggers natural identity and directory recognition checks.
- Actual `make e2e-deploy` with Actions/triggers included but before populated fixtures failed empty resource assertions (`/tmp/za-m27-deploy-red.log`).
- The strict default-role first issuance assertion failed. Focused memory/real-Node regression then failed the first-issuance permission assertion for password, authorization code, device and refresh (`/tmp/za-m27-rbac-red.log`).

Verified so far:
- `make e2e-actions`: PASS, final run `/tmp/za-m27-actions-final.log`; all 5 browser cases, SDK fourteen operations and grants, CLI operations including successful persisted execution read. No missing tool was skipped into PASS.
- `go test -race ./internal/actions/... ./internal/oauth ./internal/authz ./internal/deploymigration ./tests/e2e/deploy-cli -count=1`: PASS, `/tmp/za-m27-affected-race.log` (oauth 193.398s).
- Explicit permissions-only sealed-effects roundtrip/HasTokenEffects check: PASS under race.
- Focused comparator tests including regenerated IDs, equally invalid dangling references and secret-valued exports: PASS.
- Offline registry smoke: PASS metadata/latest 7.4.0, legacy alias version, tarball retrieval, and local unknown-package 404.
- Shell/JavaScript syntax and `git diff --check`: PASS.
- Deploy matrix: generated/YAML full cell PASS; generated/directory post-import runtime PASS but full cell and preserved-ID cells still pending in `/tmp/za-m27-deploy.log`. Deferred cells are not passing results.

Self-review checked task coverage, no public npm install in tests, write-only credential scans, missing-code rejection, Action-name identity, binding order, current API policy with frozen permissions, no-bound-flow cost, and code/device/continuation sealing. Initial browser callback routing/CORS fixture failures and temporary compile/test expectation failures were corrected before the passing runs. No SQL lane was rerun; its previously reported controller result is outside this task's verification.
