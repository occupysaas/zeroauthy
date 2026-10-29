# Task 13 — Seed, Deploy CLI and end-to-end acceptance

Status: DONE. All required local acceptance lanes passed; pinned-tool unavailability is recorded below.

## Implementation

- Added the tenant `organizations` seed section with organization branding/metadata, enabled connections by name and all three flags, members by `user_id` or `email` plus `connection`, and member roles by role name. It applies after users/connections/roles exist, inside the existing seed transaction. Missing references and ambiguous member shapes fail startup with organization/member/connection/role context.
- Organizations and all their associations are create-only, including in legacy seed apply mode. Restarts preserve console edits and removed memberships, roles and connections.
- Seed references distinguish the same email in different connections and resolve a linked secondary identity to its canonical user. Tests exercise both reference forms for role assignment as well as membership.
- Carried Task 6's three client organization fields through seed/shared validation and Deploy's credential-preserving bootstrap. Seed client writes with `allow`/`require` fail if a plugin lacks Organizations capability; empty/`deny` usage is permitted. Existing bootstrap reruns continue to allow mutable console edits; no new mutable-field drift restriction was introduced.
- Added `make e2e-organizations` and a local SQLite harness lane with pinned auth0-cli 1.37.0, node-auth0 7.4.0, auth0-spa-js 2.28.3 and Chromium. It uses actual hosted forms, actual login/signup/session handling and authorization-code exchanges.
- Management SDK acceptance covers all 25 in-scope methods: six organization CRUD/list/by-name methods; both five-method connection resources; member list/create/delete; member-role list/assign/delete; effective roles; role members; user organizations. Deferred SDK resources are explicitly reported, not passed.
- CLI acceptance exercises `orgs` create/list/show/update/delete, members list, roles list and roles members list through the pinned commands. CLI roles list synthesizes its result through member roles, matching the actual tool.
- Browser acceptance covers pre-login organization prompt, a two-organization post-login picker, non-member denial without a code, automatic membership, organization signup, branded login, the SPA SDK's organization ID validation, and operator console workflows. Console flows create/delete an organization, update and clear metadata/branding, enable/toggle/disable a connection, search/add/remove a member, assign/remove a member role, open the user's Organizations tab, and update application organization settings.
- Added two nonempty organizations with branding/metadata and distinct enterprise connection policies to every Deploy matrix cell. Strict comparison retains organization fields and all exported connection fields, matches by name and treats connection collections as sets. API reads verify imported links and application organization fields. Members/member roles are explicitly unavailable in the pinned tool.
- Added directory-export organization classification to `internal/deploymigration`: the initial real directory lane found that organization JSON was being treated as opaque files, making the comparator see zero organizations.
- Fixed a real hosted-page browser bug found by acceptance: `RenderOrganization` supplied an empty `form-action` CSP. Chromium blocked both prompt and picker submissions. Organization page data now carries the transaction's validated callback, and rendering uses the existing `formActionFor` helper, allowing same-origin submission and the validated callback redirect.
- Updated the Deploy documentation, including stale opening exclusions, the exact pinned tool boundaries and the local organization lane.

## TDD evidence

All commands used `GOTOOLCHAIN=go1.26.7`.

1. Seed RED: `go test ./internal/seed -run TestOrganizationsSeed -count=1` failed with `field organizations not found in type seed.Tenant` before adding the seed section. GREEN: same command passes, including restart preservation, ID/email references, linked identities and missing references.
2. Bootstrap RED: `go test ./internal/deploymigration -run TestBootstrapOrganizationFields -count=1` failed with `source client contains unsupported fields` before carrying the fields. GREEN: same command passes and stored client settings are retained.
3. Comparator RED: `go test ./tests/e2e/deploy-cli -run '^TestCompareOrganizations$' -count=1` rejected equal organizations with `missing or duplicate natural identity` before registering the natural key. GREEN: same command passes; mutations of display name, metadata, branding, connection name and each policy flag are rejected as data loss.
4. Lane RED: `make e2e-organizations` initially failed with `No rule to make target 'e2e-organizations'`. The first populated lane exposed fixture mistakes (CLI version spelling, missing connection access for prompt clients, console Save label), which were corrected. After those corrections it passed SDK/CLI and 5/7 browser cases, with prompt/picker form submissions blocked by browser CSP.
5. CSP RED: `go test ./internal/ui -run '^TestOrganizationFormAction$' -count=1` failed because the selection page had an empty `form-action` and lacked `'self'`. Browser console independently reported the submissions blocked. GREEN: `go test ./internal/ui -run '^TestOrganization' -count=1` passes; both screen forms allow self and their validated callback, and full browser acceptance passes.
6. Deploy RED: first `make e2e-deploy` passed the generated/YAML cell with two organizations, then failed generated/directory baseline with organizations source/target count zero. Actual `organizations/deploy-alpha.json` and `deploy-beta.json` files existed, isolating the loader classification gap.
7. Directory-loader RED: `go test ./internal/deploymigration -run '^TestDirectoryOrganizations$' -count=1` failed with `organization not parsed as a resource`. GREEN: same command passes after registering the organizations family; exact connection data is retained and no organization is treated as an opaque file.

8. Old-plugin seed-writer RED: `go test ./internal/seed -run '^TestOrganizationsSeedClientCapability$' -count=1` failed for both allow/require because the seed accepted the unsupported store. GREEN: `go test ./internal/seed -run '^TestOrganizationsSeed' -count=1` passes after guarding non-deny writes before client upsert. Empty/deny usage still passes.

## Verification results

- `go test ./internal/seed -run TestOrganizationsSeed -count=1`: PASS, including the final linked-identity case.
- `go test ./internal/deploymigration -run TestBootstrapOrganizationFields -count=1`: PASS.
- `go test ./internal/deploymigration -run '^TestDirectoryOrganizations$' -count=1`: PASS.
- `go test ./tests/e2e/deploy-cli -run 'TestCompare|TestManifest' -count=1`: PASS.
- `go test ./internal/login -run '^TestOrganization(Prompt|Picker|Templates)' -count=1`: PASS (focused in-memory hosted-flow tests; excludes SQL binding tests).
- `go test ./internal/seed ./internal/deploymigration ./internal/ui -count=1`: PASS (seed 1.968s, migration 0.008s, UI 0.031s). After the final old-plugin seed guard, `go test ./internal/seed ./internal/deploymigration -count=1` also PASS (seed 1.849s, migration 0.008s). The guard affects unsupported plugin stores; local SQL lanes take the unchanged supported-store path.
- Final `go test ./tests/e2e/deploy-cli -skip '^TestE2E' -count=1`: PASS, 0.015s. This selects all non-E2E comparator/manifest/offline unit tests; the private-email SQL fixture is exercised inside the required Deploy lane instead.
- `E2E_KEEP_WORK=1 GOTOOLCHAIN=go1.26.7 make e2e-organizations`: PASS. node-auth0 operations and pinned CLI operations passed; **7/7 Playwright cases passed in 5.2s**. Log: `/tmp/task13-org-final.log`; artifacts: `/tmp/tmp.wLgBtig9Tt`.
- `E2E_KEEP_WORK=1 GOTOOLCHAIN=go1.26.7 make e2e-deploy`: PASS, exit 0, **4/4 cells**. Each cell reports organizations source 2 / target 2 and successful initial/repeat import, credential checks, update, target-only preservation, negative detection and runtime login. Approximate cell durations: generated/YAML 224.2s, generated/directory 222.8s, preserved/YAML 231.3s, preserved/directory 231.7s; total 912.4s. Log: `/tmp/task13-deploy-final.log`; artifacts: `/tmp/tmp.FD8L8bPdND`.
- Final `git diff --cached --check`: PASS. `node --check` for the three new JS suites and `bash -n` for the runner also PASS.

## Visual inspection

Captured and inspected via `view_image` the actual organization prompt and branded hosted login, plus the console organization list, Branding, Connections and Members tabs. Screens are readable with intact controls and no observed clipping or overlap. The browser test also checks horizontal overflow at 390px and 1280px on organization settings. No design changes were needed.

Screenshots are in `/tmp/tmp.wLgBtig9Tt/playwright-results/` under the prompt/login and console test directories. A diagnostic settings screenshot was inspected at `/tmp/task13-console-diagnostic.png`.

## Files changed

- `Makefile`, `docs/deploy-cli.md`
- `internal/seed/{seed.go,apply.go,organizations.go,organizations_test.go}`
- `internal/deploymigration/{bootstrap.go,bootstrap_test.go,export.go,export_test.go}`
- `internal/login/organization.go`
- `internal/ui/{ui.go,organization_test.go}`
- `tests/e2e/run-m29-organizations.sh`, `m29-node-auth0.mjs`, `m29-mgmt-cli.mjs`, `m29-organizations.spec.mjs`, `organizations/client.mjs`, `organizations-spa.html`
- `tests/e2e/social/harness/main.go`
- `tests/e2e/m20-deploy-cli.mjs`
- `tests/e2e/deploy-cli/{manifest.json,normalize.go,normalize_test.go,seed.yaml,fixtures/organizations.json}`
- This report; no `progress.md` edits.

## Deviations, unavailable and concerns

- Used the working `m*.spec.mjs`/`playwright.config.mjs` convention. The plan's proposed `browser/*.spec.ts` path would not be discovered.
- Pinned Deploy CLI 9.1.0 does not export organization members or member roles: migration of those is **unavailable**, never counted as passing. Organization client-grant reads are empty compatibility reads; their writes, organization clients/discovery domains, invitations, groups and search remain deferred.
- Existing Deploy exclusions remain explicit: database connections are excluded; attackProtection's phone-provider-protection handler is unavailable; ACUL is excluded; `x-azure-clientip`/empty custom-domain headers are rejected by the pinned tool and reported unavailable by that lane.
- The optional upstream lane is unavailable (no observer credentials; live Auth0 requests were prohibited and none were attempted).
- No missing tools. Chromium, CLI and npm dependencies execute. The Playwright runner emits a harmless inherited `NO_COLOR`/`FORCE_COLOR` warning; this is not a test skip. Initial install-script warnings did not prevent the actual exercised browser/SDK/CLI functionality.
- No Auth0/live-tenant requests or observations. All provider traffic and fixture hosts are local. Shared PostgreSQL/MySQL containers were untouched; these acceptance lanes create disposable SQLite files only. Broad repository/storage/regression lanes remain Task 14's responsibility and are not claimed here.
- Self-review: kept original UI templates and existing helper policies; no new endpoints or storage contracts. The production findings are confined to hosted organization rendering, Deploy directory classification, and the new seed writer's old-plugin capability gate; all have focused regressions.
