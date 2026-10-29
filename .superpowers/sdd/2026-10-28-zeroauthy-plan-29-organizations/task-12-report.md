# Task 12 — Console

Status: DONE.

Base: `14f28eb`. Branch: `plan-29-organizations`.

Commit subject: `feat: add Organizations to the console`.

## Implemented

- Replaced the planned Organizations section with live list, create and detail routes. The list filters names locally over its current page and uses the existing roles Pager. Creation preserves failed drafts and puts 409 conflicts on the name field. Detail supports loading/error/not-found states and a confirmation dialog for deletion.
- Added Settings, Branding, Connections and Members tabs. Settings edits name, display name, replacement metadata and third-party access, including bounded metadata validation and a name-specific 409 error. Branding validates HTTPS logos and paired three/six-digit hex colors, previews the colors live, and supports clearing the whole branding object.
- Connections enable/disable links through the actual `/enabled_connections` resource. Strategy rules match the server's current enterprise strategies (`oidc`, `waad`); signup is available only for database connections with automatic membership. Turning automatic membership off also clears signup in the same PATCH. The tab reads the frozen maximum of 50 enabled links, displays them in 20-row pages, and excludes all enabled IDs from the connection picker, including other pages. Successful enabling clears its selection.
- Members supports paginated API user search, one-user add/remove operations and scoped member-role assignment/removal, with the local 50-role limit message. Removing a currently selected member closes its role editor. The membership message explains the next-login/refresh effect and preserved role assignments.
- Added the user-detail Organizations tab and links to organization detail.
- Added the three application organization fields. The observed D-0055 rules override the stale brief: `pre_login_prompt` remains available for deny/allow/require; discovery is available only with pre-login prompting and is explicitly cleared when another behavior is saved; post-login prompting requires OIDC conformity. Required organization usage refuses the three incompatible password/device grants locally as well as relying on the server.
- Reused the existing field/button/banner/dialog/tab and Pager components. Added a small panel lifecycle helper based on the existing roles request-sequence and Actions draft patterns: stable resource identity, tenant/resource reset, request ordering, write invalidation, unmount invalidation, preserved failed drafts and explicit reload after uncertain writes. All UI copy is localized and the layouts are original.
- Added typed API adapters over the already generated organization schemas and regenerated the committed production console bundle. `npm run gen` refreshed the schema successfully but produced no diff because Task 11 had already regenerated it.
- Removed the retired organization preview and updated its planned-page/router tests to use the still-planned MFA section.

## TDD evidence

Initial RED:

`npm --prefix console test -- src/pages/organizations src/pages/users src/pages/applications`

Exit 1: 1 failed file, 17 passing files, 133 existing tests passed. The newly written organization suite failed to resolve `./List.vue`, which did not exist before implementation. This was the expected missing-feature failure. The subsequent focused RED also included the missing tab components and the application organization-field test, which failed because `#app-organization-behavior` did not exist.

Additional behavioral RED during self-review:

`npm --prefix console test -- src/pages/organizations/tabs.test.ts`

Exit 1: 1 failed / 5 passed. `enables and disables a connection and clears the successful enable selection` found that the enable button remained enabled after its selected connection disappeared from the available options. Clearing the model after the successful write fixed the actual behavior.

GREEN:

- `npm --prefix console test -- src/pages/organizations src/pages/applications/OrganizationSettings.test.ts`: 4 files / 19 tests passed, including stale replies on all five organization panels, stale detail/list/create replies, user-organization replies, failed-write draft retention and old-write rejection.
- `npm --prefix console test -- src/pages/organizations src/pages/users src/pages/applications`: 22 files / 155 tests passed after the connection selection correction and the user-detail integration test.
- Expanded application usage/discovery/grant/stale-write tests and metadata/name boundary cases were subsequently included in the successful full target below.

## Full verification

`make console`: **exit 0**.

- `npm ci --no-audit --no-fund`: completed; existing npm notice about the unapproved `vue-demi` postinstall script.
- OpenAPI generation: successful with openapi-typescript 7.13.0.
- ESLint (`--max-warnings 0`): passed.
- `vue-tsc --noEmit`: passed.
- Vitest: **71 files / 507 tests passed**, 12.13s, no test warnings or unhandled errors.
- Vite production build: successful, 925 modules, 1.18s. The existing advisory about a minified JS chunk exceeding 500 kB remains (783.40 kB / 219.90 kB gzip).
- `git diff --check`: passed.

The first full target found 5 integration failures: retired planned Organizations assumptions in router/planned-page tests and the locale literal scanner matching a dynamically concatenated tab key. The planned tests now exercise remaining planned sections, and detail labels use explicit catalog keys. The complete target was rerun successfully after these corrections.

No Go, storage, database-backed, browser-backed or Auth0 tests were run. The console tests use the existing mocked fetch harness. No test was labeled passing while deferred.

## Files changed

- New organization components: `console/src/pages/organizations/{List,Create,Detail,SettingsTab,BrandingTab,ConnectionsTab,MembersTab,MemberRoles}.vue` and `context.ts`.
- New organization tests: `organizations.test.ts`, `tabs.test.ts`, `lifecycle.test.ts`, `validation.test.ts` in that directory.
- User detail integration: `console/src/pages/users/Detail.vue`, new `OrganizationsTab.vue` and `OrganizationsTab.test.ts`.
- Application settings: `console/src/pages/applications/SettingsTab.vue` and new `OrganizationSettings.test.ts`.
- API/navigation/localization: `console/src/api/client.ts`, `layout/sections.ts`, `locales/en.ts`, `router.ts`, `router.test.ts`.
- Retired planned UI and tests: removed `console/src/pages/planned/Organizations.vue`; updated `index.ts`, `lists.test.ts`, `planned.test.ts`.
- Generated bundle: `console/dist/index.html` and its hashed JS asset.
- This report.

## Self-review and concerns

Reviewed the full source diff against the brief, spec §10, global constraints, D-0055 and frozen inventory. Checked request path/body shapes, offset pagination, name-field conflicts, replacement/clearing semantics, connection strategy flags, atomic signup removal, selection resets, local limits, localized strings and stale read/write protection. The existing application settings file already owns other settings; its changes remain limited to the requested fields and stale-write lifecycle. No backend API, tenant-refresh disposition, dependency or progress file changes were made.

No implementation correctness concerns remain. There was no real-browser visual verification; behavior was verified through the Vue DOM tests and production build. Existing npm install-script and Vite bundle-size notices are non-blocking and were not changed in this task.
