# Plan 29 implementation record

Branch `plan-29-organizations`, base `0f5be0c`; Tasks 1–13 implemented through
`26e792d`. Task 14 documentation and final regression are complete; evidence is below.
Independent whole-branch review and the scoped re-review are complete. Its sole
Important finding was fixed in `9bdc8b5`; no Critical or Important findings remain.
The accepted minor items below remain deferred. Nothing is merged or pushed.

The [Organizations guide](../organizations.md) describes the shipped behavior.
D-0055 and the separate observer's notes override stale task defaults. Task 14
makes no live Auth0 calls. Public source reachability is checked separately
from runtime tests. Go 1.26.7 and required Node execution are used.

## Verification

All commands below ran in Task 14 on Go 1.26.7. Production code and generated
artifacts were unchanged during this task; the one browser-test correction is
described below. Raw logs live in the ignored plan workspace `task-14-logs/`;
this record preserves outcomes before that workspace can be removed.

| Command | Actual result / log |
|---|---|
| `go generate ./...` twice | PASS both; no generated diff after either run (`generate-1.log`, `generate-2.log`) |
| `make check-sources` | PASS both API source inventories, including the previously failing RFC links (`check-sources.log`) |
| `go vet ./...` | PASS (`vet.log`) |
| `ZA_REQUIRE_NODE=1 go test -race -timeout=50m ./...` | PASS, 73 packages; 22 without test files. sqlstore 1026.216s, grpcstore 1159.911s, no race report (`go-race.log`) |
| `ZEROAUTHY_TEST_PG_PORT=55632 ZEROAUTHY_TEST_MYSQL_PORT=53506 ./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/...` | PASS, SQLite/PostgreSQL 17/MySQL 8.4, 1325.976s, exit 0 (`sql.log`) |
| `make console` | PASS generation, lint, typecheck, 71 files / 507 tests, production build (`console.log`) |
| `make e2e` | PASS, 114s; CLI/SDK and 24 browser cases; 49 dedicated-lane skips (`e2e.log`) |
| `make e2e-organizations` | PASS, 10s; SDK/CLI and 7 browser cases (`e2e-organizations.log`) |
| `make e2e-rbac` | PASS, 9s; SDK/CLI and 4 browser cases (`e2e-rbac.log`) |
| `make e2e-actions` | PASS, 11s; SDK/CLI and 5 browser cases (`e2e-actions.log`) |
| `make e2e-actions-ii`, initial | FAIL, exit 2, 40s; SDK/CLI and 3 browser cases passed, fourth hit the save-wait assertion below (`e2e-actions-ii.log`) |
| `make e2e-actions-ii`, corrected rerun after conformance | PASS; SDK/CLI and all 4 browser cases, 34.2s browser duration (`e2e-actions-ii-rerun.log`) |
| `make e2e-deploy` | PASS, 933s; all 4 YAML/directory × generated/preserved-credential cells (`e2e-deploy.log`) |
| `make e2e-email-accounts` | PASS, 13s; SDK/CLI and 14 browser cases (`e2e-email-accounts.log`) |
| `make e2e-domains` | PASS, 81s; three ACME challenge types, 9 SDK operations, CLI and 2 browser cases (`e2e-domains.log`) |
| `tests/conformance/run.sh` | PASS, exit 0, 150s; all four local plans, zero failed modules (`conformance.log`) |
| `ZA_TEST_POSTGRES_DSN=… go test -race -count=1 -timeout=15m ./internal/server -run '^TestOperatorTenantsConcurrentMutations/postgres/' -v` | PASS 4.990s; all five shrink/delete-operator/delete-user/block/link concurrent mutations (`operator-postgres.log`) |

All E2E lanes and conformance ran strictly sequentially, followed by the scoped
Actions II rerun. The separate SQL run started only after the full Go race
command exited. Its temporary ports avoid the existing shared PostgreSQL/MySQL
containers at 55432/53306; those existing containers are left intact.
The SQL script removed only its own temporary containers after exit 0.

Conformance output is under `tests/conformance/results/20261029T151935Z`.
Basic and Form Post each have 35 modules: 21 passed, 0 failed, 6 warning,
4 review and 4 skipped. Config has 1 passed module. Logout has 11 modules:
3 passed, 0 failed, 8 review. Warnings/review/skips are reported as such, not
converted to passes or formal OpenID certification.

Explicit skips and unavailable coverage: the standard browser runner skipped
49 dedicated-lane cases; only the named dedicated lanes above were exercised.
The pinned Deploy CLI cannot migrate organization members or member roles;
its database migration is excluded/not demonstrated, attack protection is
unavailable pending phone-provider-protection, ACUL is excluded, and
`x-azure-clientip`/empty-header modes receive actual tool rejection. The upstream
Deploy observer lane was unavailable (no credentials supplied); no upstream
call was made. The server operator-concurrency fixture supports memory, SQLite
and PostgreSQL; it has no MySQL case, so MySQL operator-concurrency coverage
is not claimed. Three-dialect storage verification is a separate lane.

Existing nonfatal notices: npm's unapproved `vue-demi` install script,
Vite's >500kB bundle advisory, and Playwright's inherited `NO_COLOR`/`FORCE_COLOR`
warning. Source checking now passes despite Task 11's historical RFC failures.

Earlier Task 8 full sqlstore/grpcstore race attempts hit Go's default 10-minute
timeout at ActionsII/QueueCap and Jobs/CreateGet respectively. They had no race
report and were never passes. Task 14 uses the required longer timeouts.
Task 13's focused SDK/CLI, seven-browser and four-cell Deploy acceptance passed;
those historical results do not replace the full final lanes below.

## Runtime and coverage boundaries

Membership and enabled original connection are required at login, code exchange
and refresh. Roles from other organizations cannot enter the authorization
snapshot. Request names and newly minted name claims obey the tenant flag.
The spec anti-goals have the following regression owners:

| Anti-goal / boundary | Evidence owners |
|---|---|
| Non-member obtains organization token | `TestOrganizationMembership`, `TestOrganizationMembershipAtCodeIssuance`, `TestOrganizationCodeRevalidation`, `TestOrganizationRevokedAtMint` |
| Login uses organization-disabled connection | `TestOrganizationLoginPageConnections`, `TestOrganizationMembershipSQLPolicyOrdering`, `TestOrganizationOriginalConnection` |
| Permissions leak from another organization | `TestOrganizationTokens`, `TestOrganizationActionsPermissionSnapshot`, shared `AuthorizationSnapshot` store conformance |
| Names bypass tenant flag | `TestResolveOrganization`, `TestOrganizationTokens`, `TestOrganizationRefresh` |
| Pending choice overwrite | `TestOrganizationBindingSQLConcurrentChoice` |
| Code/refresh binding outlives session | shared `TokenBindings` store conformance, `TestOrganizationOriginalConnection`, `TestOrganizationsMigration` |
| Last administrator removed through another mutation path | `TestOperatorTenantsConcurrentMutations`, including explicit PostgreSQL run above |

Independent whole-branch
Review Focus/spec coverage remains the controller's review, not a claim made
from these test results.

Task 8 moved shared login policy to `internal/orglogin` to avoid an import cycle
and closed pending-choice overwrite and auto-membership SQL races. Task 9
persists `OrganizationConnectionID` beside `OrganizationID` on codes and refresh
tokens, including SQL migration 0025 and protobuf/codecs; rotation never infers
an alternative identity from a missing session. Task 11 adds local console
operator discovery and serializes all last-admin mutation paths, including
blocking, deletion and linking of the system user. Task 13 real-browser
acceptance fixed prompt/picker callback CSP and Deploy directory classification;
its seed old-plugin non-deny gate also has a RED→GREEN regression.

`/api/console/tenants` is the local discovery route; system mutation remains
`/api/system/operators/{id}`. The early generic `connection=` rejection remains
in [Plan 1 follow-ups](plan-1-followups.md). The EA connections subset and empty
client-grants read are active for Deploy CLI; full organization grants,
invitations, discovery/search and entitlement stay Plan 30. Members and their
role assignments are not migrated by the pinned tool. Groups/inherited roles
remain Plan 38, SAML/WS-Fed Plan 37, My Organization API Plan 42, and token quotas
Plan 35. No live upstream certification is claimed.

## Exhaustive execution rulings

The following lines are preserved verbatim from this plan's ledger, in order.
They record decisions and the cost of being wrong, including corrections that
supersede the original plan. No cleanup may discard them.

- Ruling: Task 8 asserts only that the organization context reaches page rendering; visual branding values are asserted in Task 10 — keeps T8 independent of T10 code — cost if wrong: one assertion moves between tasks.
- Ruling: Task 1 observation runs in a separate observer subagent (CLEAN_ROOM separation) that writes notes only to docs/compat/observations/organizations.md; the Task 1 implementer works from public docs + those notes — cost if wrong: re-run observation.
- Ruling: pull `/organizations/{id}/connections` (Early Access upstream, observed shape) and a read-only `GET /organizations/{id}/client-grants` (truthfully empty until Plan 30 enables org grants) into Task 5 — the pinned Deploy CLI 9.1.0 organizations handler needs both or exports nothing, and the plan requires the four-cell Deploy matrix — cost if wrong: EA shape may drift upstream; two extra routes to maintain.
- Ruling: observed Auth0 behavior overrides plan task text: member removal keeps role assignments (spec §3 cascade reversed; membership check still gates tokens); pre_login_prompt accepted with any usage; non-member role ops 404; connection= outside org not a pre-auth error; require refused at client config with password/device grants. Every later brief carries "D-0055 + internal/orgrules/inventory.json override this task's text" — cost if wrong: rework in the affected task.
- Ruling: corrected scopes from Task 1 inventory (effective-roles read:organization_member_effective_roles; member list either members or member_roles read; /users/{id}/organizations read:users or read:organizations; role-members both read:organization_members and read:roles) carried into Tasks 5–6 — cost if wrong: scope matrix tweak.
- Task 4: Ruling: accept missing clean RED for Task 4 — wire tests assert real behavior, reviewer approved, one real failure observed — cost if wrong: provenance only.
- Task 7: Ruling: keep the pre-existing /authorize refusal of unknown/not-enabled `connection=` (Auth0 decides in the hosted flow) — changing it affects every non-org login and is outside Plan 29; logged as a follow-up for Task 14 to add to plan-1-followups.md — cost if wrong: an Auth0 client relying on a late connection error sees an earlier invalid_request.
- Task 8: Ruling: explicitly selected client-enabled connection outside the organization is refused in the hosted step with OAuth invalid_request through the verified transaction callback; preserve generic no-connection behavior for an empty intersection without an explicit selection — reconciles D-0055 hosted timing with the task error-code requirement — cost if wrong: adjust hosted error transport.
- Task 8: Ruling: shared organization login enforcement lives in internal/orglogin, with the planned public login interfaces wrapping it — avoids the existing login→authz import cycle and allows federation to reuse policy — cost if wrong: move shared policy and update wrappers.
- Task 8: Ruling: no identifier.go edit is required because its existing handlers use the shared loader and authentication path modified in this task — equivalent integration already tested — cost if wrong: add direct identifier coverage or an explicit hook.
- Task 9: Ruling: persist original OrganizationConnectionID on organization codes and refresh tokens, propagate unchanged through rotation, add fields to unreleased migration 0025/proto/codecs; missing legacy organization connection fails closed — sessions can expire/delete before a refresh family, and guessing a linked user primary identity can bypass connection disablement — cost if wrong: two additive storage fields and codec maintenance.
- Task 9: Ruling: organization-aware authorization snapshot helper also feeds the Actions engine frozen RBAC snapshot before flows — otherwise org permissions disappear or change freeze semantics — cost if wrong: adjust shared helper/call sites; event shaping remains Task 10.
- Task 11: Ruling: add read-only local /api/console/tenants operator discovery outside system API, authenticating signed/live operator without requiring system-tenant grant and filtering intersection of token+stored tenant grants; M2M refused, existing system API restrictions unchanged — tenant-only operators otherwise cannot populate switcher without contradicting spec no-system-API rule — cost if wrong: one local endpoint and authentication exception to maintain.
- Task 11: Ruling: system-tenant Users API delete/block/link paths participate in the same tenant-before-user serialization and last-system-admin guard as operator PATCH/delete; blocked/missing identities and tenant-only operators do not count viable fallback admins — otherwise scoped grants introduce alternate lockout paths — cost if wrong: adjust shared guard/call sites.
- Task 13: Ruling: use existing m*.spec.mjs and playwright.config.mjs E2E discovery instead of stale proposed browser/*.spec.ts — ensures new browser cases actually run — cost if wrong: move fixtures when runner conventions change.

## Deferred minor ledger and carry-forward dispositions

These are the ledger's deferred findings and carry-forward notes. A later
implementation may have resolved a carried point; the historical finding is
preserved rather than silently erased. In particular, Task 2 code/refresh
persistence and SQL/gRPC limits were carried to Tasks 3–4; Task 5 rejected
explicit empty display names at the API; Task 6 schema regeneration was carried
to Task 12 and deploy fields to Task 13. Task 7 malformed fixed IDs and bound
prompt behavior were carried to Task 8; the final branch reviewer must weigh
the remaining stored-state edge cases. Deferred polish belongs with Plan 30
unless a different owner is named below.

- Task 1: ⚠️ resolved: no Auth0 calls by implementer (dispatch forbade it; observer was a separate subagent); Deploy CLI dependency ruled above.
- Task 1: minor (deferred): inventory test asserts presence not values; GET /users/{id}/organizations classified documented though observed; spec §12 "empty fields returns all but roles" unsupported by notes; plan Tasks 2/6/7/8/12 stale defaults (covered by precedence bullet + briefs); inventory accessors re-parse JSON per call.
- Task 2: minor (deferred): empty display_name defaulted at store level (mgmt must 400 explicit empty — carried to T5); hex colour edge tests; Limit() panics on unknown name. Carried to T3: OrganizationID code/refresh round trip, sql OrgLimitSetter, remove RunExcept skip.
- Task 4: minor (deferred): 4 in task-4-review.md; process-plugin Limits subtest skips (SetOrgLimits not on protocol).
- Task 5: minor (deferred): 6 in task-5-review.md.
- Task 6: ⚠️ resolved: console schema.d.ts regen carried to T12; deploymigration client org fields carried to T13.
- Task 6: minor (deferred): 6 in task-6-review.md incl. old-plugin deny client echoes behavior/methods without storing.
- Task 7: ⚠️ resolved: names-flag write path = Plan 19 top-level tenant setting key, round-trip tested in T6.
- Task 7: minor (carried to T8): bound mode re-check covers usage but not behavior; OrgFixed with empty OrgID passes re-check (unreachable).
- Task 11: minor (deferred): overlapping tenant discovery refreshes can finish out of order and restore an outdated menu entry after a newer failure (backend authorization remains enforced); existing bundle-size advisory; RFC source reachability failures disclosed.
- Task 12: minor (deferred): more regression coverage for branding/metadata clearing and member-role removal; existing npm/Vite advisories.
- Task 13: minor (deferred): inherited NO_COLOR/FORCE_COLOR Playwright environment warning (runner line70), no skipped checks.

## Exact Task 1–7 reviewed minor details

The ledger references these review files; their full minor sections are copied
here so their individual details survive deletion of the ignored workspace.
These are historical scoped-review findings, not a claim they all remain open.
Task 5's Important errorCode finding was fixed in `718f336`; it is not deferred.

### Task 1

#### Minor
1. inventory_test.go (rules loop, ~L226-L240): rules/fields are checked only for presence and provenance, not values. A wrong frozen value (e.g. name regex) would pass. Assert key values (name_format, patch_replace, scopes).
2. inventory.json: GET /users/{id}/organizations is evidence "documented" although observation notes section 3 observed it; inconsistent with the other 19 operations.
3. Spec §12 "empty `fields` returns everything except roles" is attributed to observation but organizations.md does not record it; mark it local/documented or drop.
4. Plan Tasks 2, 6, 7, 8, 12 still contain superseded defaults (unknown user 400, unauthorized_client for require, connection= invalid_request, member-removal cascade); only the precedence bullet protects them. Briefs for those tasks must restate corrected values.
5. inventory.go: each accessor re-parses ~1170 lines of JSON per call; fine now, but cache a parsed copy and deep-copy if called on hot paths later.

### Task 2

#### Minor (Nice to Have)
1. rules.go:135 / memory/organizations.go:945: Update silently defaults an empty DisplayName to Name, so a PATCH with display_name "" would succeed at store level (observed 400). Mitigate in the Management layer, or add a strict flag.
2. types.go AuthCode/RefreshToken OrganizationID: no storetest round-trip asserts persistence (memory works only by struct copy in clone.go:128,169). Add one in the AuthCodes and RefreshTokens suites before SQL work in Tasks 3-4.
3. storetest/organizations.go:2432: the Limits subtest silently skips for non-OrgLimitSetter stores, so SQL/gRPC could ship with no cap coverage. Make Tasks 3-4 implement the setter.
4. rules.go:70: the hex color regex accepts only #rgb and #rrggbb; the inventory says only "HTML hex colors". No test for 8-digit or missing "#", and no evidence the 3-digit form was observed.
5. rules.go:81: Limit panics on an unknown name. Fine now, but cover it with a test that every Limit() name used exists in the inventory (the tests only reach some names).

### Task 3

#### Minor (Nice to Have)

1. **organizations.go `AddMembers` (the INSERT into `organization_members`): a duplicate-key error is returned raw.**
   - The insert is neither passed through `t.s.conflict` nor treated as already present.
   - When `AddMembers` runs inside a caller's `WithTx` on MySQL REPEATABLE READ after that transaction made a plain read, the read view predates the tenant lock. The `COUNT(*)` can then miss a member another transaction committed, and the INSERT fails with error 1062. That breaks idempotency and surfaces as an untyped error.
   - The same pattern applies to the `ChangeMemberRoles` INSERT into `organization_member_roles`.
   - Fix: treat a mapped `ErrConflict` on these INSERTs as success, or use the dialect's insert-ignore form.
2. **organizations.go `List`: every page request loads and decodes all organizations of the tenant (up to the 10,000 cap), including branding and metadata JSON.**
   - Fix: select only `id, name, display_name, created_at` to order and page in Go, then fetch full rows for the page's IDs. Checkpoint mode without a sort (creation order) could also page in SQL.
3. **Migrations 0025 (all three) declare the `organization_id` column as `NOT NULL DEFAULT ''`, but the brief says "nullable, default empty".**
   - NOT NULL is the better choice: it scans into a plain `string`, and the legacy-row test proves the default applies.
   - Record the deviation in the plan or decision log so the brief and the schema agree.
4. **organizations.go `SetOrgLimits`: does nothing on a Store whose `orgLimits` is nil (one not built by `Open`).**
   - A test calling it on such a Store would silently keep the frozen limits.
   - Fix: lazily allocate the pointer, or document this on the interface. The current comment only covers reads.
5. **connections.go:110-115: the comment says the new `lockRBAC` orders this delete against Organizations writes.**
   - `clearProtectionIfTenant` already locks the same tenant row first (protection.go:30-37), so the new call is redundant.
   - Fix: either drop it or reword the comment to say it is defensive, so later readers do not take it for the operative lock.

### Task 4

#### Minor
1. app.go:~170: the warning says "Organizations are disabled" even for a transient probe error (not cached, so a later probe can succeed). Reword or distinguish by isOrgUnavailable.
2. organizations_test.go: the RoundTrip test delegates "every method" to the conformance suite; its own assertions cover only a subset. Acceptable, but the claim relies on storetest.
3. organizations.go: OrganizationsSupported probes with a 5s timeout and no singleflight, so concurrent first requests each probe. Cosmetic.
4. Client{} literals created without orgCap would nil-deref in cacheOrgCapability. Checked constructors: only NewClient and WithTx set it; no other literals found in the diff.

### Task 5

#### Minor (Nice to Have)

1. `internal/orgrules/inventory.json:536`, `:559`, `:582`: GET-one, PATCH and DELETE on `/connections` are labelled `"evidence": "observed"`. Only the list, the totals shape and the POST 409 were observed (observations lines 194-198), and D-0055 itself says "local where unobserved". Relabel them `local`.
2. `docs/compat/decisions.md:1522`: the D-0055 **Deferred** list still lists `/connections` and "organization client grants" under Plan 30, with no superseded marker. The earlier ruling paragraph got one. Add a marker, or say that only the client-grant writes remain deferred.
3. `internal/mgmt/organizations.go:98`: an unknown or repeated query parameter returns 400 `invalid_query_string`. This is plausible and matches `actions.go:94`, but it is not observed for organizations and not recorded in D-0055 as local. It also refuses the documented `include_client_association_for`, which node-auth0 sends whenever a caller sets it. Record both in D-0055.
4. The spec says the connection must be "one the tenant can log in with" (design line 304). The code enforces only that the connection exists, plus the strategy flag rules. That is defensible against the observation and the public reference, but no decision records the interpretation. Add a line to D-0055, or correct the spec.
5. `internal/mgmt/organizations.go:329-335`: the conditional `create:organization_connections` check runs after full body validation. A caller without the scope gets 400 for a malformed body before 403. `enabled_connections: []` or `null` also triggers 403 (pinned by `mgmt_organizations_test.go`, "conditional" case). Neither ordering nor the empty-array case is observed or recorded. Record it in D-0055, or check the scope as soon as the key is present and before the remaining validation.
6. `internal/mgmt/organization_connections.go:195`: when a link outlives its connection, the `ErrNotFound` goes through `orgError` (`organizations.go:43`) and becomes "No organization found". The organization exists, so this is misleading. It is safe only if connection deletion cascades the links (see the ⚠️ above). Map it to `errConnectionNotFound`, or skip the entry.

### Task 6

#### Minor (Nice to Have)

1. **An old plugin silently drops behavior and methods on deny clients** (`internal/mgmt/clients.go`, the `orgUsageSet` assignment in readClientBody; the 501 check in CreateClient and UpdateClient).
   - On a plugin without Organizations, `{organization_usage:"deny", organization_require_behavior:"pre_login_prompt", organization_discovery_methods:[...]}` is accepted. The 200/201 response echoes the values from the in-memory client, but the plugin cannot persist fields 21–23, so a later GET does not show them.
   - The settings are inert for deny, and a 501 here would break deploy-cli imports. Even so, the write is acknowledged and then lost.
   - Fix: at least document it (D-0055 or the proto comment). Better: when `!OrganizationsSupported`, clear the two fields before the response so the echo matches what is stored.
2. **Effective roles refuse `page`, `per_page` and `include_totals` with 400, while role members ignore them** (`organization_members.go`, `ListOrganizationMemberEffectiveRoles` → `checkpointQuery(r, "from", "take")`).
   - Neither behavior is observed for effective roles, and the two checkpoint-only listings behave inconsistently.
   - Fix: record the choice in D-0055 as a local decision, or strip those parameters the same way `ListOrganizationRoleMembers` does.
3. **`fields=roles` resolves roles one member at a time** (`memberViews` → `memberRoleList` → `GetRole` per role). A page can make up to 100×(1+50) store calls inside one transaction. This is acceptable at the D-0055 limits but worth a batch lookup later.
4. **A skipped deleted user can leave a page short while `total` still counts the row** (`memberViews`). The cascade makes this practically unreachable; noted only because the skip exists.
5. **Coverage gaps:**
   - Nothing tests the device_code grant being added to an existing require client through a grant-only PATCH. Only password and password-realm are tested; it is the same code path.
   - There is no POST test of require with device_code.
6. **A cross-tenant role used as `role_id` on member-role POST is reported as "role does not exist".** This is correct, but `changeMemberRoles` maps every store `ErrNotFound` after the membership check to `errOrgRoleMissing`, so a concurrent member removal is also reported as an unknown role (the comment acknowledges this). Cosmetic.

### Task 7

#### Minor (Nice to Have)

1. internal/authz/organization.go:277-285 (diff): a binding of `OrgMode=fixed` with an empty `OrgID` passes. `ResolveOrganization(..., "")` returns `OrgNone` with an empty ID for an allow client, and `"" == ""`. This is not reachable from request parameters (see injection check), but it is a malformed-state fail-open in a function whose job is to fail closed. Task 9 will key `AuthCode.OrganizationID` off `OrgID`. Fix: refuse `req.OrgID == ""` in the `OrgFixed` case.
2. internal/authz/organization.go:269-276, 286-293 (diff): a later step can still change the mode through config. A bound `OrgNone` is re-resolved from the raw parameter, so a client switched mid-flight to `pre_login_prompt` becomes `OrgPromptBefore` at the post-login step. A bound prompt/picker mode re-checks only `organization_usage`, not the behavior. The likely result is an extra fail-closed path, not a leak. Still, it falls short of "a second step cannot change [the binding]". Consider keeping `OrgNone` once bound (re-checking only that the client does not now require an org), and re-checking the behavior for the prompt modes.

## Task 14 acceptance failure disposition

The initial `make e2e-actions-ii` failed its fourth browser case at
`tests/e2e/m28-actions-ii.spec.mjs:26`: a GET immediately after clicking Save
provider still returned `fixture@example.test` instead of the new sender.
The test's `body` contains `saved` predicate already matched the static
credentials hint ("preserve saved values"), so it did not wait for the write.
`Provider.vue` awaits the write before showing `Changes saved.`. The regression
fix waits for that exact visible success message before reading the provider;
production behavior is unchanged. This real initial failure is RED evidence;
the required sequential rerun result is recorded in the verification table.
The controller approved this scoped test correction before implementation.

## Task 14 self-review and handoff

Documentation diff and relative links are checked before commit. Task 14 does
not perform or dispatch the independent final branch review. Its outcome and
any required fix wave must be appended by the controller before integration.


## Final whole-branch review and I1 correction

The independent review of `0f5be0c..1a3972a` found no Critical issues and one
Important issue, I1: third-party-blocked organizations participated in membership
priority, automatic selection and the 20-choice display limit before application
policy was applied. This could make an otherwise eligible login unavailable.
The correction excludes organizations unless `third_party_client_access` is
`allow` for a third-party client before those decisions. First-party selection
and the existing public `PickerChoices` signature are preserved. All production
picker calculations now use the client-aware shared helper: authenticated session
reuse (including silent login), hosted GET/POST, and the transactional binding
recheck using a freshly loaded client. Existing final binding/token checks remain.

Memory-store regressions cover an allowed membership beside a blocked membership,
a blocked membership beside an allowed auto-enrollment route, blocked-only
interactive/silent errors, 20 blocked memberships sorting ahead of allowed choices,
a forged blocked hosted POST, successful allowed selection through consent/code
issuance, and unchanged first-party behavior. They exercise real production
handlers and memory-store transactions; no authorization outcomes are fabricated.
The final hosted fixture uses the existing strict third-party client and its API
grant. An initial attempted GREEN reached the allowed choice but failed with
`invalid_request` for the fixture's missing API audience; the fixture was corrected
to request its API and complete actual consent. This was a fixture failure, not a
passing verification result. Final tests were also run against pre-fix production
source via an overlay and failed at the expected selection/display assertions.

Final fix commands and their actual results are recorded below. Raw logs are in
the ignored plan workspace `final-fix-logs/`. No separate SQL script, Deploy lane,
or unchanged console suite is repeated by this focused correction. No new upstream
observations were made. The final independent re-review remains controller-owned.

### Final retained minors

The review retained three non-gating issues without changes in this fix:

1. Overlapping tenant discovery can restore an older menu after a newer refresh;
   backend grants remain enforced, and latest-request sequencing is a follow-up.
2. SQL organization paging loads the tenant collection before slicing; lightweight
   paging and batch reads remain bounded performance follow-ups, with no measured SLA
   failure claimed.
3. Older plugins can echo inert deny-client organization settings they discard;
   they cannot enable organization login. Response/capability polish stays deferred.

The following historical triage is copied from the final review so it survives
cleanup of the ignored workspace. References to Minor 1/2/3 refer to the three
retained items above. Earlier review findings, results and rulings elsewhere in
this record remain historical and have not been rewritten.


These dispositions preserve every individual historical minor theme; they do not turn deferred verification into passes. Item numbers refer to the copied review sections in the committed implementation record.

| Origin | Disposition / actual impact |
|---|---|
| T1.1 inventory presence rather than value assertions | Retain low-priority regression-strengthening opportunity; concrete runtime validation and contract tests cover the implemented boundaries. |
| T1.2 users/organizations evidence classification | Provenance-label cleanup; no runtime impact. |
| T1.3 empty-fields observation attribution | Documentation provenance remains weaker than the claim; current local projection is consistent and no data-scope bypass found. |
| T1.4 stale plan defaults | D-0055 precedence and committed implementation record resolve execution intent. Plan status/default prose still needs eventual editorial cleanup. |
| T1.5 reparsing inventory | Cold/configuration path optimization; not measured as a production bottleneck. |
| T2.1 empty display-name normalization | API explicitly rejects an empty display_name; store-level default is intentional for unset creation/seed. |
| T2.2 missing code/refresh roundtrip assertions | Carried work completed: durable token binding fields and conformance/codec/migration tests are present. |
| T2.3 limit-test skip | SQL exposes SetOrgLimits; gRPC in-process precondition mapping tests exercise lowered backing-store caps. Process plugin setter is not part of protocol; that skip remains explicitly unclaimed. |
| T2.4 hex edge evidence | Accepted local #rgb/#rrggbb implementation is consistent frontend/backend; broader HTML color provenance/edge-test polish remains minor. |
| T2.5 Limit panic on unknown key | Internal programmer-error API, not request-controlled; value/name coverage could improve. |
| T3.1 MySQL duplicate membership/role insert | Resolved by insertIgnore duplicate-safe SQL, with existing WithTx READ COMMITTED semantics. |
| T3.2 load-all paging | Retained as Minor 2 above. |
| T3.3 NOT NULL default vs nullable brief | Safe additive choice and documented shipped schema; no runtime fix needed. |
| T3.4 SetOrgLimits on non-Open literal | Test-only malformed construction concern, not supported production initialization. |
| T3.5 redundant connection-delete lock comment | Defensive repeated acquisition of same tenant lock; no behavioral issue. |
| T4.1 transient capability warning | Wording overstates permanence; transient errors are not cached. Minor diagnostic polish. |
| T4.2 roundtrip relies on conformance | Adequate composed evidence; method-level test need not duplicate the suite. |
| T4.3 concurrent first capability probes | Bounded 5-second probes can duplicate work; minor singleflight opportunity. |
| T4.4 nil orgCap on manual Client literal | Supported constructors initialize shared state; no production construction path found requiring a fix. |
| T5.1 EA evidence labels | Preserve observed/local distinction cleanup; not a behavior gate. |
| T5.2 deferred paragraph still names implemented subset | Later Task 5 ruling and Organizations guide clarify subset; stale list is editorial debt. |
| T5.3 unknown query/local choice and include_client_association_for | Strict rejection is documented in guide, unsupported association option explicitly deferred. Additional D-0055 attribution polish remains minor. |
| T5.4 connection strategy existence vs usable allowlist | Runtime login intersects actual usable connections; stored unsupported-strategy link does not enable unsupported authentication. Guide explains no extra create allowlist. |
| T5.5 conditional scope validation ordering/empty array | Scope is still required whenever enabled_connections is supplied; earlier body error reveals no protected data. Preserve local-contract documentation cleanup. |
| T5.6 deleted connection listing error text | Cascades prevent persistent dangling links; a concurrent delete across separate list/read operations can still yield a misleading 404. Cosmetic, not isolation failure. |
| T6.1 old-plugin deny-client echo | Retained as Minor 3 above, now explicitly documented. |
| T6.2 checkpoint-only query inconsistency | Frozen/local handling differs by endpoint but does not break supported clients; provenance clarification remains minor. |
| T6.3 member roles N+1 joins | Bounded but potentially many calls at maximum page/role sizes; batch-read optimization follow-up, no demonstrated outage. |
| T6.4 short member page after user deletion | Concurrent deletion can shorten a page under READ COMMITTED; no foreign data returned. Cosmetic count consistency. |
| T6.5 device-code create/grant-only test gap | Shared CheckOrganizationGrants checks all three forbidden grant types in Normalize; missing dedicated combinations remain small coverage debt. |
| T6.6 removal racing role assignment error | Failure remains atomic/fail-closed; role-vs-member 404 text can be misleading. |
| T7.1 empty fixed organization ID | Resolved: bindOrganization explicitly rejects empty OrgID. |
| T7.2 prompt/picker config changes | Prompt/picker behavior is now rechecked. OrgNone can be re-resolved after configuration changes, but cannot acquire an unauthorized org and may only add an interaction/refusal; retained fail-closed behavior. |
| T11 overlapping discovery | Retained as Minor 1 above. |
| T11 bundle advisory | Existing nonfatal production-build size notice, not a functional defect. |
| T11 RFC source reachability | Historical failure superseded by recorded Task 14 check-sources passes; do not rewrite historical result. |
| T12 branding/metadata clearing and role-removal coverage | Implementation paths reviewed; dedicated console regression expansion remains minor. |
| T12 npm/Vite notices | Recorded as notices, not passes of an additional security or dependency audit. |
| T13 NO_COLOR/FORCE_COLOR notice | Inherited runner configuration warning; no functional blocker. |

### Final controller rulings on declined review areas

These controller decisions are preserved verbatim from the final progress ledger;
they supplement, and do not replace, the 15 historical task rulings above.

```text
Final: Ruling: rely on frozen D-0055 clean-room observations rather than new live Auth0 probes — sufficient authorized contract evidence — cost if wrong: later upstream drift requires parity followup.
Final: Ruling: retain documented refusals/defaults for Plan30 invitations, discovery, grants, search, entitlement and change-password context — explicitly deferred scope — cost if wrong: those client workflows remain unsupported until Plan30.
Final: Ruling: keep the documented EA connection compatibility subset without full access-level semantics — pinned Deploy export/import requirement is met — cost if wrong: clients needing further EA behavior wait for Plan30.
Final: Ruling: keep client-credentials organization tokens/quotas deferred with parameter refusal — owned by later plan — cost if wrong: unsupported machine organization workflows.
Final: Ruling: leave groups/inherited roles, SAML/WS-Fed org login and My Organization API to their stated plans — no current implementation promised — cost if wrong: those workflows remain unavailable.
Final: Ruling: report Deploy member/member-role and upstream migration coverage unavailable — pinned tool lacks exports and no observer lane ran — cost if wrong: manual migration or later tool support needed.
Final: Ruling: support additive forward migration and legacy rows, not mixed-version writers or rollback — existing deployment contract — cost if wrong: rollback/mixed-writer deployments need a separate migration design.
Final: Ruling: retain earlier unknown/application-disabled connection rejection as the recorded Plan1 followup — avoids changing all existing authorization flows — cost if wrong: clients receive earlier invalid_request than Auth0.
Final: Ruling: preserve expiry-based existing access-JWT semantics after member removal/blocking — next login/refresh and operator stored grants are the scoped guarantees — cost if wrong: previously issued JWT remains valid until expiry.
Final: Ruling: preserve existing Actions event.authorization.roles names while org-aware permission union and event.organization are implemented — no new role-name API semantics specified — cost if wrong: Actions relying on org role names need a later parity change.
Final: Ruling: retain bounded SQL paging/N+1 performance costs as minors without inventing an unmeasured SLA failure — no benchmark regression demonstrated — cost if wrong: large tenants may need pagination optimization.
Final: Ruling: audit authored schemas/codecs and reproducible generated output rather than minified/protobuf bulk line by line — generated consistency checks and roundtrips cover wire behavior — cost if wrong: generator-specific defects may need followup.
```

### Final fix verification

All Go commands below use `GOTOOLCHAIN=go1.26.7`. The overlay maps only the
three changed production files to their original `1a3972a` contents; the final
regression tests are unchanged. Logs are under the ignored plan workspace's
`final-fix-logs/` directory.

| Command | Actual result / log |
|---|---|
| `go test -count=1 -timeout=5m ./internal/authz ./internal/login -run '^TestOrganizationPickerClientPolicy'`, before production changes | Expected RED, exit 1: six authz selection failures and hosted blocked choices displayed (`red.log`) |
| Same focused command, initial attempted GREEN | FAIL, exit 1: authz passed; hosted fixture reached allowed selection but omitted its required API audience. Fixture corrected as described above; no pass claimed for this attempt |
| Same focused command, corrected fixture and fix | PASS, exit 0: authz 0.348s, login 0.066s (`green.log`) |
| `go test -overlay="$PWD/.superpowers/sdd/2026-10-28-zeroauthy-plan-29-organizations/final-fix-logs/red-overlay.json" -count=1 -timeout=5m ./internal/authz ./internal/login -run '^TestOrganizationPickerClientPolicy'` | Expected RED, exit 1 with final fixture against original production: same six authz selection failures and hosted blocked-choice failure (`red-final-fixture.log`) |
| `go test -race -count=1 -timeout=20m ./internal/login ./internal/authz` | PASS, exit 0: login 46.378s, authz 14.779s; no race report (`affected-race.log`) |
| `make e2e-organizations` | PASS, exit 0: node-auth0 7.4.0 and auth0-cli 1.37.0 checks plus all seven real browser cases, 5.6s (`e2e-organizations.log`) |
| `ZA_REQUIRE_NODE=1 go test -race -timeout=50m ./...` | PASS, exit 0: 73 packages (56 cached, 17 executed), 22 without tests; sqlstore 847.402s, no failure or race report (`go-race.log`) |

The original Task 14 failed Actions II attempt, all skips/unavailable coverage,
and historical results above remain unchanged. The existing Playwright
NO_COLOR/FORCE_COLOR advisory appeared again without failing the organization
lane. No separate SQL-script, Deploy, console or other broad rerun was made by
this correction. Final independent re-review and integration remain controller-owned.


## Final scoped re-review and handoff

The independent reviewer approved `1a3972a..9bdc8b5`: I1 is addressed, all
production choice paths apply the shared client policy before selection and
truncation, and the fix introduces no new Critical, Important or Minor finding.
The reviewer checked the recorded RED/GREEN, full affected-package race, seven
organization browser cases and final 73-package Go race evidence without repeating
the suites. The full earlier three-dialect SQL, console, eight E2E lanes and local
conformance results remain recorded above.

Plan 29 Tasks 1–14 and the final review gate are complete. The branch
`plan-29-organizations` is preserved in `/mnt/nvme2/code/zeroauthy-plan-29` for
maintainer review. No merge or push was performed. Deferred minors, all controller
rulings and unavailable coverage remain explicit in this record.
