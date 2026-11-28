# Plan 40 — Actions III implementation record

Branch: `plan-40-actions-iii`, worktree `/mnt/nvme2/code/zeroauthy-plan40`.
Base: `bffaac2`; previous Tasks 1–5 ended at `dea97ca`.
Status: Tasks 1–9 committed; Task 10 implementation complete, final verification
and whole-branch review pending. Nothing has been pushed. No approval to merge
this branch or PR #108 has been inferred.

## Implementation

| Task | Result |
|---|---|
| 1 contracts | D-0190, inventory, rechecked deferred triggers and custom IDs (`5dee91b`) |
| 2 runner | Session/refresh/linking/method calls, bounds and result plumbing (`a97f35b`) |
| 3 session effects | Atomic session effects, revocation and persistent/ephemeral cookie mode (`6966d14`) |
| 4 refresh effects | Revocation, shortening and ordered metadata; token-grant session effects (`9b422b3`) |
| 5 linking/methods | Shared userlink package, browser session reassignment and external MFA methods (`dea97ca`) |
| 6 event members | Local risk, custom domain, trusted fingerprints, IDs, MFA/reset/session/refresh data (`4fc75c0`) |
| 7 userinfo | Per-session/client custom claims across memory, SQL and gRPC; access tokens carry sid (`33a80d3`) |
| 8 signup/context | Admitted ulp fields, validation regression, custom signup IDs, frozen organization script context (`098cdab`) |
| 9 carried items | Persistent console limit, stronger sandbox probes, branch/expiry/counting-store checks (`96158c3`) |
| 10 acceptance | Requested operation names in console, new browser scenarios, guides and this record; verification pending |

Migration `0054_actions_iii.sql` adds session userinfo-claim JSON in SQLite,
PostgreSQL and MySQL. Cookie mode already existed. Protobuf adds an optional
session claim field and a setter RPC; an old plugin fails closed for an
unsupported claim write. Recheck migration numbering against main before merge.
No Go module, npm dependency or Action was added or updated.

Security-sensitive packages changed: actions/runner, authz, oauth, login,
identity/customdb, config/server, mgmt, userlink and store/plugin codecs.
Review against SECURITY.md and THREAT_MODEL.md covers tenant isolation,
transactional session effects/linking, shortened lifetimes, trusted-only and
bounded headers, claim filtering and log-value omission.

## Verification evidence

- Tasks 1–5: prior ledger reports focused runner, authz, oauth, login, store
  and Management checks passed; their committed work was preserved.
- Task 6: event/config tests failed on missing interfaces, then passed;
  authz/oauth linking/method checks passed. An initial wider compilation
  failed because `/tmp` was full; later checks use `/dev/shm/za40`.
- Task 7: missing claim model/setter tests failed, then userinfo client
  isolation/filtering and gRPC memory/SQLite round trips passed. Actual
  login→refresh integration checks stored claim replacement and token sid.
- Task 8: hosted field filtering/custom ID tests failed then passed. Existing
  validation/field retention already worked. Context request/frozen Node
  tests failed then passed, including old signatures, tenant isolation and
  empty delete context. Passwordless/legacy refusal checks passed.
- Task 9: aggregate console test failed at 409 characters then passed under
  256; masking still has full transient-output coverage. Sandbox checks
  confirm addon denial codes and sibling ErrUnavailable; they passed.
  Counting-store bypass, result-URL options and dry-run command checks pass.
- Task 10: effect-name backend test failed before the interface was added;
  focused backend and console execution-view checks pass (48 console tests).
  UI test was written first but dependencies were missing; its first runnable
  attempt followed implementation, so no RED claim is made for that test.
- One complete actions/config/actionsrules run passed (Actions 47.119s).
  This preceded later task changes and is not final aggregate verification.
- Two clean `make console` builds passed lint, typecheck, all 102 Vitest files /
  780 tests and production build. SHA-256 manifests match byte for byte.
  The existing >500 kB bundle warning remains.
- Empty-claims old-plugin compatibility regression failed then passed; real
  unsupported claim writes still fail closed.
- SQLite `TestConformance/sqlite/Sessions/UserinfoClaims` passed explicitly.
- First E2E attempt: SDK checks passed; nine browser cases failed at launch
  because pinned Chromium was absent. Installed the pinned shell; rerun passed all nine browser cases, SDK checks
  and Auth0 CLI 1.37.0 checks (exit 0).
- Extended browser acceptance, final fast Go tier, vulnerability scan and
  whole-branch review: pending below.

Final commands keep actual logs and exit codes in this plan's ignored workspace
until handoff; only completed runs will be reported as passing. GitHub Actions
is the full race/SQL/browser/conformance verification and must be green before
maintainer-approved merge. CI monitoring is handed back to the maintainer.

## Rulings carried and made

Task 1: Ruling: api.user.setUserId is now documented (Early Access, https://auth0.com/docs/authenticate/database-connections/custom-user-id, checked 2026-11-28): added to Task 8 per the plan's Step 1 (database connections only, unique within the connection, refused for passwordless/social, overrides the generated id, failure log fs). The four newer trigger IDs remain undocumented and stay deferred (LR40-2) — cost if wrong: one small extra member.
Task 1: Ruling: no Actions type-definition (.d.ts) file exists in the console or runner, so the "type hints" steps (Tasks 1 and 10) have nothing to update; editor hints are out of this plan — cost: none.
Task 3: Ruling: api.session.revoke ends the flow like access.deny (no later Action runs, no redirect suspends it); Auth0 documents revocation 'after the flow' without saying later Actions are skipped — cost if wrong: later Actions' side effects (metadata) are not committed after a revoke.
Task 4: Ruling: event.session now appears on offline refresh exchanges while the family's session is live (spec §6 'where a session exists'), so api.session effects reach refresh grants — cost if wrong: Actions that test event.session to detect browser logins see it on refreshes too.
Task 5: Ruling: setPrimaryUser on token grants (ROPG, refresh, etc.) is refused with access_denied — linking needs the browser session to move; Auth0's token-grant behaviour is not documented here — cost if wrong: an Action that links on ROPG fails instead of linking.
Task 5: Ruling: the race loser is refused with server_error when its flow already finds the secondary gone (access_denied only when it reaches the link step); test accepts any refusal with one winner — cost if wrong: clients see server_error instead of access_denied in a rare race.
Task 5: Ruling: "link log" is a server info log ("linked account from post-login Action"), as the Management link logs details; no tenant log type is documented for Action linking — cost if wrong: no tenant log entry for Action links.
Task 5: Ruling: amr is checked through the code's MFAAt (the minter emits amr=mfa from it); "next login's event.authentication.methods" is covered by the session's AuthMethods, which feed that member — cost if wrong: none expected.
Task 6: Ruling: trusted_ja3_header and trusted_ja4_header are top-level configuration keys, preserving the spec's ZEROAUTHY_TRUSTED_JA3_HEADER / ZEROAUTHY_TRUSTED_JA4_HEADER environment variables with the standard loader — cost if wrong: deployment config uses top-level rather than server keys.
Task 6: Ruling: actor is omitted because delegated/session-transfer sessions are out of scope; ASN is omitted because no ASN source exists. Other stored session/device members are emitted — cost if wrong: Actions requiring delegated actor or ASN data cannot use it yet.
Task 7: Ruling: migration is 0054_actions_iii.sql because 0053 is the current base's latest migration; cookie_mode already exists from earlier plans and is not added again — cost if wrong: must renumber before merge if main gains another migration.
Task 7: Ruling: /userinfo echoes filtered namespaced and private ID-token claims (current Auth0 docs permit private claims); standard profile claims and reserved claims retain precedence. Claims are replaced per client on refresh, including an empty result — cost if wrong: private custom claims may differ from upstream edge cases (X9).
Task 8: Ruling: current Auth0 public docs document enable_script_context with organization {id,name,display_name,metadata}, not the assumed request IP/client/language context. Implement that documented option and shape; preserve old script signatures and refuse disabling the setting — cost if wrong: scripts expecting the plan's speculative request fields do not receive them. Sources: https://auth0.com/docs/authenticate/database-connections/custom-db/create-db-connection and https://support.auth0.com/center/s/article/Can-the-application-name-be-accessed-in-custom-DB-with-the-context-object (checked 2026-11-27).
Task 8: Ruling: custom IDs retain the existing tenant-wide user_id uniqueness constraint (auth0|id); equal IDs on different database connections are also refused — cost if wrong: stricter collision refusal than the documentation's within-connection wording, consistent with the existing normalized subject model.
Task 9: Ruling: 256 Unicode characters (including line separators and the truncation marker) bounds persisted console output after masking. Transient Test output retains its existing 64 KiB bound, preserving full masking regression coverage — Auth0's documented restriction is explicitly persistent storage — cost if wrong: Test returns more output than an upstream test endpoint might.
Task 9: Ruling: followups.md has observation points but no Plan 27/28 minor ledger; use those plans' implementation records for the named carryovers. This task closes the console cap, addon/sibling assertions, CountingStore seam, result-URL branch cases, ticket expiry/aliasing and existing codec sentinel entries; old broad storage/build/Deploy polish not explicitly assigned to Actions III stays in its original record — cost if wrong: remaining historical polish needs separate scope, not silently claimed closed.
Task 10: Ruling: execution records expose requested_effects operation names only, not arguments; UI calls them Requested effects because engine execution precedes transactional login completion — cost if wrong: operators need the associated login outcome to know that linking committed, rather than treating a successful Action execution as a committed link.
Task 10: Ruling: external-only legacy custom databases refuse setUserId; otherwise the next external login would recreate the external profile's original subject. Local and import-mode signup paths support overrides — current docs describe automatic migration, not rewriting an authoritative legacy identity — cost if wrong: a legacy-only signup Action gets a refusal rather than a custom local ID.

## Remaining observation points

D-0190 and followups.md carry X1–X10. No live Auth0 tenant was observed.
The four undocumented triggers, Forms/Flows prompts, session-transfer actors,
ASN/GeoIP and vendor risk signals remain out of scope. Broader historical
Plan 27/28 storage/build/Deploy polish remains in its original records;
Task 9's exact closure scope is recorded in followups.md.

## Final verification and review

Two clean console builds passed (102 files, 780 tests) and match byte for byte.
`make e2e-actions` passed nine browser cases plus the SDK and CLI checks.
The initial browser launch failure and subsequent successful run are preserved
in e2e-actions.log and e2e-actions-browser.log in the plan workspace.
The base's existing Go pin is 1.26.11; the final fast tier uses that toolchain.
`govulncheck` v1.10.0 with Go 1.26.11 exited 0: no vulnerabilities found.
The first full Go aggregate at `07d4096b` exited 1. Failures were the OpenAPI
flow-style description's unquoted comma, a no-bindings session-query regression,
the formerly unsupported setUserId fixture, a full gRPC fixture missing the new
claims map, and two migration assertions still expecting 53. Focused tests now
pass after quoting/regenerating the schema description, avoiding empty session
claim writes, updating the unsupported-method fixture and extending the codec
and migration expectations. A new stale-claims regression also passed after
ensuring the no-runtime path clears previous client claims.
Original full log: `.superpowers/sdd/2026-11-16-zeroauthy-plan-40-actions-iii/fast-go-07d4096b.log`.
Final aggregate rerun, whole-branch review and CI remain pending. No merge
readiness is claimed.
