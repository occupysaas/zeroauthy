# Plan 24 — Social Connections Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Google, custom OAuth2 and basic back-channel OIDC usable through compatible connection management, hosted login, identity/token storage and console controls.

**Architecture:** A federation service stores single-use upstream attempts and resumes the existing login/authorization flow. Strategy adapters and a brokered profile runner perform bounded provider calls. A transactional identity index and separate wrapped token repository preserve identity ownership across provisioning, import and explicit linking.

**Tech Stack:** Go 1.26.7, existing JOSE/keys wrapper, restricted Node runner, memory/SQLite/PostgreSQL/MySQL/gRPC, OpenAPI/protobuf generation, Vue/TypeScript, Vitest, Playwright and pinned Auth0 clients.

**Spec:** [Social connections design](../specs/2026-10-26-zeroauthy-social-connections-design.md). Read both documents. Task 1 inventory is complete with a passing contract check; provider/runtime implementation and remaining acceptance tests are pending. Baseline is the completed Plan 23 implementation, including its final acceptance fixes.

## Global Constraints

- Keep Go 1.26.7 and the existing Vue/TypeScript toolchain; no new production OAuth framework. Follow `CLEAN_ROOM.md`; original UI and copy only.
- Implement `google-oauth2`, `oauth2`, and `oidc` with `type: back_channel`. OIDC remains enterprise (`isSocial: false`); Plan 36 retains its remaining features.
- No automatic email linking, development keys, arbitrary npm, upstream refresh worker, Token Vault or federated logout. No runtime success for unsupported authentication-critical settings.
- Provider secrets are write-only in normal reads/exports. Seal credentials and identity tokens with versioned tenant/connection-bound AAD. Explicit secret reinjection is part of migration.
- State and nonce: 32 random bytes; upstream S256 PKCE; attempt TTL is min(original transaction expiry, five minutes). Browser query limit 16 KiB. Config changes invalidate outstanding attempts.
- Production requests: HTTPS, public pinned addresses, no redirects/environment proxy; 10 seconds/request, 30 seconds callback work, 1 MiB decoded response. Profile/token/script limits each 64 KiB; subject limit 1024 UTF-8 bytes; 100 JWKS keys.
- OIDC initially RS256 only, 60-second clock skew. Cache TTL at most five minutes, 256 entries/process, tenant+connection+revision+issuer keyed; one coalesced unknown-kid refresh.
- Script runner requires Node 25+ and a real network-denial capability probe; unavailable capability disables custom OAuth only, with no unsafe fallback.
- Script runner: 64 MiB heap, five-second deadline, eight executions/tenant, 64 globally, four broker GETs/execution. No direct networking/files/processes/imports; logs discarded.
- Public IDs can exceed existing MySQL user_id VARCHAR(255) columns when subject length reaches 1024 UTF-8 bytes. Task 3 must cover users and every dependent ID column/index, with cross-driver boundary tests and no truncation.
- All persistence changes cover memory, three SQL dialects and additive gRPC; no network call inside a store transaction. Old writers are drained before enabling new identity semantics.
- No real provider/tenant calls in CI. Separate authorized observer only; unavailable evidence is never passing. Plan 19's database-test hold applies only to Plan 19, not this plan.

## Review Focus

1. Two provider subjects share email or a linked/imported identity changes owner during callback: subject index wins without merging or resurrecting deleted accounts (Tasks 3, 7, 9).
2. A legitimate browser returns to another alias, an expired domain or a changed connection: reject before exchange or before local commit, retaining exact origin/configuration binding (Tasks 4, 9).
3. Discovery/JWKS/script URLs rebound to internal networks or disclose tokens through redirects/errors: reject on the actual dial and redact all outputs (Tasks 5, 6, 8).
4. Token exchange succeeds but callback or SQL commit fails: no exchange retry, duplicate session or stale credential overwrite; restart safely (Tasks 3, 9).
5. CLI export omits credentials or external script bodies while appearing successful: strict comparisons and explicit reinjection detect omissions (Task 11).

## File and dependency map

- New `internal/federation/`: inventory, strategy validation, provider adapters, network policy, attempt orchestration and identity/profile service. Keep each responsibility in a separate small file.
- New `internal/federation/script/`: dedicated runner lifecycle, broker and protocol; reference `internal/customdb` without changing its database runtime contract.
- New `internal/store/federation.go`, memory/SQL/gRPC repositories and `pkg/storetest/federation.go`; modify user persistence/index maintenance and public aliases. Migration `0021_federation.sql` in each dialect.
- Modify `internal/connrules`, `internal/seed`, `internal/mgmt`, `internal/jobs`, `internal/authz`, `internal/login`, `internal/server`, `internal/app`, `internal/hostedlogin`, `internal/ui` and `internal/i18n` only for their integration responsibilities.
- Console: new `console/src/pages/connections/social/` components, existing router/connections/client enablement and enterprise route.
- New `tests/e2e/social/` mock-provider/harness, `m24-*` clients/browser tests and runner; extend existing deploy fixtures/comparator.

Dependency order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12. This order keeps storage/security contracts stable before integrating login. Commit each completed task with only its named files; do not use broad staging over unrelated work. Each test below is a required new assertion, not an assertion that a named test already exists. Expected results are prospective.

## Task 1: Freeze compatibility and source inventory

**Files:** Create `internal/federation/{inventory.json,inventory_test.go}`, `docs/compat/observations/social-connections.md`; modify `docs/compat/{changelog-review,decisions}.md` and these two design documents if source confirmation requires changes.

**Interfaces:** Inventory rows define strategy/field/type/default/validation/secret classification/runtime status and operation/scope/response shape. Later tasks consume these decisions, not SDK guesses.

- [x] Write `TestFederationInventory`: assert all three strategies, back-channel-only OIDC, supported Google scope flags, OAuth script API, ID formats, PATCH semantics, individual-user token projection and unsupported option dispositions. Missing inventory must fail.
- [x] Review the public references in spec §2, Management connection/user references and changelog since October 22. Freeze actual option spellings, refresh-token field shape, provider-specific ID format, `read:user_idp_tokens` and upstream parameter support. Resolve public-ID delimiter/collision rules explicitly. Record source URLs and reviewed date; do not invent live observations.
- [x] Inspect pinned SDK/CLI/Deploy CLI request and script-file handling under clean-room rules. Record exact commands/resource handlers and license provenance. Confirm Google token endpoint's chosen client auth and S256 behavior from provider docs.
- [x] Record separate observer results if available; otherwise explain unavailable observations and local deviations. Complete review without claiming the oversized changelog retrieval succeeded.
- [x] Run `go test ./internal/federation -run TestFederationInventory -count=1`; expect exit 0. Commit `docs: freeze social connection compatibility contract`.

## Task 2: Define strategy rules, models and public contracts

**Files:** Create `internal/federation/{config,types,profile,config_test,profile_test}.go`, `internal/store/federation.go`; modify `internal/store/{types,store}.go`, `pkg/store/store.go`, `internal/connrules/connrules.go` and affected adapters/mocks for compilation.

**Interfaces:** `ParseConfig(spec connrules.Spec) (Config,error)`; `NormalizeProfile(raw json.RawMessage) (Profile,error)`. Config contains strategy, client ID, wrapped-secret reference, URLs, scopes, profile-sync policy, script and immutable issuer binding. Consume the frozen inventory exactly: OIDC options.scopes is a space-delimited string, Google email/profile default true, purpose is authentication.active; reject unsupported domain/authentication-critical parameter overrides. PATCH replaces supplied nonsecret options while preserving an omitted sealed secret. Profile contains Subject and typed optional root attributes (presence is retained). Provider interface: `AuthorizationURL(StartInput) (string,error)` and `Exchange(context.Context, ExchangeInput) (ProviderResult,error)`; result contains Profile and TokenSet, never a local user/session.

Store gains `Federation() Federation`:

```go
type Federation interface {
    IdentityEpoch(ctx context.Context, tenantID string) (int64, error)
    BumpIdentityEpoch(ctx context.Context, tenantID string) error
    CreateAttempt(context.Context, *FederationAttempt) error
    GetAttempt(ctx context.Context, tenantID, stateHash string) (*FederationAttempt, error)
    ClaimAttempt(ctx context.Context, tenantID, stateHash, cookieHash, origin string, now time.Time) (*FederationAttempt, error)
    FinishAttempt(ctx context.Context, tenantID, stateHash string) error
    PutIdentity(ctx context.Context, key FederatedIdentityKey, userID string) error
    DeleteIdentity(ctx context.Context, key FederatedIdentityKey, expectedUserID string) error
    GetTokens(ctx context.Context, key FederatedIdentityKey) ([]byte, error)
    PutTokens(ctx context.Context, key FederatedIdentityKey, sealed []byte) error
    DeleteTokens(ctx context.Context, key FederatedIdentityKey) error
    DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
```

`FederatedIdentityKey{TenantID,ConnectionID,Subject string}`. Users gains `FindByIdentity(ctx context.Context, tenantID, connectionID, subject string) (*User,error)`. Connection gains `FederationRevision int64` and `FederationSecretsSealed []byte`. Tenant gains durable IdentityEpoch int64, incremented transactionally on user deletion or identity removal/transfer. Attempt captures IdentityEpoch and includes StateHash, TenantID, TransactionID, ConnectionID, Revision, CookieHash, Origin, CallbackURL, Issuer, endpoint snapshot, SealedProof, ExpiresAt and Status (`pending`, `claimed`, `finished`). Create invalidates the preceding attempt for its transaction atomically; claim returns copies and rejects wrong bindings or expiry; finish requires claimed/current. Index reassignment uses delete(expected owner)+put in one transaction; conflicting put returns ErrConflict. All methods obey existing store transaction semantics.

- [ ] Write `TestFederationConfig` table cases for strategy dispatch, missing/empty secrets, immutable binding, invalid endpoints/scopes, unsupported front-channel and ignored critical options. Write `TestFederationProfile` for absent versus false verification, missing subject, 1024-byte boundary and forbidden metadata fields.
- [ ] Run `go test ./internal/federation -run 'TestFederation(Config|Profile)' -count=1`; observe missing contracts/validation failures.
- [ ] Implement typed rules using spec §§3, 5–7. Keep database defaults confined to database strategy. Add explicit immutable binding/config revision rules and exported model aliases; compile affected adapters with stubs that return unsupported until Task 3.
- [ ] Repeat the focused tests; expect pass. Run `go build ./...`; expect compile success. Commit `feat: define federation configuration and store contracts`.

## Task 3: Persist attempts, identity ownership and sealed tokens

**Files:** Create `internal/store/memory/federation.go`, `internal/store/sqlstore/federation.go`, three `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0021_federation.sql`, `internal/store/grpcstore/federation.go`, `pkg/storetest/federation.go`; modify store constructors, users/connections/sweep repositories, `proto/store/v1/store.proto`, generated files and gRPC codecs.

**Interfaces:** Fully implement Task 2 contracts on transaction-bound repositories. Preserve monotonic connection revision; index uses binary/case-sensitive subject comparison in every dialect. Store tokens as opaque bytes. SQL uses row/unique constraints, not process mutexes, for cross-replica claim/provisioning.

- [ ] Add shared `Federation` conformance cases: duplicate state, wrong cookie/origin, expiry equality, superseded attempt, concurrent claim exactly one winner, rollback, index conflict/owner transfer, deep copies, ciphertext isolation, sweep and tenant deletion. Assert epoch increments roll back with failed deletion and old attempts fail after committed deletion/transfer, while a fresh attempt can provision again. Add independent-SQL-handle race cases and old gRPC server Unimplemented failure.
- [ ] Run new memory cases RED, then implement memory and SQL migration/repositories. Backfill existing social identities from unambiguous connection references; stop migration on duplicate ownership or unresolved identities. Preserve database email login indexes; exclude federated email/username from uniqueness. Add upgrade tests with existing database and imported/linked identities.
- [ ] Add additive protobuf messages/RPCs and generated code, transaction routing, client/server codecs and public storetest registration. No plaintext token codec fields.
- [ ] Run `go test ./internal/store/memory/... ./internal/store/grpcstore/... ./pkg/storetest/... -count=1` and `./scripts/test-sql.sh ./internal/store/sqlstore/... -timeout=30m`; expect all selected lanes pass. Run generation twice and verify generated files are stable. Commit `feat: persist atomic federation attempts and identities`.

## Task 4: Manage and seal connection configuration

**Files:** Create `internal/federation/secrets.go`, `internal/mgmt/social_connections_test.go`; modify `internal/connrules/connrules.go`, `internal/mgmt/connections.go`, `internal/seed` connection handling, `internal/keys` sealing helpers, `api/management.yaml` and generated API files.

**Interfaces:** `SealCredentials(w keys.Wrapper, tenantID, connectionID string, credentials Credentials) ([]byte,error)` and matching `OpenCredentials(...) (Credentials,error)`. `Credentials` holds ClientSecret only initially. Shared mutation helper validates immutable binding and increments revision in the transaction that persists effective changes.

- [ ] Write `TestSocialConnectionsContract` for each strategy's CRUD/filter/enabled clients, unknown inert options, immutable issuer/client/discovery/OAuth endpoint/script binding, first-discovery issuer CAS, missing versus empty secret, seed ownership and secret omission in all field projections. Verify disable/credential/scope changes invalidate pending attempts; rejected changes leave revision intact.
- [ ] Run `go test ./internal/mgmt -run TestSocialConnectionsContract -count=1`; observe RED.
- [ ] Integrate strategy dispatch and API/seed validation, seal before writing, redact reads/errors and remove obsolete plaintext copies. Extend OpenAPI/source metadata and generation. Do not modify database options/PATCH behavior accidentally.
- [ ] Run focused management, connrules and seed tests; expect pass and database regressions unchanged. Commit `feat: manage encrypted social connection settings`.

## Task 5: Implement safe provider transport and OIDC/Google adapters

**Files:** Create `internal/federation/{transport,discovery,oidc,google,oauth2,transport_test,oidc_test,google_test,oauth2_test}.go`.

**Interfaces:** `NewTransport(policy NetworkPolicy) http.RoundTripper`; policy injection is construction-only. Provider implementations satisfy Task 2. OAuth code exchange returns tokens for Task 6 mapping; Google and OIDC return validated Profile directly. Cache keys include tenant, connection, revision and issuer.

- [ ] Write `TestFederationTransport` asserting private/mixed/rebinding DNS, redirects, oversized decoded responses, slow bodies and proxy environment cannot bypass policy. Test fixture-only loopback transport separately.
- [ ] Write `TestOIDCValidation` for valid exchange, wrong signature/iss/aud/azp/nonce, expired/future token, missing subject, none/HS256, JWK ambiguity, unknown-kid rotation, cache limits and mismatched UserInfo sub. Write `TestGoogleAdapter` for fixed endpoints, documented issuer aliases, email/profile scope mapping and rejection of unsupported Google domain restrictions; hd remains a provider hint only. `TestOAuthExchange` verifies S256, exact callback and one client-auth method.
- [ ] Run `go test ./internal/federation -run 'Test(FederationTransport|OIDCValidation|GoogleAdapter|OAuthExchange)' -count=1`; observe RED.
- [ ] Implement bounded transport, caches, code exchanges and validation under spec §5. Freeze endpoint snapshot and expected issuer at start; no code retry or dynamic token-header key lookup.
- [ ] Repeat focused tests with `-race`; expect pass. Commit `feat: add bounded OAuth and OIDC provider adapters`.

## Task 6: Execute custom OAuth profile scripts

**Files:** Create `internal/federation/script/{runner.go,runner.mjs,broker.go,runner_test.go,broker_test.go}`, `internal/federation/script_profile.go`; reuse lifecycle knowledge from `internal/customdb` without enabling its unrestricted network path.

**Interfaces:** `script.Executor.Execute(ctx context.Context, req Request) (json.RawMessage,error)` and `Close() error`; Request contains TenantID, ConnectionID, Source, AccessToken and bounded JSON Context. Broker GET requests carry an execution ID bound to the originating tenant/connection, never a caller-selected policy.

- [ ] Write `TestProfileScript` for documented callback and request.get success, missing/duplicate callback, invalid profile, timeout, cancellation, malformed protocol, cross-execution leakage and missing runtime and unsupported network isolation disable custom OAuth only, leaving built-in adapters available. Write `TestScriptBroker` for four-call limit, internal DNS/redirect rejection, forbidden modules/direct networking and discarded credential-bearing logs.
- [ ] Run `go test ./internal/federation/script -count=1`; observe RED. Ensure missing Node is a required-runtime failure for this dedicated acceptance lane, not a silent pass.
- [ ] Implement spec §6's separate runner, Node 25+ version and actual forbidden-socket/fetch capability probes, broker protocol and concurrency cleanup. Enforce heap/deadline/output bounds and deny unbrokered network access. Map through NormalizeProfile; no app_metadata/identity override.
- [ ] Run runner/broker tests and existing customdb regressions; expect pass. Commit `feat: run restricted social profile scripts`.

## Task 7: Provision, synchronize and link identities transactionally

**Files:** Create `internal/federation/{identity,identity_test,tokens,tokens_test}.go`; modify `internal/mgmt/{users,user_identities}.go`, `internal/jobs` import paths, user store mutation/index helpers and their tests.

**Interfaces:** `Service.ResolveIdentity(ctx context.Context, tx store.Store, conn *store.Connection, result ProviderResult) (*store.User,error)` runs only inside the caller's transaction, resolves by subject index, applies profile policy and sealed token persistence, and never creates sessions. This task also produces `SealTokens(w keys.Wrapper, key store.FederatedIdentityKey, tokens TokenSet) ([]byte,error)` and matching `OpenTokens(...) (TokenSet,error)` so token persistence is encrypted from its first use. Task 9 owns final eligibility/attempt checks. All existing user writes maintain index ownership atomically.

- [ ] Write `TestFederatedIdentityLifecycle` for first/repeat login, same-email distinct subjects, concurrent provisioning, imported identity, public-ID collision, no email auto-link, blocked user, each sync mode and changed-email verification reset.
- [ ] Add `TestSocialLinkUnlink` asserting explicit authorization, index/token transfer, secondary-profile-only sync, recreated user's login and deletion cleanup. Add import/update/delete cases proving the same index contract; reject ambiguous unresolved imports rather than skipping them.
- [ ] Run focused tests RED; implement identity/profile mapping and same-transaction ownership maintenance across every existing mutation entrypoint. Preserve metadata and version rules. Increment IdentityEpoch on deletion or identity removal/transfer, including linking/unlinking and replacement imports; older attempts fail. Fresh login resolves the current linked owner.
- [ ] Run federation/mgmt/jobs focused tests, shared storetest and SQL identity races; expect pass. Commit `feat: provision and link federated identities atomically`.

## Task 8: Gate upstream token reads and eliminate secret leakage

**Files:** Create `internal/mgmt/idp_tokens_test.go`; modify `internal/federation/tokens_test.go`; modify `internal/mgmt/{users,user_identities}.go`, management scope registration, API schema/source metadata and user export/projection tests.

**Interfaces:** Consume Task 7’s `SealTokens` and `OpenTokens`. Management projection is separate from generic identityJSON and requires the ordinary read scope plus `read:user_idp_tokens`.

- [ ] Write `TestIDPTokenProjection`: no scope → absent; both scopes on individual GET → documented token fields/no-store; lists/search/link/jobs/userinfo/local tokens/console → absent even with token scope. Add `TestFederatedToken` for cross-tenant AAD failure, token replacement, omitted refresh preservation and no update after failed login.
- [ ] Run focused tests RED; implement the frozen inventory's field placement and no-store headers. Do not grant new scope to preexisting clients/operators. Add log/error/export redaction assertions, including encrypted-at-rest bytes inspected through all drivers.
- [ ] Run `go test ./internal/federation ./internal/mgmt ./internal/jobs -run 'Test(IDPToken|FederatedToken)' -count=1`; expect pass with both test groups present. Commit `feat: protect scoped upstream identity tokens`.

## Task 9: Integrate browser federation and existing authorization

**Files:** Create `internal/federation/{service,service_test}.go`, `internal/login/{social,social_test}.go`; modify `internal/login/{login,identifier,device}.go`, `internal/authz/{handlers,flow,validate}.go`, server routing, app wiring, `internal/protection/service.go` and tests, hosted render/widget, UI templates and i18n keys/locales.

**Interfaces:** `Service.Start(ctx context.Context, in StartInput) (string,error)` returns provider redirect URL after persistence; `Service.Complete(ctx context.Context, in CallbackInput) (*Completion,error)` claims/exchanges/validates/commits once. StartInput binds resolved tenant/origin, transaction, connection and cookie; CallbackInput carries the resolved origin, cookie, raw callback values and time. Completion contains only UserID, TransactionID, ConnectionID and the committed session reference. Refactor existing session creation/completion helpers so attempt finish, current epoch/ownership/user-version/config/client eligibility checks, local session creation and transaction consumption commit atomically; then Resume emits the established authorization response from that committed session. Recheck origin/certificate immediately before commit. No second successful completion path. `protection.Service.Begin` gains `social-login` and `social-signup` flow handling that applies IP/CAPTCHA policy without password brute-force or email lookup; callback checks current IP blocks without reserving the start budget twice.

- [ ] Write `TestSocialLoginFlow`: explicit connection, buttons, social-only/mixed apps, hidden buttons, no enabled provider, consent, downstream state/nonce/PKCE, prompt none/login, device flow and origin-bound callback. Test identifier-first/branding/database regression paths. Add `TestSocialProtection` for required CAPTCHA on explicit selection, exhausted IP budget, first-provision registration budget, callback IP block, and provider failure leaving database password counters unchanged.
- [ ] Write `TestSocialCallbackRace`: two independent nodes, replay, wrong browser/tenant/host, superseded state, malformed/duplicate params, timeout after exchange, commit failure, unlink/block/disable/delete/config change during network wait and domain expiry before completion. Assert provider exchange count ≤1 per attempt and at most one session/code completion.
- [ ] Run focused tests RED; implement spec §4 ordering and only resume after transactional eligibility/identity/token/session commit. Compare durable IdentityEpoch, rejecting in-flight attempts after deletion/transfer while allowing later fresh login. Handle provider denial locally with safe localized copy and fresh-retry path. Integrate sweeper cancellation and app shutdown.
- [ ] Run focused login/authz/federation/server tests with `-race`; expect pass. Repeat cross-handle SQL callback races. Commit `feat: complete social login through existing authorization flows`.

## Task 10: Activate console social connection controls

**Files:** Create `console/src/pages/connections/social/{List,Create,Detail,Settings,ScriptEditor}.vue` and adjacent Vitest tests; modify `console/src/router.ts`, shared connection/client controls and enterprise preview routing where defined.

**Interfaces:** Consume existing connection APIs from Task 4; no alternate configuration authority. OAuth script editor uses the frozen supported interface. Basic oidc uses the same components under Enterprise with subset labeling.

- [ ] Write component tests for all strategies, missing credentials, callback instructions, canonical/custom origins, script limits, enablement, secret replace/omit, uncertain writes, stale tenant/navigation replies, dirty drafts, keyboard and narrow layout.
- [ ] Run focused Vitest tests using the repository's console package scripts; observe RED.
- [ ] Implement original accessible controls, reusing existing components where sensible. Never store credentials/tokens in browser persistence; do not show database tabs for social connections. Mark unsupported fields and OIDC scope clearly.
- [ ] Run `make console`; expect lint/typecheck/tests/build pass. Commit `feat: manage social connections in the console`.

## Task 11: Add actual-client and provider browser acceptance lanes

**Files:** Create `tests/e2e/social/{provider/main.go,harness/main.go}`, `tests/e2e/{run-m24-social.sh,m24-node-auth0.mjs,m24-mgmt-cli.mjs,m24-social.spec.mjs}`; modify `tests/e2e/m20-deploy-cli.mjs`, deploy fixtures, Makefile and CI workflow owning existing E2E targets.

**Interfaces:** `make e2e-social` starts isolated mock Google/OAuth/OIDC providers and two zeroauthy nodes; fixture transport is constructor-only. All control operations use actual APIs/clients. Unique ports/output directories prevent existing browser lanes from racing.

- [ ] Add actual pinned SDK/CLI CRUD, enabled-client, token-scope and link/unlink assertions, plus Playwright first/repeat login for all adapters. Verify provider code exchange and signed ID tokens, not fabricated callback success. Include social-only, device, consent, custom domain, branded/identifier-first and negative callback scenarios.
- [ ] Add strict Deploy CLI YAML/directory × generated/preserved credential fixtures containing real connection settings and external OAuth script files. Materialize JS source into directory JSON explicitly; YAML uses a YAML scalar !include or explicit source materialization, since the pinned social handlers do not expand .js path strings. Verify the tool's directory-provisioning/SCIM discovery dependency and empty-enabled-client-list gap explicitly; do not substitute an unsupported successful empty response. Provider secrets are supplied separately and excluded only by explicit path/name rules; changed/missing nonsecret fields/scripts fail comparison. Test restart/update and post-import login for each mode.
- [ ] Run `make e2e-social` and `make e2e-deploy`; expect pass. Record optional real Google smoke as not run unless actually authorized and exercised; no network access to live providers in standard targets.
- [ ] Commit `test: cover social federation with real client tools`.

## Task 12: Verify acceptance, document rollout and review

**Files:** Create `docs/social-connections.md`, `docs/superpowers/2026-10-26-plan-24-implementation-record.md`; modify `docs/compat/{matrix,decisions}.md`, roadmap and follow-ups. Update task checkboxes only for actual completion.

**Interfaces:** Acceptance record maps spec AC1–AC8 to commands/results and explicitly lists unsupported/unavailable lanes. Operator guide covers callback registration per origin, required S256, supported script API, secret reinjection, token scope, network policy, imported identity conflicts, drain/backfill/rollback and future Plan 25/36 boundaries.

- [ ] Inspect spec coverage and all five Review Focus items against implementation/tests. Obtain a fresh whole-branch review; fix material findings and rerun affected checks before final acceptance.
- [ ] Run `go generate ./...` twice (stable output), `make check-sources`, `make console`, `go vet ./...`, `go test -race -timeout=30m ./...`, and `./scripts/test-sql.sh ./internal/store/sqlstore/... -timeout=30m`. Expect exit 0; record actual skips/errors and driver coverage.
- [ ] Run `make e2e-social`, `make e2e-deploy`, `make e2e`, `make e2e-branding`, `make e2e-email`, `make e2e-domains` and `make conformance` with existing local Chromium configuration where required. Record conformance pass/fail/warning/review/skip counts without certification claims. Avoid parallel browser output collisions.
- [ ] Finish operator guide and coverage records; leave optional live Google/upstream observations explicitly unavailable when not run. Preserve earlier Plan 23 claims and add only supported Plan 24 outcomes.
- [ ] Commit `docs: record social federation acceptance and rollout`. Hand back the completed branch with results; do not merge/push or begin Plan 25 without the corresponding instruction.
