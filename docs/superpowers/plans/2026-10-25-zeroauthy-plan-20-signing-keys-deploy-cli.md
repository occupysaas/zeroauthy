# Plan 20: Signing Keys and Deploy CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Ship tenant signing-key management and a repeatable, credential-aware Auth0 Deploy CLI configuration migration.

**Architecture:** Extend the existing managed-key lifecycle with durable certificates and atomic result-returning store operations; internal verification remains separate from public-key publication. Add scoped Management API/Settings controls, store custom public JWKS separately, and exercise unmodified deploy-cli through a versioned resource manifest and strict export comparator. Reuse create-only seed for offline credential bootstrap rather than extending public client-create semantics.

**Tech Stack:** Go 1.26.7, existing go-jose/crypto/x509/encoding/asn1 and go.yaml.in/yaml/v3; memory/SQLite/PostgreSQL/MySQL/gRPC stores; OpenAPI/oapi-codegen; Vue 3/TypeScript/Vite; Node >=22.12, auth0-deploy-cli 9.1.0, current pinned Auth0 CLI/SDK and Playwright.

**Spec:** [Plan 20 design](../specs/2026-10-25-zeroauthy-signing-keys-deploy-cli-design.md). Read it, the roadmap's Plan 20 section and `CLEAN_ROOM.md` before execution.

**Status:** Local implementation and available verification complete on `plan20-signing-keys-spec`. Tasks 1–12 are implemented. Both CLI formats and credential modes, console controls, SDK/CLI/browser signing lifecycle, cross-dialect stores and OIDC conformance checks pass within the recorded boundaries. Three CLI handlers are explicitly tool-unsupported; the upstream Auth0 observer lane remains unavailable. The final acceptance record below is authoritative; no live Auth0 observations were made.

## Global Constraints

- Use Go 1.26.7 and the existing Vue 3/TypeScript/Vite console. Add no Go dependency: emit the limited certificate-only PKCS#7 container with the standard library. Pin deploy-cli 9.1.0 and its lockfile; retain other tool pins.
- Keep public API payloads Auth0-shaped, tenant isolation intact, private keys envelope-encrypted, console tokens in memory, and copy original/localized.
- Audit successful management writes with actor, tenant and affected key IDs; never include private material, application secrets or bearer tokens. Reuse the existing post-commit structured audit logger; do not invent a durable audit transaction or claim a logger failure rolls back a committed mutation.
- Custom public keys are stored-only in Plan 20. They must never sign tokens, enter canonical JWKS or authorize tokens presented to zeroauthy. Custom-domain publication belongs to Plan 23.
- Preserve managed `kid`, public parameters and private material on upgrade. No implicit rotation, algorithm expansion, remote signer, scheduled rotation or time-based key pruning.
- Preserve unrevoked previous keys unless Task 1 explicitly resolves conflicting upstream evidence and updates the design. Do not leave the old store's automatic previous→revoked transition unnoticed.
- Every store change includes transaction views, tenant deletion, deep-copy semantics, gRPC codecs/RPCs and public plugin aliases. Missing new plugin RPCs fail closed with an actionable upgrade error.
- Upstream observation is a separate role. Rotation/revocation requires a disposable tenant or authorization for those irreversible changes; upstream migration is export-only. Never capture dashboard/hosted UI or commit raw upstream exports.
- The existing AGENTS.md database hold is scoped to Plan 19. It is neither removed nor extended here. During Plan 20, use focused checks per task and reserve the full cross-dialect/integration suites for Task 12; obey any subsequent repository hold. Deferred/unavailable checks are never called passing.
- All commands below are execution instructions, not commands to run while writing this plan. Stop before product implementation until the user requests execution. Commit only task-owned changes; no automatic merge/push.

## Review Focus

1. Upload a valid attacker-owned RSA key, then present a correctly signed forged Management API/userinfo/logout token: it must still be rejected. Tasks 4–5/11, `TestSigningTrustExcludesCustomKeys` and `TestM20CustomKeyForgery`.
2. Concurrent rotations, revoke after a cached signer, and a request that times out after committing: retain eligible old keys, return each operation's own result and never retry a rotation automatically. Tasks 3–4/10–11, `ConcurrentRotationResults`, `TestSigningRevocationAcrossManagers`, console uncertain-outcome case.
3. Two processes backfill the same old key, or the wrapper fails halfway through startup: no changed `kid`, competing certificate overwrite or fallback rotation. Tasks 3–4, `CertificateCAS`, `TestSigningBackfillFailure`.
4. Export files contain duplicate names, path traversal, unknown fields or a changed scope disguised by ID mapping: fail comparison/preflight without losing data or executing scripts. Tasks 7–9, `TestLoadExportBoundaries`, `TestCompareRejectsLostScope`.
5. A bootstrap is rerun against changed credentials or an API-origin tenant, or a user API has the system exclusion name: fail safely without reseeding defaults or silently omitting resources. Tasks 6–9, `TestBootstrapRerun`, `TestMigrationSystemNameCollision`.

## File and dependency map

| Unit | Ownership |
|---|---|
| Evidence | New `docs/compat/observations/management-signing-keys.md`, `management-deploy-cli.md`; changelog, decisions, spec and this plan. |
| Certificates/rules/model | New `internal/keycert/{certificate.go,pkcs7.go,certificate_test.go}`, `internal/signingrules/{rules.go,rules_test.go}`, `internal/store/signing.go`; existing store types/public aliases. |
| Storage | Existing signing repositories; new `custom_signing_keys.go` in memory/SQL, `signing.go` in gRPC; `0017_signing_keys.sql` in all three migration directories; proto and conformance suites. |
| Runtime/API | Existing `internal/keys/manager.go`; new key lifecycle/backfill files, managed/custom-key handlers and HTTP tests; OpenAPI/generated adapters, scopes, app initialization. |
| Migration | New `internal/deploymigration/{export.go,bootstrap.go,preflight.go}` and tests; new `cmd/zeroauthy/migration.go`; built-in API name/upgrade and retired-resource handlers. |
| Tool contract | New `tests/e2e/deploy-cli/` Go comparator and fixtures, `manifest.json`, Node runner and shell harness; existing npm pins/CI targets. |
| Console/E2E | New Settings key components/tests; `m20-node-auth0.mjs`, `m20-mgmt-cli.mjs`, `m20-console.spec.mjs`, `tests/e2e/signing-server/` shared-store scenarios. |
| Documentation | New `docs/signing-keys.md`, `docs/deploy-cli.md`; existing API/console/compatibility/plugin/roadmap/follow-up records. |

Dependencies: **1 → 2 → 3 → 4 → 5**; **1 → 6 → 7**; **1+7 → 8**; **5–8 → 9**; **5 → 10**; **4–6+9+10 → 11 → 12**. Execute in numbered order for straightforward review. API/console and migration are reviewable units within this single approved roadmap milestone, not separate feature expansions. Create an isolated implementation checkout at execution time if needed.

All new test names below are requirements to add. Existing harnesses are named explicitly. Task 1 may refine wire assertions, but must update this plan before the consuming task; it may not weaken the security/retention/migration boundaries silently.

## Task 1: Freeze endpoint contracts and deploy-cli inventory

**Files:** create the two observation notes above and `tests/e2e/deploy-cli/manifest.json`; modify `docs/compat/{changelog-review.md,decisions.md}`, the spec and this plan.

**Interfaces:** produces evidence rows K1–K3/D1–D2 and manifest schema `{toolVersion, resources:[{name,status,owner,reason,fixture}], normalizations:[{resource,path,rule,reason}]}`. Status is `included`, `excluded` or `tool-unsupported`. Every pinned handler has exactly one entry. Included resources name a nonempty fixture; exclusions name a roadmap owner. Allocate the next free decision ID at execution time.

- [x] **Step 1: Review public sources.** Reviewed the public changelog through 2026-10-25 and all seven key operation references. Pinned deploy-cli 9.1.0 registry/package provenance is recorded in `observations/management-deploy-cli.md`; the handler inventory is in `tests/e2e/deploy-cli/manifest.json`. Existing tool method names and prior sanitized observations are linked there. The minimum fixtures cover clients, resourceServers, clientGrants, databases, connections, tenant and attackProtection.
- [x] **Step 2: Obtain firewalled evidence.** No separate observer report or disposable-tenant authorization was available. No live or irreversible call was made. The evidence notes clearly identify public documentation and local fallbacks; the upstream lane is recorded unavailable.
- [x] **Step 3: Freeze exact assertions.** D-0046 freezes documented scopes/success codes and local contract behavior for unresolved IDs/errors, certificate encodings, timestamps, retention, custom JWKS validation, and the finite retired-resource collection paths. No wildcard compatibility shim is permitted.
- [x] **Step 4: Resolve implementation constants.** D-0046 records stored-only custom keys, no custom-key trust, create-only credential bootstrap, `Auth0 Management API` naming, and certificate policy. The manifest lists every registered 9.1.0 handler key and field-specific normalizations. Live-only behavior remains explicitly unverified.
- [x] **Step 5: Review and commit.** `git diff --check` is required before commit; the evidence files contain no credentials, tenant identifiers or personal data. Commit: `docs: freeze Plan 20 signing and deployment contracts`.

## Task 2: Certificate representation, public-key rules and model

**Files:** create `internal/keycert/{certificate.go,pkcs7.go,certificate_test.go}`, `internal/signingrules/{rules.go,rules_test.go}`, `internal/store/signing.go`; modify `internal/store/types.go`, `pkg/store/store.go`, `pkg/store/store_test.go`.

**Interfaces:** add `CertificateDER []byte` and nullable `CurrentSince`, `CurrentUntil`, `RevokedAt` (`*time.Time`) to `store.SigningKey`. Define `store.SigningKeyRotation{Current,Next *SigningKey}` and `store.CustomSigningKeySet{TenantID string; JWKS json.RawMessage}`. Add aliases now; repository methods arrive together with all implementations in Task 3.

```go
// internal/keycert; PublicCertificate has string Cert, Fingerprint, Thumbprint, PKCS7.
func Create(priv *rsa.PrivateKey, now time.Time) ([]byte, error)
func Describe(der []byte) (PublicCertificate, error)
// internal/signingrules; ManagedKey is the K1 public projection, never private material.
func Project(k *store.SigningKey) (ManagedKey, error)
func ParseCustom(raw []byte) (json.RawMessage, error)
func KeyIDs(raw json.RawMessage) ([]string, error)
```

- [x] **Step 1: Add focused tests.** `TestCertificateIdentity` asserts certificate RSA parameters equal the supplied private key and validity equals `now-5m` through `now.AddDate(10,0,0)`; `TestCertificateEncodings` independently hashes/parses the DER and verifies the K1 representation; `TestCustomSigningValidation` covers 1/10/11 keys, duplicate JSON fields/IDs, private RSA/EC members, symmetric keys, wrong operations/algorithm/curve, bad certificates and URL fields without network requests. `TestManagedKeyProjection` asserts omitted unknown dates and absence of every private field.
- [x] **Step 2: Establish RED.** Run `go test ./internal/keycert ./internal/signingrules -count=1`; expect the newly specified behavior to fail or new symbols to be missing, not an unrelated environment error.
- [x] **Step 3: Implement pure helpers and types.** Use 2048-bit generated RSA keys from the existing manager, a positive random 128-bit certificate serial and neutral subject `zeroauthy signing key`; self-sign with SHA256-RSA. Use SHA-1 only for compatibility certificate fingerprints if K1 requires it. Encode a certificate-only SignedData container, with no signers, id-data content type and absent content per [RFC 5652 §§5.1–5.2](https://www.rfc-editor.org/rfc/rfc5652.html#section-5.2), using `encoding/asn1`; add no general CMS implementation. Validate public JWKs using existing go-jose plus explicit private/unknown-field checks before unmarshalling can discard fields. Preserve validated public fields/ordering according to K3.
- [x] **Step 4: Verify.** Re-run the focused tests and require PASS. Add `TestCertificatePKCS7OpenSSL` using `openssl pkcs7 -print_certs` to compare recovered DER independently; report unavailable OpenSSL explicitly and make it required in Task 12. Verify empty/zero public aliases compile with `go test ./pkg/store -run '^Test' -count=1`.
- [x] **Step 5: Commit** `feat(keys): add stable certificate metadata and public key rules`.

## Task 3: Atomic lifecycle and custom-key storage in every driver

**Files:** modify `internal/store/store.go`, `internal/store/{memory,sqlstore}/signing_keys.go`, memory `{memory.go,tx.go,tenants.go}` and cloning helpers, SQL `{codec.go,tenants.go}`, `internal/store/grpcstore/{codec.go,client_repos.go,server_repos.go}`; create `custom_signing_keys.go` in memory/SQL and `internal/store/grpcstore/signing.go`; add all three `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0017_signing_keys.sql`; modify `proto/store/v1/store.proto` and generated files, `pkg/store/store.go`, `pkg/storetest/{signing_keys.go,tx.go,operators.go,storetest.go}`, plugin docs/tests. Create `pkg/storetest/custom_signing_keys.go` and SQL signing migration tests.

**Interfaces:** extend `SigningKeys` without removing old `Rotate`; add `Store.CustomSigningKeys() CustomSigningKeys`. Use existing `ErrInvalid` for ineligible key state, `ErrConflict` for IDs/collisions, and `ErrNotFound` for absent records; HTTP mapping follows K1/K3. Repeated revoke returns the unchanged revoked snapshot internally so the HTTP layer can implement K2 without altering its timestamp.

```go
// SigningKeys additions. All return detached snapshots from the same committed operation.
Get(ctx context.Context, tenantID, kid string) (*SigningKey, error)
RotateWithResult(ctx context.Context, tenantID string, next *SigningKey, at time.Time) (*SigningKeyRotation, error)
Revoke(ctx context.Context, tenantID, kid string, at time.Time) (*SigningKey, error)
SetCertificateIfAbsent(ctx context.Context, tenantID, kid string, der []byte) (*SigningKey, error)
// CustomSigningKeys repository; absent Get => ErrNotFound; absent Delete => nil.
Get(ctx context.Context, tenantID string) (*CustomSigningKeySet, error)
Replace(ctx context.Context, set *CustomSigningKeySet) error
Delete(ctx context.Context, tenantID string) error
```

- [x] **Step 1: Extend conformance cases.** Added `RotateRetainsPrevious`, `ConcurrentRotationResults`, `RevokeStateAndTimestamp`, `CertificateCAS`, `CustomManagedCollision`, `DeepCopy`, `TenantIsolation` and transaction/deletion cases. Tests verify operation snapshots, first revocation timestamp, certificate CAS winner, detached values, tenant isolation and both sequential/concurrent custom-to-managed collisions.
- [x] **Step 2: Establish RED with memory.** Before implementation, `go test ./internal/store/memory -run '^TestConformance/(SigningKeys|CustomSigningKeys|Tx|Operators)$' -count=1` failed to compile because the new repository methods were missing. The memory implementation then passed.
- [x] **Step 3: Implement all drivers and migrations together.** Added nullable certificate/lifecycle fields and per-tenant custom JWKS storage in migration 0017 for SQLite, PostgreSQL and MySQL. Memory and SQL operations serialize rotation, revoke, certificate CAS and key-ID collision checks; earlier previous keys remain previous. SQL and memory copy values and delete custom sets with tenants/transactions.
- [x] **Step 4: Add gRPC methods.** Added new result-returning Get/Rotate/Revoke/Certificate CAS and custom-set RPCs with `tx_id`, timestamps and detached operation snapshots; existing RPC field numbers and legacy Rotate remain. Old plugins return the plugin-too-old diagnostic. Generated with `go generate ./proto/store/v1`.
- [x] **Step 5: Verify focused suites.** PASS: memory conformance; gRPC conformance, codec and old-plugin tests; `pkg/storeplugin` process conformance; SQL migration/signing conformance. SQL executed SQLite only; no PostgreSQL/MySQL DSNs were configured. The three-dialect matrix and SQL-backed gRPC rollback cases remain for Task 12/11 respectively.
- [x] **Step 6: Commit** `feat(store): persist atomic signing lifecycle and custom public keys`.

## Task 4: Key manager, backfill and runtime trust

**Files:** modify `internal/keys/manager.go`, `internal/{app/app.go,tenantsetup/tenantsetup.go,oidc/handlers.go}`; create `internal/keys/{lifecycle.go,backfill.go,lifecycle_test.go,backfill_test.go}`; extend key manager/app/oidc tests. Inspect all `Keys.Verify`, `Keys.JWKS` and direct JWT verification callers.

**Interfaces:** keep `NewManager(store.SigningKeys, Wrapper)`, `Ensure`, `Sign`, `Verify`, `JWKS` and `Rotate` signatures usable by existing callers. Add the following manager methods; `JWKS` delegates to managed-only `VerificationKeys` for now. Custom-key publication will require an explicit future aggregator, not a modification to internal trust.

```go
func (m *Manager) RotateWithResult(ctx context.Context, tenantID string) (*store.SigningKeyRotation, error)
func (m *Manager) Revoke(ctx context.Context, tenantID, kid string) (*store.SigningKey, error)
func (m *Manager) BackfillCertificates(ctx context.Context, tenantID string) error
func (m *Manager) VerificationKeys(ctx context.Context, tenantID string) (jose.JSONWebKeySet, error)
```

- [x] **Step 1: Add memory-backed regressions.** `TestSigningBackfillIdentity` starts with legacy current/next/previous/revoked rows and pre-upgrade tokens; assert unchanged key IDs/public/private bytes and valid old tokens after fill. `TestSigningBackfillFailure` injects unwrap/CAS failures and asserts no rotation or replacement; retry completes only missing certificates. `TestSigningRevocationAcrossManagers` warms one manager, revokes through another and rejects old tokens on a subsequent Verify. `TestSigningTrustExcludesCustomKeys` uploads a matching attacker signature and expects `ErrInvalidToken`. Add malformed/multiple-signature/missing-`kid`/wrong-`alg`, store-outage and signer-retention cases.
- [x] **Step 2: Establish RED.** Run `go test ./internal/keys -run '^TestSigning' -count=1` and confirm each regression fails for the intended reason.
- [x] **Step 3: Implement lifecycle/backfill.** Generate/encrypt/certify the fresh next key before mutation; return the store's result, never infer it from a later List. Ensure certifies newly generated keys and calls the idempotent backfill for existing ones. Verify public/private/certificate correspondence before CAS. Preserve unknown historical dates using K1's explicit fallback only. Use one UTC operation clock; current keys created by Ensure receive a current-since value, next keys do not. Evict locally retired cached signers while retaining authoritative eligibility reads on every Sign/Verify. Do not globally delete sessions or opaque refresh tokens.
- [x] **Step 4: Wire startup and fresh tenants.** Complete Ensure/backfill before the app serves requests; surface wrapper/plugin/storage errors and never rotate on repair failure. Existing dynamic tenant creation already calls `tenantsetup.SigningKeys`; keep it on the same path. Use managed-only keys in internal verification even when a future JWKS publication function changes. Retain `public, max-age=300`; document the in-flight snapshot boundary rather than promising cancellation.
- [x] **Step 5: Verify and commit.** Require PASS from the focused signing tests and `go test ./internal/keys ./internal/app ./internal/oidc -count=1` (inspect their store fixtures before running under any later hold). Commit `feat(keys): enforce shared lifecycle and backfill certificates`.

## Task 5: Managed and custom signing-key Management API

**Files:** create `internal/mgmt/{signing_keys.go,custom_signing_keys.go,signing_keys_test.go,custom_signing_keys_test.go}`, `internal/server/mgmt_signing_keys_test.go`; modify `api/management.yaml`, `internal/gen/mgmtapi/mgmtapi.gen.go`, `internal/server/{mgmtapi.go,server.go}`, `internal/mgmt/clients.go` handler dependencies, `internal/tenantsetup/management.go`, `api/spec_test.go`.

**Interfaces:** OpenAPI operation IDs `ListSigningKeys`, `GetSigningKey`, `RotateSigningKeys`, `RevokeSigningKey`, `GetCustomSigningKeys`, `PutCustomSigningKeys`, `DeleteCustomSigningKeys`. Generated `mgmtAPI` adapters own scope enforcement and call corresponding `(*mgmt.Handlers)` methods with HTTP request/response and `kid` where applicable. Add `Keys *keys.Manager` to Handlers. Consumes Task 2 projection/validation, Task 3 custom repo, Task 4 lifecycle snapshots.

- [x] **Step 1: Add contract/authorization tests.** Added `TestSigningKeysAPI`, `TestCustomSigningKeysAPI`, `TestSigningKeysReservedTenant`, route scope coverage, and `TestSigningTrustExcludesCustomKeysHTTP` for Management API, userinfo and logout token consumers. Tests cover managed metadata without private fields, promoted-key response identity, previous-only and idempotent revoke, absence/replace/delete, invalid replacement preserving the old set, audit metadata and no raw key logging.
- [x] **Step 2: Establish RED.** Focused test run initially failed to compile because all seven handler methods were absent; this was the expected implementation gap.
- [x] **Step 3: Implement schema and handlers.** Added all seven OpenAPI operations with source provenance, generated types/adapters, managed projection, atomic lifecycle results and custom bounded validation/replacement. Managed rotation returns the just-promoted key. Existing `read:signing_keys`, `create:signing_keys` and `update:signing_keys` catalog scopes were already present and are reused per frozen contracts.
- [x] **Step 4: Define reserved-tenant behavior.** All seven operations reject the reserved tenant using the existing `operation_not_supported` response; internal startup and tenant setup continue through Ensure/backfill. Recorded the local choice in D-0046. The reserved-tenant test exercises a caller carrying the mutation scope and confirms the handler blocks it.
- [x] **Step 5: Verify and commit.** PASS: focused signing API/authorization/trust tests; full `go test ./internal/mgmt ./internal/server ./internal/oidc ./api -count=1`; generated API compilation and provenance checks through `go test ./api`. Commit: `feat(mgmt): expose managed and custom signing key APIs`.

## Task 6: Built-in API naming and retired-resource compatibility

**Files:** modify `internal/tenantsetup/management.go`, `internal/app/app.go`, `internal/store/store.go`, resource-server repositories in memory/SQL/gRPC, proto/generated bindings, `pkg/storetest/resource_servers.go`, `api/management.yaml`, generated adapters/types and scope catalog; create `internal/tenantsetup/management_upgrade_test.go`, `internal/mgmt/{retired.go,retired_test.go}`, `internal/server/mgmt_retired_test.go`.

**Interfaces:** `tenantsetup.UpgradeManagementAPIName(ctx context.Context, st store.Store, t *store.Tenant, baseDomain string) error` updates only the existing ordinary-tenant system API's Name. Add `ResourceServers.RenameSystem(ctx context.Context, tenantID, identifier, name string) error`: match tenant/identifier/IsSystem atomically, update only Name, return ErrNotFound for absent or non-system records. Retired endpoint IDs/methods are the finite D2 inventory produced in Task 1, using explicit adapters rather than a catch-all handler.

- [x] **Step 1: Add tests.** Added `TestManagementAPINameUpgrade` for name-only updates, repeated calls, reserved tenant, unchanged policies/lifetimes/scopes, same-name ordinary APIs, and an overlapping settings change after a stale read. Added `TestRetiredResourceContracts` for collection shapes, query parameters, required read scopes, rejected writes and no script-backed state. Store conformance covers settings, collisions, rollback and committed transaction behavior.
- [x] **Step 2: Establish RED.** The focused test command initially failed to compile because `UpgradeManagementAPIName` and the three retired handlers were not implemented.
- [x] **Step 3: Implement the narrow upgrade.** New ordinary tenant Management APIs use `Auth0 Management API`. Startup updates existing ordinary tenants through `RenameSystem` only, which matches tenant/identifier/IsSystem, and skips absent resources. Memory, SQL, gRPC/proto and `storetest` implement transaction-aware behavior. SQL changes only Name and checks matching rows for idempotent no-op behavior across dialect row-count semantics.
- [x] **Step 4: Implement retired responses.** Added only GET collection routes for Rules, Rules configs and Hooks, with empty documented collection/totals shapes and scopes; there are no writes or wildcard handlers. D2 scope and exact-error fallbacks are recorded in the observation note and D-0046.
- [x] **Step 5: Verify and commit.** PASS: focused tenant setup/Management API/server/API tests; app startup seed check; resource-server conformance on memory, gRPC and SQLite, including transaction rollback/commit; OpenAPI validity/provenance. Commit: `feat(mgmt): align deployment resource compatibility`.

## Task 7: Offline credential-preserving bootstrap

**Files:** create `internal/deploymigration/{export.go,export_test.go,bootstrap.go,bootstrap_test.go,preflight.go}`, `cmd/zeroauthy/{migration.go,migration_test.go}`; modify `cmd/zeroauthy/root.go`; consume existing `internal/seed`, `internal/clientrules`, `internal/keys/clientsecret.go`, `internal/secrets` without changing public client-create behavior.

**Interfaces:** implement `zeroauthy migration bootstrap --config FILE --input PATH --format yaml|directory --bootstrap-seed FILE --credentials-file FILE [--exclude-client-id ID ...] [--check]`. Paths are arguments; credential values are not. Bootstrap seed must describe exactly one fresh nonreserved destination tenant, its local tool client/grant and local domains. Credentials file is JSON mapping source client IDs to secrets, read privately and never echoed. Repeatable source deploy-cli/system client IDs are explicit nonsecret exclusions, validated against D1's inventory. The helper only writes through seed, not through undocumented Management API fields.

```go
type Export struct { Resources map[string]json.RawMessage; Files map[string][]byte }
type BootstrapResult struct { TenantID string; ClientCount int; AlreadyApplied bool }
type BootstrapOptions struct { ExcludedClientIDs []string }
func LoadExport(path, format string) (Export, error)
func PrepareBootstrap(source Export, bootstrap *seed.File, credentials map[string]string, opts BootstrapOptions) (*seed.File, error)
func CheckBootstrap(ctx context.Context, st store.Store, file *seed.File, w keys.Wrapper) (BootstrapResult, error)
func ApplyBootstrap(ctx context.Context, st store.Store, file *seed.File, w keys.Wrapper, now func() time.Time) (BootstrapResult, error)
func CheckExportInventory(resourceServers []json.RawMessage) error
```

- [x] **Step 1: Add memory/pure tests.** `TestLoadExportBoundaries` rejects duplicate YAML/JSON keys, ambiguous client names/IDs, absolute/parent paths, symlinks escaping the export root and unsupported format; it never executes custom scripts. `TestBootstrapPreservesCredentials` applies confidential and public fixtures, checks IDs, constant-time secret equality and no public-client secret. `TestBootstrapRerun` proves matching repeats do not call seed.Apply or reset Management API defaults, even after deploy-cli changes unrelated settings or creates its expected APIs/connections; changed credentials/immutable auth properties, API-origin tenants, partial targets and unrelated conflicting records fail before mutation. Excluded tool IDs may be absent from an export when D1 confirms the tool omits itself; do not reject that legitimate absence. `TestBootstrapRedaction` uses sentinel secrets and asserts neither errors nor stdout/stderr contain them. Add a confidential web client with no client-credentials grant.
- [x] **Step 2: Establish RED.** `go test ./internal/deploymigration -run 'Test(LoadExport|Bootstrap)' -count=1` initially failed for missing APIs.
- [x] **Step 3: Implement parsing and preparation.** YAML/directory parsing, duplicate-key/path checks, supported client mapping, protected credentials and seed validation are implemented.
- [x] **Step 4: Implement transactional preflight/application.** Create-only application, identity/auth/credential/grant rerun checks and memory-DSN refusal are implemented. Partial-target, API-origin, unrelated-domain, authentication, changed/expired-credential and no-reseed scenarios are covered.
- [x] **Step 5: Wire command and verify.** Focused command/package tests passed: `go test ./internal/deploymigration ./cmd/zeroauthy -run 'Test(LoadExport|Bootstrap|MigrationBootstrap)' -count=1`. Public client-create code was not changed.
- [x] **Step 6: Commit** `feat(migration): bootstrap preserved application credentials safely` (`f6a6c51`).

## Task 8: Strict export comparator and exclusion manifest

**Files:** create `tests/e2e/deploy-cli/{main.go,normalize.go,normalize_test.go,manifest.go,manifest_test.go}` and synthetic `fixtures/{yaml,directory}/` exports/scripts; refine Task 1's `manifest.json`. Reuse `internal/deploymigration.LoadExport`.

**Interfaces:** comparator CLI `go run ./tests/e2e/deploy-cli compare --source PATH --target PATH --format yaml|directory --manifest FILE --source-domain HOST --target-domain HOST`; exits 0 only for equivalent nonempty included resources, 1 for differences/invalid input. Also provide `validate-manifest --registry FILE --manifest FILE`, `exclusions --manifest FILE` (JSON array only), and `preflight-inventory --input FILE` calling Task 7's `CheckExportInventory` on API resource-server responses before export. Define `Compare(source,target deploymigration.Export, manifest Manifest, domains Domains) Report`; Report has `Equivalent bool`, per-resource counts and redacted `{resource,path,reason}` differences, never raw values. `Manifest` matches Task 1's schema; `Domains{Source,Target string}` prevents global string replacement.

- [x] **Step 1: Add pure tests.** `TestCompareRoundTrip` accepts changed generated IDs only with valid client/API/connection/grant reference mappings. `TestCompareRejectsLostScope` changes one granted scope and expects `Equivalent == false`. Also reject dropped resources, empty included families, unknown fields, duplicated names, missing/defaulted secret placeholders, wrong enabled clients and changed script hashes. Preserve ordered arrays; only named set fields sort. `TestManifestCoverage` rejects missing/duplicate registry entries, unjustified exclusions or normalization paths outside their resource. `TestMigrationSystemNameCollision` rejects a non-system API with the tool-excluded name.
- [x] **Step 2: Establish RED.** `go test ./tests/e2e/deploy-cli -count=1` failed initially because the comparator API was absent.
- [x] **Step 3: Implement field-specific comparison.** Resource-specific identity mapping, strict unknown-field comparison, scope/reference checks, declared normalization rules, referenced-file safety and file hashes are implemented.
- [x] **Step 4: Implement registry verification and fixtures.** The runner extracts the installed pinned registry and validates manifest coverage; synthetic YAML/directory/script fixtures are present.
- [x] **Step 5: Verify and commit.** `go test ./tests/e2e/deploy-cli -count=1` passed; self-comparisons for both fixture formats passed. Commit `fddfd6b`.

## Task 9: Unmodified deploy-cli local round trips and upstream lane

**Files:** modify `tests/e2e/{package.json,package-lock.json}`, `Makefile`, `.github/workflows/ci.yml`; create `tests/e2e/{m20-deploy-cli.mjs,run-m20-deploy.sh}`, `tests/e2e/deploy-cli/{config.json,run-upstream-export.mjs}` and local fixture setup helpers.

**Interfaces:** `make e2e-deploy` runs `./tests/e2e/run-m20-deploy.sh` for both formats; the runner builds the Task 8 comparator and uses Task 7 bootstrap for preservation mode. `run-upstream-export.mjs` is an explicitly invoked observer tool accepting credentials via environment/private file, exporting only; it is never launched by local CI. Results identify version, format, lane, included counts and outcome; missing upstream access yields `unavailable`, not pass.

- [x] **Step 1: Add failing harness scenarios.** For both YAML and directory: nonempty source export → fresh target import/export equality; repeat import preserves IDs/secrets/counts; update one supported tenant setting and one grant/connection relationship and assert API/runtime change; deletion disabled preserves an unrelated target resource. Run generated-ID and preserved-ID/secret modes. A deliberately removed scope must fail the comparator. Pre-export API inventory must catch a non-system `Auth0 Management API` name and source tool credentials must remain excluded.
- [x] **Step 2: Pin and wire the tools.** Add exactly `auth0-deploy-cli: 9.1.0`, update the npm lockfile and record registry/provenance. Build isolated local TLS source/target servers using the existing harness patterns and temp databases. Pass `NODE_EXTRA_CA_CERTS` for the local CA; use real host routing and the pinned CLI unchanged. Set `AUTH0_ALLOW_DELETE=false`, validate Task 1's manifest before execution, and record the actual installed version. Use protected temp directories, process-group cleanup and redacted logs on failure.
- [x] **Step 3: Complete the local runner.** Run both formats/scenarios end to end, invoke actual `a0deploy` export/import commands from D1, and call Task 8 comparison. Assert one token/client-credentials behavior using synthetic M2M credentials and one imported setting behavior; do not claim configuration equality proves all runtime parity. Check custom script files as inert data. Target-only resources expected to survive must be inventoried separately so comparison does not incorrectly reject or silently hide them.
- [x] **Step 4: Add the observer-only upstream lane.** Preflight supported resource counts and name collisions with documented read APIs, export to restricted storage, sanitize transport artifacts and produce a redacted field/count report. Import only into local zeroauthy. Never import upstream, reveal a raw export in a failed-test log, or substitute the local source for an unavailable Auth0 source. Credential-preserving mode requires a separate operator-supplied secret file; ordinary exports have no client secrets.
- [x] **Step 5: Verify and integrate CI.** Run `make e2e-deploy`; expect both formats and both ID modes to pass with nonzero included counts and the negative case to be detected. Wire the local target into CI's e2e job; keep upstream execution opt-in. Record source/tool/service failures honestly. Committed with Task 11 as `8e887bc` (`test(e2e): verify signing lifecycle and deployment migrations`).

## Task 10: Settings signing-key controls

**Files:** create `console/src/pages/settings/{SigningKeys.vue,CustomSigningKeys.vue,SigningKeys.test.ts,CustomSigningKeys.test.ts}`; modify `TenantSettings.vue`, `console/src/api/{client.ts,schema.d.ts}`, `console/src/locales/en.ts`, and built `console/dist`. Keep the existing Settings route; these are dedicated tabs rather than PolicyForm fields.

**Interfaces:** add typed client helpers for all seven Task 5 operations; components receive the selected tenant and use the existing delegated request path. Managed list/detail state never includes private material. Parent Settings rendering must also handle the reserved-tenant restriction from Task 5.

- [x] **Step 1: Add component tests.** Render current/next/previous/revoked metadata with unknown dates absent; copy/download public cert; rotate and eligible revoke each require confirmation and only one request. On rotate timeout, block another mutation until a successful refresh; do not automatically retry POST. Test refresh failure retains the blocked/uncertain state, stale revoke eligibility, permissions, system tenant, keyboard focus and accessible error announcements. Switch tenants while fetch/mutation is pending and assert late results cannot update or write the new tenant. Custom replacement/deletion preserves old input on validation failure and always shows stored-only/no-token-signing notice.
- [x] **Step 2: Establish RED.** From `console`, run `npm test -- src/pages/settings/SigningKeys.test.ts src/pages/settings/CustomSigningKeys.test.ts`; confirm missing UI/behavior causes failures.
- [x] **Step 3: Implement controls.** Add two Settings tabs using existing dialog/table/form primitives and localization. Display K1 metadata without made-up dates; allow public cert downloads only. Re-fetch authoritative lists after mutations. Capture tenant identity per request and cancel/ignore stale responses; disable actions while pending or uncertain. Provide distinct rotate/revoke controls, no combined two-request action. Custom input is a bounded public JWKS editor with replacement/delete confirmation and no private-key import promise.
- [x] **Step 4: Verify/build and commit.** Re-run component tests; `make console` must pass generation/lint/typecheck/tests/build. Inspect generated types and committed dist for unintended changes. Commit `feat(console): manage tenant signing keys in settings`.

## Task 11: SDK, browser and shared-store lifecycle regression harness

**Files:** create `tests/e2e/{m20-node-auth0.mjs,m20-mgmt-cli.mjs,m20-console.spec.mjs,run-m20-signing.sh}`, `tests/e2e/signing-server/{main.go,shared_test.go,http_test.go}`; modify existing `run-m3.sh`, `run-browser.sh`, Playwright setup/seed and CI; extend `internal/store/grpcstore/conformance_test.go` with targeted transaction cases.

**Interfaces:** `make e2e-signing` → `./tests/e2e/run-m20-signing.sh`; dedicated Go tests `TestM20TwoInstancesRestart`, `TestM20ConcurrentRotateRevoke`, `TestM20CustomKeyForgery`; browser invocation uses an explicit signing-harness mode, preserving the existing M19 harness. CLI/SDK calls use the method names frozen by Task 1.

- [x] **Step 1: Add lifecycle integration assertions.** Two real servers share SQL storage: acquire tokens, rotate on A, issue/verify on B, revoke on B, then require A's newly started validations to reject the old managed key. A third restart preserves cert bytes/timestamps/custom sets. Concurrent rotations return distinct correct operation results and maintain current/next uniqueness; no implicit session/refresh deletion. Demonstrate valid refresh issues a new-current-key token. Inject transaction rollback and verify no partial state.
- [x] **Step 2: Add external-client assertions.** Exercise seven key endpoints and retired-resource contracts with pinned node-auth0/`auth0 api`, including missing scopes and wrong tenants. Use a pinned JWKS client to show unknown-`kid` refresh and separately show that a cached remote public key is not forcibly revoked; distinguish local service rejection from remote cache behavior. Cross-check PKCS#7 with OpenSSL. A custom private signer can produce a mathematically valid signature, but its forged token is rejected by internal auth consumers.
- [x] **Step 3: Add browser flows.** Login to zeroauthy's console, inspect certificates, rotate, revoke a previous key, verify server state and import/delete a custom public set with stored-only notice. Simulate a committed rotation whose response is dropped; assert refresh happens and POST is not repeated. Cover tenant switch, read-only delegation and system-tenant exclusion without observing Auth0 UI. Do not hide a required scenario behind a skip unless the final report names it unavailable.
- [x] **Step 4: Implement harness wiring and run focused checks.** Add `make e2e-signing` and wire local tests into CI. `go test ./tests/e2e/signing-server -run '^TestM20' -count=1`, targeted SQL-backed gRPC rollback tests, `make e2e-signing` and the new CLI/SDK entries must pass. These are database-backed; respect any active repository hold and record deferrals. Existing `make e2e` also keeps Plans 1–19 covered.
- [x] **Step 5: Commit** `8e887bc`, `test(e2e): verify signing lifecycle and deployment migrations`.

## Task 12: Operator documentation, full verification and completion records

**Files:** create `docs/{signing-keys.md,deploy-cli.md}`; update `README.md`, `docs/{management-api.md,console.md}`, plugin/store documentation, `docs/compat/{matrix.md,decisions.md,changelog-review.md}`, `docs/superpowers/plan-1-followups.md`, roadmap, spec and this plan. Add final evidence to the observation notes without raw tenant data.

**Interfaces:** produces the final acceptance report keyed by K1–K3/D1–D2 and AC1–AC11. Report each lane as passed, failed, deferred or unavailable with actual commands/results. Completion counts reflect implemented features; custom stored-only publication and retired shims do not masquerade as finished future resources.

- [x] **Step 1: Document operations and limits.** Include certificate metadata/backfill, cache/in-flight revocation boundaries, prefetch/normal/emergency rotation and fresh Management API credential recovery. Explain no private-key import, custom stored-only state and future Plan 23 publication. Publish both deploy-cli formats, exclusions/normalization ownership, fresh-target bootstrap commands, protected credentials-file shape, `seed_mode: create_only`, rerun preflight and the danger of later overwrite-mode seeds. Resolve D-0039/D-0041 and keep algorithm/root-encryption/unrelated migration work open.
- [x] **Step 2: Run the final required checks.** `gofmt -l` on changed Go files must be empty; `go vet ./...`, `go test -race ./...`, `./scripts/test-sql.sh`, `go generate ./...`, `make console`, `make check-sources`, `make e2e`, `make e2e-deploy`, `make e2e-signing`, and `make conformance` must report their actual outcomes. Verify generated files have no unexpected diff. The SQL script must cover SQLite/PostgreSQL/MySQL; the generic Go command alone is insufficient evidence. Require OpenSSL certificate-only PKCS#7 parsing and report conformance warnings/review-only/skips separately. If a later fix changes code, rerun affected checks and state which broad results predate it.
- [x] **Step 3: Record the upstream lane.** Obtain the separate observer's dated export→local import→export report for both formats, or explicitly record missing credentials/entitlement/nonempty resources and the remaining comparison. No live credentials are required for local CI. Do not label an unavailable lane passing or conceal it in a global “all tests passed” claim.
- [x] **Step 4: Review the whole change.** Verify the coverage table below against named tests/results, review trust boundaries and migration data-loss risks, and resolve findings. Update checkboxes and roadmap only after required implementation and available local checks are complete; preserve documented upstream limitations. Mark the design's recommendations as implemented decisions only where actually implemented.
- [x] **Step 5: Commit** `docs: signing keys and deployment migration; Plan 20 records`. Leave merge/push to the user's instruction.

## Acceptance and evidence coverage

| Contract | Implementation tasks | Named proof / final result owner |
|---|---|---|
| K1, K2; AC1 | 1–5, 11 | `TestSigningKeysAPI`, SDK/CLI key operations; Task 12 evidence report |
| AC2 | 3–4, 11 | `RotateRetainsPrevious`, `TestSigningRevocationAcrossManagers`, refresh/new-key integration |
| AC3 | 3–4, 11 | `ConcurrentRotationResults`, `TestM20ConcurrentRotateRevoke`, SQL-backed gRPC rollback |
| AC4 | 2–4, 11 | `TestCertificateIdentity`, `CertificateCAS`, `TestSigningBackfillIdentity`, OpenSSL/upgrade/restart |
| K3; AC5 | 1–5, 10–11 | `TestCustomSigningValidation`, `TestCustomSigningKeysAPI`, `TestM20CustomKeyForgery` |
| AC6 | 3, 11–12 | Signing/custom conformance, transaction/deletion cases and three SQL dialects |
| D1; AC7 | 1, 7–9 | Manifest coverage, both format fixtures, comparator negatives, actual CLI repeat/update imports |
| AC8 | 7–9 | `TestBootstrapPreservesCredentials`, `TestBootstrapRerun`, preserved/generated-ID lanes |
| D2; AC9 | 1, 6–9, 11 | `TestManagementAPINameUpgrade`, `TestRetiredResourceContracts`, pre-export collision check |
| AC10 | 10–11 | Component uncertain-state/permissions tests and `m20-console.spec.mjs` |
| AC11 | 9, 12 | Observer-only lane report or explicit unavailable status; operator/matrix accuracy |

## Planning self-review

Before implementation, recheck exact paths against the checkout and reserve migration 0017 only if still next. This plan keeps old manager/store Rotate callers and protobuf fields compatible while introducing named result-returning methods; custom publication and internal verification stay distinct. Bootstrap parsing is reused by the comparator, evidence-dependent wire shapes are assigned to Task 1, and every acceptance criterion/review focus has an owning task and named assertion. No database or implementation tests were run to author this document.

## Final acceptance record — 2026-10-25

Follow-on implementation commits: `e020bdf` (bootstrap/comparator fixes),
`9b7394c` (console and corrected API route), `8e887bc` (real migration and
signing regression harnesses/CI).

### Execution rulings

- **Observer unavailable:** no separately authorized Auth0 observer or credentials
  were supplied. Public documentation and local fallback contracts stand;
  remaining upstream wire/migration parity is unverified.
- **Pinned handler limits:** `databases` needs Actions, generic `connections`
  excludes the currently implemented `auth0` strategy, and `attackProtection`
  needs phone-provider protection. The manifest explicitly classifies these
  as tool-unsupported with owners/reasons. Real migration coverage is limited
  to four included families; synthetic parser/direct API coverage remains.
- **Revoke route correction:** installed node-auth0 7.4.0 uses
  `/keys/signing/{kid}/revoke`. The initial schema without that suffix was
  corrected before release. Existing OIDC routes and older tests remain.
- **Bootstrap metadata:** identifier-bearing exports prepare the offline
  bootstrap; ordinary exports drive actual imports. Public client creation
  still generates IDs and does not accept caller-supplied IDs. Unsupported
  source metadata fails for reconciliation rather than being dropped.

### Required check results

| Check | Actual result |
|---|---|
| Changed Go files `gofmt -l`; `git diff --check` | Passed, no output |
| `go vet ./...` | Passed |
| `go test -race ./...` | Passed; targeted changed-package race checks also passed |
| `./scripts/test-sql.sh` | Passed, SQLite/PostgreSQL/MySQL; SQL package 365.885s |
| `go generate ./...`; console `npm run gen` | Passed; generated output reproduced byte-for-byte |
| `make console` | Passed generation, lint, typecheck, 329 tests and production build; existing bundle-size warning remains |
| `make check-sources` | Passed |
| `make e2e` | Passed all SDK/CLI entries; 24 browser tests passed, two harness-gated M19/M20 skips in default mode |
| `make e2e-deploy` | Passed YAML/directory × generated/preserved credentials; nonzero clients/API/grant/tenant counts, repeat/update imports, target-only survival, negative comparison and runtime token issuance |
| `make e2e-signing` | Passed SQL lifecycle/custom forgery tests, SDK/JWKS-cache assertions and the dedicated M20 browser flow (1 passed) |
| SQL-backed gRPC `TestSigningLifecycleSQLiteRollback` | Passed; rotation, revocation and custom replacement roll back together |
| `TestCertificatePKCS7OpenSSL` | Passed with OpenSSL 3.6.5 |
| `make conformance` | Exit 0, zero failed modules; Basic and Form Post each 21 passed / 6 warning / 4 review / 4 skipped; Config 1 passed; Logout 3 passed / 8 review |
| Upstream observer helper without credentials | Unavailable; no upstream calls made |
| Whole-branch review | No remaining Critical/Important findings; expired-secret, initial-GET editor race and CI integration findings fixed; lifecycle metadata display completed |

The conformance warning/review/skipped cases remain visible; this execution
is not a new certification claim. The full SQL/OIDC suites predate only
subsequent comparator/test/document changes; affected packages and the actual
Deploy CLI lane were rerun after those changes.

### Acceptance mapping

| Acceptance | Evidence and boundary |
|---|---|
| AC1, K1/K2 | Management contract/scope/tenant tests plus pinned SDK and auth0 CLI exercise all managed operations at the corrected revoke path; local contract, live behavior unobserved |
| AC2 | Real two-server SQL HTTP flow retains old tokens until revoke; refresh uses the promoted key; SDK confirms canonical JWKS removal and independently cached-key behavior |
| AC3 | Concurrent rotations and rotate/revoke preserve result identity/current-next uniqueness; SQL-backed gRPC rollback prevents partial managed/custom state |
| AC4 | Certificate identity/CAS/backfill and actual store reopen preserve bytes/timestamps; OpenSSL independently parses PKCS#7 |
| AC5, K3 | Custom invalid/colliding/private inputs preserve state; custom sets survive restart; mathematically valid attacker signatures fail management, userinfo and logout |
| AC6 | Memory/SQLite/PostgreSQL/MySQL/gRPC/plugin conformance, transaction/deletion/deep-copy coverage; missing plugin lifecycle RPCs fail closed |
| AC7, D1 | Four real CLI format/mode combinations pass for all included nonempty families; strict negative/reference/script-hash tests pass; three explicitly unsupported handlers remain unavailable |
| AC8 | Imported M2M authenticates with preserved or generated credentials; repeat imports keep ID/secret; offline confidential web (without client_credentials) and public-client cases use internal secret checks; conflicts/expired secrets fail |
| AC9, D2 | Built-in naming upgrade preserves authorization/identity; user reserved-name collision fails preflight; pinned SDK/CLI retired reads and scoped/rejected-write tests pass |
| AC10 | 329 console tests include tenant races, uncertain response, stale revoke, metadata/certificate copy/download, permission errors and initial editor lock; dedicated browser commits then drops a rotation response and observes exactly one POST, tests scoped refusal and system exclusion |
| AC11 | Observer-only export helper protects output and reports counts/fields; actual upstream run unavailable without credentials; docs/matrix state the boundary |

Integration remains the maintainer's decision. The branch is preserved without
an automatic merge or push.
