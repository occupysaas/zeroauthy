# Plan 20: Signing Keys and Deploy CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship tenant signing-key management and a repeatable, credential-aware Auth0 Deploy CLI configuration migration.

**Architecture:** Extend the existing managed-key lifecycle with durable certificates and atomic result-returning store operations; internal verification remains separate from public-key publication. Add scoped Management API/Settings controls, store custom public JWKS separately, and exercise unmodified deploy-cli through a versioned resource manifest and strict export comparator. Reuse create-only seed for offline credential bootstrap rather than extending public client-create semantics.

**Tech Stack:** Go 1.26.7, existing go-jose/crypto/x509/encoding/asn1 and go.yaml.in/yaml/v3; memory/SQLite/PostgreSQL/MySQL/gRPC stores; OpenAPI/oapi-codegen; Vue 3/TypeScript/Vite; Node >=22.12, auth0-deploy-cli 9.1.0, current pinned Auth0 CLI/SDK and Playwright.

**Spec:** [Plan 20 design](../specs/2026-10-25-zeroauthy-signing-keys-deploy-cli-design.md). Read it, the roadmap's Plan 20 section and `CLEAN_ROOM.md` before execution.

**Status:** Implementation plan requested on 2026-10-25; no implementation tasks have run. Based on `25bcb60`. The spec's proposed decisions are carried into this plan; Task 1 freezes unresolved wire details before dependent coding. This document does not claim live observations or passing implementation tests.

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

- [ ] **Step 1: Add focused tests.** `TestCertificateIdentity` asserts certificate RSA parameters equal the supplied private key and validity equals `now-5m` through `now.AddDate(10,0,0)`; `TestCertificateEncodings` independently hashes/parses the DER and verifies the K1 representation; `TestCustomSigningValidation` covers 1/10/11 keys, duplicate JSON fields/IDs, private RSA/EC members, symmetric keys, wrong operations/algorithm/curve, bad certificates and URL fields without network requests. `TestManagedKeyProjection` asserts omitted unknown dates and absence of every private field.
- [ ] **Step 2: Establish RED.** Run `go test ./internal/keycert ./internal/signingrules -count=1`; expect the newly specified behavior to fail or new symbols to be missing, not an unrelated environment error.
- [ ] **Step 3: Implement pure helpers and types.** Use 2048-bit generated RSA keys from the existing manager, a positive random 128-bit certificate serial and neutral subject `zeroauthy signing key`; self-sign with SHA256-RSA. Use SHA-1 only for compatibility certificate fingerprints if K1 requires it. Encode a certificate-only SignedData container, with no signers, id-data content type and absent content per [RFC 5652 §§5.1–5.2](https://www.rfc-editor.org/rfc/rfc5652.html#section-5.2), using `encoding/asn1`; add no general CMS implementation. Validate public JWKs using existing go-jose plus explicit private/unknown-field checks before unmarshalling can discard fields. Preserve validated public fields/ordering according to K3.
- [ ] **Step 4: Verify.** Re-run the focused tests and require PASS. Add `TestCertificatePKCS7OpenSSL` using `openssl pkcs7 -print_certs` to compare recovered DER independently; report unavailable OpenSSL explicitly and make it required in Task 12. Verify empty/zero public aliases compile with `go test ./pkg/store -run '^Test' -count=1`.
- [ ] **Step 5: Commit** `feat(keys): add stable certificate metadata and public key rules`.

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

- [ ] **Step 1: Extend conformance cases.** Add `RotateRetainsPrevious`, `ConcurrentRotationResults`, `RevokeStateAndTimestamp`, `CertificateCAS`, `CustomManagedCollision`, `DeepCopy`, `TenantIsolation` and rollback/deletion cases. Core assertions: `result.Current.KID == previouslyQueued.KID`; after two rotations both original signers remain eligible under the default; `Get(revoked).RevokedAt == firstRevokeTime`; two certificate CAS callers read identical winning DER; caller mutations do not alter persisted slices/pointers. A failed operation leaves the entire old state equal. Test collision in both directions, including concurrent custom Replace and managed Create/Rotate.
- [ ] **Step 2: Establish RED with memory.** Run `go test ./internal/store/memory -run '^TestConformance/(SigningKeys|CustomSigningKeys|Tx|Operators)$' -count=1`; newly added assertions must fail before implementation.
- [ ] **Step 3: Implement all drivers and migrations together.** Add nullable certificate/timestamp columns and a tenant-scoped custom-set table. Serialize lifecycle and custom collision checks on the same tenant lock; SQL reads after waiting must see current committed rows on PostgreSQL and MySQL, not an old repeatable-read snapshot. Use existing atomic retry/savepoint patterns. Require current and next before rotation; demote/promote/insert atomically, retain previous records, and assign timestamps from `at`. Legacy `Rotate` delegates to `RotateWithResult` with `next.CreatedAt` and discards the result. CAS only fills an absent certificate; it never updates lifecycle or overwrites existing DER. Deep-copy all new values and include custom sets in tenant deletion/transactions.
- [ ] **Step 4: Add gRPC methods.** Preserve existing field numbers and the old rotate RPC. Add distinct result-returning RPCs/messages for the new methods, including operation snapshots, nullable timestamps and `tx_id`. Update codecs/public aliases. `Unimplemented` must produce the existing plugin-too-old style error rather than falling back to old rotation semantics. Regenerate via `go generate ./proto/store/v1`.
- [ ] **Step 5: Verify focused suites.** Require PASS from the memory command, `go test ./internal/store/grpcstore -run '^TestConformance$/(SigningKeys|CustomSigningKeys|Tx|Operators)$' -count=1`, and `go test ./internal/store/sqlstore -run 'TestSigningMigration|TestConformance/.*/(SigningKeys|CustomSigningKeys|Tx|Operators)$' -count=1`. The last command is database-backed; record which dialects actually ran. Add rollback assertions for SQL-backed gRPC transactions in Task 11 and defer the full dialect matrix to Task 12.
- [ ] **Step 6: Commit** `feat(store): persist atomic signing lifecycle and custom public keys`.

## Task 4: Key manager, backfill and runtime trust

**Files:** modify `internal/keys/manager.go`, `internal/{app/app.go,tenantsetup/tenantsetup.go,oidc/handlers.go}`; create `internal/keys/{lifecycle.go,backfill.go,lifecycle_test.go,backfill_test.go}`; extend key manager/app/oidc tests. Inspect all `Keys.Verify`, `Keys.JWKS` and direct JWT verification callers.

**Interfaces:** keep `NewManager(store.SigningKeys, Wrapper)`, `Ensure`, `Sign`, `Verify`, `JWKS` and `Rotate` signatures usable by existing callers. Add the following manager methods; `JWKS` delegates to managed-only `VerificationKeys` for now. Custom-key publication will require an explicit future aggregator, not a modification to internal trust.

```go
func (m *Manager) RotateWithResult(ctx context.Context, tenantID string) (*store.SigningKeyRotation, error)
func (m *Manager) Revoke(ctx context.Context, tenantID, kid string) (*store.SigningKey, error)
func (m *Manager) BackfillCertificates(ctx context.Context, tenantID string) error
func (m *Manager) VerificationKeys(ctx context.Context, tenantID string) (jose.JSONWebKeySet, error)
```

- [ ] **Step 1: Add memory-backed regressions.** `TestSigningBackfillIdentity` starts with legacy current/next/previous/revoked rows and pre-upgrade tokens; assert unchanged key IDs/public/private bytes and valid old tokens after fill. `TestSigningBackfillFailure` injects unwrap/CAS failures and asserts no rotation or replacement; retry completes only missing certificates. `TestSigningRevocationAcrossManagers` warms one manager, revokes through another and rejects old tokens on a subsequent Verify. `TestSigningTrustExcludesCustomKeys` uploads a matching attacker signature and expects `ErrInvalidToken`. Add malformed/multiple-signature/missing-`kid`/wrong-`alg`, store-outage and signer-retention cases.
- [ ] **Step 2: Establish RED.** Run `go test ./internal/keys -run '^TestSigning' -count=1` and confirm each regression fails for the intended reason.
- [ ] **Step 3: Implement lifecycle/backfill.** Generate/encrypt/certify the fresh next key before mutation; return the store's result, never infer it from a later List. Ensure certifies newly generated keys and calls the idempotent backfill for existing ones. Verify public/private/certificate correspondence before CAS. Preserve unknown historical dates using K1's explicit fallback only. Use one UTC operation clock; current keys created by Ensure receive a current-since value, next keys do not. Evict locally retired cached signers while retaining authoritative eligibility reads on every Sign/Verify. Do not globally delete sessions or opaque refresh tokens.
- [ ] **Step 4: Wire startup and fresh tenants.** Complete Ensure/backfill before the app serves requests; surface wrapper/plugin/storage errors and never rotate on repair failure. Existing dynamic tenant creation already calls `tenantsetup.SigningKeys`; keep it on the same path. Use managed-only keys in internal verification even when a future JWKS publication function changes. Retain `public, max-age=300`; document the in-flight snapshot boundary rather than promising cancellation.
- [ ] **Step 5: Verify and commit.** Require PASS from the focused signing tests and `go test ./internal/keys ./internal/app ./internal/oidc -count=1` (inspect their store fixtures before running under any later hold). Commit `feat(keys): enforce shared lifecycle and backfill certificates`.

## Task 5: Managed and custom signing-key Management API

**Files:** create `internal/mgmt/{signing_keys.go,custom_signing_keys.go,signing_keys_test.go,custom_signing_keys_test.go}`, `internal/server/mgmt_signing_keys_test.go`; modify `api/management.yaml`, `internal/gen/mgmtapi/mgmtapi.gen.go`, `internal/server/{mgmtapi.go,server.go}`, `internal/mgmt/clients.go` handler dependencies, `internal/tenantsetup/management.go`, `api/spec_test.go`.

**Interfaces:** OpenAPI operation IDs `ListSigningKeys`, `GetSigningKey`, `RotateSigningKeys`, `RevokeSigningKey`, `GetCustomSigningKeys`, `PutCustomSigningKeys`, `DeleteCustomSigningKeys`. Generated `mgmtAPI` adapters own scope enforcement and call corresponding `(*mgmt.Handlers)` methods with HTTP request/response and `kid` where applicable. Add `Keys *keys.Manager` to Handlers. Consumes Task 2 projection/validation, Task 3 custom repo, Task 4 lifecycle snapshots.

- [ ] **Step 1: Add contract/authorization tests.** `TestSigningKeysAPI` covers K1/K2 field/status/scope fixtures, malformed/unknown/foreign IDs, body handling, repeated/ineligible revoke, sequential rotation and exact response key. `TestCustomSigningKeysAPI` covers K3 absence/replace/delete and all validation failures with old set unchanged. `TestSigningTrustExcludesCustomKeysHTTP` rejects forged tokens on Management API, userinfo and logout consumers. Check successful writes audit actor/tenant/key IDs, failures do not log success, and logs never contain raw request keys/secrets.
- [ ] **Step 2: Establish RED.** `go test ./internal/mgmt ./internal/server -run 'Test(SigningKeysAPI|CustomSigningKeysAPI|SigningTrustExcludesCustomKeysHTTP)' -count=1` must expose absent routes or assertions.
- [ ] **Step 3: Implement schema and handlers.** Add seven exact contracts with public sources and K1/K3 limits; generate adapters/types via `go generate ./...`. Managed reads use Task 2 projection; rotate returns the K2-selected member of Task 4's result with 201; revoke returns its snapshot with 200. Map storage failures to the existing error envelope. Use the 1 MiB existing Management API body limit and any stricter K3 limit. Custom PUT validates before atomic Replace and checks collision again in storage. Add only the frozen custom scopes to the built-in catalog; do not assume managed scopes apply to custom operations.
- [ ] **Step 4: Define reserved-tenant behavior.** Local implementation choice: keep these tenant Management API operations unavailable for the reserved operator tenant, following the existing tenant-settings restriction; leave its internal Ensure/backfill operational. Add tests proving an operator's delegated tenant token cannot change the system tenant's signing keys. Never broaden normal tenant M2M access to the operator API. Record this restriction in the decision log and operator docs.
- [ ] **Step 5: Verify and commit.** Re-run focused tests and `go test ./api -count=1`, checking schema coverage/provenance and generated compilation. Commit `feat(mgmt): expose managed and custom signing key APIs`.

## Task 6: Built-in API naming and retired-resource compatibility

**Files:** modify `internal/tenantsetup/management.go`, `internal/app/app.go`, `internal/store/store.go`, resource-server repositories in memory/SQL/gRPC, proto/generated bindings, `pkg/storetest/resource_servers.go`, `api/management.yaml`, generated adapters/types and scope catalog; create `internal/tenantsetup/management_upgrade_test.go`, `internal/mgmt/{retired.go,retired_test.go}`, `internal/server/mgmt_retired_test.go`.

**Interfaces:** `tenantsetup.UpgradeManagementAPIName(ctx context.Context, st store.Store, t *store.Tenant, baseDomain string) error` updates only the existing ordinary-tenant system API's Name. Add `ResourceServers.RenameSystem(ctx context.Context, tenantID, identifier, name string) error`: match tenant/identifier/IsSystem atomically, update only Name, return ErrNotFound for absent or non-system records. Retired endpoint IDs/methods are the finite D2 inventory produced in Task 1, using explicit adapters rather than a catch-all handler.

- [ ] **Step 1: Add tests.** `TestManagementAPINameUpgrade` creates an existing system API with nondefault token lifetimes/policies and asserts only Name changes to `Auth0 Management API`, IDs/audience/scopes remain equal, repeat upgrade is a no-op, and the reserved `urn:zeroauthy:management` is untouched. Include an ordinary API with the same name and verify it is never renamed/mutated. `TestRetiredResourceContracts` uses D2 read/write/missing-scope/parameter fixtures and asserts no successful write or hidden persistence.
- [ ] **Step 2: Establish RED.** Run `go test ./internal/tenantsetup ./internal/mgmt ./internal/server -run 'Test(ManagementAPINameUpgrade|RetiredResourceContracts)' -count=1`.
- [ ] **Step 3: Implement the narrow upgrade.** Set the bootstrap name constant; implement the name-only repository mutation in every driver/transaction view and its new gRPC RPC. In SQL use an UPDATE of Name alone with tenant/identifier/IsSystem predicates, never a stale whole-record write. Invoke it for existing ordinary tenants at startup; skip ErrNotFound without creating or converting a resource. Do not call `ManagementAPI` as the migration shortcut: it resets configurable defaults. Add `RenameSystemPreservesSettings` conformance assertions and a concurrent settings-update case to prove the upgrade cannot overwrite unrelated fields.
- [ ] **Step 4: Implement retired responses.** Add exact documented collection GET shapes/scopes and finite rejected-write routes from D2. No broad routing wildcard and no Rules/Hooks execution. Regenerate OpenAPI bindings and add frozen scope names only where operations require them.
- [ ] **Step 5: Verify and commit.** Require PASS from the focused command and API schema tests. Commit `feat(mgmt): align deployment resource compatibility`.

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

- [ ] **Step 1: Add memory/pure tests.** `TestLoadExportBoundaries` rejects duplicate YAML/JSON keys, ambiguous client names/IDs, absolute/parent paths, symlinks escaping the export root and unsupported format; it never executes custom scripts. `TestBootstrapPreservesCredentials` applies confidential and public fixtures, checks IDs, constant-time secret equality and no public-client secret. `TestBootstrapRerun` proves matching repeats do not call seed.Apply or reset Management API defaults, even after deploy-cli changes unrelated settings or creates its expected APIs/connections; changed credentials/immutable auth properties, API-origin tenants, partial targets and unrelated conflicting records fail before mutation. Excluded tool IDs may be absent from an export when D1 confirms the tool omits itself; do not reject that legitimate absence. `TestBootstrapRedaction` uses sentinel secrets and asserts neither errors nor stdout/stderr contain them. Add a confidential web client with no client-credentials grant.
- [ ] **Step 2: Establish RED.** Run `go test ./internal/deploymigration -run 'Test(LoadExport|Bootstrap)' -count=1`.
- [ ] **Step 3: Implement parsing and preparation.** Use the existing YAML library with explicit duplicate-key/path checks and D1 format mappings; preserve arbitrary resource JSON for the comparator instead of dropping unrecognized fields. Map supported exported client fields into seed structs, fill secrets from the protected file, retain immutable first/third-party/auth settings, and reject unsupported mappings. Merge destination tool resources only from the local bootstrap seed. Re-parse/validate the prepared seed using existing shared rules; require `seed_mode: create_only`, schema readiness and wrapper availability. No plaintext generated seed artifact is needed.
- [ ] **Step 4: Implement transactional preflight/application.** Require an offline destination/maintenance window. A first application creates the destination tenant and local tool resources itself; existing tenants are accepted only as a fully matching prior bootstrap, not a partial target to fill. Check identity/auth configuration, secrets and reserved-name collisions inside the same outer transaction before seed.Apply. Repeat checks compare only bootstrap identity/auth/credential invariants, allowing mutable settings and other resources subsequently imported by deploy-cli; use `keys.OpenClientSecret` plus constant-time compare or existing legacy hash verification, then return without reseeding. No grants are added merely to verify credentials. Incomplete/conflicting bootstrap fails for explicit operator reconciliation; it does not silently resume by replacing secrets. `--check` makes no writes and reports only counts/status. Reject ephemeral memory DSNs for the real migration command, although unit tests use memory stores.
- [ ] **Step 5: Wire command and verify.** Follow existing seed command config/master-key/storage lifecycle; close stores and sanitize parse/storage errors. Add command tests for flags, required create-only mode, `--check`, secret redaction and refusal of unsupported targets. Run `go test ./internal/deploymigration ./cmd/zeroauthy -run 'Test(LoadExport|Bootstrap|MigrationBootstrap)' -count=1`; assert PASS and unchanged public client POST contract.
- [ ] **Step 6: Commit** `feat(migration): bootstrap preserved application credentials safely`.

## Task 8: Strict export comparator and exclusion manifest

**Files:** create `tests/e2e/deploy-cli/{main.go,normalize.go,normalize_test.go,manifest.go,manifest_test.go}` and synthetic `fixtures/{yaml,directory}/` exports/scripts; refine Task 1's `manifest.json`. Reuse `internal/deploymigration.LoadExport`.

**Interfaces:** comparator CLI `go run ./tests/e2e/deploy-cli compare --source PATH --target PATH --format yaml|directory --manifest FILE --source-domain HOST --target-domain HOST`; exits 0 only for equivalent nonempty included resources, 1 for differences/invalid input. Also provide `validate-manifest --registry FILE --manifest FILE`, `exclusions --manifest FILE` (JSON array only), and `preflight-inventory --input FILE` calling Task 7's `CheckExportInventory` on API resource-server responses before export. Define `Compare(source,target deploymigration.Export, manifest Manifest, domains Domains) Report`; Report has `Equivalent bool`, per-resource counts and redacted `{resource,path,reason}` differences, never raw values. `Manifest` matches Task 1's schema; `Domains{Source,Target string}` prevents global string replacement.

- [ ] **Step 1: Add pure tests.** `TestCompareRoundTrip` accepts changed generated IDs only with valid client/API/connection/grant reference mappings. `TestCompareRejectsLostScope` changes one granted scope and expects `Equivalent == false`. Also reject dropped resources, empty included families, unknown fields, duplicated names, missing/defaulted secret placeholders, wrong enabled clients and changed script hashes. Preserve ordered arrays; only named set fields sort. `TestManifestCoverage` rejects missing/duplicate registry entries, unjustified exclusions or normalization paths outside their resource. `TestMigrationSystemNameCollision` rejects a non-system API with the tool-excluded name.
- [ ] **Step 2: Establish RED.** `go test ./tests/e2e/deploy-cli -count=1` must fail on the new assertions.
- [ ] **Step 3: Implement field-specific comparison.** Build explicit source→target ID maps by supported natural identity; validate relationships before substituting. Normalize only Task 1's approved timestamps/read-only fields/defaults, known secret omissions, declared sets and designated tenant URLs. Never delete all unknown fields or recursively rewrite arbitrary strings. Include file content hashes and counts in comparison; escaped/unreadable references fail. Actual secret values do not enter the report. Resource APIs omitted by the tool require pre-export collision preflight in Task 9; the comparator cannot detect an already-omitted object by itself.
- [ ] **Step 4: Implement registry verification and fixtures.** Maintain complete included/excluded/tool-unsupported classification from the pinned registry; `exclusions` selects only justified excluded handler names. Add nonempty synthetic files for every included family, original inert database scripts and both directory/YAML references. Build the registry snapshot during tool installation in Task 9 and compare it; never silently regenerate exclusions to fit new upstream handlers.
- [ ] **Step 5: Verify and commit.** `go test ./tests/e2e/deploy-cli -count=1` must pass including negative comparisons; run the CLI on fixture pairs and assert exit 0/1 appropriately. Commit `test(deploy): define strict migration comparison and exclusions`.

## Task 9: Unmodified deploy-cli local round trips and upstream lane

**Files:** modify `tests/e2e/{package.json,package-lock.json}`, `Makefile`, `.github/workflows/ci.yml`; create `tests/e2e/{m20-deploy-cli.mjs,run-m20-deploy.sh}`, `tests/e2e/deploy-cli/{config.json,run-upstream-export.mjs}` and local fixture setup helpers.

**Interfaces:** `make e2e-deploy` runs `./tests/e2e/run-m20-deploy.sh` for both formats; the runner builds the Task 8 comparator and uses Task 7 bootstrap for preservation mode. `run-upstream-export.mjs` is an explicitly invoked observer tool accepting credentials via environment/private file, exporting only; it is never launched by local CI. Results identify version, format, lane, included counts and outcome; missing upstream access yields `unavailable`, not pass.

- [ ] **Step 1: Add failing harness scenarios.** For both YAML and directory: nonempty source export → fresh target import/export equality; repeat import preserves IDs/secrets/counts; update one supported tenant setting and one grant/connection relationship and assert API/runtime change; deletion disabled preserves an unrelated target resource. Run generated-ID and preserved-ID/secret modes. A deliberately removed scope must fail the comparator. Pre-export API inventory must catch a non-system `Auth0 Management API` name and source tool credentials must remain excluded.
- [ ] **Step 2: Pin and wire the tools.** Add exactly `auth0-deploy-cli: 9.1.0`, update the npm lockfile and record registry/provenance. Build isolated local TLS source/target servers using the existing harness patterns and temp databases. Pass `NODE_EXTRA_CA_CERTS` for the local CA; use real host routing and the pinned CLI unchanged. Set `AUTH0_ALLOW_DELETE=false`, validate Task 1's manifest before execution, and record the actual installed version. Use protected temp directories, process-group cleanup and redacted logs on failure.
- [ ] **Step 3: Complete the local runner.** Run both formats/scenarios end to end, invoke actual `a0deploy` export/import commands from D1, and call Task 8 comparison. Assert one token/client-credentials behavior using synthetic M2M credentials and one imported setting behavior; do not claim configuration equality proves all runtime parity. Check custom script files as inert data. Target-only resources expected to survive must be inventoried separately so comparison does not incorrectly reject or silently hide them.
- [ ] **Step 4: Add the observer-only upstream lane.** Preflight supported resource counts and name collisions with documented read APIs, export to restricted storage, sanitize transport artifacts and produce a redacted field/count report. Import only into local zeroauthy. Never import upstream, reveal a raw export in a failed-test log, or substitute the local source for an unavailable Auth0 source. Credential-preserving mode requires a separate operator-supplied secret file; ordinary exports have no client secrets.
- [ ] **Step 5: Verify and integrate CI.** Run `make e2e-deploy`; expect both formats and both ID modes to pass with nonzero included counts and the negative case to be detected. Wire the local target into CI's e2e job; keep upstream execution opt-in. Record source/tool/service failures honestly. Commit `test(e2e): add deploy-cli migration round trips`.

## Task 10: Settings signing-key controls

**Files:** create `console/src/pages/settings/{SigningKeys.vue,CustomSigningKeys.vue,SigningKeys.test.ts,CustomSigningKeys.test.ts}`; modify `TenantSettings.vue`, `console/src/api/{client.ts,schema.d.ts}`, `console/src/locales/en.ts`, and built `console/dist`. Keep the existing Settings route; these are dedicated tabs rather than PolicyForm fields.

**Interfaces:** add typed client helpers for all seven Task 5 operations; components receive the selected tenant and use the existing delegated request path. Managed list/detail state never includes private material. Parent Settings rendering must also handle the reserved-tenant restriction from Task 5.

- [ ] **Step 1: Add component tests.** Render current/next/previous/revoked metadata with unknown dates absent; copy/download public cert; rotate and eligible revoke each require confirmation and only one request. On rotate timeout, block another mutation until a successful refresh; do not automatically retry POST. Test refresh failure retains the blocked/uncertain state, stale revoke eligibility, permissions, system tenant, keyboard focus and accessible error announcements. Switch tenants while fetch/mutation is pending and assert late results cannot update or write the new tenant. Custom replacement/deletion preserves old input on validation failure and always shows stored-only/no-token-signing notice.
- [ ] **Step 2: Establish RED.** From `console`, run `npm test -- src/pages/settings/SigningKeys.test.ts src/pages/settings/CustomSigningKeys.test.ts`; confirm missing UI/behavior causes failures.
- [ ] **Step 3: Implement controls.** Add two Settings tabs using existing dialog/table/form primitives and localization. Display K1 metadata without made-up dates; allow public cert downloads only. Re-fetch authoritative lists after mutations. Capture tenant identity per request and cancel/ignore stale responses; disable actions while pending or uncertain. Provide distinct rotate/revoke controls, no combined two-request action. Custom input is a bounded public JWKS editor with replacement/delete confirmation and no private-key import promise.
- [ ] **Step 4: Verify/build and commit.** Re-run component tests; `make console` must pass generation/lint/typecheck/tests/build. Inspect generated types and committed dist for unintended changes. Commit `feat(console): manage tenant signing keys in settings`.

## Task 11: SDK, browser and shared-store lifecycle regression harness

**Files:** create `tests/e2e/{m20-node-auth0.mjs,m20-mgmt-cli.mjs,m20-console.spec.mjs,run-m20-signing.sh}`, `tests/e2e/signing-server/{main.go,shared_test.go,http_test.go}`; modify existing `run-m3.sh`, `run-browser.sh`, Playwright setup/seed and CI; extend `internal/store/grpcstore/conformance_test.go` with targeted transaction cases.

**Interfaces:** `make e2e-signing` → `./tests/e2e/run-m20-signing.sh`; dedicated Go tests `TestM20TwoInstancesRestart`, `TestM20ConcurrentRotateRevoke`, `TestM20CustomKeyForgery`; browser invocation uses an explicit signing-harness mode, preserving the existing M19 harness. CLI/SDK calls use the method names frozen by Task 1.

- [ ] **Step 1: Add lifecycle integration assertions.** Two real servers share SQL storage: acquire tokens, rotate on A, issue/verify on B, revoke on B, then require A's newly started validations to reject the old managed key. A third restart preserves cert bytes/timestamps/custom sets. Concurrent rotations return distinct correct operation results and maintain current/next uniqueness; no implicit session/refresh deletion. Demonstrate valid refresh issues a new-current-key token. Inject transaction rollback and verify no partial state.
- [ ] **Step 2: Add external-client assertions.** Exercise seven key endpoints and retired-resource contracts with pinned node-auth0/`auth0 api`, including missing scopes and wrong tenants. Use a pinned JWKS client to show unknown-`kid` refresh and separately show that a cached remote public key is not forcibly revoked; distinguish local service rejection from remote cache behavior. Cross-check PKCS#7 with OpenSSL. A custom private signer can produce a mathematically valid signature, but its forged token is rejected by internal auth consumers.
- [ ] **Step 3: Add browser flows.** Login to zeroauthy's console, inspect certificates, rotate, revoke a previous key, verify server state and import/delete a custom public set with stored-only notice. Simulate a committed rotation whose response is dropped; assert refresh happens and POST is not repeated. Cover tenant switch, read-only delegation and system-tenant exclusion without observing Auth0 UI. Do not hide a required scenario behind a skip unless the final report names it unavailable.
- [ ] **Step 4: Implement harness wiring and run focused checks.** Add `make e2e-signing` and wire local tests into CI. `go test ./tests/e2e/signing-server -run '^TestM20' -count=1`, targeted SQL-backed gRPC rollback tests, `make e2e-signing` and the new CLI/SDK entries must pass. These are database-backed; respect any active repository hold and record deferrals. Existing `make e2e` also keeps Plans 1–19 covered.
- [ ] **Step 5: Commit** `test(e2e): verify signing lifecycle across clients and instances`.

## Task 12: Operator documentation, full verification and completion records

**Files:** create `docs/{signing-keys.md,deploy-cli.md}`; update `README.md`, `docs/{management-api.md,console.md}`, plugin/store documentation, `docs/compat/{matrix.md,decisions.md,changelog-review.md}`, `docs/superpowers/plan-1-followups.md`, roadmap, spec and this plan. Add final evidence to the observation notes without raw tenant data.

**Interfaces:** produces the final acceptance report keyed by K1–K3/D1–D2 and AC1–AC11. Report each lane as passed, failed, deferred or unavailable with actual commands/results. Completion counts reflect implemented features; custom stored-only publication and retired shims do not masquerade as finished future resources.

- [ ] **Step 1: Document operations and limits.** Include certificate metadata/backfill, cache/in-flight revocation boundaries, prefetch/normal/emergency rotation and fresh Management API credential recovery. Explain no private-key import, custom stored-only state and future Plan 23 publication. Publish both deploy-cli formats, exclusions/normalization ownership, fresh-target bootstrap commands, protected credentials-file shape, `seed_mode: create_only`, rerun preflight and the danger of later overwrite-mode seeds. Resolve D-0039/D-0041 and keep algorithm/root-encryption/unrelated migration work open.
- [ ] **Step 2: Run the final required checks.** `gofmt -l` on changed Go files must be empty; `go vet ./...`, `go test -race ./...`, `./scripts/test-sql.sh`, `go generate ./...`, `make console`, `make check-sources`, `make e2e`, `make e2e-deploy`, `make e2e-signing`, and `make conformance` must report their actual outcomes. Verify generated files have no unexpected diff. The SQL script must cover SQLite/PostgreSQL/MySQL; the generic Go command alone is insufficient evidence. Require OpenSSL certificate-only PKCS#7 parsing and report conformance warnings/review-only/skips separately. If a later fix changes code, rerun affected checks and state which broad results predate it.
- [ ] **Step 3: Record the upstream lane.** Obtain the separate observer's dated export→local import→export report for both formats, or explicitly record missing credentials/entitlement/nonempty resources and the remaining comparison. No live credentials are required for local CI. Do not label an unavailable lane passing or conceal it in a global “all tests passed” claim.
- [ ] **Step 4: Review the whole change.** Verify the coverage table below against named tests/results, review trust boundaries and migration data-loss risks, and resolve findings. Update checkboxes and roadmap only after required implementation and available local checks are complete; preserve documented upstream limitations. Mark the design's recommendations as implemented decisions only where actually implemented.
- [ ] **Step 5: Commit** `docs: signing keys and deployment migration; Plan 20 records`. Leave merge/push to the user's instruction.

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
