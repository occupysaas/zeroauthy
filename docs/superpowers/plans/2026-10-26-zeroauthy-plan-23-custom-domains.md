# Plan 23 — Custom Domains and Automatic Certificates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Serve verified customer authentication domains with automatic certificate renewal or authenticated customer proxies, plus deployment-owned wildcard hosting and compatible management/console/tooling flows.

**Architecture:** A global hostname registry and pinned canonical identity unify legacy aliases and new verified domains. A fenced, store-backed ACME worker publishes encrypted certificates and shared challenges; TLS handshakes only read eligible material. Bind authentication artifacts and asynchronous user links to their public origin, preserving stable API audiences.

**Tech Stack:** Go 1.26.7, existing `golang.org/x/crypto/acme`, `crypto/tls`, `keys.Wrapper`, IDNA/public-suffix utilities, memory/SQLite/PostgreSQL/MySQL/gRPC, OpenAPI/protobuf generation, Vue/TypeScript, Vitest, Playwright, Pebble, local authoritative DNS and a fake DigitalOcean API.

**Spec:** [Custom domains design](../specs/2026-10-26-zeroauthy-custom-domains-design.md). Read both documents. Baseline `1b6ffef` includes Plan 22. Status: Tasks 1–14 complete; final review fixes and all required local acceptance checks passed. See the dated implementation record for actual outcomes and external/tool limits.

## Global Constraints

- Keep Go 1.26.7 and the existing Vue/TypeScript toolchain. Follow `CLEAN_ROOM.md`; original UI/copy only. A separate authorized observer supplies live upstream notes; unavailable evidence is never a passing lane.
- Nine API operations, at most 100 API-owned domains per tenant, 64 KiB request bodies, metadata at most 10 string values of at most 255 Unicode characters. DNS labels ≤63 bytes, normalized API hostname ≤253 bytes. No API ports, wildcards or IP literals.
- Canonical Management API audience is immutable. API-created names require fresh proof; operator/seed aliases retain privileged ownership and existing routing. `Tenant.Domains` is a projection, not a second independent authority.
- No issuance, DNS lookup or provider call from a TLS handshake. No private material in API reads, logs, traces, exports, URLs or browser persistence. Use versioned AAD with deployment/record/tenant/domain-generation binding.
- DNS proof: five-second total deadline, eight CNAME hops, 64 KiB records. Attempts: one/domain/30s and 20/tenant/minute across replicas. Retry 1m/5m/15m/1h/6h ±10%; pause initial verification at 72h. Existing proof-loss grace 24h.
- Lease duration 120s, heartbeat 30s, storage-clock expiry with `now >= expiry` rejected. Fencing and generation checked in the transaction that publishes state; no transaction spans external I/O.
- Renewal starts at two-thirds of actual certificate lifetime, jitter ≤5% of lifetime, before expiry; CA Retry-After honored. Expired certificates never served. Cleanup deadline 24h for expired order/challenge records.
- Diagnostics: ten seconds, 64 KiB response, two addresses maximum, no redirects or environment proxy, globally routable addresses only, DNS answers pinned to the dial. Provider calls: ten seconds; propagation: ten minutes with 5s–30s polling.
- Production supports HTTP-01 and TLS-ALPN-01; hosted apex/wildcard uses DNS-01 with DigitalOcean. CI uses only local CA/DNS/fake provider; never public CA orders or real DNS writes.
- Preserve PKCE, nonce/state, expiry, CAS/replay, consent, protection, tenant isolation and host-only cookies. Legacy empty Origin maps to pinned canonical origin; document reauthentication/reissue for pre-upgrade noncanonical grants.
- Plan 19's database-test hold applies only to Plan 19. Run Plan 23 database checks with their owning tasks. Merge, push and live provider use are separate actions from implementing this plan.

## Review Focus

1. Two tenants claim equivalent IDNA/case/trailing-dot names while seed or system APIs also change domains: one global owner wins; no canonical or private-origin shadowing. Tests in Tasks 2–4.
2. A worker loses its lease during a CA/DNS response, then a second worker or a recreated domain takes over: stale work cannot publish or delete a successor's challenge. Tests in Tasks 3, 8 and 9.
3. DNS changes between diagnostic resolution and connection, or a public proxy sends spoofed forwarded headers: no internal requests, tenant switch or attack-protection bypass. Tests in Tasks 6 and 13.
4. A default domain expires or is deleted while an email job is queued or a code is redeemed on another alias: no silent retargeting, token consumption or audience change. Tests in Tasks 5, 10 and 13.
5. Actual Deploy CLI has narrower header support, cannot clear defaults, and previously skipped template export: report these limits, require explicit preparation, and preserve strict comparisons. Tests in Tasks 11 and 13.

## File and dependency map

- `internal/customdomain/`: normalized rules, registry/lifecycle, DNS proof, proxy admission, link selection and bounded diagnostics; no private-key cryptography.
- `internal/certificates/`: wrapped TLS/account material, ACME order adapter, worker/leases, HTTP-01/TLS-ALPN-01, DNS-01 and DigitalOcean adapter; no tenant policy bypass.
- `internal/store/{custom_domains,tls_assets}.go`: models/contracts; memory/SQL/gRPC implement them, public aliases live in `pkg/store`. Migration is `0020_custom_domains.sql` in each dialect.
- Existing `internal/{tenant,tenantsetup,seed,app,config,httpx,authz,oauth,login,dbconn,mgmt,jobs,email,hostedlogin,ui}` receive focused integrations. Keep `internal/keycert` scoped to token-signing certificate representation.
- `console/src/pages/custom-domains/`: list/detail/DNS/proxy-secret components and tests; replace only that planned-page entry.
- `tests/e2e/domains/`: local DNS/CA/proxy/provider harness and isolated fixtures. Actual SDK/CLI/deploy clients remain pinned unless Task 1 records a necessary source-backed update.

Order: 1 → 2 → 3 → 4 → 5. Tasks 6 and 7 consume that shared foundation; 8 consumes 5/7, 9 consumes 8; 10 consumes 4–6; 11 integrates 5–10; 12 consumes 11; 13 and 14 close acceptance. Even where tasks could be parallel, preserve shared interface changes and review boundaries.

## Task 1: Freeze sourced wire and deployment contracts

**Files:** Create `internal/customdomain/inventory.json`, `internal/customdomain/inventory_test.go`, `docs/compat/observations/custom-domains.md`; modify `docs/compat/{decisions,changelog-review}.md`, source/license records only when needed. Read `api/management.yaml`, `tests/e2e/package.json`, pinned SDK domain request/types and Deploy CLI `customDomains`/`branding` handlers.

**Interfaces:** The inventory defines each operation ID/path/method/scope/request/response/error, all enums and empty/null rules, list query subset, one-time secret fields, and `active`, `stored-only`, `tool-unavailable` distinctions. This is the wire authority consumed by Tasks 2, 11 and 13.

- [x] Write `TestDomainInventory` asserting nine unique operations, `/default` literal precedence, 201 create/204 delete, `{domain}` default request/canonical response, no secret GET field, TXT-only verification, recommended-only TLS, the exact header enum and per-field limits from spec §3. First run must fail on missing inventory or wrong assertions.
- [x] Check public pages linked in spec §2 and current changelog since 2026-10-22. Freeze scopes, response verification/certificate enums, list fields, metadata key limits and upstream error codes from public references. Where prose conflicts with schema/examples, record the chosen local behavior and source; do not leave a later handler to guess. Record observer unavailable unless a separate authorized observer supplies notes.
- [x] Confirm public template GET/PUT contract against the pinned branding handler's `body` expectation. Record the minimal compatibility adjustment required to unblock real export, including treatment of Plan 22's existing `template` response consumers. No fabricated custom-domain fixture, silent omission or unsupported ACUL success.
- [x] Record Deploy CLI header restrictions and canonical-default preparation; pin a Pebble image digest and test-only DNS implementation/version/license. Define exact test network/ports without using a public CA or provider.
- [x] Run `go test ./internal/customdomain -run TestDomainInventory -count=1`; expect exit 0. Commit `docs: freeze custom domain and certificate contracts`.

## Task 2: Define models, validation and shared interfaces

**Files:** Create `internal/store/{custom_domains,tls_assets}.go`, `internal/customdomain/{rules,rules_test}.go`, `internal/certificates/types.go`; modify `internal/store/{store,types}.go`, `pkg/store/store.go`, repository adapters/mocks needed for compilation. New origin fields are persisted and exercised in Task 3; do not claim old codecs already preserve them.

**Interfaces:** `customdomain.NormalizeDNSName(raw string) (string,error)`; `ValidateCreate(raw []byte, reserved ReservedNames) (CreateInput,error)`; `ValidatePatch(raw []byte,current *store.CustomDomain) (PatchInput,error)`. `ReservedNames` contains system host, base domain and origin suffix. Inputs distinguish omitted/null/empty values.

Models:

- `Tenant.CanonicalHost string`; `Origin string` on `AuthTransaction`, `AuthCode`, `PushedAuthRequest`, `DeviceCode`, `LoginSession`, `RefreshToken`, reset/verification tickets; a selected origin on verification-email job payloads.
- `CustomDomain`: TenantID, ID, Domain, Type, Source, OriginHost, Generation, Revision; public settings; proof record/status/times; lifecycle/next-attempt/failure fields; proxy-key hash; active certificate reference. Deep-copy maps/bytes. Internal fields never marshal directly as public DTOs.
- `HostBinding`: normalized Host, TenantID, DomainID, Generation, Kind (`canonical`, `operator`, `public`, `origin`), Active. Pending public hosts remain claimed but inactive.
- `TLSAsset`: Key, Kind (`account`, `order`, `certificate`, `challenge`, `dns-intent`), TenantID/DomainID/Generation where applicable, Revision, Ciphertext, versioned PublicData, ExpiresAt; public metadata contains no private key.
- `TLSLease`: Key, Owner, Fence, Until. Fence never resets on release or reacquisition.

Repository contracts (ctx is `context.Context`; all returned objects are copies):

```go
// Store gains CustomDomains() CustomDomains and TLSAssets() TLSAssets.
type CustomDomains interface {
    Get(ctx context.Context, tenantID, id string) (*CustomDomain, error)
    List(ctx context.Context, tenantID string) ([]*CustomDomain, error)
    ListDue(ctx context.Context, limit int) ([]*CustomDomain, error)
    Create(ctx context.Context, row *CustomDomain) error
    Update(ctx context.Context, row *CustomDomain, expectedRevision int64) error
    Delete(ctx context.Context, tenantID, id string, expectedRevision int64) error
    GetHost(ctx context.Context, host string) (*HostBinding, error)
    PutHost(ctx context.Context, row *HostBinding) error
    DeleteHost(ctx context.Context, host, tenantID, domainID string) error
    GetDefault(ctx context.Context, tenantID string) (string, error)
    SetDefault(ctx context.Context, tenantID, domainID string) error
    AdmitAttempt(ctx context.Context, tenantID, domainID string) (time.Duration, error)
}
type TLSAssets interface {
    Get(ctx context.Context, key string) (*TLSAsset, error)
    Put(ctx context.Context, row *TLSAsset, expectedRevision int64) error
    Delete(ctx context.Context, key string, expectedRevision int64) error
    ListExpired(ctx context.Context, limit int) ([]*TLSAsset, error)
    ClaimLease(ctx context.Context, key, owner string, duration time.Duration) (*TLSLease, error)
    RenewLease(ctx context.Context, lease TLSLease, duration time.Duration) (*TLSLease, error)
    CheckLease(ctx context.Context, lease TLSLease) error
    ReleaseLease(ctx context.Context, lease TLSLease) error
}
```

List is all tenant rows; the service applies public query/projection. Due/expired lists use storage time and deterministic key ordering. PutHost creates a unique claim or updates only the same owner; GetDefault's empty ID means canonical. AdmitAttempt atomically applies both distributed attempt limits, returning zero duration on admission or a positive Retry-After on refusal with no partial counter mutation. Storage supplies time (inject a clock in memory tests; database current time in SQL). CheckLease participates in Store.WithTx so a subsequent write cannot race a takeover. Create uses expected revision 0; updates increment on success. Use ErrNotFound/ErrConflict/ErrInvalid and new ErrCustomDomainRepositoryUnavailable/ErrTLSAssetRepositoryUnavailable sentinels. Default selection, domain create/delete and projection changes are service transactions, never unrelated best-effort writes. Leaf package `customdomain` must not import `tenant`, `config` or `certificates`; pass local configuration/interfaces to avoid resolver/config cycles.

- [x] Add table-driven `TestDomainValidation`, `TestDomainQuerySubset`, `TestDomainCopies`: Unicode/ASCII identity, uppercase/trailing dot equivalence, 63/64-byte labels, 253/254-byte total, protected namespaces, URL/port/IP/wildcard rejection, cap100/101, metadata255/256 characters, null semantics, RP ancestor/public-suffix checks, eight/nine query terms and 1,024/1,025 bytes.
- [x] Run `go test ./internal/customdomain -run 'Validation|Query|Copies' -count=1`; expect RED before rules. Implement finite validation from Task 1; no general Lucene parser or per-request external suffix lookup.
- [x] Add model fields, interfaces and explicit unavailable stubs; update `pkg/store` exports and compile-only mocks. Run focused rules tests and `go build ./...`; expect exit 0. Commit `feat(domains): define domain ownership and TLS state contracts`.

## Task 3: Persist registry, grants, leases and TLS state in every driver

**Files:** Create `internal/store/memory/{custom_domains,tls_assets}.go`, `internal/store/sqlstore/{custom_domains,tls_assets}.go`, three `migrations/*/0020_custom_domains.sql`, `pkg/storetest/{custom_domains,tls_assets}.go`; modify tenant/grant/session/ticket repositories, `sqlstore/{codec,rows}.go`, `grpcstore/{codec,client_repos,server_repos}.go`, proto/schema generation and conformance/rollback fixtures.

**Interfaces:** Implement Task 2 repositories, atomic host uniqueness and storage-clock lease fencing under `Store.WithTx`. `Tenants.Create/Update/Delete` must maintain canonical/operator claims and cascade domain state; they cannot activate pending API names or steal an API/origin claim. Preserve Origin through every read/consume/rotation/update and exhaustive gRPC fixtures.

- [x] Write shared `CustomDomainClaims`, `CustomDomainCAS`, `CustomDomainDefaultRollback`, `CustomDomainCascade`, `TLSAssetCopies`, `TLSLeaseFence`, `OriginRoundTrip` tests. Assert one winner for same normalized hostname across tenants, rollback of default/host/domain changes together, same-owner-only claim mutation, no mutable aliasing, expired boundary rejection, monotonic fence on release/reclaim, stale lease cannot publish under a transaction, and domain deletion cannot remove deployment wildcard/account records. Distributed AdmitAttempt tests pin both limits and exact storage-time boundaries with two handles.
- [x] Run focused memory tests RED, then implement locking and copies. Write migration-from-0019 fixtures with nonempty domains, active grants/tickets and encrypted existing signing/email state before SQL implementation; migration must preserve original bytes and empty-origin meaning.
- [x] Implement SQL uniqueness/conditional writes and transactional adapters. Add two-independent-handle lease and default/domain races, including a fence check followed by a competing claim. Avoid a check-then-write outside the transaction.
- [x] Implement additive gRPC messages/RPCs, wrappers, error mapping and nested transaction behavior. Update all exact codec fixtures and plugin capability checks. Old plugin unsupported methods must fail explicitly, not appear as empty registry data.
- [x] Run `go generate ./...`, `go test -race -timeout=30m ./internal/store/memory ./internal/store/sqlstore ./internal/store/grpcstore ./pkg/storeplugin` and `./scripts/test-sql.sh ./internal/store/sqlstore/... -timeout=30m`; require actual exit 0 for all three dialects. Commit `feat(store): persist custom domains and fenced certificate state`.

## Task 4: Migrate canonical identity and reconcile privileged aliases

**Files:** Create `internal/customdomain/registry.go`, `internal/tenantsetup/domains.go` and tests; modify `internal/tenant/{resolver,management}.go`, `internal/seed/{apply,validate}.go`, `internal/mgmt/system.go`, `internal/app/app.go`, existing system/seed/store upgrade tests.

**Interfaces:** `tenantsetup.ReconcileDomains(ctx context.Context, st store.Store, baseDomain, systemHost, originDomain string) error`; `customdomain.ReconcileOperatorAliases(ctx context.Context, st store.Store, tenantID string, aliases []string) error`; `tenant.ManagementAPIIdentifier` consumes CanonicalHost after initialization. `customdomain.ResolveHost(ctx context.Context, st store.Store, host string) (*store.HostBinding,error)` is the registry read for later routing.

- [x] Write `TestCanonicalDomainUpgrade`, `TestDomainAliasOwnership`, `TestDomainMigrationRestart`: base versus no-base audience initialization, raw domain order preserved, expected managed audience/grants unchanged, localhost/ports survive only for operator aliases, canonical removal refused, omitted seed preserves API domains, explicit apply/create-only ownership, idempotent crash retry and conflicting reserved hosts reported.
- [x] Run focused tenantsetup/seed/system tests RED; implement startup reconciliation before listener/worker start. Existing `GetByDomain` callers consume the same active projection. Fail startup for unresolved audience drift or unsupported plugin capability; never run lazy migration inside TLS callbacks.
- [x] Test a seed/system update concurrent with API claim/deletion and new tenant canonical-name creation. Assert one global owner and no accidental promotion of pending public claims. Confirm reserved system setup remains reachable.
- [x] Run `go test -race ./internal/tenant ./internal/tenantsetup ./internal/seed ./internal/system ./internal/server`; expect exit 0. Commit `feat(domains): preserve canonical hosts and migrate operator aliases`.

## Task 5: Implement ownership proof and domain lifecycle

**Files:** Create `internal/customdomain/{dns,service,lifecycle}.go` and adjacent tests; update `internal/store` lifecycle helpers only through Task 2 contracts.

**Interfaces:** `DNSResolver.LookupTXT(ctx,name) ([]string,error)`, `LookupCNAME(ctx,name) (string,error)`, `LookupNetIP(ctx,network,name) ([]netip.Addr,error)` mirror bounded resolver needs. `NewService(st store.Store, resolver DNSResolver, cfg ServiceConfig, clock func() time.Time, random io.Reader) *Service`. ServiceConfig carries BaseDomain, SystemHost, OriginDomain strings and ManagedEnabled/OriginTLSReady booleans; it contains no provider credential. Production bounded DNS parsing uses the existing `golang.org/x/net/dns/dnsmessage` with explicit hop/response/deadline accounting, not an opaque lookup whose hidden CNAME chain cannot be counted. Methods: `Create(ctx,tenantID string,in CreateInput) (*store.CustomDomain,error)`, `Update(ctx,tenantID,id string,in PatchInput) (*store.CustomDomain,error)`, `Verify(ctx,tenantID,id string) (VerifyResult,error)`, `Delete(ctx,tenantID,id string) error`, `SetDefault(ctx,tenantID,host string) (*store.CustomDomain,error)`, `CheckDue(ctx) error`. `VerifyResult{Domain *store.CustomDomain; CNAMEAPIKey string}` holds the one-time secret only for the winning explicit call; canonical default returns nil Domain and is projected using CanonicalHost by Task 11.

- [x] Write `TestDomainProof`, `TestDomainVerificationBudgets`, `TestDomainOneTimeKey`, `TestDomainLifecycle`: correct RR/chunk comparison, wrong tenant/generation, NXDOMAIN, loop/deadline/size limits, distributed rate limits, exact retry schedule/72h pause, concurrent verify one secret winner, repeat verify no secret, self-managed background never activates, managed proof queues work but is not ready, fresh proof after recreate.
- [x] Observe focused RED, then implement cryptographic proof/key generation and only hashed proxy storage. Create allocates and globally reserves public/private-origin names atomically. Managed creation fails visibly if issuance disabled; self-managed creation checks origin TLS deployment prerequisites.
- [x] Add `TestDomainLossAndDefault`: 24h continuous loss grace, timeout recovery, suspension/reactivation, default pointer retained through temporary unavailability, default deletion canonical fallback and no automatic first-domain choice. Explicit unavailable selection returns 503; implicit new notifications choose canonical (Task 10 implements consumers).
- [x] Run `go test -race ./internal/customdomain ./internal/tenantsetup`; require exit 0. Commit `feat(domains): verify ownership and manage domain readiness`.

## Task 6: Enforce proxy admission and safe diagnostics

**Files:** Create `internal/customdomain/{proxy,diagnostics}.go` and tests; modify `internal/httpx/clientip.go`, `internal/tenant/{context,resolver}.go`, `internal/server/server.go`, `internal/config/{config,config_test}.go`.

**Interfaces:** `ProxyPolicy{Trusted []netip.Prefix; LegacyTrust bool}`; `Service.Admit(r *http.Request) (Admission,error)` with `Admission{TenantID, PublicHost, ClientIP, DomainID string}`; `Service.Test(ctx,tenantID,id string) (Diagnostic,error)`, `Diagnostic{Success bool; Message string}`. Put authenticated client identity in request context so all protection/logging/recorded-IP consumers share it. Test-only injected dialer/resolver are constructor dependencies, never tenant/deployment insecure options.

- [x] Write `TestDomainProxyAdmission`, `TestDomainClientIP`, `TestDomainHostSNI`: trusted immediate peer plus correct key required; private origin maps to stored public host regardless of spoofed XFH; foreign key, untrusted peer, plaintext origin, invalid/multiple IP, comma-list selected header and conflicting SNI/Host rejected before protection state changes. Disabled header uses peer. Preserve legacy trust behavior only in its explicitly documented mode; CIDRs constrain it when configured.
- [x] Write `TestDomainDiagnosticSSRF`: IPv4/IPv6/private/mapped addresses, mixed answers, DNS rebinding, redirects, environment proxy, >64KiB response, >10s, >two addresses, wrong issuer/cert all fail safely. The dial target must equal a validated answer; re-resolution may not choose a new internal address. Success verifies a real local fixture through the injected test transport; does not mutate domain state.
- [x] Run these tests RED; implement admission, header stripping and bounded probe. Local fixtures may use private networks only via test dependencies. No request data alters ACME/provider endpoints.
- [x] Run `go test -race ./internal/customdomain ./internal/httpx ./internal/tenant ./internal/protection ./internal/server`; expect exit 0. Commit `feat(domains): authenticate proxies and constrain domain probes`.

## Task 7: Add encrypted TLS material and certificate selection

**Files:** Create `internal/certificates/{secrets,tls,tls_test}.go`; modify `internal/config/{config,config_test}.go`, `internal/app/app.go` and app tests. Keep signing-key certificate code unchanged.

**Interfaces:** `Manager` takes Store, `keys.Wrapper`, deployment config and clock. `Seal(kind,key,tenantID,domainID string,generation int64,plaintext []byte) ([]byte,error)` and inverse Open use explicit versioned AAD. `GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate,error)`; `TLSConfig() (*tls.Config,error)`; `ValidateCertificate(chainPEM,keyPEM []byte, names []string, now time.Time, roots *x509.CertPool) error`. TLS mode selection follows spec §7 and requires known eligible registry hosts.

- [x] Write `TestTLSAssetAAD`, `TestDomainCertificateSelection`, `TestTLSConfigValidation`: ciphertext swap/deployment/directory mismatch and wrong master key fail; matching chain/key/SAN/EKU/time required; static/exact/wildcard precedence; no unknown-SNI default cert; no expired cert; deletion/store failure invalidates parsed cache eligibility; TLS1.0/1.1 rejected. Counters assert zero DNS/order calls from handshakes.
- [x] Add table tests for every new configuration field/default/range and invalid combinations: terms/email/deployment ID, challenge/listener pairing, no-base/system-origin SAN coverage, portless hosted suffix, credential-file requirements. Unknown configuration keys remain rejected.
- [x] Observe RED, implement encrypted persistence and bounded cache reads, listener TLS config and stable deployment identity. Opening persisted account state never automatically replaces it on decryption failure.
- [x] Run `go test -race ./internal/certificates ./internal/config ./internal/app ./internal/keys`; expect exit 0. Commit `feat(tls): select eligible encrypted tenant certificates`.

## Task 8: Coordinate ACME orders and shared HTTP/TLS challenges

**Files:** Create `internal/certificates/{acme,worker,http01,tlsalpn}.go`, adjacent tests and `acme_integration_test.go` (tag `domainintegration`); create `tests/e2e/domains/{compose.yaml,run-acme.sh}` for isolated service-level ACME tests; extend app worker shutdown and HTTP listener handling. Use Task 1's pinned test CA fixture configuration.

**Interfaces:** `Worker.Run(ctx context.Context)`, `Worker.Reconcile(ctx context.Context,key string) error`; resource key is `domain/<id>/<generation>` or `hosted/<deploymentID>/<baseDomain>`. `Manager.HTTPHandler(next http.Handler) http.Handler` exposes exact active HTTP-01 challenges and safe redirects. ACME adapter uses `acme.Client` account/order/authorization/finalization APIs; `OrderState` persists directory/account URL, order URL, requested SANs, encrypted order key, generation and next action before advancing. Challenge solver publishes through fenced store transactions; all replicas read the same state.

- [x] Write `TestACMEOrderRecovery`, `TestACMELeaseTakeover`, `TestSharedChallenges`, `TestCertificateRenewal`: one live lease/order workflow across two instances, lost reply/restart reuses saved order, stale fence cannot publish/delete challenge, domain deletion/recreation rejects old work, Challenge expiry boundary, renewal jitter/rate-limit schedule, renewal error retains valid old cert, expiry denies TLS, shutdown cancels cleanly.
- [x] Run focused tests RED with fake CA/time; implement save-before-network transitions, heartbeat, generation checks and atomic certificate+ready publication under `CheckLease`. Persist private challenge material encrypted. Bound all retries and classify safe public errors independently of raw CA payloads.
- [x] Add `TestChallengeRouting`: exact HTTP host/token GET/HEAD only; unknown token 404; no open redirect; POST never redirected; ALPN cert only for matching active challenge plus `acme-tls/1`, ordinary HTTPS always uses ordinary cert. Two-node challenge response must succeed when issuance and validation hit different nodes.
- [x] Run `go test -race ./internal/certificates ./internal/customdomain ./internal/app`; require exit 0. Run `./tests/e2e/domains/run-acme.sh http01,tlsalpn`, which starts isolated fixtures and executes `go test -tags=domainintegration -run 'TestPebbleHTTP01|TestPebbleTLSALPN01' ./internal/certificates -count=1`; require exit 0. Setup uses Create/Verify services with actual DNS proof, never direct ready-state writes. Task 13 later tests the public API/client boundary. Commit `feat(acme): coordinate orders renewal and shared challenges`.

## Task 9: Provision hosted wildcard certificates through DigitalOcean DNS

**Files:** Create `internal/certificates/{dns01,digitalocean}.go`, provider/worker tests and `tests/e2e/domains/{dns,provider}/` local helpers. Add license provenance for any new test DNS dependency.

**Interfaces:** `DNSProvider.Present(ctx context.Context,zone,name,value string) (DNSRecord,error)` and `CleanUp(ctx context.Context,record DNSRecord) error`, where DNSRecord includes provider ID, zone, name, value and whether this operation created it. The adapter uses the fixed DigitalOcean API origin in production; fake transport is injected in tests. Worker persists intent/ownership before and after provider calls through Task 3 assets.

- [x] Write `TestDNS01RecordOwnership`, `TestHostedWildcard`, `TestDNS01CrashRecovery`: distinct apex/wildcard TXT values at one name coexist; only created IDs are deleted; pre-existing/successor values survive; crash between create/recording ID recovers safely; duplicate external records cannot trigger broad cleanup; NS/CNAME challenge delegation rejected; provider timeout/rate-limit/token redaction, wrong zone, propagation deadline and cancellation enforced.
- [x] Observe RED; implement zone-relative names, 10s API deadlines, 10m propagation polling and fence-aware cleanup. Credential loading uses the configured token file and never tenant storage/exports. Cover both a test provider and the real HTTP adapter's authenticated request shapes against a fake API server.
- [x] Run `go test -race ./internal/certificates`; expect exit 0. Run `./tests/e2e/domains/run-acme.sh dns01` (selecting `TestPebbleDNS01` under the same integration tag) to complete a real Pebble DNS-01 order for apex plus wildcard via local authoritative DNS/fake DigitalOcean and assert one-label/system coverage, no arbitrary-depth or customer-name coverage, restart/renewal/two-worker behavior. Commit `feat(acme): issue hosted wildcard certificates with DNS-01`.

## Task 10: Bind grants, notification links and template context to public origins

**Files:** Create `internal/customdomain/links.go`; modify `internal/{authz,oauth,login,dbconn,session}` origin creation/consumption paths, `internal/mgmt/{auth,tickets,jobs}.go`, `internal/jobs/verify.go`, `internal/email/{context,notifications}.go`, `internal/hostedlogin/context.go`, `internal/ui/ui.go` and corresponding tests.

**Interfaces:** `SelectNotificationOrigin(ctx context.Context,tenantID,explicitHost string) (string,error)` returns explicit eligible host → usable default → canonical. `CheckOrigin(storedOrigin,canonicalOrigin,requestOrigin string) error` resolves empty stored origin to canonical and rejects mismatches before state mutation. Job payloads persist selected origin; executor rechecks ownership/readiness just before side effects. `tenant.Resolved` exposes public origin/domain metadata only.

- [x] Write `TestDomainOriginBindings` across code/PKCE/PAR/device/session/refresh/tickets/logout: same-origin success; alternate alias denied without consume/rotate/revoke/protection mutation; public origin persists across restart; deleting default cannot retarget grants. Assert canonical audience stays unchanged while `iss`, discovery and `/userinfo` use public host; M2M Management API issuer must match serving origin; system operator authentication remains separate.
- [x] Write `TestDomainNotificationOrigins`: explicit header/default/canonical selection, invalid/foreign header before ticket/job writes, queued selection stable across default changes, unavailable bound job sends nothing and fails visibly, unavailable implicit default falls back while pointer remains, old queued job/empty-origin artifacts use canonical. Assert pre-upgrade noncanonical grants need reauthentication/reissue rather than first-presenter binding.
- [x] Add `TestPublicCustomDomainContext` for email and hosted Liquid: public domain/metadata render; private origin/proof/key/certificate values absent; synthetic branding preview uses example data without DNS/store hostname resolution; context budgets/escaping retained. Keep every existing email/protection/login fixture.
- [x] Observe RED, implement propagation/checks and notification selection without weakening expiry/replay logic. Run `go test -race ./internal/authz ./internal/oauth ./internal/login ./internal/dbconn ./internal/session ./internal/mgmt ./internal/jobs ./internal/email ./internal/hostedlogin ./internal/ui ./internal/server`; expect exit 0. Commit `feat(auth): bind domain issuers and notification origins`.

## Task 11: Expose API contracts and wire the application lifecycle

**Files:** Create `internal/mgmt/custom_domains.go`, `internal/server/custom_domains_test.go`; modify `api/management.yaml`, generated API code, `internal/mgmt/{auth,clients}.go` (Handlers is currently in clients.go), `internal/tenantsetup/management.go`, `internal/config/config.go`, `internal/app/app.go`, `internal/server/server.go`, Plan 22 template handler only for Task 1's evidenced compatibility fix.

**Interfaces:** Generated nine-operation handlers consume Task 5 service and Task 6 diagnostics. Wire `CustomDomainService`/`CertificateManager` into existing dependencies; worker lifecycle starts after canonical reconciliation and capability/config validation, and stops before store close. DTO mapping never marshals internal store structs. Discovery/default routes have explicit precedence.

- [x] Write `TestCustomDomainManagementContract` with inventory-driven cases for all methods/statuses/scopes, null/empty/unknown fields, 64KiB/over-limit, cap100/101, foreign IDs, stale/revoked operator grants, reserved writes, literal default routing and unavailable store/issuance services. Assert a create response never says ready before proof/serving prerequisites.
- [x] Add `TestDomainSecretExposure`: reads/list projections/errors/logs/exports omit proxy/private keys; only winning first verify returns key; failed transaction returns none; uncertain reply does not generate another key. Verify metadata and stored-only RP behavior on actual routes.
- [x] Observe RED, implement API/authorization and app startup/listener/worker wiring, explicit readiness/config diagnostics and safe shutdown. Add the minimal sourced branding-template compatibility adjustment from Task 1 and preserve documented existing client behavior with regression tests.
- [x] Run `go generate ./...`, `go test -race ./internal/mgmt ./internal/server ./internal/app ./internal/config ./api`, `go build ./...`; require exit 0. Commit `feat(mgmt): manage custom domains and activate certificate services`.

## Task 12: Build accessible domain administration

**Files:** Create `console/src/pages/custom-domains/{CustomDomains,DomainDetail,DNSInstructions,ProxySecret}.vue` and adjacent tests; modify `console/src/{api/client,router}.ts`, `layout/sections.ts`, `locales/en.ts`, `pages/planned/index.ts` and planned-page tests; remove the obsolete custom-domain placeholder; build through normal commands.

**Interfaces:** API client wraps Task 11 generated wire types. List/detail model owns fetch sequence IDs and tenant cancellation. ProxySecret accepts only the transient successful verify response and clears on navigation/unmount; it never re-fetches or persists the key. Default state distinguishes configured versus currently usable.

- [x] Write tests for add/edit/delete, TXT/CNAME routing instructions, certificate progress/expiry/retry errors, ready-only default changes, canonical reset, unusable default display, IP header settings and stored-only RP label. Use localized labels and original copy.
- [x] Write `DomainSecret.test.ts` and `DomainRaces.test.ts`: secret revealed only once, no browser persistence/URL, uncertain verify refreshes ordinary status but never retries/reconstructs key; failed reads lock writes; reversed tenant replies and cancelled polls cannot leak data; selected drafts survive safe navigation/errors. Keyboard and screen-reader labels asserted.
- [x] Observe Vitest RED, implement the screens using existing form/components/API conventions. `make console` must pass lint, typecheck, full tests, schema generation and build. Add browser narrow/wide and keyboard acceptance to Task 13. Commit `feat(console): configure and diagnose custom domains`.

## Task 13: Verify actual clients, migration and domain-hosted authentication

**Files:** Create `tests/e2e/{m23-node-auth0.mjs,m23-mgmt-cli.mjs,m23-domains.spec.mjs,run-m23-domains.sh}`, extend `tests/e2e/domains/compose.yaml` and harness helpers; modify `Makefile`, CI, deploy manifest/normalizer/comparator/fixtures and `m20-deploy-cli.mjs`. Keep separate existing branding/email/default lanes.

**Interfaces:** Add `make e2e-domains`, which boots isolated CA/DNS/provider/proxy and two zeroauthy nodes against a shared persistent store. Harness emits readiness only after listening and uses real scoped API calls for domain state, never direct fixture writes that mark an unproved domain ready. Public addressing restrictions are overridden solely through injected test transports; trust Pebble's test root explicitly.

- [x] Actual node-auth0 7.4.0 and Auth0 CLI 1.37.0 must exercise all nine operations, using raw `auth0 api` only where no high-level command exists. Assert scopes, list/default shapes, one-time key, state transitions, deletes, wrong tenant, query limits and rejected writes.
- [x] Add real Pebble HTTP-01/TLS-ALPN-01 and hosted DNS-01 cases: validation hits the other node, restart mid-order, two claimants, key persistence, accelerated renewal, CA outage, certificate expiry, stale-worker resume, domain delete/recreate and cache invalidation. Confirm expired certificate handshakes fail and no on-demand unknown-host orders occur. Assert fake DigitalOcean cleanup preserves unrelated TXT records.
- [x] Add proxy and browser cases: public-domain discovery/PKCE/custom branding, correct `iss`/stable `aud`, independent cookies, refresh/replay cross-host rejection, reset/verification/default links, authenticated proxy IP passed through attack protection, wrong key/peer/Host/SNI, diagnostic rebinding, lost verify reply, stale console tenant response, keyboard and 390/1280px layouts.
- [x] Add strict YAML/directory × generated/preserved migrations with nonempty custom domains/settings and Universal Login template body. First demonstrate a source default cannot import onto an unverified target. Then import declarations, prove domains through local DNS/API, explicitly clear target default when source is canonical, and import final defaults. Verify repeat stability and detect missing/changed domain/header/metadata/RP/default/template data. Assert pinned CLI rejection for API-only `x-azure-clientip`/empty header; report tool-unavailable rather than normalizing. Proxy keys, certificates and target-specific proofs are never migrated. ACUL remains excluded.
- [x] Run `E2E_CHROMIUM=/usr/bin/chromium make e2e-domains`, `make e2e-deploy`, `make e2e-branding`, `make e2e-email`, `make e2e` (use the installed browser path available in the execution environment). Require real exit 0 for supported lanes; record intentional skips and unavailable live-provider/upstream cases separately. Commit `test(e2e): verify custom domains certificate renewal and migration`.

## Task 14: Final acceptance, documentation and review

**Files:** Create `docs/custom-domains.md` and a dated Plan 23 implementation record; update README, roadmap, `docs/{branding,email,deploy-cli,console}.md`, compatibility matrix/decisions/changelog/observations, follow-ups, this plan and source/license records. Do not edit CLEAN_ROOM.md.

- [x] Review AC1–AC11 against the map below, perform the implementation workflow's whole-branch review, fix findings with regressions, and rerun affected checks. Pay particular attention to central registry writes, source-default migration, lease fencing inside transaction boundaries, secret loss and notification-origin readiness.
- [x] Run `git diff --check`, changed-Go formatting, `go vet ./...`, `go test -race -timeout=30m ./...`, `./scripts/test-sql.sh ./internal/store/sqlstore/... -timeout=30m`, `go generate ./...` twice, `make console`, `make check-sources`, all five E2E targets from Task 13 and `make conformance`. Expect exit 0; second generation must add no diff. Record actual OIDC pass/failure/warning/review/skip counts, not certification.
- [x] Document the coordinated fleet rollout (drain/stop older nodes before migration; no mixed old/new serving), configuration/ports, DNS proof versus routing, self-managed trust boundary, one-time secret loss, shared wrapper keys/backups, wildcard/provider ownership, renewal/expiry alarms, existing-alias migration, pinned canonical audience and legacy noncanonical reauthentication. Define rollback: stop new workers/listeners before restoring the old binary/schema; restore a pre-upgrade backup for schema rollback, never make the old resolver consume new pending aliases.
- [x] Record local decisions and precise upstream/tool limits, staged default imports and template-export supersession. Mark roadmap done only after acceptance; no hypothetical test result counts as evidence. Commit `docs: custom domains and certificates; Plan 23 records`.

## Acceptance mapping and handoff

| Acceptance | Tasks |
|---|---|
| AC1 wire/client/evidence | 1, 2, 11, 13 |
| AC2 storage/migration/canonical identity | 2, 3, 4 |
| AC3 proof/lifecycle | 3, 5, 11 |
| AC4 shared ACME/renewal | 3, 7, 8, 13 |
| AC5 hosted DNS-01/provider ownership | 3, 7, 9, 13 |
| AC6 proxy/network boundaries | 6, 7, 8, 13 |
| AC7 authentication/notification origins | 4, 5, 10, 13 |
| AC8 console | 11, 12, 13 |
| AC9 migration/tools | 1, 11, 13 |
| AC10 final regression gates | 3, 13, 14 |
| AC11 operator documentation | 14 |

Self-review must check every interface name, storage generation/lease boundary and spec number against this plan before execution. Implementation checkboxes follow the committed task ledger and final acceptance evidence. Recommended execution is native/inline because registry, certificate and origin contracts are tightly coupled, with one fresh whole-branch review after implementation. Implementation was separately authorized and completed under the task ledger; merge and push remain separate user actions.

Draft self-review completed 2026-10-26: AC1–AC11 map to tasks; repository signatures and attempt-budget persistence were made explicit; the DNS adapter must expose bounded wire parsing; early ACME tasks own a runnable local CA harness; provider/default-import limitations and unavailable queued-domain behavior have concrete tests. The fresh design check and its resolutions are recorded in spec §10. Only document structure/link checks ran during drafting.


## Final implementation acceptance — 2026-10-26

Tasks 13–14 complete. Whole-branch review found six Important issues and two
console issues regraded Important; regressions reproduced each before fixes.
Review fix commit `44d141a`; migration parser regressions/fix `5cc4514`.
All final required commands exited 0: Go race/vet, three SQL dialects,
generation twice without generated changes, console (373 tests), source checks,
domains/deploy/branding/email/baseline E2E and local conformance. Deployment
completed all four YAML/directory × generated/preserved modes with real domain
proof, strict defaults and nonempty template-body comparisons. Baseline browser:
24 passed, 9 dedicated-harness skips. Domains: three real local Pebble lanes,
actual pinned SDK/high-level CLI and two browser cases. Conformance: 46 passed,
0 failed, 12 warnings, 16 review, 8 skipped; no certification claim.

See [implementation record](../2026-10-26-plan-23-implementation-record.md) and
[operator guide](../../custom-domains.md). No real provider credentials, public
CA orders or authenticated upstream observations were used. RP enforcement,
custom public signing JWKS publication, ACUL, prompt-partial domain context and
additional DNS providers/delegation remain explicit follow-ups. Branch integration
is separate from implementation acceptance.
