# zeroauthy — Plan 20 design: signing keys and deploy-cli migration

- **Status:** Draft for review; implementation has not started. Proposed local decisions below are not prior maintainer approvals or observed Auth0 behavior.
- **Date:** 2026-10-25
- **Roadmap:** [Plan 20, slice 5b](2026-10-19-zeroauthy-management-roadmap-design.md#plan-20--signing-keys-and-the-auth0-deploy-cli-round-trip-slice-5b).
- **Basis:** Plan 19 completed and merged at `d9ecb6e`. Follow [CLEAN_ROOM.md](../../../CLEAN_ROOM.md), D-0039 and D-0041 in [the decision log](../../compat/decisions.md), and the existing client/connection/API observation notes.
- **Deliverable of this document:** the design for Plan 20. A separate implementation plan follows design approval.

## 1. Outcome and scope

Operators can inspect, rotate and revoke a tenant's managed signing keys through the Management API and Settings. Rotation changes subsequent token issuance across instances; revocation removes the public key and stops zeroauthy from accepting its tokens. Existing installations gain certificate metadata without changing their key IDs or invalidating tokens.

The same milestone establishes a repeatable migration check: export supported resources with the unmodified Auth0 Deploy CLI, import them into zeroauthy, export again and compare configuration and references. Both YAML and directory formats are covered. A documented bootstrap preserves application IDs and operator-supplied secrets when required.

Included:

- Four managed signing-key endpoints, durable lifecycle/certificate metadata, shared-store behavior, and a live Signing keys Settings page.
- GET/PUT/DELETE for custom **public** signing-key sets, with explicitly stored-only behavior until the custom-domain publication feature is implemented.
- Deploy-cli resource inventory, exclusions, normalization, local regression harness and a separate authorized Auth0 export lane.
- Credential-preserving bootstrap using the existing create-only seed, resolution of the system API naming issue, and minimal compatibility responses for retired Rules/Hooks resources.
- Memory, SQLite, PostgreSQL, MySQL and gRPC store parity; API schemas, SDK/CLI/browser coverage, operator and compatibility records.

Excluded: customer-managed root encryption keys, importing private token-signing keys, remote signers/HSMs, scheduled automatic rotation, new JWT signing algorithms, custom-domain provisioning, token re-signing proxies, Rules/Hooks execution, and general migration of users/sessions/refresh tokens/jobs. Signing material and runtime user state are not deploy-cli configuration resources.

Use the current Go/Vue toolchains and repository conventions. Keep public API payloads Auth0-shaped, tenant isolation intact, private keys envelope-encrypted, console tokens in memory, and copy original/localized. Audit successful management writes with actor, tenant and affected key IDs; never include private material, application secrets or bearer tokens. No product code is part of this spec change.

## 2. Public evidence and implementation gate

Public sources reviewed on 2026-10-25:

| Source | Design consequence |
|---|---|
| [List signing keys](https://auth0.com/docs/api/management/v2/keys/get-signing-keys), [get by ID](https://auth0.com/docs/api/management/v2/keys/get-signing-key) | Public responses contain certificates, fingerprints, state flags and lifecycle timestamps; the existing public JWK alone is insufficient. |
| [Rotate endpoint](https://auth0.com/docs/api/management/v2/keys/post-signing-keys) | Documented success is 201 with `cert` and `kid`; its descriptions refer to the next key. Determine precisely which key is returned. |
| [Revoke endpoint](https://auth0.com/docs/api/management/v2/keys/put-signing-keys), [revocation guide](https://auth0.com/docs/get-started/tenant-settings/signing-keys/revoke-signing-keys) | Success is 200 with `cert` and `kid`; the guide permits revoking previously used keys and says revocation is irreversible. |
| [Rotation guide](https://auth0.com/docs/get-started/tenant-settings/signing-keys/rotate-signing-keys) | Current and queued keys are published before promotion; old tokens need the prior public key while still valid. Multiple successive rotations need explicit evidence. |
| [Custom-key guide](https://auth0.com/docs/get-started/tenant-settings/signing-keys/customer-signing-keys), [GET](https://auth0.com/docs/api/management/v2/keys/get-custom-signing-keys), [PUT](https://auth0.com/docs/api/management/v2/keys/put-custom-signing-keys), [DELETE](https://auth0.com/docs/api/management/v2/keys/delete-custom-signing-keys) | This is public JWKS distribution, not a private-key signing API. The guide limits the set to ten keys, ties aggregate publication to custom domains, and excludes customer-signed tokens from Auth0 API consumption. |
| [Deploy CLI overview](https://auth0.com/docs/deploy-monitor/deploy-cli-tool), [9.1.0 configuration](https://github.com/auth0/auth0-deploy-cli/blob/v9.1.0/docs/configuring-the-deploy-cli.md) | Pin the tool; exclusions are resource-type names, and deletion can be disabled. Export/import behavior is version-dependent. |
| [Existing client observations](../../compat/observations/management-clients.md), [API observations](../../compat/observations/management-apis.md), [connection observations](../../compat/observations/management-connections.md) | Version 9.1.0 omits client secrets, matches clients by ID/name, handles connection enablement separately, and excludes Auth0's Management API by name. |

The roadmap's phrase “used for signing” for `/keys/custom-signing` is superseded by this document: uploading a public key cannot enable zeroauthy to sign with it. Never infer private-key import or internal trust from that resource's name.

**Task 1 of the future implementation plan** reviews the changelog since the last recorded review and freezes these evidence rows before dependent coding. A separate observer uses documented APIs on the maintainer's authorized dev tenant, following the role separation in CLEAN_ROOM.md. The implementer consumes public documentation and sanitized notes only. This spec involved no live tenant calls.

| ID | Facts to freeze in observation notes and a Plan 20 decision |
|---|---|
| K1 | Managed-key endpoint scopes, schema/field omission, ordering/history limits, ID validation, unknown IDs, missing scopes, request-body handling and exact error/status identifiers. |
| K2 | Rotation response identity; first and successive rotations; previous-key retention/automatic retirement; eligibility for revoke; duplicate revoke; lifecycle timestamp transitions and certificate encodings. |
| K3 | Custom-key scopes and entitlements, no-set GET/DELETE, full replacement semantics, valid key types/algorithms/operations, duplicate/missing IDs, private fields, size/count limits and unknown fields. |
| D1 | Pinned deploy-cli resource registry, HTTP calls, export/import order, supported resource fields, secret omissions, system API exclusion, identifier/name matching and repeat-import behavior in both formats. |
| D2 | Retired `/rules`, `/rules-configs`, `/hooks` collection shapes, accepted listing parameters/scopes and documented write rejection behavior for tenants without those features. |

Record each finding as observed, documented or a named local fallback. A missing entitlement is not a successful observation. Exact wire details unresolved by docs remain a Task 1 gate, not permission to guess parity. Freeze an endpoint/schema inventory and concrete fixtures there; update this draft if evidence changes its lifecycle guarantees or scope.

Rotation and revocation cannot restore the old private-key lifecycle. Use a disposable tenant where possible; do not call them on a shared dev tenant merely because another application was created. The observer must establish that the tenant is disposable or has explicit authorization for the irreversible key changes. Otherwise use documentation/local fallbacks and record the missing observation. Upstream export is read-only; upstream import/deletion is outside this migration check.

## 3. Managed signing keys

### 3.1 API and authorization

| Operation | Intended scope | Success contract |
|---|---|---|
| `GET /api/v2/keys/signing` | `read:signing_keys` | 200, documented key list |
| `GET /api/v2/keys/signing/{kid}` | `read:signing_keys` | 200, documented key record |
| `POST /api/v2/keys/signing/rotate` | `create:signing_keys` | 201, certificate and ID identified by K2 |
| `PUT /api/v2/keys/signing/{kid}/revoke` | `update:signing_keys` | 200, revoked certificate and ID |

The existing scope catalog already contains these names. Reuse the tenant Management API authorization and operator delegation paths. A key ID is always resolved inside the authorized tenant. Missing/wrong-tenant IDs disclose no foreign metadata. Add operations and `x-source` URLs to `api/management.yaml`, regenerate Go and console types, and centralize validation/projection in a shared rules package. No private JWK or encrypted private blob is returned.

### 3.2 Lifecycle and concurrency

Exactly one current and one next managed key exist for an initialized tenant. The next key is visible in JWKS before it is selected for signing. Rotate commits current→previous, next→current and creation of a fresh next key as one store operation. Generate/encrypt the new key before entering the mutation; a generation, storage or audit-transaction failure leaves the old state usable and returns no success.

**Proposed local default:** preserve all unrevoked previous keys across successive rotations. The current store contract automatically changes older previous keys to revoked, so it must be reviewed and changed rather than simply exposed over HTTP. If K2 establishes different Auth0 retirement behavior, explicitly resolve that difference in the design/decision log before implementation; do not silently discard keys to keep a three-key array. Retain revoked metadata for audit; response history filtering, if any, is independent of retention. No time-based pruning is introduced here.

Revoke is an atomic transition of an eligible previous key. Current/next revocation is rejected without mutation. Repeated and unknown-key responses follow K1/K2; neither may resurrect a key. Set lifecycle timestamps once using one operation clock. Keep `current_since`, `current_until` and `revoked_at` distinct from `CreatedAt`; project absent values according to K1.

Mutations serialize in the shared store, not just `Manager.mu`. Concurrent rotations may both succeed in a defined serial order; each response must describe its own committed operation, not a later list read. Concurrent rotate/revoke and restart must preserve the one-current/one-next invariant. Extend `SigningKeys` in memory, transactional views, SQL and gRPC with atomic operations/results; update public store aliases, proto/codecs, tenant deletion and store conformance tests. Prevent a failed CAS/transaction from partially retiring keys or creating an orphan next key.

### 3.3 Runtime trust and cache behavior

Every Sign/Verify operation chooses managed-key eligibility from authoritative store state. The current signer cache may cache cryptographic objects by tenant/key ID, but never authorizes a stale key by itself. Evict locally retired signers; another instance must consult current state even if it retains an old object. Store errors fail closed.

After a revocation commits, verification started afterwards rejects that key across instances, including Management API tokens, `/userinfo` and other callers of the key manager. Audit all verification consumers. An operation whose key-state read preceded the commit may finish using that snapshot; do not promise cancellation of already-running requests. Opaque refresh tokens and sessions are not globally deleted by signing-key revocation; normal eligible refresh exchanges issue tokens under the new current key.

JWKS excludes revoked keys. Keep the existing five-minute public cache policy unless K2 requires a documented change; explain that remote consumers can retain an already-cached public key and zeroauthy cannot force immediate third-party revocation. Exercise unknown-`kid` refresh with the pinned SDK. Rapid successive rotations can promote a key a client has not fetched yet, so cache refresh behavior is part of the operational guidance.

**Separate trust from publication now:** internal verification uses only managed issuer keys. It must not begin trusting arbitrary uploaded custom keys when a future custom-domain JWKS aggregates both collections. JWT `alg` and `kid` checks remain strict; no HS256/PS256 expansion is bundled into this work.

### 3.4 Certificates and upgrades

Store a stable X.509 public certificate for each managed key and derive `cert`, certificate fingerprint/thumbprint and PKCS#7 representation from it. The certificate public key must match the stored JWK and the encrypted private key; validate with parsers and independent hash/encoding assertions. Certificate fingerprint fields are not the existing RFC 7638 key ID. Persist lifecycle metadata and the certificate in all drivers; use nullable migration fields for existing rows.

**Proposed local certificate policy:** self-signed RSA certificates for key representation, with random positive serials, non-identifying subject text, a five-minute clock allowance and ten-year validity. They are not TLS identities or a PKI trust chain. Freeze exact presentation/hash encodings from K1/K2; use SHA-1 only if required for a compatibility fingerprint, never for token signing. PKCS#7 must contain real parseable certificate data, not PEM with a changed label. Dependency choice is left to the implementation plan after checking existing packages and licenses.

Upgrade backfills certificates once, through the key manager using the existing wrapper, without changing private material, public parameters or `kid`. Use a compare-and-set/transaction so concurrent startup cannot overwrite the winning certificate. If no trustworthy historical transition time exists, leave it unknown where the public contract permits; any required synthesized timestamp must be a documented fallback, not invented historical precision. Already-revoked rows stay revoked. Refuse to serve an incomplete key API if required backfill cannot complete; never rotate as a recovery shortcut. Restart must reproduce identical certificate bytes and lifecycle metadata.

## 4. Custom public signing keys

Implement documented GET, PUT and DELETE on `/api/v2/keys/custom-signing`; PUT replaces the entire set atomically. Store the validated public JWKS as a separate tenant-scoped record in every driver. K3 freezes scopes/statuses, absent-set representation and field inventory. Bound requests using the existing HTTP limits and the documented ten-key maximum.

This plan stores the resource for compatibility. It does **not** add it to canonical JWKS, choose it for signing, fetch `x5u`, or use it to verify tokens presented to zeroauthy. Aggregate custom-domain publication is a named Plan 23 follow-up. The console, operator docs and compatibility matrix state this limitation. This is the roadmap's permitted stored-only fallback; managed keys are fully enforced.

Validate public RSA/EC parameters against the documented supported combinations and reject private/symmetric material, including RSA `d`/primes, EC `d` and symmetric `k`. Check unique usable key IDs, compatible `use`/`key_ops`/`alg`, and parseable bounded certificate chains when present; never dereference uploaded URLs. Explicitly reject collisions with managed IDs under the proposed local security policy, recording any upstream difference. A malformed member leaves the entire prior set intact. Arbitrary uploaded keys must not make forged Management API, userinfo or logout tokens acceptable. Public material may be returned; audit only identifiers and operation metadata.

## 5. Deploy-cli round trip and migration decisions

### 5.1 A versioned, growing contract

Start with `auth0-deploy-cli` **9.1.0**, matching the existing observation records; pin the package and lockfile and record its resolved version. Keep the current Auth0 CLI/SDK pins unless a documented incompatibility requires a separate update. Run the CLI unchanged over the existing local TLS/domain harness; do not patch its handlers or disable certificate validation globally.

Initial nonempty fixture families are `clients`, `resourceServers`, `clientGrants`, database connections (`databases`/`connections` according to the registry), `tenant` and `attackProtection`. Exercise enabled-client relationships, nested settings, tenant defaults, API audiences and client-grant scopes. Fields accepted but inert in previous milestones remain visibly so; export equality alone does not prove runtime parity. Custom signing keys and managed private keys are not presumed to be deploy-cli resource families; exercise them through the SDK/API.

Task 1 records every handler in the pinned registry in a checked-in manifest: included with fixture/test evidence, excluded with roadmap owner/reason, or tool-unsupported. Generate/validate the exact `AUTH0_EXCLUDED` array from that inventory. Do not hand-copy a list from the current unpinned documentation or silently exclude a supported family after an assertion fails. Retired-resource shims are tested separately if the pinned CLI no longer calls them.

Local CI lane, independently for YAML and directory formats:

1. Provision isolated source/target tenants and tool clients; export a nonempty supported source fixture.
2. Import into a fresh target, export again, and compare canonical configuration plus relationship identities.
3. Import the same input a second time and require stable IDs, counts, secrets and relationships; export/compare again.
4. Change one supported setting and relationship in the input, reimport, and prove the change through API reads and one relevant runtime flow. Retain unrelated resources with `AUTH0_ALLOW_DELETE=false`.
5. Exercise each documented format's file references/custom database scripts with original synthetic fixtures and stable content hashes. Treat exports as data; do not execute source scripts as part of comparison.

The comparison normalizes only named differences: generated target IDs through an explicit reference map, timestamps/read-only fields, documented omitted secrets, documented defaults, set ordering, and source/target tenant URLs. Use a per-resource field allowlist with a reason for each normalization; preserve ordered data and validate all rewritten references. Duplicate names or ambiguous matching fail preflight. Unknown fields, dangling references, lost scopes, incorrect secret placeholders and unexpected resource removal fail, not disappear into normalization. Emit a redacted machine-readable diff and resource counts so an empty export cannot pass.

The authorized upstream lane is export from the maintainer's dev tenant → local zeroauthy import → local export → the same comparison. The observer owns upstream access and supplies sanitized fixture/evidence artifacts. Keep raw exports/credentials in restricted temporary storage, never source control or CI logs. It is a separately reported compatibility run; local source→target success does not establish upstream parity. If credentials, entitlements or supported nonempty source resources are unavailable, report that lane as unavailable and retain the follow-up rather than claiming it passed.

### 5.2 Preserving application IDs and secrets (D-0039)

**Proposed decision:** reuse the existing offline `zeroauthy seed` create-only mode to bootstrap client IDs and known plaintext secrets, then let deploy-cli update the matching clients. Keep caller-supplied `client_id` rejection on the public create endpoint; no new migration-only Management API extension is needed.

Provide a documented bootstrap recipe and a small fixture/helper that maps exported client metadata to the existing seed shape. Secrets come from an operator-owned protected input, never inferred from deploy-cli export, emitted in a diff, or supplied in process arguments. Include public clients without secrets. Reject ambiguous client names/IDs, unsupported immutable attributes, incompatible secrets and existing target ID/name conflicts before import. Do not bypass existing validation to accommodate an unknown source credential.

Create the destination tenant and its tool/bootstrap resources with the create-only seed before the first deploy-cli import. Do not create that tenant through the system API: the existing seed skips API-origin tenants, including their children. Require a fresh destination apart from these bootstrap resources. On repeat execution, verify existing clients match the recorded migration identity and authentication configuration before create-only seed skips them; a skipped client is not proof its secret matches. The helper compares supplied secrets to stored credentials internally using the existing wrapper/hash support and constant-time comparison, without emitting either value. Prove supplied M2M test credentials also authenticate through a synthetic client-credentials flow; confidential web clients need not support that grant, and public clients have no secret to compare. Do not add grants to production clients merely to test credentials.

Create-only is a seed application mode, not a transfer to API ownership. Keep this deployment in create-only mode after migration and stop supplying bootstrap files once they are no longer needed; applying an overwrite-mode seed later can overwrite seed-origin records. The recipe must say this explicitly. It must also avoid reapplying tenant Management API defaults through bootstrap setup after operators have changed them: preflight a completed bootstrap and skip seed execution on reruns. Preserve neither system operator clients nor deploy-cli's own credentials from the source.

The regular round-trip lane also supports generated target IDs with reference mapping. Missing confidential-client secrets mean new credentials are required; clearly distinguish that mode from credential preservation. After either mode, connection enablement and grants must refer to the correct destination clients. No migration claims to preserve issuer/domain, existing user sessions, or previously issued Auth0 tokens.

### 5.3 System API naming (D-0041)

**Proposed decision for approval with this spec:** use `Auth0 Management API` as the compatibility resource name for ordinary tenants, so the unmodified pinned tool's existing system-resource exclusion works. Retain zeroauthy branding in product copy and retain the system operator API `urn:zeroauthy:management`. API identifiers, IDs, scopes, policies and authorization remain unchanged.

Update bootstrap and upgrade only the known built-in tenant Management API selected by its system marker and canonical identifier, never by display name alone. Do not rename user APIs that happen to share a name. Preserve existing configurable lifetimes/policies during this migration. Verify exports omit the built-in resource while retaining a normal user API. Because the tool's exclusion is name-based, migration preflight must detect a user API named `Auth0 Management API` and fail with an actionable rename instruction rather than silently omit it. Document the observable name change and add the resolution to D-0041 when implementation is approved.

### 5.4 Retired resources

For documented `/api/v2/rules`, `/api/v2/rules-configs` and `/api/v2/hooks` collection GETs, return the K/D evidence's empty representation with correct scope checks and supported list parameters. Writes never report success for unimplemented execution features; use the documented/observed rejection status and error identifier for a tenant without them. Inventory exact methods and any detail/secret routes in D2 before planning those handlers. Do not invent blanket catch-all success routes or imply Rules/Hooks runtime support. Record the compatibility shim separately from roadmap resource-completion counts.

## 6. Console and operational behavior

Add Signing keys under the live Settings area using existing components, routing and English catalog conventions. Show current, queued, previous and revoked state, available lifecycle times, key ID and public certificate details. Allow copying/downloading public certificates. No private-key upload/export control is offered.

Rotate and revoke each require confirmation explaining affected tokens and public-key caching. Revoke is available only for an eligible previous key; the server rechecks stale views. Lock mutations while a request is pending, refresh after success, and preserve useful errors. A network timeout after rotate has an uncertain outcome: refresh state before allowing another rotation, with no automatic POST retry. Do not bundle a multi-request “rotate and revoke” button in this milestone.

Honor delegated permissions, keyboard/focus behavior, light/dark themes and accessible status/error announcements. The custom public-key area exposes validated set replacement/deletion and a persistent stored-only notice; show the current public set without suggesting it controls token issuance. Its destructive replacement uses the same confirmation/pending-state patterns.

Operator guidance covers prefetching the next key, normal/emergency rotation, revocation/cache delay, obtaining fresh Management API credentials if the previous token was revoked, restart/backfill failures, and two-instance behavior. Document migration bootstrap, format examples, normalization/exclusion ownership and secret handling. Carry custom-domain publication to Plan 23 and keep notifications (Plan 21), encryption-key management and new algorithms in their existing scopes.

## 7. Acceptance criteria and review focus

| ID | Required evidence |
|---|---|
| AC1 | All managed-key operations match frozen schemas, scopes, field omissions, statuses and errors through API contract tests and pinned `auth0 api`/SDK clients; tenant A cannot inspect or mutate B's key. |
| AC2 | Token issued before rotation still verifies with an eligible previous key; tokens issued afterwards use the promoted key; explicit revoke removes it from JWKS and rejects its tokens. Successive rotation retention matches K2/the recorded fallback. |
| AC3 | Two managers/server instances on one SQL store, concurrent rotate/revoke, failed mutations and restart preserve key invariants, response identity and timestamps. Cached signers cannot bypass shared state. |
| AC4 | Upgrading existing keys preserves IDs and pre-upgrade token validity; certificate/JWK/private-key correspondence, PKCS#7 and fingerprints parse/verify independently; concurrent backfill and restart preserve certificate bytes. |
| AC5 | Custom-key GET/replace/delete survives restart across drivers; invalid/private/duplicate/colliding inputs leave state unchanged. Uploaded keys do not affect signing, canonical JWKS or internal token verification. |
| AC6 | All store drivers and gRPC transactional paths pass the lifecycle/custom-set conformance cases, including tenant deletion, rollback and same key ID in separate tenants. |
| AC7 | YAML and directory local round trips contain every included nonempty family, preserve relationships and file content, support repeat/update imports and produce a meaningful failure on a deliberately changed field. Exclusions are complete and justified. |
| AC8 | Credential-preserving bootstrap authenticates with the supplied test ID/secret after import and reimport; conflicts are rejected; ordinary generated-ID migration rewrites references correctly. No credential values enter tracked fixtures or logs. |
| AC9 | Built-in system API is omitted by unmodified deploy-cli, user APIs remain; naming upgrade changes no IDs, scopes or authorization. Retired-resource reads and rejected writes match D2 and require authorization. |
| AC10 | Browser coverage proves key inspection, rotation, revocation, refresh after uncertain completion, permissions and custom-set stored-only messaging. No proprietary UI is captured. |
| AC11 | The separate Auth0 export lane has a dated result or explicit unavailable status; local results never stand in for an upstream run. Compatibility matrix and operator docs accurately describe cache effects and stored-only custom keys. |

Review focus: (1) arbitrary uploaded keys never expand internal trust; (2) revocation and successive rotation do not accidentally trust stale process caches or silently invalidate retained keys; (3) certificate backfill never changes signing identity; (4) normalization cannot conceal lost relationships or resources; (5) bootstrap/name migration cannot overwrite unrelated credentials or privilege boundaries.

The future implementation plan must map each K/D row and acceptance criterion to a task and named verification. Follow repository rules governing when tests may run. The present database hold in AGENTS.md is explicitly scoped to Plan 19; this document neither extends nor removes it. Spec authoring requires document/link review, not database execution. At implementation completion, run affected store/SQL suites, Go race/static checks, generation checks, console build/tests, SDK/CLI/browser round trips and OIDC conformance; record actual results and unavailable lanes.

## 8. Decisions proposed by this draft

These are design recommendations, to be accepted or changed during review:

1. Preserve unrevoked prior managed keys by default, with K2 resolving any upstream retirement difference before coding.
2. Add durable certificates and a non-rotating backfill; use the local certificate policy in §3.4 where public evidence is silent.
3. Store custom public JWKS only in Plan 20; defer custom-domain publication to Plan 23 and never trust these keys internally.
4. Preserve known client IDs/secrets through the existing create-only seed and a checked migration recipe, without changing public client-create semantics.
5. Rename ordinary tenants' built-in Management API resource to `Auth0 Management API` for unmodified deploy-cli compatibility.
6. Pin deploy-cli 9.1.0 and use an explicit, tested exclusion/normalization manifest that later plans shrink.

The implementation author can choose package/file boundaries, SQL locking/CAS details, certificate encoding helpers and fixture layout within these contracts. Wire behavior and security boundaries belong in evidence/decisions, not undocumented implementation choices.

## 9. Design review

A separate builder review on 2026-10-25 identified two planning gaps: credential verification for confidential clients without the client-credentials grant, and user APIs colliding with deploy-cli's excluded system API name. Sections 5.2–5.3 now specify internal secret comparison with a separate M2M fixture, and preflight rejection of the name collision. Re-review found no important planning questions beyond the explicitly assigned Task 1 evidence gate. Local document links and whitespace were checked; no implementation or database tests were run for this documentation change.
