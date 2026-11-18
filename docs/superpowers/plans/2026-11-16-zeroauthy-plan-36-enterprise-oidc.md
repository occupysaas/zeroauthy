# Plan 36 — Enterprise OIDC connections Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auth0-compatible enterprise `oidc` (front and back channel,
explicit endpoints, claim mapping, PKCE modes, `private_key_jwt`, encrypted
ID tokens, upstream PAR) and `okta` connections, the connection keys API,
home realm discovery from `domain_aliases` (also for `waad`), and the
`/connections/{id}/users` and `/status` routes.

**Architecture:**
- **`internal/federation/rules`** stays the one option authority; the
  inventory moves to version 2 with the new rows.
- **`internal/federation`** gains: explicit endpoint resolution, the PKCE
  mode matrix, a client-assertion signer, a PAR step, a JWE step before ID
  token validation, a front-channel completion path, a userinfo fetch and a
  pure-Go attribute-map evaluator (`attrmap.go`), plus an `okta` provider
  that is the `oidc` provider with a derived issuer.
- **Storage.** A `store.ConnectionKeys` repository (memory, SQL, gRPC
  `connection_keys.v1`); private keys sealed with the master key.
- **`internal/mgmt/connection_keys.go`** serves the keys API;
  `internal/mgmt/connections.go` gains users-by-email delete and status.
- **`internal/login`** gains `POST /login/callback` and HRD in
  `identifierPost`.

**Tech Stack:** Go 1.26.10, go-jose v4 (in `go.mod`; **no new Go module**),
Vue/TypeScript console, SQLite/PostgreSQL/MySQL, protobuf/gRPC, Playwright
1.64.0, pinned node-auth0 7.4.0, auth0-cli 1.37.0, auth0-deploy-cli 9.1.0.

**Spec:** [Plan 36 design](../specs/2026-11-16-zeroauthy-enterprise-oidc-design.md).
Read it before any task. § refers to it.

## Global Constraints

- **Toolchain and dependencies.** Go `1.26.10`. Keep every dependency and
  Node pin. No new Go module, no SDK/CLI bump without maintainer approval.
- **Clean room.** `CLEAN_ROOM.md`: every doc, console and error string in our
  own words.
- **Parity.** Strict 1:1 with documented Auth0 behaviour. Local rulings
  LR36-1…17 and observation points V1–V13 go in **D-0120**; the V points are
  also listed in `docs/superpowers/plan-1-followups.md`.
- **Algorithms.**
  - Client-assertion signing: `RS256 RS384 RS512 PS256 PS384 ES256 ES384`.
  - ID token signature allowlist: `RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512`; never `none`/`HS*`.
  - JWE key management: `RSA-OAEP-256 RSA-OAEP-384 RSA-OAEP-512 ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW`.
  - JWE content: `A128CBC-HS256 A192CBC-HS384 A256CBC-HS512 A128GCM A192GCM A256GCM`.
  - Keys: RSA 2048; EC P-256 (`ES256`, `ECDH-ES*`), P-384 (`ES384`).
- **Limits.** Discovery/metadata ≤ 128 KiB; `domain_aliases` ≤ 1000 entries,
  each ≤ 256 characters; attribute map ≤ 100 entries, template ≤ 1024 bytes;
  client assertion lifetime 60 s; existing inventory limits otherwise.
- **Never logged.** No log line, log stream, event or Action log carries a
  client assertion, ID token (JWS or JWE), userinfo body, upstream token or
  connection private key. Add `client_assertion`, `id_token`, `userinfo`,
  `private_key` to the key-name scrub if absent.
- **Generated code.** API changes carry `x-source` in `api/*.yaml`;
  `make generate`; never hand-edit generated Go/protobuf/TypeScript.
  `console/dist` is a committed build artifact.
- **Migration.** One forward-only migration `00NN_connection_keys.sql` in
  three dialects. Write it as `0037`; **rename to main's latest + 1 when the
  branch merges** (parallel-paths numbering rule).
- **Plugin stores.** gRPC capability `connection_keys.v1`, negotiated and
  latched like `client_credentials.v1`. Without it: keys API `501`;
  `private_key_jwt` and encryption options refused on write with `400`.
- **Tests.** Injected clocks for every expiry; concurrency tests assert
  exactly one winner.
- **Verification** per `AGENTS.md` "Plan verification in CI": focused tests
  per task; at the end `TMPDIR=/dev/shm/za36 GOTMPDIR=/dev/shm/za36 go test -p 4 ./...`
  plus `make e2e-enterprise-oidc`; push `plan-36-enterprise-oidc`; report
  the CI run.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan36` on branch
  `plan-36-enterprise-oidc`. Record commits and results in
  `docs/superpowers/2026-11-16-plan-36-implementation-record.md`.
- **Commits** signed off (`git commit -s`, DCO).

## Review Focus

1. **Front-channel token injection.** A posted `id_token` from another
   attempt, with a wrong `nonce`, `alg: none`, an `HS256` signature keyed
   with the client ID, or a posted `code` on a front-channel attempt must
   fail. Pinned in Task 10 (`TestFrontChannelRefusals`).
2. **Attribute map writing protected fields.** `use_map` targeting
   `user_id`, `identities`, `app_metadata`, `blocked` is refused at write;
   `bind_all` with a restricted upstream claim drops it and logs in. Pinned
   in Task 3 (`TestAttrMapRestricted`) and Task 11
   (`TestBindAllDropsRestricted`).
3. **Key rotation race.** Two concurrent rotates leave exactly one current,
   one next, one previous. Pinned in Task 4 (storetest `RotateOneWinner`).
4. **HRD leaking or overriding.** An email domain on a connection *not*
   enabled for the client never routes; an organization transaction only
   considers that organization's connections, after Plan 30 discovery
   domains. Pinned in Task 12 (`TestHRDCandidates`).
5. **Revision invalidation.** Switching `type`, auth method, PKCE or the
   attribute map invalidates pending attempts. Pinned in Task 2
   (`TestOIDCEffectiveChangeBumpsRevision`).

---

## File boundaries and shared interfaces

```go
// internal/store/connection_keys.go
type ConnectionKey struct {
    TenantID, ConnectionID, KID, Use, Alg string // Use: "signing" | "encryption"
    State        string    // "current" | "next" | "previous"
    CertDER      []byte    // self-signed X.509
    PrivateSealed []byte   // master-key sealed PKCS#8
    CurrentSince *time.Time
    CreatedAt    time.Time
}
var ErrConnectionKeysUnavailable = errors.New("store: connection keys unavailable")
type ConnectionKeysSupporter interface { ConnectionKeysSupported() bool }
type ConnectionKeys interface {
    List(ctx context.Context, tid, connID string) ([]*ConnectionKey, error)      // ordered Use, State(current,next,previous)
    Create(ctx context.Context, tid, connID, use string, current, next *ConnectionKey) error // ErrConflict if use already has keys
    // Rotate: drop previous; current→previous; next→current (CurrentSince=now); newNext becomes next. ErrNotFound if no keys of use.
    Rotate(ctx context.Context, tid, connID, use string, newNext *ConnectionKey, now time.Time) (*ConnectionKey, error)
}
// Store gains: ConnectionKeys() ConnectionKeys. Connection delete cascades.

// internal/federation/rules — Settings gains:
Channel            string   // "back_channel" | "front_channel"
Explicit           *ExplicitEndpoints // nil = discovery
PKCE               string   // "auto" | "S256" | "plain" | "disabled"
SendNonce          bool
TokenAuth          string   // "" (discovery choice) | "client_secret_post" | "private_key_jwt"
AssertionAlg, AssertionAud string
IDTokenAlgs        []string
EncAlg             string; EncEncs []string
PAR                bool; PAREndpoint string
AttrMap            *AttrMap
DomainAliases      []string
OktaDomain         string
type ExplicitEndpoints struct{ Issuer, Authorization, Token, JWKS, UserInfo string; Metadata map[string]any }
type AttrMap struct{ Mode string; Attributes map[string]string; UserinfoScope string }

// internal/federation/attrmap.go
func CompileAttrMap(m *rules.AttrMap, strategy string, channel string) (*CompiledMap, error) // write-time validation
func (c *CompiledMap) Apply(ctx MapContext) (root map[string]any, profileData map[string]any)
type MapContext struct{ TokenSet, UserInfo map[string]any; ConnectionID, Strategy string }

// internal/federation — new
func (ps *Providers) clientAssertion(cfg Config, aud string, now time.Time) (string, error) // signs with current signing key
func decryptIDToken(raw string, keys []*store.ConnectionKey, open func([]byte) ([]byte, error), alg string, encs []string) (string, error)
type FrontChannelInput struct{ State, IDToken, Error, ErrorDescription string }
func (s *FlowService) CompleteFrontChannel(ctx context.Context, in CompleteInput, fc FrontChannelInput) (*Completion, error)
func MatchHomeRealm(email string, conns []*store.Connection) *store.Connection
```

---

### Task 1: Contracts, decisions and inventory

**Files:**
- Modify: `api/management.yaml`:
  - Paths `/connections/{id}/keys` (GET, POST), `/connections/{id}/keys/rotate`
    (POST), `/connections/{id}/status` (GET), `/connections/{id}/users`
    (DELETE, `email` query), with `x-source` to the OpenAPI operations in
    spec §2.
  - `ConnectionCreate.strategy` enum gains `okta`; option schemas for
    `oidc`/`okta` per spec §3 (reuse the OpenAPI names).
- Modify: `internal/federation/inventory.json` → `"version": 2`, new `okta`
  strategy block, `oidc` rows per spec §3.1 table, `unsupported.front_channel`
  removed, `dpop_signing_alg` added as rejected.
- Modify: scope inventory in `internal/tenantsetup/management.go` and
  `internal/server/mgmtapi.go`: `read:connections_keys`,
  `create:connections_keys`, `update:connections_keys`.
- Modify: `docs/compat/decisions.md` — new `## D-0120` with the LR36 table
  and V1–V13; `docs/superpowers/plan-1-followups.md` — "Plan 36
  observation points" V1–V13.
- Test: `api/spec_test.go`, `internal/federation/inventory_test.go`.

**Interfaces:**
- Produces: generated `mgmtapi.ConnectionKey`, request types, and
  `ServerInterface` methods `GetConnectionKeys`, `PostConnectionKeys`,
  `PostConnectionKeysRotate`, `GetConnectionStatus`,
  `DeleteConnectionUsersByEmail`, stubbed `501` in `internal/mgmt` until
  their tasks.

- [ ] **Step 1:** Write the OpenAPI changes; `make generate`.
- [ ] **Step 2:** Add `501` stubs; `go build ./...`.
- [ ] **Step 3:** Update the inventory; run `go test ./internal/federation/ ./api/`. Expected: FAIL only where tests pin version 1 or the rejected `front_channel`; update those expectations.
- [ ] **Step 4:** Write D-0120 and the follow-ups entries.
- [ ] **Step 5:** `go test ./api/ ./internal/federation/... ./internal/mgmt/` → PASS.
- [ ] **Step 6:** Commit `docs: freeze Plan 36 contracts and D-0120`.

### Task 2: Option rules for `oidc`, `okta` and `waad` aliases

**Files:**
- Modify: `internal/federation/rules/rules.go` (remove `issuer`, endpoint,
  `oidc_metadata`, `token_endpoint_auth_*`, `domain_aliases`,
  `attribute_map`, `tenant_domain` from `rejectedOptions` for `oidc`/`okta`;
  keep them rejected for `oauth2`/`google-oauth2`), new
  `internal/federation/rules/oidc.go`, `internal/federation/rules/okta.go`,
  `internal/federation/rules/aliases.go`.
- Modify: `internal/federation/rules/microsoft.go` (accept `domain_aliases`).
- Modify: `rules.IsFederated` gains `okta`; `IsSocial` unchanged.
- Modify: `internal/connrules/connrules.go` dispatch for `okta`.
- Test: `internal/federation/rules/oidc_test.go`, `okta_test.go`,
  `aliases_test.go`, `internal/connrules/connrules_test.go`.

**Interfaces:**
- Consumes: Task 1 inventory.
- Produces: the `Settings` fields in "File boundaries"; `rules.Okta = "okta"`;
  `rules.IsEnterprise(strategy)` (`oidc`, `okta`, `waad`).

- [ ] **Step 1: Write the failing tests**
  - `TestOIDCTypeDefault`: omitted `type` → `front_channel`.
  - `TestOIDCEndpointsExplicit`: no `discovery_url` + full explicit set → OK; missing `jwks_uri` → error; `http://` endpoint → error; front channel without `token_endpoint` → OK.
  - `TestOIDCMetadataCap`: 128 KiB + 1 → error.
  - `TestOIDCClientSecretByChannel`: front channel + secret → error (LR36-2); back channel `client_secret_post` without secret → error; `private_key_jwt` without secret → OK.
  - `TestOIDCPKCEModes`: `auto`, `S256`, `s256`, `plain`, `disabled` OK; `sha512` error.
  - `TestOIDCAlgLists`: `id_token_signed_response_algs: ["none"]` error; `["HS256"]` error; encryption alg/encs enum.
  - `TestOIDCDPoP`: `dpop_signing_alg: "ES256"` → error (LR36-6); `null` OK.
  - `TestOIDCPARBackChannelOnly`: PAR on front channel → error (LR36-5).
  - `TestOktaDomain`: `dev-1.okta.com` OK and lower-cased; `https://x`, `x/y`, `x:443` error; `bind_all` error; `front_channel` error; `discovery_url` error.
  - `TestDomainAliases`: 1000 OK, 1001 error, 257-char error, upper-case normalized, duplicates removed; on `waad` OK; on `google-oauth2` error.
  - `TestOIDCEffectiveChangeBumpsRevision`: each effective field change reports `Effective=true` from the patch comparison used by `connections.go`; `icon_url` change does not.
  - `TestOIDCImmutable`: changing `discovery_url`, `issuer`, Okta `domain` on PATCH → error.
- [ ] **Step 2:** Run `go test ./internal/federation/rules/ ./internal/connrules/` → FAIL.
- [ ] **Step 3:** Implement; keep one validation path for seed, API and console checker (`console/src/pages/connections/checker.ts` mirrors only the shape, not the rules).
- [ ] **Step 4:** Add the stored-option migration step from LR36-1 to the migration in Task 5 (note it here, implement there): stored `oidc` without `type` gets `back_channel`.
- [ ] **Step 5:** Tests → PASS. Commit `feat(federation): oidc and okta enterprise option rules`.

### Task 3: Attribute map evaluator

**Files:**
- Create: `internal/federation/attrmap.go`, `attrmap_test.go`,
  `attrmap_fuzz_test.go`.

**Interfaces:**
- Consumes: `rules.AttrMap`.
- Produces: `CompileAttrMap`, `CompiledMap.Apply`, `MapContext`,
  `RestrictedTargets` (the spec §4.3 list, one source of truth).

- [ ] **Step 1: Write the failing tests**
  - `TestAttrMapTemplates`: literal; `${context.tokenset.email}`; `"user|${context.tokenset.sub}"`; `${context.connection.id}`; URL-named claim `${context.tokenset.https://example.com/roles}`.
  - `TestAttrMapMissing` (LR36-8): whole-value missing → attribute absent; concatenation → empty part.
  - `TestAttrMapRestricted`: targets `user_id`, `identities`, `app_metadata`, `blocked`, `logins_count`, `last_login` → compile error.
  - `TestAttrMapGrammar`: `${context.env.X}`, `${a}`, nested `${${x}}`, unterminated `${` → compile error.
  - `TestAttrMapUserinfoFrontChannel`: userinfo reference on `front_channel` → compile error (LR36-16).
  - `TestAttrMapLimits`: 101 entries, 1025-byte template → error.
  - `TestBindAll`: every claim copied; restricted claims dropped; `email_verified` non-boolean dropped.
  - `FuzzAttrMapCompile`: no panic; compile+apply is deterministic.
- [ ] **Step 2:** `go test ./internal/federation/ -run AttrMap` → FAIL.
- [ ] **Step 3:** Implement a hand-written scanner (no regexp backtracking on user input), no reflection on claims beyond `map[string]any`.
- [ ] **Step 4:** Tests → PASS. Commit `feat(federation): attribute map templates for enterprise OIDC`.

### Task 4: Connection keys storage contract and memory store

**Files:**
- Create: `internal/store/connection_keys.go`,
  `internal/store/memory/connection_keys.go`,
  `pkg/storetest/connection_keys.go`.
- Modify: `internal/store/store.go` (`ConnectionKeys()`), memory connection
  delete (cascade).
- Test: `internal/store/memory/memory_test.go`.

**Interfaces:**
- Produces: the store block in "File boundaries".

- [ ] **Step 1: Write the storetest cases**
  - `KeysCreateConflict`: second Create of the same use → `ErrConflict`; a different use → OK.
  - `KeysListOrder`: signing before encryption; current, next, previous.
  - `KeysRotate`: states move as specified; `CurrentSince` = now; returned key is the new current.
  - `KeysRotateNone`: Rotate without keys → `ErrNotFound`.
  - `RotateOneWinner`: 8 concurrent rotates from one state → states remain one each per use, and exactly 8 sequential transitions happened or the losers got `ErrConflict` (the driver chooses serialization; the invariant is checked).
  - `KeysCascade`: deleting the connection removes its keys.
  - `KeysTenantIsolation`: tenant B cannot list tenant A's keys.
- [ ] **Step 2:** Run `go test ./internal/store/memory/` → FAIL.
- [ ] **Step 3:** Implement memory; clone on read.
- [ ] **Step 4:** PASS. Commit `feat(store): connection keys contract and memory driver`.

### Task 5: SQL and gRPC drivers, migration

**Files:**
- Create: `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0037_connection_keys.sql`
  (table `connection_keys(tenant_id, connection_id, kid, use, alg, state,
  cert_der, private_sealed, current_since, created_at)`, PK
  `(tenant_id, connection_id, kid)`, unique `(tenant_id, connection_id, use, state)`,
  FK cascade; plus the LR36-1 `oidc` options rewrite as an idempotent
  data step).
- Create: `internal/store/sqlstore/connection_keys.go`,
  `internal/store/grpcstore/connection_keys.go`.
- Modify: `proto/store/v1/store.proto` (messages and RPCs
  `ListConnectionKeys`, `CreateConnectionKeys`, `RotateConnectionKeys`;
  capability string `connection_keys.v1`); `make generate`.
- Modify: `internal/store/sqlstore/migrate_test.go` (oldest-schema upgrade
  covers 0037).
- Test: sqlstore and grpcstore storetest runs.

- [ ] **Step 1:** Write the migration and the sqlstore driver; Rotate in one transaction with `SELECT ... FOR UPDATE` (PostgreSQL/MySQL) and `BEGIN IMMEDIATE` (SQLite).
- [ ] **Step 2:** gRPC driver with capability latch; without the capability `ConnectionKeys()` returns `UnimplementedConnectionKeys` (`ErrConnectionKeysUnavailable`).
- [ ] **Step 3:** `go test ./internal/store/sqlstore/ -run 'ConnectionKeys|Migrat'` on SQLite locally; PostgreSQL/MySQL through CI (or `./scripts/test-sql.sh` with containers).
- [ ] **Step 4:** `go test ./internal/store/grpcstore/` → PASS.
- [ ] **Step 5:** Commit `feat(store): connection keys in SQL and gRPC drivers`.

### Task 6: Keys Management API

**Files:**
- Create: `internal/mgmt/connection_keys.go`, `connection_keys_test.go`.
- Modify: `internal/keycert/certificate.go` (ECDSA P-256/P-384 self-signed
  certs; SHA-1 colon fingerprint and SHA-1 upper-hex thumbprint helpers for
  this API only; existing SHA-256 helpers unchanged), `internal/keycert/certificate_test.go`.
- Create: `internal/federation/connkeys.go` (generate a key for an
  alg/use; `EnsureKeys` for lazy creation, V12).

**Interfaces:**
- Consumes: `store.ConnectionKeys`, `keys` sealing.
- Produces: `federation.GenerateConnectionKey(use, alg string, subject string, now time.Time) (*store.ConnectionKey, error)`, `federation.EnsureKeys(ctx, st, conn, use, alg)`.

- [ ] **Step 1: Write the failing tests**
  - `TestKeysGetEmpty`: `oidc` without keys → `200 []`.
  - `TestKeysPostSigning`: default body → `201`, two keys (current, next), `RS256`, `key_use: signing`, `cert` PEM parses, `pkcs` PEM, `fingerprint` matches `^([0-9A-F]{2}:){19}[0-9A-F]{2}$`.
  - `TestKeysPostConflict`: second POST signing → `409`.
  - `TestKeysPostEncryption`: `{key_use: encryption, encryption_alg: ECDH-ES}` → P-256 key.
  - `TestKeysRotateRequiresConfig`: rotate signing without `private_key_jwt` → `400`; encryption without `id_token_encrypted_response_alg` → `400`.
  - `TestKeysRotate`: after rotate, GET shows previous/current/next.
  - `TestKeysStrategy`: `google-oauth2` and `auth0` connections → `400`; unknown id → `404`.
  - `TestKeysScopes`: `read:connections_keys` for GET; rotate needs both create and update.
  - `TestKeysNoPrivateMaterial`: response bodies contain no `PRIVATE KEY`.
  - `TestKeysPlugin501`: store without capability → `501`.
- [ ] **Step 2:** `go test ./internal/mgmt/ -run Keys ./internal/keycert/` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** PASS. Commit `feat(mgmt): connection keys API for oidc and okta`.

### Task 7: Explicit endpoints, metadata, PKCE modes, nonce, ID token algorithms

**Files:**
- Modify: `internal/federation/oidc.go`, `discovery.go`, `id_token.go`,
  `config.go`, `service_flow.go`.
- Modify: `internal/store/federation.go` (`FederationEndpoints.ResponseType`,
  `PKCEMethod`), memory/sql/grpc codecs (JSON column, no migration needed
  if the attempt stores endpoints as JSON — check `sqlstore/federation.go`;
  if columns are typed, add the columns to Task 5's migration instead).
- Test: `internal/federation/oidc_test.go`, `discovery_test.go`.

- [ ] **Step 1: Write the failing tests**
  - `TestExplicitEndpointsNoDiscovery`: no HTTP call to `/.well-known`; endpoints pinned on the attempt.
  - `TestOIDCMetadataWins`: non-empty `oidc_metadata` used, discovery not fetched.
  - `TestPKCEAuto`: metadata `["S256","plain"]` → S256; `["plain"]` → plain; absent → no `code_challenge` (LR36-4).
  - `TestPKCEPlainDisabled`: explicit modes honoured; token request carries `code_verifier` only when PKCE was sent.
  - `TestNonceOptional`: `send_back_channel_nonce:false` → no `nonce` sent, ID token without nonce accepted; with `true`, missing nonce refused.
  - `TestIDTokenAlgAllowlist`: allowlist `["PS256"]` refuses an RS256-signed token; `null` accepts RS256/ES256.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(federation): explicit OIDC endpoints, PKCE modes and ID token algorithms`.

### Task 8: `private_key_jwt` to the provider and upstream PAR

**Files:**
- Create: `internal/federation/assertion.go`, `assertion_test.go`,
  `par.go`, `par_test.go`.
- Modify: `internal/federation/oidc.go` (`exchangeCode` gains the assertion
  method), `service_flow.go` (PAR on Begin).

- [ ] **Step 1: Write the failing tests**
  - `TestAssertionShape`: header `alg`/`kid`; claims `iss`=`sub`=client_id, `aud` per `token_endpoint_jwtca_aud_format` (`issuer` default, `token_endpoint`), `exp-iat`=60, unique `jti`; verifies with the key's `cert`.
  - `TestAssertionUsesCurrentKey`: after rotate, the new current `kid` is used.
  - `TestAssertionLazyKey`: no keys + `private_key_jwt` → keys created once (V12), concurrent first logins create one set.
  - `TestTokenRequestNoSecretWithAssertion`: body has no `client_secret`.
  - `TestPARBegin`: POST to the PAR endpoint with the same parameters and client auth; browser redirect has only `client_id` and `request_uri`; PAR `4xx` → attempt fails with the existing upstream error, no fallback.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(federation): private_key_jwt and PAR towards enterprise OIDC providers`.

### Task 9: Encrypted ID tokens

**Files:**
- Create: `internal/federation/jwe.go`, `jwe_test.go`.
- Modify: `internal/federation/oidc.go` (`validateIDToken` decrypts first).

- [ ] **Step 1: Write the failing tests**
  - `TestJWEAccept`: each key-management alg × `A256GCM`/`A128CBC-HS256` decrypts with the current key, and with the previous key after rotation.
  - `TestJWERefuse`: `enc` outside a non-empty allowlist; JWE to an unknown key; nested payload `alg: none`; plain JWS when encryption is configured (LR36-14); JWE when encryption is not configured.
  - `TestJWEErrorOmitsToken`: error strings never contain the token.
- [ ] **Step 2–4:** FAIL → implement with go-jose `jose.ParseEncrypted` with explicit alg/enc lists → PASS.
- [ ] **Step 5:** Commit `feat(federation): encrypted ID tokens from enterprise OIDC providers`.

### Task 10: Front channel

**Files:**
- Modify: `internal/federation/service_flow.go` (`Begin` builds the
  `id_token`/`form_post` request; `CompleteFrontChannel`),
  `internal/login/social.go` (`SocialCallbackPost`; cookie `SameSite=None;
  Secure` for front-channel attempts, LR36-15), `internal/server/server.go`
  (`tr.Post("/login/callback", lg.SocialCallbackPost)`, CSRF exemption scoped
  to that route since `state` is the binding).
- Test: `internal/federation/front_channel_test.go`,
  `internal/login/social_test.go`.

- [ ] **Step 1: Write the failing tests**
  - `TestFrontChannelBegin`: authorization URL has `response_type=id_token`, `response_mode=form_post`, `nonce`, no `code_challenge`.
  - `TestFrontChannelComplete`: valid posted `id_token` → user signed in, identity `oidc|<conn>|<sub>`, no stored upstream tokens.
  - `TestFrontChannelRefusals`: wrong `state`; replayed `state`; wrong `nonce`; `alg: none`; HS256 keyed with the client ID; expired; wrong `aud`; a posted `code`; a back-channel attempt receiving a POST → each fails with the existing callback error page and no user created.
  - `TestFrontChannelError`: posted `error=access_denied` → error page, `fs` log without token values.
  - `TestCallbackGetUnchanged`: Plan 24 GET callback tests still pass.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(login): front-channel OIDC form-post callback`.

### Task 11: Userinfo, mapping in login, and the `okta` provider

**Files:**
- Modify: `internal/federation/profile.go`, `oidc.go`, `identity.go`,
  `discovery.go` (`okta` derives issuer/discovery from `domain`),
  `internal/federation/types.go`.
- Test: `internal/federation/profile_test.go`, `okta_test.go`.

- [ ] **Step 1: Write the failing tests**
  - `TestUserinfoFetchedOnlyWhenReferenced`: map without `context.userinfo` → no userinfo call; with → one call with the access token; `sub` mismatch → login fails.
  - `TestUseMapProfile`: mapped `name`, `nickname`, custom `federated_groups` land as documented (root attributes; non-root to identity `profileData`, V6).
  - `TestBindAllDropsRestricted`.
  - `TestOktaIssuer`: `domain: dev-1.okta.com` → issuer `https://dev-1.okta.com`, discovery fetched there; identity `okta|<conn>|<sub>` (V2); `basic_profile` = Plan 24 normalization.
  - `TestSetUserRootAttributesWithMap`: `on_first_login` keeps later mapped root values unchanged.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(federation): claim mapping, userinfo and okta connections`.

### Task 12: Home realm discovery

**Files:**
- Create: `internal/federation/hrd.go`, `hrd_test.go`.
- Modify: `internal/login/identifier.go` (`identifierPost`: email → match →
  start the upstream attempt with `login_hint`), `internal/login/social.go`
  (shared start helper taking a `login_hint`).
- Test: `internal/login/identifier_test.go`.

- [ ] **Step 1: Write the failing tests**
  - `TestMatchHomeRealm`: exact domain match; case-insensitive; IDNA `bücher.example` = `xn--bcher-kva.example`; subdomain does not match; non-email identifier → nil.
  - `TestHRDCandidates`: connection not enabled for the client → no route; disabled `authentication.active=false` → no route; organization transaction → only that organization's enabled connections, after Plan 30 discovery domains.
  - `TestHRDOrder` (LR36-11): two matches → first enabled-client order.
  - `TestIdentifierHRDRedirect`: POST identifier `a@corp.example` → `303` to the IdP with `login_hint=a@corp.example`; no password page; unknown domain → password page as today.
  - `TestHRDNoUserLookup`: the handler performs no user read for routing (store spy).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(login): home realm discovery from connection domain aliases`.

### Task 13: Users-by-email delete and connection status

**Files:**
- Modify: `internal/mgmt/connections.go`; test `connections_users_test.go`.

- [ ] **Step 1: Write the failing tests**
  - `TestDeleteConnectionUserByEmail`: database connection → `204`, user removed with the existing user-delete side effects (identity epoch bump, sessions, logs `sdu`); unknown email → `204` (the OpenAPI reads "the user no longer exists"); non-database connection → `400`; missing `email` → `400`; unknown connection → `404`; scope `delete:users`.
  - `TestDeleteByEmailMultipleUsers`: two users with the same email on one connection (possible when `requires_username`) → both deleted (V13).
  - `TestConnectionStatus` (LR36-9): `oidc`/`auth0` → `404` with the OpenAPI shape; scope `read:connections`.
- [ ] **Step 2–4:** FAIL → implement (reuse the user deletion service, not a second path) → PASS.
- [ ] **Step 5:** Commit `feat(mgmt): delete connection users by email and connection status`.

### Task 14: Console

**Files:**
- Modify/Create under `console/src/pages/connections/enterprise/`:
  `Create.vue` (OIDC/Okta choice, discovery URL or domain, channel,
  client ID/secret), `Detail.vue`, `Settings.vue`, `Mapping.vue`,
  `Keys.vue`, `LoginExperience.vue`, tests for each.
- Modify: `console/src/pages/connections/social/MicrosoftOptions.vue`
  (domains), `console/src/api` generated types (`make generate`).
- Rebuild: `console/dist`.

- [ ] **Step 1:** Vitest tests first: create payloads for both strategies; Keys tab create/rotate with confirmation and stale-response guard; mapping editor refuses restricted targets client-side with the server message as the authority; PKCE `plain`/`disabled` marked weaker; stored-only options marked with `StoredMark`.
- [ ] **Step 2:** Implement; `npm --prefix console test`, `npm --prefix console run build`.
- [ ] **Step 3:** Commit `feat(console): enterprise OIDC and Okta connections`.

### Task 15: Seed and Deploy CLI

**Files:**
- Modify: `internal/seed` connection parsing (new strategies/options through
  `connrules`; keys never seeded, LR36-17), seed tests.
- Modify: `tests/e2e/deploy-cli` fixtures and `AUTH0_EXCLUDED` (drop
  `oidc`/`okta` connections), `tests/e2e/m20-deploy-cli.mjs` expectations.

- [ ] **Step 1:** Seed tests: `oidc` back/front, `okta`, invalid options rejected with the same messages as the API.
- [ ] **Step 2:** Deploy CLI four-cell round trip includes one `oidc` and one `okta` connection (secrets reinjected as today).
- [ ] **Step 3:** `go test ./internal/seed/`; Deploy lane runs in CI.
- [ ] **Step 4:** Commit `feat(seed): enterprise OIDC connections; deploy round trip`.

### Task 16: E2E lane, docs, final verification

**Files:**
- Create: `tests/e2e/run-m36-enterprise-oidc.sh`,
  `tests/e2e/m36-enterprise-oidc.spec.mjs`, `tests/e2e/m36-node-auth0.mjs`,
  `tests/e2e/m36-mgmt-cli.mjs`.
- Modify: `tests/e2e/social/provider/provider.go` (front-channel form post,
  `private_key_jwt` verification against a registered cert, JWE ID tokens,
  PAR endpoint, userinfo), `Makefile` (`e2e-enterprise-oidc`),
  `.github/workflows/ci.yml` (suite matrix).
- Create: `docs/enterprise-connections.md`; modify
  `docs/social-connections.md` (pointer), `docs/compatibility.md`,
  `docs/compat/matrix.md`, `CHANGELOG.md`, roadmap §0/Plan 36 status.
- Create: `docs/superpowers/2026-11-16-plan-36-implementation-record.md`.

- [ ] **Step 1:** E2E per spec §8.4 (Playwright HRD, front channel, `private_key_jwt`, mapping; node-auth0 keys/delete-by-email/status; auth0-cli `api`; secret scan).
- [ ] **Step 2:** Docs in our own words; the guide lists every stored-only option and the V points.
- [ ] **Step 3:** Fast tier: `TMPDIR=/dev/shm/za36 GOTMPDIR=/dev/shm/za36 go test -p 4 ./...` and `make e2e-enterprise-oidc`; record exit codes.
- [ ] **Step 4:** Rename the migration to main's latest + 1 if main moved; push `plan-36-enterprise-oidc`; record the CI run URL, failed jobs and actual failures in the implementation record.
- [ ] **Step 5:** Whole-branch review (superpowers:requesting-code-review), fix wave, CI green, then maintainer approval to merge.
