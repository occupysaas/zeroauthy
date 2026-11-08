# Plan 35 — Client credentials, `private_key_jwt`, JAR and custom token exchange Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auth0-compatible client credentials (`public_key`, `x509_cert`),
`private_key_jwt` client authentication, signed request objects (JAR), token
exchange profiles with the custom token exchange grant and its
`custom-token-exchange` Action, `HS256`/`PS256` API signing, and the six
Plan 33b MFA cleanups.

**Architecture:**
- **`internal/clientcred`** (new, pure): parses and validates credential PEMs
  and verifies JWTs signed by a client credential, with
  `jti` replay checks through a store callback.
- **`internal/oauth/clientauth.go`** gains the `private_key_jwt` method. It
  serves every endpoint that already calls `authenticateClient`.
- **`internal/authz`** verifies the `request` object, then merges it before
  the existing authorize validation.
- **Storage.** A `store.ClientCredentials` repository (memory, SQL, gRPC
  `client_credentials.v1`) holds credentials, the `jti` replay table and token
  exchange profiles.
- **Token exchange.** `internal/oauth/grant_token_exchange.go` runs throttling,
  then the new trigger in `internal/actions`, then post-login, then the
  minter.
- **Signing.** `internal/keys` and the minter gain `PS256` and per-API `HS256`.

**Tech Stack:** Go 1.26.10, go-jose v4 (already in `go.mod`; **no new Go
module**), Vue/TypeScript console, SQLite/PostgreSQL/MySQL, protobuf/gRPC,
Playwright 1.64.0, and the pinned `@auth0/auth0-auth-js` 1.16.1, node-auth0
7.4.0, auth0-cli 1.37.0 and auth0-deploy-cli 9.1.0.

**Spec:** [Plan 35 design](../specs/2026-11-08-zeroauthy-client-credentials-jar-token-exchange-design.md).
Read it before any task. § refers to it.

## Global Constraints

- **Toolchain and dependencies.** Go `1.26.10` (`GOTOOLCHAIN=go1.26.10`). Keep
  every dependency and Node pin. No new Go module. No SDK or CLI version bump
  without maintainer approval.
- **Clean room.** Follow `CLEAN_ROOM.md`: every doc, console and error string
  is in our own words.
- **Parity.** Strict 1:1 with Auth0's documented behaviour. Local rulings
  **LR35-1…9** and observation points **C1–C19** go in **D-0063**. The C
  points are also listed in `docs/superpowers/plan-1-followups.md`.
- **Credentials.**
  - Algorithms are `RS256`, `RS384` and `PS256` only.
  - RSA keys are 2048–4096 bits.
  - At most **2** credentials per client.
  - `kid` matches `^[0-9a-zA-Z-_]{10,64}$`. A generated `kid` is the RFC 7638
    thumbprint.
  - Ids are `cred_` + 22 random base62 characters. Profile ids are `tep_` +
    22 random base62 characters.
- **Client assertion.**
  - `client_assertion_type` is
    `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
  - The assertion is at most 2048 bytes. `iss`, `sub` and `jti` are at most
    64 characters, and the header `alg` at most 16.
  - `exp` is required, with a lifetime of at most 5 minutes. Clock leeway is
    10 s.
  - `jti` is required and single-use.
  - `aud` is the issuer URL with its trailing slash, or the exact endpoint
    URL (LR35-3).
- **JAR.**
  - `typ` is absent, `JWT`, `jwt` or `oauth-authz-req+jwt`.
  - `none` is refused with `request_not_supported` (LR35-4).
  - Lifetime is at most 60 min. Leeway is 10 s.
  - `jti` is at most 64 bytes and single-use (LR35-7).
  - Inner parameters win over the query.
- **Custom token exchange.**
  - The grant is `urn:ietf:params:oauth:grant-type:token-exchange`.
  - Profile `type` is `custom_authentication`, `name` is 3–50 characters and
    `subject_token_type` is 8–100 characters starting with `https://` or
    `urn:`.
  - These reserved prefixes are refused: `http://auth0.com`,
    `https://auth0.com`, `http://okta.com`, `https://okta.com`, `urn:ietf`,
    `urn:auth0`, `urn:okta`.
  - At most 100 profiles per tenant.
  - Throttle defaults are 10 attempts and a rate of 600000 ms.
  - A blocked request gets `429 too_many_attempts`.
- **Never logged.** No log line, log stream, event or Action log carries a
  `client_assertion`, `request` object, `subject_token`, `actor_token` or
  `signing_secret`. Add each key name to the existing secret key-name scrub.
- **Generated code.** API changes carry `x-source` in `api/*.yaml`. Regenerate
  with `make generate`. Never hand-edit generated Go, protobuf or TypeScript.
  `console/dist` is a committed build artifact.
- **Migration.** `0036_client_credentials.sql` in 3 dialects, forward only.
  Expired `jti` rows join the sweeper.
- **Plugin stores.** The gRPC capability `client_credentials.v1` is
  negotiated and latched like `webauthn.v1`. Without it, the new Management
  API writes answer `501`, `private_key_jwt`, JAR and the exchange grant are
  unavailable, and the new client fields are not sent.
- **Tests.** Use injected clocks for every expiry. Concurrency tests assert
  exactly one winner.
- **Verification** follows `AGENTS.md` "Plan verification in CI".
  - During tasks, run focused tests.
  - At the end, run the fast tier
    `TMPDIR=GOTMPDIR=/dev/shm/za35 go test -p 4 ./...` plus
    `make e2e-client-auth`.
  - Then push the `plan-35-client-auth` branch and report the CI run.
- **Worktree.** Work in `/mnt/nvme2/code/zeroauthy-plan35` on branch
  `plan-35-client-auth`. Record commits and results in
  `docs/superpowers/2026-11-08-plan-35-implementation-record.md`.

## Review Focus

1. **Assertion replay across replicas or retries.** If the same assertion is
   posted twice, concurrently, the first wins and the second gets
   `401 invalid_client`. Pinned in Task 7 (`TestPrivateKeyJWTReplayOneWinner`).
2. **Key rotation with two credentials.** A client has an old and a new key.
   An assertion without `kid` signed by either key must authenticate. An
   expired key must not. Pinned in Task 7 (`TestPrivateKeyJWTTwoKeysNoKid`).
3. **A custom domain receives the assertion or the request object.** `aud`
   equals `https://login.example.test/` (the custom domain) and is accepted
   there. On the canonical host it is refused. Pinned in Task 7
   (`TestPrivateKeyJWTAudPerHost`) and Task 8 (`TestJARAudPerHost`).
4. **A JAR whose inner `redirect_uri` is unregistered while the outer one is
   registered.** The error goes to the error page, never to either URI.
   Pinned in Task 8 (`TestJARInnerRedirectUnregistered`).
5. **The exchange Action throws, times out, or calls neither setUser
   method.** The client receives a 4xx/5xx OAuth error, `fecte` is logged
   without the subject token, and no user is created. Pinned in Task 12
   (`TestTokenExchangeActionFailureModes`).

---

## File boundaries and shared interfaces

These are the names later tasks use. Each task's Interfaces block repeats
only what it consumes.

```go
// internal/store/client_credentials.go
type ClientCredential struct {
    TenantID, ClientID, ID, Type, Name, KID, Alg string // Type: "public_key" | "x509_cert"
    PublicKeyDER    []byte    // PKIX SubjectPublicKeyInfo
    Thumbprint      string    // base64url SHA-256 of the RFC 7638 JWK thumbprint input (thumbprint_sha256)
    ExpiresAt       *time.Time
    CreatedAt, UpdatedAt time.Time
}
type TokenExchangeProfile struct {
    TenantID, ID, Name, SubjectTokenType, ActionID, Type string
    CreatedAt, UpdatedAt time.Time
}
var ErrClientCredentialsUnavailable = errors.New("store: client credentials unavailable")
type ClientCredentialsSupporter interface { CheckClientCredentialsSupport(context.Context) error; ClientCredentialsSupported() bool }
type ClientCredentials interface {
    Create(ctx context.Context, c *ClientCredential, limit int) error           // ErrPrecondition at limit; ErrNotFound if client missing
    Get(ctx context.Context, tid, clientID, id string) (*ClientCredential, error)
    List(ctx context.Context, tid, clientID string) ([]*ClientCredential, error) // ordered CreatedAt, ID
    UpdateExpiry(ctx context.Context, tid, clientID, id string, exp *time.Time) error
    Delete(ctx context.Context, tid, clientID, id string) error // also removes the id from both client settings
    // UseJTI records (tid, clientID, sha256(jti)) until exp; ErrConflict if already present and unexpired.
    UseJTI(ctx context.Context, tid, clientID, jti string, exp time.Time) error
    PurgeJTIs(ctx context.Context, before time.Time, limit int) (int, error)
    CreateProfile(ctx context.Context, p *TokenExchangeProfile, limit int) error // ErrConflict on subject_token_type; ErrPrecondition at limit
    GetProfile(ctx context.Context, tid, id string) (*TokenExchangeProfile, error)
    GetProfileByType(ctx context.Context, tid, subjectTokenType string) (*TokenExchangeProfile, error)
    ListProfiles(ctx context.Context, tid, from string, take int) ([]*TokenExchangeProfile, string, error) // checkpoint: next = last id
    UpdateProfile(ctx context.Context, p *TokenExchangeProfile) error
    DeleteProfile(ctx context.Context, tid, id string) error
    ProfilesForAction(ctx context.Context, tid, actionID string) (int, error)
}
// Store gains: ClientCredentials() ClientCredentials

// store.Client gains:
PrivateKeyJWTCredentials []string // nil = client_authentication_methods null
SignedRequestObject      *SignedRequestObject
TokenExchangeTypes       []string // token_exchange.allow_any_profile_of_type
type SignedRequestObject struct { Required bool; Credentials []string }
const AuthMethodPrivateKeyJWT = "private_key_jwt" // the method authenticateClient reports; never stored in TokenEndpointAuthMethod

// store.ResourceServer gains:
SigningSecretSealed []byte // HS256 only

// internal/clientcred
func ParsePEM(credType, pemText, alg string) (*Parsed, error)                         // *Error{Field, Msg} on 400
type Parsed struct { DER []byte; KID, Thumbprint string; CertNotAfter *time.Time }
type Purpose int; const (Assertion Purpose = iota; RequestObject)
type VerifyInput struct {
    Raw string; ClientID string; Audiences []string; Purpose Purpose
    Credentials []*store.ClientCredential; Now time.Time
    UseJTI func(jti string, exp time.Time) error // store.ErrConflict = replay
}
func Verify(in VerifyInput) (claims map[string]any, err error) // err never contains Raw

// internal/actions
const TriggerCustomTokenExchange = "custom-token-exchange"
type TokenExchangeInput struct { Tenant tenant.Resolved; Client *store.Client; Resource *store.ResourceServer; Organization *store.Organization;
    SubjectToken, SubjectTokenType, ActorToken, ActorTokenType, RequestedTokenType string; RequestedScopes []string; ActorTokenUser map[string]any; Request RequestInfo; ActionID string }
type TokenExchangeResult struct {
    UserID string // setUserById
    Connection string; Attributes map[string]any; CreationBehavior, UpdateBehavior string // setUserByConnection
    OrganizationRef string; Actor map[string]any; AppMetadata, UserMetadata map[string]any
    Denied *DenyError; RejectedSubjectToken bool
}
func (e *Engine) CustomTokenExchange(ctx context.Context, in TokenExchangeInput) (*TokenExchangeResult, error)
```

---

### Task 1: Contracts, decisions and inventory

**Files:**
- Modify: `api/management.yaml`:
  - Add paths `/clients/{id}/credentials` and
    `/clients/{id}/credentials/{credential_id}`.
  - Add `/token-exchange-profiles` and `/token-exchange-profiles/{id}`.
  - Client schema: `client_authentication_methods`, `signed_request_object`,
    `token_exchange`.
  - Resource server: `signing_alg` enum `RS256|HS256|PS256` and
    `signing_secret`. Replace the RS256-only description at line ~21919.
- Modify: `api/authentication.yaml`:
  - `/oauth/token`: `client_assertion`, `client_assertion_type`, the
    token-exchange grant parameters, and `requested_token_type`.
  - `/authorize` and `/oauth/par`: `request` is now supported. Replace the
    D-0035 text.
  - Discovery fields per §4.
- Modify: `internal/actionsrules/inventory.json`:
  - Move `custom-token-exchange` from `deferred_triggers` to `triggers`, with
    the §5.3 members.
  - Mark `api.transaction.setMetadata` unsupported.
  - Use handler `onExecuteCustomTokenExchange`, blocking `true`.
- Modify: `internal/mgmt` scope inventory (wherever `create:client_grants` is
  listed). Add `read:`, `create:`, `update:` and `delete:client_credentials`,
  `update:credentials`, and the four `*:token_exchange_profiles` scopes.
- Modify:
  - `docs/compat/decisions.md`: new `## D-0063` with the LR35-1…9 table and
    C1–C19. Amend D-0035 ("lifted by Plan 35 for signed objects; `none`
    still refused") and D-0041 (signing).
  - `docs/superpowers/plan-1-followups.md`: a C1–C19 observation list.
- Test: `api/spec_test.go` (existing contract tests), and
  `internal/actionsrules` inventory tests.

**Interfaces:**
- Produces:
  - the generated `mgmtapi.ClientCredential`, `mgmtapi.TokenExchangeProfile`
    and their request types;
  - the new `mgmtapi.ServerInterface` methods
    `GetClientCredentials`, `PostClientCredentials`, `GetClientCredential`,
    `PatchClientCredential`, `DeleteClientCredential`,
    `GetTokenExchangeProfiles`, `PostTokenExchangeProfile`,
    `GetTokenExchangeProfile`, `PatchTokenExchangeProfile` and
    `DeleteTokenExchangeProfile`.
  - Stub each in `internal/mgmt/retired.go` style returning `501` until its
    task lands.

- [ ] **Step 1:** Write the OpenAPI changes with `x-source` URLs from spec §2. Run `make generate`.
- [ ] **Step 2:** Add 501 stubs so `go build ./...` passes.
- [ ] **Step 3:** Update the inventory. Run `go test ./internal/actionsrules/ ./api/`. Expected: FAIL only where tests pin the old deferred list. Update those expectations to the new trigger.
- [ ] **Step 4:** Write D-0063 and the amendments.
- [ ] **Step 5:** Run `go test ./api/ ./internal/actionsrules/ ./internal/mgmt/`. Expected: PASS.
- [ ] **Step 6:** Commit `docs: freeze Plan 35 contracts and D-0063`.

### Task 2: `internal/clientcred` — PEM parsing and JWT verification

**Files:**
- Create: `internal/clientcred/parse.go`, `internal/clientcred/verify.go`,
  `internal/clientcred/clientcred_test.go`,
  `internal/clientcred/testdata/` (generated test keys and certificates:
  2048, 4096, 1024 and 8192-bit RSA, EC P-256, an expired cert, PKCS#1 and
  SPKI forms).

**Interfaces:**
- Consumes: `store.ClientCredential` (Task 3 defines the type; add the
  struct in this task if Task 3 is not merged yet, and Task 3 keeps it).
- Produces: `ParsePEM`, `Verify`, `Purpose`, `VerifyInput` (above), and
  `ErrInvalid` (every Verify failure wraps it; `errors.Is` only, with the
  reason in `err.Error()` for server logs).

- [ ] **Step 1: Write the failing tests**
  - `TestParsePEMForms`:
    - SPKI, PKCS#1 and a certificate each parse.
    - `KID` equals the RFC 7638 thumbprint.
    - A certificate sets `CertNotAfter`.
  - `TestParsePEMRefuses`:
    - 1024-bit and 8192-bit RSA, an EC key, garbage, and two PEM blocks each
      give `*Error`.
    - `alg` `HS256` and `ES256` give `*Error`.
  - `TestVerifyAssertion` (table-driven). Accepted: a valid RS256, RS384 and
    PS256 assertion. Refused with `ErrInvalid`:
    - `alg` ≠ credential alg; `alg: none`; an HS256 token signed with the PEM
      bytes as the secret.
    - `iss` ≠ `sub`; `aud` mismatch; a missing `exp`.
    - `exp − iat` = 301 s; `nbf` 11 s in the future.
    - A `jti` of 65 characters; a raw length of 2049 bytes; an expired
      credential.
  - `TestVerifyKidSelection`:
    - With `kid`, only that credential is tried.
    - Without `kid`, either of two credentials verifies.
  - `TestVerifyReplay`: the `UseJTI` callback returning `store.ErrConflict` →
    `ErrInvalid`.
  - `TestVerifyRequestObject`:
    - The `RequestObject` purpose accepts `typ` absent, `JWT` or
      `oauth-authz-req+jwt` and refuses `typ: at+jwt`.
    - `jti` is optional, but when present it goes through `UseJTI`.
    - Lifetime is capped at 3600 s.
  - `TestVerifyErrorOmitsToken`: `err.Error()` does not contain `Raw`.
- [ ] **Step 2:** Run `go test ./internal/clientcred/`. Expected: FAIL (package missing).
- [ ] **Step 3:** Implement `ParsePEM`. Use `crypto/x509` for parsing.
  Compute the RFC 7638 thumbprint with `jose.JSONWebKey.Thumbprint(crypto.SHA256)`.
- [ ] **Step 4:** Implement `Verify` with go-jose.
  - Parse with `jose.ParseSigned(raw, []jose.SignatureAlgorithm{RS256, RS384, PS256})`.
  - Pick credentials by `kid` or `alg`.
  - Check claims manually against the Global Constraints values.
  - Call `UseJTI` last, only after the signature and claims pass.
- [ ] **Step 5:** Run `go test ./internal/clientcred/`. Expected: PASS.
- [ ] **Step 6:** Commit `feat(clientcred): parse client credentials and verify signed client JWTs`.

### Task 3: Storage contract and memory store

**Files:**
- Create:
  - `internal/store/client_credentials.go` (types, interface, `UnimplementedClientCredentials`, `ErrClientCredentialsUnavailable`).
  - `internal/store/memory/client_credentials.go`.
  - `pkg/storetest/client_credentials.go` (the conformance suite every driver runs).
- Modify:
  - `internal/store/store.go`: `ClientCredentials()`.
  - `internal/store/types.go`: the Client and ResourceServer fields above.
  - `internal/store/memory` Client and ResourceServer copy and clone helpers.
  - `internal/app/sweeper.go`: a `purgeJTIs` batch like `purgeWebAuthn`.
- Test: `internal/store/memory/memory_test.go` (run the storetest suite).

**Interfaces:**
- Produces: everything in the "File boundaries" store block.

- [ ] **Step 1: Write the storetest cases**
  - `CredentialLimit`: a third Create → `ErrPrecondition`.
  - `CredentialDeleteDetaches`: Delete removes the id from
    `PrivateKeyJWTCredentials` and `SignedRequestObject.Credentials` on the
    client.
  - `CredentialTenantScoped`: another client's id → `ErrNotFound`.
  - `JTIOneWinner`: 8 goroutines call `UseJTI` with the same jti; exactly one
    gets nil and the rest get `ErrConflict`.
  - `JTIReuseAfterExpiry`: allowed after `exp`.
  - `JTIPurge`: removes only expired rows.
  - `ProfileUniqueType`: a duplicate type → `ErrConflict`.
  - `ProfileLimit`: the 101st → `ErrPrecondition`.
  - `ProfileCheckpoint`: pages of 2 over 5 profiles return every id once, in
    id order.
  - `ProfilesForAction`: counts profiles bound to an action.
  - `ClientFieldsRoundTrip`: the three client fields and
    `SigningSecretSealed` round-trip.
- [ ] **Step 2:** Run `go test ./internal/store/memory/`. Expected: FAIL.
- [ ] **Step 3:** Implement the memory store. Use the same locking as the other memory repositories.
- [ ] **Step 4:** Add the sweeper hook. Run `go test ./internal/store/memory/ ./internal/app/`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(store): client credentials, assertion jtis and token exchange profiles`.

### Task 4: Migration 0036 and SQL store

**Files:**
- Create: `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0036_client_credentials.sql`
  and `internal/store/sqlstore/client_credentials.go`.
- Modify:
  - The sqlstore client and resource-server row mapping: the new nullable
    JSON columns `client_authentication_methods`, `signed_request_object`
    and `token_exchange`, plus `resource_servers.signing_secret_sealed`.
  - `internal/store/sqlstore/migrate_test.go`: `TestLatestVersion` expects
    36. Trim the new columns in the legacy-seed helpers the way Plan 33b
    did for 0035.
- Test: the sqlstore storetest run on all three dialects
  (`./scripts/test-sql.sh` or the CI `sql` job).

- [ ] **Step 1:** Write the migration.
  - Tables `client_credentials` (PK tenant, client, id; index tenant, client),
    `client_assertion_jtis` (PK tenant, client, jti_hash; index expires_at)
    and `token_exchange_profiles` (PK tenant, id; unique tenant,
    subject_token_type; index tenant, action_id).
  - The new client and resource-server columns, and
    `pushed_auth_requests.signed` (boolean, default false; used by Task 8).
- [ ] **Step 2:** Implement the SQL repository.
  - Create enforces the limit inside one transaction (`SELECT COUNT … FOR
    UPDATE` on PostgreSQL/MySQL, serialized writes on SQLite).
  - `UseJTI` is `INSERT`, or on conflict a conditional update when the row is
    expired. Exactly one winner.
- [ ] **Step 3:** Run
  `TMPDIR=/dev/shm/za35 go test ./internal/store/sqlstore/ -run 'TestStore|TestLatestVersion|TestMigration'`
  for SQLite locally. Expected: PASS. PostgreSQL and MySQL run in CI.
- [ ] **Step 4:** Commit `feat(sqlstore): migration 0036 for client credentials and token exchange`.

### Task 5: `client_credentials.v1` plugin capability

**Files:**
- Modify:
  - `proto/store/v1/store.proto`: a `ClientCredentialsCapabilities` RPC and
    the repository RPCs; client fields `client_authentication_methods = 26`,
    `signed_request_object = 27`, `token_exchange = 28` (JSON bytes, absent =
    unset); resource-server `signing_secret_sealed`.
  - Regenerate.
- Create:
  - `internal/store/grpcstore/client_credentials.go` (client, latched like
    `webauthn.go`).
  - `pkg/storeplugin` server side.
- Modify: the grpcstore codec, which drops the new fields when the capability
  is absent.
- Test:
  - `internal/store/grpcstore/client_credentials_test.go`: the storetest
    suite over gRPC.
  - `TestClientCredentialsCapabilityAbsent`: an old plugin gives
    `ErrClientCredentialsUnavailable`, and the fields are not sent.

- [ ] **Step 1:** Write both tests. Run them. Expected: FAIL.
- [ ] **Step 2:** Implement the proto, client and server. Run `make generate` and the tests. Expected: PASS.
- [ ] **Step 3:** Commit `feat(grpcstore): negotiate client_credentials.v1`.

### Task 6: Management API — credentials and client settings

**Files:**
- Create: `internal/mgmt/client_credentials.go` and `internal/mgmt/client_credentials_test.go`.
- Modify: `internal/mgmt/clients.go`.
  - `CreateClient`/`UpdateClient`: the three settings, inline credential
    creation, and mutual exclusion with `token_endpoint_auth_method`.
  - `clientView`: render the settings as `{"private_key_jwt":{"credentials":[{"id":…}]}}`.

**Interfaces:**
- Consumes: `clientcred.ParsePEM` and `store.ClientCredentials`.
- Produces: `func (h *Handlers) supportsClientCredentials(ctx context.Context) bool`.
  This is the single capability check, used by Tasks 7, 8, 10 and 12.

- [ ] **Step 1: Write the failing tests**
  - `TestCredentialCreateRead`:
    - 201 with `id` prefix `cred_`, `kid`, `thumbprint_sha256` and
      `alg: RS256` default.
    - No `pem` in any response (C1).
  - `TestCredentialValidation`. Each of these → 400 `invalid_body`:
    - `cert_subject_dn`; `parse_expiry_from_cert` with an SPKI key; both
      `parse_expiry_from_cert` and `expires_at`.
    - A bad `kid` pattern; a 1024-bit key; an unknown property; a third
      credential.
  - `TestCredentialPatchOnlyExpiry`: `name` in the patch → 400. `expires_at`
    → 200.
  - `TestCredentialDeleteDetaches`.
  - `TestClientPrivateKeyJWTSetting`:
    - Requires `token_endpoint_auth_method: null` (else 400).
    - Inline creation works.
    - Another client's credential id → 400.
    - `tls_client_auth` → 400.
    - Revert works (`null` plus `client_secret_basic`).
  - `TestClientTokenExchangeSetting`: a third-party client → 400 (LR35-6). An
    unknown type → 400.
  - `TestClientCredentialsScopes`: each route refuses a token without its
    scope (403).
  - `TestClientCredentialsPluginUnavailable`: 501 when
    `supportsClientCredentials` is false.
- [ ] **Step 2:** Run `go test ./internal/mgmt/ -run 'Credential|PrivateKeyJWT|TokenExchangeSetting'`. Expected: FAIL.
- [ ] **Step 3:** Implement the handlers and the client changes. The client patch and the credential writes happen in one `WithTx`.
- [ ] **Step 4:** Run the tests. Expected: PASS. Then run `go test ./internal/mgmt/`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(mgmt): client credentials API and private_key_jwt client settings`.

### Task 7: `private_key_jwt` client authentication and discovery

**Files:**
- Modify:
  - `internal/oauth/clientauth.go`: the fourth method.
  - `internal/oidc/handlers.go` (discovery):
    `token_endpoint_auth_methods_supported` adds `private_key_jwt`;
    `token_endpoint_auth_signing_alg_values_supported` is
    `["RS256","RS384","PS256"]`.
- Test: `internal/oauth/clientauth_test.go` and `internal/oidc` discovery test.

**Interfaces:**
- Consumes: `clientcred.Verify`, `store.ClientCredentials.UseJTI`, and
  `supportsClientCredentials` (Task 6).
- Produces: `authenticateClient` reports `store.AuthMethodPrivateKeyJWT` for
  these clients. Callers need no change: `/oauth/token`, `/oauth/revoke`,
  `/oauth/par` (LR35-1), `/mfa/challenge` (`mfa_api.go`),
  `/passwordless/start` and the passkey endpoints.

- [ ] **Step 1: Write the failing tests**
  - `TestPrivateKeyJWTClientCredentials`: a token issued, with the same
    claims as a secret-authenticated client.
  - `TestPrivateKeyJWTEndpoints`: revoke, PAR, `/mfa/challenge` and
    `/passwordless/start` each accept it.
  - `TestPrivateKeyJWTRefusals`. Each gives `401 invalid_client` with the
    shared description:
    - An assertion plus Basic auth, or plus `client_secret`.
    - `client_id` ≠ `iss`; the wrong `client_assertion_type`.
    - A secret-registered client sending an assertion; a
      `private_key_jwt` client sending a secret.
  - `TestPrivateKeyJWTReplayOneWinner`: concurrent duplicate posts give
    exactly one 200.
  - `TestPrivateKeyJWTTwoKeysNoKid`.
  - `TestPrivateKeyJWTAudPerHost`: the custom-domain `aud` is accepted on the
    custom host and refused on the canonical host. The endpoint URL as `aud`
    is accepted (LR35-3).
  - `TestPrivateKeyJWTNotLogged`: the captured server log and the tenant log
    entry contain no assertion substring.
  - `TestDiscoveryAuthMethods`.
- [ ] **Step 2:** Run `go test ./internal/oauth/ -run PrivateKeyJWT`. Expected: FAIL.
- [ ] **Step 3:** Implement.
  - When `client_assertion_type` is present, select the method.
  - Load the client by the assertion's unverified `sub`, compared with
    `client_id` if present.
  - Require `PrivateKeyJWTCredentials` to be non-nil.
  - Verify with `Audiences = [issuer(host), endpointURL(r)]`.
- [ ] **Step 4:** Run `go test ./internal/oauth/ ./internal/oidc/`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(oauth): private_key_jwt client authentication`.

### Task 8: JAR at `/authorize` and `/oauth/par`

**Files:**
- Modify:
  - `internal/authz/request.go`: replace `requestObjectDelivery` with
    `verifyRequestObject`, then merge.
  - `internal/authz/errors.go`: add `invalid_request_object`.
  - `internal/oauth/par.go`: verify a pushed `request`, and store whether it
    was signed.
  - `store.PushedAuthRequest`: a `Signed bool` field. Its column comes from
    Task 4 (0036).
  - `internal/oidc/handlers.go` discovery:
    `request_parameter_supported: true` and
    `request_object_signing_alg_values_supported`.
  - `tests/conformance/expected-skips.json` / `expected-failures.json`,
    wherever D-0035 entries change.
- Test: `internal/authz/request_test.go`, `internal/oauth/par_test.go`.

**Interfaces:**
- Consumes: `clientcred.Verify` (Purpose `RequestObject`).
- Produces: `func verifyRequestObject(ctx context.Context, raw string, c *store.Client, issuer string, now time.Time, useJTI func(string, time.Time) error) (url.Values, *Error)`.

- [ ] **Step 1: Write the failing tests**
  - `TestJARMergesInnerWins`: inner `scope` and `state` override the query.
  - `TestJARClientIDMismatch` → `invalid_request_object`.
  - `TestJARUnsignedStillRefused` → `request_not_supported` (LR35-4).
  - `TestJARRequired`:
    - The client has `signed_request_object.required`.
    - A plain request → `invalid_request`.
    - A PAR `request_uri` from an unsigned push → `invalid_request`.
    - From a signed push → OK.
  - `TestJARInnerRedirectUnregistered`: the error page, with no redirect.
  - `TestJARAudPerHost`.
  - `TestJARReplay`: the same `jti` twice → the second is
    `invalid_request_object`.
  - `TestPARSignedRequest`: 201, then authorize with its `request_uri`
    succeeds.
  - `TestDiscoveryRequestObject`.
- [ ] **Step 2:** Run `go test ./internal/authz/ ./internal/oauth/ -run 'JAR|PARSigned|DiscoveryRequest'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
  - Deliver errors through the existing authorize error path.
  - Trust `redirect_uri` only after the merged value passes registration.
- [ ] **Step 4:** Run `go test ./internal/authz/ ./internal/oauth/ ./internal/oidc/`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(authz): signed request objects (JAR)`.

### Task 9: API signing `HS256` and `PS256`

**Files:**
- Modify:
  - `internal/mgmt/resource_servers.go`: accept `HS256` and `PS256`; generate
    a 32-byte base64url secret for HS256 when absent; refuse a supplied
    secret under 16 characters; seal it like client secrets; return it on
    read (C16); allow a `signing_alg` patch (LR35-8).
  - `internal/keys/manager.go`:
    `SignWithAlg(ctx, tenantID string, claims any, tokenType string, alg jose.SignatureAlgorithm) (string, error)`
    for PS256. `Verify` accepts PS256 from the tenant keys. The JWK `alg`
    stays RS256 (C19).
  - `internal/oauth/minter.go`: `AccessTokenParams` gains `SigningAlg string`
    and `SigningSecret []byte`. HS256 signs with the secret
    (`jose.HS256`, header `kid` omitted). HS256 drops the `{issuer}userinfo`
    audience (LR35-9; see `internal/oauth/user_tokens.go:195-200`).
  - Every minter caller that loads a ResourceServer passes the two fields.
  - Remove the RS256-only rows in `docs/compat/matrix.md`.
- Test: `internal/mgmt/resource_servers_test.go`, `internal/oauth/minter_test.go`, `internal/oidc` userinfo test.

- [ ] **Step 1: Write the failing tests**
  - `TestResourceServerHS256Secret`: create without a secret → a 43-character
    secret returned. A short secret → 400.
  - `TestResourceServerPS256`.
  - `TestMinterHS256`: verifies with the secret, no `kid`, and no `userinfo`
    audience.
  - `TestMinterPS256`: verifies with the JWKS key, and keeps `userinfo`.
  - `TestUserinfoAcceptsPS256`.
  - `TestSigningSecretNeverLogged`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test ./internal/mgmt/ ./internal/oauth/ ./internal/keys/ ./internal/oidc/`. Expected: PASS.
- [ ] **Step 5:** Commit `feat: HS256 and PS256 API signing`.

### Task 10: Management API — token exchange profiles

**Files:**
- Create: `internal/mgmt/token_exchange_profiles.go` and its `_test.go`.
- Modify: `internal/mgmt/actions.go`, so that a delete of an Action whose
  `ProfilesForAction > 0` is refused with 400. Use the existing Actions error
  helper. Our own wording: "action is used by a token exchange profile" (C9).

- [ ] **Step 1: Write the failing tests**
  - `TestProfileCreate`: 201 with `tep_` id.
  - `TestProfileValidation`. Each → 400:
    - `name` of 2 or 51 characters; a type of 7 characters or with an
      `http://` scheme.
    - Each reserved prefix; `type` ≠ `custom_authentication`.
    - An undeployed action ("Action is not deployed"), an action with the
      wrong trigger, an unknown action.
  - `TestProfileDuplicateType` → 409.
  - `TestProfileLimit` → 403 at 101.
  - `TestProfilePatch`: `name` and `subject_token_type` change; `action_id`
    → 400.
  - `TestProfileCheckpointList`: `from`/`take` with a `next` token.
  - `TestActionDeleteGuard`.
  - `TestProfilesPluginUnavailable` → 501.
- [ ] **Step 2:** Run `go test ./internal/mgmt/ -run 'Profile|ActionDeleteGuard'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test ./internal/mgmt/`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(mgmt): token exchange profiles`.

### Task 11: The `custom-token-exchange` trigger

**Files:**
- Modify:
  - `internal/actions/triggers.go`: `TriggerCustomTokenExchange`.
  - `internal/actions/event.go`: the event builder per §5.3, with
    `request.body` empty.
  - `internal/actions/commands.go`: apply `authentication.setUserById`,
    `setUserByConnection`, `setOrganization`, `setActor`,
    `access.deny`, `access.rejectInvalidSubjectToken` and
    `user.setAppMetadata`/`setUserMetadata`.
  - `internal/actions/runner.mjs`: the `api` surface. Unsupported members
    throw the existing "not supported" error.
- Create: `internal/actions/token_exchange.go` (`CustomTokenExchange`) and
  `internal/actions/token_exchange_test.go`.
- Modify: the Actions secret redactor input, so that `subject_token` and
  `actor_token` values are masked in Action logs.

**Interfaces:**
- Produces: `CustomTokenExchange` and `TokenExchangeResult` (above).
- Validation lives here:
  - Exactly one setUser call, otherwise an error `ErrNoUserSelected`.
  - `setActor` depth ≤ 5, ≤ 5 properties per level, values string, number
    or bool, `sub` required.
  - setUserByConnection defaults are `create_if_not_exists` / `none` (C14).

- [ ] **Step 1: Write the failing tests** (with `actionstest` runner fixtures)
  - `TestCTESetUserByID`.
  - `TestCTESetUserByConnectionDefaults`.
  - `TestCTEBothOrNeither` → `ErrNoUserSelected` / error.
  - `TestCTEDeny`: code and reason propagated.
  - `TestCTERejectInvalidSubjectToken`: `RejectedSubjectToken` true.
  - `TestCTEActorLimits`: depth 6 → error; 6 properties → error.
  - `TestCTEEventShape`: the paths per §5.3, `actor_token_user` only for a
    valid same-tenant ID token.
  - `TestCTETransactionMetadataUnsupported`.
  - `TestCTESubjectTokenMaskedInLogs`.
- [ ] **Step 2:** Run `go test ./internal/actions/ -run CTE`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test ./internal/actions/`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(actions): custom-token-exchange trigger`.

### Task 12: The token exchange grant, throttling and logs

**Files:**
- Create: `internal/oauth/grant_token_exchange.go` and its `_test.go`.
- Modify:
  - `internal/oauth/token.go`: register
    `"urn:ietf:params:oauth:grant-type:token-exchange"`. Do not add it to
    `orgLessGrants`: it accepts `organization`.
  - `internal/protection/service.go`: a new flow `"custom-token-exchange"`
    using `store.ProtectionSuspiciousIPTokenExchange =
    "suspicious-ip-token-exchange"` and `p.SuspiciousIP.Stage.PreCustomTokenExchange`.
    The check happens before the Action. `RejectedSubjectToken` spends one
    attempt.
  - `internal/store/protection.go`: drop the "stored only until Plan 35"
    comment.
  - `internal/logs` type catalog: `secte` / `fecte`.
  - `docs/logs.md` rows: change the owner from "Plan 35" to implemented.
  - `internal/oauth/minter.go`: an `act` claim when `Actor` is set.
  - User creation via setUserByConnection goes through the existing
    user-create path, so pre-/post-registration Actions and events behave as
    for other creations (C13 local answer).

**Interfaces:**
- Consumes: `actions.CustomTokenExchange`, `store.ClientCredentials.GetProfileByType`,
  the post-login runner (`Engine.PostLogin`) and the minter.
- Order: client checks → profile → API consent-skip → throttle → trigger →
  user resolution → post-login (with `challengeWith`/`enrollWith`,
  `redirect` and `prompt` → failure) → tokens.

- [ ] **Step 1: Write the failing tests**
  - `TestTokenExchangeHappyPath`:
    - access + ID token (`openid`);
    - a refresh token with `offline_access` on an API allowing it;
    - a `secte` log.
  - `TestTokenExchangeActorNoRefresh`: an `act` claim nested correctly, and
    no `refresh_token`.
  - `TestTokenExchangeClientRules`. Each refused:
    - a third-party client;
    - a client without `token_exchange`;
    - an unknown `subject_token_type` → `invalid_request`;
    - an API without consent skip → `403 access_denied` (C11).
  - `TestTokenExchangeThrottle`: with max 2, two rejected subject tokens,
    then the third request → `429 too_many_attempts` with our description.
  - `TestTokenExchangeActionFailureModes`: throw, timeout and no setUser
    each → an OAuth error, `fecte` without the token, and no user created.
  - `TestTokenExchangePostLoginMFARefused`.
  - `TestTokenExchangeSetUserByConnectionImmutableEmail` → error.
  - `TestTokenExchangeOrganization`.
  - `TestTokenExchangePublicClient` (C10).
- [ ] **Step 2:** Run `go test ./internal/oauth/ -run TokenExchange`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test ./internal/oauth/ ./internal/protection/ ./internal/logs/`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(oauth): custom token exchange grant`.

### Task 13: Console

**Files:**
- Create:
  - `console/src/pages/applications/CredentialsTab.vue` (+ `.test.ts`).
  - `console/src/pages/actions/TokenExchangeProfiles.vue` (+ `.test.ts`).
- Modify:
  - `console/src/pages/applications/Detail.vue`: the tab, the auth-method
    picker with "Private Key JWT", the JAR toggle and the token-exchange
    toggle.
  - The API create page: the algorithm choice and the HS256 secret reveal.
  - The router and nav.
  - Rebuild `console/dist`.
- Test: `npm --prefix console test`. Update `tests/e2e/m15-console.spec.mjs`
  only if a selector it uses changes.

- [ ] **Step 1:** Write vitest cases.
  - Add a PEM: the request body has `credential_type: public_key`.
  - A third key: the add button is disabled.
  - Remove a key.
  - Choosing Private Key JWT sends `token_endpoint_auth_method: null`.
  - A profile is created with an action picker filtered to the
    `custom-token-exchange` trigger.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `make console` and the tests. Expected: PASS.
- [ ] **Step 5:** Commit `feat(console): credentials, JAR and token exchange profiles`.

### Task 14: Seed, Deploy CLI and docs

**Files:**
- Modify:
  - `internal/seed`: clients accept `credentials` (pem, alg, name, kid) and
    the three settings; a top-level `token_exchange_profiles` (by action
    name).
  - `internal/seed` tests.
- Create: `docs/client-authentication.md` and `docs/token-exchange.md`.
- Modify:
  - `docs/actions.md`: replace "Custom token exchange waits for Plan 35".
  - `docs/attack-protection.md`: line ~139.
  - `docs/logs.md` and `docs/compatibility.md`.
  - `docs/compat/matrix.md` rows.
  - The Deploy CLI lane fixtures used by `tests/e2e`, with the client fields
    and `tokenExchangeProfiles`.

- [ ] **Step 1:** Write seed tests: `TestSeedClientCredentials` and `TestSeedTokenExchangeProfiles` (idempotent re-apply, and create-only rules like existing seed resources).
- [ ] **Step 2:** Run `go test ./internal/seed/`. Expected: FAIL. Implement. Expected: PASS.
- [ ] **Step 3:** Write the docs.
- [ ] **Step 4:** Commit `feat(seed): client credentials and token exchange profiles; docs`.

### Task 15: Plan 33b MFA cleanups (behaviour-neutral)

Each item is a refactor guarded by the existing tests. If an item needs a
behaviour change, skip it and record it in the followups (maintainer: keep
it small).

**Files:**
- `internal/login/mfa.go`:
  - The finish and approve paths call `mfa.Decide` once (lines ~117, ~967)
    and pass the result on.
  - `internal/login/mfa_webauthn.go:81` reuses it where the page state allows.
- `internal/store/webauthn.go`: `func WebAuthnAvailable(ctx context.Context, s Store) bool`.
  Replace the type-assertion copies in `internal/seed/passkeys.go`,
  `internal/oauth/passkey.go`, `internal/session/session.go`,
  `internal/mgmt/user_auth_methods.go`, `internal/events/webauthn.go`,
  `internal/mfa/webauthn.go`, `internal/passkey/service.go` and
  `internal/login/passkey.go`.
- The page scripts that list `NotAllowedError` etc. (`internal/login`,
  `internal/mfa`): one shared constant.
- `internal/oauth/passkey.go:300`: `timeout` from the passkey service's native
  ceremony constant, not the literal `60000`.
- The challenge-table KV use (find it with
  `grep -rn "Challenge" internal/passkey internal/login | grep -i metadata`):
  move it to a purpose column in 0036 only if a column suffices. Otherwise
  record it as deferred.
- The login page view writes: skip the write when the stored state is
  unchanged.

- [ ] **Step 1:** Make each change with the existing tests.
- [ ] **Step 2:** Run `go test ./internal/login/ ./internal/mfa/ ./internal/passkey/ ./internal/oauth/ ./internal/mgmt/ ./internal/seed/ ./internal/session/ ./internal/events/`. Expected: PASS.
- [ ] **Step 3:** Add `TestLoginPageViewNoWrite`: a store wrapper counts writes, and viewing the login page twice gives 0 writes on the second view.
- [ ] **Step 4:** Commit `refactor: Plan 33b MFA cleanups`.

### Task 16: End-to-end acceptance, CI and record

**Files:**
- Create:
  - `tests/e2e/run-m35-client-auth.sh`
  - `tests/e2e/m35-client-auth.spec.mjs` (Playwright: the JAR authorize plus
    PAR journey; console credentials)
  - `tests/e2e/m35-node.mjs`:
    - auth0-auth-js with `clientAssertionSigningKey` (client credentials,
      refresh via auth code) and `exchangeToken`;
    - node-auth0 credentials and profiles managers;
    - `express-oauth2-jwt-bearer` verifying HS256 and PS256 tokens.
  - `tests/e2e/m35-cli.mjs`: auth0-cli where it has commands, and the Deploy
    CLI round trip.
- Modify:
  - `Makefile`: `e2e-client-auth`.
  - `.github/workflows/ci.yml`: add `e2e-client-auth` to the e2e matrix.
- Create: `docs/superpowers/2026-11-08-plan-35-implementation-record.md`.
- Modify: the roadmap Plan 35 section and row.

- [ ] **Step 1:** Write the suite. It covers:
  - private_key_jwt client credentials, replay refusal, and two-key rotation;
  - JAR required on a client, plus the PAR signed push;
  - a custom token exchange round trip with a deployed Action
    (`setUserByConnection` create, then a second exchange reusing the user),
    the actor chain without a refresh token, and the throttle lockout
    returning 429;
  - HS256/PS256 verification;
  - a representative-secret audit: grep the log export and the Action logs
    for the assertion, request object, subject token and signing secret, and
    expect none.
- [ ] **Step 2:** Run `make e2e-client-auth` locally (SQLite). Expected: PASS.
- [ ] **Step 3:** Run the fast tier `TMPDIR=/dev/shm/za35 GOTMPDIR=/dev/shm/za35 go test -p 4 ./...`. Expected: exit 0.
- [ ] **Step 4:** Push `plan-35-client-auth`. Report the CI run URL and each failed job with its actual failure. Fix on the branch and push again until green.
- [ ] **Step 5:** Write the implementation record and the roadmap status.
- [ ] **Step 6:** Commit `test: verify Plan 35 client authentication, JAR and token exchange end to end`. Ask the maintainer for merge approval.

## Dependency order

1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16.

- Task 9 depends only on Tasks 1 and 3, and may run after Task 3.
- Task 15 is independent of everything except Task 4 (if it adds a column),
  and may run any time after it.
