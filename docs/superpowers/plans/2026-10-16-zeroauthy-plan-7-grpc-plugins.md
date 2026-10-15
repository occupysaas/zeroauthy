# zeroauthy Plan 7: gRPC Storage Plugins (Milestone 8)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** an operator can point `storage.dsn` at `plugin:///path/to/binary`, and zeroauthy stores everything through an out-of-process gRPC driver. A sample plugin backed by the memory driver passes the complete `pkg/storetest` conformance suite, including transactions and concurrency, through a real plugin process. Plugin authors get a public Go SDK and a language-neutral protocol.

**Architecture:**
- **`proto/store/v1/store.proto`** mirrors every `store.Store` method as one RPC on a `StoreService`.
  - Domain errors (`ErrNotFound`, `ErrConflict`, `ErrAlreadyUsed`, and others) travel inside the response, not as gRPC status codes, because `Consume` returns a record *and* `ErrAlreadyUsed`.
  - gRPC status codes mean transport or plugin failure only.
  - Generated Go code is committed under `proto/store/v1`.
- **Remote transactions** (user decision, 2026-10-16; this replaces spec §5.2's "no transactions across the boundary"):
  - `BeginTx` returns a transaction ID. Every request carries an optional `tx_id`, and `Commit` and `Rollback` end the transaction.
  - A `BeginTx` with a `parent_tx_id` opens a nested transaction. It has the savepoint semantics of D-0020: an inner error undoes only the inner work.
  - The Go server adapter implements this for any `store.Store`. It runs the driver's own `WithTx` in a goroutine that holds the transaction open until `Commit` or `Rollback` arrives.
- **`internal/store/grpcstore`** has three parts:
  - a client that implements `store.Store` over a `grpc.ClientConn`;
  - a server adapter that turns a `store.Store` into a `StoreServiceServer`;
  - a codec between domain types and protobuf messages that preserves nil versus empty slices and maps, `*time.Time` presence, and nanosecond times.
- **`pkg/store`** re-exports the store interfaces, types and errors as type aliases, so code outside this module can implement or consume a `store.Store`.
- **`pkg/storeplugin`** is the public SDK:
  - `Serve(store.Store)` for plugin binaries;
  - `Open(ctx, path, args...)` for hosts and conformance tests.
  - Both use `hashicorp/go-plugin` (handshake, AutoMTLS, process lifecycle).
- **Sample plugin:** `cmd/zeroauthy-store-memory` is the sample plugin. It serves `memory.New()`.

**Tech Stack:**
- Go 1.26+.
- `github.com/hashicorp/go-plugin` (gRPC protocol), `google.golang.org/grpc` and `google.golang.org/protobuf`.
- Code generation uses `go tool buf generate` with the `protoc-gen-go` and `protoc-gen-go-grpc` tool dependencies. No protoc install is needed, and the output does not depend on a host protoc version.

**Spec:** `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md`:
- §3.1: `internal/store/grpcstore/` and `proto/store/v1/`;
- §5.1: the `plugin:///path/to/binary?arg=…` DSN;
- §5.2: external driver plugins;
- §12: storetest runs against the sample gRPC plugin;
- §13: milestone 8;
- §14: the plugin-boundary risk.

## Global Constraints

- **Earlier constraints still apply:**
  - Drivers return copies.
  - Every atomic operation is one store method.
  - `go test -race ./...`, `go vet` and `gofmt` stay clean, and `go generate ./...` produces no diff.
  - The binary stays CGO-free (`CGO_ENABLED=0 go build`).
- **Errors never quote a DSN.** `plugin://` arguments may carry secrets (see `internal/storage/open.go`).
- **Plugin DSN format:** `plugin:///absolute/path/to/binary?arg=…&arg=…`.
  - The path must be absolute, and the host must be empty.
  - Each `arg` query value becomes one argv entry, in order.
  - No other query keys are accepted. An unknown key is an error that names the key, not its value.
- **Plugin storage is persistent.** It needs `security.master_key` like the SQL drivers (`internal/app/app.go` `loadMasterKey` already requires it for every non-`memory:` DSN).
- **Handshake:**
  - `ProtocolVersion: 1`
  - `MagicCookieKey: "ZEROAUTHY_STORE_PLUGIN"`
  - `MagicCookieValue: "5b0f7c1e-store-v1"`
  - go-plugin plugin name: `"store"`.
- **Transport:** the gRPC protocol only (`plugin.ProtocolGRPC`) with `AutoMTLS: true`. The default 4 MiB gRPC message size is enough; signing keys and user metadata are small.
- **Clean room:** the protocol, docs and names are our own. No Auth0 material is involved in this milestone.

## Review Focus

1. **Abandoned transactions.**
   - Condition: the host's `fn` panics, its context is cancelled, or the host process dies mid-transaction.
   - Expected: the plugin rolls the transaction back and releases it. For the memory driver that means `txMu` is unlocked, so later `WithTx` calls do not hang.
   - Pinned in Task 3 (rollback on idle timeout) and Task 4 (panic and cancelled context on the client).
2. **Plugin crash or exit.**
   - Condition: the plugin process exits while serving.
   - Expected: store calls return an error promptly and never hang. `Ping` fails, so `/healthz` reports the problem.
   - Pinned in Task 5.
3. **Bad plugin binary.**
   - Condition: the binary is missing, not executable, or a program that never completes the handshake.
   - Expected: `storage.Open` fails within the start timeout with a clear error that does not include the DSN.
   - Pinned in Tasks 5 and 6.
4. **Concurrency through the boundary.**
   - Condition: many goroutines call atomic methods at once through one plugin connection.
   - Expected: the same outcomes as in-process, with exactly one winner per single-use item.
   - Pinned by running the full storetest suite (with its concurrency cases) in Tasks 4 and 5.
5. **Fidelity of values across the wire.**
   - Condition: nil versus empty slices and maps, nil `*time.Time`, zero `time.Time`, nanosecond times, `UserMetadata` with nested values, and `CustomText`.
   - Expected: each round-trips unchanged. Metadata numbers decode as `float64`, as they do in the SQL drivers.
   - Pinned in Task 2.

## Out of Scope

- **Automatic plugin restart.** A crashed plugin makes the store fail until zeroauthy restarts (follow-up).
- **Plugin binary checksum pinning** (go-plugin `SecureConfig`) (follow-up).
- **Schema migration for plugins.** `grpcstore` does not implement `storage.Migrator`; plugins own their schema.
- **Non-Go reference plugins.** The protocol is language-neutral, but only the Go SDK ships.

## File Map

| Path | Responsibility |
|---|---|
| `proto/store/v1/store.proto` | Wire protocol (hand-written) |
| `proto/store/v1/*.pb.go`, `*_grpc.pb.go` | Generated, committed |
| `proto/store/v1/generate.go`, `buf.yaml`, `buf.gen.yaml` | `go:generate` entry |
| `pkg/store/store.go` | Public type aliases of `internal/store` |
| `internal/store/grpcstore/codec.go`, `codec_test.go` | Domain ↔ proto conversion |
| `internal/store/grpcstore/server.go`, `server_repos.go`, `server_test.go` | `store.Store` → `StoreServiceServer`, transaction registry |
| `internal/store/grpcstore/client.go`, `client_repos.go`, `client_test.go` | `StoreServiceClient` → `store.Store` |
| `internal/store/grpcstore/conformance_test.go` | storetest over in-process gRPC (bufconn) |
| `pkg/storeplugin/storeplugin.go`, `storeplugin_test.go` | go-plugin `Serve` / `Open`, handshake |
| `cmd/zeroauthy-store-memory/main.go` | Sample plugin |
| `internal/storage/open.go`, `open_test.go` | `plugin://` dispatch |
| `docs/compat/decisions.md` (D-0021), `README.md`, spec §5.2 and §14, `docs/superpowers/plan-1-followups.md`, `.github/workflows/ci.yml`, `Makefile` | Wiring and docs |

---

### Task 1: Protocol, code generation, public type aliases

**Files:**
- Create: `proto/store/v1/store.proto`, `proto/store/v1/buf.yaml`, `proto/store/v1/buf.gen.yaml`, `proto/store/v1/generate.go`
- Create: generated `proto/store/v1/store.pb.go` and `proto/store/v1/store_grpc.pb.go`
- Create: `pkg/store/store.go`, `pkg/store/store_test.go`
- Modify: `go.mod`/`go.sum`, adding the tool and library dependencies

**Interfaces (produced):**
- Go package `storev1` (`github.com/zeroauthy/zeroauthy/proto/store/v1`) with `StoreServiceServer`, `StoreServiceClient`, `RegisterStoreServiceServer`, `NewStoreServiceClient` and the messages below.
- Package `github.com/zeroauthy/zeroauthy/pkg/store` with aliases: `Store`, the 12 repository interfaces, every domain type, `ErrNotFound`, `ErrConflict`, `ErrAlreadyUsed`, and the `KeyStatus`/`AppType`/`AuthMethod*`/`StrategyDatabase` constants.

- [ ] **Step 1: Dependencies**

```bash
go get -tool github.com/bufbuild/buf/cmd/buf@latest
go get -tool google.golang.org/protobuf/cmd/protoc-gen-go@latest
go get -tool google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
go get google.golang.org/grpc@latest google.golang.org/protobuf@latest github.com/hashicorp/go-plugin@latest
```

Record the resolved versions in the report.

- [ ] **Step 2: Write the protocol**

`proto/store/v1/store.proto`:

```proto
syntax = "proto3";

package zeroauthy.store.v1;

import "google/protobuf/duration.proto";
import "google/protobuf/timestamp.proto";

option go_package = "github.com/zeroauthy/zeroauthy/proto/store/v1;storev1";

// StoreService mirrors zeroauthy's store.Store. Every request carries tx_id:
// empty means "no transaction"; otherwise the call runs inside the
// transaction BeginTx returned. Domain errors are reported in the response's
// `error` field; gRPC status codes mean transport or plugin failure.
service StoreService {
  rpc Ping(PingRequest) returns (Result);
  rpc BeginTx(BeginTxRequest) returns (BeginTxResponse);
  rpc Commit(EndTxRequest) returns (Result);
  rpc Rollback(EndTxRequest) returns (Result);

  rpc TenantsCreate(TenantWrite) returns (Result);
  rpc TenantsGet(TenantsGetRequest) returns (TenantResult);
  rpc TenantsGetByName(TenantsGetRequest) returns (TenantResult);
  rpc TenantsGetByDomain(TenantsGetRequest) returns (TenantResult);
  rpc TenantsUpdate(TenantWrite) returns (Result);
  rpc TenantsList(TenantsListRequest) returns (TenantList);

  rpc ClientsCreate(ClientWrite) returns (Result);
  rpc ClientsGet(ScopedKey) returns (ClientResult);
  rpc ClientsUpdate(ClientWrite) returns (Result);
  rpc ClientsDelete(ScopedKey) returns (Result);
  rpc ClientsList(TenantScope) returns (ClientList);

  rpc ResourceServersCreate(ResourceServerWrite) returns (Result);
  rpc ResourceServersGet(ScopedKey) returns (ResourceServerResult);
  rpc ResourceServersGetByIdentifier(ScopedKey) returns (ResourceServerResult);
  rpc ResourceServersUpdate(ResourceServerWrite) returns (Result);
  rpc ResourceServersDelete(ScopedKey) returns (Result);

  rpc ClientGrantsCreate(ClientGrantWrite) returns (Result);
  rpc ClientGrantsFind(ClientGrantsFindRequest) returns (ClientGrantResult);
  rpc ClientGrantsUpdate(ClientGrantWrite) returns (Result);
  rpc ClientGrantsDelete(ScopedKey) returns (Result);

  rpc SigningKeysCreate(SigningKeyWrite) returns (Result);
  rpc SigningKeysList(TenantScope) returns (SigningKeyList);
  rpc SigningKeysRotate(SigningKeysRotateRequest) returns (Result);

  rpc ConnectionsCreate(ConnectionWrite) returns (Result);
  rpc ConnectionsGet(ScopedKey) returns (ConnectionResult);
  rpc ConnectionsGetByName(ScopedKey) returns (ConnectionResult);
  rpc ConnectionsUpdate(ConnectionWrite) returns (Result);
  rpc ConnectionsList(TenantScope) returns (ConnectionList);

  rpc UsersCreate(UserWrite) returns (Result);
  rpc UsersGet(ScopedKey) returns (UserResult);
  rpc UsersFindByLogin(UsersFindByLoginRequest) returns (UserResult);
  rpc UsersUpdate(UserWrite) returns (Result);
  rpc UsersRecordLogin(UsersRecordLoginRequest) returns (Result);
  rpc UsersSetPasswordHash(UsersSetPasswordHashRequest) returns (Result);

  rpc SessionsCreate(SessionWrite) returns (Result);
  rpc SessionsGetByTokenHash(ScopedKey) returns (SessionResult);
  rpc SessionsTouch(TouchRequest) returns (Result);
  rpc SessionsAddClient(SessionsAddClientRequest) returns (Result);
  rpc SessionsDelete(ScopedKey) returns (Result);
  rpc SessionsDeleteByUser(ScopedKey) returns (CountResult);
  rpc SessionsDeleteExpired(DeleteExpiredRequest) returns (CountResult);

  rpc AuthTransactionsCreate(AuthTransactionWrite) returns (Result);
  rpc AuthTransactionsGet(ScopedKey) returns (AuthTransactionResult);
  rpc AuthTransactionsDelete(ScopedKey) returns (Result);
  rpc AuthTransactionsDeleteExpired(DeleteExpiredRequest) returns (CountResult);

  rpc AuthCodesCreate(AuthCodeWrite) returns (Result);
  rpc AuthCodesConsume(ConsumeRequest) returns (AuthCodeResult);
  rpc AuthCodesGet(ScopedKey) returns (AuthCodeResult);
  rpc AuthCodesDeleteExpired(DeleteExpiredRequest) returns (CountResult);

  rpc RefreshTokensCreate(RefreshTokenWrite) returns (Result);
  rpc RefreshTokensGetByTokenHash(ScopedKey) returns (RefreshTokenResult);
  rpc RefreshTokensRotate(RefreshTokensRotateRequest) returns (Result);
  rpc RefreshTokensTouch(TouchRequest) returns (Result);
  rpc RefreshTokensRevokeFamily(RevokeRequest) returns (Result);
  rpc RefreshTokensRevokeByUser(RevokeRequest) returns (CountResult);
  rpc RefreshTokensDeleteExpired(DeleteExpiredRequest) returns (CountResult);

  rpc PasswordResetTicketsCreate(PasswordResetTicketWrite) returns (Result);
  rpc PasswordResetTicketsGetByTokenHash(ScopedKey) returns (PasswordResetTicketResult);
  rpc PasswordResetTicketsConsume(ConsumeRequest) returns (PasswordResetTicketResult);
  rpc PasswordResetTicketsDeleteByUser(ScopedKey) returns (CountResult);
  rpc PasswordResetTicketsDeleteExpired(DeleteExpiredRequest) returns (CountResult);
}

// ---- errors and generic results ----

message Error {
  enum Kind {
    KIND_UNSPECIFIED = 0; // any other error; see message
    KIND_NOT_FOUND = 1;   // store.ErrNotFound
    KIND_CONFLICT = 2;    // store.ErrConflict
    KIND_ALREADY_USED = 3; // store.ErrAlreadyUsed
  }
  Kind kind = 1;
  string message = 2; // human-readable; for KIND_UNSPECIFIED the whole error
}

message Result { Error error = 1; }            // absent error = success
message CountResult { Error error = 1; int64 count = 2; }

// ---- transactions ----

message PingRequest {}
message BeginTxRequest { string parent_tx_id = 1; } // empty = top level
message BeginTxResponse { Error error = 1; string tx_id = 2; }
message EndTxRequest { string tx_id = 1; }

// ---- shared request shapes ----

message TenantScope { string tx_id = 1; string tenant_id = 2; }
// ScopedKey addresses one entity in a tenant by its key (ID, client ID,
// identifier, name or token hash, depending on the RPC).
message ScopedKey { string tx_id = 1; string tenant_id = 2; string key = 3; }
message TouchRequest {
  string tx_id = 1; string tenant_id = 2; string id = 3;
  google.protobuf.Timestamp idle_expires_at = 4;
}
message DeleteExpiredRequest { string tx_id = 1; google.protobuf.Timestamp before = 2; }
message ConsumeRequest {
  string tx_id = 1; string tenant_id = 2; string hash = 3;
  google.protobuf.Timestamp at = 4;
}
message RevokeRequest {
  string tx_id = 1; string tenant_id = 2; string key = 3; // family ID or user ID
  google.protobuf.Timestamp at = 4;
}

// ---- presence-preserving wrappers: an absent wrapper is a nil slice/map ----

message StringList { repeated string values = 1; }
message StringMap { map<string, string> values = 1; }

// ---- entities ----

message Tenant {
  string id = 1;
  string name = 2;
  string friendly_name = 3;
  StringList domains = 4;
  string default_audience = 5;
  StringList allowed_logout_urls = 6;
  StringList enabled_locales = 7;
  optional bytes custom_text_json = 8; // absent = nil CustomText
  int64 session_lifetime = 9;
  int64 idle_session_lifetime = 10;
  Branding branding = 11;
  string default_directory = 12;
  google.protobuf.Timestamp created_at = 13;
}
message Branding { string logo_url = 1; string primary_color = 2; }

message ClientSecret {
  string hash = 1;
  google.protobuf.Timestamp created_at = 2;
  google.protobuf.Timestamp expires_at = 3; // absent = nil
}
message ClientSecretList { repeated ClientSecret values = 1; }
message RefreshTokenPolicy {
  bool rotating = 1; int64 leeway = 2; bool expiring = 3;
  int64 token_lifetime = 4; int64 idle_token_lifetime = 5;
}
message Client {
  string tenant_id = 1;
  string client_id = 2;
  string name = 3;
  string app_type = 4;
  ClientSecretList secrets = 5;
  string token_endpoint_auth_method = 6;
  StringList grant_types = 7;
  StringList callbacks = 8;
  StringList allowed_logout_urls = 9;
  StringList web_origins = 10;
  StringList allowed_origins = 11;
  int64 id_token_lifetime = 12;
  RefreshTokenPolicy refresh_token = 13;
  google.protobuf.Timestamp created_at = 14;
}

message Scope { string value = 1; string description = 2; }
message ScopeList { repeated Scope values = 1; }
message ResourceServer {
  string tenant_id = 1; string id = 2; string identifier = 3; string name = 4;
  ScopeList scopes = 5; string signing_alg = 6; int64 token_lifetime = 7;
  bool allow_offline_access = 8; google.protobuf.Timestamp created_at = 9;
}

message ClientGrant {
  string tenant_id = 1; string id = 2; string client_id = 3; string audience = 4;
  StringList scopes = 5; google.protobuf.Timestamp created_at = 6;
}

message SigningKey {
  string tenant_id = 1; string kid = 2; string alg = 3; string status = 4;
  optional bytes private_key = 5; // absent = nil
  optional bytes public_jwk = 6;  // absent = nil
  google.protobuf.Timestamp created_at = 7;
}

message PasswordPolicy { int64 min_length = 1; int64 require_character_classes = 2; }
message Connection {
  string tenant_id = 1; string id = 2; string name = 3; string strategy = 4;
  StringList enabled_clients = 5; bool disable_signup = 6; bool requires_username = 7;
  PasswordPolicy password_policy = 8; google.protobuf.Timestamp created_at = 9;
}

message Identity { string connection = 1; string provider = 2; string user_id = 3; string password_hash = 4; }
message IdentityList { repeated Identity values = 1; }
message User {
  string tenant_id = 1; string user_id = 2; string email = 3; bool email_verified = 4;
  string username = 5; string name = 6; string nickname = 7; string picture = 8;
  string given_name = 9; string family_name = 10;
  optional bytes user_metadata_json = 11; // absent = nil map
  bool blocked = 12; IdentityList identities = 13;
  google.protobuf.Timestamp last_login = 14; // absent = nil
  int64 logins_count = 15;
  google.protobuf.Timestamp created_at = 16; google.protobuf.Timestamp updated_at = 17;
}

message LoginSession {
  string tenant_id = 1; string id = 2; string token_hash = 3; string user_id = 4;
  string connection = 5; google.protobuf.Timestamp authenticated_at = 6;
  StringList client_ids = 7; google.protobuf.Timestamp expires_at = 8;
  google.protobuf.Timestamp idle_expires_at = 9; google.protobuf.Timestamp created_at = 10;
}

message AuthTransaction {
  string tenant_id = 1; string id = 2; string cookie_hash = 3; string csrf_token = 4;
  string client_id = 5; StringMap params = 6;
  google.protobuf.Timestamp expires_at = 7; google.protobuf.Timestamp created_at = 8;
}

message AuthCode {
  string tenant_id = 1; string code_hash = 2; string client_id = 3; string redirect_uri = 4;
  string user_id = 5; string session_id = 6; StringList scopes = 7; string audience = 8;
  string nonce = 9; string code_challenge = 10; string code_challenge_method = 11;
  google.protobuf.Timestamp auth_time = 12; google.protobuf.Timestamp expires_at = 13;
  google.protobuf.Timestamp created_at = 14;
  google.protobuf.Timestamp used_at = 15;     // absent = nil
  google.protobuf.Timestamp replayed_at = 16; // absent = nil
}

message RefreshToken {
  string tenant_id = 1; string id = 2; string token_hash = 3; string family_id = 4;
  string client_id = 5; string user_id = 6; string session_id = 7; StringList scopes = 8;
  string audience = 9; google.protobuf.Timestamp auth_time = 10; bool rotating = 11;
  google.protobuf.Timestamp expires_at = 12; google.protobuf.Timestamp idle_expires_at = 13;
  google.protobuf.Timestamp rotated_at = 14; // absent = nil
  google.protobuf.Timestamp revoked_at = 15; // absent = nil
  google.protobuf.Timestamp created_at = 16;
}

message PasswordResetTicket {
  string tenant_id = 1; string id = 2; string token_hash = 3; string user_id = 4;
  string connection = 5; string client_id = 6; string lang = 7;
  google.protobuf.Timestamp expires_at = 8;
  google.protobuf.Timestamp used_at = 9; // absent = nil
  google.protobuf.Timestamp created_at = 10;
}

// ---- per-entity requests and results ----

message TenantWrite { string tx_id = 1; Tenant value = 2; }
message TenantsGetRequest { string tx_id = 1; string key = 2; } // id, name or domain
message TenantsListRequest { string tx_id = 1; }
message TenantResult { Error error = 1; Tenant value = 2; }
message TenantList { Error error = 1; repeated Tenant values = 2; }

message ClientWrite { string tx_id = 1; Client value = 2; }
message ClientResult { Error error = 1; Client value = 2; }
message ClientList { Error error = 1; repeated Client values = 2; }

message ResourceServerWrite { string tx_id = 1; ResourceServer value = 2; }
message ResourceServerResult { Error error = 1; ResourceServer value = 2; }

message ClientGrantWrite { string tx_id = 1; ClientGrant value = 2; }
message ClientGrantsFindRequest { string tx_id = 1; string tenant_id = 2; string client_id = 3; string audience = 4; }
message ClientGrantResult { Error error = 1; ClientGrant value = 2; }

message SigningKeyWrite { string tx_id = 1; SigningKey value = 2; }
message SigningKeyList { Error error = 1; repeated SigningKey values = 2; }
message SigningKeysRotateRequest { string tx_id = 1; string tenant_id = 2; SigningKey next = 3; }

message ConnectionWrite { string tx_id = 1; Connection value = 2; }
message ConnectionResult { Error error = 1; Connection value = 2; }
message ConnectionList { Error error = 1; repeated Connection values = 2; }

message UserWrite { string tx_id = 1; User value = 2; }
message UserResult { Error error = 1; User value = 2; }
message UsersFindByLoginRequest { string tx_id = 1; string tenant_id = 2; string connection = 3; string login = 4; }
message UsersRecordLoginRequest { string tx_id = 1; string tenant_id = 2; string user_id = 3; google.protobuf.Timestamp at = 4; }
message UsersSetPasswordHashRequest {
  string tx_id = 1; string tenant_id = 2; string user_id = 3; string connection = 4;
  string hash = 5; google.protobuf.Timestamp at = 6;
}

message SessionWrite { string tx_id = 1; LoginSession value = 2; }
message SessionResult { Error error = 1; LoginSession value = 2; }
message SessionsAddClientRequest { string tx_id = 1; string tenant_id = 2; string id = 3; string client_id = 4; }

message AuthTransactionWrite { string tx_id = 1; AuthTransaction value = 2; }
message AuthTransactionResult { Error error = 1; AuthTransaction value = 2; }

message AuthCodeWrite { string tx_id = 1; AuthCode value = 2; }
message AuthCodeResult { Error error = 1; AuthCode value = 2; } // Consume may set both

message RefreshTokenWrite { string tx_id = 1; RefreshToken value = 2; }
message RefreshTokenResult { Error error = 1; RefreshToken value = 2; }
message RefreshTokensRotateRequest {
  string tx_id = 1; string tenant_id = 2; string old_id = 3; RefreshToken next = 4;
  google.protobuf.Timestamp at = 5; google.protobuf.Duration leeway = 6;
}

message PasswordResetTicketWrite { string tx_id = 1; PasswordResetTicket value = 2; }
message PasswordResetTicketResult { Error error = 1; PasswordResetTicket value = 2; }
```

Two conventions make the encoding unambiguous:
- **Plain `time.Time` fields** are always sent as a present `Timestamp`, including the zero time (0001-01-01 is inside the Timestamp range). An absent `Timestamp` on such a field decodes to the zero time.
- **`*time.Time` fields** use absence for nil.

- [ ] **Step 3: Generation config**

`proto/store/v1/buf.yaml`:

```yaml
version: v2
```

`proto/store/v1/buf.gen.yaml`:

```yaml
version: v2
plugins:
  - local: ["go", "tool", "protoc-gen-go"]
    out: .
    opt: paths=source_relative
  - local: ["go", "tool", "protoc-gen-go-grpc"]
    out: .
    opt: paths=source_relative
```

`proto/store/v1/generate.go`:

```go
// Package storev1 is the gRPC protocol between zeroauthy and external
// storage plugins. The .pb.go files are generated; edit store.proto.
package storev1

//go:generate go tool buf generate
```

Run: `go generate ./proto/...`, then `go build ./proto/...`
Expected: `store.pb.go` and `store_grpc.pb.go` appear and compile. A second `go generate` produces no `git diff`.

- [ ] **Step 4: Failing test for the public aliases**

`pkg/store/store_test.go`:

```go
package store_test

import (
	"errors"
	"testing"

	internal "github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/store"
)

// The aliases are the same types, so values flow both ways without conversion.
func TestAliasesAreIdentical(t *testing.T) {
	var s store.Store = memory.New()
	var _ internal.Store = s
	var u *store.User = &internal.User{}
	_ = u
	if !errors.Is(internal.ErrNotFound, store.ErrNotFound) ||
		!errors.Is(internal.ErrConflict, store.ErrConflict) ||
		!errors.Is(internal.ErrAlreadyUsed, store.ErrAlreadyUsed) {
		t.Fatal("sentinel errors differ")
	}
	if store.KeyCurrent != internal.KeyCurrent || store.StrategyDatabase != internal.StrategyDatabase {
		t.Fatal("constants differ")
	}
}
```

Run: `go test ./pkg/store/`
Expected: FAIL to compile.

- [ ] **Step 5: Implement `pkg/store/store.go`**

```go
// Package store re-exports zeroauthy's storage interfaces and domain types
// for code outside this module, such as external storage plugins. The
// definitions and their documentation live in internal/store; every name
// here is an alias, so values are interchangeable.
package store

import "github.com/zeroauthy/zeroauthy/internal/store"

type (
	Store                = store.Store
	Tenants              = store.Tenants
	Clients              = store.Clients
	ResourceServers      = store.ResourceServers
	ClientGrants         = store.ClientGrants
	SigningKeys          = store.SigningKeys
	Connections          = store.Connections
	Users                = store.Users
	Sessions             = store.Sessions
	AuthTransactions     = store.AuthTransactions
	AuthCodes            = store.AuthCodes
	RefreshTokens        = store.RefreshTokens
	PasswordResetTickets = store.PasswordResetTickets

	Tenant              = store.Tenant
	Branding            = store.Branding
	CustomText          = store.CustomText
	AppType             = store.AppType
	ClientSecret        = store.ClientSecret
	Client              = store.Client
	RefreshTokenPolicy  = store.RefreshTokenPolicy
	Scope               = store.Scope
	ResourceServer      = store.ResourceServer
	ClientGrant         = store.ClientGrant
	KeyStatus           = store.KeyStatus
	SigningKey          = store.SigningKey
	PasswordPolicy      = store.PasswordPolicy
	Connection          = store.Connection
	Identity            = store.Identity
	User                = store.User
	LoginSession        = store.LoginSession
	AuthTransaction     = store.AuthTransaction
	AuthCode            = store.AuthCode
	RefreshToken        = store.RefreshToken
	PasswordResetTicket = store.PasswordResetTicket
)

var (
	ErrNotFound    = store.ErrNotFound
	ErrConflict    = store.ErrConflict
	ErrAlreadyUsed = store.ErrAlreadyUsed
)

const (
	AppTypeSPA            = store.AppTypeSPA
	AppTypeRegularWeb     = store.AppTypeRegularWeb
	AppTypeNative         = store.AppTypeNative
	AppTypeNonInteractive = store.AppTypeNonInteractive

	AuthMethodNone              = store.AuthMethodNone
	AuthMethodClientSecretPost  = store.AuthMethodClientSecretPost
	AuthMethodClientSecretBasic = store.AuthMethodClientSecretBasic

	KeyNext     = store.KeyNext
	KeyCurrent  = store.KeyCurrent
	KeyPrevious = store.KeyPrevious
	KeyRevoked  = store.KeyRevoked

	StrategyDatabase = store.StrategyDatabase
)
```

If `internal/store` gains a type or constant that this file misses, the alias test still passes. Add a reflection-free guard: a comment at the top of `internal/store/types.go` and `store.go` reading `// Exported through pkg/store; add new names there too.`

- [ ] **Step 6: Verify and commit**

Run: `go test ./pkg/store/ && go vet ./... && gofmt -l . && go generate ./... && git diff --exit-code -- proto`
Expected: PASS and no diff.

```bash
git add proto pkg/store internal/store/store.go internal/store/types.go go.mod go.sum
git commit -m "feat(proto): store/v1 plugin protocol; pkg/store public aliases"
```

---

### Task 2: Codec, domain types to and from protobuf

**Files:**
- Create: `internal/store/grpcstore/codec.go`, `internal/store/grpcstore/codec_test.go`

**Interfaces:**
- Consumes: `storev1` messages (Task 1); `internal/store` types.
- Produces, in package `grpcstore`:
  - one `toPB`/`fromPB` pair per entity: `tenantToPB(*store.Tenant) (*storev1.Tenant, error)` and `tenantFromPB(*storev1.Tenant) (*store.Tenant, error)`, and likewise for `client`, `resourceServer`, `clientGrant`, `signingKey`, `connection`, `user`, `session` (`LoginSession`), `authTransaction`, `authCode`, `refreshToken` and `passwordResetTicket`;
  - time helpers `tsToPB(time.Time) *timestamppb.Timestamp`, `tsFromPB(*timestamppb.Timestamp) time.Time`, `optTSToPB(*time.Time) *timestamppb.Timestamp` and `optTSFromPB(*timestamppb.Timestamp) *time.Time`;
  - error mapping `errToPB(error) *storev1.Error` and `errFromPB(*storev1.Error) error`.

Errors are returned only where JSON is involved (`UserMetadata`, `CustomText`). A `nil` entity pointer maps to `nil` in both directions.

- [ ] **Step 1: Failing round-trip tests**

`internal/store/grpcstore/codec_test.go` covers each entity with three values:
- **full:** every field set, slices and maps non-empty, every `*time.Time` set, and times with nanoseconds such as `time.Date(2026,1,2,3,4,5,123456789,time.UTC)`;
- **empty:** every slice and map set to a non-nil empty value;
- **zero:** the struct's zero value, with nil slices, maps and pointers.

Each case asserts `cmp.Diff(in, fromPB(toPB(in))) == ""`.

```go
package grpcstore

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

var nanoTime = time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)

func ptr[T any](v T) *T { return &v }

func roundTrip[T any](t *testing.T, name string, in *T, to func(*T) (any, error), from func(any) (*T, error)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		pb, err := to(in)
		if err != nil {
			t.Fatal(err)
		}
		out, err := from(pb)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(in, out); diff != "" {
			t.Fatalf("round trip (-in +out):\n%s", diff)
		}
	})
}

func TestUserRoundTrip(t *testing.T) {
	to := func(u *store.User) (any, error) { return userToPB(u) }
	from := func(v any) (*store.User, error) { return userFromPB(v.(*storev1.User)) }
	roundTrip(t, "full", &store.User{
		TenantID: "ten", UserID: "auth0|u1", Email: "a@example.test", EmailVerified: true,
		Username: "alice", Name: "Alice", Nickname: "al", Picture: "https://p.example/a.png",
		GivenName: "A", FamilyName: "L",
		// JSON numbers decode as float64, as in the SQL drivers (D-0020).
		UserMetadata: map[string]any{"plan": "pro", "seats": float64(3), "tags": []any{"x", "y"}, "nested": map[string]any{"k": true}},
		Blocked:      true,
		Identities:   []store.Identity{{Connection: "db", Provider: "auth0", UserID: "u1", PasswordHash: "$argon2id$..."}},
		LastLogin:    ptr(nanoTime), LoginsCount: 7, CreatedAt: nanoTime, UpdatedAt: nanoTime.Add(time.Second),
	}, to, from)
	roundTrip(t, "empty", &store.User{UserMetadata: map[string]any{}, Identities: []store.Identity{}}, to, from)
	roundTrip(t, "zero", &store.User{}, to, from)
}

func TestErrorMapping(t *testing.T) {
	for _, e := range []error{nil, store.ErrNotFound, store.ErrConflict, store.ErrAlreadyUsed,
		fmt.Errorf("wrapped: %w", store.ErrConflict)} {
		got := errFromPB(errToPB(e))
		if e == nil {
			if got != nil {
				t.Fatalf("nil → %v", got)
			}
			continue
		}
		for _, sentinel := range []error{store.ErrNotFound, store.ErrConflict, store.ErrAlreadyUsed} {
			if errors.Is(e, sentinel) != errors.Is(got, sentinel) {
				t.Fatalf("%v → %v: errors.Is(%v) differs", e, got, sentinel)
			}
		}
	}
	other := errFromPB(errToPB(errors.New("next key must have status next")))
	if other == nil || other.Error() != "next key must have status next" {
		t.Fatalf("other error = %v", other)
	}
}
```

Write the same full, empty and zero triple for the other eleven entities, setting every field the struct has (see `internal/store/types.go`):
- `Tenant`: include `CustomText` with nested maps, and `Branding`.
- `Client`: include `Secrets` with one nil and one set `ExpiresAt`.
- `ResourceServer`, `ClientGrant`.
- `SigningKey`: include non-nil empty `PrivateKey` in the empty case.
- `Connection`, `LoginSession`, `AuthTransaction` (with `Params`), `AuthCode`, `RefreshToken`, `PasswordResetTicket`.

Add `TestTimeHelpers`:
- `tsFromPB(tsToPB(time.Time{})).IsZero()` is true;
- `optTSFromPB(nil) == nil`;
- a time in a non-UTC location comes back `Equal` and in UTC.

Run: `go test ./internal/store/grpcstore/`
Expected: FAIL to compile.

- [ ] **Step 2: Implement `codec.go`**

The rules:
- **Slices and maps.** A nil slice or map becomes an absent wrapper (`StringList`, `StringMap`, `ClientSecretList`, `ScopeList`, `IdentityList`). A non-nil one, including an empty one, becomes a present wrapper. Decode the reverse way: a present wrapper with no values becomes `[]T{}` or `map[K]V{}`.
- **Bytes.** A nil `[]byte` (or nil map for the JSON fields) is absent, and non-nil is present (proto3 `optional`).
- **`UserMetadata` and `CustomText`.** Encode with `json.Marshal`. Decode with `json.Unmarshal` into `map[string]any` or `store.CustomText`. A present but empty encoding cannot occur: an empty map marshals to `{}`.
- **Integers.** `int` fields map to `int64`.
- **Times.** `time.Time` is always `timestamppb.New(t)`, and decoding uses `AsTime().UTC()`. Before decoding, check `CheckValid()`; an invalid timestamp returns an error.

```go
package grpcstore

import (
	"encoding/json"
	"errors"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

func tsToPB(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }

func tsFromPB(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime().UTC()
}

func optTSToPB(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func optTSFromPB(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime().UTC()
	return &t
}

func stringsToPB(v []string) *storev1.StringList {
	if v == nil {
		return nil
	}
	return &storev1.StringList{Values: v}
}

func stringsFromPB(l *storev1.StringList) []string {
	if l == nil {
		return nil
	}
	if l.Values == nil {
		return []string{}
	}
	return append([]string{}, l.Values...)
}

func errToPB(err error) *storev1.Error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return &storev1.Error{Kind: storev1.Error_KIND_NOT_FOUND, Message: err.Error()}
	case errors.Is(err, store.ErrConflict):
		return &storev1.Error{Kind: storev1.Error_KIND_CONFLICT, Message: err.Error()}
	case errors.Is(err, store.ErrAlreadyUsed):
		return &storev1.Error{Kind: storev1.Error_KIND_ALREADY_USED, Message: err.Error()}
	default:
		return &storev1.Error{Kind: storev1.Error_KIND_UNSPECIFIED, Message: err.Error()}
	}
}

// errFromPB returns the sentinel itself for the known kinds, so callers'
// errors.Is checks and == comparisons both work.
func errFromPB(e *storev1.Error) error {
	if e == nil {
		return nil
	}
	switch e.Kind {
	case storev1.Error_KIND_NOT_FOUND:
		return store.ErrNotFound
	case storev1.Error_KIND_CONFLICT:
		return store.ErrConflict
	case storev1.Error_KIND_ALREADY_USED:
		return store.ErrAlreadyUsed
	default:
		return errors.New(e.Message)
	}
}

func userToPB(u *store.User) (*storev1.User, error) {
	if u == nil {
		return nil, nil
	}
	pb := &storev1.User{
		TenantId: u.TenantID, UserId: u.UserID, Email: u.Email, EmailVerified: u.EmailVerified,
		Username: u.Username, Name: u.Name, Nickname: u.Nickname, Picture: u.Picture,
		GivenName: u.GivenName, FamilyName: u.FamilyName, Blocked: u.Blocked,
		LastLogin: optTSToPB(u.LastLogin), LoginsCount: int64(u.LoginsCount),
		CreatedAt: tsToPB(u.CreatedAt), UpdatedAt: tsToPB(u.UpdatedAt),
	}
	if u.UserMetadata != nil {
		b, err := json.Marshal(u.UserMetadata)
		if err != nil {
			return nil, err
		}
		pb.UserMetadataJson = b
	}
	if u.Identities != nil {
		pb.Identities = &storev1.IdentityList{Values: make([]*storev1.Identity, 0, len(u.Identities))}
		for _, id := range u.Identities {
			pb.Identities.Values = append(pb.Identities.Values, &storev1.Identity{
				Connection: id.Connection, Provider: id.Provider, UserId: id.UserID, PasswordHash: id.PasswordHash})
		}
	}
	return pb, nil
}
```

`userFromPB` and the other eleven pairs follow the same rules field by field. Every field in `internal/store/types.go` must appear in exactly one `toPB` and one `fromPB`. The round-trip tests enforce this, because the "full" case sets every field.

- [ ] **Step 3: Verify and commit**

Run: `go test -race ./internal/store/grpcstore/`
Expected: PASS.

```bash
git add internal/store/grpcstore/codec.go internal/store/grpcstore/codec_test.go
git commit -m "feat(grpcstore): lossless codec between store types and the plugin protocol"
```

---

### Task 3: Server adapter, `store.Store` to `StoreServiceServer`, with remote transactions

**Files:**
- Create: `internal/store/grpcstore/server.go` (the type, the transaction registry, `Ping`/`BeginTx`/`Commit`/`Rollback`), `internal/store/grpcstore/server_repos.go` (the 61 repository RPCs) and `internal/store/grpcstore/server_test.go`.

**Interfaces:**
- Consumes: the codec (Task 2) and `storev1` (Task 1).
- Produces:
  - `func NewServer(s store.Store, opts ...ServerOption) *Server`. `*Server` implements `storev1.StoreServiceServer` and embeds `storev1.UnimplementedStoreServiceServer`.
  - `func WithTxIdleTimeout(d time.Duration) ServerOption`. The default is `60 * time.Second`.
  - `func (s *Server) Close()`, which rolls back every open transaction and waits for their goroutines.

- [ ] **Step 1: Failing tests**

`server_test.go` calls the `Server` methods directly. No network is needed.

```go
package grpcstore

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

func tenantPB(id string) *storev1.Tenant {
	pb, _ := tenantToPB(&store.Tenant{ID: id, Name: id})
	return pb
}

func TestServerDomainErrorsInResponse(t *testing.T) {
	ctx := context.Background()
	srv := NewServer(memory.New())
	defer srv.Close()
	res, err := srv.TenantsGet(ctx, &storev1.TenantsGetRequest{Key: "missing"})
	if err != nil {
		t.Fatalf("transport error %v; domain errors belong in the response", err)
	}
	if res.GetError().GetKind() != storev1.Error_KIND_NOT_FOUND {
		t.Fatalf("error = %v, want NOT_FOUND", res.GetError())
	}
}

func TestServerTxCommitAndRollback(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	srv := NewServer(mem)
	defer srv.Close()

	begin := func(parent string) string {
		r, err := srv.BeginTx(ctx, &storev1.BeginTxRequest{ParentTxId: parent})
		if err != nil || r.Error != nil {
			t.Fatalf("BeginTx: %v %v", err, r.GetError())
		}
		return r.TxId
	}
	create := func(tx, id string) {
		r, err := srv.TenantsCreate(ctx, &storev1.TenantWrite{TxId: tx, Value: tenantPB(id)})
		if err != nil || r.Error != nil {
			t.Fatalf("create %s: %v %v", id, err, r.GetError())
		}
	}

	tx := begin("")
	create(tx, "committed")
	if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: tx}); r.Error != nil {
		t.Fatal(r.Error)
	}
	if _, err := mem.Tenants().Get(ctx, "committed"); err != nil {
		t.Fatal("committed write missing")
	}

	tx = begin("")
	create(tx, "outer")
	inner := begin(tx)
	create(inner, "inner")
	srv.Rollback(ctx, &storev1.EndTxRequest{TxId: inner}) // inner only
	if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: tx}); r.Error != nil {
		t.Fatal(r.Error)
	}
	if _, err := mem.Tenants().Get(ctx, "outer"); err != nil {
		t.Fatal("outer write lost")
	}
	if _, err := mem.Tenants().Get(ctx, "inner"); err == nil {
		t.Fatal("rolled-back inner write persisted")
	}
}

func TestServerUnknownTxIsAnError(t *testing.T) {
	srv := NewServer(memory.New())
	defer srv.Close()
	r, err := srv.TenantsCreate(context.Background(), &storev1.TenantWrite{TxId: "nope", Value: tenantPB("a")})
	if err != nil {
		t.Fatal(err)
	}
	if r.GetError() == nil || r.GetError().Kind != storev1.Error_KIND_UNSPECIFIED {
		t.Fatalf("error = %v, want an unknown-transaction error", r.GetError())
	}
}

// An abandoned transaction is rolled back after the idle timeout and its
// locks are released (memory's txMu), so a later transaction can proceed.
func TestServerAbandonedTxIsRolledBack(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	srv := NewServer(mem, WithTxIdleTimeout(50*time.Millisecond))
	defer srv.Close()
	r, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{})
	srv.TenantsCreate(ctx, &storev1.TenantWrite{TxId: r.TxId, Value: tenantPB("abandoned")})

	done := make(chan error, 1)
	go func() { done <- mem.WithTx(ctx, func(store.Store) error { return nil }) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("abandoned transaction never released")
	}
	if _, err := mem.Tenants().Get(ctx, "abandoned"); err == nil {
		t.Fatal("abandoned write persisted")
	}
	if c, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: r.TxId}); c.GetError() == nil {
		t.Fatal("Commit of an expired transaction succeeded")
	}
}

func TestServerCommitWithOpenChildFails(t *testing.T) {
	ctx := context.Background()
	srv := NewServer(memory.New())
	defer srv.Close()
	p, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{})
	c, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{ParentTxId: p.TxId})
	if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: p.TxId}); r.GetError() == nil {
		t.Fatal("parent committed while a child was open")
	}
	srv.Rollback(ctx, &storev1.EndTxRequest{TxId: c.TxId})
	if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: p.TxId}); r.GetError() != nil {
		t.Fatal(r.GetError())
	}
}
```

Run: `go test ./internal/store/grpcstore/ -run TestServer`
Expected: FAIL to compile.

- [ ] **Step 2: Implement the transaction registry (`server.go`)**

```go
package grpcstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// errRollback ends a held transaction without committing it.
var errRollback = errors.New("grpcstore: rolled back")

// Server exposes a store.Store as a StoreService. Transactions opened by
// BeginTx run the store's own WithTx in a goroutine that holds the
// transaction open until Commit, Rollback, the idle timeout or Close.
type Server struct {
	storev1.UnimplementedStoreServiceServer
	st   store.Store
	idle time.Duration

	mu  sync.Mutex
	txs map[string]*heldTx
	wg  sync.WaitGroup
}

type ServerOption func(*Server)

// WithTxIdleTimeout sets how long a transaction may go without a call
// before the server rolls it back.
func WithTxIdleTimeout(d time.Duration) ServerOption { return func(s *Server) { s.idle = d } }

func NewServer(st store.Store, opts ...ServerOption) *Server {
	s := &Server{st: st, idle: 60 * time.Second, txs: map[string]*heldTx{}}
	for _, o := range opts {
		o(s)
	}
	return s
}

// heldTx is one open transaction. A nested transaction runs on its parent's
// underlying transaction (a SQL savepoint, a memory snapshot), so every
// transaction in one tree shares the root's lock: no two calls, and no
// BeginTx/finish, touch the same underlying transaction at once.
type heldTx struct {
	id     string
	parent *heldTx
	lock   *sync.Mutex // the root's; shared by the whole tree
	st     store.Store
	kids   map[string]*heldTx // open nested transactions (guarded by Server.mu)
	end    chan error         // nil = commit, errRollback = rollback
	result chan error         // the store's WithTx result
	timer  *time.Timer
	cancel context.CancelFunc
}

func newTxID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

var (
	errUnknownTx = errors.New("grpcstore: unknown or finished transaction")
	errOpenChild = errors.New("grpcstore: transaction has an open nested transaction")
)

func (s *Server) BeginTx(ctx context.Context, r *storev1.BeginTxRequest) (*storev1.BeginTxResponse, error) {
	base, lock := s.st, &sync.Mutex{}
	var parent *heldTx
	if r.ParentTxId != "" {
		s.mu.Lock()
		parent = s.txs[r.ParentTxId]
		s.mu.Unlock()
		if parent == nil {
			return &storev1.BeginTxResponse{Error: errToPB(errUnknownTx)}, nil
		}
		base, lock = parent.st, parent.lock
	}
	lock.Lock() // the nested WithTx issues its savepoint on the shared transaction
	defer lock.Unlock()

	txCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &heldTx{id: newTxID(), parent: parent, lock: lock, kids: map[string]*heldTx{},
		end: make(chan error, 1), result: make(chan error, 1), cancel: cancel}
	ready := make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		h.result <- base.WithTx(txCtx, func(tx store.Store) error {
			h.st = tx
			close(ready)
			return <-h.end
		})
	}()
	select {
	case <-ready:
	case err := <-h.result: // WithTx failed before running fn
		cancel()
		return &storev1.BeginTxResponse{Error: errToPB(err)}, nil
	}
	h.timer = time.AfterFunc(s.idle, func() { _ = s.finish(h.id, errRollback) })
	s.mu.Lock()
	s.txs[h.id] = h
	if parent != nil {
		parent.kids[h.id] = h
	}
	s.mu.Unlock()
	return &storev1.BeginTxResponse{TxId: h.id}, nil
}

// finish ends transaction id with signal (nil commits, errRollback rolls
// back) and returns the store's result; a rollback is not an error. Commit
// refuses while nested transactions are open; Rollback first rolls back the
// open nested transactions, innermost first.
func (s *Server) finish(id string, signal error) error {
	s.mu.Lock()
	h := s.txs[id]
	if h == nil {
		s.mu.Unlock()
		return errUnknownTx
	}
	if signal == nil && len(h.kids) > 0 {
		s.mu.Unlock()
		return errOpenChild
	}
	kids := make([]string, 0, len(h.kids))
	for k := range h.kids {
		kids = append(kids, k)
	}
	s.mu.Unlock()
	for _, k := range kids {
		_ = s.finish(k, errRollback)
	}

	s.mu.Lock()
	if s.txs[id] != h { // finished concurrently (e.g. the idle timer)
		s.mu.Unlock()
		return errUnknownTx
	}
	delete(s.txs, id)
	if h.parent != nil {
		delete(h.parent.kids, id)
	}
	s.mu.Unlock()

	h.timer.Stop()
	h.lock.Lock() // wait for an in-flight call in this tree
	h.end <- signal
	err := <-h.result
	h.lock.Unlock()
	h.cancel()
	if errors.Is(err, errRollback) {
		return nil
	}
	return err
}

func (s *Server) Commit(_ context.Context, r *storev1.EndTxRequest) (*storev1.Result, error) {
	return &storev1.Result{Error: errToPB(s.finish(r.TxId, nil))}, nil
}

func (s *Server) Rollback(_ context.Context, r *storev1.EndTxRequest) (*storev1.Result, error) {
	return &storev1.Result{Error: errToPB(s.finish(r.TxId, errRollback))}, nil
}

func (s *Server) Ping(ctx context.Context, _ *storev1.PingRequest) (*storev1.Result, error) {
	return &storev1.Result{Error: errToPB(s.st.Ping(ctx))}, nil
}

// Close rolls back every open transaction (roots; their nested
// transactions go first) and waits for the transaction goroutines.
func (s *Server) Close() {
	s.mu.Lock()
	var roots []string
	for id, h := range s.txs {
		if h.parent == nil {
			roots = append(roots, id)
		}
	}
	s.mu.Unlock()
	for _, id := range roots {
		_ = s.finish(id, errRollback)
	}
	s.wg.Wait()
}

// with runs f against the store a request addresses: the base store, or
// the held transaction txID. Calls in one transaction tree are serialized,
// and each call resets the transaction's idle timer.
func (s *Server) with(txID string, f func(store.Store) error) error {
	if txID == "" {
		return f(s.st)
	}
	s.mu.Lock()
	h := s.txs[txID]
	s.mu.Unlock()
	if h == nil {
		return errUnknownTx
	}
	h.lock.Lock()
	defer h.lock.Unlock()
	if !h.timer.Stop() { // the idle timer already fired: finish is rolling it back
		return errUnknownTx
	}
	h.timer.Reset(s.idle)
	return f(h.st)
}
```

Locking order is always `Server.mu` (held briefly, never across a store call) and then the tree lock. `finish` takes the tree lock only after releasing `Server.mu`, so the idle timer, `Close` and concurrent RPCs cannot deadlock. Add a `-race` stress test, `TestServerTxStress`: 8 goroutines each run 50 rounds of BeginTx → create → nested BeginTx → create → random Commit or Rollback of the nested transaction → Commit of the outer one. Assert that the number of tenants stored equals the number of committed creates, and that `Close` returns.

- [ ] **Step 3: Implement the repository RPCs (`server_repos.go`)**

Every RPC follows this shape: decode, call through `with`, and encode the result.

```go
func (s *Server) TenantsCreate(ctx context.Context, r *storev1.TenantWrite) (*storev1.Result, error) {
	t, err := tenantFromPB(r.Value)
	if err == nil {
		err = s.with(r.TxId, func(st store.Store) error { return st.Tenants().Create(ctx, t) })
	}
	return &storev1.Result{Error: errToPB(err)}, nil
}

func (s *Server) AuthCodesConsume(ctx context.Context, r *storev1.ConsumeRequest) (*storev1.AuthCodeResult, error) {
	var code *store.AuthCode
	err := s.with(r.TxId, func(st store.Store) (e error) {
		code, e = st.AuthCodes().Consume(ctx, r.TenantId, r.Hash, tsFromPB(r.At))
		return e
	})
	pb, encErr := authCodeToPB(code) // Consume returns the code with ErrAlreadyUsed too
	if encErr != nil {
		return nil, encErr
	}
	return &storev1.AuthCodeResult{Error: errToPB(err), Value: pb}, nil
}

func (s *Server) SessionsDeleteExpired(ctx context.Context, r *storev1.DeleteExpiredRequest) (*storev1.CountResult, error) {
	var n int
	err := s.with(r.TxId, func(st store.Store) (e error) {
		n, e = st.Sessions().DeleteExpired(ctx, tsFromPB(r.Before))
		return e
	})
	return &storev1.CountResult{Error: errToPB(err), Count: int64(n)}, nil
}
```

A nil `Value` on a write request becomes the domain value `nil`, and the store decides what to do with it. An encoding error from the server's own `toPB` is a real fault, so it returns a gRPC `Internal` status. Implement every RPC in the `.proto` service with this pattern. A compile-time assertion keeps the set complete:

```go
var _ storev1.StoreServiceServer = (*Server)(nil)
```

The embedded `Unimplemented…` type would hide a missing method, so add a test that walks `storev1.StoreService_ServiceDesc.Methods`. For each method name, it asserts `reflect.TypeOf(&Server{}).MethodByName(name)` is defined on `*Server` itself, not promoted from the embedded type. Compare the method's `Func` pointer with the one from `UnimplementedStoreServiceServer`.

- [ ] **Step 4: Verify and commit**

Run: `go test -race -count=3 ./internal/store/grpcstore/ -run TestServer`
Expected: PASS.

```bash
git add internal/store/grpcstore/server.go internal/store/grpcstore/server_repos.go internal/store/grpcstore/server_test.go
git commit -m "feat(grpcstore): server adapter with held remote transactions"
```

---

### Task 4: Client driver and in-process conformance

**Files:**
- Create: `internal/store/grpcstore/client.go`, `internal/store/grpcstore/client_repos.go`, `internal/store/grpcstore/client_test.go`, `internal/store/grpcstore/conformance_test.go`

**Interfaces:**
- Consumes: `NewServer` (Task 3), the codec (Task 2) and `storev1` (Task 1).
- Produces:
  - `func NewClient(conn grpc.ClientConnInterface, closer func() error) *Client`. `*Client` implements `store.Store`, and its `Close` calls `closer` (which may be nil).
  - Transactional views are unexported `*Client` values that carry a `txID`.

- [ ] **Step 1: Failing tests**

`conformance_test.go` runs the whole suite through real gRPC over `bufconn`:

```go
package grpcstore

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

var _ store.Store = (*Client)(nil)

// inProcess serves a fresh memory store over bufconn and returns a client.
func inProcess(t *testing.T) *Client {
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	srv := NewServer(memory.New())
	storev1.RegisterStoreServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	return NewClient(conn, func() error {
		err := conn.Close()
		srv.Close()
		gs.Stop()
		return err
	})
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return inProcess(t) })
}
```

`client_test.go` covers what storetest cannot see:

```go
// A panic inside fn rolls the remote transaction back and is re-raised.
func TestClientWithTxPanicRollsBack(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	defer c.Close()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic swallowed")
			}
		}()
		_ = c.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Tenants().Create(ctx, &store.Tenant{ID: "p", Name: "p"}); err != nil {
				return err
			}
			panic("boom")
		})
	}()
	if _, err := c.Tenants().Get(ctx, "p"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("write after panic: %v", err)
	}
	// The server-side transaction was released: another WithTx proceeds.
	if err := c.WithTx(ctx, func(store.Store) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// Cancelling ctx inside fn still rolls back (Rollback uses WithoutCancel).
func TestClientWithTxCancelledContext(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	err := c.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Tenants().Create(ctx, &store.Tenant{ID: "c", Name: "c"}); err != nil {
			return err
		}
		cancel()
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.Tenants().Get(context.Background(), "c"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("write after cancel: %v", err)
	}
}

// Transport failures are errors, not domain errors.
func TestClientTransportErrorIsNotADomainError(t *testing.T) {
	c := inProcess(t)
	c.Close()
	_, err := c.Tenants().Get(context.Background(), "x")
	if err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want a transport error", err)
	}
}
```

Run: `go test ./internal/store/grpcstore/`
Expected: FAIL to compile.

- [ ] **Step 2: Implement `client.go`**

```go
package grpcstore

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// Client is a store.Store backed by a StoreService.
type Client struct {
	rpc    storev1.StoreServiceClient
	closer func() error
	txID   string // empty outside a transaction
}

func NewClient(conn grpc.ClientConnInterface, closer func() error) *Client {
	return &Client{rpc: storev1.NewStoreServiceClient(conn), closer: closer}
}

// rpcErr wraps a transport failure so it never matches a store sentinel.
func rpcErr(op string, err error) error { return fmt.Errorf("storage plugin: %s: %w", op, err) }

func (c *Client) Ping(ctx context.Context) error {
	r, err := c.rpc.Ping(ctx, &storev1.PingRequest{})
	if err != nil {
		return rpcErr("Ping", err)
	}
	return errFromPB(r.Error)
}

func (c *Client) Close() error {
	if c.txID != "" || c.closer == nil {
		return nil
	}
	return c.closer()
}

// WithTx opens a remote transaction (nested when c is already inside one),
// runs fn against a view bound to it, and commits only if fn returns nil.
// It never retries. A panic in fn rolls back and is re-raised.
func (c *Client) WithTx(ctx context.Context, fn func(store.Store) error) (err error) {
	r, rerr := c.rpc.BeginTx(ctx, &storev1.BeginTxRequest{ParentTxId: c.txID})
	if rerr != nil {
		return rpcErr("BeginTx", rerr)
	}
	if e := errFromPB(r.Error); e != nil {
		return e
	}
	tx := &Client{rpc: c.rpc, txID: r.TxId}
	end := context.WithoutCancel(ctx)
	committed := false
	defer func() {
		if committed {
			return
		}
		if _, rbErr := c.rpc.Rollback(end, &storev1.EndTxRequest{TxId: r.TxId}); rbErr != nil && err != nil {
			err = errors.Join(err, rpcErr("Rollback", rbErr))
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	cr, cerr := c.rpc.Commit(end, &storev1.EndTxRequest{TxId: r.TxId})
	committed = true // a failed Commit has already ended the transaction
	if cerr != nil {
		return rpcErr("Commit", cerr)
	}
	return errFromPB(cr.Error)
}
```

`client_repos.go` implements the 12 accessors (`Tenants()` returns `clientTenants{c}`, and so on) and every method. Each method encodes, calls the RPC with `TxId: c.txID`, wraps a transport error with `rpcErr(<RPC name>, err)`, and otherwise decodes `Value` and returns `errFromPB(r.Error)`. A `Get` that returns NOT_FOUND returns `nil, store.ErrNotFound`. `Consume` returns the decoded value *together with* the error, matching `store.AuthCodes.Consume`.

```go
type clientAuthCodes struct{ c *Client }

func (a clientAuthCodes) Consume(ctx context.Context, tenantID, codeHash string, at time.Time) (*store.AuthCode, error) {
	r, err := a.c.rpc.AuthCodesConsume(ctx, &storev1.ConsumeRequest{TxId: a.c.txID, TenantId: tenantID, Hash: codeHash, At: tsToPB(at)})
	if err != nil {
		return nil, rpcErr("AuthCodesConsume", err)
	}
	code, derr := authCodeFromPB(r.Value)
	if derr != nil {
		return nil, derr
	}
	return code, errFromPB(r.Error)
}
```

- [ ] **Step 3: Verify and commit**

Run: `go test -race ./internal/store/grpcstore/`, then `go test -race -count=5 -run 'TestConformance/(Users|Sessions|RefreshTokens|AuthCodes|PasswordResetTickets|SigningKeys|Tx)' ./internal/store/grpcstore/`
Expected: PASS. The concurrency cases (concurrent `Rotate`, concurrent create, `ConcurrentRotateAndRevoke`, sweeper versus insert, and the `Tx` cases) pass through the RPC layer.

```bash
git add internal/store/grpcstore/client.go internal/store/grpcstore/client_repos.go internal/store/grpcstore/client_test.go internal/store/grpcstore/conformance_test.go
git commit -m "feat(grpcstore): client driver; full storetest conformance over gRPC"
```

---

### Task 5: go-plugin SDK, sample plugin, out-of-process conformance

**Files:**
- Create: `pkg/storeplugin/storeplugin.go`, `pkg/storeplugin/storeplugin_test.go`, `cmd/zeroauthy-store-memory/main.go`
- Modify: `Makefile`, adding the sample plugin to `build`

**Interfaces:**
- Consumes: `grpcstore.NewServer` and `NewClient`, and `pkg/store`.
- Produces:
  - `func Serve(s store.Store)`: plugin binaries call this from `main`, and it never returns.
  - `func Open(ctx context.Context, path string, args ...string) (store.Store, error)`: hosts and tests use it to start the binary and complete the handshake. The returned store's `Close` kills the plugin.
  - `var Handshake plugin.HandshakeConfig`, using the Global Constraints values.

- [ ] **Step 1: Failing tests**

`pkg/storeplugin/storeplugin_test.go` builds the sample plugin once in `TestMain`, then runs:

```go
package storeplugin_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/pkg/store"
	"github.com/zeroauthy/zeroauthy/pkg/storeplugin"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

var pluginBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "zeroauthy-plugin")
	if err != nil {
		panic(err)
	}
	pluginBin = filepath.Join(dir, "zeroauthy-store-memory")
	out, err := exec.Command("go", "build", "-o", pluginBin, "github.com/zeroauthy/zeroauthy/cmd/zeroauthy-store-memory").CombinedOutput()
	if err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// Spec §12: storetest runs against the sample gRPC plugin, one plugin
// process per fresh store.
func TestConformanceThroughPluginProcess(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		s, err := storeplugin.Open(context.Background(), pluginBin)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestOpenErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := storeplugin.Open(ctx, "/nonexistent/plugin"); err == nil {
		t.Fatal("missing binary opened")
	}
	if _, err := storeplugin.Open(ctx, "relative/plugin"); err == nil {
		t.Fatal("relative path accepted")
	}
	// A program that never handshakes fails within the start timeout.
	sleeper := filepath.Join(t.TempDir(), "sleeper.sh")
	os.WriteFile(sleeper, []byte("#!/bin/sh\nsleep 60\n"), 0o755)
	start := time.Now()
	_, err := storeplugin.Open(ctx, sleeper)
	if err == nil {
		t.Fatal("non-plugin opened")
	}
	if time.Since(start) > 15*time.Second {
		t.Fatalf("took %v; want the start timeout", time.Since(start))
	}
}

// When the plugin dies, calls fail promptly and Ping reports it.
func TestPluginCrash(t *testing.T) {
	ctx := context.Background()
	s, err := storeplugin.Open(ctx, pluginBin)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	storeplugin.KillForTest(s) // see Step 2
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.Ping(cctx); err == nil {
		t.Fatal("Ping succeeded after the plugin died")
	}
	if cctx.Err() != nil {
		t.Fatal("Ping hung until the deadline")
	}
}
```

Run: `go test ./pkg/storeplugin/`
Expected: FAIL to compile.

- [ ] **Step 2: Implement `pkg/storeplugin/storeplugin.go`**

```go
// Package storeplugin is the SDK for zeroauthy storage plugins: separate
// executables that store zeroauthy's data and talk to it over gRPC
// (hashicorp/go-plugin). A plugin's main calls Serve with its store.Store;
// zeroauthy starts it from a plugin:///path DSN. Run pkg/storetest against
// Open(path) to check a plugin before shipping it.
package storeplugin

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/zeroauthy/zeroauthy/internal/store/grpcstore"
	"github.com/zeroauthy/zeroauthy/pkg/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// Handshake must match between zeroauthy and the plugin.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "ZEROAUTHY_STORE_PLUGIN",
	MagicCookieValue: "5b0f7c1e-store-v1",
}

const pluginName = "store"

// StartTimeout bounds how long Open waits for the plugin's handshake.
const StartTimeout = 10 * time.Second

type grpcPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	impl store.Store
}

func (p *grpcPlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	storev1.RegisterStoreServiceServer(s, grpcstore.NewServer(p.impl))
	return nil
}

func (p *grpcPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, conn *grpc.ClientConn) (any, error) {
	return conn, nil
}

// Serve runs s as a zeroauthy storage plugin. It does not return.
func Serve(s store.Store) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins:         plugin.PluginSet{pluginName: &grpcPlugin{impl: s}},
		GRPCServer:      plugin.DefaultGRPCServer,
	})
}

// Open starts the plugin at path (absolute) with args and returns a
// store.Store backed by it. Closing the store stops the plugin.
// Errors name neither the path's arguments nor any secret.
func Open(ctx context.Context, path string, args ...string) (store.Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("storage plugin: the binary path must be absolute")
	}
	if fi, err := os.Stat(path); err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
		return nil, errors.New("storage plugin: the binary does not exist or is not executable")
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  Handshake,
		Plugins:          plugin.PluginSet{pluginName: &grpcPlugin{}},
		Cmd:              exec.Command(path, args...),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		StartTimeout:     StartTimeout,
		Logger:           hclog.New(&hclog.LoggerOptions{Name: "storage-plugin", Output: os.Stderr, Level: hclog.Warn}),
	})
	rpc, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, errors.New("storage plugin: start failed (handshake): " + err.Error())
	}
	raw, err := rpc.Dispense(pluginName)
	if err != nil {
		client.Kill()
		return nil, errors.New("storage plugin: dispense failed: " + err.Error())
	}
	conn := raw.(*grpc.ClientConn)
	st := grpcstore.NewClient(conn, func() error { client.Kill(); return nil })
	if err := st.Ping(ctx); err != nil {
		client.Kill()
		return nil, err
	}
	return &opened{Store: st, client: client}, nil
}

type opened struct {
	store.Store
	client *plugin.Client
}
```

Check the go-plugin error texts that `Open` passes through (`client.Client()` and `Dispense`). They must not contain `args`. go-plugin reports the command path in some errors, and the path is acceptable to show; arguments are not. If an error would include arguments, replace it with a fixed message.

Test hook: `export_test.go` cannot reach from another package, so add an exported but documented hook:

```go
// KillForTest stops the plugin process behind a store returned by Open,
// without closing the store. It exists for crash tests.
func KillForTest(s store.Store) {
	if o, ok := s.(*opened); ok {
		o.client.Kill()
	}
}
```

`cmd/zeroauthy-store-memory/main.go`:

```go
// Command zeroauthy-store-memory is the sample storage plugin: the in-memory
// driver served over the plugin protocol. It is for tests and as a template
// for plugin authors; its data is lost when it exits.
package main

import (
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storeplugin"
)

func main() { storeplugin.Serve(memory.New()) }
```

Run `go doc github.com/hashicorp/go-plugin.ClientConfig` and `go doc github.com/hashicorp/go-plugin.GRPCPlugin`, and adjust the field and method names to the resolved version if they differ. The behaviour above is the requirement.

`Makefile` `build` also produces `bin/zeroauthy-store-memory`:

```make
build:
	CGO_ENABLED=0 go build -trimpath -o bin/zeroauthy ./cmd/zeroauthy
	CGO_ENABLED=0 go build -trimpath -o bin/zeroauthy-store-memory ./cmd/zeroauthy-store-memory
```

- [ ] **Step 3: Verify and commit**

Run: `go test -race ./pkg/storeplugin/` and `go test -race -count=3 -run 'TestConformanceThroughPluginProcess/(SigningKeys|Users|RefreshTokens|Tx)' ./pkg/storeplugin/`
Expected: PASS. After the run, `pgrep -f zeroauthy-store-memory` finds no leftover processes.

```bash
git add pkg/storeplugin cmd/zeroauthy-store-memory Makefile go.mod go.sum
git commit -m "feat(storeplugin): go-plugin SDK and sample memory plugin; conformance through a plugin process"
```

---

### Task 6: `plugin://` DSN, app wiring, CI, docs

**Files:**
- Modify: `internal/storage/open.go`, `internal/storage/open_test.go`, `internal/storage/redact_test.go`
- Modify: `internal/app/app_test.go`, adding a plugin-backed app test
- Modify: `.github/workflows/ci.yml`, adding a `go generate` no-diff check for `proto/`
- Modify: `docs/compat/decisions.md` (D-0021), `README.md`, spec §5.2 and §14, `docs/superpowers/plan-1-followups.md`

**Interfaces:**
- Consumes: `storeplugin.Open`.
- Produces: `storage.Open(ctx, "plugin:///abs/path?arg=…")`.

- [ ] **Step 1: Failing tests**

`internal/storage/open_test.go`:
- The sample plugin is built in `TestMain` the same way as Task 5.
- `plugin://` + an absolute path opens and pings.
- `plugin://relative` is rejected. So is `plugin://host/abs`, because the host must be empty.
- `?arg=a&arg=b` reaches the plugin as argv. Pass `?arg=--ignored` to the sample plugin; it ignores argv, so this only checks that `Open` accepts the DSN.
- `?other=x` is rejected, and the error names `other` but not `x`.

`internal/storage/redact_test.go`: add `plugin:///nonexistent?arg=s3cr3tPW` and `plugin:///abs?other=s3cr3tPW` to the leak table. The error must never contain `s3cr3tPW`.

`internal/app/app_test.go` gets `TestAppOnPluginStorage`:
- config `storage.dsn: plugin://<built sample>`, with a master key and a seed that has one tenant and one client;
- `app.New` succeeds;
- `GET /healthz` returns 200;
- a `client_credentials` token request succeeds, using the existing test helpers for M3.

Run: `go test ./internal/storage/ ./internal/app/`
Expected: FAIL.

- [ ] **Step 2: Implement the dispatch**

In `storage.Open`, add this case:

```go
	case "plugin":
		if u.Host != "" || !strings.HasPrefix(u.Path, "/") {
			return nil, errors.New("storage: plugin DSN must be plugin:///absolute/path/to/binary")
		}
		q := u.Query()
		for k := range q {
			if k != "arg" {
				return nil, fmt.Errorf("storage: plugin DSN: unknown query parameter %q (only arg is allowed)", k)
			}
		}
		return storeplugin.Open(ctx, u.Path, q["arg"]...)
```

Update the package comment of `Open` to list `plugin://`. `prepareSchema` already skips stores that are not a `Migrator`. The master-key rule already covers `plugin://`. Confirm both with the app test.

- [ ] **Step 3: CI**

In `.github/workflows/ci.yml`, after the existing generate check (or as a new step in the test job), add:

```yaml
      - name: Generated protocol is up to date
        run: |
          go generate ./proto/...
          git diff --exit-code -- proto
```

The plugin conformance test runs inside the normal `go test -race ./...` step; it builds the sample plugin itself.

- [ ] **Step 4: Docs**

- **D-0021** "Storage plugins: protocol and remote transactions", written in our own words:
  - the protocol shape: one RPC per store method, with domain errors in the response;
  - the encoding conventions: wrappers for nil versus empty, Timestamps, JSON for metadata and custom text;
  - remote transactions: `BeginTx`, `Commit` and `Rollback`; nesting through `parent_tx_id` with savepoint semantics; the 60 s idle rollback; no retry across the boundary;
  - the handshake values and AutoMTLS;
  - the DSN format and its error rules;
  - that this replaces the earlier "no transactions across the plugin boundary" (user decision, 2026-10-16).
- **Spec §5.2.** Replace the sentence "Transactions are not offered across the plugin boundary; plugins must implement the atomic methods themselves." with a short description of remote transactions and the Go SDK (`pkg/storeplugin`, `pkg/store`). §14 "Plugin boundary" becomes: a plugin crash fails storage calls until restart, and automatic restart is a follow-up.
- **README "Storage":** add a `plugin://` row, plus a short "Writing a storage plugin" paragraph. It should cover `pkg/storeplugin.Serve`, `cmd/zeroauthy-store-memory` as a template, and running `storetest.Run` with `storeplugin.Open`.
- **`plan-1-followups.md`, "Plan 7 follow-ups":**
  - automatic plugin restart and backoff;
  - binary checksum pinning (go-plugin `SecureConfig`);
  - plugin-side schema migration hooks;
  - a non-Go reference plugin.

- [ ] **Step 5: Verify and commit**

Run: `go test -race ./... && go vet ./... && gofmt -l . && go generate ./... && git diff --exit-code`, then `make e2e` (regression; it still runs on SQLite).
Expected: PASS, no diff. E2E reports "OK", "OK", "6 passed".

```bash
git add internal/storage internal/app .github/workflows/ci.yml docs README.md
git commit -m "feat(storage): plugin:// DSN; D-0021 storage plugin protocol and remote transactions"
```

---

## Plan Self-Review (completed by the planner)

- **Spec coverage:**
  - §3.1 layout: `proto/store/v1` and `internal/store/grpcstore` are in Tasks 1 to 4.
  - §5.1: the `plugin://` DSN is in Task 6.
  - §5.2: the go-plugin host and sample plugin are in Task 5, and plugin authors running storetest is covered by Task 5 and the `pkg/store` aliases. The transaction sentence is replaced per the user decision in Task 6.
  - §12: storetest runs against the sample plugin in Task 5.
  - §13 milestone 8 is covered as a whole.
- **Placeholder scan:**
  - Repeated RPC and codec bodies are specified by an exact rule plus full examples. Completeness is enforced by tests: round-trip "full" values in Task 2, the service-descriptor walk in Task 3, and storetest in Tasks 4 and 5.
  - The go-plugin API names are pinned to `go doc` of the resolved version.
- **Type consistency:**
  - `NewServer`/`Server.Close` and `NewClient(conn, closer)` are used the same way in Tasks 3 to 5.
  - `storeplugin.Open(ctx, path, args...)` matches the Task 6 dispatch.
  - The codec function names match between Tasks 2, 3 and 4.
- **Review Focus mapping:**
  - Item 1: Task 3 `TestServerAbandonedTxIsRolledBack` and Task 4 panic and cancel tests.
  - Item 2: Task 5 `TestPluginCrash`.
  - Item 3: Task 5 `TestOpenErrors` and Task 6 DSN tests.
  - Item 4: storetest concurrency cases in Tasks 4 and 5.
  - Item 5: Task 2 round-trip tests.
