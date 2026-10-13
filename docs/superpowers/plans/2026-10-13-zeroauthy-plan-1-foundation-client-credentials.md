# zeroauthy Plan 1: Foundation through Client Credentials (Milestones 1–3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a runnable `zeroauthy` binary that serves multi-tenant OIDC discovery, JWKS, and the OAuth 2.0 `client_credentials` grant. Tokens it issues must be accepted unmodified by `express-oauth2-jwt-bearer`, and requested successfully through `@auth0/auth0-auth-js` and node-auth0's `auth0/legacy` `AuthenticationClient`.

**Architecture:**
- One Go module with one static binary.
- Every handler reaches data through the tenant-scoped `store.Store` interfaces. This plan ships the in-memory driver plus an exported conformance suite (`pkg/storetest`) that later drivers must pass.
- The OpenAPI 3.1 file `api/authentication.yaml` is the hand-written contract. oapi-codegen generates the route interface from it, and every HTTP test validates traffic against it with kin-openapi.
- Signing keys are per-tenant RS256, envelope-encrypted at rest under a master key.

**Tech Stack:** Go 1.26+, chi v5, cobra, koanf v2, go-jose v4, oapi-codegen v2.8 (as a `go tool`), kin-openapi v0.150, golang.org/x/crypto (argon2id), go.yaml.in/yaml/v3, go-cmp. E2E uses Node 22+ with `@auth0/auth0-auth-js` 1.16.1, `auth0` 7.4.0, `express` 5.3.0, and `express-oauth2-jwt-bearer` 1.11.0.

**Spec:** `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md`. This plan covers spec §13 milestones 1–3. The remaining milestones get their own plans.

**Module path:** `github.com/zeroauthy/zeroauthy`. This is an assumption, because the repo has no remote yet. Changing it later is one `go mod edit -module` plus a search-and-replace of imports.

## Global Constraints

- The clean-room policy in `CLEAN_ROOM.md` applies to every task:
  - Behavior comes only from public docs, RFCs and OIDC specs, and black-box runs of open-source SDKs against *our* server.
  - Every OpenAPI operation carries an `x-source` list of public URLs.
- Single static binary: `CGO_ENABLED=0 go build ./cmd/zeroauthy` must succeed. No cgo dependencies.
- `api/authentication.yaml` (OpenAPI 3.1) is the source of truth. Generated code in `internal/gen/authapi` is committed, and `go generate ./...` must produce no diff.
- Issuer is `https://{tenant domain}/` with a trailing slash. The tenant domain is the normalized request host.
- Unknown `Host` → `404` with JSON `{"error":"not_found","error_description":"unknown tenant"}`.
- Every store call is tenant-scoped (the tenant ID is part of every key), except calls on `Tenants` itself.
- API errors use JSON `{"error": "...", "error_description": "..."}`. Token endpoint responses (success and error) carry `Cache-Control: no-store` and `Pragma: no-cache`.
- Signing keys:
  - Per tenant, RS256, with lifecycle `next → current → previous → revoked`.
  - JWKS publishes current, next and previous.
  - Private keys are stored only envelope-encrypted with AES-256-GCM. The data key is wrapped by a 32-byte master key from `ZEROAUTHY_SECURITY__MASTER_KEY` (base64) or `security.master_key_file`.
- Client secrets are stored only as argon2id PHC strings.
- Access token defaults:
  - Lifetime is 86400 s when the resource server sets none.
  - For `client_credentials`: `sub` = `{client_id}@clients`, `gty` = `client-credentials`, `azp` = client ID.
  - `aud` is a JSON string when there is one audience and an array otherwise.
- Config comes from YAML plus `ZEROAUTHY_*` env vars, where `__` separates nesting levels (e.g. `ZEROAUTHY_SERVER__LISTEN`).
- Tests use only the standard `testing` package plus `go-cmp`. Run them with `go test ./...` (CI adds `-race`).

## Review Focus

These are the inputs most likely to bite real users that no milestone test exercises naturally. Each one has a pinned test in the task named.

1. **Host header variants:** `ACME.example.test`, `acme.example.test.`, `acme.example.test:443`, and `X-Forwarded-Host` (honored only when `trust_proxy_headers` is on) must all resolve to the same tenant. An untrusted forwarded header must be ignored. (Task 7)
2. **Credentials sent two ways at once:** HTTP Basic *and* `client_secret` in the body → `400 invalid_request`. Never silently pick one. (Task 13)
3. **Basic credentials with reserved characters:** RFC 6749 §2.3.1 form-urlencodes the ID and secret before base64. A secret like `p@ss:w+rd` must authenticate when the client sends `p%40ss%3Aw%2Brd`. (Task 13)
4. **Content-Type parameters:** `application/x-www-form-urlencoded; charset=UTF-8` and `application/json; charset=utf-8` must be accepted. SDKs send both. (Task 13)
5. **Cross-tenant use:** a client or audience from tenant A presented on tenant B's host must get `invalid_client` / `access_denied` and never a token. (Task 15)

## Out of Scope for This Plan (later plans, per spec §13)

- `/authorize` and hosted login, sessions, refresh tokens, logout, `/userinfo`, the password grants, `/dbconnections/*`, email
- SQL drivers and `Store.WithTx`; the gRPC plugin host; the `custom-db` bridge
- Device flow, PAR, consent; CORS and rate limiting; the `keys rotate` CLI (the rotation function is built here); the OIDF suite

## File Map

```
go.mod, go.sum, Makefile, README.md, .github/workflows/ci.yml
cmd/zeroauthy/{main.go, root.go, serve.go, seed.go, logger.go, *_test.go}
api/{authentication.yaml, embed.go, spec_test.go}
scripts/check-sources.sh                    verifies every x-source URL is reachable
internal/store/{store.go, types.go}          interfaces + domain types (no logic)
internal/store/memory/{memory.go, clone.go, tenants.go, clients.go, resource_servers.go,
                       client_grants.go, signing_keys.go, memory_test.go}
pkg/storetest/{storetest.go, helpers.go, tenants.go, clients.go, resource_servers.go,
               client_grants.go, signing_keys.go}
internal/storage/{open.go, open_test.go}     DSN → driver
internal/secrets/{secrets.go, secrets_test.go}   argon2id + random strings
internal/config/{config.go, config_test.go}
internal/httpx/{json.go}                      JSON + error writers
internal/tenant/{host.go, resolver.go, context.go, *_test.go}
internal/keys/{wrapper.go, envelope.go, manager.go, *_test.go}
internal/seed/{seed.go, validate.go, apply.go, *_test.go}
internal/gen/authapi/{generate.go, cfg.yaml, authapi.gen.go}
internal/testutil/contract/{contract.go, contract_test.go}
internal/oidc/{handlers.go, handlers_test.go}
internal/oauth/{handlers.go, errors.go, request.go, clientauth.go, minter.go, scopes.go,
                grant_client_credentials.go, *_test.go, fixture_test.go}
internal/server/{server.go, docs.go, log.go, server_test.go}
internal/app/{app.go, app_test.go}
tests/e2e/{package.json, package-lock.json, config.yaml, seed.yaml,
           m3-client-credentials.mjs, run-m3.sh}
docs/compat/{decisions.md, matrix.md}
```

---

### Task 1: Repository skeleton, CLI, CI

**Files:**
- Create: `go.mod`, `Makefile`, `cmd/zeroauthy/main.go`, `cmd/zeroauthy/root.go`, `cmd/zeroauthy/root_test.go`, `.github/workflows/ci.yml`

**Interfaces:**
- Produces: `newRootCmd() *cobra.Command` (package `main`). Later tasks add subcommands with `root.AddCommand(...)` inside `newRootCmd`. Package var `version = "dev"`.

- [ ] **Step 1: Initialize the module**

```bash
cd /mnt/nvme2/code/zeroauthy
go mod init github.com/zeroauthy/zeroauthy
go mod edit -go=1.26.0
go get github.com/spf13/cobra@v1.10.2
```

- [ ] **Step 2: Write the failing test** at `cmd/zeroauthy/root_test.go`

```go
package main

import (
	"bytes"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "zeroauthy dev\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./cmd/zeroauthy/`
Expected: FAIL: `undefined: newRootCmd`

- [ ] **Step 4: Implement** `cmd/zeroauthy/root.go` and `cmd/zeroauthy/main.go`

```go
// cmd/zeroauthy/root.go
package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set at build time with -ldflags "-X main.version=<v>".
var version = "dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "zeroauthy",
		Short:         "Auth0-compatible identity server",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the zeroauthy version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "zeroauthy", version)
			return err
		},
	}
}
```

```go
// cmd/zeroauthy/main.go
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "zeroauthy:", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 5: Add `Makefile` and `.github/workflows/ci.yml`**

```make
.PHONY: build test lint generate check-sources e2e

build:
	CGO_ENABLED=0 go build -trimpath -o bin/zeroauthy ./cmd/zeroauthy

test:
	go test ./...

lint:
	go vet ./...

generate:
	go generate ./...

check-sources:
	./scripts/check-sources.sh api/authentication.yaml

e2e:
	./tests/e2e/run-m3.sh
```

```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - run: go vet ./...
      - run: go test -race ./...
      - run: CGO_ENABLED=0 go build ./cmd/zeroauthy
```

- [ ] **Step 6: Run the tests and build**

Run: `go test ./... && go vet ./... && CGO_ENABLED=0 go build -o /dev/null ./cmd/zeroauthy`
Expected: `ok  github.com/zeroauthy/zeroauthy/cmd/zeroauthy`, then no vet output, and a successful build.

- [ ] **Step 7: Commit**

```bash
go mod tidy
git add go.mod go.sum Makefile cmd .github/workflows/ci.yml
git commit -m "feat: add zeroauthy CLI skeleton and CI"
```

---

### Task 2: Store interfaces, tenants, memory driver, conformance suite

**Files:**
- Create: `internal/store/store.go`, `internal/store/types.go`
- Create: `pkg/storetest/storetest.go`, `pkg/storetest/helpers.go`, `pkg/storetest/tenants.go`
- Create: `internal/store/memory/memory.go`, `internal/store/memory/clone.go`, `internal/store/memory/tenants.go`, `internal/store/memory/memory_test.go`

**Interfaces:**
- Produces (package `store`):
  - `var ErrNotFound, ErrConflict error`
  - `type Store interface { Tenants() Tenants; Ping(ctx) error; Close() error }`. Tasks 3 and 4 add accessors.
  - `type Tenants interface { Create; Get(ctx, id); GetByName(ctx, name); GetByDomain(ctx, domain); Update; List }`
  - `type Tenant struct { ID, Name, FriendlyName string; Domains []string; DefaultAudience string; CreatedAt time.Time }`
- Produces (package `storetest`): `type Factory func(t *testing.T) store.Store`, `func Run(t *testing.T, newStore Factory)`
- Produces (package `memory`): `func New() *Store` (implements `store.Store`)

- [ ] **Step 1: Write the interfaces and types** (definitions only, no logic)

```go
// internal/store/store.go

// Package store defines zeroauthy's storage interfaces. Every driver
// (memory, SQL, external plugin) implements Store and must pass the
// conformance suite in pkg/storetest.
//
// Drivers return copies: mutating a value passed to or returned from a
// driver never changes stored state.
package store

import (
	"context"
	"errors"
)

var (
	// ErrNotFound is returned when the requested entity does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when a create or update would violate a
	// uniqueness rule.
	ErrConflict = errors.New("store: conflict")
)

// Store aggregates the repositories of one storage backend.
type Store interface {
	Tenants() Tenants
	Ping(ctx context.Context) error
	Close() error
}

// Tenants stores tenants. Tenants are the only entities not scoped by a
// tenant ID.
type Tenants interface {
	// Create stores a new tenant. It returns ErrConflict if the ID, the
	// name, or any of the domains is already used by another tenant.
	Create(ctx context.Context, t *Tenant) error
	Get(ctx context.Context, id string) (*Tenant, error)
	GetByName(ctx context.Context, name string) (*Tenant, error)
	// GetByDomain finds the tenant that lists domain in Domains. Callers
	// pass normalized hosts (see tenant.NormalizeHost).
	GetByDomain(ctx context.Context, domain string) (*Tenant, error)
	// Update replaces the tenant with the same ID. It returns ErrNotFound
	// if absent and ErrConflict if the new name or a domain collides with
	// another tenant.
	Update(ctx context.Context, t *Tenant) error
	// List returns all tenants ordered by Name.
	List(ctx context.Context) ([]*Tenant, error)
}
```

```go
// internal/store/types.go
package store

import "time"

// Tenant is an isolated identity domain with its own clients, users,
// connections and signing keys.
type Tenant struct {
	ID string
	// Name is unique and also serves as the subdomain under
	// server.base_domain.
	Name         string
	FriendlyName string
	// Domains are normalized hosts that resolve to this tenant.
	Domains []string
	// DefaultAudience is used when a token request has no audience.
	DefaultAudience string
	CreatedAt       time.Time
}
```

- [ ] **Step 2: Write the conformance suite** (these are the failing tests for the memory driver)

```go
// pkg/storetest/storetest.go

// Package storetest is the conformance suite for store.Store drivers.
// A driver package calls Run from one of its tests; authors of external
// storage plugins can do the same.
package storetest

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Factory returns a new, empty store. Run closes it when the subtest ends.
type Factory func(t *testing.T) store.Store

// Run executes every conformance test against stores made by newStore.
func Run(t *testing.T, newStore Factory) {
	t.Run("Tenants", func(t *testing.T) { testTenants(t, newStore) })
}

func open(t *testing.T, newStore Factory) store.Store {
	t.Helper()
	s := newStore(t)
	t.Cleanup(func() { _ = s.Close() })
	return s
}
```

> Note: `pkg/storetest` imports `internal/store`. Go allows that within the same module. Third-party plugin authors will need the store types exported too; moving `internal/store` to `pkg/store` is a task in the plugin-host plan, not this one.

```go
// pkg/storetest/helpers.go
package storetest

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// ts returns a fixed-precision UTC timestamp so values round-trip through
// databases that store milliseconds.
func ts(offset time.Duration) time.Time {
	return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Add(offset)
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustErrIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want %v", err, target)
	}
}

func mustEqual(t *testing.T, got, want any) {
	t.Helper()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}
}
```

```go
// pkg/storetest/tenants.go
package storetest

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newTenant(name string) *store.Tenant {
	return &store.Tenant{
		ID:              "ten_" + name,
		Name:            name,
		FriendlyName:    strings.ToUpper(name),
		Domains:         []string{name + ".example.test"},
		DefaultAudience: "https://" + name + ".api.test",
		CreatedAt:       ts(0),
	}
}

func testTenants(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CreateAndGet", func(t *testing.T) {
		s := open(t, newStore)
		want := newTenant("acme")
		mustNoErr(t, s.Tenants().Create(ctx, want))

		got, err := s.Tenants().Get(ctx, want.ID)
		mustNoErr(t, err)
		mustEqual(t, got, want)

		got, err = s.Tenants().GetByName(ctx, "acme")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		got, err = s.Tenants().GetByDomain(ctx, "acme.example.test")
		mustNoErr(t, err)
		mustEqual(t, got, want)
	})

	t.Run("NotFound", func(t *testing.T) {
		s := open(t, newStore)
		_, err := s.Tenants().Get(ctx, "missing")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Tenants().GetByName(ctx, "missing")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Tenants().GetByDomain(ctx, "missing.example.test")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.Tenants().Update(ctx, newTenant("missing")), store.ErrNotFound)
	})

	t.Run("Conflicts", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))

		sameID := newTenant("other")
		sameID.ID = "ten_acme"
		mustErrIs(t, s.Tenants().Create(ctx, sameID), store.ErrConflict)

		sameName := newTenant("acme")
		sameName.ID = "ten_x"
		sameName.Domains = []string{"x.example.test"}
		mustErrIs(t, s.Tenants().Create(ctx, sameName), store.ErrConflict)

		sameDomain := newTenant("other")
		sameDomain.Domains = []string{"other.example.test", "acme.example.test"}
		mustErrIs(t, s.Tenants().Create(ctx, sameDomain), store.ErrConflict)
	})

	t.Run("Update", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("globex")))

		upd := newTenant("acme")
		upd.FriendlyName = "Acme Corp"
		upd.Domains = []string{"acme.example.test", "login.acme.test"}
		mustNoErr(t, s.Tenants().Update(ctx, upd))
		got, err := s.Tenants().GetByDomain(ctx, "login.acme.test")
		mustNoErr(t, err)
		mustEqual(t, got, upd)

		steal := newTenant("acme")
		steal.Domains = []string{"globex.example.test"}
		mustErrIs(t, s.Tenants().Update(ctx, steal), store.ErrConflict)
	})

	t.Run("ListOrderedByName", func(t *testing.T) {
		s := open(t, newStore)
		for _, n := range []string{"zeta", "acme", "mid"} {
			mustNoErr(t, s.Tenants().Create(ctx, newTenant(n)))
		}
		got, err := s.Tenants().List(ctx)
		mustNoErr(t, err)
		var names []string
		for _, tn := range got {
			names = append(names, tn.Name)
		}
		mustEqual(t, names, []string{"acme", "mid", "zeta"})
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newTenant("acme")
		mustNoErr(t, s.Tenants().Create(ctx, in))
		in.Domains[0] = "mutated.example.test"

		got, err := s.Tenants().Get(ctx, "ten_acme")
		mustNoErr(t, err)
		got.Domains[0] = "mutated-again.example.test"

		again, err := s.Tenants().Get(ctx, "ten_acme")
		mustNoErr(t, err)
		mustEqual(t, again.Domains, []string{"acme.example.test"})
	})
}
```

```go
// internal/store/memory/memory_test.go
package memory_test

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return memory.New() })
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go get github.com/google/go-cmp@v0.7.0 && go test ./internal/store/memory/`
Expected: FAIL: `undefined: memory.New`

- [ ] **Step 4: Implement the memory driver**

```go
// internal/store/memory/memory.go

// Package memory is an in-memory store.Store for tests and demos. All data
// is lost when the process exits.
package memory

import (
	"context"
	"sync"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Store is safe for concurrent use. One RWMutex guards all maps, so
// multi-entity operations such as key rotation are trivially atomic.
type Store struct {
	mu      sync.RWMutex
	tenants map[string]*store.Tenant // by ID
}

// New returns an empty store.
func New() *Store {
	return &Store{
		tenants: map[string]*store.Tenant{},
	}
}

func (s *Store) Tenants() store.Tenants         { return tenants{s} }
func (s *Store) Ping(context.Context) error     { return nil }
func (s *Store) Close() error                   { return nil }

var _ store.Store = (*Store)(nil)
```

```go
// internal/store/memory/clone.go
package memory

import (
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func cloneTenant(t *store.Tenant) *store.Tenant {
	c := *t
	c.Domains = slices.Clone(t.Domains)
	return &c
}
```

```go
// internal/store/memory/tenants.go
package memory

import (
	"context"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type tenants struct{ s *Store }

func (r tenants) Create(_ context.Context, t *store.Tenant) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.tenants[t.ID]; ok || r.collides(t) {
		return store.ErrConflict
	}
	r.s.tenants[t.ID] = cloneTenant(t)
	return nil
}

func (r tenants) Get(_ context.Context, id string) (*store.Tenant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	t, ok := r.s.tenants[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneTenant(t), nil
}

func (r tenants) GetByName(_ context.Context, name string) (*store.Tenant, error) {
	return r.find(func(t *store.Tenant) bool { return t.Name == name })
}

func (r tenants) GetByDomain(_ context.Context, domain string) (*store.Tenant, error) {
	return r.find(func(t *store.Tenant) bool { return slices.Contains(t.Domains, domain) })
}

func (r tenants) Update(_ context.Context, t *store.Tenant) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.tenants[t.ID]; !ok {
		return store.ErrNotFound
	}
	if r.collides(t) {
		return store.ErrConflict
	}
	r.s.tenants[t.ID] = cloneTenant(t)
	return nil
}

func (r tenants) List(context.Context) ([]*store.Tenant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]*store.Tenant, 0, len(r.s.tenants))
	for _, t := range r.s.tenants {
		out = append(out, cloneTenant(t))
	}
	slices.SortFunc(out, func(a, b *store.Tenant) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (r tenants) find(match func(*store.Tenant) bool) (*store.Tenant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, t := range r.s.tenants {
		if match(t) {
			return cloneTenant(t), nil
		}
	}
	return nil, store.ErrNotFound
}

// collides reports whether t's name or domains are used by another tenant.
// The caller holds the lock.
func (r tenants) collides(t *store.Tenant) bool {
	for id, o := range r.s.tenants {
		if id == t.ID {
			continue
		}
		if o.Name == t.Name {
			return true
		}
		for _, d := range t.Domains {
			if slices.Contains(o.Domains, d) {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `gofmt -l . ; go test ./internal/store/... ./pkg/...`
Expected: `gofmt` prints nothing, and `ok  .../internal/store/memory`.

- [ ] **Step 6: Commit**

```bash
go mod tidy
git add go.mod go.sum internal/store pkg/storetest
git commit -m "feat(store): add tenant store interface, memory driver, conformance suite"
```

---

### Task 3: Clients, resource servers, client grants

**Files:**
- Modify: `internal/store/store.go` (add accessors and interfaces), `internal/store/types.go` (add types)
- Modify: `pkg/storetest/storetest.go` (register new suites), `internal/store/memory/memory.go`, `internal/store/memory/clone.go`
- Create: `pkg/storetest/clients.go`, `pkg/storetest/resource_servers.go`, `pkg/storetest/client_grants.go`
- Create: `internal/store/memory/clients.go`, `internal/store/memory/resource_servers.go`, `internal/store/memory/client_grants.go`

**Interfaces:**
- Consumes: Task 2's `store.Store`, `ErrNotFound`, `ErrConflict`, `storetest.open/ts/mustEqual/mustErrIs/mustNoErr`.
- Produces (package `store`):
  - `Store.Clients() Clients`, `Store.ResourceServers() ResourceServers`, `Store.ClientGrants() ClientGrants`
  - Types `Client`, `ClientSecret`, `AppType` (with constants `AppTypeSPA`, `AppTypeRegularWeb`, `AppTypeNative`, `AppTypeNonInteractive`), auth-method constants `AuthMethodNone`, `AuthMethodClientSecretPost`, `AuthMethodClientSecretBasic`, and `ResourceServer`, `Scope`, `ClientGrant` (fields below).

- [ ] **Step 1: Add the types and interfaces**

Append to `internal/store/types.go`:

```go
// AppType is the kind of application a client represents.
type AppType string

const (
	AppTypeSPA            AppType = "spa"
	AppTypeRegularWeb     AppType = "regular_web"
	AppTypeNative         AppType = "native"
	AppTypeNonInteractive AppType = "non_interactive"
)

// Token endpoint client authentication methods (RFC 7591 names).
const (
	AuthMethodNone              = "none"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodClientSecretBasic = "client_secret_basic"
)

// ClientSecret is one credential of a confidential client. Several can be
// valid at once to allow rotation.
type ClientSecret struct {
	Hash      string // argon2id PHC string, see internal/secrets
	CreatedAt time.Time
	ExpiresAt *time.Time // nil means the secret does not expire
}

// Client is an application registered in a tenant.
type Client struct {
	TenantID                string
	ClientID                string
	Name                    string
	AppType                 AppType
	Secrets                 []ClientSecret
	TokenEndpointAuthMethod string
	GrantTypes              []string
	Callbacks               []string
	AllowedLogoutURLs       []string
	WebOrigins              []string
	AllowedOrigins          []string
	CreatedAt               time.Time
}

// Scope is a permission defined by a resource server.
type Scope struct {
	Value       string
	Description string
}

// ResourceServer is an API that access tokens are issued for. Identifier
// is the value of the audience parameter and aud claim.
type ResourceServer struct {
	TenantID           string
	ID                 string
	Identifier         string
	Name               string
	Scopes             []Scope
	SigningAlg         string
	TokenLifetime      int // seconds; 0 means the default
	AllowOfflineAccess bool
	CreatedAt          time.Time
}

// ClientGrant authorizes a client to obtain client_credentials tokens for
// an audience, limited to Scopes.
type ClientGrant struct {
	TenantID  string
	ID        string
	ClientID  string
	Audience  string
	Scopes    []string
	CreatedAt time.Time
}
```

Add to the `Store` interface in `internal/store/store.go`:

```go
	Clients() Clients
	ResourceServers() ResourceServers
	ClientGrants() ClientGrants
```

Then append the interfaces:

```go
// Clients stores applications, keyed by (TenantID, ClientID).
type Clients interface {
	// Create returns ErrConflict if the client ID exists in the tenant.
	Create(ctx context.Context, c *Client) error
	Get(ctx context.Context, tenantID, clientID string) (*Client, error)
	// Update returns ErrNotFound if the client does not exist.
	Update(ctx context.Context, c *Client) error
	// Delete returns ErrNotFound if the client does not exist.
	Delete(ctx context.Context, tenantID, clientID string) error
}

// ResourceServers stores APIs, keyed by (TenantID, ID). Identifier is
// unique within a tenant.
type ResourceServers interface {
	// Create returns ErrConflict if the ID or Identifier exists in the tenant.
	Create(ctx context.Context, rs *ResourceServer) error
	Get(ctx context.Context, tenantID, id string) (*ResourceServer, error)
	GetByIdentifier(ctx context.Context, tenantID, identifier string) (*ResourceServer, error)
	// Update returns ErrNotFound if absent and ErrConflict if the new
	// Identifier is used by another resource server in the tenant.
	Update(ctx context.Context, rs *ResourceServer) error
	Delete(ctx context.Context, tenantID, id string) error
}

// ClientGrants stores client_credentials authorizations, keyed by
// (TenantID, ID). (ClientID, Audience) is unique within a tenant.
type ClientGrants interface {
	// Create returns ErrConflict if the ID or (ClientID, Audience) exists.
	Create(ctx context.Context, g *ClientGrant) error
	Find(ctx context.Context, tenantID, clientID, audience string) (*ClientGrant, error)
	// Update replaces the grant with the same ID. ClientID and Audience
	// must not change; drivers return ErrConflict if they do.
	Update(ctx context.Context, g *ClientGrant) error
	Delete(ctx context.Context, tenantID, id string) error
}
```

- [ ] **Step 2: Write the conformance tests**

In `pkg/storetest/storetest.go`, add to `Run`:

```go
	t.Run("Clients", func(t *testing.T) { testClients(t, newStore) })
	t.Run("ResourceServers", func(t *testing.T) { testResourceServers(t, newStore) })
	t.Run("ClientGrants", func(t *testing.T) { testClientGrants(t, newStore) })
```

```go
// pkg/storetest/clients.go
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newClient(tenantID, clientID string) *store.Client {
	exp := ts(48 * time.Hour)
	return &store.Client{
		TenantID: tenantID,
		ClientID: clientID,
		Name:     "App " + clientID,
		AppType:  store.AppTypeNonInteractive,
		Secrets: []store.ClientSecret{
			{Hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA", CreatedAt: ts(0)},
			{Hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdDI$aGFzaDI", CreatedAt: ts(time.Hour), ExpiresAt: &exp},
		},
		TokenEndpointAuthMethod: store.AuthMethodClientSecretPost,
		GrantTypes:              []string{"client_credentials"},
		Callbacks:               []string{"https://app.test/callback"},
		AllowedLogoutURLs:       []string{"https://app.test/"},
		WebOrigins:              []string{"https://app.test"},
		AllowedOrigins:          []string{"https://app.test"},
		CreatedAt:               ts(0),
	}
}

func testClients(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		s := open(t, newStore)
		want := newClient("ten_a", "c1")
		mustNoErr(t, s.Clients().Create(ctx, want))
		mustErrIs(t, s.Clients().Create(ctx, newClient("ten_a", "c1")), store.ErrConflict)

		got, err := s.Clients().Get(ctx, "ten_a", "c1")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		want.Name = "Renamed"
		want.Secrets = want.Secrets[:1]
		mustNoErr(t, s.Clients().Update(ctx, want))
		got, err = s.Clients().Get(ctx, "ten_a", "c1")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		mustNoErr(t, s.Clients().Delete(ctx, "ten_a", "c1"))
		_, err = s.Clients().Get(ctx, "ten_a", "c1")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.Clients().Delete(ctx, "ten_a", "c1"), store.ErrNotFound)
		mustErrIs(t, s.Clients().Update(ctx, want), store.ErrNotFound)
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		s := open(t, newStore)
		a := newClient("ten_a", "same-id")
		b := newClient("ten_b", "same-id")
		b.Name = "Tenant B app"
		mustNoErr(t, s.Clients().Create(ctx, a))
		mustNoErr(t, s.Clients().Create(ctx, b))

		got, err := s.Clients().Get(ctx, "ten_b", "same-id")
		mustNoErr(t, err)
		mustEqual(t, got.Name, "Tenant B app")
		_, err = s.Clients().Get(ctx, "ten_c", "same-id")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newClient("ten_a", "c1")
		mustNoErr(t, s.Clients().Create(ctx, in))
		*in.Secrets[1].ExpiresAt = ts(0)
		in.GrantTypes[0] = "mutated"

		got, err := s.Clients().Get(ctx, "ten_a", "c1")
		mustNoErr(t, err)
		mustEqual(t, got, newClient("ten_a", "c1"))
	})
}
```

```go
// pkg/storetest/resource_servers.go
package storetest

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newResourceServer(tenantID, id, identifier string) *store.ResourceServer {
	return &store.ResourceServer{
		TenantID:   tenantID,
		ID:         id,
		Identifier: identifier,
		Name:       "API " + id,
		Scopes: []store.Scope{
			{Value: "read:things", Description: "Read things"},
			{Value: "write:things", Description: "Write things"},
		},
		SigningAlg:         "RS256",
		TokenLifetime:      3600,
		AllowOfflineAccess: true,
		CreatedAt:          ts(0),
	}
}

func testResourceServers(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		s := open(t, newStore)
		want := newResourceServer("ten_a", "rs1", "https://api.test")
		mustNoErr(t, s.ResourceServers().Create(ctx, want))

		got, err := s.ResourceServers().Get(ctx, "ten_a", "rs1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		got, err = s.ResourceServers().GetByIdentifier(ctx, "ten_a", "https://api.test")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		want.Scopes = want.Scopes[:1]
		want.Identifier = "https://api2.test"
		mustNoErr(t, s.ResourceServers().Update(ctx, want))
		_, err = s.ResourceServers().GetByIdentifier(ctx, "ten_a", "https://api.test")
		mustErrIs(t, err, store.ErrNotFound)
		got, err = s.ResourceServers().GetByIdentifier(ctx, "ten_a", "https://api2.test")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		mustNoErr(t, s.ResourceServers().Delete(ctx, "ten_a", "rs1"))
		_, err = s.ResourceServers().Get(ctx, "ten_a", "rs1")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.ResourceServers().Delete(ctx, "ten_a", "rs1"), store.ErrNotFound)
		mustErrIs(t, s.ResourceServers().Update(ctx, want), store.ErrNotFound)
	})

	t.Run("IdentifierUniquePerTenant", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_a", "rs1", "https://api.test")))
		mustErrIs(t, s.ResourceServers().Create(ctx, newResourceServer("ten_a", "rs2", "https://api.test")), store.ErrConflict)
		mustErrIs(t, s.ResourceServers().Create(ctx, newResourceServer("ten_a", "rs1", "https://other.test")), store.ErrConflict)
		// Same identifier in another tenant is fine.
		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_b", "rs1", "https://api.test")))

		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_a", "rs3", "https://three.test")))
		steal := newResourceServer("ten_a", "rs3", "https://api.test")
		mustErrIs(t, s.ResourceServers().Update(ctx, steal), store.ErrConflict)

		_, err := s.ResourceServers().GetByIdentifier(ctx, "ten_c", "https://api.test")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newResourceServer("ten_a", "rs1", "https://api.test")
		mustNoErr(t, s.ResourceServers().Create(ctx, in))
		in.Scopes[0].Value = "mutated"
		got, err := s.ResourceServers().Get(ctx, "ten_a", "rs1")
		mustNoErr(t, err)
		mustEqual(t, got.Scopes[0].Value, "read:things")
	})
}
```

```go
// pkg/storetest/client_grants.go
package storetest

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newClientGrant(tenantID, id, clientID, audience string) *store.ClientGrant {
	return &store.ClientGrant{
		TenantID:  tenantID,
		ID:        id,
		ClientID:  clientID,
		Audience:  audience,
		Scopes:    []string{"read:things"},
		CreatedAt: ts(0),
	}
}

func testClientGrants(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		s := open(t, newStore)
		want := newClientGrant("ten_a", "cg1", "c1", "https://api.test")
		mustNoErr(t, s.ClientGrants().Create(ctx, want))

		got, err := s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		want.Scopes = []string{"read:things", "write:things"}
		mustNoErr(t, s.ClientGrants().Update(ctx, want))
		got, err = s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		moved := *want
		moved.Audience = "https://other.test"
		mustErrIs(t, s.ClientGrants().Update(ctx, &moved), store.ErrConflict)

		mustNoErr(t, s.ClientGrants().Delete(ctx, "ten_a", "cg1"))
		_, err = s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.ClientGrants().Delete(ctx, "ten_a", "cg1"), store.ErrNotFound)
		mustErrIs(t, s.ClientGrants().Update(ctx, want), store.ErrNotFound)
	})

	t.Run("Uniqueness", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.ClientGrants().Create(ctx, newClientGrant("ten_a", "cg1", "c1", "https://api.test")))
		mustErrIs(t, s.ClientGrants().Create(ctx, newClientGrant("ten_a", "cg2", "c1", "https://api.test")), store.ErrConflict)
		mustErrIs(t, s.ClientGrants().Create(ctx, newClientGrant("ten_a", "cg1", "c2", "https://api.test")), store.ErrConflict)
		mustNoErr(t, s.ClientGrants().Create(ctx, newClientGrant("ten_b", "cg1", "c1", "https://api.test")))
		_, err := s.ClientGrants().Find(ctx, "ten_c", "c1", "https://api.test")
		mustErrIs(t, err, store.ErrNotFound)
	})
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/store/memory/`
Expected: FAIL. Compile errors: `*Store does not implement store.Store (missing method ClientGrants)`.

- [ ] **Step 4: Implement the memory repositories**

In `internal/store/memory/memory.go`, add a composite key type and maps:

```go
// key addresses a tenant-scoped entity.
type key struct{ tenant, id string }

type Store struct {
	mu              sync.RWMutex
	tenants         map[string]*store.Tenant      // by ID
	clients         map[key]*store.Client         // by (tenant, client ID)
	resourceServers map[key]*store.ResourceServer // by (tenant, ID)
	clientGrants    map[key]*store.ClientGrant    // by (tenant, ID)
}

func New() *Store {
	return &Store{
		tenants:         map[string]*store.Tenant{},
		clients:         map[key]*store.Client{},
		resourceServers: map[key]*store.ResourceServer{},
		clientGrants:    map[key]*store.ClientGrant{},
	}
}

func (s *Store) Clients() store.Clients                 { return clients{s} }
func (s *Store) ResourceServers() store.ResourceServers { return resourceServers{s} }
func (s *Store) ClientGrants() store.ClientGrants       { return clientGrants{s} }
```

Append to `clone.go`:

```go
func cloneClient(c *store.Client) *store.Client {
	out := *c
	out.Secrets = make([]store.ClientSecret, len(c.Secrets))
	for i, sec := range c.Secrets {
		out.Secrets[i] = sec
		if sec.ExpiresAt != nil {
			exp := *sec.ExpiresAt
			out.Secrets[i].ExpiresAt = &exp
		}
	}
	if c.Secrets == nil {
		out.Secrets = nil
	}
	out.GrantTypes = slices.Clone(c.GrantTypes)
	out.Callbacks = slices.Clone(c.Callbacks)
	out.AllowedLogoutURLs = slices.Clone(c.AllowedLogoutURLs)
	out.WebOrigins = slices.Clone(c.WebOrigins)
	out.AllowedOrigins = slices.Clone(c.AllowedOrigins)
	return &out
}

func cloneResourceServer(rs *store.ResourceServer) *store.ResourceServer {
	out := *rs
	out.Scopes = slices.Clone(rs.Scopes)
	return &out
}

func cloneClientGrant(g *store.ClientGrant) *store.ClientGrant {
	out := *g
	out.Scopes = slices.Clone(g.Scopes)
	return &out
}
```

```go
// internal/store/memory/clients.go
package memory

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type clients struct{ s *Store }

func (r clients) Create(_ context.Context, c *store.Client) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{c.TenantID, c.ClientID}
	if _, ok := r.s.clients[k]; ok {
		return store.ErrConflict
	}
	r.s.clients[k] = cloneClient(c)
	return nil
}

func (r clients) Get(_ context.Context, tenantID, clientID string) (*store.Client, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	c, ok := r.s.clients[key{tenantID, clientID}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneClient(c), nil
}

func (r clients) Update(_ context.Context, c *store.Client) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{c.TenantID, c.ClientID}
	if _, ok := r.s.clients[k]; !ok {
		return store.ErrNotFound
	}
	r.s.clients[k] = cloneClient(c)
	return nil
}

func (r clients) Delete(_ context.Context, tenantID, clientID string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{tenantID, clientID}
	if _, ok := r.s.clients[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.clients, k)
	return nil
}
```

```go
// internal/store/memory/resource_servers.go
package memory

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type resourceServers struct{ s *Store }

func (r resourceServers) Create(_ context.Context, rs *store.ResourceServer) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{rs.TenantID, rs.ID}
	if _, ok := r.s.resourceServers[k]; ok || r.identifierTaken(rs) {
		return store.ErrConflict
	}
	r.s.resourceServers[k] = cloneResourceServer(rs)
	return nil
}

func (r resourceServers) Get(_ context.Context, tenantID, id string) (*store.ResourceServer, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	rs, ok := r.s.resourceServers[key{tenantID, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneResourceServer(rs), nil
}

func (r resourceServers) GetByIdentifier(_ context.Context, tenantID, identifier string) (*store.ResourceServer, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for k, rs := range r.s.resourceServers {
		if k.tenant == tenantID && rs.Identifier == identifier {
			return cloneResourceServer(rs), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r resourceServers) Update(_ context.Context, rs *store.ResourceServer) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{rs.TenantID, rs.ID}
	if _, ok := r.s.resourceServers[k]; !ok {
		return store.ErrNotFound
	}
	if r.identifierTaken(rs) {
		return store.ErrConflict
	}
	r.s.resourceServers[k] = cloneResourceServer(rs)
	return nil
}

func (r resourceServers) Delete(_ context.Context, tenantID, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{tenantID, id}
	if _, ok := r.s.resourceServers[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.resourceServers, k)
	return nil
}

// identifierTaken reports whether another resource server in the tenant
// uses rs.Identifier. The caller holds the lock.
func (r resourceServers) identifierTaken(rs *store.ResourceServer) bool {
	for k, o := range r.s.resourceServers {
		if k.tenant == rs.TenantID && k.id != rs.ID && o.Identifier == rs.Identifier {
			return true
		}
	}
	return false
}
```

```go
// internal/store/memory/client_grants.go
package memory

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type clientGrants struct{ s *Store }

func (r clientGrants) Create(_ context.Context, g *store.ClientGrant) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{g.TenantID, g.ID}
	if _, ok := r.s.clientGrants[k]; ok {
		return store.ErrConflict
	}
	if _, ok := r.find(g.TenantID, g.ClientID, g.Audience); ok {
		return store.ErrConflict
	}
	r.s.clientGrants[k] = cloneClientGrant(g)
	return nil
}

func (r clientGrants) Find(_ context.Context, tenantID, clientID, audience string) (*store.ClientGrant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	g, ok := r.find(tenantID, clientID, audience)
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneClientGrant(g), nil
}

func (r clientGrants) Update(_ context.Context, g *store.ClientGrant) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{g.TenantID, g.ID}
	old, ok := r.s.clientGrants[k]
	if !ok {
		return store.ErrNotFound
	}
	if old.ClientID != g.ClientID || old.Audience != g.Audience {
		return store.ErrConflict
	}
	r.s.clientGrants[k] = cloneClientGrant(g)
	return nil
}

func (r clientGrants) Delete(_ context.Context, tenantID, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{tenantID, id}
	if _, ok := r.s.clientGrants[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.clientGrants, k)
	return nil
}

// find is called with the lock held.
func (r clientGrants) find(tenantID, clientID, audience string) (*store.ClientGrant, bool) {
	for k, g := range r.s.clientGrants {
		if k.tenant == tenantID && g.ClientID == clientID && g.Audience == audience {
			return g, true
		}
	}
	return nil, false
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/store/... && go vet ./...`
Expected: `ok  .../internal/store/memory`

- [ ] **Step 6: Commit**

```bash
git add internal/store pkg/storetest
git commit -m "feat(store): add clients, resource servers, client grants"
```

---

### Task 4: Signing key storage with atomic rotation

**Files:**
- Modify: `internal/store/store.go`, `internal/store/types.go`, `pkg/storetest/storetest.go`, `internal/store/memory/memory.go`, `internal/store/memory/clone.go`
- Create: `pkg/storetest/signing_keys.go`, `internal/store/memory/signing_keys.go`

**Interfaces:**
- Produces (package `store`):
  - `Store.SigningKeys() SigningKeys`
  - `type KeyStatus string` with constants `KeyNext`, `KeyCurrent`, `KeyPrevious`, `KeyRevoked`
  - `type SigningKey struct { TenantID, KID, Alg string; Status KeyStatus; PrivateKey []byte; PublicJWK []byte; CreatedAt time.Time }`
  - `SigningKeys.Create(ctx, *SigningKey) error`, `List(ctx, tenantID) ([]*SigningKey, error)`, `Rotate(ctx, tenantID string, next *SigningKey) error`

- [ ] **Step 1: Add the types and interface**

Append to `internal/store/types.go`:

```go
// KeyStatus is a signing key's place in the rotation lifecycle:
// next → current → previous → revoked.
type KeyStatus string

const (
	KeyNext     KeyStatus = "next"     // published in JWKS, not yet signing
	KeyCurrent  KeyStatus = "current"  // signs new tokens
	KeyPrevious KeyStatus = "previous" // published so recent tokens still verify
	KeyRevoked  KeyStatus = "revoked"  // kept for audit, not published
)

// SigningKey is a tenant's token signing key pair.
type SigningKey struct {
	TenantID string
	KID      string
	Alg      string
	Status   KeyStatus
	// PrivateKey is the envelope-encrypted private key (see internal/keys).
	// Drivers store it opaquely and never see plaintext key material.
	PrivateKey []byte
	// PublicJWK is the public key as a JSON Web Key.
	PublicJWK []byte
	CreatedAt time.Time
}
```

In `internal/store/store.go`, add `SigningKeys() SigningKeys` to `Store` and append:

```go
// SigningKeys stores signing keys, keyed by (TenantID, KID).
type SigningKeys interface {
	// Create returns ErrConflict if the KID exists in the tenant.
	Create(ctx context.Context, k *SigningKey) error
	// List returns all of a tenant's keys, every status, ordered by
	// CreatedAt then KID.
	List(ctx context.Context, tenantID string) ([]*SigningKey, error)
	// Rotate atomically moves previous→revoked, current→previous and
	// next→current, then stores next, which must have Status KeyNext.
	// If the tenant has no next key it returns ErrNotFound and changes
	// nothing. A duplicate KID returns ErrConflict and changes nothing.
	Rotate(ctx context.Context, tenantID string, next *SigningKey) error
}
```

- [ ] **Step 2: Write the conformance tests**

Add to `Run`: `t.Run("SigningKeys", func(t *testing.T) { testSigningKeys(t, newStore) })`

```go
// pkg/storetest/signing_keys.go
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newSigningKey(tenantID, kid string, status store.KeyStatus, age time.Duration) *store.SigningKey {
	return &store.SigningKey{
		TenantID:   tenantID,
		KID:        kid,
		Alg:        "RS256",
		Status:     status,
		PrivateKey: []byte("sealed-" + kid),
		PublicJWK:  []byte(`{"kid":"` + kid + `"}`),
		CreatedAt:  ts(age),
	}
}

func statuses(t *testing.T, s store.Store, tenantID string) map[string]store.KeyStatus {
	t.Helper()
	ks, err := s.SigningKeys().List(context.Background(), tenantID)
	mustNoErr(t, err)
	out := map[string]store.KeyStatus{}
	for _, k := range ks {
		out[k.KID] = k.Status
	}
	return out
}

func testSigningKeys(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CreateList", func(t *testing.T) {
		s := open(t, newStore)
		k2 := newSigningKey("ten_a", "k2", store.KeyNext, time.Hour)
		k1 := newSigningKey("ten_a", "k1", store.KeyCurrent, 0)
		mustNoErr(t, s.SigningKeys().Create(ctx, k2))
		mustNoErr(t, s.SigningKeys().Create(ctx, k1))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_b", "k1", store.KeyCurrent, 0)))
		mustErrIs(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyCurrent, 0)), store.ErrConflict)

		got, err := s.SigningKeys().List(ctx, "ten_a")
		mustNoErr(t, err)
		mustEqual(t, got, []*store.SigningKey{k1, k2})

		got, err = s.SigningKeys().List(ctx, "ten_none")
		mustNoErr(t, err)
		mustEqual(t, len(got), 0)
	})

	t.Run("Rotate", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k2", store.KeyNext, time.Hour)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_b", "b1", store.KeyCurrent, 0)))

		mustNoErr(t, s.SigningKeys().Rotate(ctx, "ten_a", newSigningKey("ten_a", "k3", store.KeyNext, 2*time.Hour)))
		mustEqual(t, statuses(t, s, "ten_a"), map[string]store.KeyStatus{
			"k1": store.KeyPrevious, "k2": store.KeyCurrent, "k3": store.KeyNext,
		})

		mustNoErr(t, s.SigningKeys().Rotate(ctx, "ten_a", newSigningKey("ten_a", "k4", store.KeyNext, 3*time.Hour)))
		mustEqual(t, statuses(t, s, "ten_a"), map[string]store.KeyStatus{
			"k1": store.KeyRevoked, "k2": store.KeyPrevious, "k3": store.KeyCurrent, "k4": store.KeyNext,
		})

		// Other tenants are untouched.
		mustEqual(t, statuses(t, s, "ten_b"), map[string]store.KeyStatus{"b1": store.KeyCurrent})
	})

	t.Run("RotateWithoutNextChangesNothing", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyCurrent, 0)))
		err := s.SigningKeys().Rotate(ctx, "ten_a", newSigningKey("ten_a", "k2", store.KeyNext, time.Hour))
		mustErrIs(t, err, store.ErrNotFound)
		mustEqual(t, statuses(t, s, "ten_a"), map[string]store.KeyStatus{"k1": store.KeyCurrent})
	})

	t.Run("RotateDuplicateKIDChangesNothing", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k2", store.KeyNext, time.Hour)))
		err := s.SigningKeys().Rotate(ctx, "ten_a", newSigningKey("ten_a", "k1", store.KeyNext, 2*time.Hour))
		mustErrIs(t, err, store.ErrConflict)
		mustEqual(t, statuses(t, s, "ten_a"), map[string]store.KeyStatus{"k1": store.KeyCurrent, "k2": store.KeyNext})
	})
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/store/memory/`
Expected: FAIL with `missing method SigningKeys`.

- [ ] **Step 4: Implement**

In `memory.go`, add the field `signingKeys map[key]*store.SigningKey // by (tenant, KID)`, initialize it in `New`, and add:

```go
func (s *Store) SigningKeys() store.SigningKeys { return signingKeys{s} }
```

Append to `clone.go`:

```go
func cloneSigningKey(k *store.SigningKey) *store.SigningKey {
	out := *k
	out.PrivateKey = slices.Clone(k.PrivateKey)
	out.PublicJWK = slices.Clone(k.PublicJWK)
	return &out
}
```

```go
// internal/store/memory/signing_keys.go
package memory

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type signingKeys struct{ s *Store }

func (r signingKeys) Create(_ context.Context, k *store.SigningKey) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	kk := key{k.TenantID, k.KID}
	if _, ok := r.s.signingKeys[kk]; ok {
		return store.ErrConflict
	}
	r.s.signingKeys[kk] = cloneSigningKey(k)
	return nil
}

func (r signingKeys) List(_ context.Context, tenantID string) ([]*store.SigningKey, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []*store.SigningKey
	for k, sk := range r.s.signingKeys {
		if k.tenant == tenantID {
			out = append(out, cloneSigningKey(sk))
		}
	}
	slices.SortFunc(out, func(a, b *store.SigningKey) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.KID, b.KID)
	})
	return out, nil
}

func (r signingKeys) Rotate(_ context.Context, tenantID string, next *store.SigningKey) error {
	if next.Status != store.KeyNext || next.TenantID != tenantID {
		return fmt.Errorf("memory: rotate needs a %q key for tenant %q", store.KeyNext, tenantID)
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.signingKeys[key{tenantID, next.KID}]; ok {
		return store.ErrConflict
	}
	hasNext := false
	for k, sk := range r.s.signingKeys {
		if k.tenant == tenantID && sk.Status == store.KeyNext {
			hasNext = true
		}
	}
	if !hasNext {
		return store.ErrNotFound
	}
	promote := map[store.KeyStatus]store.KeyStatus{
		store.KeyPrevious: store.KeyRevoked,
		store.KeyCurrent:  store.KeyPrevious,
		store.KeyNext:     store.KeyCurrent,
	}
	for k, sk := range r.s.signingKeys {
		if k.tenant != tenantID {
			continue
		}
		if to, ok := promote[sk.Status]; ok {
			sk.Status = to
		}
	}
	r.s.signingKeys[key{tenantID, next.KID}] = cloneSigningKey(next)
	return nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/store/...`
Expected: `ok`

- [ ] **Step 6: Commit**

```bash
git add internal/store pkg/storetest
git commit -m "feat(store): add signing key storage with atomic rotation"
```

---

### Task 5: Secret hashing and random identifiers

**Files:**
- Create: `internal/secrets/secrets.go`, `internal/secrets/secrets_test.go`

**Interfaces:**
- Produces (package `secrets`): `func Hash(secret string) (string, error)`, `func Verify(encoded, secret string) (bool, error)`, `func RandomString(n int) string`

- [ ] **Step 1: Write the failing test**

```go
// internal/secrets/secrets_test.go
package secrets

import (
	"strings"
	"testing"
)

func TestHashVerify(t *testing.T) {
	h, err := Hash("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected encoding %q", h)
	}
	ok, err := Verify(h, "s3cret")
	if err != nil || !ok {
		t.Fatalf("Verify(correct) = %v, %v", ok, err)
	}
	ok, err = Verify(h, "wrong")
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v", ok, err)
	}
	h2, _ := Hash("s3cret")
	if h == h2 {
		t.Fatal("two hashes of the same secret are identical; salt not random")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, enc := range []string{
		"",
		"plaintext",
		"$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=18$m=19456,t=2,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=x,t=2,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=19456,t=2,p=1$!!!$aGFzaA",
	} {
		if _, err := Verify(enc, "x"); err == nil {
			t.Errorf("Verify(%q) returned no error", enc)
		}
	}
}

func TestRandomString(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		s := RandomString(32)
		if len(s) != 32 {
			t.Fatalf("len = %d", len(s))
		}
		for _, r := range s {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("unexpected rune %q in %q", r, s)
			}
		}
		if seen[s] {
			t.Fatalf("duplicate %q", s)
		}
		seen[s] = true
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/secrets/`
Expected: FAIL: `undefined: Hash`

- [ ] **Step 3: Implement**

```go
// internal/secrets/secrets.go

// Package secrets hashes credentials with argon2id and generates random
// identifiers.
package secrets

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parameters follow the OWASP minimum recommendation for argon2id.
const (
	memoryKiB = 19456
	timeCost  = 2
	threads   = 1
	saltLen   = 16
	keyLen    = 32
)

var errMalformed = errors.New("secrets: malformed argon2id hash")

// Hash returns an argon2id PHC string for secret.
func Hash(secret string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(secret), salt, timeCost, memoryKiB, threads, keyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, timeCost, threads, b64.EncodeToString(salt), b64.EncodeToString(sum)), nil
}

// Verify reports whether secret matches the PHC string encoded. It uses the
// parameters stored in encoded, so hashes made with older parameters still
// verify.
func Verify(encoded, secret string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, errMalformed
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errMalformed
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, errMalformed
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errMalformed
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, errMalformed
	}
	got := argon2.IDKey([]byte(secret), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// RandomString returns n characters drawn uniformly from [A-Za-z0-9] using
// crypto/rand. It panics if the system random source fails.
func RandomString(n int) string {
	const max = 256 - 256%len(alphabet) // reject bytes that would bias the result
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			panic("secrets: crypto/rand failed: " + err.Error())
		}
		for _, b := range buf {
			if int(b) < max && len(out) < n {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go get golang.org/x/crypto@v0.58.0 && go test ./internal/secrets/`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
go mod tidy
git add go.mod go.sum internal/secrets
git commit -m "feat(secrets): add argon2id hashing and random identifiers"
```

---

### Task 6: Configuration

**Files:**
- Create: `internal/config/config.go`, `internal/config/config_test.go`

**Interfaces:**
- Produces (package `config`):
  - `type Config struct { Server Server; Storage Storage; Security Security; Log Log; Seed string }` (fields below)
  - `func Load(path string, environ []string) (*Config, error)`
  - `func (s Security) MasterKeyBytes() ([]byte, error)`: returns `nil, nil` when neither key setting is set

- [ ] **Step 1: Write the failing test**

```go
// internal/config/config_test.go
package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFileAndEnv(t *testing.T) {
	path := writeFile(t, "zeroauthy.yaml", `
server:
  listen: ":9000"
  base_domain: auth.example.test
storage:
  dsn: memory://
seed: /etc/zeroauthy/seed.yaml
`)
	cfg, err := Load(path, []string{
		"ZEROAUTHY_SERVER__LISTEN=:9100",
		"ZEROAUTHY_SERVER__TRUST_PROXY_HEADERS=true",
		"ZEROAUTHY_LOG__LEVEL=debug",
		"UNRELATED=1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != ":9100" {
		t.Errorf("listen = %q, want env override :9100", cfg.Server.Listen)
	}
	if cfg.Server.BaseDomain != "auth.example.test" || cfg.Storage.DSN != "memory://" || cfg.Seed != "/etc/zeroauthy/seed.yaml" {
		t.Errorf("file values not loaded: %+v", cfg)
	}
	if !cfg.Server.TrustProxyHeaders {
		t.Error("bool env override not applied")
	}
	if cfg.Log.Level != "debug" || cfg.Log.Format != "json" {
		t.Errorf("log = %+v, want level debug (env) and format json (default)", cfg.Log)
	}
}

func TestLoadEnvOnly(t *testing.T) {
	cfg, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("default listen = %q", cfg.Server.Listen)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]struct {
		file string
		env  []string
		want string
	}{
		"missing dsn":       {env: nil, want: "storage.dsn is required"},
		"half tls":          {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__TLS_CERT_FILE=/c.pem"}, want: "tls_cert_file and server.tls_key_file"},
		"bad level":         {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_LOG__LEVEL=loud"}, want: "log.level"},
		"bad format":        {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_LOG__FORMAT=xml"}, want: "log.format"},
		"both master keys":  {env: []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SECURITY__MASTER_KEY=x", "ZEROAUTHY_SECURITY__MASTER_KEY_FILE=/k"}, want: "only one of"},
		"unknown file":      {file: "/nonexistent/zeroauthy.yaml", want: "no such file"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(tc.file, tc.env)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestMasterKeyBytes(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc := base64.StdEncoding.EncodeToString(key)

	got, err := Security{MasterKey: enc}.MasterKeyBytes()
	if err != nil || string(got) != string(key) {
		t.Fatalf("inline key: %v %v", got, err)
	}

	file := writeFile(t, "master.key", enc+"\n")
	got, err = Security{MasterKeyFile: file}.MasterKeyBytes()
	if err != nil || string(got) != string(key) {
		t.Fatalf("file key: %v %v", got, err)
	}

	got, err = Security{}.MasterKeyBytes()
	if err != nil || got != nil {
		t.Fatalf("unset key: %v %v", got, err)
	}

	if _, err := (Security{MasterKey: base64.StdEncoding.EncodeToString([]byte("short"))}).MasterKeyBytes(); err == nil {
		t.Fatal("short key accepted")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/config/`
Expected: FAIL: `undefined: Load`

- [ ] **Step 3: Implement**

```go
// internal/config/config.go

// Package config loads zeroauthy configuration from a YAML file and
// ZEROAUTHY_* environment variables. In variable names, "__" separates
// nesting levels: ZEROAUTHY_SERVER__LISTEN sets server.listen.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

const envPrefix = "ZEROAUTHY_"

type Config struct {
	Server   Server   `koanf:"server"`
	Storage  Storage  `koanf:"storage"`
	Security Security `koanf:"security"`
	Log      Log      `koanf:"log"`
	// Seed is an optional path to a declarative seed file applied at startup.
	Seed string `koanf:"seed"`
}

type Server struct {
	Listen string `koanf:"listen"`
	// BaseDomain makes tenant "acme" reachable at acme.<BaseDomain>.
	BaseDomain string `koanf:"base_domain"`
	// TrustProxyHeaders honors X-Forwarded-Host. Enable it only behind a
	// proxy that sets the header.
	TrustProxyHeaders bool   `koanf:"trust_proxy_headers"`
	TLSCertFile       string `koanf:"tls_cert_file"`
	TLSKeyFile        string `koanf:"tls_key_file"`
}

type Storage struct {
	// DSN selects the driver: memory://, and later sqlite://, postgres://,
	// mysql://, plugin://.
	DSN string `koanf:"dsn"`
}

type Security struct {
	// MasterKey is a base64-encoded 32-byte key. Prefer MasterKeyFile.
	MasterKey     string `koanf:"master_key"`
	MasterKeyFile string `koanf:"master_key_file"`
}

type Log struct {
	Level  string `koanf:"level"`  // debug, info, warn, error
	Format string `koanf:"format"` // json, text
}

func defaults() *Config {
	return &Config{
		Server: Server{Listen: ":8080"},
		Log:    Log{Level: "info", Format: "json"},
	}
}

// Load reads the YAML file at path (skipped when path is ""), applies
// ZEROAUTHY_* variables from environ, and validates the result.
func Load(path string, environ []string) (*Config, error) {
	k := koanf.New(".")
	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("config: read %s: %w", path, err)
		}
	}
	err := k.Load(env.Provider(".", env.Opt{
		Prefix:      envPrefix,
		EnvironFunc: func() []string { return environ },
		TransformFunc: func(key, value string) (string, any) {
			key = strings.ToLower(strings.TrimPrefix(key, envPrefix))
			return strings.ReplaceAll(key, "__", "."), value
		},
	}), nil)
	if err != nil {
		return nil, fmt.Errorf("config: environment: %w", err)
	}
	cfg := defaults()
	if err := k.UnmarshalWithConf("", cfg, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	var errs []error
	if c.Storage.DSN == "" {
		errs = append(errs, errors.New("storage.dsn is required"))
	}
	if (c.Server.TLSCertFile == "") != (c.Server.TLSKeyFile == "") {
		errs = append(errs, errors.New("set both server.tls_cert_file and server.tls_key_file, or neither"))
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level %q must be debug, info, warn or error", c.Log.Level))
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("log.format %q must be json or text", c.Log.Format))
	}
	if c.Security.MasterKey != "" && c.Security.MasterKeyFile != "" {
		errs = append(errs, errors.New("set only one of security.master_key and security.master_key_file"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// MasterKeyBytes decodes the configured master key. It returns nil, nil
// when no key is configured.
func (s Security) MasterKeyBytes() ([]byte, error) {
	encoded := s.MasterKey
	if s.MasterKeyFile != "" {
		b, err := os.ReadFile(s.MasterKeyFile)
		if err != nil {
			return nil, fmt.Errorf("config: master key file: %w", err)
		}
		encoded = string(b)
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("config: master key is not valid base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("config: master key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go get github.com/knadh/koanf/v2@v2.3.8 github.com/knadh/koanf/providers/env/v2@v2.0.2 \
  github.com/knadh/koanf/providers/file@v1.2.1 github.com/knadh/koanf/parsers/yaml@v1.1.1
go test ./internal/config/
```

Expected: `ok`. If `"unknown file"` fails because the error text differs on your OS, change that case's `want` to `"read /nonexistent"`. The point of that case is that the path appears in the error.

- [ ] **Step 5: Commit**

```bash
go mod tidy
git add go.mod go.sum internal/config
git commit -m "feat(config): load YAML config with ZEROAUTHY_ env overrides"
```

---
### Task 7: Tenant resolution from the Host header

**Files:**
- Create: `internal/httpx/json.go`
- Create: `internal/tenant/host.go`, `internal/tenant/resolver.go`, `internal/tenant/context.go`
- Create: `internal/tenant/host_test.go`, `internal/tenant/resolver_test.go`

**Interfaces:**
- Consumes: `store.Tenants`, `store.ErrNotFound`, `memory.New` (tests).
- Produces (package `httpx`):
  - `func WriteJSON(w http.ResponseWriter, status int, v any)`
  - `func WriteError(w http.ResponseWriter, status int, code, description string)`
  - `type ErrorBody struct { Error string \`json:"error"\`; ErrorDescription string \`json:"error_description"\` }`
- Produces (package `tenant`):
  - `func NormalizeHost(host string) string`
  - `type Resolved struct { Tenant *store.Tenant; Host string }` with `func (r Resolved) Issuer() string` (returns `"https://" + Host + "/"`)
  - `var ErrUnknownTenant error`
  - `type Resolver struct{...}`, `func NewResolver(t store.Tenants, baseDomain string, trustProxyHeaders bool) *Resolver`, `func (r *Resolver) Resolve(ctx, host string) (Resolved, error)`, `func (r *Resolver) Middleware(next http.Handler) http.Handler`
  - `func WithResolved(ctx context.Context, r Resolved) context.Context`, `func FromContext(ctx context.Context) (Resolved, bool)`

- [ ] **Step 1: Write the JSON helpers** (exercised by the tests below)

```go
// internal/httpx/json.go

// Package httpx holds small HTTP helpers shared by handlers.
package httpx

import (
	"encoding/json"
	"net/http"
)

// ErrorBody is the error shape used by every JSON API endpoint.
type ErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// WriteJSON writes v as a JSON response with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes an ErrorBody.
func WriteError(w http.ResponseWriter, status int, code, description string) {
	WriteJSON(w, status, ErrorBody{Error: code, ErrorDescription: description})
}
```

- [ ] **Step 2: Write the failing tests**

```go
// internal/tenant/host_test.go
package tenant

import "testing"

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"acme.example.test":         "acme.example.test",
		"ACME.Example.TEST":         "acme.example.test",
		"acme.example.test.":        "acme.example.test",
		"acme.example.test:443":     "acme.example.test",
		"acme.example.test.:443":    "acme.example.test",
		"localhost:8443":            "localhost:8443",
		" acme.example.test ":       "acme.example.test",
		"[::1]:8443":                "[::1]:8443",
		"[::1]:443":                 "[::1]",
		"[::1]":                     "[::1]",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
```

```go
// internal/tenant/resolver_test.go
package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	s := memory.New()
	ctx := context.Background()
	for _, tn := range []*store.Tenant{
		{ID: "ten_acme", Name: "acme", Domains: []string{"login.acme.test"}},
		{ID: "ten_globex", Name: "globex", Domains: []string{"localhost:8443"}},
	} {
		if err := s.Tenants().Create(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestResolve(t *testing.T) {
	r := NewResolver(newTestStore(t).Tenants(), "Auth.Example.Test", false)
	cases := []struct {
		host, wantTenant, wantHost string
	}{
		{"login.acme.test", "ten_acme", "login.acme.test"},
		{"LOGIN.acme.test.:443", "ten_acme", "login.acme.test"},
		{"acme.auth.example.test", "ten_acme", "acme.auth.example.test"},
		{"localhost:8443", "ten_globex", "localhost:8443"},
	}
	for _, tc := range cases {
		got, err := r.Resolve(context.Background(), tc.host)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", tc.host, err)
		}
		if got.Tenant.ID != tc.wantTenant || got.Host != tc.wantHost {
			t.Errorf("Resolve(%q) = %s @ %s, want %s @ %s", tc.host, got.Tenant.ID, got.Host, tc.wantTenant, tc.wantHost)
		}
	}
	if got, _ := r.Resolve(context.Background(), "login.acme.test"); got.Issuer() != "https://login.acme.test/" {
		t.Errorf("Issuer = %q", got.Issuer())
	}
	for _, host := range []string{"unknown.test", "auth.example.test", "x.acme.auth.example.test", "nobody.auth.example.test"} {
		if _, err := r.Resolve(context.Background(), host); !errors.Is(err, ErrUnknownTenant) {
			t.Errorf("Resolve(%q) err = %v, want ErrUnknownTenant", host, err)
		}
	}
}

func TestMiddleware(t *testing.T) {
	st := newTestStore(t)
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, ok := FromContext(r.Context())
		if !ok {
			t.Error("no tenant in context")
		}
		_, _ = w.Write([]byte(res.Tenant.ID + " " + res.Issuer()))
	})

	t.Run("resolves host", func(t *testing.T) {
		h := NewResolver(st.Tenants(), "", false).Middleware(echo)
		req := httptest.NewRequest("GET", "https://login.acme.test/x", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 || rec.Body.String() != "ten_acme https://login.acme.test/" {
			t.Fatalf("got %d %q", rec.Code, rec.Body)
		}
	})

	t.Run("unknown host is 404 JSON", func(t *testing.T) {
		h := NewResolver(st.Tenants(), "", false).Middleware(echo)
		req := httptest.NewRequest("GET", "https://evil.test/x", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != 404 || body["error"] != "not_found" || body["error_description"] != "unknown tenant" {
			t.Fatalf("got %d %v", rec.Code, body)
		}
	})

	// Review focus 1: forwarded host only when trusted.
	t.Run("X-Forwarded-Host ignored unless trusted", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://login.acme.test/x", nil)
		req.Header.Set("X-Forwarded-Host", "localhost:8443")

		rec := httptest.NewRecorder()
		NewResolver(st.Tenants(), "", false).Middleware(echo).ServeHTTP(rec, req)
		if rec.Body.String() != "ten_acme https://login.acme.test/" {
			t.Fatalf("untrusted: got %q", rec.Body)
		}

		rec = httptest.NewRecorder()
		NewResolver(st.Tenants(), "", true).Middleware(echo).ServeHTTP(rec, req)
		if rec.Body.String() != "ten_globex https://localhost:8443/" {
			t.Fatalf("trusted: got %q", rec.Body)
		}
	})

	t.Run("X-Forwarded-Host list uses first entry", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://internal.test/x", nil)
		req.Header.Set("X-Forwarded-Host", "login.acme.test, proxy.internal")
		rec := httptest.NewRecorder()
		NewResolver(st.Tenants(), "", true).Middleware(echo).ServeHTTP(rec, req)
		if rec.Body.String() != "ten_acme https://login.acme.test/" {
			t.Fatalf("got %q", rec.Body)
		}
	})
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/tenant/`
Expected: FAIL: `undefined: NormalizeHost`

- [ ] **Step 4: Implement**

```go
// internal/tenant/host.go

// Package tenant maps incoming requests to tenants.
package tenant

import (
	"net"
	"strings"
)

// NormalizeHost canonicalizes a Host header value: lowercase, no trailing
// dot, and no port when the port is the HTTPS default (443). Stored tenant
// domains use the same form.
func NormalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	name, port, err := net.SplitHostPort(h)
	if err != nil {
		// No port present.
		return strings.TrimSuffix(h, ".")
	}
	name = strings.TrimSuffix(name, ".")
	if port == "" || port == "443" {
		if strings.Contains(name, ":") {
			return "[" + name + "]" // IPv6 literal
		}
		return name
	}
	return net.JoinHostPort(name, port)
}
```

```go
// internal/tenant/context.go
package tenant

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Resolved is the tenant a request was addressed to and the normalized
// host it used.
type Resolved struct {
	Tenant *store.Tenant
	Host   string
}

// Issuer is the token issuer for this tenant and host. The trailing slash
// is part of the issuer.
func (r Resolved) Issuer() string { return "https://" + r.Host + "/" }

type ctxKey struct{}

// WithResolved returns a context carrying r.
func WithResolved(ctx context.Context, r Resolved) context.Context {
	return context.WithValue(ctx, ctxKey{}, r)
}

// FromContext returns the tenant stored by the resolver middleware.
func FromContext(ctx context.Context) (Resolved, bool) {
	r, ok := ctx.Value(ctxKey{}).(Resolved)
	return r, ok
}
```

```go
// internal/tenant/resolver.go
package tenant

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ErrUnknownTenant means no tenant serves the requested host.
var ErrUnknownTenant = errors.New("tenant: unknown host")

// Resolver finds the tenant for a host. A host matches a tenant if it is in
// the tenant's Domains, or if it is <tenant name>.<base domain>.
type Resolver struct {
	tenants           store.Tenants
	baseDomain        string
	trustProxyHeaders bool
}

func NewResolver(t store.Tenants, baseDomain string, trustProxyHeaders bool) *Resolver {
	bd := ""
	if baseDomain != "" {
		bd = NormalizeHost(baseDomain)
	}
	return &Resolver{tenants: t, baseDomain: bd, trustProxyHeaders: trustProxyHeaders}
}

func (r *Resolver) Resolve(ctx context.Context, host string) (Resolved, error) {
	h := NormalizeHost(host)
	t, err := r.tenants.GetByDomain(ctx, h)
	if err == nil {
		return Resolved{Tenant: t, Host: h}, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return Resolved{}, err
	}
	if r.baseDomain != "" {
		if name, ok := strings.CutSuffix(h, "."+r.baseDomain); ok && name != "" && !strings.Contains(name, ".") {
			t, err := r.tenants.GetByName(ctx, name)
			if err == nil {
				return Resolved{Tenant: t, Host: h}, nil
			}
			if !errors.Is(err, store.ErrNotFound) {
				return Resolved{}, err
			}
		}
	}
	return Resolved{}, ErrUnknownTenant
}

// Middleware resolves the tenant and stores it in the request context.
// Unknown hosts get a 404 JSON error.
func (r *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host := req.Host
		if r.trustProxyHeaders {
			if fwd := req.Header.Get("X-Forwarded-Host"); fwd != "" {
				host = strings.TrimSpace(strings.Split(fwd, ",")[0])
			}
		}
		res, err := r.Resolve(req.Context(), host)
		switch {
		case errors.Is(err, ErrUnknownTenant):
			httpx.WriteError(w, http.StatusNotFound, "not_found", "unknown tenant")
			return
		case err != nil:
			httpx.WriteError(w, http.StatusInternalServerError, "server_error", "internal error")
			return
		}
		next.ServeHTTP(w, req.WithContext(WithResolved(req.Context(), res)))
	})
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `gofmt -w internal && go test ./internal/tenant/ ./internal/httpx/`
Expected: `ok  .../internal/tenant`. httpx has no tests yet, so `go test` prints `[no test files]` for it.

- [ ] **Step 6: Commit**

```bash
git add internal/httpx internal/tenant
git commit -m "feat(tenant): resolve tenants from Host, base domain, trusted X-Forwarded-Host"
```

---

### Task 8: Signing keys: envelope encryption, rotation, JWKS, signing

**Files:**
- Create: `internal/keys/wrapper.go`, `internal/keys/envelope.go`, `internal/keys/manager.go`
- Create: `internal/keys/wrapper_test.go`, `internal/keys/manager_test.go`

**Interfaces:**
- Consumes: `store.SigningKeys`, `store.SigningKey`, `store.KeyStatus` constants, `store.ErrNotFound`.
- Produces (package `keys`):
  - `type Wrapper interface { Wrap(plaintext, aad []byte) ([]byte, error); Unwrap(ciphertext, aad []byte) ([]byte, error) }`
  - `func NewLocalWrapper(masterKey []byte) (*LocalWrapper, error)`
  - `type Manager struct{...}`, `func NewManager(s store.SigningKeys, w Wrapper) *Manager`
  - `func (m *Manager) Ensure(ctx, tenantID string) error`
  - `func (m *Manager) Rotate(ctx, tenantID string) error`
  - `func (m *Manager) Sign(ctx, tenantID string, claims any) (string, error)`
  - `func (m *Manager) JWKS(ctx, tenantID string) (jose.JSONWebKeySet, error)`: current first, then next, then previous; revoked omitted
  - `var ErrNoSigningKey error`

- [ ] **Step 1: Write the failing tests**

```go
// internal/keys/wrapper_test.go
package keys

import (
	"bytes"
	"testing"
)

func testMasterKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestLocalWrapper(t *testing.T) {
	w, err := NewLocalWrapper(testMasterKey(1))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := w.Wrap([]byte("data key"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("data key")) {
		t.Fatal("ciphertext contains plaintext")
	}
	pt, err := w.Unwrap(ct, []byte("aad"))
	if err != nil || string(pt) != "data key" {
		t.Fatalf("Unwrap = %q, %v", pt, err)
	}
	if _, err := w.Unwrap(ct, []byte("other aad")); err == nil {
		t.Fatal("Unwrap accepted wrong AAD")
	}
	other, _ := NewLocalWrapper(testMasterKey(2))
	if _, err := other.Unwrap(ct, []byte("aad")); err == nil {
		t.Fatal("Unwrap accepted wrong master key")
	}
	if _, err := NewLocalWrapper([]byte("short")); err == nil {
		t.Fatal("short master key accepted")
	}
}

func TestEnvelope(t *testing.T) {
	w, _ := NewLocalWrapper(testMasterKey(1))
	blob, err := seal(w, []byte("private key bytes"), []byte("ten|kid"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("private key bytes")) {
		t.Fatal("sealed blob contains plaintext")
	}
	pt, err := unseal(w, blob, []byte("ten|kid"))
	if err != nil || string(pt) != "private key bytes" {
		t.Fatalf("unseal = %q, %v", pt, err)
	}
	if _, err := unseal(w, blob, []byte("ten|other")); err == nil {
		t.Fatal("unseal accepted wrong AAD")
	}
}
```

```go
// internal/keys/manager_test.go
package keys

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func newManager(t *testing.T) (*Manager, store.Store) {
	t.Helper()
	st := memory.New()
	w, err := NewLocalWrapper(testMasterKey(7))
	if err != nil {
		t.Fatal(err)
	}
	return NewManager(st.SigningKeys(), w), st
}

func kids(set jose.JSONWebKeySet) []string {
	var out []string
	for _, k := range set.Keys {
		out = append(out, k.KeyID)
	}
	return out
}

func TestEnsureIsIdempotent(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	ks, _ := st.SigningKeys().List(ctx, "ten_a")
	if len(ks) != 2 || ks[0].Status != store.KeyCurrent || ks[1].Status != store.KeyNext {
		t.Fatalf("keys after Ensure: %+v", ks)
	}
	for _, k := range ks {
		if k.Alg != "RS256" || len(k.KID) != 43 { // base64url SHA-256 thumbprint
			t.Errorf("key %q alg %q", k.KID, k.Alg)
		}
	}
}

func TestJWKSFollowsRotation(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	ks, _ := st.SigningKeys().List(ctx, "ten_a")
	cur, next := ks[0].KID, ks[1].KID

	set, err := m.JWKS(ctx, "ten_a")
	if err != nil {
		t.Fatal(err)
	}
	if got := kids(set); len(got) != 2 || got[0] != cur || got[1] != next {
		t.Fatalf("JWKS kids = %v, want [%s %s]", got, cur, next)
	}
	for _, k := range set.Keys {
		if !k.IsPublic() || k.Use != "sig" || k.Algorithm != "RS256" {
			t.Fatalf("bad published key %+v", k)
		}
	}

	if err := m.Rotate(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	set, _ = m.JWKS(ctx, "ten_a")
	got := kids(set)
	if len(got) != 3 || got[0] != next || got[2] != cur {
		t.Fatalf("after rotate kids = %v; want next promoted first and old current last", got)
	}

	if err := m.Rotate(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	set, _ = m.JWKS(ctx, "ten_a")
	for _, k := range kids(set) {
		if k == cur {
			t.Fatal("revoked key still published")
		}
	}
}

func TestSignVerifiesWithPublishedKey(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	if _, err := m.Sign(ctx, "ten_a", map[string]any{"sub": "x"}); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("Sign before Ensure: err = %v, want ErrNoSigningKey", err)
	}
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Sign(ctx, "ten_a", map[string]any{"sub": "user-1", "exp": time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	h := tok.Headers[0]
	if h.ExtraHeaders["typ"] != "JWT" {
		t.Errorf("typ = %v", h.ExtraHeaders["typ"])
	}
	set, _ := m.JWKS(ctx, "ten_a")
	if h.KeyID != set.Keys[0].KeyID {
		t.Fatalf("signed with kid %q, current is %q", h.KeyID, set.Keys[0].KeyID)
	}
	var claims map[string]any
	if err := tok.Claims(set.Key(h.KeyID)[0].Key, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("claims = %v", claims)
	}
}

func TestKeysAreTenantScoped(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	_ = m.Ensure(ctx, "ten_a")
	_ = m.Ensure(ctx, "ten_b")
	a, _ := m.JWKS(ctx, "ten_a")
	b, _ := m.JWKS(ctx, "ten_b")
	for _, ka := range kids(a) {
		for _, kb := range kids(b) {
			if ka == kb {
				t.Fatal("tenants share a key")
			}
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go get github.com/go-jose/go-jose/v4@v4.1.5 && go test ./internal/keys/`
Expected: FAIL: `undefined: NewLocalWrapper`

- [ ] **Step 3: Implement**

```go
// internal/keys/wrapper.go

// Package keys manages per-tenant token signing keys: generation, envelope
// encryption at rest, rotation, JWKS publication and signing.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Wrapper encrypts data keys under a key-encryption key. LocalWrapper uses
// a configured master key; a KMS-backed implementation can replace it.
type Wrapper interface {
	Wrap(plaintext, aad []byte) ([]byte, error)
	Unwrap(ciphertext, aad []byte) ([]byte, error)
}

// LocalWrapper is AES-256-GCM under a 32-byte master key. Output is
// nonce || ciphertext.
type LocalWrapper struct{ aead cipher.AEAD }

func NewLocalWrapper(masterKey []byte) (*LocalWrapper, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("keys: master key must be 32 bytes, got %d", len(masterKey))
	}
	aead, err := newGCM(masterKey)
	if err != nil {
		return nil, err
	}
	return &LocalWrapper{aead: aead}, nil
}

func (w *LocalWrapper) Wrap(plaintext, aad []byte) ([]byte, error) {
	return gcmSeal(w.aead, plaintext, aad)
}

func (w *LocalWrapper) Unwrap(ciphertext, aad []byte) ([]byte, error) {
	return gcmOpen(w.aead, ciphertext, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func gcmSeal(aead cipher.AEAD, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

func gcmOpen(aead cipher.AEAD, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("keys: ciphertext too short")
	}
	nonce, ct := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("keys: decryption failed")
	}
	return pt, nil
}
```

```go
// internal/keys/envelope.go
package keys

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// envelope is the stored form of an encrypted private key. A random data
// encryption key (DEK) encrypts the payload, and the Wrapper encrypts the
// DEK. Both layers are bound to the same AAD.
type envelope struct {
	Version int    `json:"v"`
	DEK     []byte `json:"dek"` // wrapped DEK
	CT      []byte `json:"ct"`  // nonce || AES-256-GCM ciphertext under the DEK
}

func seal(w Wrapper, plaintext, aad []byte) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	ct, err := gcmSeal(aead, plaintext, aad)
	if err != nil {
		return nil, err
	}
	wrapped, err := w.Wrap(dek, aad)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{Version: 1, DEK: wrapped, CT: ct})
}

func unseal(w Wrapper, blob, aad []byte) ([]byte, error) {
	var env envelope
	if err := json.Unmarshal(blob, &env); err != nil {
		return nil, fmt.Errorf("keys: malformed envelope: %w", err)
	}
	if env.Version != 1 {
		return nil, fmt.Errorf("keys: unsupported envelope version %d", env.Version)
	}
	dek, err := w.Unwrap(env.DEK, aad)
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	return gcmOpen(aead, env.CT, aad)
}
```

```go
// internal/keys/manager.go
package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ErrNoSigningKey means the tenant has no current key; call Ensure first.
var ErrNoSigningKey = errors.New("keys: tenant has no current signing key")

const rsaBits = 2048

type Manager struct {
	store store.SigningKeys
	wrap  Wrapper
	now   func() time.Time

	mu      sync.Mutex // serializes Ensure and Rotate in this process
	signers sync.Map   // "tenantID|kid" -> jose.Signer
}

func NewManager(s store.SigningKeys, w Wrapper) *Manager {
	return &Manager{store: s, wrap: w, now: time.Now}
}

// Ensure creates a current key and a next key for a tenant that has no
// keys. It does nothing if the tenant already has keys.
func (m *Manager) Ensure(ctx context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ks, err := m.store.List(ctx, tenantID)
	if err != nil {
		return err
	}
	if len(ks) > 0 {
		return nil
	}
	for _, status := range []store.KeyStatus{store.KeyCurrent, store.KeyNext} {
		k, err := m.generate(tenantID, status)
		if err != nil {
			return err
		}
		if err := m.store.Create(ctx, k); err != nil {
			return err
		}
	}
	return nil
}

// Rotate promotes next to current and publishes a fresh next key.
func (m *Manager) Rotate(ctx context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, err := m.generate(tenantID, store.KeyNext)
	if err != nil {
		return err
	}
	return m.store.Rotate(ctx, tenantID, next)
}

// Sign serializes claims as a JWT signed with the tenant's current key.
func (m *Manager) Sign(ctx context.Context, tenantID string, claims any) (string, error) {
	ks, err := m.store.List(ctx, tenantID)
	if err != nil {
		return "", err
	}
	for _, k := range ks {
		if k.Status == store.KeyCurrent {
			signer, err := m.signer(k)
			if err != nil {
				return "", err
			}
			return jwt.Signed(signer).Claims(claims).Serialize()
		}
	}
	return "", ErrNoSigningKey
}

// JWKS returns the tenant's published keys: current, next, previous.
func (m *Manager) JWKS(ctx context.Context, tenantID string) (jose.JSONWebKeySet, error) {
	ks, err := m.store.List(ctx, tenantID)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	for _, status := range []store.KeyStatus{store.KeyCurrent, store.KeyNext, store.KeyPrevious} {
		for _, k := range ks {
			if k.Status != status {
				continue
			}
			var jwk jose.JSONWebKey
			if err := json.Unmarshal(k.PublicJWK, &jwk); err != nil {
				return jose.JSONWebKeySet{}, fmt.Errorf("keys: stored JWK %s: %w", k.KID, err)
			}
			set.Keys = append(set.Keys, jwk)
		}
	}
	return set, nil
}

func (m *Manager) generate(tenantID string, status store.KeyStatus) (*store.SigningKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, err
	}
	pub := jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(jose.RS256), Use: "sig"}
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	pub.KeyID = base64.RawURLEncoding.EncodeToString(thumb) // RFC 7638 thumbprint
	pubJSON, err := pub.MarshalJSON()
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	sealed, err := seal(m.wrap, der, aad(tenantID, pub.KeyID))
	if err != nil {
		return nil, err
	}
	return &store.SigningKey{
		TenantID:   tenantID,
		KID:        pub.KeyID,
		Alg:        string(jose.RS256),
		Status:     status,
		PrivateKey: sealed,
		PublicJWK:  pubJSON,
		CreatedAt:  m.now().UTC(),
	}, nil
}

func (m *Manager) signer(k *store.SigningKey) (jose.Signer, error) {
	cacheKey := k.TenantID + "|" + k.KID
	if s, ok := m.signers.Load(cacheKey); ok {
		return s.(jose.Signer), nil
	}
	der, err := unseal(m.wrap, k.PrivateKey, aad(k.TenantID, k.KID))
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keys: %s is not an RSA key", k.KID)
	}
	s, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: rsaKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.KID),
	)
	if err != nil {
		return nil, err
	}
	m.signers.Store(cacheKey, s)
	return s, nil
}

// aad binds ciphertext to its tenant and key ID so a sealed key cannot be
// moved to another record.
func aad(tenantID, kid string) []byte { return []byte(tenantID + "|" + kid) }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/keys/`
Expected: `ok`. RSA key generation makes this take about 1–2 s.

- [ ] **Step 5: Commit**

```bash
go mod tidy
git add go.mod go.sum internal/keys
git commit -m "feat(keys): add envelope-encrypted per-tenant RS256 keys with rotation and JWKS"
```

---

### Task 9: Declarative seed file

**Files:**
- Create: `internal/seed/seed.go`, `internal/seed/validate.go`, `internal/seed/apply.go`
- Create: `internal/seed/seed_test.go`

**Interfaces:**
- Consumes:
  - `store.Store` with all of its accessors
  - `secrets.Hash`, `secrets.Verify`, `secrets.RandomString`
  - `tenant.NormalizeHost`
- Produces (package `seed`):
  - `type File struct { Tenants []Tenant }` (YAML shape below)
  - `func Load(path string) (*File, error)`: decodes strictly and validates
  - `func Parse(data []byte) (*File, error)`
  - `func Apply(ctx context.Context, st store.Store, f *File, now func() time.Time) error`: idempotent upsert
- Seed semantics:
  - Upsert by natural keys: tenant by `name`, resource server by `identifier`, client by `client_id`, grant by `(client_id, audience)`.
  - Nothing is ever deleted.
  - If the existing secrets already verify against the seed's `client_secret`, they are kept. Otherwise they are replaced by one new hash.

- [ ] **Step 1: Write the failing test**

```go
// internal/seed/seed_test.go
package seed

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const sample = `
tenants:
  - name: acme
    friendly_name: Acme
    domains: ["Login.Acme.TEST", "localhost:8443"]
    default_audience: https://api.acme.test
    resource_servers:
      - identifier: https://api.acme.test
        name: Acme API
        token_lifetime: 3600
        scopes:
          - {value: "read:things", description: "Read things"}
          - {value: "write:things", description: "Write things"}
    clients:
      - client_id: m2m
        name: Backend
        app_type: non_interactive
        client_secret: first-secret
        grant_types: [client_credentials]
      - client_id: spa
        name: Web
        app_type: spa
        callbacks: ["https://app.acme.test/callback"]
    client_grants:
      - client_id: m2m
        audience: https://api.acme.test
        scopes: ["read:things"]
`

var fixedNow = func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }

func TestApply(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}

	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tn.Domains, ",") != "login.acme.test,localhost:8443" {
		t.Errorf("domains not normalized: %v", tn.Domains)
	}
	if tn.DefaultAudience != "https://api.acme.test" || !strings.HasPrefix(tn.ID, "ten_") {
		t.Errorf("tenant = %+v", tn)
	}

	rs, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://api.acme.test")
	if err != nil || rs.TokenLifetime != 3600 || len(rs.Scopes) != 2 || rs.SigningAlg != "RS256" {
		t.Fatalf("resource server = %+v, %v", rs, err)
	}

	m2m, err := st.Clients().Get(ctx, tn.ID, "m2m")
	if err != nil {
		t.Fatal(err)
	}
	if m2m.TokenEndpointAuthMethod != store.AuthMethodClientSecretPost {
		t.Errorf("default auth method for non_interactive = %q", m2m.TokenEndpointAuthMethod)
	}
	if len(m2m.Secrets) != 1 {
		t.Fatalf("secrets = %d", len(m2m.Secrets))
	}
	if ok, _ := secrets.Verify(m2m.Secrets[0].Hash, "first-secret"); !ok {
		t.Error("stored hash does not verify against seed secret")
	}

	spa, _ := st.Clients().Get(ctx, tn.ID, "spa")
	if spa.TokenEndpointAuthMethod != store.AuthMethodNone || len(spa.Secrets) != 0 {
		t.Errorf("spa = %+v", spa)
	}

	g, err := st.ClientGrants().Find(ctx, tn.ID, "m2m", "https://api.acme.test")
	if err != nil || strings.Join(g.Scopes, " ") != "read:things" {
		t.Fatalf("grant = %+v, %v", g, err)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, _ := Parse([]byte(sample))
	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	tn1, _ := st.Tenants().GetByName(ctx, "acme")
	c1, _ := st.Clients().Get(ctx, tn1.ID, "m2m")
	rs1, _ := st.ResourceServers().GetByIdentifier(ctx, tn1.ID, "https://api.acme.test")

	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	tn2, _ := st.Tenants().GetByName(ctx, "acme")
	c2, _ := st.Clients().Get(ctx, tn2.ID, "m2m")
	rs2, _ := st.ResourceServers().GetByIdentifier(ctx, tn2.ID, "https://api.acme.test")
	if tn1.ID != tn2.ID || rs1.ID != rs2.ID || c1.Secrets[0].Hash != c2.Secrets[0].Hash {
		t.Fatal("second Apply changed IDs or re-hashed an unchanged secret")
	}

	changed, _ := Parse([]byte(strings.Replace(sample, "first-secret", "second-secret", 1)))
	if err := Apply(ctx, st, changed, fixedNow); err != nil {
		t.Fatal(err)
	}
	c3, _ := st.Clients().Get(ctx, tn2.ID, "m2m")
	if ok, _ := secrets.Verify(c3.Secrets[0].Hash, "second-secret"); !ok || len(c3.Secrets) != 1 {
		t.Fatal("changed secret was not applied")
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"unknown field": {`tenants: [{name: a, domainz: [x]}]`, "domainz"},
		"no name":       {`tenants: [{domains: [x]}]`, "name is required"},
		"dup tenant":    {`tenants: [{name: a}, {name: a}]`, `duplicate tenant "a"`},
		"bad app type": {`tenants: [{name: a, clients: [{client_id: c, app_type: robot}]}]`, `app_type "robot"`},
		"secret missing": {`tenants: [{name: a, clients: [{client_id: c, app_type: non_interactive}]}]`, "client_secret is required"},
		"secret on public": {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, client_secret: x}]}]`, "must not have a client_secret"},
		"grant unknown client": {`tenants: [{name: a, resource_servers: [{identifier: "https://x"}], client_grants: [{client_id: nope, audience: "https://x"}]}]`, `unknown client "nope"`},
		"grant unknown api": {`tenants: [{name: a, clients: [{client_id: c, app_type: non_interactive, client_secret: s}], client_grants: [{client_id: c, audience: "https://nope"}]}]`, `unknown audience "https://nope"`},
		"grant undefined scope": {`tenants: [{name: a, resource_servers: [{identifier: "https://x", scopes: [{value: r}]}], clients: [{client_id: c, app_type: non_interactive, client_secret: s}], client_grants: [{client_id: c, audience: "https://x", scopes: [w]}]}]`, `scope "w"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/seed/`
Expected: FAIL: `undefined: Parse`

- [ ] **Step 3: Implement**

```go
// internal/seed/seed.go

// Package seed applies a declarative YAML description of tenants, APIs,
// applications and grants to a store. Until the Management API exists,
// seeding is how zeroauthy is administered.
package seed

import (
	"bytes"
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

type File struct {
	Tenants []Tenant `yaml:"tenants"`
}

type Tenant struct {
	Name            string           `yaml:"name"`
	FriendlyName    string           `yaml:"friendly_name"`
	Domains         []string         `yaml:"domains"`
	DefaultAudience string           `yaml:"default_audience"`
	ResourceServers []ResourceServer `yaml:"resource_servers"`
	Clients         []Client         `yaml:"clients"`
	ClientGrants    []ClientGrant    `yaml:"client_grants"`
}

type ResourceServer struct {
	Identifier         string  `yaml:"identifier"`
	Name               string  `yaml:"name"`
	Scopes             []Scope `yaml:"scopes"`
	TokenLifetime      int     `yaml:"token_lifetime"`
	AllowOfflineAccess bool    `yaml:"allow_offline_access"`
}

type Scope struct {
	Value       string `yaml:"value"`
	Description string `yaml:"description"`
}

type Client struct {
	ClientID string `yaml:"client_id"`
	Name     string `yaml:"name"`
	AppType  string `yaml:"app_type"`
	// ClientSecret is plaintext in the seed file and hashed when applied.
	// Protect seed files like any other credential store.
	ClientSecret            string   `yaml:"client_secret"`
	TokenEndpointAuthMethod string   `yaml:"token_endpoint_auth_method"`
	GrantTypes              []string `yaml:"grant_types"`
	Callbacks               []string `yaml:"callbacks"`
	AllowedLogoutURLs       []string `yaml:"allowed_logout_urls"`
	WebOrigins              []string `yaml:"web_origins"`
	AllowedOrigins          []string `yaml:"allowed_origins"`
}

type ClientGrant struct {
	ClientID string   `yaml:"client_id"`
	Audience string   `yaml:"audience"`
	Scopes   []string `yaml:"scopes"`
}

// Load reads and validates a seed file.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	f, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("seed %s: %w", path, err)
	}
	return f, nil
}

// Parse decodes seed YAML, rejecting unknown fields, and validates it.
func Parse(data []byte) (*File, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}
```

```go
// internal/seed/validate.go
package seed

import (
	"errors"
	"fmt"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

var appTypes = []string{
	string(store.AppTypeSPA), string(store.AppTypeRegularWeb),
	string(store.AppTypeNative), string(store.AppTypeNonInteractive),
}

var authMethods = []string{
	store.AuthMethodNone, store.AuthMethodClientSecretPost, store.AuthMethodClientSecretBasic,
}

// defaultAuthMethod picks a method when the seed omits one. Browser and
// native apps cannot keep secrets, so they are public clients.
func defaultAuthMethod(appType string) string {
	switch store.AppType(appType) {
	case store.AppTypeSPA, store.AppTypeNative:
		return store.AuthMethodNone
	default:
		return store.AuthMethodClientSecretPost
	}
}

func (f *File) validate() error {
	var errs []error
	seenTenants := map[string]bool{}
	for i := range f.Tenants {
		t := &f.Tenants[i]
		if t.Name == "" {
			errs = append(errs, fmt.Errorf("seed: tenants[%d]: name is required", i))
			continue
		}
		if seenTenants[t.Name] {
			errs = append(errs, fmt.Errorf("seed: duplicate tenant %q", t.Name))
		}
		seenTenants[t.Name] = true
		errs = append(errs, t.validate()...)
	}
	return errors.Join(errs...)
}

func (t *Tenant) validate() []error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("seed: tenant %q: "+format, append([]any{t.Name}, args...)...))
	}

	apis := map[string]*ResourceServer{}
	for i := range t.ResourceServers {
		rs := &t.ResourceServers[i]
		if rs.Identifier == "" {
			fail("resource_servers[%d]: identifier is required", i)
			continue
		}
		if apis[rs.Identifier] != nil {
			fail("duplicate resource server %q", rs.Identifier)
		}
		apis[rs.Identifier] = rs
	}

	clients := map[string]bool{}
	for i := range t.Clients {
		c := &t.Clients[i]
		if c.ClientID == "" {
			fail("clients[%d]: client_id is required", i)
			continue
		}
		if clients[c.ClientID] {
			fail("duplicate client %q", c.ClientID)
		}
		clients[c.ClientID] = true
		if !slices.Contains(appTypes, c.AppType) {
			fail("client %q: app_type %q must be one of %v", c.ClientID, c.AppType, appTypes)
		}
		if c.TokenEndpointAuthMethod == "" {
			c.TokenEndpointAuthMethod = defaultAuthMethod(c.AppType)
		}
		if !slices.Contains(authMethods, c.TokenEndpointAuthMethod) {
			fail("client %q: token_endpoint_auth_method %q must be one of %v", c.ClientID, c.TokenEndpointAuthMethod, authMethods)
		}
		public := c.TokenEndpointAuthMethod == store.AuthMethodNone
		if public && c.ClientSecret != "" {
			fail("client %q: public clients must not have a client_secret", c.ClientID)
		}
		if !public && c.ClientSecret == "" {
			fail("client %q: client_secret is required for %s", c.ClientID, c.TokenEndpointAuthMethod)
		}
	}

	seenGrants := map[[2]string]bool{}
	for _, g := range t.ClientGrants {
		if !clients[g.ClientID] {
			fail("client grant references unknown client %q", g.ClientID)
		}
		rs := apis[g.Audience]
		if rs == nil {
			fail("client grant references unknown audience %q", g.Audience)
			continue
		}
		k := [2]string{g.ClientID, g.Audience}
		if seenGrants[k] {
			fail("duplicate client grant %q → %q", g.ClientID, g.Audience)
		}
		seenGrants[k] = true
		for _, s := range g.Scopes {
			if !slices.ContainsFunc(rs.Scopes, func(d Scope) bool { return d.Value == s }) {
				fail("client grant %q → %q: scope %q is not defined by the resource server", g.ClientID, g.Audience, s)
			}
		}
	}
	return errs
}
```

```go
// internal/seed/apply.go
package seed

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Apply upserts everything in f. It never deletes.
func Apply(ctx context.Context, st store.Store, f *File, now func() time.Time) error {
	for _, t := range f.Tenants {
		if err := applyTenant(ctx, st, t, now().UTC()); err != nil {
			return fmt.Errorf("seed: tenant %q: %w", t.Name, err)
		}
	}
	return nil
}

func applyTenant(ctx context.Context, st store.Store, in Tenant, now time.Time) error {
	domains := make([]string, len(in.Domains))
	for i, d := range in.Domains {
		domains[i] = tenant.NormalizeHost(d)
	}
	tn, err := st.Tenants().GetByName(ctx, in.Name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		tn = &store.Tenant{ID: "ten_" + secrets.RandomString(16), Name: in.Name, CreatedAt: now}
		tn.FriendlyName, tn.Domains, tn.DefaultAudience = in.FriendlyName, domains, in.DefaultAudience
		if err := st.Tenants().Create(ctx, tn); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		tn.FriendlyName, tn.Domains, tn.DefaultAudience = in.FriendlyName, domains, in.DefaultAudience
		if err := st.Tenants().Update(ctx, tn); err != nil {
			return err
		}
	}

	for _, rs := range in.ResourceServers {
		if err := applyResourceServer(ctx, st, tn.ID, rs, now); err != nil {
			return fmt.Errorf("resource server %q: %w", rs.Identifier, err)
		}
	}
	for _, c := range in.Clients {
		if err := applyClient(ctx, st, tn.ID, c, now); err != nil {
			return fmt.Errorf("client %q: %w", c.ClientID, err)
		}
	}
	for _, g := range in.ClientGrants {
		if err := applyClientGrant(ctx, st, tn.ID, g, now); err != nil {
			return fmt.Errorf("client grant %q → %q: %w", g.ClientID, g.Audience, err)
		}
	}
	return nil
}

func applyResourceServer(ctx context.Context, st store.Store, tenantID string, in ResourceServer, now time.Time) error {
	scopes := make([]store.Scope, len(in.Scopes))
	for i, s := range in.Scopes {
		scopes[i] = store.Scope{Value: s.Value, Description: s.Description}
	}
	rs, err := st.ResourceServers().GetByIdentifier(ctx, tenantID, in.Identifier)
	create := errors.Is(err, store.ErrNotFound)
	if err != nil && !create {
		return err
	}
	if create {
		rs = &store.ResourceServer{TenantID: tenantID, ID: "rs_" + secrets.RandomString(24), Identifier: in.Identifier, CreatedAt: now}
	}
	rs.Name, rs.Scopes, rs.SigningAlg = in.Name, scopes, "RS256"
	rs.TokenLifetime, rs.AllowOfflineAccess = in.TokenLifetime, in.AllowOfflineAccess
	if create {
		return st.ResourceServers().Create(ctx, rs)
	}
	return st.ResourceServers().Update(ctx, rs)
}

func applyClient(ctx context.Context, st store.Store, tenantID string, in Client, now time.Time) error {
	c, err := st.Clients().Get(ctx, tenantID, in.ClientID)
	create := errors.Is(err, store.ErrNotFound)
	if err != nil && !create {
		return err
	}
	if create {
		c = &store.Client{TenantID: tenantID, ClientID: in.ClientID, CreatedAt: now}
	}
	c.Name, c.AppType = in.Name, store.AppType(in.AppType)
	c.TokenEndpointAuthMethod = in.TokenEndpointAuthMethod
	c.GrantTypes = slices.Clone(in.GrantTypes)
	c.Callbacks, c.AllowedLogoutURLs = slices.Clone(in.Callbacks), slices.Clone(in.AllowedLogoutURLs)
	c.WebOrigins, c.AllowedOrigins = slices.Clone(in.WebOrigins), slices.Clone(in.AllowedOrigins)

	switch {
	case in.ClientSecret == "":
		c.Secrets = nil
	case !secretMatches(c.Secrets, in.ClientSecret):
		h, err := secrets.Hash(in.ClientSecret)
		if err != nil {
			return err
		}
		c.Secrets = []store.ClientSecret{{Hash: h, CreatedAt: now}}
	}
	if create {
		return st.Clients().Create(ctx, c)
	}
	return st.Clients().Update(ctx, c)
}

func secretMatches(existing []store.ClientSecret, plaintext string) bool {
	for _, s := range existing {
		if ok, err := secrets.Verify(s.Hash, plaintext); err == nil && ok {
			return true
		}
	}
	return false
}

func applyClientGrant(ctx context.Context, st store.Store, tenantID string, in ClientGrant, now time.Time) error {
	g, err := st.ClientGrants().Find(ctx, tenantID, in.ClientID, in.Audience)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return st.ClientGrants().Create(ctx, &store.ClientGrant{
			TenantID: tenantID, ID: "cgr_" + secrets.RandomString(24),
			ClientID: in.ClientID, Audience: in.Audience, Scopes: slices.Clone(in.Scopes), CreatedAt: now,
		})
	case err != nil:
		return err
	default:
		g.Scopes = slices.Clone(in.Scopes)
		return st.ClientGrants().Update(ctx, g)
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go get go.yaml.in/yaml/v3@v3.0.5 && go test ./internal/seed/`
Expected: `ok`. If the `unknown field` case fails because the YAML library reports the field differently, keep the assertion on `"domainz"`. Only the field name has to appear in the error.

- [ ] **Step 5: Commit**

```bash
go mod tidy
git add go.mod go.sum internal/seed
git commit -m "feat(seed): add idempotent declarative seed file"
```

---

### Task 10: OpenAPI contract, code generation, provenance check

**Files:**
- Create: `api/authentication.yaml`, `api/embed.go`, `api/spec_test.go`
- Create: `internal/gen/authapi/generate.go`, `internal/gen/authapi/cfg.yaml`; generated: `internal/gen/authapi/authapi.gen.go`
- Create: `scripts/check-sources.sh`
- Modify: `.github/workflows/ci.yml` (add generated-code check)

**Interfaces:**
- Produces (package `api`): `var AuthenticationYAML []byte`
- Produces (package `authapi`, generated):
  - `type ServerInterface interface { Discovery(w, r); Jwks(w, r); OauthToken(w, r) }`
  - `func HandlerFromMux(si ServerInterface, r chi.Router) http.Handler`
  - `type TokenResponse struct { AccessToken string; ExpiresIn int; IdToken *string; RefreshToken *string; Scope *string; TokenType string }`
  - `type OAuthError struct { Error string; ErrorDescription string }`

- [ ] **Step 1: Write the failing test**

```go
// api/spec_test.go
package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestAuthenticationSpecIsValid(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(AuthenticationYAML)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Every operation must cite the public sources it was derived from
// (CLEAN_ROOM.md, "Provenance").
func TestEveryOperationHasProvenance(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(AuthenticationYAML)
	if err != nil {
		t.Fatal(err)
	}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			raw, ok := op.Extensions["x-source"]
			if !ok {
				t.Errorf("%s %s: missing x-source", method, path)
				continue
			}
			b, _ := json.Marshal(raw)
			var urls []string
			if err := json.Unmarshal(b, &urls); err != nil || len(urls) == 0 {
				t.Errorf("%s %s: x-source must be a non-empty list of URLs, got %s", method, path, b)
				continue
			}
			for _, u := range urls {
				if !strings.HasPrefix(u, "https://") {
					t.Errorf("%s %s: x-source %q is not an https URL", method, path, u)
				}
			}
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go get github.com/getkin/kin-openapi@v0.150.0 && go test ./api/`
Expected: FAIL: `undefined: AuthenticationYAML`

- [ ] **Step 3: Write the contract and embed it**

```go
// api/embed.go

// Package api embeds zeroauthy's hand-written OpenAPI contracts.
package api

import _ "embed"

//go:embed authentication.yaml
var AuthenticationYAML []byte
```

```yaml
# api/authentication.yaml
openapi: 3.1.0
info:
  title: zeroauthy Authentication API
  version: 0.1.0
  summary: Auth0-compatible Authentication API served by every zeroauthy tenant.
  description: |
    The Authentication API of a zeroauthy tenant. It is wire-compatible with
    the Auth0 Authentication API, so existing Auth0 SDKs work by changing only
    the domain.

    Each tenant is addressed by its own domain. Tokens are issued with the
    issuer `https://{tenant_domain}/`, with a trailing slash.

    Every operation lists the public documents it was derived from in
    `x-source`. zeroauthy is a clean-room implementation; see `CLEAN_ROOM.md`.
  license:
    name: Apache-2.0
    identifier: Apache-2.0
servers:
  - url: https://{tenant_domain}
    variables:
      tenant_domain:
        default: tenant.example.com
        description: Any domain configured for the tenant.
tags:
  - name: Discovery
    description: Metadata that lets clients configure themselves.
  - name: Tokens
    description: Obtain tokens.
paths:
  /.well-known/openid-configuration:
    get:
      operationId: discovery
      tags: [Discovery]
      summary: OpenID Provider configuration
      description: |
        Returns the tenant's OpenID Provider metadata. Lists only grant
        types and features that this server version implements.
      x-source:
        - https://openid.net/specs/openid-connect-discovery-1_0.html
        - https://auth0.com/docs/get-started/applications/configure-applications-with-oidc-discovery
      responses:
        "200":
          description: Provider metadata.
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/OpenIDConfiguration"
        "404":
          $ref: "#/components/responses/UnknownTenant"
        default:
          $ref: "#/components/responses/ServerError"
  /.well-known/jwks.json:
    get:
      operationId: jwks
      tags: [Discovery]
      summary: JSON Web Key Set
      description: |
        Public keys for verifying tokens signed by this tenant: the current
        signing key first, followed by the next key and the previous key.
      x-source:
        - https://www.rfc-editor.org/rfc/rfc7517
        - https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets
      responses:
        "200":
          description: The tenant's published keys.
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/JWKS"
        "404":
          $ref: "#/components/responses/UnknownTenant"
        default:
          $ref: "#/components/responses/ServerError"
  /oauth/token:
    post:
      operationId: oauthToken
      tags: [Tokens]
      summary: Get a token
      description: |
        Exchanges a grant for tokens. The body may be form-encoded or JSON.

        **Supported grant types**

        | `grant_type` | Purpose |
        |---|---|
        | `client_credentials` | Machine-to-machine access token for `audience` |

        **Client authentication.** Confidential clients authenticate with
        the method they are registered with: `client_secret_post`
        (`client_id` and `client_secret` in the body) or
        `client_secret_basic` (HTTP Basic, with the client ID and secret
        form-urlencoded before base64 encoding). Using both methods in one
        request is rejected.
      x-source:
        - https://www.rfc-editor.org/rfc/rfc6749#section-4.4
        - https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
        - https://auth0.com/docs/api/authentication
        - https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow
      security:
        - clientSecretBasic: []
        - {}
      requestBody:
        required: true
        content:
          application/x-www-form-urlencoded:
            schema:
              $ref: "#/components/schemas/TokenRequest"
          application/json:
            schema:
              $ref: "#/components/schemas/TokenRequest"
      responses:
        "200":
          description: Tokens issued.
          headers:
            Cache-Control:
              schema: {type: string, const: no-store}
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/TokenResponse"
        "400":
          $ref: "#/components/responses/OAuthErrorResponse"
        "401":
          $ref: "#/components/responses/OAuthErrorResponse"
        "403":
          $ref: "#/components/responses/OAuthErrorResponse"
        "404":
          $ref: "#/components/responses/UnknownTenant"
        default:
          $ref: "#/components/responses/ServerError"
components:
  securitySchemes:
    clientSecretBasic:
      type: http
      scheme: basic
      description: Client ID and secret, each form-urlencoded, as HTTP Basic credentials.
  responses:
    OAuthErrorResponse:
      description: |
        The request failed. Common `error` values: `invalid_request`,
        `invalid_client`, `unauthorized_client`, `unsupported_grant_type`,
        `invalid_scope`, `access_denied`.
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/OAuthError"
    UnknownTenant:
      description: The request host is not a domain of any tenant.
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/OAuthError"
    ServerError:
      description: Unexpected server error.
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/OAuthError"
  schemas:
    OAuthError:
      type: object
      required: [error, error_description]
      properties:
        error:
          type: string
          examples: [invalid_client]
        error_description:
          type: string
    TokenRequest:
      type: object
      required: [grant_type]
      properties:
        grant_type:
          type: string
          examples: [client_credentials]
        client_id:
          type: string
        client_secret:
          type: string
        audience:
          type: string
          description: Identifier of the API the token is for. Defaults to the tenant's default audience.
        scope:
          type: string
          description: Space-separated scopes to request. Defaults to all scopes granted to the client.
    TokenResponse:
      type: object
      required: [access_token, token_type, expires_in]
      properties:
        access_token:
          type: string
        token_type:
          type: string
          examples: [Bearer]
        expires_in:
          type: integer
          minimum: 0
          description: Lifetime of the access token in seconds.
        scope:
          type: string
        id_token:
          type: string
        refresh_token:
          type: string
    OpenIDConfiguration:
      type: object
      required:
        - issuer
        - authorization_endpoint
        - token_endpoint
        - jwks_uri
        - response_types_supported
        - subject_types_supported
        - id_token_signing_alg_values_supported
      properties:
        issuer: {type: string, format: uri}
        authorization_endpoint: {type: string, format: uri}
        token_endpoint: {type: string, format: uri}
        jwks_uri: {type: string, format: uri}
        response_types_supported: {type: array, items: {type: string}}
        subject_types_supported: {type: array, items: {type: string}}
        id_token_signing_alg_values_supported: {type: array, items: {type: string}}
        token_endpoint_auth_methods_supported: {type: array, items: {type: string}}
        grant_types_supported: {type: array, items: {type: string}}
    JWKS:
      type: object
      required: [keys]
      properties:
        keys:
          type: array
          items:
            $ref: "#/components/schemas/JWK"
    JWK:
      type: object
      required: [kty, kid, use, alg, n, e]
      properties:
        kty: {type: string, examples: [RSA]}
        kid: {type: string}
        use: {type: string, examples: [sig]}
        alg: {type: string, examples: [RS256]}
        "n": {type: string}
        e: {type: string}
```

> `"n"` is quoted because a bare `n` can be parsed as a boolean by YAML 1.1 parsers.

- [ ] **Step 4: Run the spec tests**

Run: `go test ./api/`
Expected: `ok`

- [ ] **Step 5: Set up code generation**

```bash
go get -tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0
```

```yaml
# internal/gen/authapi/cfg.yaml
package: authapi
output: authapi.gen.go
generate:
  models: true
  chi-server: true
```

```go
// internal/gen/authapi/generate.go

// Package authapi is generated from api/authentication.yaml. Do not edit
// authapi.gen.go; edit the spec and run `go generate ./...`.
package authapi

//go:generate go tool oapi-codegen -config cfg.yaml ../../../api/authentication.yaml
```

Run:

```bash
go get github.com/go-chi/chi/v5@v5.4.0
go generate ./internal/gen/authapi/ && go mod tidy && go build ./...
grep -nE "type (ServerInterface|TokenResponse|OAuthError) |func HandlerFromMux|IdToken|Jwks\(|Discovery\(|OauthToken\(" internal/gen/authapi/authapi.gen.go
```

Expected: the build succeeds, and grep shows `ServerInterface` with the methods `Discovery`, `Jwks` and `OauthToken`, `TokenResponse` with an `IdToken *string` field, `OAuthError`, and `HandlerFromMux`. **If any name differs** (for example `IDToken` instead of `IdToken`), use the generated name in Tasks 15 and 16. Do not edit the generated file.

- [ ] **Step 6: Add the provenance link checker**

```bash
#!/usr/bin/env bash
# scripts/check-sources.sh: verify every x-source URL in an OpenAPI file is reachable.
set -euo pipefail
spec="${1:?usage: check-sources.sh <openapi.yaml>}"
fail=0
while read -r url; do
  code=$(curl -sL -o /dev/null -w '%{http_code}' --max-time 20 "$url" || echo 000)
  if [[ "$code" != 200 ]]; then
    echo "UNREACHABLE ($code): $url"
    fail=1
  else
    echo "ok: $url"
  fi
done < <(awk '/x-source:/{f=1;next} f&&/^[[:space:]]*- https:/{print $2;next} {f=0}' "$spec" | sort -u)
exit $fail
```

Run: `chmod +x scripts/check-sources.sh && ./scripts/check-sources.sh api/authentication.yaml`
Expected: every line prints `ok:`. **If an auth0.com URL is unreachable**, find the current public page that documents the same thing, replace the URL in the spec, and re-run. Never remove a source without replacing it.

- [ ] **Step 7: Add the generated-code check to CI**

Append to the `test` job in `.github/workflows/ci.yml`:

```yaml
      - name: generated code is up to date
        run: go generate ./... && git diff --exit-code
```

- [ ] **Step 8: Commit**

```bash
git add api internal/gen scripts .github/workflows/ci.yml go.mod go.sum
git commit -m "feat(api): add OpenAPI 3.1 contract for discovery, JWKS, token endpoint"
```

---

### Task 11: Contract-validation test harness

**Files:**
- Create: `internal/testutil/contract/contract.go`, `internal/testutil/contract/contract_test.go`

**Interfaces:**
- Consumes: `api.AuthenticationYAML`.
- Produces (package `contract`):
  - `func Wrap(t testing.TB, h http.Handler) http.Handler`: validates request and response
  - `func WrapResponses(t testing.TB, h http.Handler) http.Handler`: validates only the response; use it for tests that deliberately send malformed requests
  - Violations, including a path not described in the spec, are reported with `t.Errorf`.

- [ ] **Step 1: Write the failing test**

```go
// internal/testutil/contract/contract_test.go
package contract

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recorder captures Errorf calls instead of failing the real test.
type recorder struct {
	testing.TB
	errs []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func respond(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func do(h http.Handler, method, target, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const form = "application/x-www-form-urlencoded"

func TestValidExchangePasses(t *testing.T) {
	r := &recorder{TB: t}
	h := Wrap(r, respond(200, `{"access_token":"x","token_type":"Bearer","expires_in":60}`))
	rec := do(h, "POST", "https://acme.test/oauth/token", form, "grant_type=client_credentials")
	if len(r.errs) != 0 {
		t.Fatalf("unexpected violations: %v", r.errs)
	}
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"access_token":"x"`) {
		t.Fatalf("response not passed through: %d %s", rec.Code, rec.Body)
	}
}

func TestBadResponseIsReported(t *testing.T) {
	r := &recorder{TB: t}
	h := Wrap(r, respond(200, `{"token_type":"Bearer","expires_in":60}`))
	do(h, "POST", "https://acme.test/oauth/token", form, "grant_type=client_credentials")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "access_token") {
		t.Fatalf("violations = %v", r.errs)
	}
}

func TestUndeclaredStatusIsReported(t *testing.T) {
	r := &recorder{TB: t}
	h := Wrap(r, respond(418, `{"error":"teapot","error_description":"x"}`))
	do(h, "GET", "https://acme.test/.well-known/jwks.json", "", "")
	// 418 falls under "default", which is declared, so it passes. A
	// response whose body doesn't match must still fail:
	h = Wrap(r, respond(418, `{"oops":true}`))
	do(h, "GET", "https://acme.test/.well-known/jwks.json", "", "")
	if len(r.errs) != 1 {
		t.Fatalf("violations = %v", r.errs)
	}
}

func TestBadRequestReportedOnlyByWrap(t *testing.T) {
	ok := respond(400, `{"error":"invalid_request","error_description":"grant_type is required"}`)

	r := &recorder{TB: t}
	do(Wrap(r, ok), "POST", "https://acme.test/oauth/token", form, "audience=x")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "grant_type") {
		t.Fatalf("Wrap violations = %v", r.errs)
	}

	r = &recorder{TB: t}
	do(WrapResponses(r, ok), "POST", "https://acme.test/oauth/token", form, "audience=x")
	if len(r.errs) != 0 {
		t.Fatalf("WrapResponses violations = %v", r.errs)
	}
}

func TestUnknownPathIsReported(t *testing.T) {
	r := &recorder{TB: t}
	do(Wrap(r, respond(200, `{}`)), "GET", "https://acme.test/not-in-spec", "", "")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "not described") {
		t.Fatalf("violations = %v", r.errs)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/testutil/contract/`
Expected: FAIL: `undefined: Wrap`

- [ ] **Step 3: Implement**

```go
// internal/testutil/contract/contract.go

// Package contract checks HTTP traffic in tests against
// api/authentication.yaml, so handlers cannot drift from the published
// contract.
package contract

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/zeroauthy/zeroauthy/api"
)

var (
	loadOnce  sync.Once
	theRouter routers.Router
	loadErr   error
)

func router() (routers.Router, error) {
	loadOnce.Do(func() {
		doc, err := openapi3.NewLoader().LoadFromData(api.AuthenticationYAML)
		if err != nil {
			loadErr = err
			return
		}
		// Match on path only. Test requests use arbitrary hosts and
		// plain HTTP, which the https://{tenant_domain} server entry would
		// otherwise reject (silently skipping validation).
		doc.Servers = nil
		theRouter, loadErr = gorillamux.NewRouter(doc)
	})
	return theRouter, loadErr
}

// Wrap validates every request and response passing through h.
func Wrap(t testing.TB, h http.Handler) http.Handler { return wrap(t, h, true) }

// WrapResponses validates only responses. Use it in tests that send
// deliberately invalid requests.
func WrapResponses(t testing.TB, h http.Handler) http.Handler { return wrap(t, h, false) }

func wrap(t testing.TB, h http.Handler, checkRequest bool) http.Handler {
	t.Helper()
	rt, err := router()
	if err != nil {
		t.Fatalf("contract: load spec: %v", err)
	}
	opts := &openapi3filter.Options{
		AuthenticationFunc:    openapi3filter.NoopAuthenticationFunc,
		IncludeResponseStatus: true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, params, err := rt.FindRoute(r)
		if err != nil {
			t.Errorf("contract: %s %s is not described in api/authentication.yaml: %v", r.Method, r.URL.Path, err)
			h.ServeHTTP(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		in := &openapi3filter.RequestValidationInput{Request: r, PathParams: params, Route: route, Options: opts}
		if checkRequest {
			if err := openapi3filter.ValidateRequest(context.Background(), in); err != nil {
				t.Errorf("contract: request %s %s violates spec: %v", r.Method, r.URL.Path, err)
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)

		out := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: in,
			Status:                 rec.Code,
			Header:                 rec.Header(),
			Body:                   io.NopCloser(bytes.NewReader(rec.Body.Bytes())),
			Options:                opts,
		}
		if err := openapi3filter.ValidateResponse(context.Background(), out); err != nil {
			t.Errorf("contract: response %d to %s %s violates spec: %v", rec.Code, r.Method, r.URL.Path, err)
		}

		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go mod tidy && go test ./internal/testutil/contract/`
Expected: `ok`. If `TestUndeclaredStatusIsReported` reports 0 violations, kin-openapi is not validating `default` response bodies. In that case add a 418-specific check to the test, so that a body which matches no declared response is still reported. Keep the harness strict; don't loosen the assertion.

- [ ] **Step 5: Commit**

```bash
git add internal/testutil go.mod go.sum
git commit -m "test: add OpenAPI contract-validation harness"
```

---
### Task 12: Discovery and JWKS handlers

**Files:**
- Create: `internal/oidc/handlers.go`, `internal/oidc/handlers_test.go`

**Interfaces:**
- Consumes:
  - `tenant.FromContext`, `tenant.Resolved.Issuer()`, `tenant.NewResolver`
  - `keys.Manager.JWKS`, `httpx.WriteJSON`, `httpx.WriteError`
  - `contract.Wrap`
- Produces (package `oidc`): `type Handlers struct { Keys *keys.Manager; Log *slog.Logger }` with methods `Discovery(w, r)` and `Jwks(w, r)`. The method names match `authapi.ServerInterface`.

- [ ] **Step 1: Write the failing test**

```go
// internal/oidc/handlers_test.go
package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

func setup(t *testing.T) (http.Handler, *keys.Manager) {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten_acme", Name: "acme", Domains: []string{"acme.example.test"}}); err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{3}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	if err := km.Ensure(ctx, "ten_acme"); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{Keys: km}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", h.Discovery)
	mux.HandleFunc("GET /.well-known/jwks.json", h.Jwks)
	return contract.Wrap(t, tenant.NewResolver(st.Tenants(), "", false).Middleware(mux)), km
}

func get(h http.Handler, url string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", url, nil))
	return rec
}

func TestDiscovery(t *testing.T) {
	h, _ := setup(t)
	rec := get(h, "https://acme.example.test/.well-known/openid-configuration")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"issuer":                 "https://acme.example.test/",
		"authorization_endpoint": "https://acme.example.test/authorize",
		"token_endpoint":         "https://acme.example.test/oauth/token",
		"jwks_uri":               "https://acme.example.test/.well-known/jwks.json",
	}
	for k, v := range want {
		if doc[k] != v {
			t.Errorf("%s = %v, want %s", k, doc[k], v)
		}
	}
	if got := doc["grant_types_supported"]; len(got.([]any)) != 1 || got.([]any)[0] != "client_credentials" {
		t.Errorf("grant_types_supported = %v", got)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestJWKS(t *testing.T) {
	h, km := setup(t)
	rec := get(h, "https://acme.example.test/.well-known/jwks.json")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		Keys []struct {
			Kid string `json:"kid"`
			D   string `json:"d"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	set, _ := km.JWKS(context.Background(), "ten_acme")
	if len(body.Keys) != 2 || body.Keys[0].Kid != set.Keys[0].KeyID {
		t.Fatalf("keys = %+v", body.Keys)
	}
	for _, k := range body.Keys {
		if k.D != "" {
			t.Fatal("private key material published")
		}
	}
}

func TestUnknownTenant(t *testing.T) {
	h, _ := setup(t)
	if rec := get(h, "https://nobody.test/.well-known/jwks.json"); rec.Code != 404 {
		t.Fatalf("status %d", rec.Code)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/oidc/`
Expected: FAIL: `undefined: Handlers`

- [ ] **Step 3: Implement**

```go
// internal/oidc/handlers.go

// Package oidc serves OpenID Connect metadata: discovery and JWKS.
package oidc

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Metadata is cacheable briefly: keys are pre-published as "next" before
// they sign anything, so a short cache never hides a signing key.
const metadataCacheControl = "public, max-age=300"

type Handlers struct {
	Keys *keys.Manager
	Log  *slog.Logger
}

// Configuration is OpenID Provider metadata (OpenID Connect Discovery 1.0
// §3). It lists only what this server implements.
type Configuration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
}

func (h *Handlers) Discovery(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	base := strings.TrimSuffix(res.Issuer(), "/")
	w.Header().Set("Cache-Control", metadataCacheControl)
	httpx.WriteJSON(w, http.StatusOK, Configuration{
		Issuer:                            res.Issuer(),
		AuthorizationEndpoint:             base + "/authorize",
		TokenEndpoint:                     base + "/oauth/token",
		JWKSURI:                           base + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		GrantTypesSupported:               []string{"client_credentials"},
	})
}

func (h *Handlers) Jwks(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	set, err := h.Keys.JWKS(r.Context(), res.Tenant.ID)
	if err != nil {
		h.log().ErrorContext(r.Context(), "load JWKS", "tenant", res.Tenant.ID, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	w.Header().Set("Cache-Control", metadataCacheControl)
	httpx.WriteJSON(w, http.StatusOK, set)
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}
```

> `authorization_endpoint` is required by OpenID Discovery, so it is advertised now. It returns 404 until the hosted-login plan implements `/authorize`. Record this in the compat matrix (Task 17).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/oidc/`
Expected: `ok`, with no `contract:` violations.

- [ ] **Step 5: Commit**

```bash
git add internal/oidc
git commit -m "feat(oidc): serve per-tenant discovery and JWKS"
```

---

### Task 13: Token endpoint plumbing: errors, request parsing, client authentication

**Files:**
- Create: `internal/oauth/handlers.go`, `internal/oauth/errors.go`, `internal/oauth/request.go`, `internal/oauth/clientauth.go`
- Create: `internal/oauth/fixture_test.go`, `internal/oauth/request_test.go`, `internal/oauth/clientauth_test.go`

**Interfaces:**
- Consumes:
  - `store.Store`, `store.AuthMethod*`, `secrets.Verify`, `httpx.WriteError`
  - `seed.Parse`, `seed.Apply`, `memory.New` (tests)
- Produces (package `oauth`):
  - `type Handlers struct { Store store.Store; Log *slog.Logger; Now func() time.Time }`. Task 15 adds `Minter *Minter`.
  - `type Error struct { Status int; Code, Description string }`, plus constructors `invalidRequest`, `invalidClient(desc string, basic bool)`, `unauthorizedClient`, `unsupportedGrantType`, `invalidScope`, `accessDenied`, `serverError`
  - `func writeError(w, *Error)`, `func noStore(w)`
  - `func parseTokenRequest(w http.ResponseWriter, r *http.Request) (url.Values, *Error)`
  - `func (h *Handlers) authenticateClient(ctx, r *http.Request, form url.Values, tenantID string) (*store.Client, *Error)`
  - Test fixture: `newFixture(t) *fixture` with fields `st store.Store` and `h *Handlers`, method `tenantID(t, name) string`, and package var `fixedNow`

- [ ] **Step 1: Write the test fixture**

```go
// internal/oauth/fixture_test.go
package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }

const fixtureSeed = `
tenants:
  - name: acme
    domains: [acme.example.test]
    default_audience: https://api.acme.test
    resource_servers:
      - identifier: https://api.acme.test
        name: Acme API
        token_lifetime: 3600
        scopes: [{value: "read:things"}, {value: "write:things"}]
      - identifier: https://billing.acme.test
        name: Billing
        scopes: [{value: "read:invoices"}]
    clients:
      - {client_id: m2m, app_type: non_interactive, client_secret: m2m-secret, grant_types: [client_credentials]}
      - {client_id: m2m-basic, app_type: non_interactive, client_secret: "p@ss:w+rd", token_endpoint_auth_method: client_secret_basic, grant_types: [client_credentials]}
      - {client_id: web, app_type: regular_web, client_secret: web-secret, grant_types: [authorization_code]}
      - {client_id: spa, app_type: spa, grant_types: [client_credentials]}
    client_grants:
      - {client_id: m2m, audience: https://api.acme.test, scopes: ["read:things", "write:things"]}
      - {client_id: m2m-basic, audience: https://api.acme.test, scopes: ["read:things"]}
      - {client_id: spa, audience: https://api.acme.test, scopes: ["read:things"]}
  - name: globex
    domains: [globex.example.test]
    resource_servers:
      - {identifier: https://api.globex.test, name: Globex API, scopes: [{value: "read:things"}]}
    clients:
      - {client_id: globex-m2m, app_type: non_interactive, client_secret: globex-secret, grant_types: [client_credentials]}
    client_grants:
      - {client_id: globex-m2m, audience: https://api.globex.test, scopes: ["read:things"]}
`

type fixture struct {
	st store.Store
	h  *Handlers
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := memory.New()
	f, err := seed.Parse([]byte(fixtureSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(context.Background(), st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	return &fixture{st: st, h: &Handlers{Store: st, Now: fixedNow}}
}

func (f *fixture) tenantID(t *testing.T, name string) string {
	t.Helper()
	tn, err := f.st.Tenants().GetByName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return tn.ID
}
```

- [ ] **Step 2: Write the failing tests**

```go
// internal/oauth/request_test.go
package oauth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseTokenRequest(t *testing.T) {
	cases := []struct {
		name, contentType, body string
		want                    map[string]string
		wantErr                 string
	}{
		{name: "form", contentType: "application/x-www-form-urlencoded", body: "grant_type=client_credentials&audience=https%3A%2F%2Fapi",
			want: map[string]string{"grant_type": "client_credentials", "audience": "https://api"}},
		// Review focus 4: media type parameters.
		{name: "form with charset", contentType: "application/x-www-form-urlencoded; charset=UTF-8", body: "grant_type=x",
			want: map[string]string{"grant_type": "x"}},
		{name: "json with charset", contentType: "application/json; charset=utf-8", body: `{"grant_type":"x","client_id":"c"}`,
			want: map[string]string{"grant_type": "x", "client_id": "c"}},
		{name: "json number and null", contentType: "application/json", body: `{"grant_type":"x","n":5,"skip":null}`,
			want: map[string]string{"grant_type": "x", "n": "5"}},
		{name: "json object value", contentType: "application/json", body: `{"grant_type":{"a":1}}`, wantErr: "invalid_request"},
		{name: "json malformed", contentType: "application/json", body: `{`, wantErr: "invalid_request"},
		{name: "repeated param", contentType: "application/x-www-form-urlencoded", body: "grant_type=a&grant_type=b", wantErr: "invalid_request"},
		{name: "unsupported type", contentType: "text/plain", body: "grant_type=x", wantErr: "invalid_request"},
		{name: "missing type", contentType: "", body: "grant_type=x", wantErr: "invalid_request"},
		{name: "too large", contentType: "application/x-www-form-urlencoded", body: "grant_type=" + strings.Repeat("a", maxTokenRequestBytes), wantErr: "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			form, oerr := parseTokenRequest(httptest.NewRecorder(), req)
			if tc.wantErr != "" {
				if oerr == nil || oerr.Code != tc.wantErr || oerr.Status != 400 {
					t.Fatalf("err = %+v, want %s", oerr, tc.wantErr)
				}
				return
			}
			if oerr != nil {
				t.Fatalf("unexpected error %+v", oerr)
			}
			if len(form) != len(tc.want) {
				t.Fatalf("form = %v, want %v", form, tc.want)
			}
			for k, v := range tc.want {
				if form.Get(k) != v {
					t.Errorf("%s = %q, want %q", k, form.Get(k), v)
				}
			}
		})
	}
}

func TestQueryParametersAreIgnored(t *testing.T) {
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token?client_secret=leak", strings.NewReader("grant_type=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form, oerr := parseTokenRequest(httptest.NewRecorder(), req)
	if oerr != nil || form.Has("client_secret") {
		t.Fatalf("query parameters must not be read as body parameters: %v %+v", form, oerr)
	}
}
```

```go
// internal/oauth/clientauth_test.go
package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func authRequest(t *testing.T, body url.Values, basicID, basicSecret string) (*http.Request, url.Values) {
	t.Helper()
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(url.QueryEscape(basicID), url.QueryEscape(basicSecret))
	}
	form, oerr := parseTokenRequest(httptest.NewRecorder(), req)
	if oerr != nil {
		t.Fatal(oerr)
	}
	return req, form
}

func TestAuthenticateClient(t *testing.T) {
	f := newFixture(t)
	acme := f.tenantID(t, "acme")
	globex := f.tenantID(t, "globex")

	cases := []struct {
		name          string
		tenantID      string
		body          url.Values
		basicID       string
		basicSecret   string
		wantClient    string
		wantCode      string
		wantStatus    int
		wantChallenge bool
	}{
		{name: "post", tenantID: acme, body: url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, wantClient: "m2m"},
		// Review focus 3: reserved characters in Basic credentials.
		{name: "basic with reserved chars", tenantID: acme, basicID: "m2m-basic", basicSecret: "p@ss:w+rd", wantClient: "m2m-basic"},
		{name: "basic plus matching body client_id", tenantID: acme, body: url.Values{"client_id": {"m2m-basic"}}, basicID: "m2m-basic", basicSecret: "p@ss:w+rd", wantClient: "m2m-basic"},
		{name: "public client", tenantID: acme, body: url.Values{"client_id": {"spa"}}, wantClient: "spa"},
		{name: "wrong secret post", tenantID: acme, body: url.Values{"client_id": {"m2m"}, "client_secret": {"nope"}}, wantCode: "invalid_client", wantStatus: 401},
		{name: "wrong secret basic", tenantID: acme, basicID: "m2m-basic", basicSecret: "nope", wantCode: "invalid_client", wantStatus: 401, wantChallenge: true},
		{name: "unknown client", tenantID: acme, body: url.Values{"client_id": {"ghost"}, "client_secret": {"x"}}, wantCode: "invalid_client", wantStatus: 401},
		{name: "no client id", tenantID: acme, body: url.Values{}, wantCode: "invalid_client", wantStatus: 401},
		{name: "method mismatch post for basic client", tenantID: acme, body: url.Values{"client_id": {"m2m-basic"}, "client_secret": {"p@ss:w+rd"}}, wantCode: "invalid_client", wantStatus: 401},
		{name: "method mismatch basic for post client", tenantID: acme, basicID: "m2m", basicSecret: "m2m-secret", wantCode: "invalid_client", wantStatus: 401, wantChallenge: true},
		{name: "confidential client without secret", tenantID: acme, body: url.Values{"client_id": {"m2m"}}, wantCode: "invalid_client", wantStatus: 401},
		// Review focus 2: two methods at once.
		{name: "basic and body secret", tenantID: acme, body: url.Values{"client_secret": {"p@ss:w+rd"}}, basicID: "m2m-basic", basicSecret: "p@ss:w+rd", wantCode: "invalid_request", wantStatus: 400},
		{name: "basic and different body client_id", tenantID: acme, body: url.Values{"client_id": {"m2m"}}, basicID: "m2m-basic", basicSecret: "p@ss:w+rd", wantCode: "invalid_request", wantStatus: 400},
		// Review focus 5: tenant isolation.
		{name: "client from other tenant", tenantID: globex, body: url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, wantCode: "invalid_client", wantStatus: 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, form := authRequest(t, tc.body, tc.basicID, tc.basicSecret)
			c, oerr := f.h.authenticateClient(context.Background(), req, form, tc.tenantID)
			if tc.wantClient != "" {
				if oerr != nil {
					t.Fatalf("unexpected error %+v", oerr)
				}
				if c.ClientID != tc.wantClient {
					t.Fatalf("client = %s, want %s", c.ClientID, tc.wantClient)
				}
				return
			}
			if oerr == nil || oerr.Code != tc.wantCode || oerr.Status != tc.wantStatus || oerr.basicChallenge != tc.wantChallenge {
				t.Fatalf("err = %+v, want %s/%d challenge=%v", oerr, tc.wantCode, tc.wantStatus, tc.wantChallenge)
			}
		})
	}
}

func TestExpiredSecretRejected(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acme := f.tenantID(t, "acme")
	c, _ := f.st.Clients().Get(ctx, acme, "m2m")
	old, _ := secrets.Hash("old-secret")
	expired := fixedNow().Add(-time.Minute)
	c.Secrets = append([]store.ClientSecret{{Hash: old, CreatedAt: fixedNow().Add(-time.Hour), ExpiresAt: &expired}}, c.Secrets...)
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}

	req, form := authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"old-secret"}}, "", "")
	if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr == nil || oerr.Code != "invalid_client" {
		t.Fatalf("expired secret accepted: %+v", oerr)
	}
	req, form = authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, "", "")
	if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr != nil {
		t.Fatalf("current secret rejected: %+v", oerr)
	}
}

func TestWriteErrorHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, invalidClient("client authentication failed", true))
	if rec.Code != 401 {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("headers = %v", rec.Header())
	}
	if !strings.Contains(rec.Body.String(), `"error":"invalid_client"`) {
		t.Fatalf("body = %s", rec.Body)
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/oauth/`
Expected: FAIL: `undefined: parseTokenRequest`, `undefined: Handlers`

- [ ] **Step 4: Implement**

```go
// internal/oauth/handlers.go

// Package oauth implements the OAuth 2.0 endpoints of the Authentication
// API.
package oauth

import (
	"log/slog"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type Handlers struct {
	Store store.Store
	Log   *slog.Logger
	Now   func() time.Time
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}
```

```go
// internal/oauth/errors.go
package oauth

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
)

// Error is an OAuth 2.0 error response (RFC 6749 §5.2).
type Error struct {
	Status      int
	Code        string
	Description string
	// basicChallenge adds WWW-Authenticate. RFC 6749 §5.2 requires it when
	// a client that used HTTP Basic fails to authenticate.
	basicChallenge bool
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

func invalidRequest(desc string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_request", Description: desc}
}

func invalidClient(desc string, basic bool) *Error {
	return &Error{Status: http.StatusUnauthorized, Code: "invalid_client", Description: desc, basicChallenge: basic}
}

func unauthorizedClient(desc string) *Error {
	return &Error{Status: http.StatusForbidden, Code: "unauthorized_client", Description: desc}
}

func unsupportedGrantType(desc string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "unsupported_grant_type", Description: desc}
}

func invalidScope(desc string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_scope", Description: desc}
}

func accessDenied(desc string) *Error {
	return &Error{Status: http.StatusForbidden, Code: "access_denied", Description: desc}
}

func serverError() *Error {
	return &Error{Status: http.StatusInternalServerError, Code: "server_error", Description: "internal error"}
}

// noStore marks a response as uncacheable (RFC 6749 §5.1).
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func writeError(w http.ResponseWriter, e *Error) {
	noStore(w)
	if e.basicChallenge {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	httpx.WriteError(w, e.Status, e.Code, e.Description)
}
```

```go
// internal/oauth/request.go
package oauth

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
)

const maxTokenRequestBytes = 64 << 10

// parseTokenRequest reads the body of a token endpoint request. Auth0 SDKs
// send both form-encoded and JSON bodies, so both are accepted. JSON
// values must be scalars and are converted to strings. Query parameters
// are never read: credentials must not travel in URLs.
func parseTokenRequest(w http.ResponseWriter, r *http.Request) (url.Values, *Error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBytes)
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, invalidRequest("Content-Type must be application/x-www-form-urlencoded or application/json")
	}
	switch mediaType {
	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return nil, invalidRequest("malformed or oversized form body")
		}
		for k, vs := range r.PostForm {
			if len(vs) > 1 {
				return nil, invalidRequest(fmt.Sprintf("parameter %q is repeated", k))
			}
		}
		return r.PostForm, nil
	case "application/json":
		var raw map[string]any
		dec := json.NewDecoder(r.Body)
		dec.UseNumber()
		if err := dec.Decode(&raw); err != nil {
			return nil, invalidRequest("malformed or oversized JSON body")
		}
		form := url.Values{}
		for k, v := range raw {
			switch x := v.(type) {
			case string:
				form.Set(k, x)
			case json.Number:
				form.Set(k, x.String())
			case bool:
				form.Set(k, strconv.FormatBool(x))
			case nil:
				// null is treated as absent
			default:
				return nil, invalidRequest(fmt.Sprintf("parameter %q must be a string", k))
			}
		}
		return form, nil
	default:
		return nil, invalidRequest("Content-Type must be application/x-www-form-urlencoded or application/json")
	}
}
```

```go
// internal/oauth/clientauth.go
package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const authFailed = "client authentication failed"

// authenticateClient implements token endpoint client authentication
// (RFC 6749 §2.3). The method used must be the one the client is
// registered with. Failures share one description so responses do not
// reveal which part was wrong; the reason is logged instead.
func (h *Handlers) authenticateClient(ctx context.Context, r *http.Request, form url.Values, tenantID string) (*store.Client, *Error) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
	if hasBasic {
		// RFC 6749 §2.3.1: credentials are form-urlencoded before base64.
		id, err1 := url.QueryUnescape(basicID)
		secret, err2 := url.QueryUnescape(basicSecret)
		if err1 != nil || err2 != nil {
			return nil, invalidClient(authFailed, true)
		}
		basicID, basicSecret = id, secret
		if form.Get("client_secret") != "" {
			return nil, invalidRequest("use only one client authentication method")
		}
		if id := form.Get("client_id"); id != "" && id != basicID {
			return nil, invalidRequest("client_id does not match the HTTP Basic credentials")
		}
	}

	clientID, method, secret := form.Get("client_id"), store.AuthMethodNone, ""
	switch {
	case hasBasic:
		clientID, method, secret = basicID, store.AuthMethodClientSecretBasic, basicSecret
	case form.Get("client_secret") != "":
		method, secret = store.AuthMethodClientSecretPost, form.Get("client_secret")
	}
	if clientID == "" {
		return nil, invalidClient(authFailed, hasBasic)
	}

	c, err := h.Store.Clients().Get(ctx, tenantID, clientID)
	if errors.Is(err, store.ErrNotFound) {
		h.log().InfoContext(ctx, "client authentication failed: unknown client", "tenant", tenantID, "client_id", clientID)
		return nil, invalidClient(authFailed, hasBasic)
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load client", "tenant", tenantID, "client_id", clientID, "err", err)
		return nil, serverError()
	}
	if c.TokenEndpointAuthMethod != method {
		h.log().InfoContext(ctx, "client authentication failed: method mismatch",
			"tenant", tenantID, "client_id", clientID, "registered", c.TokenEndpointAuthMethod, "used", method)
		return nil, invalidClient(authFailed, hasBasic)
	}
	if method != store.AuthMethodNone && !h.secretValid(c, secret) {
		h.log().InfoContext(ctx, "client authentication failed: bad secret", "tenant", tenantID, "client_id", clientID)
		return nil, invalidClient(authFailed, hasBasic)
	}
	return c, nil
}

func (h *Handlers) secretValid(c *store.Client, secret string) bool {
	now := h.now()
	for _, s := range c.Secrets {
		if s.ExpiresAt != nil && !now.Before(*s.ExpiresAt) {
			continue
		}
		if ok, err := secrets.Verify(s.Hash, secret); err == nil && ok {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/oauth/`
Expected: `ok`

- [ ] **Step 6: Commit**

```bash
git add internal/oauth
git commit -m "feat(oauth): parse token requests and authenticate clients"
```

---

### Task 14: Access token minting

**Files:**
- Create: `internal/oauth/minter.go`, `internal/oauth/minter_test.go`

**Interfaces:**
- Consumes: `keys.Manager.Sign`, `keys.Manager.JWKS`, `secrets.RandomString`.
- Produces (package `oauth`):
  - `type Minter struct { Keys *keys.Manager; Now func() time.Time }`
  - `type AccessTokenParams struct { TenantID, Issuer, Subject, ClientID, GrantType string; Audience, Scopes []string; Lifetime time.Duration }`
  - `func (m *Minter) AccessToken(ctx, p AccessTokenParams) (string, error)`
  - `const DefaultAccessTokenLifetime = 24 * time.Hour`

- [ ] **Step 1: Write the failing test**

```go
// internal/oauth/minter_test.go
package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func newTestKeys(t *testing.T, tenantIDs ...string) *keys.Manager {
	t.Helper()
	st := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{9}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	for _, id := range tenantIDs {
		if err := km.Ensure(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	return km
}

// verifyToken checks the signature against the tenant's JWKS and returns
// the raw claims and the header kid.
func verifyToken(t *testing.T, km *keys.Manager, tenantID, raw string) (map[string]any, string) {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	set, _ := km.JWKS(context.Background(), tenantID)
	kid := tok.Headers[0].KeyID
	ks := set.Key(kid)
	if len(ks) != 1 {
		t.Fatalf("kid %q not in tenant JWKS", kid)
	}
	var claims map[string]any
	if err := tok.Claims(ks[0].Key, &claims); err != nil {
		t.Fatal(err)
	}
	return claims, kid
}

func TestAccessTokenClaims(t *testing.T) {
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	raw, err := m.AccessToken(context.Background(), AccessTokenParams{
		TenantID:  "ten_a",
		Issuer:    "https://a.example.test/",
		Subject:   "m2m@clients",
		Audience:  []string{"https://api.test"},
		ClientID:  "m2m",
		Scopes:    []string{"read:things", "write:things"},
		GrantType: "client-credentials",
		Lifetime:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := verifyToken(t, km, "ten_a", raw)
	iat := float64(fixedNow().Unix())
	want := map[string]any{
		"iss":   "https://a.example.test/",
		"sub":   "m2m@clients",
		"aud":   "https://api.test", // single audience is a string
		"azp":   "m2m",
		"scope": "read:things write:things",
		"gty":   "client-credentials",
		"iat":   iat,
		"exp":   iat + 3600,
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("%s = %#v, want %#v", k, claims[k], v)
		}
	}
	if jti, _ := claims["jti"].(string); len(jti) != 24 {
		t.Errorf("jti = %v", claims["jti"])
	}
}

func TestAccessTokenOptionalClaims(t *testing.T) {
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	raw, err := m.AccessToken(context.Background(), AccessTokenParams{
		TenantID: "ten_a", Issuer: "https://a.example.test/", Subject: "u1", ClientID: "c",
		Audience: []string{"https://api.test", "https://a.example.test/userinfo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := verifyToken(t, km, "ten_a", raw)
	aud, _ := json.Marshal(claims["aud"])
	if string(aud) != `["https://api.test","https://a.example.test/userinfo"]` {
		t.Errorf("aud = %s, want array", aud)
	}
	if _, ok := claims["gty"]; ok {
		t.Error("empty gty must be omitted")
	}
	if _, ok := claims["scope"]; ok {
		t.Error("empty scope must be omitted")
	}
	if claims["exp"].(float64)-claims["iat"].(float64) != DefaultAccessTokenLifetime.Seconds() {
		t.Errorf("default lifetime not applied: %v", claims)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/oauth/ -run AccessToken`
Expected: FAIL: `undefined: Minter`

- [ ] **Step 3: Implement**

```go
// internal/oauth/minter.go
package oauth

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
)

// DefaultAccessTokenLifetime applies when the resource server sets none.
const DefaultAccessTokenLifetime = 24 * time.Hour

type Minter struct {
	Keys *keys.Manager
	Now  func() time.Time
}

type AccessTokenParams struct {
	TenantID string
	Issuer   string
	Subject  string
	Audience []string
	ClientID string
	Scopes   []string
	// GrantType is the gty claim, e.g. "client-credentials". Empty omits it.
	GrantType string
	// Lifetime defaults to DefaultAccessTokenLifetime when zero.
	Lifetime time.Duration
}

type accessTokenClaims struct {
	Issuer          string   `json:"iss"`
	Subject         string   `json:"sub"`
	Audience        audience `json:"aud"`
	IssuedAt        int64    `json:"iat"`
	Expiry          int64    `json:"exp"`
	Scope           string   `json:"scope,omitempty"`
	AuthorizedParty string   `json:"azp"`
	GrantType       string   `json:"gty,omitempty"`
	ID              string   `json:"jti"`
}

// audience encodes as a string when it has one element and as an array
// otherwise.
type audience []string

func (a audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// AccessToken returns a signed JWT access token.
func (m *Minter) AccessToken(ctx context.Context, p AccessTokenParams) (string, error) {
	lifetime := p.Lifetime
	if lifetime <= 0 {
		lifetime = DefaultAccessTokenLifetime
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	iat := now().Unix()
	return m.Keys.Sign(ctx, p.TenantID, accessTokenClaims{
		Issuer:          p.Issuer,
		Subject:         p.Subject,
		Audience:        audience(p.Audience),
		IssuedAt:        iat,
		Expiry:          iat + int64(lifetime/time.Second),
		Scope:           strings.Join(p.Scopes, " "),
		AuthorizedParty: p.ClientID,
		GrantType:       p.GrantType,
		ID:              secrets.RandomString(24),
	})
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/oauth/`
Expected: `ok`

- [ ] **Step 5: Record the `jti` decision** in `docs/compat/decisions.md` (append):

```markdown
## D-0001: Access tokens carry `jti`

- **Context:** Public Auth0 docs list the standard access token claims but do not say whether a token ID is included.
- **Sources:** RFC 9068 §2.2 (JWT access token profile requires `jti`); RFC 7519 §4.1.7.
- **Decision:** Every access token has a random 24-character `jti`.
- **Rationale:** It follows the JWT access token standard and enables future revocation lists. Clients that ignore unknown claims are unaffected.
```

- [ ] **Step 6: Commit**

```bash
git add internal/oauth docs/compat/decisions.md
git commit -m "feat(oauth): mint signed JWT access tokens"
```

---

### Task 15: `/oauth/token` with the client_credentials grant

**Files:**
- Modify: `internal/oauth/handlers.go` (add `Minter` field), `internal/oauth/fixture_test.go` (add keys and minter)
- Create: `internal/oauth/token.go`, `internal/oauth/scopes.go`, `internal/oauth/grant_client_credentials.go`
- Create: `internal/oauth/scopes_test.go`, `internal/oauth/token_test.go`
- Modify: `docs/compat/decisions.md`

**Interfaces:**
- Consumes:
  - `authapi.TokenResponse` (generated; fields `AccessToken`, `TokenType`, `ExpiresIn int`, `Scope *string`)
  - `tenant.FromContext`, `tenant.NewResolver`
  - `Minter.AccessToken`, `authenticateClient`, `parseTokenRequest`, `writeError`, `noStore`
  - `contract.Wrap`, `contract.WrapResponses`, and `verifyToken` / `newTestKeys` from Task 14's test file
- Produces:
  - `func (h *Handlers) OauthToken(w http.ResponseWriter, r *http.Request)`, which matches `authapi.ServerInterface`
  - `Handlers.Minter *Minter`
  - `func resolveScopes(requested string, granted []string, defined []store.Scope) ([]string, *Error)`

- [ ] **Step 1: Extend the fixture**

In `internal/oauth/handlers.go`, add the field `Minter *Minter` to `Handlers`.

In `internal/oauth/fixture_test.go`:
- Add a `keys *keys.Manager` field to `fixture`.
- In `newFixture`, after `seed.Apply`, ensure keys for every tenant and construct the minter:

```go
	km := newTestKeys(t)
	tenants, _ := st.Tenants().List(context.Background())
	for _, tn := range tenants {
		if err := km.Ensure(context.Background(), tn.ID); err != nil {
			t.Fatal(err)
		}
	}
	return &fixture{st: st, keys: km, h: &Handlers{Store: st, Now: fixedNow, Minter: &Minter{Keys: km, Now: fixedNow}}}
```

Note: `newTestKeys` builds its own memory store for keys. Keys and the other entities may live in different stores here because `keys.Manager` only touches `SigningKeys`.

Add this method to `fixture`:

```go
// server returns the token endpoint behind tenant resolution and contract
// validation. Use strict=false for tests that send malformed requests.
func (f *fixture) server(t *testing.T, strict bool) http.Handler {
	h := tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthToken))
	if strict {
		return contract.Wrap(t, h)
	}
	return contract.WrapResponses(t, h)
}
```

Add the imports `net/http`, `github.com/zeroauthy/zeroauthy/internal/keys`, `.../internal/tenant`, and `.../internal/testutil/contract`.

- [ ] **Step 2: Write the failing tests**

```go
// internal/oauth/scopes_test.go
package oauth

import (
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestResolveScopes(t *testing.T) {
	defined := []store.Scope{{Value: "a"}, {Value: "b"}, {Value: "c"}}
	granted := []string{"a", "b", "removed"}
	cases := []struct {
		requested, want, wantErr string
	}{
		{requested: "", want: "a b"},               // default: everything granted and still defined
		{requested: "b", want: "b"},                // narrowing
		{requested: "  b   a b ", want: "b a"},     // whitespace and duplicates
		{requested: "a c", want: "a"},              // c defined but not granted → dropped
		{requested: "removed", wantErr: "invalid_scope"}, // granted but no longer defined
		{requested: "zzz", wantErr: "invalid_scope"},
	}
	for _, tc := range cases {
		got, oerr := resolveScopes(tc.requested, granted, defined)
		if tc.wantErr != "" {
			if oerr == nil || oerr.Code != tc.wantErr {
				t.Errorf("resolveScopes(%q) err = %+v, want %s", tc.requested, oerr, tc.wantErr)
			}
			continue
		}
		if oerr != nil || strings.Join(got, " ") != tc.want {
			t.Errorf("resolveScopes(%q) = %v, %+v; want %q", tc.requested, got, oerr, tc.want)
		}
	}
}
```

```go
// internal/oauth/token_test.go
package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type tokenCall struct {
	host        string
	form        url.Values
	json        string // when set, sent as an application/json body instead of form
	basicID     string
	basicSecret string
}

func (f *fixture) call(t *testing.T, strict bool, c tokenCall) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var req *http.Request
	if c.json != "" {
		req = httptest.NewRequest("POST", "https://"+c.host+"/oauth/token", strings.NewReader(c.json))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest("POST", "https://"+c.host+"/oauth/token", strings.NewReader(c.form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c.basicID != "" {
		req.SetBasicAuth(url.QueryEscape(c.basicID), url.QueryEscape(c.basicSecret))
	}
	rec := httptest.NewRecorder()
	f.server(t, strict).ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func cc(clientID, secret string, extra ...string) url.Values {
	v := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}}
	if secret != "" {
		v.Set("client_secret", secret)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func TestClientCredentialsSuccess(t *testing.T) {
	f := newFixture(t)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test",
		form: cc("m2m", "m2m-secret", "audience", "https://api.acme.test")})
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	if body["token_type"] != "Bearer" || body["expires_in"] != float64(3600) || body["scope"] != "read:things write:things" {
		t.Errorf("body = %v", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Errorf("headers = %v", rec.Header())
	}
	claims, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	want := map[string]any{
		"iss": "https://acme.example.test/", "sub": "m2m@clients", "aud": "https://api.acme.test",
		"azp": "m2m", "gty": "client-credentials", "scope": "read:things write:things",
		"exp": float64(fixedNow().Unix() + 3600),
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("claim %s = %#v, want %#v", k, claims[k], v)
		}
	}
}

func TestClientCredentialsVariants(t *testing.T) {
	f := newFixture(t)

	t.Run("json body", func(t *testing.T) {
		rec, body := f.call(t, true, tokenCall{host: "acme.example.test",
			json: `{"grant_type":"client_credentials","client_id":"m2m","client_secret":"m2m-secret","audience":"https://api.acme.test"}`})
		if rec.Code != 200 {
			t.Fatalf("status %d: %v", rec.Code, body)
		}
	})

	t.Run("basic auth", func(t *testing.T) {
		rec, body := f.call(t, true, tokenCall{host: "acme.example.test",
			form:    url.Values{"grant_type": {"client_credentials"}, "audience": {"https://api.acme.test"}},
			basicID: "m2m-basic", basicSecret: "p@ss:w+rd"})
		if rec.Code != 200 || body["scope"] != "read:things" {
			t.Fatalf("status %d: %v", rec.Code, body)
		}
	})

	t.Run("default audience", func(t *testing.T) {
		rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret")})
		if rec.Code != 200 {
			t.Fatalf("status %d: %v", rec.Code, body)
		}
		claims, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
		if claims["aud"] != "https://api.acme.test" {
			t.Fatalf("aud = %v", claims["aud"])
		}
	})

	t.Run("token lifetime default", func(t *testing.T) {
		rec, body := f.call(t, true, tokenCall{host: "globex.example.test", form: cc("globex-m2m", "globex-secret", "audience", "https://api.globex.test")})
		if rec.Code != 200 || body["expires_in"] != float64(86400) {
			t.Fatalf("status %d: %v", rec.Code, body)
		}
	})

	t.Run("scope narrowing", func(t *testing.T) {
		rec, body := f.call(t, true, tokenCall{host: "acme.example.test",
			form: cc("m2m", "m2m-secret", "audience", "https://api.acme.test", "scope", "write:things  write:things")})
		if rec.Code != 200 || body["scope"] != "write:things" {
			t.Fatalf("status %d: %v", rec.Code, body)
		}
	})
}

func TestTokenErrors(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name       string
		strict     bool
		call       tokenCall
		wantStatus int
		wantError  string
	}{
		{"missing grant_type", false, tokenCall{host: "acme.example.test", form: url.Values{"client_id": {"m2m"}}}, 400, "invalid_request"},
		{"unsupported grant", true, tokenCall{host: "acme.example.test", form: url.Values{"grant_type": {"password"}, "client_id": {"m2m"}}}, 400, "unsupported_grant_type"},
		{"bad secret", true, tokenCall{host: "acme.example.test", form: cc("m2m", "wrong")}, 401, "invalid_client"},
		{"grant type not allowed", true, tokenCall{host: "acme.example.test", form: cc("web", "web-secret")}, 403, "unauthorized_client"},
		{"public client", true, tokenCall{host: "acme.example.test", form: cc("spa", "")}, 403, "unauthorized_client"},
		{"unknown audience", true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", "https://nope.test")}, 403, "access_denied"},
		{"no grant for audience", true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", "https://billing.acme.test")}, 403, "access_denied"},
		{"no audience and no default", true, tokenCall{host: "globex.example.test", form: cc("globex-m2m", "globex-secret")}, 400, "invalid_request"},
		{"no requested scope granted", true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "scope", "read:invoices")}, 400, "invalid_scope"},
		// Review focus 5: cross-tenant.
		{"client of other tenant", true, tokenCall{host: "globex.example.test", form: cc("m2m", "m2m-secret", "audience", "https://api.globex.test")}, 401, "invalid_client"},
		{"audience of other tenant", true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", "https://api.globex.test")}, 403, "access_denied"},
		{"unknown host", true, tokenCall{host: "nobody.test", form: cc("m2m", "m2m-secret")}, 404, "not_found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := f.call(t, tc.strict, tc.call)
			if rec.Code != tc.wantStatus || body["error"] != tc.wantError {
				t.Fatalf("got %d %v, want %d %s", rec.Code, body, tc.wantStatus, tc.wantError)
			}
			if _, leaked := body["access_token"]; leaked {
				t.Fatal("error response contains a token")
			}
		})
	}

	t.Run("basic failure sends challenge", func(t *testing.T) {
		rec, _ := f.call(t, true, tokenCall{host: "acme.example.test",
			form: url.Values{"grant_type": {"client_credentials"}}, basicID: "m2m-basic", basicSecret: "wrong"})
		if rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("got %d %v", rec.Code, rec.Header())
		}
	})
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/oauth/`
Expected: FAIL: `f.h.OauthToken undefined` and `undefined: resolveScopes`

- [ ] **Step 4: Implement**

```go
// internal/oauth/scopes.go
package oauth

import (
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// resolveScopes returns the scopes to issue. Only scopes that are both
// granted to the client and still defined by the resource server count.
// With no request, all of them are issued. Requested scopes that don't
// count are dropped. If a request names scopes and none count, the result
// is invalid_scope rather than an empty token.
func resolveScopes(requested string, granted []string, defined []store.Scope) ([]string, *Error) {
	var valid []string
	for _, g := range granted {
		if slices.ContainsFunc(defined, func(s store.Scope) bool { return s.Value == g }) {
			valid = append(valid, g)
		}
	}
	req := strings.Fields(requested)
	if len(req) == 0 {
		return valid, nil
	}
	var out []string
	for _, r := range req {
		if slices.Contains(valid, r) && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, invalidScope("none of the requested scopes are granted to this client")
	}
	return out, nil
}
```

```go
// internal/oauth/token.go
package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type grantHandler func(h *Handlers, ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error)

// grantHandlers maps grant_type to its implementation. Later plans add
// authorization_code, refresh_token, password, password-realm, and
// device_code.
var grantHandlers = map[string]grantHandler{
	"client_credentials": (*Handlers).clientCredentials,
}

// OauthToken implements POST /oauth/token.
func (h *Handlers) OauthToken(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		writeError(w, serverError())
		return
	}
	resp, oerr := h.token(w, r, res)
	if oerr != nil {
		writeError(w, oerr)
		return
	}
	noStore(w)
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handlers) token(w http.ResponseWriter, r *http.Request, res tenant.Resolved) (*authapi.TokenResponse, *Error) {
	form, oerr := parseTokenRequest(w, r)
	if oerr != nil {
		return nil, oerr
	}
	grantType := form.Get("grant_type")
	if grantType == "" {
		return nil, invalidRequest("grant_type is required")
	}
	grant, ok := grantHandlers[grantType]
	if !ok {
		return nil, unsupportedGrantType(fmt.Sprintf("grant type %q is not supported", grantType))
	}
	client, oerr := h.authenticateClient(r.Context(), r, form, res.Tenant.ID)
	if oerr != nil {
		return nil, oerr
	}
	if !slices.Contains(client.GrantTypes, grantType) {
		return nil, unauthorizedClient(fmt.Sprintf("grant type %q is not allowed for this client", grantType))
	}
	return grant(h, r.Context(), res, client, form)
}
```

```go
// internal/oauth/grant_client_credentials.go
package oauth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// clientCredentials implements RFC 6749 §4.4. The client must be
// confidential and hold a client grant for the audience.
func (h *Handlers) clientCredentials(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	if c.TokenEndpointAuthMethod == store.AuthMethodNone {
		return nil, unauthorizedClient("client_credentials requires a confidential client")
	}
	tenantID := res.Tenant.ID
	aud := form.Get("audience")
	if aud == "" {
		aud = res.Tenant.DefaultAudience
	}
	if aud == "" {
		return nil, invalidRequest("audience is required because the tenant has no default audience")
	}

	rs, err := h.Store.ResourceServers().GetByIdentifier(ctx, tenantID, aud)
	if errors.Is(err, store.ErrNotFound) {
		return nil, accessDenied("unknown audience")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load resource server", "tenant", tenantID, "audience", aud, "err", err)
		return nil, serverError()
	}
	grant, err := h.Store.ClientGrants().Find(ctx, tenantID, c.ClientID, aud)
	if errors.Is(err, store.ErrNotFound) {
		return nil, accessDenied("client is not authorized for this audience")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load client grant", "tenant", tenantID, "client_id", c.ClientID, "err", err)
		return nil, serverError()
	}
	scopes, oerr := resolveScopes(form.Get("scope"), grant.Scopes, rs.Scopes)
	if oerr != nil {
		return nil, oerr
	}

	lifetime := time.Duration(rs.TokenLifetime) * time.Second
	if lifetime <= 0 {
		lifetime = DefaultAccessTokenLifetime
	}
	token, err := h.Minter.AccessToken(ctx, AccessTokenParams{
		TenantID:  tenantID,
		Issuer:    res.Issuer(),
		Subject:   c.ClientID + "@clients",
		Audience:  []string{rs.Identifier},
		ClientID:  c.ClientID,
		Scopes:    scopes,
		GrantType: "client-credentials",
		Lifetime:  lifetime,
	})
	if err != nil {
		h.log().ErrorContext(ctx, "mint access token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	resp := &authapi.TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(lifetime / time.Second),
	}
	if len(scopes) > 0 {
		s := strings.Join(scopes, " ")
		resp.Scope = &s
	}
	return resp, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/oauth/ && go vet ./...`
Expected: `ok`, with no `contract:` violations in the output.

- [ ] **Step 6: Record decisions** by appending to `docs/compat/decisions.md`:

```markdown
## D-0002: client_credentials without an audience

- **Context:** A client_credentials request omits `audience` and the tenant has no default audience.
- **Sources:** RFC 6749 §5.2; Auth0 public docs describe `audience` as the target API and a tenant-level default audience.
- **Decision:** `400 invalid_request` with a description naming the missing audience.
- **Rationale:** The request lacks a required parameter, which is the definition of `invalid_request`.

## D-0003: Requested scopes that are not granted

- **Context:** The `scope` parameter names scopes the client grant does not include.
- **Sources:** RFC 6749 §3.3 (the server may issue a narrower scope and must then return `scope`), §5.2 (`invalid_scope`).
- **Decision:** Ungranted scopes are dropped and the response's `scope` lists what was issued. If none of the requested scopes are granted, respond `400 invalid_scope`.
- **Rationale:** Narrowing is standard; issuing a token with no requested permission is more likely a client bug than intent.

## D-0004: Strict token endpoint client authentication

- **Context:** A client authenticates with a method other than its registered `token_endpoint_auth_method`, or with two methods at once.
- **Sources:** RFC 6749 §2.3 ("MUST NOT use more than one authentication method in each request"); RFC 7591 §2 (`token_endpoint_auth_method`).
- **Decision:** A mismatched method → `401 invalid_client`. Two methods → `400 invalid_request`. The server log records the registered and used methods.
- **Rationale:** It follows the RFCs and avoids ambiguity about which credential was checked.
```

- [ ] **Step 7: Commit**

```bash
git add internal/oauth docs/compat/decisions.md
git commit -m "feat(oauth): implement /oauth/token client_credentials grant"
```

---
### Task 16: HTTP server, app wiring, `serve` and `seed` commands

**Files:**
- Create: `internal/storage/open.go`, `internal/storage/open_test.go`
- Create: `internal/server/server.go`, `internal/server/docs.go`, `internal/server/log.go`, `internal/server/server_test.go`
- Create: `internal/app/app.go`, `internal/app/app_test.go`
- Create: `cmd/zeroauthy/serve.go`, `cmd/zeroauthy/seed.go`, `cmd/zeroauthy/logger.go`, `cmd/zeroauthy/seed_test.go`
- Modify: `cmd/zeroauthy/root.go` (register the commands)

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `storage.Open(ctx, dsn string) (store.Store, error)`
  - `server.Deps{ Store store.Store; Keys *keys.Manager; Resolver *tenant.Resolver; Log *slog.Logger }`, `server.New(d Deps) http.Handler`
  - `app.New(ctx, cfg *config.Config, log *slog.Logger) (*App, error)`, `(*App).Handler() http.Handler`, `(*App).Serve(ctx) error`, `(*App).Close() error`
  - CLI: `zeroauthy serve --config <path>`, `zeroauthy seed --config <path> [--file <seed.yaml>]`

- [ ] **Step 1: Write the failing tests**

```go
// internal/storage/open_test.go
package storage

import (
	"context"
	"strings"
	"testing"
)

func TestOpen(t *testing.T) {
	st, err := Open(context.Background(), "memory://")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	for dsn, want := range map[string]string{
		"postgres://localhost/db": `driver "postgres" is not available`,
		"nonsense":                "scheme",
		"":                        "scheme",
	} {
		if _, err := Open(context.Background(), dsn); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Open(%q) err = %v, want it to contain %q", dsn, err, want)
		}
	}
}
```

```go
// internal/server/server_test.go
package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/api"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

const testSeed = `
tenants:
  - name: acme
    domains: [acme.example.test]
    resource_servers: [{identifier: "https://api.acme.test", scopes: [{value: "read:things"}]}]
    clients: [{client_id: m2m, app_type: non_interactive, client_secret: s3cret, grant_types: [client_credentials]}]
    client_grants: [{client_id: m2m, audience: "https://api.acme.test", scopes: ["read:things"]}]
`

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	f, err := seed.Parse([]byte(testSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(ctx, st, f, nil); err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if err := km.Ensure(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	return New(Deps{
		Store:    st,
		Keys:     km,
		Resolver: tenant.NewResolver(st.Tenants(), "", false),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func get(h http.Handler, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", target, nil))
	return rec
}

func TestOperationalEndpoints(t *testing.T) {
	h := newTestServer(t)
	if rec := get(h, "http://any.host/healthz"); rec.Code != 200 {
		t.Errorf("healthz %d", rec.Code)
	}
	if rec := get(h, "http://any.host/readyz"); rec.Code != 200 {
		t.Errorf("readyz %d", rec.Code)
	}
	rec := get(h, "http://any.host/openapi.yaml")
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), api.AuthenticationYAML) || rec.Header().Get("Content-Type") != "application/yaml" {
		t.Errorf("openapi.yaml %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = get(h, "http://any.host/docs")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "createApiReference") || !strings.Contains(rec.Body.String(), "/openapi.yaml") {
		t.Errorf("docs %d", rec.Code)
	}
}

func TestAPIRoutesThroughServer(t *testing.T) {
	h := contract.Wrap(t, newTestServer(t))

	if rec := get(h, "https://acme.example.test/.well-known/openid-configuration"); rec.Code != 200 {
		t.Errorf("discovery %d: %s", rec.Code, rec.Body)
	}
	if rec := get(h, "https://acme.example.test/.well-known/jwks.json"); rec.Code != 200 {
		t.Errorf("jwks %d: %s", rec.Code, rec.Body)
	}
	if rec := get(h, "https://unknown.test/.well-known/jwks.json"); rec.Code != 404 {
		t.Errorf("unknown tenant %d", rec.Code)
	}

	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"m2m"}, "client_secret": {"s3cret"}, "audience": {"https://api.acme.test"}}
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "access_token") {
		t.Errorf("token %d: %s", rec.Code, rec.Body)
	}
}
```

> `seed.Apply(ctx, st, f, nil)` passes a nil clock. Make `Apply` default a nil `now` to `time.Now` with this guard at the top of `seed.Apply`: `if now == nil { now = time.Now }`.

```go
// internal/app/app_test.go
package app

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

func TestNewSeedsAndServes(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.yaml")
	if err := os.WriteFile(seedPath, []byte("tenants:\n  - name: acme\n    domains: [acme.example.test]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Storage: config.Storage{DSN: "memory://"}, Seed: seedPath}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "https://acme.example.test/.well-known/jwks.json", nil))
	if rec.Code != 200 || len(rec.Body.String()) < 100 {
		t.Fatalf("jwks after startup: %d %s (keys should be ensured for seeded tenants)", rec.Code, rec.Body)
	}
}

func TestNewRejectsBadSeed(t *testing.T) {
	cfg := &config.Config{Storage: config.Storage{DSN: "memory://"}, Seed: "/nonexistent/seed.yaml"}
	if _, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected error for missing seed file")
	}
}
```

```go
// cmd/zeroauthy/seed_test.go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeedCommand(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.yaml")
	cfgPath := filepath.Join(dir, "zeroauthy.yaml")
	_ = os.WriteFile(seedPath, []byte("tenants:\n  - name: acme\n  - name: globex\n"), 0o600)
	_ = os.WriteFile(cfgPath, []byte("storage:\n  dsn: memory://\n"), 0o600)

	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"seed", "--config", cfgPath, "--file", seedPath})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "2 tenant(s)") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestSeedCommandNeedsFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "zeroauthy.yaml")
	_ = os.WriteFile(cfgPath, []byte("storage:\n  dsn: memory://\n"), 0o600)
	cmd := newRootCmd()
	cmd.SetArgs([]string{"seed", "--config", cfgPath})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "no seed file") {
		t.Fatalf("err = %v", err)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/storage/ ./internal/server/ ./internal/app/ ./cmd/...`
Expected: FAIL. Compile errors: `undefined: Open`, `undefined: New`, `undefined: Deps`, and unknown command `seed`.

- [ ] **Step 3: Implement storage.Open**

```go
// internal/storage/open.go

// Package storage opens a store.Store driver from a DSN.
package storage

import (
	"context"
	"fmt"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// Open returns the driver named by the DSN scheme. Only memory:// exists in
// this release. sqlite, postgres, mysql and plugin drivers come in later
// releases.
func Open(_ context.Context, dsn string) (store.Store, error) {
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" {
		return nil, fmt.Errorf("storage: DSN %q has no scheme (e.g. memory://)", dsn)
	}
	switch u.Scheme {
	case "memory":
		return memory.New(), nil
	default:
		return nil, fmt.Errorf("storage: driver %q is not available in this build", u.Scheme)
	}
}
```

- [ ] **Step 4: Implement the server**

```go
// internal/server/server.go

// Package server assembles zeroauthy's HTTP handler.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/zeroauthy/zeroauthy/api"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/oauth"
	"github.com/zeroauthy/zeroauthy/internal/oidc"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type Deps struct {
	Store    store.Store
	Keys     *keys.Manager
	Resolver *tenant.Resolver
	Log      *slog.Logger
}

// authAPI adapts the handler groups to the generated ServerInterface.
// The var _ assertion fails to compile when api/authentication.yaml gains
// an operation that has no forwarding method here.
type authAPI struct {
	oidc  *oidc.Handlers
	oauth *oauth.Handlers
}

func (a authAPI) Discovery(w http.ResponseWriter, r *http.Request)  { a.oidc.Discovery(w, r) }
func (a authAPI) Jwks(w http.ResponseWriter, r *http.Request)       { a.oidc.Jwks(w, r) }
func (a authAPI) OauthToken(w http.ResponseWriter, r *http.Request) { a.oauth.OauthToken(w, r) }

var _ authapi.ServerInterface = authAPI{}

func New(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, requestLog(d.Log), middleware.Recoverer)

	// Operational endpoints answer on any host.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := d.Store.Ping(ctx); err != nil {
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(api.AuthenticationYAML)
	})
	r.Get("/docs", serveDocs)

	// Authentication API: every route is tenant-scoped.
	r.Group(func(tr chi.Router) {
		tr.Use(d.Resolver.Middleware)
		authapi.HandlerFromMux(authAPI{
			oidc:  &oidc.Handlers{Keys: d.Keys, Log: d.Log},
			oauth: &oauth.Handlers{Store: d.Store, Log: d.Log, Minter: &oauth.Minter{Keys: d.Keys}},
		}, tr)
	})
	return r
}
```


```go
// internal/server/docs.go
package server

import "net/http"

// scalarVersion pins the API reference UI loaded from the jsDelivr CDN.
const scalarVersion = "1.74.0"

var docsPage = []byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>zeroauthy Authentication API</title>
</head>
<body>
  <div id="app"></div>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference@` + scalarVersion + `"></script>
  <script>Scalar.createApiReference('#app', { url: '/openapi.yaml' })</script>
</body>
</html>
`)

func serveDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(docsPage)
}
```

```go
// internal/server/log.go
package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

func requestLog(log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			log.InfoContext(r.Context(), "request",
				"method", r.Method,
				"host", r.Host,
				"path", r.URL.Path,
				"status", ww.Status(),
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", middleware.GetReqID(r.Context()),
			)
		})
	}
}
```

- [ ] **Step 5: Implement the app**

```go
// internal/app/app.go

// Package app wires configuration, storage, keys and the HTTP server.
package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/server"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type App struct {
	cfg     *config.Config
	log     *slog.Logger
	store   store.Store
	handler http.Handler
}

func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (*App, error) {
	st, err := storage.Open(ctx, cfg.Storage.DSN)
	if err != nil {
		return nil, err
	}
	a, err := build(ctx, cfg, log, st)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	return a, nil
}

func build(ctx context.Context, cfg *config.Config, log *slog.Logger, st store.Store) (*App, error) {
	masterKey, err := cfg.Security.MasterKeyBytes()
	if err != nil {
		return nil, err
	}
	if masterKey == nil {
		if !strings.HasPrefix(cfg.Storage.DSN, "memory:") {
			return nil, errors.New("app: security.master_key or security.master_key_file is required with persistent storage")
		}
		log.Warn("no master key configured; using an ephemeral key (acceptable only with memory storage)")
		masterKey = make([]byte, 32)
		if _, err := rand.Read(masterKey); err != nil {
			return nil, err
		}
	}
	wrapper, err := keys.NewLocalWrapper(masterKey)
	if err != nil {
		return nil, err
	}
	km := keys.NewManager(st.SigningKeys(), wrapper)

	if cfg.Seed != "" {
		f, err := seed.Load(cfg.Seed)
		if err != nil {
			return nil, err
		}
		if err := seed.Apply(ctx, st, f, time.Now); err != nil {
			return nil, err
		}
		log.Info("applied seed", "file", cfg.Seed, "tenants", len(f.Tenants))
	}

	tenants, err := st.Tenants().List(ctx)
	if err != nil {
		return nil, err
	}
	for _, tn := range tenants {
		if err := km.Ensure(ctx, tn.ID); err != nil {
			return nil, fmt.Errorf("app: signing keys for tenant %q: %w", tn.Name, err)
		}
	}

	return &App{
		cfg:   cfg,
		log:   log,
		store: st,
		handler: server.New(server.Deps{
			Store:    st,
			Keys:     km,
			Resolver: tenant.NewResolver(st.Tenants(), cfg.Server.BaseDomain, cfg.Server.TrustProxyHeaders),
			Log:      log,
		}),
	}, nil
}

func (a *App) Handler() http.Handler { return a.handler }

// Serve listens until ctx is cancelled, then shuts down gracefully.
func (a *App) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              a.cfg.Server.Listen,
		Handler:           a.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	tls := a.cfg.Server.TLSCertFile != ""
	errc := make(chan error, 1)
	go func() {
		if tls {
			errc <- srv.ListenAndServeTLS(a.cfg.Server.TLSCertFile, a.cfg.Server.TLSKeyFile)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	a.log.Info("listening", "addr", a.cfg.Server.Listen, "tls", tls)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		a.log.Info("shutting down")
		return srv.Shutdown(shutdownCtx)
	}
}

func (a *App) Close() error { return a.store.Close() }
```

Also in `internal/seed/apply.go`, add as the first line of `Apply`:

```go
	if now == nil {
		now = time.Now
	}
```

- [ ] **Step 6: Implement the commands**

```go
// cmd/zeroauthy/logger.go
package main

import (
	"io"
	"log/slog"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

func newLogger(w io.Writer, c config.Log) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(c.Level)) // validated by config.Load
	opts := &slog.HandlerOptions{Level: level}
	if c.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}
```

```go
// cmd/zeroauthy/serve.go
package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/zeroauthy/zeroauthy/internal/app"
	"github.com/zeroauthy/zeroauthy/internal/config"
)

func newServeCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the HTTP server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath, os.Environ())
			if err != nil {
				return err
			}
			log := newLogger(cmd.ErrOrStderr(), cfg.Log)
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			a, err := app.New(ctx, cfg, log)
			if err != nil {
				return err
			}
			defer a.Close()
			return a.Serve(ctx)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", os.Getenv("ZEROAUTHY_CONFIG"), "path to the YAML config file")
	return cmd
}
```

```go
// cmd/zeroauthy/seed.go
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/storage"
)

func newSeedCmd() *cobra.Command {
	var configPath, file string
	cmd := &cobra.Command{
		Use:   "seed",
		Short: "Apply a declarative seed file to the configured store",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath, os.Environ())
			if err != nil {
				return err
			}
			path := file
			if path == "" {
				path = cfg.Seed
			}
			if path == "" {
				return errors.New("no seed file: pass --file or set seed in the config")
			}
			f, err := seed.Load(path)
			if err != nil {
				return err
			}
			st, err := storage.Open(cmd.Context(), cfg.Storage.DSN)
			if err != nil {
				return err
			}
			defer st.Close()
			if err := seed.Apply(cmd.Context(), st, f, time.Now); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "applied %s: %d tenant(s)\n", path, len(f.Tenants))
			if strings.HasPrefix(cfg.Storage.DSN, "memory:") {
				fmt.Fprintln(cmd.OutOrStdout(), "note: memory storage is discarded when this command exits; the seed was validated only")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", os.Getenv("ZEROAUTHY_CONFIG"), "path to the YAML config file")
	cmd.Flags().StringVarP(&file, "file", "f", "", "seed file (defaults to the config's seed setting)")
	return cmd
}
```

In `root.go`, change `root.AddCommand(newVersionCmd())` to:

```go
	root.AddCommand(newVersionCmd(), newServeCmd(), newSeedCmd())
```

- [ ] **Step 7: Run all tests**

Run: `go mod tidy && go test ./... && go vet ./... && CGO_ENABLED=0 go build -o /dev/null ./cmd/zeroauthy`
Expected: every package `ok`, with no `contract:` violations.

- [ ] **Step 8: Commit**

```bash
git add internal/storage internal/server internal/app internal/seed/apply.go cmd go.mod go.sum
git commit -m "feat: wire HTTP server, app startup, serve and seed commands"
```

---

### Task 17: End-to-end SDK test, documentation, compatibility tracking

**Files:**
- Create: `tests/e2e/package.json`, `tests/e2e/package-lock.json` (generated), `tests/e2e/config.yaml`, `tests/e2e/seed.yaml`, `tests/e2e/m3-client-credentials.mjs`, `tests/e2e/run-m3.sh`
- Create: `README.md`
- Modify: `.github/workflows/ci.yml` (e2e job), `docs/compat/matrix.md`, `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md` (§1.2 SDK naming)

**Interfaces:**
- Consumes: the `zeroauthy serve` binary, with TLS from `ZEROAUTHY_SERVER__TLS_CERT_FILE` and `ZEROAUTHY_SERVER__TLS_KEY_FILE`.
- Produces: `make e2e`, plus a CI job that runs the open-source SDKs as black-box clients.

- [ ] **Step 1: Write the e2e fixtures**

```json
{
  "name": "zeroauthy-e2e",
  "private": true,
  "type": "module",
  "engines": { "node": ">=22" },
  "dependencies": {
    "@auth0/auth0-auth-js": "1.16.1",
    "auth0": "7.4.0",
    "express": "5.3.0",
    "express-oauth2-jwt-bearer": "1.11.0"
  }
}
```

```yaml
# tests/e2e/config.yaml: paths are relative to the repository root.
server:
  listen: ":8443"
storage:
  dsn: memory://
seed: tests/e2e/seed.yaml
log:
  level: debug
  format: text
```

```yaml
# tests/e2e/seed.yaml: test-only credentials; never reuse them.
tenants:
  - name: e2e
    friendly_name: E2E
    domains: ["localhost:8443"]
    resource_servers:
      - identifier: https://api.e2e.local
        name: E2E API
        token_lifetime: 3600
        scopes:
          - {value: "read:things", description: "Read things"}
    clients:
      - client_id: e2e-m2m
        name: E2E machine client
        app_type: non_interactive
        client_secret: e2e-m2m-secret-not-for-production
        grant_types: [client_credentials]
    client_grants:
      - client_id: e2e-m2m
        audience: https://api.e2e.local
        scopes: ["read:things"]
```

- [ ] **Step 2: Write the e2e test** (this is the failing test: the SDKs run as black boxes against our server)

```js
// tests/e2e/m3-client-credentials.mjs
// Black-box test: Auth0's open-source SDKs talk to zeroauthy with only the
// domain changed. See CLEAN_ROOM.md: we observe requests to our own server.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import express from 'express';
import { auth } from 'express-oauth2-jwt-bearer';
import { AuthClient } from '@auth0/auth0-auth-js';
import { AuthenticationClient } from 'auth0/legacy';

const domain = process.env.ZA_DOMAIN ?? 'localhost:8443';
const clientId = 'e2e-m2m';
const clientSecret = 'e2e-m2m-secret-not-for-production';
const audience = 'https://api.e2e.local';

// 1. Current SDK: @auth0/auth0-auth-js (uses OIDC discovery).
const modern = new AuthClient({ domain, clientId, clientSecret });
const t1 = await modern.getTokenByClientCredentials({ audience });
assert.ok(t1.accessToken, '@auth0/auth0-auth-js returned an access token');

// 2. Legacy SDK: node-auth0 v4 AuthenticationClient via auth0/legacy.
const legacy = new AuthenticationClient({ domain, clientId, clientSecret });
const { data: t2 } = await legacy.oauth.clientCredentialsGrant({ audience });
assert.ok(t2.access_token, 'auth0/legacy returned an access token');

// 3. Resource server: express-oauth2-jwt-bearer validates both tokens.
const app = express();
app.get('/protected', auth({ issuerBaseURL: `https://${domain}`, audience }), (req, res) => {
  res.json({ sub: req.auth.payload.sub, scope: req.auth.payload.scope });
});
const server = app.listen(0, '127.0.0.1');
await once(server, 'listening');
const base = `http://127.0.0.1:${server.address().port}`;

try {
  for (const [name, token] of [['auth0-auth-js', t1.accessToken], ['auth0/legacy', t2.access_token]]) {
    const res = await fetch(`${base}/protected`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(res.status, 200, `${name} token accepted by express-oauth2-jwt-bearer`);
    const body = await res.json();
    assert.equal(body.sub, `${clientId}@clients`);
    assert.equal(body.scope, 'read:things');
  }
  const anon = await fetch(`${base}/protected`);
  assert.equal(anon.status, 401, 'request without a token is rejected');
  const forged = await fetch(`${base}/protected`, { headers: { authorization: `Bearer ${t1.accessToken.slice(0, -4)}AAAA` } });
  assert.equal(forged.status, 401, 'token with a broken signature is rejected');
} finally {
  server.close();
}
console.log('e2e m3 client credentials: OK');
```

```bash
#!/usr/bin/env bash
# tests/e2e/run-m3.sh: build zeroauthy, serve it over TLS on localhost:8443,
# and run the SDK black-box test against it.
set -euo pipefail
cd "$(dirname "$0")/../.."

work="$(mktemp -d)"
pid=""
cleanup() { [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null

CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy

ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem" \
ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem" \
  "$work/zeroauthy" serve --config tests/e2e/config.yaml >"$work/server.log" 2>&1 &
pid=$!

for _ in $(seq 1 50); do
  curl -sf --cacert "$work/cert.pem" https://localhost:8443/healthz >/dev/null && break
  sleep 0.2
done

status=0
(cd tests/e2e && npm ci --no-audit --no-fund --silent && \
  NODE_EXTRA_CA_CERTS="$work/cert.pem" node m3-client-credentials.mjs) || status=$?
if [[ $status -ne 0 ]]; then
  echo "--- zeroauthy server log ---"
  cat "$work/server.log"
fi
exit $status
```

- [ ] **Step 3: Install and run**

```bash
chmod +x tests/e2e/run-m3.sh
(cd tests/e2e && npm install --no-audit --no-fund)   # creates package-lock.json
make e2e
```

Expected: `e2e m3 client credentials: OK`.

**If it fails, debug from our side only** (CLEAN_ROOM.md: black-box). Read the dumped server log, which records each request's method, path and status, plus any `client authentication failed: method mismatch` line showing the `used` method. Typical fixes:
- **SDK uses HTTP Basic** (`used=client_secret_basic`): set `token_endpoint_auth_method: client_secret_basic` for `e2e-m2m` in `tests/e2e/seed.yaml`, then add a matching entry to `docs/compat/decisions.md` noting the observed SDK behavior.
- **Discovery is missing a field an SDK needs** (the SDK's error names it): add the field to `oidc.Configuration` *and* to the `OpenIDConfiguration` schema in `api/authentication.yaml`, with a test in `internal/oidc/handlers_test.go`.
- **Issuer mismatch** (an error mentioning `iss` or issuer): check that discovery `issuer` equals the token `iss` (`https://localhost:8443/`). Fix the server, never the test's expectations.

Commit each fix with its test before re-running.

- [ ] **Step 4: Add the CI e2e job** (append to `.github/workflows/ci.yml` under `jobs:`)

```yaml
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
          cache-dependency-path: tests/e2e/package-lock.json
      - run: ./tests/e2e/run-m3.sh
```

- [ ] **Step 5: Update the compatibility matrix**

Replace the `Authentication API` row in `docs/compat/matrix.md` with these rows:

```markdown
| Discovery (`/.well-known/openid-configuration`) | Implemented | Advertises only implemented grants; `authorization_endpoint` returns 404 until hosted login lands |
| JWKS (`/.well-known/jwks.json`) | Implemented | current, next, previous keys |
| `/oauth/token`: `client_credentials` | Implemented | Verified with @auth0/auth0-auth-js 1.16.1, auth0/legacy 7.4.0, express-oauth2-jwt-bearer 1.11.0 |
| Other Authentication API endpoints | Planned (sub-project 1, later milestones) | |
```

- [ ] **Step 6: Amend spec §1.2** to reflect the SDK split observed in public READMEs. node-auth0 v7 moved authentication into `@auth0/auth0-auth-js` and kept the old client at `auth0/legacy`. In `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md`, replace the line beginning `3. **node-auth0 \`AuthenticationClient\`:**` with:

```markdown
3. **@auth0/auth0-auth-js `AuthClient`** (current) **and node-auth0 `auth0/legacy` `AuthenticationClient`** (v4 API): client credentials, refresh, password (realm), signup, change password, as each SDK supports them.
```

- [ ] **Step 7: Write `README.md`**

````markdown
# zeroauthy

An open-source, self-hostable identity server that speaks the Auth0
Authentication API. Point an existing Auth0 SDK at a zeroauthy tenant
domain and it works with no code changes.

zeroauthy is a clean-room implementation built from public documentation
and open standards. It is not affiliated with Auth0 or Okta. See
[CLEAN_ROOM.md](CLEAN_ROOM.md).

> **Status:** early. Multi-tenant discovery, JWKS and the
> `client_credentials` grant work today. See the
> [compatibility matrix](docs/compat/matrix.md).

## Quick start

```bash
go build -o bin/zeroauthy ./cmd/zeroauthy

# Self-signed certificate for localhost (SDKs require HTTPS).
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" -keyout key.pem -out cert.pem

ZEROAUTHY_SERVER__TLS_CERT_FILE=cert.pem ZEROAUTHY_SERVER__TLS_KEY_FILE=key.pem \
  ./bin/zeroauthy serve --config tests/e2e/config.yaml
```

Then:

```bash
curl --cacert cert.pem https://localhost:8443/.well-known/openid-configuration
curl --cacert cert.pem https://localhost:8443/oauth/token \
  -d grant_type=client_credentials -d client_id=e2e-m2m \
  -d client_secret=e2e-m2m-secret-not-for-production -d audience=https://api.e2e.local
```

API reference: `https://localhost:8443/docs`. The raw contract is at
`/openapi.yaml`, and its source is [api/authentication.yaml](api/authentication.yaml).

## Configuration

YAML file (`--config`) plus `ZEROAUTHY_*` environment variables. `__`
separates levels: `ZEROAUTHY_STORAGE__DSN=memory://` sets `storage.dsn`.
See [internal/config/config.go](internal/config/config.go) for every
setting. Tenants, APIs, applications and grants come from a declarative
[seed file](tests/e2e/seed.yaml) until the Management API exists.

## Development

```bash
make test           # unit + contract + storage conformance tests
make generate       # regenerate code from api/authentication.yaml
make e2e            # Auth0 SDKs against a live zeroauthy (needs Node 22+, openssl)
make check-sources  # verify every x-source provenance link
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
````

- [ ] **Step 8: Run everything**

Run: `go test ./... && go vet ./... && make e2e && ./scripts/check-sources.sh api/authentication.yaml`
Expected: all `ok`, `e2e m3 client credentials: OK`, and every source `ok:`.

- [ ] **Step 9: Commit**

```bash
git add tests/e2e README.md .github/workflows/ci.yml docs
git commit -m "test(e2e): verify Auth0 SDKs against zeroauthy client_credentials; add README"
```

---

## Plan Self-Review (completed by the planner)

**Spec coverage (milestones 1–3 of spec §13):**

| Spec requirement | Task |
|---|---|
| Repo skeleton, config, CI | 1, 6, 10 (generate check), 17 (e2e job) |
| Store interfaces + memory driver + exported conformance suite (§5.1) | 2, 3, 4 |
| Tenant-scoped data; Host / custom domain / base-domain resolution; unknown host → 404 (§3.2) | 2–4, 7 |
| argon2id client secrets; rotation-friendly multiple secrets (§8) | 5, 9, 13 |
| Per-tenant RS256 keys, next/current/previous, envelope encryption, master key (§8) | 4, 8, 16 |
| Declarative idempotent seed (§9) | 9, 16 |
| Spec-first OpenAPI 3.1 + `x-source` + codegen + `/openapi.yaml` + `/docs` (§10) | 10, 16 |
| Contract validation in tests (§12) | 11, used in 12, 15, 16 |
| Discovery + JWKS (§6.1) | 12 |
| `/oauth/token` form + JSON, `client_secret_post` / `basic` / `none`, error shape and statuses (§6.3, §6.5) | 13, 15 |
| `client_credentials`, `{client_id}@clients`, `gty`, `azp`, `aud`, default lifetime 86400 (§6.3, §6.4) | 14, 15 |
| `/healthz`, `/readyz`, slog request logging, graceful shutdown (§11) | 16 |
| E2E with express-oauth2-jwt-bearer and the auth SDKs (§1.2, §12) | 17 |

Deliberately left to later plans: everything listed under "Out of Scope for This Plan". The spec's `Store.WithTx` is deferred to the SQL-driver plan because the memory driver gets atomicity from single-method operations (spec §5.1), and nothing in this plan composes transactions.

**Placeholder scan:** none. Task 17's script is the end-to-end smoke test of the binary.

**Type consistency check:**
- `Handlers.Minter` is added in Task 15 and used by Task 16.
- `authAPI` forwards `Discovery`, `Jwks` and `OauthToken`, which match the operationIds `discovery`, `jwks` and `oauthToken`. Task 10 Step 5 greps the generated names.
- `seed.Apply(ctx, st, f, now)` accepts a nil `now` from Task 16 on.
- `verifyToken` and `newTestKeys` are defined in Task 14's test file and reused in Task 15.

**Review Focus:** all five items have pinned tests: Task 7 (host variants), Task 13 (two methods, reserved characters, content-type parameters), and Task 15 (cross-tenant).
