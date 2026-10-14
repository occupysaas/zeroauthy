# zeroauthy Plan 2: Hosted Login and Authorization Code Flow (Milestone 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a person log in on a zeroauthy-hosted page and let an unmodified `@auth0/auth0-spa-js` app finish login with authorization code + PKCE, then call an API with the access token.

Specifically:
- the app's own page start does not hang;
- after login the app knows the user (`getUser`) and gets an access token (`getTokenSilently`);
- that access token is accepted by `express-oauth2-jwt-bearer`;
- after a page reload the app is still logged in, via silent authentication.

**Architecture:** The plan adds these pieces:
- Tenant-scoped store interfaces for connections, users, login sessions, login transactions and authorization codes, with the in-memory driver and conformance tests.
- An `identity` package for database-connection users (password policy, login, signup, brute-force throttling).
- A `session` package for the session cookie.
- A `ui` package of embedded, original `html/template` pages with nonce-based CSP.
- An `authz` package that serves `/authorize` and writes responses for `response_mode` `query`, `fragment`, `form_post` and `web_message`.
- A `login` package for `/u/login` and `/u/signup`.
- The `authorization_code` grant in `oauth`, ID tokens in the minter, and `/userinfo` in `oidc`.
- A CORS middleware.

As before, every API operation is described in `api/authentication.yaml` first and wired through the generated `ServerInterface`.

**Tech Stack:**
- Go 1.26+, building on Plan 1's stack (chi, oapi-codegen v2.8, kin-openapi v0.150, go-jose v4, koanf v2) plus `html/template` and `embed`.
- E2E runs on Node 22+ with `@auth0/auth0-spa-js` 2.28.3, `@playwright/test` 1.64.0 (Chromium), `express` 5.3.0 and `express-oauth2-jwt-bearer` 1.11.0.
- If Chromium cannot run on the host, the E2E falls back to the official Playwright container image under docker/podman.

**Spec:** `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md`. This plan covers spec §13 milestone 4, plus two items pulled forward from milestone 5, explained below. Prerequisites come from `docs/superpowers/plan-1-followups.md`.

**Pulled forward from milestone 5, and why:**
- **`response_mode=web_message` with `prompt=none`.** The public spa-js README states that `createAuth0Client` runs a silent session check at startup. Without `web_message`, every SPA page load would wait for that check to time out.
- **CORS on `/oauth/token`.** SPAs call it cross-origin.

Logout, refresh tokens and implicit response types stay in milestone 5.

## Global Constraints

Plan 1's constraints all still apply: clean room, a static binary, the spec-first contract, issuer `https://{host}/`, tenant-scoped storage, the JSON error shape, no-store on token responses, argon2id secrets, and config via YAML plus `ZEROAUTHY_*` env (`__` separates nesting levels). New constraints:

- **Authorization request handling:**
  - `/authorize` never redirects when `client_id` is unknown or `redirect_uri` is not registered. It renders the error page with HTTP 400.
  - Every other error is returned to the `redirect_uri` using the chosen `response_mode`.
  - `redirect_uri` must exactly match a registered callback. The only exception is the documented single-label wildcard host form `https://*.example.com/path`.
- **PKCE:**
  - Only `S256` is supported. `plain` and a missing method alongside a `code_challenge` are rejected.
  - Public clients (`token_endpoint_auth_method: none`) must send a `code_challenge`.
- **Authorization codes:** single use, 60-second lifetime, stored only as SHA-256 hex (`secrets.HashToken`), and bound to the client, `redirect_uri`, PKCE challenge, user and session.
- **ID tokens:**
  - Claims: `iss`, `sub`, `aud` = client_id, `iat`, `exp`, `auth_time`, `nonce` (if sent), `sid`, `at_hash`.
  - Profile claims with scope `profile`: `name`, `nickname`, `picture`, `updated_at` as a number. Email claims with scope `email`: `email`, `email_verified`.
  - Default lifetime 36000 s, or the client's `id_token_lifetime`.
- **User-flow access tokens:**
  - With an `audience`, `aud` = `[api identifier, https://{host}/userinfo]` when `openid` is requested, otherwise the API identifier.
  - Without an audience, `aud` = `https://{host}/userinfo`.
  - No `gty` claim.
  - Granted scopes are the requested OIDC scopes (`openid profile email`) plus requested scopes the API defines.
- **Session cookie:**
  - `za_session`, `HttpOnly; Secure; SameSite=None; Path=/`.
  - Default absolute lifetime 7 days (604800 s) and idle lifetime 3 days (259200 s), overridable per tenant.
  - The server stores only the SHA-256 of the cookie value.
- **Login transactions:**
  - Server-side records that expire after 15 minutes.
  - Each is bound to the browser by a cookie `za_txn_<id>` (`HttpOnly; Secure; SameSite=Lax; Path=/u`) and to the form by a CSRF token.
- **Hosted pages:**
  - CSP `default-src 'none'` with per-response nonces, `frame-ancestors 'none'` (the `web_message` response alone allows its target origin), `X-Frame-Options: DENY` on frameable-denied pages, and `Cache-Control: no-store`.
  - No external resources except the tenant's logo URL.
  - All templates, CSS and copy are original (CLEAN_ROOM.md).
- **Password policy:** minimum length 8 by default. Optionally, a required number of character classes, 0–4 (lowercase, uppercase, digit, other).
- **Emails and usernames:** stored and compared lowercase and trimmed.
- **Login throttling:** after 10 failed attempts per (tenant, connection, login) within a 15-minute window, that login is locked for 15 minutes. The IP limit is 10× the user limit. Both values come from config.
- **CORS:**
  - Discovery and JWKS send `Access-Control-Allow-Origin: *`.
  - `/oauth/token` and `/userinfo` allow an `Origin` only if a client of the tenant lists it in `allowed_origins` or `web_origins`. Preflight reflects the requested headers.

## Review Focus

1. **`redirect_uri` lookalikes.** A trailing slash, a different case, extra query, a fragment, `user@host` userinfo, a different port, or a wildcard abuse such as `https://evil.test/.example.com` must all be rejected with an error page and never a redirect. (Task 9)
2. **Authorization code misuse:**
   - a second redemption;
   - redemption by another client;
   - a different `redirect_uri`;
   - a missing or wrong `code_verifier`;
   - an expired code.

   Each must give `invalid_grant` and never tokens. (Task 12)
3. **Login CSRF and transaction binding:**
   - a POST to `/u/login` without the `za_txn_<id>` cookie;
   - a POST with a wrong CSRF token;
   - a transaction from another tenant;
   - an expired transaction.

   Each must be rejected with an error page and no session. (Task 11)
4. **Email case and whitespace:** ` Alice@Example.COM ` must log in user `alice@example.com`. Signup with a differently cased existing email must say the account exists. (Task 4)
5. **`prompt=none` without a session:**
   - It must return `login_required` to the client through its `response_mode`, including as a `web_message` page posted to the client's origin, and never render a login page.
   - `max_age=0` must force a fresh login.

   (Task 10)

## Out of Scope (later plans)

- Logout (`/v2/logout`, `/oidc/logout`), refresh tokens and rotation, the implicit and hybrid `response_type`s, consent screens (third-party clients)
- Password reset, `/dbconnections/*`, the password grants, email
- SQL drivers, plugins, `custom-db`, device flow, PAR
- Template override directory, bcrypt-hash import

Remaining Plan 1 follow-ups stay tracked in `docs/superpowers/plan-1-followups.md`; Task 15 updates it.

## File Map

```
internal/secrets/secrets.go               + HashToken, RandomHex, argon2 parameter bounds
internal/oauth/minter.go                  + empty-audience guard, IDToken
internal/server/docs.go                   SRI + CSP for /docs
internal/store/{store.go,types.go}        + Connections, Users, Sessions, AuthTransactions, AuthCodes, Clients.List; tenant/client fields
internal/store/memory/*.go                + connections.go users.go sessions.go auth_transactions.go auth_codes.go
pkg/storetest/*.go                        + connections.go users.go sessions.go auth_transactions.go auth_codes.go
internal/identity/{identity.go,database.go,throttle.go}   password policy, login/signup, throttle
internal/seed/*.go                        + connections, users, tenant session/branding, client id_token_lifetime
internal/keys/manager.go                  + Verify
internal/claims/claims.go                 standard OIDC user claims
internal/ui/{ui.go,templates/*.html}      page rendering, CSP nonces, form_post / web_message pages
internal/session/session.go               session cookie lifecycle
internal/authz/{request.go,validate.go,response.go,handlers.go}   /authorize
internal/login/{login.go,ip.go}           /u/login, /u/signup
internal/oauth/grant_authorization_code.go + pkce.go
internal/oidc/userinfo.go                 /userinfo
internal/server/cors.go                   CORS middleware
api/authentication.yaml                   + /authorize, /userinfo; discovery fields
internal/config/config.go                 + security.login_max_attempts, security.login_lockout_seconds
tests/e2e/{m4-spa-login.spec.mjs, playwright.config.mjs, spa/*, spa-server.mjs, run-m4.sh}
docs/compat/{decisions.md,matrix.md}, README.md, docs/superpowers/plan-1-followups.md
```

---

### Task 1: Prerequisite hardening (argon2 bounds, token hashing helpers, minter audience guard, /docs SRI + CSP)

**Files:**
- Modify: `internal/secrets/secrets.go`, `internal/secrets/secrets_test.go`
- Modify: `internal/oauth/minter.go`, `internal/oauth/minter_test.go`
- Modify: `internal/server/docs.go`, `internal/server/server_test.go`

**Interfaces:**
- Produces:
  - `secrets.HashToken(s string) string` returns the lowercase hex SHA-256 of `s`.
  - `secrets.RandomHex(nBytes int) string`.
  - `secrets.Verify` returns an error, and never panics, on out-of-range parameters.
  - `Minter.AccessToken` returns an error when `len(p.Audience) == 0`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/secrets/secrets_test.go`:

```go
func TestVerifyRejectsOutOfRangeParameters(t *testing.T) {
	salt := "c2FsdHNhbHRzYWx0c2FsdA" // 16 bytes, raw std base64
	key := "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g" // 32 bytes
	for _, params := range []string{
		"m=0,t=2,p=1",          // memory below 8*p
		"m=19456,t=0,p=1",      // zero time cost
		"m=19456,t=2,p=0",      // zero parallelism
		"m=4294967295,t=2,p=1", // absurd memory
		"m=19456,t=99,p=1",     // absurd time cost
	} {
		enc := "$argon2id$v=19$" + params + "$" + salt + "$" + key
		if _, err := Verify(enc, "x"); err == nil {
			t.Errorf("Verify accepted %s", params)
		}
	}
	short := "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$" + key // 4-byte salt
	if _, err := Verify(short, "x"); err == nil {
		t.Error("Verify accepted a 4-byte salt")
	}
}

func TestHashToken(t *testing.T) {
	// SHA-256("abc"), FIPS 180-2 test vector.
	if got, want := HashToken("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Fatalf("HashToken = %s", got)
	}
}

func TestRandomHex(t *testing.T) {
	a, b := RandomHex(12), RandomHex(12)
	if len(a) != 24 || a == b || strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("RandomHex = %q, %q", a, b)
	}
}
```

Append to `internal/oauth/minter_test.go`:

```go
func TestAccessTokenRequiresAudience(t *testing.T) {
	m := &Minter{Keys: newTestKeys(t, "ten_a"), Now: fixedNow}
	if _, err := m.AccessToken(context.Background(), AccessTokenParams{TenantID: "ten_a", Issuer: "https://a/", Subject: "s", ClientID: "c"}); err == nil {
		t.Fatal("token minted without an audience")
	}
}
```

Append to `internal/server/server_test.go`:

```go
func TestDocsPageIsPinnedAndLockedDown(t *testing.T) {
	rec := get(newTestServer(t), "http://any.host/docs")
	body := rec.Body.String()
	if !strings.Contains(body, `integrity="sha384-VXnKAz61Xwc3tbw1P+KKrUP7YbcsSl1Ik4is5UnogJyw9XEYZ5Ay/T1i0zPYtSZH"`) ||
		!strings.Contains(body, `crossorigin="anonymous"`) ||
		!strings.Contains(body, "@scalar/api-reference@1.74.0/dist/browser/standalone.js") {
		t.Fatalf("docs script is not pinned with SRI:\n%s", body)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'sha256-", "https://cdn.jsdelivr.net", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/secrets/ ./internal/oauth/ ./internal/server/`
Expected: FAIL. There are compile errors (`undefined: HashToken`, `undefined: RandomHex`). Once those compile, `TestVerifyRejectsOutOfRangeParameters` will panic or fail, `TestAccessTokenRequiresAudience` and `TestDocsPageIsPinnedAndLockedDown` will fail.

- [ ] **Step 3: Implement**

In `internal/secrets/secrets.go`:
- Add `"crypto/sha256"` and `"encoding/hex"` to the imports.
- Add the bounds below the parameter constants.
- Replace the body of `Verify` from the parameter parse onward.
- Append the helpers.

```go
// Bounds for parameters read from stored hashes. They keep a corrupt or
// hostile stored value from panicking argon2 or exhausting memory.
const (
	maxMemoryKiB = 256 * 1024 // 256 MiB
	maxTimeCost  = 10
	minSaltLen   = 8
	maxSaltLen   = 64
	minKeyLen    = 16
	maxKeyLen    = 64
)
```

```go
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, errMalformed
	}
	if t < 1 || t > maxTimeCost || p < 1 || m < 8*uint32(p) || m > maxMemoryKiB {
		return false, errMalformed
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < minSaltLen || len(salt) > maxSaltLen {
		return false, errMalformed
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < minKeyLen || len(want) > maxKeyLen {
		return false, errMalformed
	}
	got := argon2.IDKey([]byte(secret), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// HashToken returns the hex SHA-256 of a high-entropy token (session
// cookie, authorization code, transaction cookie). Such tokens are stored
// only in this form. Never use it for passwords; use Hash.
func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// RandomHex returns nBytes of crypto/rand output as lowercase hex.
func RandomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic("secrets: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
```

> The Task 5 (Plan 1) test `TestVerifyRejectsMalformed` used the 4-byte salt `c2FsdA` in rows meant to test other defects. Those rows still fail, which is what they assert. Check that `go test ./internal/secrets/` passes them.

In `internal/oauth/minter.go`, add `"errors"` to the imports, and make this the first statement of `AccessToken`:

```go
	if len(p.Audience) == 0 {
		return "", errors.New("oauth: an access token needs at least one audience")
	}
```

Replace `internal/server/docs.go` with:

```go
package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
)

// scalarVersion and scalarIntegrity pin the API reference UI on the
// jsDelivr CDN. To upgrade, change the version and recompute the hash:
//
//	curl -sL https://cdn.jsdelivr.net/npm/@scalar/api-reference@<v>/dist/browser/standalone.js \
//	  | openssl dgst -sha384 -binary | openssl base64 -A
const (
	scalarVersion   = "1.74.0"
	scalarIntegrity = "sha384-VXnKAz61Xwc3tbw1P+KKrUP7YbcsSl1Ik4is5UnogJyw9XEYZ5Ay/T1i0zPYtSZH"
)

const docsInlineScript = `Scalar.createApiReference('#app', { url: '/openapi.yaml' })`

var docsPage = []byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>zeroauthy Authentication API</title>
</head>
<body>
  <div id="app"></div>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference@` + scalarVersion + `/dist/browser/standalone.js" integrity="` + scalarIntegrity + `" crossorigin="anonymous"></script>
  <script>` + docsInlineScript + `</script>
</body>
</html>
`)

// docsCSP allows only the pinned CDN script and the one inline bootstrap
// script (by hash). Scalar injects styles and may load fonts, hence the
// style and font allowances.
var docsCSP = func() string {
	sum := sha256.Sum256([]byte(docsInlineScript))
	inline := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	return "default-src 'none'; script-src " + inline + " https://cdn.jsdelivr.net; " +
		"style-src 'unsafe-inline'; font-src https: data:; img-src https: data:; " +
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
}()

func serveDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", docsCSP)
	_, _ = w.Write(docsPage)
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/secrets/ ./internal/oauth/ ./internal/server/ && go vet ./...`
Expected: `ok` for all three packages.

- [ ] **Step 5: Check /docs manually in a browser (optional but recommended)**

Run `go run ./cmd/zeroauthy serve` with `ZEROAUTHY_STORAGE__DSN=memory://`, open `http://localhost:8080/docs`, and confirm the reference renders. If the browser console reports a blocked resource, add only the specific source it names to `docsCSP` and record why in the comment above it.

- [ ] **Step 6: Commit**

```bash
git add internal/secrets internal/oauth/minter.go internal/oauth/minter_test.go internal/server/docs.go internal/server/server_test.go
git commit -m "fix: bound argon2 parameters, guard empty audiences, pin /docs with SRI and CSP"
```

---

### Task 2: Store: connections, users, client listing, tenant and client settings

**Files:**
- Modify: `internal/store/store.go`, `internal/store/types.go`
- Modify: `internal/store/memory/memory.go`, `internal/store/memory/clone.go`, `internal/store/memory/clients.go`
- Create: `internal/store/memory/connections.go`, `internal/store/memory/users.go`
- Modify: `pkg/storetest/storetest.go`, `pkg/storetest/clients.go`
- Create: `pkg/storetest/connections.go`, `pkg/storetest/users.go`

**Interfaces:**
- Produces (package `store`):
  - `Tenant` gains `SessionLifetime int`, `IdleSessionLifetime int` (seconds; 0 means default) and `Branding Branding{LogoURL, PrimaryColor string}`.
  - `Client` gains `IDTokenLifetime int` (seconds; 0 means default).
  - `Clients.List(ctx, tenantID) ([]*Client, error)`, ordered by ClientID.
  - `const StrategyDatabase = "auth0"`. `PasswordPolicy{MinLength, RequireCharacterClasses int}`. `Connection{TenantID, ID, Name, Strategy string; EnabledClients []string; DisableSignup, RequiresUsername bool; PasswordPolicy PasswordPolicy; CreatedAt time.Time}`.
  - `Store.Connections() Connections` with `Create`, `Get(ctx, tenantID, id)`, `GetByName(ctx, tenantID, name)`, `Update`, and `List(ctx, tenantID)` ordered by Name.
  - `Identity{Connection, Provider, UserID, PasswordHash string}`. `User{TenantID, UserID, Email string; EmailVerified bool; Username, Name, Nickname, Picture string; Blocked bool; Identities []Identity; LastLogin *time.Time; LoginsCount int; CreatedAt, UpdatedAt time.Time}`.
  - `Store.Users() Users` with `Create`, `Get(ctx, tenantID, userID)`, `FindByLogin(ctx, tenantID, connection, login)`, `Update`, and `RecordLogin(ctx, tenantID, userID string, at time.Time)`.

- [ ] **Step 1: Add the types and interfaces**

Add to `Tenant` in `internal/store/types.go`, after `DefaultAudience`:

```go
	// SessionLifetime and IdleSessionLifetime bound login sessions, in
	// seconds. Zero means the defaults (7 days and 3 days).
	SessionLifetime     int
	IdleSessionLifetime int
	Branding            Branding
```

Add to `Client`, after `AllowedOrigins`:

```go
	// IDTokenLifetime in seconds; zero means the default (36000).
	IDTokenLifetime int
```

Append to `types.go`:

```go
// Branding customizes the hosted login pages.
type Branding struct {
	LogoURL      string // https URL, shown above the form
	PrimaryColor string // "#rrggbb"
}

// StrategyDatabase is the strategy of zeroauthy-managed username/password
// connections.
const StrategyDatabase = "auth0"

// PasswordPolicy constrains passwords on a database connection.
type PasswordPolicy struct {
	MinLength int // zero means 8
	// RequireCharacterClasses is how many of lowercase, uppercase, digits
	// and other characters a password must contain (0-4).
	RequireCharacterClasses int
}

// Connection is a source of user identities for a tenant.
type Connection struct {
	TenantID         string
	ID               string
	Name             string // unique per tenant, e.g. "Username-Password-Authentication"
	Strategy         string
	EnabledClients   []string
	DisableSignup    bool
	RequiresUsername bool
	PasswordPolicy   PasswordPolicy
	CreatedAt        time.Time
}

// Identity links a user to a connection.
type Identity struct {
	Connection   string
	Provider     string // the connection strategy, e.g. "auth0"
	UserID       string // ID within the provider (User.UserID without "provider|")
	PasswordHash string // argon2id PHC string; database connections only
}

// User is a person in a tenant. Email and Username are stored lowercase.
type User struct {
	TenantID      string
	UserID        string // "<provider>|<id>", e.g. "auth0|65f0c2..."
	Email         string
	EmailVerified bool
	Username      string
	Name          string
	Nickname      string
	Picture       string
	Blocked       bool
	Identities    []Identity
	LastLogin     *time.Time
	LoginsCount   int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
```

In `internal/store/store.go`, add `"time"` to the imports, add `Connections() Connections` and `Users() Users` to `Store`, add `List` to `Clients`, and append:

```go
	// List returns the tenant's clients ordered by ClientID.
	List(ctx context.Context, tenantID string) ([]*Client, error)
```

(That snippet goes inside the `Clients` interface.)

```go
// Connections stores identity sources, keyed by (TenantID, ID). Name is
// unique within a tenant.
type Connections interface {
	// Create returns ErrConflict if the ID or Name exists in the tenant.
	Create(ctx context.Context, c *Connection) error
	Get(ctx context.Context, tenantID, id string) (*Connection, error)
	GetByName(ctx context.Context, tenantID, name string) (*Connection, error)
	// Update returns ErrNotFound if absent and ErrConflict if the new Name
	// is used by another connection in the tenant.
	Update(ctx context.Context, c *Connection) error
	// List returns the tenant's connections ordered by Name.
	List(ctx context.Context, tenantID string) ([]*Connection, error)
}

// Users stores people, keyed by (TenantID, UserID). Within one connection,
// non-empty Email and non-empty Username values are unique. Callers pass
// lowercase emails and usernames.
type Users interface {
	// Create returns ErrConflict if the UserID exists, or if another user
	// with an identity on the same connection has the same Email or
	// Username.
	Create(ctx context.Context, u *User) error
	Get(ctx context.Context, tenantID, userID string) (*User, error)
	// FindByLogin finds the user with an identity on connection whose
	// Email or Username equals login.
	FindByLogin(ctx context.Context, tenantID, connection, login string) (*User, error)
	// Update replaces the user. ErrNotFound if absent; ErrConflict under
	// the same uniqueness rules as Create.
	Update(ctx context.Context, u *User) error
	// RecordLogin atomically sets LastLogin and increments LoginsCount.
	RecordLogin(ctx context.Context, tenantID, userID string, at time.Time) error
}
```

- [ ] **Step 2: Write the conformance tests**

In `pkg/storetest/storetest.go` `Run`, add:

```go
	t.Run("Connections", func(t *testing.T) { testConnections(t, newStore) })
	t.Run("Users", func(t *testing.T) { testUsers(t, newStore) })
```

Append to `pkg/storetest/clients.go`, inside `testClients`:

```go
	t.Run("ListOrderedByClientID", func(t *testing.T) {
		s := open(t, newStore)
		for _, id := range []string{"zz", "aa", "mm"} {
			mustNoErr(t, s.Clients().Create(ctx, newClient("ten_a", id)))
		}
		mustNoErr(t, s.Clients().Create(ctx, newClient("ten_b", "other")))
		got, err := s.Clients().List(ctx, "ten_a")
		mustNoErr(t, err)
		var ids []string
		for _, c := range got {
			ids = append(ids, c.ClientID)
		}
		mustEqual(t, ids, []string{"aa", "mm", "zz"})
	})
```

```go
// pkg/storetest/connections.go
package storetest

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newConnection(tenantID, id, name string) *store.Connection {
	return &store.Connection{
		TenantID:         tenantID,
		ID:               id,
		Name:             name,
		Strategy:         store.StrategyDatabase,
		EnabledClients:   []string{"c1", "c2"},
		DisableSignup:    true,
		RequiresUsername: true,
		PasswordPolicy:   store.PasswordPolicy{MinLength: 10, RequireCharacterClasses: 3},
		CreatedAt:        ts(0),
	}
}

func testConnections(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		s := open(t, newStore)
		want := newConnection("ten_a", "con1", "Database")
		mustNoErr(t, s.Connections().Create(ctx, want))
		got, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		got, err = s.Connections().GetByName(ctx, "ten_a", "Database")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		want.EnabledClients = []string{"c3"}
		want.Name = "Renamed"
		mustNoErr(t, s.Connections().Update(ctx, want))
		_, err = s.Connections().GetByName(ctx, "ten_a", "Database")
		mustErrIs(t, err, store.ErrNotFound)
		got, err = s.Connections().GetByName(ctx, "ten_a", "Renamed")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		mustErrIs(t, s.Connections().Update(ctx, newConnection("ten_a", "missing", "x")), store.ErrNotFound)
		_, err = s.Connections().Get(ctx, "ten_b", "con1")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("NameUniquePerTenant", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_a", "con1", "Database")))
		mustErrIs(t, s.Connections().Create(ctx, newConnection("ten_a", "con2", "Database")), store.ErrConflict)
		mustErrIs(t, s.Connections().Create(ctx, newConnection("ten_a", "con1", "Other")), store.ErrConflict)
		mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_b", "con1", "Database")))
		mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_a", "con3", "Third")))
		mustErrIs(t, s.Connections().Update(ctx, newConnection("ten_a", "con3", "Database")), store.ErrConflict)
	})

	t.Run("ListOrderedByName", func(t *testing.T) {
		s := open(t, newStore)
		for _, n := range []string{"b", "c", "a"} {
			mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_a", "con-"+n, n)))
		}
		mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_b", "x", "zz")))
		got, err := s.Connections().List(ctx, "ten_a")
		mustNoErr(t, err)
		var names []string
		for _, c := range got {
			names = append(names, c.Name)
		}
		mustEqual(t, names, []string{"a", "b", "c"})
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newConnection("ten_a", "con1", "Database")
		mustNoErr(t, s.Connections().Create(ctx, in))
		in.EnabledClients[0] = "mutated"
		got, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustNoErr(t, err)
		got.EnabledClients[1] = "mutated-too"
		again, _ := s.Connections().Get(ctx, "ten_a", "con1")
		mustEqual(t, again.EnabledClients, []string{"c1", "c2"})
	})
}
```

```go
// pkg/storetest/users.go
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newUser(tenantID, id, email, username string) *store.User {
	return &store.User{
		TenantID:      tenantID,
		UserID:        "auth0|" + id,
		Email:         email,
		EmailVerified: true,
		Username:      username,
		Name:          "User " + id,
		Nickname:      id,
		Picture:       "https://img.test/" + id + ".png",
		Identities: []store.Identity{{
			Connection: "Database", Provider: store.StrategyDatabase, UserID: id, PasswordHash: "$argon2id$hash-" + id,
		}},
		CreatedAt: ts(0),
		UpdatedAt: ts(0),
	}
}

func testUsers(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CreateGetFind", func(t *testing.T) {
		s := open(t, newStore)
		want := newUser("ten_a", "u1", "alice@example.test", "alice")
		mustNoErr(t, s.Users().Create(ctx, want))

		got, err := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		for _, login := range []string{"alice@example.test", "alice"} {
			got, err = s.Users().FindByLogin(ctx, "ten_a", "Database", login)
			mustNoErr(t, err)
			mustEqual(t, got.UserID, "auth0|u1")
		}
		_, err = s.Users().FindByLogin(ctx, "ten_a", "OtherConnection", "alice")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Users().FindByLogin(ctx, "ten_b", "Database", "alice")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Users().Get(ctx, "ten_b", "auth0|u1")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("Uniqueness", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u1", "alice@example.test", "alice")))
		mustErrIs(t, s.Users().Create(ctx, newUser("ten_a", "u1", "other@example.test", "other")), store.ErrConflict)
		mustErrIs(t, s.Users().Create(ctx, newUser("ten_a", "u2", "alice@example.test", "")), store.ErrConflict)
		mustErrIs(t, s.Users().Create(ctx, newUser("ten_a", "u3", "bob@example.test", "alice")), store.ErrConflict)

		otherConn := newUser("ten_a", "u4", "alice@example.test", "alice")
		otherConn.Identities[0].Connection = "Other"
		mustNoErr(t, s.Users().Create(ctx, otherConn))
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_b", "u1", "alice@example.test", "alice")))

		// Empty usernames never collide.
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u5", "carol@example.test", "")))
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u6", "dave@example.test", "")))
	})

	t.Run("Update", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u1", "alice@example.test", "alice")))
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u2", "bob@example.test", "bob")))

		u, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		u.Email = "alice2@example.test"
		u.Blocked = true
		mustNoErr(t, s.Users().Update(ctx, u))
		_, err := s.Users().FindByLogin(ctx, "ten_a", "Database", "alice@example.test")
		mustErrIs(t, err, store.ErrNotFound)
		got, err := s.Users().FindByLogin(ctx, "ten_a", "Database", "alice2@example.test")
		mustNoErr(t, err)
		mustEqual(t, got.Blocked, true)

		u.Email = "bob@example.test"
		mustErrIs(t, s.Users().Update(ctx, u), store.ErrConflict)
		mustErrIs(t, s.Users().Update(ctx, newUser("ten_a", "missing", "m@example.test", "")), store.ErrNotFound)
	})

	t.Run("RecordLogin", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u1", "alice@example.test", "")))
		mustNoErr(t, s.Users().RecordLogin(ctx, "ten_a", "auth0|u1", ts(time.Hour)))
		mustNoErr(t, s.Users().RecordLogin(ctx, "ten_a", "auth0|u1", ts(2*time.Hour)))
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, got.LoginsCount, 2)
		mustEqual(t, got.LastLogin.Equal(ts(2*time.Hour)), true)
		mustErrIs(t, s.Users().RecordLogin(ctx, "ten_a", "auth0|missing", ts(0)), store.ErrNotFound)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newUser("ten_a", "u1", "alice@example.test", "")
		mustNoErr(t, s.Users().Create(ctx, in))
		in.Identities[0].PasswordHash = "mutated"

		mustNoErr(t, s.Users().RecordLogin(ctx, "ten_a", "auth0|u1", ts(time.Hour)))
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		got.Identities[0].Connection = "mutated"
		*got.LastLogin = ts(0)

		again, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, again.Identities[0], newUser("ten_a", "u1", "alice@example.test", "").Identities[0])
		mustEqual(t, again.LastLogin.Equal(ts(time.Hour)), true)
	})
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/store/memory/`
Expected: compile errors: `*Store does not implement store.Store (missing method Connections)`.

- [ ] **Step 4: Implement the memory driver**

In `memory.go`, add these fields and initialize them in `New`:

```go
	connections map[key]*store.Connection // by (tenant, ID)
	users       map[key]*store.User       // by (tenant, UserID)
```

```go
func (s *Store) Connections() store.Connections { return connections{s} }
func (s *Store) Users() store.Users             { return users{s} }
```

Append to `clone.go`:

```go
func cloneConnection(c *store.Connection) *store.Connection {
	out := *c
	out.EnabledClients = slices.Clone(c.EnabledClients)
	return &out
}

func cloneUser(u *store.User) *store.User {
	out := *u
	out.Identities = slices.Clone(u.Identities)
	if u.LastLogin != nil {
		t := *u.LastLogin
		out.LastLogin = &t
	}
	return &out
}
```

Append to `clients.go`:

```go
func (r clients) List(_ context.Context, tenantID string) ([]*store.Client, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []*store.Client
	for k, c := range r.s.clients {
		if k.tenant == tenantID {
			out = append(out, cloneClient(c))
		}
	}
	slices.SortFunc(out, func(a, b *store.Client) int { return strings.Compare(a.ClientID, b.ClientID) })
	return out, nil
}
```

(Add `"slices"` and `"strings"` to the imports of `clients.go`.)

```go
// internal/store/memory/connections.go
package memory

import (
	"context"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type connections struct{ s *Store }

func (r connections) Create(_ context.Context, c *store.Connection) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{c.TenantID, c.ID}
	if _, ok := r.s.connections[k]; ok || r.nameTaken(c) {
		return store.ErrConflict
	}
	r.s.connections[k] = cloneConnection(c)
	return nil
}

func (r connections) Get(_ context.Context, tenantID, id string) (*store.Connection, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	c, ok := r.s.connections[key{tenantID, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneConnection(c), nil
}

func (r connections) GetByName(_ context.Context, tenantID, name string) (*store.Connection, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for k, c := range r.s.connections {
		if k.tenant == tenantID && c.Name == name {
			return cloneConnection(c), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r connections) Update(_ context.Context, c *store.Connection) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{c.TenantID, c.ID}
	if _, ok := r.s.connections[k]; !ok {
		return store.ErrNotFound
	}
	if r.nameTaken(c) {
		return store.ErrConflict
	}
	r.s.connections[k] = cloneConnection(c)
	return nil
}

func (r connections) List(_ context.Context, tenantID string) ([]*store.Connection, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []*store.Connection
	for k, c := range r.s.connections {
		if k.tenant == tenantID {
			out = append(out, cloneConnection(c))
		}
	}
	slices.SortFunc(out, func(a, b *store.Connection) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// nameTaken is called with the lock held.
func (r connections) nameTaken(c *store.Connection) bool {
	for k, o := range r.s.connections {
		if k.tenant == c.TenantID && k.id != c.ID && o.Name == c.Name {
			return true
		}
	}
	return false
}
```

```go
// internal/store/memory/users.go
package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type users struct{ s *Store }

func (r users) Create(_ context.Context, u *store.User) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{u.TenantID, u.UserID}
	if _, ok := r.s.users[k]; ok || r.loginTaken(u) {
		return store.ErrConflict
	}
	r.s.users[k] = cloneUser(u)
	return nil
}

func (r users) Get(_ context.Context, tenantID, userID string) (*store.User, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	u, ok := r.s.users[key{tenantID, userID}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneUser(u), nil
}

func (r users) FindByLogin(_ context.Context, tenantID, connection, login string) (*store.User, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	if login == "" {
		return nil, store.ErrNotFound
	}
	for k, u := range r.s.users {
		if k.tenant == tenantID && onConnection(u, connection) && (u.Email == login || u.Username == login) {
			return cloneUser(u), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r users) Update(_ context.Context, u *store.User) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{u.TenantID, u.UserID}
	if _, ok := r.s.users[k]; !ok {
		return store.ErrNotFound
	}
	if r.loginTaken(u) {
		return store.ErrConflict
	}
	r.s.users[k] = cloneUser(u)
	return nil
}

func (r users) RecordLogin(_ context.Context, tenantID, userID string, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	u, ok := r.s.users[key{tenantID, userID}]
	if !ok {
		return store.ErrNotFound
	}
	t := at
	u.LastLogin = &t
	u.LoginsCount++
	return nil
}

// loginTaken reports whether another user shares a connection with u and
// has the same non-empty email or username. The caller holds the lock.
func (r users) loginTaken(u *store.User) bool {
	for k, o := range r.s.users {
		if k.tenant != u.TenantID || k.id == u.UserID {
			continue
		}
		for _, id := range u.Identities {
			if !onConnection(o, id.Connection) {
				continue
			}
			if (u.Email != "" && o.Email == u.Email) || (u.Username != "" && o.Username == u.Username) {
				return true
			}
		}
	}
	return false
}

func onConnection(u *store.User, connection string) bool {
	for _, id := range u.Identities {
		if id.Connection == connection {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run the tests**

Run: `gofmt -l . ; go vet ./... && go test ./internal/store/... ./internal/seed/ ./internal/oauth/`
Expected: no gofmt output; `ok` everywhere. The new `Tenant`/`Client` fields are additive, so existing tests compile unchanged.

- [ ] **Step 6: Commit**

```bash
git add internal/store pkg/storetest
git commit -m "feat(store): add connections, users, client listing, session and branding settings"
```

---

### Task 3: Store: login sessions, login transactions, authorization codes

**Files:**
- Modify: `internal/store/store.go`, `internal/store/types.go`, `internal/store/memory/memory.go`, `internal/store/memory/clone.go`, `pkg/storetest/storetest.go`
- Create: `internal/store/memory/sessions.go`, `internal/store/memory/auth_transactions.go`, `internal/store/memory/auth_codes.go`
- Create: `pkg/storetest/sessions.go`, `pkg/storetest/auth_transactions.go`, `pkg/storetest/auth_codes.go`

**Interfaces:**
- Produces (package `store`):
  - `var ErrAlreadyUsed`
  - `LoginSession{TenantID, ID, TokenHash, UserID, Connection string; AuthenticatedAt time.Time; ClientIDs []string; ExpiresAt, IdleExpiresAt, CreatedAt time.Time}`; `Store.Sessions() Sessions` with `Create`, `GetByTokenHash(ctx, tenantID, hash)`, `Update`, `Delete(ctx, tenantID, id)`
  - `AuthTransaction{TenantID, ID, CookieHash, CSRFToken, ClientID string; Params map[string]string; ExpiresAt, CreatedAt time.Time}`; `Store.AuthTransactions() AuthTransactions` with `Create`, `Get(ctx, tenantID, id)`, `Delete(ctx, tenantID, id)`
  - `AuthCode{TenantID, CodeHash, ClientID, RedirectURI, UserID, SessionID string; Scopes []string; Audience, Nonce, CodeChallenge, CodeChallengeMethod string; AuthTime, ExpiresAt, CreatedAt time.Time; UsedAt *time.Time}`; `Store.AuthCodes() AuthCodes` with `Create`, `Consume(ctx, tenantID, codeHash string, at time.Time) (*AuthCode, error)`

- [ ] **Step 1: Add the types and interfaces**

Append to `types.go`:

```go
// LoginSession is a browser's authenticated session with a tenant.
type LoginSession struct {
	TenantID        string
	ID              string // public identifier, used as the ID token "sid" claim
	TokenHash       string // secrets.HashToken of the session cookie value
	UserID          string
	Connection      string
	AuthenticatedAt time.Time
	ClientIDs       []string // clients that received tokens through this session
	ExpiresAt       time.Time
	IdleExpiresAt   time.Time
	CreatedAt       time.Time
}

// AuthTransaction holds an /authorize request while the user logs in.
type AuthTransaction struct {
	TenantID   string
	ID         string // the "state" of the hosted login pages
	CookieHash string // secrets.HashToken of the za_txn_<ID> cookie value
	CSRFToken  string
	ClientID   string
	Params     map[string]string // the validated authorize request
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// AuthCode is an issued authorization code.
type AuthCode struct {
	TenantID            string
	CodeHash            string // secrets.HashToken of the code
	ClientID            string
	RedirectURI         string
	UserID              string
	SessionID           string
	Scopes              []string
	Audience            string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            time.Time
	ExpiresAt           time.Time
	CreatedAt           time.Time
	UsedAt              *time.Time
}
```

In `store.go`, add `ErrAlreadyUsed = errors.New("store: already used")` to the `var` block, add `Sessions() Sessions`, `AuthTransactions() AuthTransactions` and `AuthCodes() AuthCodes` to `Store`, and append:

```go
// Sessions stores login sessions, keyed by (TenantID, ID). TokenHash is
// unique within a tenant.
type Sessions interface {
	// Create returns ErrConflict if the ID or TokenHash exists.
	Create(ctx context.Context, s *LoginSession) error
	GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*LoginSession, error)
	// Update returns ErrNotFound if absent.
	Update(ctx context.Context, s *LoginSession) error
	// Delete returns ErrNotFound if absent.
	Delete(ctx context.Context, tenantID, id string) error
}

// AuthTransactions stores in-progress logins, keyed by (TenantID, ID).
type AuthTransactions interface {
	// Create returns ErrConflict if the ID exists.
	Create(ctx context.Context, t *AuthTransaction) error
	Get(ctx context.Context, tenantID, id string) (*AuthTransaction, error)
	// Delete returns ErrNotFound if absent.
	Delete(ctx context.Context, tenantID, id string) error
}

// AuthCodes stores authorization codes, keyed by (TenantID, CodeHash).
type AuthCodes interface {
	// Create returns ErrConflict if the CodeHash exists.
	Create(ctx context.Context, c *AuthCode) error
	// Consume atomically marks the code used at `at` and returns it. A
	// code that was already used is returned together with ErrAlreadyUsed,
	// so callers can react to replay. Unknown codes return ErrNotFound.
	Consume(ctx context.Context, tenantID, codeHash string, at time.Time) (*AuthCode, error)
}
```

- [ ] **Step 2: Write the conformance tests**

Add these to `Run`:

```go
	t.Run("Sessions", func(t *testing.T) { testSessions(t, newStore) })
	t.Run("AuthTransactions", func(t *testing.T) { testAuthTransactions(t, newStore) })
	t.Run("AuthCodes", func(t *testing.T) { testAuthCodes(t, newStore) })
```

```go
// pkg/storetest/sessions.go
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newSession(tenantID, id, tokenHash string) *store.LoginSession {
	return &store.LoginSession{
		TenantID: tenantID, ID: id, TokenHash: tokenHash,
		UserID: "auth0|u1", Connection: "Database",
		AuthenticatedAt: ts(0), ClientIDs: []string{"spa"},
		ExpiresAt: ts(7 * 24 * time.Hour), IdleExpiresAt: ts(3 * 24 * time.Hour), CreatedAt: ts(0),
	}
}

func testSessions(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		s := open(t, newStore)
		want := newSession("ten_a", "s1", "hash1")
		mustNoErr(t, s.Sessions().Create(ctx, want))
		mustErrIs(t, s.Sessions().Create(ctx, newSession("ten_a", "s1", "hash2")), store.ErrConflict)
		mustErrIs(t, s.Sessions().Create(ctx, newSession("ten_a", "s2", "hash1")), store.ErrConflict)

		got, err := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_b", "hash1")
		mustErrIs(t, err, store.ErrNotFound)

		want.ClientIDs = append(want.ClientIDs, "web")
		want.IdleExpiresAt = ts(4 * 24 * time.Hour)
		mustNoErr(t, s.Sessions().Update(ctx, want))
		got, _ = s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustEqual(t, got, want)

		mustNoErr(t, s.Sessions().Delete(ctx, "ten_a", "s1"))
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.Sessions().Delete(ctx, "ten_a", "s1"), store.ErrNotFound)
		mustErrIs(t, s.Sessions().Update(ctx, want), store.ErrNotFound)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newSession("ten_a", "s1", "hash1")
		mustNoErr(t, s.Sessions().Create(ctx, in))
		in.ClientIDs[0] = "mutated"
		got, _ := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		got.ClientIDs[0] = "mutated-too"
		again, _ := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustEqual(t, again.ClientIDs, []string{"spa"})
	})
}
```

```go
// pkg/storetest/auth_transactions.go
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newAuthTransaction(tenantID, id string) *store.AuthTransaction {
	return &store.AuthTransaction{
		TenantID: tenantID, ID: id, CookieHash: "cookie-" + id, CSRFToken: "csrf-" + id, ClientID: "spa",
		Params:    map[string]string{"redirect_uri": "https://app.test/cb", "state": "xyz"},
		ExpiresAt: ts(15 * time.Minute), CreatedAt: ts(0),
	}
}

func testAuthTransactions(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CreateGetDelete", func(t *testing.T) {
		s := open(t, newStore)
		want := newAuthTransaction("ten_a", "t1")
		mustNoErr(t, s.AuthTransactions().Create(ctx, want))
		mustErrIs(t, s.AuthTransactions().Create(ctx, newAuthTransaction("ten_a", "t1")), store.ErrConflict)
		got, err := s.AuthTransactions().Get(ctx, "ten_a", "t1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		_, err = s.AuthTransactions().Get(ctx, "ten_b", "t1")
		mustErrIs(t, err, store.ErrNotFound)
		mustNoErr(t, s.AuthTransactions().Delete(ctx, "ten_a", "t1"))
		_, err = s.AuthTransactions().Get(ctx, "ten_a", "t1")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.AuthTransactions().Delete(ctx, "ten_a", "t1"), store.ErrNotFound)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newAuthTransaction("ten_a", "t1")
		mustNoErr(t, s.AuthTransactions().Create(ctx, in))
		in.Params["state"] = "mutated"
		got, _ := s.AuthTransactions().Get(ctx, "ten_a", "t1")
		got.Params["redirect_uri"] = "https://evil.test"
		again, _ := s.AuthTransactions().Get(ctx, "ten_a", "t1")
		mustEqual(t, again.Params, map[string]string{"redirect_uri": "https://app.test/cb", "state": "xyz"})
	})
}
```

```go
// pkg/storetest/auth_codes.go
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newAuthCode(tenantID, hash string) *store.AuthCode {
	return &store.AuthCode{
		TenantID: tenantID, CodeHash: hash, ClientID: "spa", RedirectURI: "https://app.test/cb",
		UserID: "auth0|u1", SessionID: "s1", Scopes: []string{"openid", "email"},
		Audience: "https://api.test", Nonce: "n", CodeChallenge: "ch", CodeChallengeMethod: "S256",
		AuthTime: ts(0), ExpiresAt: ts(time.Minute), CreatedAt: ts(0),
	}
}

func testAuthCodes(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("ConsumeOnce", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")))
		mustErrIs(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")), store.ErrConflict)

		got, err := s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(10*time.Second))
		mustNoErr(t, err)
		want := newAuthCode("ten_a", "h1")
		used := ts(10 * time.Second)
		want.UsedAt = &used
		mustEqual(t, got, want)

		again, err := s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(20*time.Second))
		mustErrIs(t, err, store.ErrAlreadyUsed)
		mustEqual(t, again.UsedAt.Equal(used), true) // the first use time is kept
		mustEqual(t, again.ClientID, "spa")
	})

	t.Run("UnknownAndOtherTenant", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")))
		_, err := s.AuthCodes().Consume(ctx, "ten_a", "nope", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.AuthCodes().Consume(ctx, "ten_b", "h1", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		// The failed cross-tenant attempt must not have consumed it.
		_, err = s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(0))
		mustNoErr(t, err)
	})
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/store/memory/`
Expected: compile errors (`missing method Sessions`).

- [ ] **Step 4: Implement the memory driver**

In `memory.go`, add these fields and initialize them in `New`:

```go
	sessions     map[key]*store.LoginSession    // by (tenant, ID)
	transactions map[key]*store.AuthTransaction // by (tenant, ID)
	authCodes    map[key]*store.AuthCode        // by (tenant, CodeHash)
```

```go
func (s *Store) Sessions() store.Sessions                 { return sessions{s} }
func (s *Store) AuthTransactions() store.AuthTransactions { return authTransactions{s} }
func (s *Store) AuthCodes() store.AuthCodes               { return authCodes{s} }
```

Append to `clone.go`, adding `"maps"` to its imports:

```go
func cloneSession(s *store.LoginSession) *store.LoginSession {
	out := *s
	out.ClientIDs = slices.Clone(s.ClientIDs)
	return &out
}

func cloneAuthTransaction(t *store.AuthTransaction) *store.AuthTransaction {
	out := *t
	out.Params = maps.Clone(t.Params)
	return &out
}

func cloneAuthCode(c *store.AuthCode) *store.AuthCode {
	out := *c
	out.Scopes = slices.Clone(c.Scopes)
	if c.UsedAt != nil {
		t := *c.UsedAt
		out.UsedAt = &t
	}
	return &out
}
```

```go
// internal/store/memory/sessions.go
package memory

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type sessions struct{ s *Store }

func (r sessions) Create(_ context.Context, s *store.LoginSession) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{s.TenantID, s.ID}
	if _, ok := r.s.sessions[k]; ok {
		return store.ErrConflict
	}
	if _, ok := r.findByHash(s.TenantID, s.TokenHash); ok {
		return store.ErrConflict
	}
	r.s.sessions[k] = cloneSession(s)
	return nil
}

func (r sessions) GetByTokenHash(_ context.Context, tenantID, tokenHash string) (*store.LoginSession, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	s, ok := r.findByHash(tenantID, tokenHash)
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneSession(s), nil
}

func (r sessions) Update(_ context.Context, s *store.LoginSession) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{s.TenantID, s.ID}
	if _, ok := r.s.sessions[k]; !ok {
		return store.ErrNotFound
	}
	r.s.sessions[k] = cloneSession(s)
	return nil
}

func (r sessions) Delete(_ context.Context, tenantID, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{tenantID, id}
	if _, ok := r.s.sessions[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.sessions, k)
	return nil
}

// findByHash is called with the lock held.
func (r sessions) findByHash(tenantID, hash string) (*store.LoginSession, bool) {
	for k, s := range r.s.sessions {
		if k.tenant == tenantID && s.TokenHash == hash {
			return s, true
		}
	}
	return nil, false
}
```

```go
// internal/store/memory/auth_transactions.go
package memory

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type authTransactions struct{ s *Store }

func (r authTransactions) Create(_ context.Context, t *store.AuthTransaction) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{t.TenantID, t.ID}
	if _, ok := r.s.transactions[k]; ok {
		return store.ErrConflict
	}
	r.s.transactions[k] = cloneAuthTransaction(t)
	return nil
}

func (r authTransactions) Get(_ context.Context, tenantID, id string) (*store.AuthTransaction, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	t, ok := r.s.transactions[key{tenantID, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneAuthTransaction(t), nil
}

func (r authTransactions) Delete(_ context.Context, tenantID, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{tenantID, id}
	if _, ok := r.s.transactions[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.transactions, k)
	return nil
}
```

```go
// internal/store/memory/auth_codes.go
package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type authCodes struct{ s *Store }

func (r authCodes) Create(_ context.Context, c *store.AuthCode) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{c.TenantID, c.CodeHash}
	if _, ok := r.s.authCodes[k]; ok {
		return store.ErrConflict
	}
	r.s.authCodes[k] = cloneAuthCode(c)
	return nil
}

func (r authCodes) Consume(_ context.Context, tenantID, codeHash string, at time.Time) (*store.AuthCode, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	c, ok := r.s.authCodes[key{tenantID, codeHash}]
	if !ok {
		return nil, store.ErrNotFound
	}
	if c.UsedAt != nil {
		return cloneAuthCode(c), store.ErrAlreadyUsed
	}
	t := at
	c.UsedAt = &t
	return cloneAuthCode(c), nil
}
```

- [ ] **Step 5: Run the tests**

Run: `gofmt -l . ; go vet ./... && go test ./internal/store/...`
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add internal/store pkg/storetest
git commit -m "feat(store): add login sessions, login transactions, authorization codes"
```

---
### Task 4: Identity: password policy, database login and signup, login throttle

**Files:**
- Create: `internal/identity/identity.go`, `internal/identity/database.go`, `internal/identity/throttle.go`
- Create: `internal/identity/identity_test.go`, `internal/identity/database_test.go`, `internal/identity/throttle_test.go`

**Interfaces:**
- Consumes: `store.Store` (`Users()`), `store.Connection`, `store.PasswordPolicy`, `secrets.Hash/Verify/RandomHex`.
- Produces (package `identity`):
  - Errors: `ErrInvalidCredentials`, `ErrUserBlocked`, `ErrSignupDisabled`, `ErrUserExists`. Type `*PolicyError{Reason string}`.
  - `NormalizeLogin(s string) string`: trim and lowercase.
  - `CheckPassword(p store.PasswordPolicy, password string) error`.
  - `type Database struct{ Store store.Store; Now func() time.Time }` with:
    - `Login(ctx, conn *store.Connection, login, password string) (*store.User, error)`
    - `Signup(ctx, conn *store.Connection, email, username, password string) (*store.User, error)`
  - `type Throttle`: `NewThrottle(maxFailures int, window, lockout time.Duration) *Throttle` with `Allowed(key string) bool`, `Failure(key string)`, `Success(key string)`; field `Now func() time.Time` for tests.

- [ ] **Step 1: Write the failing tests**

```go
// internal/identity/identity_test.go
package identity

import (
	"errors"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestNormalizeLogin(t *testing.T) {
	if got := NormalizeLogin("  Alice@Example.COM \t"); got != "alice@example.com" {
		t.Fatalf("NormalizeLogin = %q", got)
	}
}

func TestCheckPassword(t *testing.T) {
	cases := []struct {
		policy   store.PasswordPolicy
		password string
		ok       bool
	}{
		{store.PasswordPolicy{}, "1234567", false},          // default minimum is 8
		{store.PasswordPolicy{}, "12345678", true},
		{store.PasswordPolicy{MinLength: 12}, "abcdefghijk", false},
		{store.PasswordPolicy{MinLength: 4}, "ééééé", true}, // runes, not bytes
		{store.PasswordPolicy{RequireCharacterClasses: 3}, "alllowercase", false},
		{store.PasswordPolicy{RequireCharacterClasses: 3}, "Lower1upper", true},
		{store.PasswordPolicy{RequireCharacterClasses: 4}, "Lower1upper!", true},
		{store.PasswordPolicy{}, strings.Repeat("a", maxPasswordBytes+1), false},
	}
	for _, tc := range cases {
		err := CheckPassword(tc.policy, tc.password)
		if (err == nil) != tc.ok {
			t.Errorf("CheckPassword(%+v, %q) = %v, want ok=%v", tc.policy, tc.password, err, tc.ok)
		}
		var pe *PolicyError
		if err != nil && !errors.As(err, &pe) {
			t.Errorf("error %v is not a *PolicyError", err)
		}
	}
}
```

```go
// internal/identity/database_test.go
package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }

func newDB(t *testing.T) (*Database, *store.Connection) {
	t.Helper()
	st := memory.New()
	conn := &store.Connection{TenantID: "ten_a", ID: "con1", Name: "Database", Strategy: store.StrategyDatabase}
	if err := st.Connections().Create(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	return &Database{Store: st, Now: fixedNow}, conn
}

func TestSignupThenLogin(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)

	u, err := db.Signup(ctx, conn, " Alice@Example.COM ", "", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "alice@example.com" || u.EmailVerified || u.Nickname != "alice" || u.Name != "alice@example.com" {
		t.Fatalf("user = %+v", u)
	}
	if len(u.UserID) != len("auth0|")+24 || u.UserID[:6] != "auth0|" {
		t.Fatalf("user_id = %q", u.UserID)
	}
	if id := u.Identities; len(id) != 1 || id[0].Connection != "Database" || id[0].Provider != "auth0" || "auth0|"+id[0].UserID != u.UserID {
		t.Fatalf("identities = %+v", id)
	}
	if ok, _ := secrets.Verify(u.Identities[0].PasswordHash, "correct horse"); !ok {
		t.Fatal("password hash does not verify")
	}

	// Review focus 4: case and whitespace insensitive login.
	got, err := db.Login(ctx, conn, "  ALICE@example.com", "correct horse")
	if err != nil || got.UserID != u.UserID {
		t.Fatalf("Login = %v, %v", got, err)
	}

	_, err = db.Signup(ctx, conn, "alice@EXAMPLE.com", "", "another pass")
	if !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate signup err = %v, want ErrUserExists", err)
	}
}

func TestLoginFailures(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	u, _ := db.Signup(ctx, conn, "bob@example.com", "", "bobs password")

	if _, err := db.Login(ctx, conn, "bob@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password err = %v", err)
	}
	if _, err := db.Login(ctx, conn, "nobody@example.com", "x"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown user err = %v", err)
	}
	other := &store.Connection{TenantID: "ten_a", ID: "con2", Name: "Other", Strategy: store.StrategyDatabase}
	if _, err := db.Login(ctx, other, "bob@example.com", "bobs password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong connection err = %v", err)
	}

	u.Blocked = true
	if err := db.Store.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Login(ctx, conn, "bob@example.com", "bobs password"); !errors.Is(err, ErrUserBlocked) {
		t.Errorf("blocked err = %v", err)
	}
	// A blocked user with a wrong password must not learn it is blocked.
	if _, err := db.Login(ctx, conn, "bob@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("blocked+wrong err = %v", err)
	}
}

func TestSignupRules(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)

	conn.PasswordPolicy = store.PasswordPolicy{MinLength: 10}
	var pe *PolicyError
	if _, err := db.Signup(ctx, conn, "c@example.com", "", "short"); !errors.As(err, &pe) {
		t.Errorf("weak password err = %v", err)
	}
	for _, bad := range []string{"", "not-an-email", "a@", "Name <x@example.com>"} {
		if _, err := db.Signup(ctx, conn, bad, "", "long enough pw"); !errors.As(err, &pe) {
			t.Errorf("email %q err = %v", bad, err)
		}
	}

	conn.RequiresUsername = true
	if _, err := db.Signup(ctx, conn, "d@example.com", "", "long enough pw"); !errors.As(err, &pe) {
		t.Errorf("missing username err = %v", err)
	}
	u, err := db.Signup(ctx, conn, "d@example.com", " Dave_1 ", "long enough pw")
	if err != nil || u.Username != "dave_1" {
		t.Fatalf("signup with username = %+v, %v", u, err)
	}
	if got, err := db.Login(ctx, conn, "DAVE_1", "long enough pw"); err != nil || got.UserID != u.UserID {
		t.Fatalf("login by username = %v, %v", got, err)
	}

	conn.DisableSignup = true
	if _, err := db.Signup(ctx, conn, "e@example.com", "eve", "long enough pw"); !errors.Is(err, ErrSignupDisabled) {
		t.Errorf("disabled signup err = %v", err)
	}
}
```

```go
// internal/identity/throttle_test.go
package identity

import (
	"testing"
	"time"
)

func TestThrottle(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := NewThrottle(3, 15*time.Minute, 10*time.Minute)
	th.Now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !th.Allowed("k") {
			t.Fatalf("blocked after %d failures", i)
		}
		th.Failure("k")
	}
	if th.Allowed("k") {
		t.Fatal("not locked after 3 failures")
	}
	if !th.Allowed("other") {
		t.Fatal("unrelated key locked")
	}

	now = now.Add(10*time.Minute + time.Second)
	if !th.Allowed("k") {
		t.Fatal("still locked after the lockout period")
	}

	// Failures outside the window do not accumulate.
	th.Failure("w")
	th.Failure("w")
	now = now.Add(16 * time.Minute)
	th.Failure("w")
	if !th.Allowed("w") {
		t.Fatal("old failures counted after the window")
	}

	// Success clears the counter.
	th.Failure("s")
	th.Failure("s")
	th.Success("s")
	th.Failure("s")
	th.Failure("s")
	if !th.Allowed("s") {
		t.Fatal("success did not reset the counter")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/identity/`
Expected: FAIL: `undefined: NormalizeLogin` (and others).

- [ ] **Step 3: Implement**

```go
// internal/identity/identity.go

// Package identity authenticates and registers users of database
// connections and throttles failed logins.
package identity

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	ErrInvalidCredentials = errors.New("identity: invalid credentials")
	ErrUserBlocked        = errors.New("identity: user is blocked")
	ErrSignupDisabled     = errors.New("identity: signup is disabled for this connection")
	ErrUserExists         = errors.New("identity: user already exists")
)

// PolicyError explains why input was rejected. Reason is safe to show to
// the person signing up.
type PolicyError struct{ Reason string }

func (e *PolicyError) Error() string { return "identity: " + e.Reason }

const (
	defaultMinPasswordLength = 8
	// maxPasswordBytes bounds hashing work per request.
	maxPasswordBytes = 256
)

// NormalizeLogin trims and lowercases an email or username.
func NormalizeLogin(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// CheckPassword enforces a connection's password policy.
func CheckPassword(p store.PasswordPolicy, password string) error {
	minLen := p.MinLength
	if minLen <= 0 {
		minLen = defaultMinPasswordLength
	}
	if len(password) > maxPasswordBytes {
		return &PolicyError{Reason: "password is too long"}
	}
	if utf8.RuneCountInString(password) < minLen {
		return &PolicyError{Reason: fmt.Sprintf("password must be at least %d characters", minLen)}
	}
	if p.RequireCharacterClasses > 0 {
		var lower, upper, digit, other bool
		for _, r := range password {
			switch {
			case unicode.IsLower(r):
				lower = true
			case unicode.IsUpper(r):
				upper = true
			case unicode.IsDigit(r):
				digit = true
			default:
				other = true
			}
		}
		n := 0
		for _, b := range []bool{lower, upper, digit, other} {
			if b {
				n++
			}
		}
		if n < p.RequireCharacterClasses {
			return &PolicyError{Reason: fmt.Sprintf(
				"password must contain at least %d of: lowercase letters, uppercase letters, digits, symbols",
				p.RequireCharacterClasses)}
		}
	}
	return nil
}
```

```go
// internal/identity/database.go
package identity

import (
	"context"
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9_.+-]{1,64}$`)

// dummyHash is verified when a login names an unknown user, so that the
// response time does not reveal whether the user exists.
var dummyHash = sync.OnceValue(func() string {
	h, err := secrets.Hash("zeroauthy timing equalizer")
	if err != nil {
		panic(err)
	}
	return h
})

// Database authenticates users stored by zeroauthy (strategy "auth0").
type Database struct {
	Store store.Store
	Now   func() time.Time
}

func (d *Database) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Login checks a login (email or username) and password against a
// database connection. It returns ErrInvalidCredentials for unknown users
// and wrong passwords alike, and ErrUserBlocked only after the password
// has been verified.
func (d *Database) Login(ctx context.Context, conn *store.Connection, login, password string) (*store.User, error) {
	u, err := d.Store.Users().FindByLogin(ctx, conn.TenantID, conn.Name, NormalizeLogin(login))
	if errors.Is(err, store.ErrNotFound) {
		_, _ = secrets.Verify(dummyHash(), password)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	hash := ""
	for _, id := range u.Identities {
		if id.Connection == conn.Name {
			hash = id.PasswordHash
		}
	}
	if hash == "" {
		_, _ = secrets.Verify(dummyHash(), password)
		return nil, ErrInvalidCredentials
	}
	ok, err := secrets.Verify(hash, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidCredentials
	}
	if u.Blocked {
		return nil, ErrUserBlocked
	}
	return u, nil
}

// Signup registers a user on a database connection.
func (d *Database) Signup(ctx context.Context, conn *store.Connection, email, username, password string) (*store.User, error) {
	if conn.DisableSignup {
		return nil, ErrSignupDisabled
	}
	email = NormalizeLogin(email)
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email || addr.Name != "" {
		return nil, &PolicyError{Reason: "enter a valid email address"}
	}
	username = NormalizeLogin(username)
	if conn.RequiresUsername {
		if !usernamePattern.MatchString(username) {
			return nil, &PolicyError{Reason: "username must be 1-64 characters: letters, digits, and _ . + -"}
		}
	} else {
		username = ""
	}
	if err := CheckPassword(conn.PasswordPolicy, password); err != nil {
		return nil, err
	}
	hash, err := secrets.Hash(password)
	if err != nil {
		return nil, err
	}
	id := secrets.RandomHex(12)
	now := d.now().UTC()
	u := &store.User{
		TenantID: conn.TenantID,
		UserID:   store.StrategyDatabase + "|" + id,
		Email:    email,
		Username: username,
		Name:     email,
		Nickname: strings.SplitN(email, "@", 2)[0],
		Identities: []store.Identity{{
			Connection: conn.Name, Provider: store.StrategyDatabase, UserID: id, PasswordHash: hash,
		}},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := d.Store.Users().Create(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, ErrUserExists
		}
		return nil, err
	}
	return u, nil
}
```

```go
// internal/identity/throttle.go
package identity

import (
	"sync"
	"time"
)

// maxThrottleEntries bounds memory. Expired entries are pruned when the
// map grows past it.
const maxThrottleEntries = 100_000

// Throttle locks a key after too many failures within a window. It is
// in-process; each server instance counts separately.
type Throttle struct {
	Now func() time.Time

	max     int
	window  time.Duration
	lockout time.Duration

	mu      sync.Mutex
	entries map[string]*throttleEntry
}

type throttleEntry struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

func NewThrottle(maxFailures int, window, lockout time.Duration) *Throttle {
	return &Throttle{max: maxFailures, window: window, lockout: lockout, entries: map[string]*throttleEntry{}}
}

func (t *Throttle) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// Allowed reports whether an attempt for key may proceed.
func (t *Throttle) Allowed(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[key]
	return !ok || !t.now().Before(e.lockedUntil)
}

// Failure records a failed attempt.
func (t *Throttle) Failure(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	e, ok := t.entries[key]
	if !ok || now.Sub(e.windowStart) > t.window {
		if len(t.entries) >= maxThrottleEntries {
			t.prune(now)
		}
		e = &throttleEntry{windowStart: now}
		t.entries[key] = e
	}
	e.failures++
	if e.failures >= t.max {
		e.lockedUntil = now.Add(t.lockout)
		e.failures = 0
		e.windowStart = now
	}
}

// Success clears the failures for key.
func (t *Throttle) Success(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// prune removes entries whose window and lockout have both passed. The
// caller holds the lock.
func (t *Throttle) prune(now time.Time) {
	for k, e := range t.entries {
		if now.Sub(e.windowStart) > t.window && !now.Before(e.lockedUntil) {
			delete(t.entries, k)
		}
	}
}
```

- [ ] **Step 4: Run the tests**

Run: `go test -race ./internal/identity/`
Expected: `ok`. Hashing makes this take a few seconds.

- [ ] **Step 5: Commit**

```bash
git add internal/identity
git commit -m "feat(identity): add database login and signup, password policy, login throttle"
```

---

### Task 5: Seed: connections, users, session and branding settings

**Files:**
- Modify: `internal/seed/seed.go`, `internal/seed/validate.go`, `internal/seed/apply.go`, `internal/seed/seed_test.go`

**Interfaces:**
- Consumes: `identity.CheckPassword`, `identity.NormalizeLogin`, `store.Connection`, `store.User`, `store.Branding`, `secrets.Hash/Verify/RandomHex/RandomString`.
- Produces: the seed YAML shape below. `seed.Apply` upserts connections by name and users by (connection, email). It never deletes. It keeps a user's password hash when the seed password still verifies.

```yaml
tenants:
  - name: acme
    session_lifetime: 604800        # seconds; optional
    idle_session_lifetime: 259200   # seconds; optional
    branding: {logo_url: "https://...", primary_color: "#1a73e8"}  # optional
    clients:
      - client_id: spa
        app_type: spa
        id_token_lifetime: 36000    # optional
        # ...existing client fields
    connections:
      - name: Username-Password-Authentication
        strategy: auth0              # optional; the only supported value
        enabled_clients: [spa]
        disable_signup: false
        requires_username: false
        password_policy: {min_length: 8, require_character_classes: 0}
    users:
      - connection: Username-Password-Authentication
        email: alice@example.com     # stored lowercase
        password: "plaintext; hashed when applied"
        email_verified: true
        username: alice              # required iff the connection requires usernames
        name: Alice Example
        nickname: alice
        picture: https://...
        blocked: false
```

- [ ] **Step 1: Write the failing tests**

Append to `internal/seed/seed_test.go`:

```go
const sampleWithUsers = `
tenants:
  - name: acme
    domains: [acme.test]
    session_lifetime: 3600
    idle_session_lifetime: 600
    branding: {logo_url: "https://cdn.acme.test/logo.png", primary_color: "#1A73E8"}
    clients:
      - {client_id: spa, app_type: spa, id_token_lifetime: 1200, callbacks: ["https://app.acme.test/"]}
    connections:
      - name: Username-Password-Authentication
        enabled_clients: [spa]
        password_policy: {min_length: 10}
    users:
      - connection: Username-Password-Authentication
        email: " Alice@Acme.TEST "
        password: "alice password 1"
        email_verified: true
        name: Alice
`

func TestApplyConnectionsAndUsers(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(sampleWithUsers))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if tn.SessionLifetime != 3600 || tn.IdleSessionLifetime != 600 || tn.Branding.PrimaryColor != "#1a73e8" || tn.Branding.LogoURL != "https://cdn.acme.test/logo.png" {
		t.Errorf("tenant settings = %+v", tn)
	}
	c, _ := st.Clients().Get(ctx, tn.ID, "spa")
	if c.IDTokenLifetime != 1200 {
		t.Errorf("id_token_lifetime = %d", c.IDTokenLifetime)
	}
	conn, err := st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	if err != nil || conn.Strategy != store.StrategyDatabase || conn.PasswordPolicy.MinLength != 10 || len(conn.EnabledClients) != 1 {
		t.Fatalf("connection = %+v, %v", conn, err)
	}
	u, err := st.Users().FindByLogin(ctx, tn.ID, conn.Name, "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if !u.EmailVerified || u.Name != "Alice" || u.Nickname != "alice" || !strings.HasPrefix(u.UserID, "auth0|") {
		t.Errorf("user = %+v", u)
	}
	if ok, _ := secrets.Verify(u.Identities[0].PasswordHash, "alice password 1"); !ok {
		t.Error("seeded password does not verify")
	}

	// Idempotent: same user ID and hash on re-apply; a changed password is re-hashed.
	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	u2, _ := st.Users().FindByLogin(ctx, tn.ID, conn.Name, "alice@acme.test")
	if u2.UserID != u.UserID || u2.Identities[0].PasswordHash != u.Identities[0].PasswordHash {
		t.Fatal("re-apply changed the user")
	}
	f2, _ := Parse([]byte(strings.Replace(sampleWithUsers, "alice password 1", "alice password 2", 1)))
	if err := Apply(ctx, st, f2, fixedNow); err != nil {
		t.Fatal(err)
	}
	u3, _ := st.Users().FindByLogin(ctx, tn.ID, conn.Name, "alice@acme.test")
	if ok, _ := secrets.Verify(u3.Identities[0].PasswordHash, "alice password 2"); !ok || u3.UserID != u.UserID {
		t.Fatal("changed password not applied in place")
	}
}

func TestValidateConnectionsAndUsers(t *testing.T) {
	base := `tenants: [{name: a, clients: [{client_id: spa, app_type: spa}], connections: [%s], users: [%s]}]`
	conn := `{name: DB, enabled_clients: [spa]}`
	cases := map[string]struct{ conns, users, want string }{
		"unknown strategy":   {`{name: DB, strategy: google-oauth2}`, ``, `strategy "google-oauth2"`},
		"unknown client":     {`{name: DB, enabled_clients: [nope]}`, ``, `unknown client "nope"`},
		"dup connection":     {conn + `, ` + conn, ``, `duplicate connection "DB"`},
		"bad policy":         {`{name: DB, password_policy: {require_character_classes: 5}}`, ``, "require_character_classes"},
		"user unknown conn":  {conn, `{connection: Nope, email: a@b.test, password: "long enough 1"}`, `unknown connection "Nope"`},
		"user bad email":     {conn, `{connection: DB, email: nope, password: "long enough 1"}`, "valid email"},
		"user weak password": {conn, `{connection: DB, email: a@b.test, password: short}`, "at least 8"},
		"user dup email":     {conn, `{connection: DB, email: a@b.test, password: "long enough 1"}, {connection: DB, email: A@B.test, password: "long enough 2"}`, `duplicate user "a@b.test"`},
		"username required":  {`{name: DB, requires_username: true}`, `{connection: DB, email: a@b.test, password: "long enough 1"}`, "username is required"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(fmt.Sprintf(base, tc.conns, tc.users)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	for name, branding := range map[string]string{
		"http logo": `{logo_url: "http://x.test/l.png"}`,
		"bad color": `{primary_color: "blue"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(`tenants: [{name: a, branding: ` + branding + `}]`))
			if err == nil || !strings.Contains(err.Error(), "branding") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
```

Add `"fmt"` to the test file imports if it is not already there.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/seed/`
Expected: FAIL. `Parse` rejects the unknown fields `session_lifetime` and `connections` (strict decoding).

- [ ] **Step 3: Extend the seed types** (`internal/seed/seed.go`)

Add to `Tenant`:

```go
	SessionLifetime     int          `yaml:"session_lifetime"`
	IdleSessionLifetime int          `yaml:"idle_session_lifetime"`
	Branding            Branding     `yaml:"branding"`
	Connections         []Connection `yaml:"connections"`
	Users               []User       `yaml:"users"`
```

Add to `Client`:

```go
	IDTokenLifetime int `yaml:"id_token_lifetime"`
```

Append:

```go
type Branding struct {
	LogoURL      string `yaml:"logo_url"`
	PrimaryColor string `yaml:"primary_color"`
}

type Connection struct {
	Name             string         `yaml:"name"`
	Strategy         string         `yaml:"strategy"`
	EnabledClients   []string       `yaml:"enabled_clients"`
	DisableSignup    bool           `yaml:"disable_signup"`
	RequiresUsername bool           `yaml:"requires_username"`
	PasswordPolicy   PasswordPolicy `yaml:"password_policy"`
}

type PasswordPolicy struct {
	MinLength               int `yaml:"min_length"`
	RequireCharacterClasses int `yaml:"require_character_classes"`
}

type User struct {
	Connection    string `yaml:"connection"`
	Email         string `yaml:"email"`
	Username      string `yaml:"username"`
	// Password is plaintext in the seed file and hashed when applied.
	Password      string `yaml:"password"`
	EmailVerified bool   `yaml:"email_verified"`
	Name          string `yaml:"name"`
	Nickname      string `yaml:"nickname"`
	Picture       string `yaml:"picture"`
	Blocked       bool   `yaml:"blocked"`
}
```

- [ ] **Step 4: Extend validation** (`internal/seed/validate.go`)

Add `"net/mail"` and `"net/url"` to the imports, plus `"github.com/zeroauthy/zeroauthy/internal/identity"`. Add a color pattern next to `dnsLabel`:

```go
var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
```

At the end of `(*Tenant).validate`, before `return errs`, add:

```go
	if b := t.Branding; b.LogoURL != "" {
		if u, err := url.Parse(b.LogoURL); err != nil || u.Scheme != "https" || u.Host == "" {
			fail("branding.logo_url must be an https URL")
		}
	}
	if c := t.Branding.PrimaryColor; c != "" && !hexColor.MatchString(c) {
		fail("branding.primary_color must look like #1a73e8")
	}

	conns := map[string]*Connection{}
	for i := range t.Connections {
		c := &t.Connections[i]
		if c.Name == "" {
			fail("connections[%d]: name is required", i)
			continue
		}
		if conns[c.Name] != nil {
			fail("duplicate connection %q", c.Name)
		}
		conns[c.Name] = c
		if c.Strategy == "" {
			c.Strategy = store.StrategyDatabase
		}
		if c.Strategy != store.StrategyDatabase {
			fail("connection %q: strategy %q is not supported (only %q)", c.Name, c.Strategy, store.StrategyDatabase)
		}
		for _, id := range c.EnabledClients {
			if !clients[id] {
				fail("connection %q: unknown client %q", c.Name, id)
			}
		}
		if p := c.PasswordPolicy; p.MinLength < 0 || p.RequireCharacterClasses < 0 || p.RequireCharacterClasses > 4 {
			fail("connection %q: password_policy.min_length must be >= 0 and require_character_classes 0-4", c.Name)
		}
	}

	seenUsers := map[[2]string]bool{}
	for i := range t.Users {
		u := &t.Users[i]
		c := conns[u.Connection]
		if c == nil {
			fail("users[%d]: unknown connection %q", i, u.Connection)
			continue
		}
		u.Email = identity.NormalizeLogin(u.Email)
		u.Username = identity.NormalizeLogin(u.Username)
		if addr, err := mail.ParseAddress(u.Email); err != nil || addr.Address != u.Email {
			fail("users[%d]: %q is not a valid email address", i, u.Email)
			continue
		}
		k := [2]string{u.Connection, u.Email}
		if seenUsers[k] {
			fail("duplicate user %q on connection %q", u.Email, u.Connection)
		}
		seenUsers[k] = true
		if c.RequiresUsername && u.Username == "" {
			fail("user %q: username is required by connection %q", u.Email, c.Name)
		}
		if err := identity.CheckPassword(store.PasswordPolicy{
			MinLength: c.PasswordPolicy.MinLength, RequireCharacterClasses: c.PasswordPolicy.RequireCharacterClasses,
		}, u.Password); err != nil {
			fail("user %q: %v", u.Email, err)
		}
	}
```

> The "user weak password" case expects the text "at least 8". `identity.PolicyError` messages begin with `identity: `, followed by the reason. The `fail` call includes the full error, so the substring matches.

- [ ] **Step 5: Extend apply** (`internal/seed/apply.go`)

In `applyTenant`, set the new tenant fields in both the create and the update branches, next to the existing assignment of `FriendlyName`, `Domains` and `DefaultAudience`:

```go
		tn.SessionLifetime, tn.IdleSessionLifetime = in.SessionLifetime, in.IdleSessionLifetime
		tn.Branding = store.Branding{LogoURL: in.Branding.LogoURL, PrimaryColor: strings.ToLower(in.Branding.PrimaryColor)}
```

(Add `"strings"` to the imports.) In `applyClient`, after setting `c.AllowedOrigins`:

```go
	c.IDTokenLifetime = in.IDTokenLifetime
```

At the end of `applyTenant`, before `return nil`:

```go
	for _, c := range in.Connections {
		if err := applyConnection(ctx, st, tn.ID, c, now); err != nil {
			return fmt.Errorf("connection %q: %w", c.Name, err)
		}
	}
	for _, u := range in.Users {
		if err := applyUser(ctx, st, tn.ID, u, now); err != nil {
			return fmt.Errorf("user %q: %w", u.Email, err)
		}
	}
```

Append:

```go
func applyConnection(ctx context.Context, st store.Store, tenantID string, in Connection, now time.Time) error {
	c, err := st.Connections().GetByName(ctx, tenantID, in.Name)
	create := errors.Is(err, store.ErrNotFound)
	if err != nil && !create {
		return err
	}
	if create {
		c = &store.Connection{TenantID: tenantID, ID: "con_" + secrets.RandomString(16), Name: in.Name, CreatedAt: now}
	}
	c.Strategy = in.Strategy
	c.EnabledClients = slices.Clone(in.EnabledClients)
	c.DisableSignup, c.RequiresUsername = in.DisableSignup, in.RequiresUsername
	c.PasswordPolicy = store.PasswordPolicy{MinLength: in.PasswordPolicy.MinLength, RequireCharacterClasses: in.PasswordPolicy.RequireCharacterClasses}
	if create {
		return st.Connections().Create(ctx, c)
	}
	return st.Connections().Update(ctx, c)
}

func applyUser(ctx context.Context, st store.Store, tenantID string, in User, now time.Time) error {
	u, err := st.Users().FindByLogin(ctx, tenantID, in.Connection, in.Email)
	create := errors.Is(err, store.ErrNotFound)
	if err != nil && !create {
		return err
	}
	if create {
		id := secrets.RandomHex(12)
		u = &store.User{
			TenantID: tenantID, UserID: store.StrategyDatabase + "|" + id, CreatedAt: now,
			Identities: []store.Identity{{Connection: in.Connection, Provider: store.StrategyDatabase, UserID: id}},
		}
	}
	u.Email, u.EmailVerified, u.Username = in.Email, in.EmailVerified, in.Username
	u.Name, u.Nickname, u.Picture, u.Blocked = in.Name, in.Nickname, in.Picture, in.Blocked
	if u.Name == "" {
		u.Name = in.Email
	}
	if u.Nickname == "" {
		u.Nickname = strings.SplitN(in.Email, "@", 2)[0]
	}
	u.UpdatedAt = now
	for i := range u.Identities {
		if u.Identities[i].Connection != in.Connection {
			continue
		}
		if ok, err := secrets.Verify(u.Identities[i].PasswordHash, in.Password); err == nil && ok {
			continue
		}
		h, err := secrets.Hash(in.Password)
		if err != nil {
			return err
		}
		u.Identities[i].PasswordHash = h
	}
	if create {
		return st.Users().Create(ctx, u)
	}
	return st.Users().Update(ctx, u)
}
```

> On create, the identity starts with an empty `PasswordHash`, so `secrets.Verify` returns an error and the loop hashes the password. That is intended.

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/seed/ ./internal/... && go vet ./...`
Expected: `ok` everywhere.

- [ ] **Step 7: Commit**

```bash
git add internal/seed
git commit -m "feat(seed): seed connections, users, session lifetimes, branding, id token lifetime"
```

---

### Task 6: Token verification, OIDC user claims, ID tokens

**Files:**
- Modify: `internal/keys/manager.go`, `internal/keys/manager_test.go`
- Create: `internal/claims/claims.go`, `internal/claims/claims_test.go`
- Modify: `internal/oauth/minter.go`, `internal/oauth/minter_test.go`

**Interfaces:**
- Produces:
  - `(*keys.Manager).Verify(ctx, tenantID, raw string, dst ...any) error`. It accepts RS256 only, requires the `kid` to be one of the tenant's published keys (current, next or previous), and decodes the claims into `dst`. It does **not** validate `exp`, `iss` or `aud`; callers do.
  - `var keys.ErrInvalidToken`.
  - `claims.ForUser(u *store.User, scopes []string) map[string]any`: always includes `sub`. With `profile`: `name`, `nickname`, `updated_at` (unix seconds), and `picture` if set. With `email`: `email`, `email_verified`.
  - `oauth.IDTokenParams{TenantID, Issuer, ClientID string; User *store.User; Scopes []string; Nonce, SessionID string; AuthTime time.Time; AccessToken string; Lifetime time.Duration}`, `(*Minter).IDToken(ctx, p) (string, error)`, `const oauth.DefaultIDTokenLifetime = 10 * time.Hour`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/keys/manager_test.go`:

```go
func TestVerify(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(ctx, "ten_b"); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Sign(ctx, "ten_a", map[string]any{"sub": "u1"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := m.Verify(ctx, "ten_a", raw, &got); err != nil || got["sub"] != "u1" {
		t.Fatalf("Verify = %v, %v", got, err)
	}
	if err := m.Verify(ctx, "ten_b", raw, &got); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("cross-tenant Verify err = %v", err)
	}
	if err := m.Verify(ctx, "ten_a", raw[:len(raw)-4]+"AAAA", &got); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tampered Verify err = %v", err)
	}
	if err := m.Verify(ctx, "ten_a", "not.a.jwt", &got); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("garbage Verify err = %v", err)
	}
	// Still valid after one rotation (key becomes "previous").
	if err := m.Rotate(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(ctx, "ten_a", raw, &got); err != nil {
		t.Fatalf("Verify after rotation: %v", err)
	}
}
```

```go
// internal/claims/claims_test.go
package claims

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestForUser(t *testing.T) {
	u := &store.User{
		UserID: "auth0|1", Email: "alice@example.com", EmailVerified: true,
		Name: "Alice", Nickname: "ally", Picture: "https://img.test/a.png",
		UpdatedAt: time.Unix(1700000000, 0),
	}
	cases := []struct {
		scopes []string
		want   map[string]any
	}{
		{[]string{"openid"}, map[string]any{"sub": "auth0|1"}},
		{[]string{"openid", "email"}, map[string]any{"sub": "auth0|1", "email": "alice@example.com", "email_verified": true}},
		{[]string{"openid", "profile"}, map[string]any{
			"sub": "auth0|1", "name": "Alice", "nickname": "ally", "picture": "https://img.test/a.png", "updated_at": int64(1700000000),
		}},
	}
	for _, tc := range cases {
		if diff := cmp.Diff(tc.want, ForUser(u, tc.scopes)); diff != "" {
			t.Errorf("scopes %v (-want +got):\n%s", tc.scopes, diff)
		}
	}
}

func TestForUserFallbacks(t *testing.T) {
	got := ForUser(&store.User{UserID: "auth0|2", Email: "bob@example.com"}, []string{"profile"})
	if got["name"] != "bob@example.com" || got["nickname"] != "bob" {
		t.Fatalf("fallbacks = %v", got)
	}
	if _, ok := got["picture"]; ok {
		t.Fatal("empty picture must be omitted")
	}
}
```

Append to `internal/oauth/minter_test.go`:

```go
func TestIDToken(t *testing.T) {
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	u := &store.User{UserID: "auth0|1", Email: "alice@example.com", EmailVerified: true, Name: "Alice", UpdatedAt: fixedNow()}
	authTime := fixedNow().Add(-time.Minute)
	raw, err := m.IDToken(context.Background(), IDTokenParams{
		TenantID: "ten_a", Issuer: "https://a.example.test/", ClientID: "spa", User: u,
		Scopes: []string{"openid", "email"}, Nonce: "n-123", SessionID: "sid-1",
		AuthTime: authTime, AccessToken: "the-access-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := verifyToken(t, km, "ten_a", raw)
	iat := float64(fixedNow().Unix())
	sum := sha256.Sum256([]byte("the-access-token"))
	want := map[string]any{
		"iss": "https://a.example.test/", "sub": "auth0|1", "aud": "spa",
		"iat": iat, "exp": iat + DefaultIDTokenLifetime.Seconds(), "auth_time": float64(authTime.Unix()),
		"nonce": "n-123", "sid": "sid-1", "email": "alice@example.com", "email_verified": true,
		"at_hash": base64.RawURLEncoding.EncodeToString(sum[:16]),
	}
	if diff := cmp.Diff(want, claims); diff != "" {
		t.Fatalf("claims (-want +got):\n%s", diff)
	}
}
```

Add `"crypto/sha256"`, `"encoding/base64"`, `"github.com/google/go-cmp/cmp"` and `"github.com/zeroauthy/zeroauthy/internal/store"` to the test imports.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/keys/ ./internal/claims/ ./internal/oauth/`
Expected: FAIL with `undefined: ErrInvalidToken`, `ForUser`, `IDTokenParams`.

- [ ] **Step 3: Implement**

Append to `internal/keys/manager.go`:

```go
// ErrInvalidToken means a token is malformed, uses another algorithm, or
// is not signed by one of the tenant's published keys.
var ErrInvalidToken = errors.New("keys: invalid token")

// Verify checks raw's signature against the tenant's published keys
// (current, next, previous) and decodes its claims into dst. It does not
// validate time or audience claims.
func (m *Manager) Verify(ctx context.Context, tenantID, raw string, dst ...any) error {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(tok.Headers) != 1 {
		return ErrInvalidToken
	}
	set, err := m.JWKS(ctx, tenantID)
	if err != nil {
		return err
	}
	keys := set.Key(tok.Headers[0].KeyID)
	if len(keys) != 1 {
		return ErrInvalidToken
	}
	if err := tok.Claims(keys[0].Key, dst...); err != nil {
		return ErrInvalidToken
	}
	return nil
}
```

```go
// internal/claims/claims.go

// Package claims builds the OpenID Connect standard claims for a user.
package claims

import (
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ForUser returns the claims a user's ID token and /userinfo response
// carry for the granted scopes (OpenID Connect Core §5.4).
func ForUser(u *store.User, scopes []string) map[string]any {
	out := map[string]any{"sub": u.UserID}
	if slices.Contains(scopes, "profile") {
		out["name"] = Name(u)
		out["nickname"] = Nickname(u)
		out["updated_at"] = u.UpdatedAt.Unix()
		if u.Picture != "" {
			out["picture"] = u.Picture
		}
	}
	if slices.Contains(scopes, "email") {
		out["email"] = u.Email
		out["email_verified"] = u.EmailVerified
	}
	return out
}

// Name is the display name, falling back to the email or username.
func Name(u *store.User) string {
	switch {
	case u.Name != "":
		return u.Name
	case u.Email != "":
		return u.Email
	default:
		return u.Username
	}
}

// Nickname falls back to the email's local part or the username.
func Nickname(u *store.User) string {
	switch {
	case u.Nickname != "":
		return u.Nickname
	case u.Email != "":
		return strings.SplitN(u.Email, "@", 2)[0]
	default:
		return u.Username
	}
}
```

Append to `internal/oauth/minter.go` (add `"crypto/sha256"`, `"encoding/base64"`, `claims` and `store` imports). Also refactor `AccessToken` to use the new `now()` helper in place of its inline `now := time.Now ...` block:

```go
// DefaultIDTokenLifetime applies when the client sets none.
const DefaultIDTokenLifetime = 10 * time.Hour

func (m *Minter) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

type IDTokenParams struct {
	TenantID  string
	Issuer    string
	ClientID  string
	User      *store.User
	Scopes    []string
	Nonce     string
	SessionID string
	AuthTime  time.Time
	// AccessToken, when set, adds at_hash (OpenID Connect Core §3.1.3.6).
	AccessToken string
	// Lifetime defaults to DefaultIDTokenLifetime when zero.
	Lifetime time.Duration
}

// IDToken returns a signed OpenID Connect ID token.
func (m *Minter) IDToken(ctx context.Context, p IDTokenParams) (string, error) {
	lifetime := p.Lifetime
	if lifetime <= 0 {
		lifetime = DefaultIDTokenLifetime
	}
	c := claims.ForUser(p.User, p.Scopes)
	iat := m.now().Unix()
	c["iss"] = p.Issuer
	c["aud"] = p.ClientID
	c["iat"] = iat
	c["exp"] = iat + int64(lifetime/time.Second)
	c["auth_time"] = p.AuthTime.Unix()
	if p.Nonce != "" {
		c["nonce"] = p.Nonce
	}
	if p.SessionID != "" {
		c["sid"] = p.SessionID
	}
	if p.AccessToken != "" {
		sum := sha256.Sum256([]byte(p.AccessToken))
		c["at_hash"] = base64.RawURLEncoding.EncodeToString(sum[:16])
	}
	return m.Keys.Sign(ctx, p.TenantID, c)
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/keys/ ./internal/claims/ ./internal/oauth/ && go vet ./...`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/keys internal/claims internal/oauth/minter.go internal/oauth/minter_test.go
git commit -m "feat: verify tenant tokens, build OIDC user claims, mint ID tokens"
```

---

### Task 7: Hosted pages: templates, CSP nonces, form_post and web_message responses

**Files:**
- Create: `internal/ui/ui.go`, `internal/ui/ui_test.go`
- Create: `internal/ui/templates/layout.html`, `login.html`, `signup.html`, `error.html`, `form_post.html`, `web_message.html`

**Interfaces:**
- Produces (package `ui`):
  - `type Tenant struct{ Name, LogoURL, PrimaryColor string }`, `func TenantView(t *store.Tenant) Tenant`.
  - `type LoginData struct{ State, CSRF, Login, SignupURL, Error string }`. An empty `SignupURL` hides the signup link.
  - `type SignupData struct{ State, CSRF, Email, Username string; RequiresUsername bool; LoginURL, Error string }`.
  - `func RenderLogin(w http.ResponseWriter, status int, t Tenant, d LoginData)`.
  - `func RenderSignup(w http.ResponseWriter, status int, t Tenant, d SignupData)`.
  - `func RenderError(w http.ResponseWriter, status int, t Tenant, message string)`.
  - `func RenderFormPost(w http.ResponseWriter, action string, params url.Values)`: an auto-submitting POST to `action`.
  - `func RenderWebMessage(w http.ResponseWriter, targetOrigin string, response map[string]string)`: `postMessage({type:"authorization_response", response}, targetOrigin)` to `window.opener || window.parent`.
  - Every render sets `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and a nonce-based CSP. Login, signup, error and form_post pages also send `frame-ancestors 'none'` plus `X-Frame-Options: DENY`. The web_message page sends `frame-ancestors <targetOrigin>` and no `X-Frame-Options`.

- [ ] **Step 1: Write the failing test**

```go
// internal/ui/ui_test.go
package ui

import (
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var nonceAttr = regexp.MustCompile(`nonce="([^"]+)"`)

func checkNonce(t *testing.T, csp, body string) {
	t.Helper()
	m := nonceAttr.FindAllStringSubmatch(body, -1)
	if len(m) == 0 {
		t.Fatal("no nonce attribute in body")
	}
	for _, x := range m {
		if !strings.Contains(csp, "'nonce-"+x[1]+"'") {
			t.Fatalf("nonce %q not in CSP %q", x[1], csp)
		}
	}
}

func TestRenderLogin(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderLogin(rec, 200, Tenant{Name: "Acme", PrimaryColor: "#112233", LogoURL: "https://cdn.acme.test/l.png"}, LoginData{
		State: "st", CSRF: "cs", Login: `"><script>alert(1)</script>`, SignupURL: "/u/signup?state=st", Error: "Nope",
	})
	body, h := rec.Body.String(), rec.Header()
	for _, want := range []string{`name="state" value="st"`, `name="csrf" value="cs"`, `id="username"`, `id="password"`,
		`type="submit"`, "Acme", "#112233", "https://cdn.acme.test/l.png", "/u/signup?state=st", "Nope"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("login hint not escaped")
	}
	csp := h.Get("Content-Security-Policy")
	checkNonce(t, csp, body)
	for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "form-action 'self'", "img-src https:"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if h.Get("X-Frame-Options") != "DENY" || h.Get("Cache-Control") != "no-store" || h.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("headers = %v", h)
	}
}

func TestRenderLoginWithoutSignup(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderLogin(rec, 200, Tenant{Name: "Acme"}, LoginData{State: "st", CSRF: "cs"})
	if strings.Contains(rec.Body.String(), "/u/signup") {
		t.Fatal("signup link shown without SignupURL")
	}
}

func TestRenderSignupAndError(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderSignup(rec, 400, Tenant{Name: "Acme"}, SignupData{State: "st", CSRF: "cs", Email: "a@b.test", RequiresUsername: true, LoginURL: "/u/login?state=st", Error: "Too short"})
	body := rec.Body.String()
	for _, want := range []string{`id="email"`, `id="username"`, `id="password"`, "Too short", "/u/login?state=st"} {
		if !strings.Contains(body, want) {
			t.Errorf("signup lacks %q", want)
		}
	}
	if rec.Code != 400 {
		t.Errorf("status %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	RenderError(rec, 400, Tenant{Name: "Acme"}, "Something <b>bad</b>")
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "Something &lt;b&gt;bad&lt;/b&gt;") {
		t.Fatalf("error page = %d %s", rec.Code, rec.Body)
	}
}

func TestRenderFormPost(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderFormPost(rec, "https://app.test/cb?x=1", url.Values{"code": {"abc"}, "state": {`"><x`}})
	body, csp := rec.Body.String(), rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{`method="post"`, `action="https://app.test/cb?x=1"`, `name="code" value="abc"`, `value="&#34;&gt;&lt;x"`} {
		if !strings.Contains(body, want) {
			t.Errorf("form_post lacks %q:\n%s", want, body)
		}
	}
	checkNonce(t, csp, body)
	if !strings.Contains(csp, "form-action https://app.test") {
		t.Errorf("CSP %q does not allow posting to the client", csp)
	}
}

func TestRenderWebMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderWebMessage(rec, "https://app.test", map[string]string{"code": "abc", "state": "</script><script>alert(1)"})
	body, h := rec.Body.String(), rec.Header()
	if strings.Contains(body, "</script><script>alert(1)") {
		t.Fatal("response not escaped in script context")
	}
	// html/template escapes "/" inside JS strings, so match the host only.
	for _, want := range []string{"authorization_response", "postMessage", "app.test"} {
		if !strings.Contains(body, want) {
			t.Errorf("web_message lacks %q:\n%s", want, body)
		}
	}
	csp := h.Get("Content-Security-Policy")
	checkNonce(t, csp, body)
	if !strings.Contains(csp, "frame-ancestors https://app.test") || h.Get("X-Frame-Options") != "" {
		t.Errorf("web_message must be frameable by its origin only: csp=%q xfo=%q", csp, h.Get("X-Frame-Options"))
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/ui/`
Expected: FAIL: `undefined: RenderLogin` (and others).

- [ ] **Step 3: Write the templates.** All markup, wording and CSS are original.

`internal/ui/templates/layout.html`:

```html
{{define "layout"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{template "title" .}} · {{.Tenant.Name}}</title>
<style nonce="{{.Nonce}}">
:root { --accent: {{if .Tenant.PrimaryColor}}{{.Tenant.PrimaryColor}}{{else}}#3355cc{{end}}; }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f3f4f6;
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: #1f2933; }
main { width: min(380px, 92vw); background: #fff; border-radius: 12px; padding: 32px;
  box-shadow: 0 6px 24px rgba(0, 0, 0, .08); }
header { text-align: center; margin-bottom: 24px; }
header img { max-height: 48px; max-width: 100%; }
h1 { font-size: 1.25rem; margin: 12px 0 4px; }
p.sub { margin: 0; color: #52606d; font-size: .9rem; }
label { display: block; font-size: .85rem; margin: 16px 0 4px; }
input { width: 100%; padding: 10px 12px; border: 1px solid #cbd2d9; border-radius: 8px; font: inherit; }
input:focus { outline: 2px solid var(--accent); border-color: transparent; }
button { width: 100%; margin-top: 24px; padding: 11px; border: 0; border-radius: 8px;
  background: var(--accent); color: #fff; font: inherit; font-weight: 600; cursor: pointer; }
.alert { background: #fdecea; color: #8a1c13; padding: 10px 12px; border-radius: 8px; font-size: .9rem; }
.alt { text-align: center; margin-top: 20px; font-size: .9rem; }
a { color: var(--accent); }
</style>
</head>
<body>
<main>
<header>
{{if .Tenant.LogoURL}}<img src="{{.Tenant.LogoURL}}" alt="{{.Tenant.Name}}">{{end}}
<h1>{{template "title" .}}</h1>
<p class="sub">{{.Tenant.Name}}</p>
</header>
{{template "content" .}}
</main>
</body>
</html>{{end}}
```

`login.html`:

```html
{{define "title"}}Sign in{{end}}
{{define "content"}}
{{if .Data.Error}}<p class="alert" role="alert">{{.Data.Error}}</p>{{end}}
<form method="post" action="/u/login" novalidate>
<input type="hidden" name="state" value="{{.Data.State}}">
<input type="hidden" name="csrf" value="{{.Data.CSRF}}">
<label for="username">Email or username</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" value="{{.Data.Login}}" required autofocus>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Continue</button>
</form>
{{if .Data.SignupURL}}<p class="alt">New here? <a href="{{.Data.SignupURL}}">Create an account</a></p>{{end}}
{{end}}
```

`signup.html`:

```html
{{define "title"}}Create your account{{end}}
{{define "content"}}
{{if .Data.Error}}<p class="alert" role="alert">{{.Data.Error}}</p>{{end}}
<form method="post" action="/u/signup" novalidate>
<input type="hidden" name="state" value="{{.Data.State}}">
<input type="hidden" name="csrf" value="{{.Data.CSRF}}">
<label for="email">Email</label>
<input id="email" name="email" type="email" autocomplete="email" value="{{.Data.Email}}" required autofocus>
{{if .Data.RequiresUsername}}
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" value="{{.Data.Username}}" required>
{{end}}
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="new-password" required>
<button type="submit">Sign up</button>
</form>
<p class="alt">Already have an account? <a href="{{.Data.LoginURL}}">Sign in</a></p>
{{end}}
```

`error.html`:

```html
{{define "title"}}Something went wrong{{end}}
{{define "content"}}
<p class="alert" role="alert">{{.Data}}</p>
<p class="alt">Return to the application and try again.</p>
{{end}}
```

`form_post.html` (standalone):

```html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Continuing…</title></head>
<body>
<form method="post" action="{{.Action}}">
{{range $k, $vs := .Params}}{{range $vs}}<input type="hidden" name="{{$k}}" value="{{.}}">
{{end}}{{end}}<noscript><button type="submit">Continue</button></noscript>
</form>
<script nonce="{{.Nonce}}">document.forms[0].submit();</script>
</body>
</html>
```

`web_message.html` (standalone):

```html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Authorization response</title></head>
<body>
<script nonce="{{.Nonce}}">
(function () {
  var target = window.opener || window.parent;
  target.postMessage({ type: "authorization_response", response: {{.Response}} }, {{.Origin}});
})();
</script>
</body>
</html>
```

- [ ] **Step 4: Implement `internal/ui/ui.go`**

```go
// Package ui renders zeroauthy's hosted pages. Templates are embedded,
// original work, and every response carries a nonce-based CSP.
package ui

import (
	"bytes"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

//go:embed templates/*.html
var files embed.FS

var (
	pages = map[string]*template.Template{
		"login":  template.Must(template.ParseFS(files, "templates/layout.html", "templates/login.html")),
		"signup": template.Must(template.ParseFS(files, "templates/layout.html", "templates/signup.html")),
		"error":  template.Must(template.ParseFS(files, "templates/layout.html", "templates/error.html")),
	}
	formPost   = template.Must(template.ParseFS(files, "templates/form_post.html"))
	webMessage = template.Must(template.ParseFS(files, "templates/web_message.html"))
)

// Tenant is the branding shown on hosted pages.
type Tenant struct {
	Name         string
	LogoURL      string
	PrimaryColor string
}

// TenantView builds the page branding for a tenant.
func TenantView(t *store.Tenant) Tenant {
	name := t.FriendlyName
	if name == "" {
		name = t.Name
	}
	return Tenant{Name: name, LogoURL: t.Branding.LogoURL, PrimaryColor: t.Branding.PrimaryColor}
}

type LoginData struct {
	State, CSRF, Login string
	SignupURL          string // empty hides the signup link
	Error              string
}

type SignupData struct {
	State, CSRF, Email, Username string
	RequiresUsername             bool
	LoginURL                     string
	Error                        string
}

type page struct {
	Tenant Tenant
	Nonce  string
	Data   any
}

func RenderLogin(w http.ResponseWriter, status int, t Tenant, d LoginData) {
	render(w, status, "login", t, d)
}

func RenderSignup(w http.ResponseWriter, status int, t Tenant, d SignupData) {
	render(w, status, "signup", t, d)
}

func RenderError(w http.ResponseWriter, status int, t Tenant, message string) {
	render(w, status, "error", t, message)
}

func render(w http.ResponseWriter, status int, name string, t Tenant, data any) {
	nonce := newNonce()
	setHeaders(w, nonce, "'none'", "'self'")
	write(w, status, pages[name], "layout", page{Tenant: t, Nonce: nonce, Data: data})
}

// RenderFormPost writes the OAuth 2.0 Form Post Response Mode page.
func RenderFormPost(w http.ResponseWriter, action string, params url.Values) {
	nonce := newNonce()
	setHeaders(w, nonce, "'none'", origin(action))
	write(w, http.StatusOK, formPost, "form_post.html", map[string]any{"Action": action, "Params": params, "Nonce": nonce})
}

// RenderWebMessage writes the Web Message Response Mode page, which posts
// the authorization response to targetOrigin from a popup or iframe.
func RenderWebMessage(w http.ResponseWriter, targetOrigin string, response map[string]string) {
	nonce := newNonce()
	setHeaders(w, nonce, targetOrigin, "'none'")
	write(w, http.StatusOK, webMessage, "web_message.html", map[string]any{"Origin": targetOrigin, "Response": response, "Nonce": nonce})
}

func newNonce() string { return secrets.RandomString(22) }

// setHeaders applies the shared security headers. frameAncestors is a CSP
// source ("'none'" or an origin); formAction likewise.
func setHeaders(w http.ResponseWriter, nonce, frameAncestors, formAction string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; "+
		"img-src https:; form-action "+formAction+"; frame-ancestors "+frameAncestors+"; base-uri 'none'")
	if frameAncestors == "'none'" {
		h.Set("X-Frame-Options", "DENY")
	}
}

func write(w http.ResponseWriter, status int, t *template.Template, name string, data any) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		slog.Error("render page", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// origin returns scheme://host[:port] of u, or "'none'" if u is not an
// absolute URL.
func origin(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Scheme == "" || p.Host == "" {
		return "'none'"
	}
	return p.Scheme + "://" + p.Host
}
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/ui/ && go vet ./...`
Expected: `ok`. If the escaped-quote assertion in `TestRenderFormPost` (`&#34;&gt;&lt;x`) differs because `html/template` uses another escape for `"` in attributes, assert on the escaped form it actually emits. The test's goal is only that the raw `">` sequence does not appear. Also add an assertion that the body does not contain `value=""><x`.

- [ ] **Step 6: Commit**

```bash
git add internal/ui
git commit -m "feat(ui): add hosted login pages, form_post and web_message responses with nonce CSP"
```

---
### Task 8: Session cookie lifecycle

**Files:**
- Create: `internal/session/session.go`, `internal/session/session_test.go`

**Interfaces:**
- Consumes: `store.Sessions`, `store.Tenant` (`SessionLifetime`, `IdleSessionLifetime`), `secrets.HashToken/RandomString`.
- Produces (package `session`):
  - `const CookieName = "za_session"`.
  - `DefaultLifetime = 7*24*time.Hour` and `DefaultIdleLifetime = 3*24*time.Hour`.
  - `type Manager struct{ Store store.Store; Now func() time.Time }` with:
    - `Current(ctx, r *http.Request, t *store.Tenant) (*store.LoginSession, error)`. Returns nil, nil when there is no valid session. It slides the idle expiry and deletes expired records.
    - `Start(ctx, w http.ResponseWriter, r *http.Request, t *store.Tenant, userID, connection string, authTime time.Time) (*store.LoginSession, error)`. Replaces any existing session from `r`.
    - `AddClient(ctx, s *store.LoginSession, clientID string) error`.

- [ ] **Step 1: Write the failing test**

```go
// internal/session/session_test.go
package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func setup() (*Manager, *clock, *store.Tenant) {
	c := &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	return &Manager{Store: memory.New(), Now: c.now}, c, &store.Tenant{ID: "ten_a", Name: "a"}
}

func requestWith(cookies []*http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", "https://a.test/authorize", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

func TestStartAndCurrent(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	s, err := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v", cookies)
	}
	ck := cookies[0]
	if ck.Name != CookieName || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteNoneMode || ck.Path != "/" || len(ck.Value) < 40 {
		t.Fatalf("cookie = %+v", ck)
	}
	if s.TokenHash != secrets.HashToken(ck.Value) || s.TokenHash == ck.Value {
		t.Fatal("session must store only the cookie hash")
	}
	if !s.ExpiresAt.Equal(c.t.Add(DefaultLifetime)) || !s.IdleExpiresAt.Equal(c.t.Add(DefaultIdleLifetime)) {
		t.Fatalf("expiry = %v / %v", s.ExpiresAt, s.IdleExpiresAt)
	}

	c.t = c.t.Add(time.Hour)
	got, err := m.Current(ctx, requestWith(cookies), tn)
	if err != nil || got == nil || got.ID != s.ID {
		t.Fatalf("Current = %+v, %v", got, err)
	}
	if !got.IdleExpiresAt.Equal(c.t.Add(DefaultIdleLifetime)) {
		t.Fatalf("idle expiry not slid: %v", got.IdleExpiresAt)
	}

	other := &store.Tenant{ID: "ten_b"}
	if got, _ := m.Current(ctx, requestWith(cookies), other); got != nil {
		t.Fatal("session visible to another tenant")
	}
	if got, _ := m.Current(ctx, requestWith([]*http.Cookie{{Name: CookieName, Value: "forged"}}), tn); got != nil {
		t.Fatal("forged cookie accepted")
	}
}

func TestExpiry(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	tn.SessionLifetime, tn.IdleSessionLifetime = 7200, 1800

	rec := httptest.NewRecorder()
	_, _ = m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	cookies := rec.Result().Cookies()

	c.t = c.t.Add(31 * time.Minute) // idle timeout passed
	if got, _ := m.Current(ctx, requestWith(cookies), tn); got != nil {
		t.Fatal("idle-expired session accepted")
	}

	rec = httptest.NewRecorder()
	_, _ = m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	cookies = rec.Result().Cookies()
	for i := 0; i < 5; i++ { // stay active, but pass the absolute limit
		c.t = c.t.Add(25 * time.Minute)
		_, _ = m.Current(ctx, requestWith(cookies), tn)
	}
	if got, _ := m.Current(ctx, requestWith(cookies), tn); got != nil {
		t.Fatal("session outlived its absolute lifetime")
	}
}

func TestStartReplacesExistingSession(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	_, _ = m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	first := rec.Result().Cookies()

	rec = httptest.NewRecorder()
	_, _ = m.Start(ctx, rec, requestWith(first), tn, "auth0|2", "Database", c.t)
	if got, _ := m.Current(ctx, requestWith(first), tn); got != nil {
		t.Fatal("old session survived a new login")
	}
}

func TestAddClient(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	s, _ := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	if err := m.AddClient(ctx, s, "spa"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddClient(ctx, s, "spa"); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Current(ctx, requestWith(rec.Result().Cookies()), tn)
	if len(got.ClientIDs) != 1 || got.ClientIDs[0] != "spa" {
		t.Fatalf("clients = %v", got.ClientIDs)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/session/`
Expected: FAIL: `undefined: Manager`

- [ ] **Step 3: Implement**

```go
// internal/session/session.go

// Package session manages login session cookies. The cookie carries a
// random token; the store holds only its SHA-256.
package session

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const CookieName = "za_session"

const (
	DefaultLifetime     = 7 * 24 * time.Hour
	DefaultIdleLifetime = 3 * 24 * time.Hour
)

type Manager struct {
	Store store.Store
	Now   func() time.Time
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func lifetimes(t *store.Tenant) (absolute, idle time.Duration) {
	absolute, idle = DefaultLifetime, DefaultIdleLifetime
	if t.SessionLifetime > 0 {
		absolute = time.Duration(t.SessionLifetime) * time.Second
	}
	if t.IdleSessionLifetime > 0 {
		idle = time.Duration(t.IdleSessionLifetime) * time.Second
	}
	return absolute, idle
}

// Current returns the request's valid session for tenant t, or nil. Each
// call extends the idle expiry, never past the absolute expiry.
func (m *Manager) Current(ctx context.Context, r *http.Request, t *store.Tenant) (*store.LoginSession, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	s, err := m.Store.Sessions().GetByTokenHash(ctx, t.ID, secrets.HashToken(c.Value))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := m.now()
	if !now.Before(s.ExpiresAt) || !now.Before(s.IdleExpiresAt) {
		if err := m.Store.Sessions().Delete(ctx, t.ID, s.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		return nil, nil
	}
	_, idle := lifetimes(t)
	s.IdleExpiresAt = minTime(now.Add(idle), s.ExpiresAt)
	if err := m.Store.Sessions().Update(ctx, s); err != nil {
		return nil, err
	}
	return s, nil
}

// Start creates a session for a freshly authenticated user and sets the
// cookie. Any session the request already carries is deleted first, so a
// login always gets a new session identifier.
func (m *Manager) Start(ctx context.Context, w http.ResponseWriter, r *http.Request, t *store.Tenant, userID, connection string, authTime time.Time) (*store.LoginSession, error) {
	if old, err := r.Cookie(CookieName); err == nil && old.Value != "" {
		if s, err := m.Store.Sessions().GetByTokenHash(ctx, t.ID, secrets.HashToken(old.Value)); err == nil {
			_ = m.Store.Sessions().Delete(ctx, t.ID, s.ID)
		}
	}
	now := m.now()
	absolute, idle := lifetimes(t)
	token := secrets.RandomString(43)
	s := &store.LoginSession{
		TenantID:        t.ID,
		ID:              secrets.RandomString(24),
		TokenHash:       secrets.HashToken(token),
		UserID:          userID,
		Connection:      connection,
		AuthenticatedAt: authTime.UTC(),
		ExpiresAt:       now.Add(absolute),
		IdleExpiresAt:   minTime(now.Add(idle), now.Add(absolute)),
		CreatedAt:       now,
	}
	if err := m.Store.Sessions().Create(ctx, s); err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		Expires:  s.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		// None so the cookie reaches the hidden iframe used for silent
		// authentication (response_mode=web_message).
		SameSite: http.SameSiteNoneMode,
	})
	return s, nil
}

// AddClient records that clientID received tokens through s.
func (m *Manager) AddClient(ctx context.Context, s *store.LoginSession, clientID string) error {
	if slices.Contains(s.ClientIDs, clientID) {
		return nil
	}
	s.ClientIDs = append(s.ClientIDs, clientID)
	return m.Store.Sessions().Update(ctx, s)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
```

- [ ] **Step 4: Run the tests**

Run: `go test -race ./internal/session/`
Expected: `ok`

- [ ] **Step 5: Record decision D-0005** by appending to `docs/compat/decisions.md`. First check that the cited page loads: `curl -sL -o /dev/null -w '%{http_code}' <url>` must print `200`. If it does not, find the current public Auth0 page on session lifetime settings and cite that.

```markdown
## D-0005: Session lifetime defaults

- **Context:** The spec requires absolute and idle session timeouts but does not give defaults.
- **Sources:** https://auth0.com/docs/manage-users/sessions/configure-session-lifetime-settings (public docs on tenant session lifetime settings).
- **Decision:** Default absolute lifetime 7 days and idle lifetime 3 days, overridable per tenant (`session_lifetime`, `idle_session_lifetime`, seconds). Every authenticated request slides the idle expiry, never past the absolute expiry.
- **Rationale:** These are conservative defaults for a hosted login session. Making them configurable covers deployments that need other values.
```

- [ ] **Step 6: Commit**

```bash
git add internal/session docs/compat/decisions.md
git commit -m "feat(session): add login session cookies with absolute and idle expiry"
```

---

### Task 9: /authorize request parsing and validation

**Files:**
- Create: `internal/authz/request.go`, `internal/authz/validate.go`, `internal/authz/errors.go`
- Create: `internal/authz/validate_test.go`, `internal/authz/fixture_test.go`

**Interfaces:**
- Consumes: `store.Store` (Clients, ResourceServers, Connections), `store.Tenant`, `store.AuthMethodNone`.
- Produces (package `authz`):
  - `type Request struct{ ClientID, RedirectURI, ResponseType, ResponseMode, Scope, State, Nonce, Audience, Prompt, MaxAge, CodeChallenge, CodeChallengeMethod, Connection, LoginHint, ScreenHint, Organization, Invitation string }`. These are the raw query values; `Scope`, `Prompt` and `MaxAge` stay strings.
  - `ParseRequest(q url.Values) Request`.
  - `(Request).Params() map[string]string`; `RequestFromParams(map[string]string) Request`.
  - `(Request).Scopes() []string`; `(Request).Prompts() []string`; `(Request).MaxAgeSeconds() (int, bool)`.
  - `type Error struct{ Code, Description string }`.
  - `func validate(ctx, st store.Store, t *store.Tenant, req *Request) (client *store.Client, err *Error, redirectable bool)`. Fills in defaults: `ResponseMode` becomes `query`, and `Audience` becomes the tenant default.
  - `func callbackAllowed(callbacks []string, uri string) bool`; `func originOf(rawURL string) string`.
  - Test fixture `newFixture(t) *fixture{st store.Store; tenant *store.Tenant}`, built from a seed string (shared with Task 10).

- [ ] **Step 1: Write the fixture and failing tests**

```go
// internal/authz/fixture_test.go
package authz

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
    resource_servers:
      - {identifier: "https://api.acme.test", name: API, scopes: [{value: "read:things"}]}
    clients:
      - client_id: spa
        app_type: spa
        grant_types: [authorization_code]
        callbacks: ["https://app.acme.test/callback", "https://*.preview.acme.test/cb", "http://localhost:3000/"]
        web_origins: ["https://app.acme.test"]
      - client_id: web
        app_type: regular_web
        client_secret: web-secret
        grant_types: [authorization_code]
        callbacks: ["https://web.acme.test/cb"]
      - client_id: m2m
        app_type: non_interactive
        client_secret: m2m-secret
        grant_types: [client_credentials]
        callbacks: ["https://m2m.acme.test/cb"]
    connections:
      - {name: Username-Password-Authentication, enabled_clients: [spa, web]}
      - {name: Other-DB, enabled_clients: [web]}
    users:
      - {connection: Username-Password-Authentication, email: alice@acme.test, password: "alice password 1", email_verified: true}
  - name: globex
    domains: [globex.example.test]
    clients:
      - {client_id: globex-spa, app_type: spa, grant_types: [authorization_code], callbacks: ["https://app.globex.test/cb"]}
`

type fixture struct {
	st     store.Store
	tenant *store.Tenant
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
	tn, err := st.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{st: st, tenant: tn}
}
```

```go
// internal/authz/validate_test.go
package authz

import (
	"context"
	"net/url"
	"testing"
)

const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" // RFC 7636 Appendix B

func goodQuery() url.Values {
	return url.Values{
		"client_id":             {"spa"},
		"redirect_uri":          {"https://app.acme.test/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"st"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
}

func with(q url.Values, kv ...string) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			out.Del(kv[i])
		} else {
			out.Set(kv[i], kv[i+1])
		}
	}
	return out
}

func TestValidateOK(t *testing.T) {
	f := newFixture(t)
	req := ParseRequest(goodQuery())
	c, err, _ := validate(context.Background(), f.st, f.tenant, &req)
	if err != nil {
		t.Fatalf("unexpected error %+v", err)
	}
	if c.ClientID != "spa" || req.ResponseMode != "query" {
		t.Fatalf("client=%v mode=%q", c.ClientID, req.ResponseMode)
	}
}

func TestValidateErrors(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name         string
		q            url.Values
		code         string
		redirectable bool
	}{
		{"no client", with(goodQuery(), "client_id", ""), "invalid_request", false},
		{"unknown client", with(goodQuery(), "client_id", "nope"), "invalid_request", false},
		{"client of other tenant", with(goodQuery(), "client_id", "globex-spa", "redirect_uri", "https://app.globex.test/cb"), "invalid_request", false},
		{"no redirect_uri", with(goodQuery(), "redirect_uri", ""), "invalid_request", false},
		// Review focus 1: lookalike redirect URIs are never redirected to.
		{"trailing slash", with(goodQuery(), "redirect_uri", "https://app.acme.test/callback/"), "invalid_request", false},
		{"case differs", with(goodQuery(), "redirect_uri", "https://app.acme.test/Callback"), "invalid_request", false},
		{"extra query", with(goodQuery(), "redirect_uri", "https://app.acme.test/callback?x=1"), "invalid_request", false},
		{"fragment", with(goodQuery(), "redirect_uri", "https://app.acme.test/callback#x"), "invalid_request", false},
		{"userinfo", with(goodQuery(), "redirect_uri", "https://evil.test@app.acme.test/callback"), "invalid_request", false},
		{"other port", with(goodQuery(), "redirect_uri", "https://app.acme.test:8443/callback"), "invalid_request", false},
		{"wildcard two labels", with(goodQuery(), "redirect_uri", "https://a.b.preview.acme.test/cb"), "invalid_request", false},
		{"wildcard suffix trick", with(goodQuery(), "redirect_uri", "https://evil.test/.preview.acme.test/cb"), "invalid_request", false},
		{"wildcard scheme", with(goodQuery(), "redirect_uri", "http://x.preview.acme.test/cb"), "invalid_request", false},
		{"web_message unregistered origin", with(goodQuery(), "redirect_uri", "http://localhost:3000/", "response_mode", "web_message"), "invalid_request", false},
		// Redirectable errors.
		{"no response_type", with(goodQuery(), "response_type", ""), "invalid_request", true},
		{"implicit", with(goodQuery(), "response_type", "token"), "unsupported_response_type", true},
		{"bad response_mode", with(goodQuery(), "response_mode", "jwt"), "invalid_request", true},
		{"grant not allowed", with(goodQuery(), "client_id", "m2m", "redirect_uri", "https://m2m.acme.test/cb"), "unauthorized_client", true},
		{"public without pkce", with(goodQuery(), "code_challenge", "", "code_challenge_method", ""), "invalid_request", true},
		{"plain pkce", with(goodQuery(), "code_challenge_method", "plain"), "invalid_request", true},
		{"pkce without method", with(goodQuery(), "code_challenge_method", ""), "invalid_request", true},
		{"short challenge", with(goodQuery(), "code_challenge", "abc"), "invalid_request", true},
		{"bad max_age", with(goodQuery(), "max_age", "-1"), "invalid_request", true},
		{"prompt none plus login", with(goodQuery(), "prompt", "none login"), "invalid_request", true},
		{"unknown prompt", with(goodQuery(), "prompt", "nonsense"), "invalid_request", true},
		{"unknown audience", with(goodQuery(), "audience", "https://nope.test"), "access_denied", true},
		{"organization", with(goodQuery(), "organization", "org_1"), "invalid_request", true},
		{"connection not enabled", with(goodQuery(), "connection", "Other-DB"), "invalid_request", true},
		{"unknown connection", with(goodQuery(), "connection", "Nope"), "invalid_request", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := ParseRequest(tc.q)
			_, err, redirectable := validate(context.Background(), f.st, f.tenant, &req)
			if err == nil || err.Code != tc.code || redirectable != tc.redirectable {
				t.Fatalf("got err=%+v redirectable=%v, want %s/%v", err, redirectable, tc.code, tc.redirectable)
			}
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	f := newFixture(t)
	for name, q := range map[string]url.Values{
		"wildcard one label":     with(goodQuery(), "redirect_uri", "https://pr-42.preview.acme.test/cb"),
		"localhost http":         with(goodQuery(), "redirect_uri", "http://localhost:3000/"),
		"web_message registered": with(goodQuery(), "response_mode", "web_message", "prompt", "none"),
		"form_post":              with(goodQuery(), "response_mode", "form_post"),
		"known audience":         with(goodQuery(), "audience", "https://api.acme.test"),
		"enabled connection":     with(goodQuery(), "connection", "Username-Password-Authentication"),
		"max_age zero":           with(goodQuery(), "max_age", "0"),
		"consent prompt ignored": with(goodQuery(), "prompt", "consent"),
		"confidential no pkce":   with(goodQuery(), "client_id", "web", "redirect_uri", "https://web.acme.test/cb", "code_challenge", "", "code_challenge_method", ""),
	} {
		t.Run(name, func(t *testing.T) {
			req := ParseRequest(q)
			if _, err, _ := validate(context.Background(), f.st, f.tenant, &req); err != nil {
				t.Fatalf("unexpected error %+v", err)
			}
		})
	}
}

func TestDefaultAudience(t *testing.T) {
	f := newFixture(t)
	f.tenant.DefaultAudience = "https://api.acme.test"
	req := ParseRequest(goodQuery())
	if _, err, _ := validate(context.Background(), f.st, f.tenant, &req); err != nil || req.Audience != "https://api.acme.test" {
		t.Fatalf("audience = %q, err %+v", req.Audience, err)
	}
}

func TestRequestParamsRoundTrip(t *testing.T) {
	req := ParseRequest(with(goodQuery(), "nonce", "n", "max_age", "60", "login_hint", "a@b.test"))
	if got := RequestFromParams(req.Params()); got != req {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, req)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/authz/`
Expected: FAIL: `undefined: ParseRequest` (and others).

- [ ] **Step 3: Implement**

```go
// internal/authz/errors.go

// Package authz implements the /authorize endpoint: request validation,
// session checks, login hand-off, code issuance and response delivery.
package authz

// Error is an authorization error (RFC 6749 §4.1.2.1).
type Error struct {
	Code        string
	Description string
}

func errInvalidRequest(d string) *Error   { return &Error{"invalid_request", d} }
func errUnauthorizedClient(d string) *Error { return &Error{"unauthorized_client", d} }
func errAccessDenied(d string) *Error     { return &Error{"access_denied", d} }
func errUnsupportedResponseType(d string) *Error {
	return &Error{"unsupported_response_type", d}
}
func errLoginRequired() *Error { return &Error{"login_required", "the user must log in"} }
func errServer() *Error        { return &Error{"server_error", "internal error"} }
```

```go
// internal/authz/request.go
package authz

import (
	"net/url"
	"strconv"
	"strings"
)

// Request holds the /authorize parameters zeroauthy uses. Unknown
// parameters (such as SDK telemetry) are ignored.
type Request struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	ResponseMode        string
	Scope               string
	State               string
	Nonce               string
	Audience            string
	Prompt              string
	MaxAge              string
	CodeChallenge       string
	CodeChallengeMethod string
	Connection          string
	LoginHint           string
	ScreenHint          string
	Organization        string
	Invitation          string
}

// paramNames maps query parameter names to Request fields; it drives
// parsing and the transaction round trip.
var paramNames = []string{
	"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce",
	"audience", "prompt", "max_age", "code_challenge", "code_challenge_method",
	"connection", "login_hint", "screen_hint", "organization", "invitation",
}

func (r *Request) field(name string) *string {
	switch name {
	case "client_id":
		return &r.ClientID
	case "redirect_uri":
		return &r.RedirectURI
	case "response_type":
		return &r.ResponseType
	case "response_mode":
		return &r.ResponseMode
	case "scope":
		return &r.Scope
	case "state":
		return &r.State
	case "nonce":
		return &r.Nonce
	case "audience":
		return &r.Audience
	case "prompt":
		return &r.Prompt
	case "max_age":
		return &r.MaxAge
	case "code_challenge":
		return &r.CodeChallenge
	case "code_challenge_method":
		return &r.CodeChallengeMethod
	case "connection":
		return &r.Connection
	case "login_hint":
		return &r.LoginHint
	case "screen_hint":
		return &r.ScreenHint
	case "organization":
		return &r.Organization
	case "invitation":
		return &r.Invitation
	}
	panic("authz: unknown parameter " + name)
}

// ParseRequest reads /authorize query parameters.
func ParseRequest(q url.Values) Request {
	var r Request
	for _, name := range paramNames {
		*r.field(name) = q.Get(name)
	}
	return r
}

// Params flattens r for storage in a login transaction.
func (r Request) Params() map[string]string {
	out := map[string]string{}
	for _, name := range paramNames {
		if v := *r.field(name); v != "" {
			out[name] = v
		}
	}
	return out
}

// RequestFromParams is the inverse of Params.
func RequestFromParams(p map[string]string) Request {
	var r Request
	for _, name := range paramNames {
		*r.field(name) = p[name]
	}
	return r
}

func (r Request) Scopes() []string  { return strings.Fields(r.Scope) }
func (r Request) Prompts() []string { return strings.Fields(r.Prompt) }

// MaxAgeSeconds returns max_age and whether it was set.
func (r Request) MaxAgeSeconds() (int, bool) {
	if r.MaxAge == "" {
		return 0, false
	}
	n, err := strconv.Atoi(r.MaxAge)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
```

> `(*Request).field` is called on the addressable local `r` in `Params`. Go takes `&r` automatically because `field` has a pointer receiver and `r` is a local variable, so this compiles.

```go
// internal/authz/validate.go
package authz

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	responseModes = []string{"query", "fragment", "form_post", "web_message"}
	knownPrompts  = []string{"none", "login", "consent", "select_account"}
	// RFC 7636 §4.2: S256 challenges are 43 base64url characters.
	s256Challenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// validate checks an authorization request in the order of spec §6.2.
// Errors with redirectable=false must be shown on an error page: the
// client or redirect URI cannot be trusted.
func validate(ctx context.Context, st store.Store, t *store.Tenant, req *Request) (*store.Client, *Error, bool) {
	if req.ClientID == "" {
		return nil, errInvalidRequest("client_id is required"), false
	}
	client, err := st.Clients().Get(ctx, t.ID, req.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errInvalidRequest("unknown client"), false
	}
	if err != nil {
		return nil, errServer(), false
	}
	if req.RedirectURI == "" {
		return client, errInvalidRequest("redirect_uri is required"), false
	}
	if !callbackAllowed(client.Callbacks, req.RedirectURI) {
		return client, errInvalidRequest("redirect_uri is not registered for this application"), false
	}

	if req.ResponseMode == "" {
		req.ResponseMode = "query"
	}
	if !slices.Contains(responseModes, req.ResponseMode) {
		req.ResponseMode = "query"
		return client, errInvalidRequest("unsupported response_mode"), true
	}
	if req.ResponseMode == "web_message" && !slices.Contains(client.WebOrigins, originOf(req.RedirectURI)) {
		return client, errInvalidRequest("web_message requires the redirect_uri origin to be an allowed web origin"), false
	}

	switch req.ResponseType {
	case "":
		return client, errInvalidRequest("response_type is required"), true
	case "code":
	default:
		return client, errUnsupportedResponseType("only response_type=code is supported"), true
	}
	if !slices.Contains(client.GrantTypes, "authorization_code") {
		return client, errUnauthorizedClient("the application may not use the authorization code grant"), true
	}
	if req.Organization != "" || req.Invitation != "" {
		return client, errInvalidRequest("organizations are not supported yet"), true
	}

	switch {
	case req.CodeChallenge != "" && req.CodeChallengeMethod != "S256":
		return client, errInvalidRequest("code_challenge_method must be S256"), true
	case req.CodeChallenge != "" && !s256Challenge.MatchString(req.CodeChallenge):
		return client, errInvalidRequest("code_challenge is malformed"), true
	case req.CodeChallenge == "" && req.CodeChallengeMethod != "":
		return client, errInvalidRequest("code_challenge is required with code_challenge_method"), true
	case req.CodeChallenge == "" && client.TokenEndpointAuthMethod == store.AuthMethodNone:
		return client, errInvalidRequest("public applications must use PKCE (code_challenge)"), true
	}

	if req.MaxAge != "" {
		if n, err := strconv.Atoi(req.MaxAge); err != nil || n < 0 {
			return client, errInvalidRequest("max_age must be a non-negative integer"), true
		}
	}
	prompts := req.Prompts()
	for _, p := range prompts {
		if !slices.Contains(knownPrompts, p) {
			return client, errInvalidRequest("unsupported prompt value " + strconv.Quote(p)), true
		}
	}
	if slices.Contains(prompts, "none") && len(prompts) > 1 {
		return client, errInvalidRequest("prompt=none cannot be combined with other values"), true
	}

	if req.Audience == "" {
		req.Audience = t.DefaultAudience
	}
	if req.Audience != "" {
		if _, err := st.ResourceServers().GetByIdentifier(ctx, t.ID, req.Audience); errors.Is(err, store.ErrNotFound) {
			return client, errAccessDenied("unknown audience"), true
		} else if err != nil {
			return client, errServer(), true
		}
	}

	if req.Connection != "" {
		conn, err := st.Connections().GetByName(ctx, t.ID, req.Connection)
		if errors.Is(err, store.ErrNotFound) || (err == nil && !slices.Contains(conn.EnabledClients, client.ClientID)) {
			return client, errInvalidRequest("connection is not enabled for this application"), true
		} else if err != nil {
			return client, errServer(), true
		}
	}
	return client, nil, true
}

// callbackAllowed reports whether uri exactly matches a registered
// callback, or matches a callback of the form scheme://*.domain/path where
// "*" stands for exactly one DNS label.
func callbackAllowed(callbacks []string, uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || u.Fragment != "" || strings.Contains(uri, "#") || u.User != nil || u.Host == "" {
		return false
	}
	for _, cb := range callbacks {
		if cb == uri {
			return true
		}
		if !strings.Contains(cb, "://*.") {
			continue
		}
		pattern, err := url.Parse(strings.Replace(cb, "://*.", "://wildcard.", 1))
		if err != nil {
			continue
		}
		suffix := strings.TrimPrefix(pattern.Host, "wildcard")
		label, ok := strings.CutSuffix(u.Host, suffix)
		if !ok || label == "" || strings.ContainsAny(label, ".:@") {
			continue
		}
		if u.Scheme == pattern.Scheme && u.Path == pattern.Path && u.RawQuery == pattern.RawQuery {
			return true
		}
	}
	return false
}

// originOf returns scheme://host[:port] of an absolute URL, or "".
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
```

- [ ] **Step 4: Run the tests**

Run: `gofmt -l internal/authz; go test ./internal/authz/ && go vet ./...`
Expected: `ok`. gofmt aligns `errors.go`; run `gofmt -w internal/authz` if it lists files.

- [ ] **Step 5: Record decisions** by appending to `docs/compat/decisions.md`:

```markdown
## D-0006: Authorization request validation choices

- **Context:** Several /authorize behaviors are not pinned down by public Auth0 docs.
- **Sources:** RFC 6749 §3.1.2 and §4.1.2.1; RFC 7636; OpenID Connect Core §3.1.2.1; OAuth 2.0 Security BCP (RFC 9700) §4.1 and §2.1.1.
- **Decision:**
  - `redirect_uri` must match a registered callback exactly, except for the single-label wildcard host form `scheme://*.domain/path`. URIs with a fragment or userinfo are rejected.
  - Public clients must use PKCE with `S256`; `plain` is rejected.
  - `prompt=consent` and `prompt=select_account` are accepted and ignored. All clients are first-party until the consent milestone.
  - With no `audience`, the tenant's default audience applies.
  - `organization` and `invitation` are rejected until Organizations are implemented.
- **Rationale:** Exact matching and mandatory S256 PKCE are the security BCP's recommendations. Rejecting organization parameters prevents tokens that silently lack an organization claim.
```

- [ ] **Step 6: Commit**

```bash
git add internal/authz docs/compat/decisions.md
git commit -m "feat(authz): parse and validate authorization requests"
```

---

### Task 10: /authorize endpoint: sessions, login hand-off, codes, response modes

**Files:**
- Modify: `api/authentication.yaml` (add `/authorize`), then regenerate `internal/gen/authapi/authapi.gen.go`
- Create: `internal/authz/handlers.go`, `internal/authz/response.go`, `internal/authz/handlers_test.go`
- Modify: `internal/server/server.go` (forward `Authorize`, use `HandlerWithOptions` with a JSON error handler, new `Deps.Sessions`), `internal/app/app.go` (construct `session.Manager`)

**Interfaces:**
- Consumes: `validate`, `Request`, `ui.RenderError/RenderFormPost/RenderWebMessage`, `ui.TenantView`, `session.Manager`, `store.AuthTransactions`, `store.AuthCodes`, `secrets.HashToken/RandomString`, `tenant.FromContext`.
- Produces (package `authz`):
  - `type Handlers struct{ Store store.Store; Sessions *session.Manager; Log *slog.Logger; Now func() time.Time }`.
  - `(*Handlers).Authorize(w, r)`.
  - `(*Handlers).Resume(w, r, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession)`: completes a transaction after login. Used by Task 11.
  - `const TxnCookiePrefix = "za_txn_"`, `const CodeLifetime = 60 * time.Second`, `const TxnLifetime = 15 * time.Minute`.
  - `server.Deps` gains `Sessions *session.Manager`.
  - Generated `authapi.ServerInterface` gains `Authorize(w, r, params authapi.AuthorizeParams)`.

- [ ] **Step 1: Add `/authorize` to the contract**

Insert under `paths:` in `api/authentication.yaml`, before `/oauth/token`:

```yaml
  /authorize:
    get:
      operationId: authorize
      tags: [Login]
      summary: Start an authorization (login) flow
      description: |
        Starts the authorization code flow (with PKCE for public applications).
        If the browser has a valid session, the authorization code is returned
        immediately. Otherwise the user is sent to the hosted login page.

        Responses are delivered according to `response_mode`: `query`
        (default), `fragment`, `form_post` (an auto-submitting form), or
        `web_message` (a page that posts the response to the application's
        window, used for silent authentication with `prompt=none`).

        If `client_id` is unknown or `redirect_uri` is not registered, an
        error page is shown and nothing is sent to the `redirect_uri`.
        Unknown parameters are ignored.
      x-source:
        - https://www.rfc-editor.org/rfc/rfc6749#section-4.1
        - https://www.rfc-editor.org/rfc/rfc7636
        - https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
        - https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
        - https://datatracker.ietf.org/doc/html/draft-sakimura-oauth-wmrm-00
        - https://auth0.com/docs/api/authentication
      parameters:
        - {name: client_id, in: query, schema: {type: string}, description: The application's client ID.}
        - {name: redirect_uri, in: query, schema: {type: string}, description: A callback URL registered for the application.}
        - {name: response_type, in: query, schema: {type: string}, description: Must be `code`.}
        - {name: response_mode, in: query, schema: {type: string}, description: "`query`, `fragment`, `form_post` or `web_message`."}
        - {name: scope, in: query, schema: {type: string}, description: Space-separated scopes, e.g. `openid profile email`.}
        - {name: state, in: query, schema: {type: string}, description: Opaque value returned unchanged.}
        - {name: nonce, in: query, schema: {type: string}, description: Value copied into the ID token.}
        - {name: audience, in: query, schema: {type: string}, description: Identifier of the API to issue an access token for.}
        - {name: prompt, in: query, schema: {type: string}, description: "`none` (fail instead of showing login) or `login` (force login)."}
        - {name: max_age, in: query, schema: {type: string}, description: Maximum authentication age in seconds.}
        - {name: code_challenge, in: query, schema: {type: string}, description: PKCE challenge (S256).}
        - {name: code_challenge_method, in: query, schema: {type: string}, description: Must be `S256`.}
        - {name: connection, in: query, schema: {type: string}, description: Name of the connection to log in with.}
        - {name: login_hint, in: query, schema: {type: string}, description: Prefills the login identifier.}
        - {name: screen_hint, in: query, schema: {type: string}, description: "`signup` opens the signup page."}
        - {name: organization, in: query, schema: {type: string}, description: Not supported yet; rejected.}
        - {name: invitation, in: query, schema: {type: string}, description: Not supported yet; rejected.}
      responses:
        "302":
          description: Redirect to the login page, or to `redirect_uri` with `code` or `error` (query and fragment modes).
        "200":
          description: A `form_post` or `web_message` response page.
          content:
            text/html:
              schema: {type: string}
        "400":
          description: Error page for an unknown client or unregistered redirect URI.
          content:
            text/html:
              schema: {type: string}
        "404":
          $ref: "#/components/responses/UnknownTenant"
        default:
          $ref: "#/components/responses/ServerError"
```

Add a `Login` tag under `tags:` with `description: Browser-based login flows.`. Then run:

```bash
go generate ./internal/gen/authapi/ && grep -n "Authorize(w http.ResponseWriter, r \*http.Request, params AuthorizeParams)" internal/gen/authapi/authapi.gen.go
```

Expected: one match in `ServerInterface`. `go build ./...` now fails in `internal/server` because `authAPI` lacks `Authorize`. Step 4 fixes that.

- [ ] **Step 2: Write the failing handler tests**

```go
// internal/authz/handlers_test.go
package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

type env struct {
	*fixture
	h   *Handlers
	srv http.Handler
}

func newEnv(t *testing.T) *env {
	f := newFixture(t)
	sm := &session.Manager{Store: f.st, Now: fixedNow}
	h := &Handlers{Store: f.st, Sessions: sm, Now: fixedNow}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", h.Authorize)
	return &env{fixture: f, h: h, srv: contract.Wrap(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(mux))}
}

func (e *env) get(t *testing.T, q url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "https://acme.example.test/authorize?"+q.Encode(), nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, r)
	return rec
}

// login creates a session for alice directly and returns its cookie.
func (e *env) login(t *testing.T, authTime time.Time) *http.Cookie {
	t.Helper()
	u, err := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if _, err := e.h.Sessions.Start(context.Background(), rec, httptest.NewRequest("GET", "/", nil), e.tenant, u.UserID, "Username-Password-Authentication", authTime); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()[0]
}

func location(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestNoSessionStartsLogin(t *testing.T) {
	e := newEnv(t)
	rec := e.get(t, goodQuery())
	loc := location(t, rec)
	if loc.Path != "/u/login" || loc.Query().Get("state") == "" {
		t.Fatalf("Location = %s", loc)
	}
	txnID := loc.Query().Get("state")
	var txnCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == TxnCookiePrefix+txnID {
			txnCookie = c
		}
	}
	if txnCookie == nil || !txnCookie.HttpOnly || !txnCookie.Secure || txnCookie.Path != "/u" || txnCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("txn cookie = %+v", txnCookie)
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, txnID)
	if err != nil {
		t.Fatal(err)
	}
	if txn.CookieHash != secrets.HashToken(txnCookie.Value) || txn.ClientID != "spa" || txn.CSRFToken == "" ||
		txn.Params["redirect_uri"] != "https://app.acme.test/callback" || !txn.ExpiresAt.Equal(fixedNow().Add(TxnLifetime)) {
		t.Fatalf("txn = %+v", txn)
	}

	signup := location(t, e.get(t, with(goodQuery(), "screen_hint", "signup")))
	if signup.Path != "/u/signup" {
		t.Fatalf("screen_hint=signup went to %s", signup)
	}
}

func TestSessionIssuesCode(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow().Add(-time.Minute))
	loc := location(t, e.get(t, with(goodQuery(), "nonce", "n1", "audience", "https://api.acme.test"), ck))
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != "https://app.acme.test/callback" {
		t.Fatalf("redirected to %s", loc)
	}
	code, state := loc.Query().Get("code"), loc.Query().Get("state")
	if len(code) < 40 || state != "st" {
		t.Fatalf("code=%q state=%q", code, state)
	}
	ac, err := e.st.AuthCodes().Consume(context.Background(), e.tenant.ID, secrets.HashToken(code), fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if ac.ClientID != "spa" || ac.RedirectURI != "https://app.acme.test/callback" || ac.Nonce != "n1" ||
		ac.Audience != "https://api.acme.test" || ac.CodeChallenge != challenge || ac.CodeChallengeMethod != "S256" ||
		strings.Join(ac.Scopes, " ") != "openid profile" || !ac.ExpiresAt.Equal(fixedNow().Add(CodeLifetime)) ||
		!ac.AuthTime.Equal(fixedNow().Add(-time.Minute)) || ac.SessionID == "" {
		t.Fatalf("code = %+v", ac)
	}
}

func TestResponseModes(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())

	frag := location(t, e.get(t, with(goodQuery(), "response_mode", "fragment"), ck))
	fv, _ := url.ParseQuery(frag.Fragment)
	if frag.RawQuery != "" || fv.Get("code") == "" || fv.Get("state") != "st" {
		t.Fatalf("fragment response = %s", frag)
	}

	rec := e.get(t, with(goodQuery(), "response_mode", "form_post"), ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `action="https://app.acme.test/callback"`) || !strings.Contains(rec.Body.String(), `name="code"`) {
		t.Fatalf("form_post = %d %s", rec.Code, rec.Body)
	}

	rec = e.get(t, with(goodQuery(), "response_mode", "web_message", "prompt", "none"), ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "authorization_response") || !strings.Contains(rec.Body.String(), "code") {
		t.Fatalf("web_message = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors https://app.acme.test") {
		t.Fatalf("web_message CSP = %q", rec.Header().Get("Content-Security-Policy"))
	}
}

// Review focus 5.
func TestPromptNoneWithoutSession(t *testing.T) {
	e := newEnv(t)
	loc := location(t, e.get(t, with(goodQuery(), "prompt", "none")))
	if loc.Host != "app.acme.test" || loc.Query().Get("error") != "login_required" || loc.Query().Get("state") != "st" {
		t.Fatalf("Location = %s", loc)
	}
	rec := e.get(t, with(goodQuery(), "prompt", "none", "response_mode", "web_message"))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "login_required") || strings.Contains(body, "<form") {
		t.Fatalf("web_message login_required = %d %s", rec.Code, body)
	}
}

func TestForcedReauthentication(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow().Add(-10*time.Minute))
	for name, q := range map[string]url.Values{
		"prompt=login":       with(goodQuery(), "prompt", "login"),
		"max_age=0":          with(goodQuery(), "max_age", "0"),
		"max_age exceeded":   with(goodQuery(), "max_age", "300"),
		"other connection":   with(goodQuery(), "client_id", "web", "redirect_uri", "https://web.acme.test/cb", "connection", "Other-DB", "code_challenge", "", "code_challenge_method", ""),
	} {
		t.Run(name, func(t *testing.T) {
			if loc := location(t, e.get(t, q, ck)); loc.Path != "/u/login" {
				t.Fatalf("Location = %s", loc)
			}
		})
	}
	if loc := location(t, e.get(t, with(goodQuery(), "max_age", "3600"), ck)); loc.Query().Get("code") == "" {
		t.Fatalf("recent session with max_age=3600 should get a code: %s", loc)
	}
	if loc := location(t, e.get(t, with(goodQuery(), "max_age", "0", "prompt", "none"), ck)); loc.Query().Get("error") != "login_required" {
		t.Fatalf("max_age=0 with prompt=none: %s", loc)
	}
}

func TestErrorDelivery(t *testing.T) {
	e := newEnv(t)
	rec := e.get(t, with(goodQuery(), "redirect_uri", "https://evil.test/cb"))
	if rec.Code != 400 || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), "not registered") {
		t.Fatalf("unregistered redirect = %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	loc := location(t, e.get(t, with(goodQuery(), "response_type", "token")))
	if loc.Host != "app.acme.test" || loc.Query().Get("error") != "unsupported_response_type" || loc.Query().Get("state") != "st" {
		t.Fatalf("Location = %s", loc)
	}
}

func TestResume(t *testing.T) {
	e := newEnv(t)
	loc := location(t, e.get(t, with(goodQuery(), "response_mode", "fragment")))
	txn, _ := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))

	u, _ := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
	rec := httptest.NewRecorder()
	sess, _ := e.h.Sessions.Start(context.Background(), rec, httptest.NewRequest("GET", "/", nil), e.tenant, u.UserID, "Username-Password-Authentication", fixedNow())

	rec = httptest.NewRecorder()
	r := httptest.NewRequest("POST", "https://acme.example.test/u/login", nil)
	e.h.Resume(rec, r, tenant.Resolved{Tenant: e.tenant, Host: "acme.example.test"}, txn, sess)
	back := location(t, rec)
	fv, _ := url.ParseQuery(back.Fragment)
	if back.Host != "app.acme.test" || fv.Get("code") == "" || fv.Get("state") != "st" {
		t.Fatalf("Resume redirect = %s", back)
	}
	s2, _ := e.st.Sessions().GetByTokenHash(context.Background(), e.tenant.ID, sess.TokenHash)
	if len(s2.ClientIDs) != 1 || s2.ClientIDs[0] != "spa" {
		t.Fatalf("session clients = %v", s2.ClientIDs)
	}
	if _, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, txn.ID); err == nil {
		t.Fatal("transaction not deleted after resume")
	}
}

```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/authz/`
Expected: FAIL: `h.Authorize undefined`, `undefined: TxnCookiePrefix`.

- [ ] **Step 4: Implement**

```go
// internal/authz/response.go
package authz

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// writeResponse delivers an authorization response (code or error) to the
// client using the request's response_mode.
func writeResponse(w http.ResponseWriter, r *http.Request, req Request, params url.Values) {
	switch req.ResponseMode {
	case "form_post":
		ui.RenderFormPost(w, req.RedirectURI, params)
	case "web_message":
		resp := map[string]string{}
		for k := range params {
			resp[k] = params.Get(k)
		}
		ui.RenderWebMessage(w, originOf(req.RedirectURI), resp)
	case "fragment":
		redirect(w, r, strings.SplitN(req.RedirectURI, "#", 2)[0]+"#"+params.Encode())
	default:
		u, _ := url.Parse(req.RedirectURI) // validated by callbackAllowed
		q := u.Query()
		for k, vs := range params {
			q[k] = vs
		}
		u.RawQuery = q.Encode()
		redirect(w, r, u.String())
	}
}

func redirect(w http.ResponseWriter, r *http.Request, to string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, to, http.StatusFound)
}

func errorParams(e *Error, state string) url.Values {
	v := url.Values{"error": {e.Code}, "error_description": {e.Description}}
	if state != "" {
		v.Set("state", state)
	}
	return v
}
```

```go
// internal/authz/handlers.go
package authz

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

const (
	// TxnCookiePrefix + transaction ID names the cookie binding a login
	// transaction to the browser that started it.
	TxnCookiePrefix = "za_txn_"
	TxnLifetime     = 15 * time.Minute
	CodeLifetime    = 60 * time.Second
)

type Handlers struct {
	Store    store.Store
	Sessions *session.Manager
	Log      *slog.Logger
	Now      func() time.Time
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// Authorize implements GET /authorize.
func (h *Handlers) Authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	view := ui.TenantView(res.Tenant)
	req := ParseRequest(r.URL.Query())
	client, verr, redirectable := validate(ctx, h.Store, res.Tenant, &req)
	if verr != nil {
		if !redirectable {
			ui.RenderError(w, http.StatusBadRequest, view, verr.Description)
			return
		}
		writeResponse(w, r, req, errorParams(verr, req.State))
		return
	}

	sess, err := h.Sessions.Current(ctx, r, res.Tenant)
	if err != nil {
		h.log().ErrorContext(ctx, "load session", "tenant", res.Tenant.ID, "err", err)
		writeResponse(w, r, req, errorParams(errServer(), req.State))
		return
	}
	if h.needsLogin(req, sess) {
		if slices.Contains(req.Prompts(), "none") {
			writeResponse(w, r, req, errorParams(errLoginRequired(), req.State))
			return
		}
		h.startLogin(w, r, res, client, req)
		return
	}
	h.issueCode(w, r, res, client, req, sess)
}

func (h *Handlers) needsLogin(req Request, sess *store.LoginSession) bool {
	if sess == nil || slices.Contains(req.Prompts(), "login") {
		return true
	}
	if req.Connection != "" && sess.Connection != req.Connection {
		return true
	}
	if maxAge, ok := req.MaxAgeSeconds(); ok && (maxAge == 0 || h.now().Sub(sess.AuthenticatedAt) > time.Duration(maxAge)*time.Second) {
		return true
	}
	return false
}

// startLogin stores the request in a transaction bound to this browser and
// sends the user to the hosted login (or signup) page.
func (h *Handlers) startLogin(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request) {
	ctx := r.Context()
	now := h.now()
	cookieValue := secrets.RandomString(43)
	params := req.Params()
	delete(params, "prompt") // prompt=login is satisfied by this login
	txn := &store.AuthTransaction{
		TenantID:   res.Tenant.ID,
		ID:         secrets.RandomString(24),
		CookieHash: secrets.HashToken(cookieValue),
		CSRFToken:  secrets.RandomString(32),
		ClientID:   client.ClientID,
		Params:     params,
		ExpiresAt:  now.Add(TxnLifetime),
		CreatedAt:  now,
	}
	if err := h.Store.AuthTransactions().Create(ctx, txn); err != nil {
		h.log().ErrorContext(ctx, "create login transaction", "tenant", res.Tenant.ID, "err", err)
		writeResponse(w, r, req, errorParams(errServer(), req.State))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: TxnCookiePrefix + txn.ID, Value: cookieValue, Path: "/u",
		MaxAge: int(TxnLifetime / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	page := "/u/login"
	if req.ScreenHint == "signup" {
		page = "/u/signup"
	}
	redirect(w, r, page+"?"+url.Values{"state": {txn.ID}}.Encode())
}

// Resume finishes a login transaction for an authenticated session. The
// login pages call it after a successful login or signup.
func (h *Handlers) Resume(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) {
	ctx := r.Context()
	if err := h.Store.AuthTransactions().Delete(ctx, res.Tenant.ID, txn.ID); err != nil {
		h.log().WarnContext(ctx, "delete login transaction", "tenant", res.Tenant.ID, "err", err)
	}
	http.SetCookie(w, &http.Cookie{Name: TxnCookiePrefix + txn.ID, Value: "", Path: "/u", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})

	req := RequestFromParams(txn.Params)
	client, verr, redirectable := validate(ctx, h.Store, res.Tenant, &req)
	if verr != nil {
		// The application changed while the user was logging in.
		if !redirectable {
			ui.RenderError(w, http.StatusBadRequest, ui.TenantView(res.Tenant), verr.Description)
			return
		}
		writeResponse(w, r, req, errorParams(verr, req.State))
		return
	}
	h.issueCode(w, r, res, client, req, sess)
}

func (h *Handlers) issueCode(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request, sess *store.LoginSession) {
	ctx := r.Context()
	code, err := h.createCode(ctx, res, client, req, sess)
	if err != nil {
		h.log().ErrorContext(ctx, "issue authorization code", "tenant", res.Tenant.ID, "err", err)
		writeResponse(w, r, req, errorParams(errServer(), req.State))
		return
	}
	params := url.Values{"code": {code}}
	if req.State != "" {
		params.Set("state", req.State)
	}
	writeResponse(w, r, req, params)
}

func (h *Handlers) createCode(ctx context.Context, res tenant.Resolved, client *store.Client, req Request, sess *store.LoginSession) (string, error) {
	now := h.now()
	code := secrets.RandomString(43)
	ac := &store.AuthCode{
		TenantID:            res.Tenant.ID,
		CodeHash:            secrets.HashToken(code),
		ClientID:            client.ClientID,
		RedirectURI:         req.RedirectURI,
		UserID:              sess.UserID,
		SessionID:           sess.ID,
		Scopes:              req.Scopes(),
		Audience:            req.Audience,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		AuthTime:            sess.AuthenticatedAt,
		ExpiresAt:           now.Add(CodeLifetime),
		CreatedAt:           now,
	}
	if err := h.Store.AuthCodes().Create(ctx, ac); err != nil {
		return "", err
	}
	if err := h.Sessions.AddClient(ctx, sess, client.ClientID); err != nil {
		return "", err
	}
	return code, nil
}
```

Now wire it into the server. In `internal/server/server.go`:
- add the `authz` and `session` imports;
- add `Sessions *session.Manager` to `Deps`;
- add the field `authz *authz.Handlers` to `authAPI`;
- add the forwarding method;
- switch from `HandlerFromMux` to `HandlerWithOptions` so that parameter-binding errors return the JSON error shape.

```go
func (a authAPI) Authorize(w http.ResponseWriter, r *http.Request, _ authapi.AuthorizeParams) {
	a.authz.Authorize(w, r)
}
```

```go
	r.Group(func(tr chi.Router) {
		tr.Use(d.Resolver.Middleware)
		authapi.HandlerWithOptions(authAPI{
			oidc:  &oidc.Handlers{Keys: d.Keys, Log: d.Log},
			oauth: &oauth.Handlers{Store: d.Store, Log: d.Log, Minter: &oauth.Minter{Keys: d.Keys}},
			authz: &authz.Handlers{Store: d.Store, Sessions: d.Sessions, Log: d.Log},
		}, authapi.ChiServerOptions{
			BaseRouter: tr,
			ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
				httpx.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
			},
		})
	})
```

In `internal/server/server_test.go` `newTestServer`, add `Sessions: &session.Manager{Store: st}` to the `Deps` literal. In `internal/app/app.go` `build`, add `Sessions: &session.Manager{Store: st}` to the `server.Deps` literal. Add the `session` import to both files.

- [ ] **Step 5: Run the tests**

Run: `gofmt -l . ; go vet ./... && go test ./...`
Expected: no gofmt output; `ok` in every package, with no `contract:` violations.

- [ ] **Step 6: Commit**

```bash
git add api internal/gen internal/authz internal/server internal/app
git commit -m "feat(authz): serve /authorize with sessions, login hand-off, codes and response modes"
```

---
### Task 11: Hosted login and signup pages

**Files:**
- Create: `internal/login/login.go`, `internal/login/ip.go`, `internal/login/login_test.go`
- Modify: `internal/config/config.go`, `internal/config/config_test.go` (throttle settings)
- Modify: `internal/server/server.go` (routes, `Deps`), `internal/server/server_test.go`, `internal/app/app.go`

**Interfaces:**
- Consumes:
  - `authz.Handlers.Resume`, `authz.TxnCookiePrefix`
  - `identity.Database`, `identity.Throttle`, `identity.NormalizeLogin`, the identity errors and `*identity.PolicyError`
  - `session.Manager.Start`
  - `ui.RenderLogin/RenderSignup/RenderError/TenantView`
  - `store.AuthTransactions/Connections/Clients/Users`, `secrets.HashToken`
- Produces (package `login`):
  - `type Handlers struct{ Store store.Store; Sessions *session.Manager; Authz *authz.Handlers; Database *identity.Database; UserThrottle, IPThrottle *identity.Throttle; TrustProxyHeaders bool; Log *slog.Logger; Now func() time.Time }`
  - methods `LoginPage`, `LoginSubmit`, `SignupPage`, `SignupSubmit` (all `http.HandlerFunc` shaped)
  - `config.Security` gains `LoginMaxAttempts int` (`login_max_attempts`, default 10) and `LoginLockoutSeconds int` (`login_lockout_seconds`, default 900). Both must be > 0.
  - `server.Deps` gains `UserThrottle, IPThrottle *identity.Throttle` and `TrustProxyHeaders bool`. Routes `GET/POST /u/login` and `GET/POST /u/signup` are added inside the tenant group.

- [ ] **Step 1: Write the failing tests**

```go
// internal/login/login_test.go
package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }

const loginSeed = `
tenants:
  - name: acme
    domains: [acme.example.test]
    clients:
      - {client_id: spa, app_type: spa, grant_types: [authorization_code], callbacks: ["https://app.acme.test/cb"]}
      - {client_id: closed, app_type: spa, grant_types: [authorization_code], callbacks: ["https://closed.acme.test/cb"]}
    connections:
      - {name: Username-Password-Authentication, enabled_clients: [spa]}
      - {name: Invite-Only, enabled_clients: [closed], disable_signup: true}
    users:
      - {connection: Username-Password-Authentication, email: alice@acme.test, password: "alice password 1"}
  - name: globex
    domains: [globex.example.test]
`

const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

type env struct {
	st  store.Store
	srv http.Handler
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := memory.New()
	f, err := seed.Parse([]byte(loginSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(context.Background(), st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	sm := &session.Manager{Store: st, Now: fixedNow}
	az := &authz.Handlers{Store: st, Sessions: sm, Now: fixedNow}
	h := &Handlers{
		Store: st, Sessions: sm, Authz: az,
		Database:     &identity.Database{Store: st, Now: fixedNow},
		UserThrottle: identity.NewThrottle(3, 15*time.Minute, 15*time.Minute),
		IPThrottle:   identity.NewThrottle(30, 15*time.Minute, 15*time.Minute),
		Now:          fixedNow,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", az.Authorize)
	mux.HandleFunc("GET /u/login", h.LoginPage)
	mux.HandleFunc("POST /u/login", h.LoginSubmit)
	mux.HandleFunc("GET /u/signup", h.SignupPage)
	mux.HandleFunc("POST /u/signup", h.SignupSubmit)
	return &env{st: st, srv: tenant.NewResolver(st.Tenants(), "", false).Middleware(mux)}
}

// browser is a minimal cookie-keeping client for one host.
type browser struct {
	e       *env
	host    string
	cookies map[string]*http.Cookie
}

func (e *env) browser(host string) *browser {
	return &browser{e: e, host: host, cookies: map[string]*http.Cookie{}}
}

func (b *browser) do(t *testing.T, method, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, "https://"+b.host+path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, "https://"+b.host+path, nil)
	}
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.e.srv.ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return rec
}

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// begin runs /authorize for the spa client and returns the login page
// response and the transaction state.
func (b *browser) begin(t *testing.T, extra ...string) (*httptest.ResponseRecorder, string, string) {
	t.Helper()
	q := url.Values{
		"client_id": {"spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"app-state"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	rec := b.do(t, "GET", "/authorize?"+q.Encode(), nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := loc.Query().Get("state")
	page := b.do(t, "GET", loc.RequestURI(), nil)
	m := csrfField.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("no csrf on page %s: %s", loc, page.Body)
	}
	return page, state, m[1]
}

func TestLoginSuccess(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t, "login_hint", "alice@acme.test")
	if page.Code != 200 || !strings.Contains(page.Body.String(), `value="alice@acme.test"`) || !strings.Contains(page.Body.String(), "/u/signup?state=") {
		t.Fatalf("login page = %d %s", page.Code, page.Body)
	}

	// Review focus 4: case and whitespace insensitive.
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"  ALICE@acme.test "}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Host != "app.acme.test" || loc.Query().Get("code") == "" || loc.Query().Get("state") != "app-state" {
		t.Fatalf("login = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if b.cookies[session.CookieName] == nil {
		t.Fatal("no session cookie after login")
	}
	if _, ok := b.cookies[authz.TxnCookiePrefix+state]; ok {
		t.Fatal("transaction cookie not cleared")
	}
	u, _ := e.st.Users().FindByLogin(context.Background(), mustTenant(t, e, "acme").ID, "Username-Password-Authentication", "alice@acme.test")
	if u.LoginsCount != 1 || u.LastLogin == nil {
		t.Fatalf("login not recorded: %+v", u)
	}

	// The session now satisfies /authorize directly.
	q := url.Values{"client_id": {"spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "prompt": {"none"}}
	rec = b.do(t, "GET", "/authorize?"+q.Encode(), nil)
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("prompt=none after login = %s", loc)
	}
}

func TestWrongPassword(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"wrong"}})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Incorrect") || b.cookies[session.CookieName] != nil {
		t.Fatalf("wrong password = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `value="alice@acme.test"`) {
		t.Error("login identifier not kept after a failed attempt")
	}
	// The same transaction can be retried.
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	if rec.Code != 302 {
		t.Fatalf("retry = %d %s", rec.Code, rec.Body)
	}
}

func TestThrottle(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	for i := 0; i < 3; i++ {
		b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"wrong"}})
	}
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	if rec.Code != http.StatusTooManyRequests || b.cookies[session.CookieName] != nil {
		t.Fatalf("locked login = %d %s", rec.Code, rec.Body)
	}
}

// Review focus 3.
func TestTransactionBinding(t *testing.T) {
	e := newEnv(t)
	good := func(b *browser) (string, string) {
		_, state, csrf := b.begin(t)
		return state, csrf
	}
	creds := func(state, csrf string) url.Values {
		return url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}}
	}

	t.Run("missing txn cookie", func(t *testing.T) {
		b := e.browser("acme.example.test")
		state, csrf := good(b)
		delete(b.cookies, authz.TxnCookiePrefix+state)
		if rec := b.do(t, "POST", "/u/login", creds(state, csrf)); rec.Code != 400 || b.cookies[session.CookieName] != nil {
			t.Fatalf("got %d", rec.Code)
		}
	})
	t.Run("other browser", func(t *testing.T) {
		victim := e.browser("acme.example.test")
		state, csrf := good(victim)
		attacker := e.browser("acme.example.test")
		if rec := attacker.do(t, "POST", "/u/login", creds(state, csrf)); rec.Code != 400 || attacker.cookies[session.CookieName] != nil {
			t.Fatalf("got %d", rec.Code)
		}
	})
	t.Run("wrong csrf", func(t *testing.T) {
		b := e.browser("acme.example.test")
		state, _ := good(b)
		if rec := b.do(t, "POST", "/u/login", creds(state, "nope")); rec.Code != 400 || b.cookies[session.CookieName] != nil {
			t.Fatalf("got %d", rec.Code)
		}
	})
	t.Run("other tenant", func(t *testing.T) {
		b := e.browser("acme.example.test")
		state, csrf := good(b)
		other := &browser{e: e, host: "globex.example.test", cookies: b.cookies}
		if rec := other.do(t, "POST", "/u/login", creds(state, csrf)); rec.Code != 400 {
			t.Fatalf("got %d", rec.Code)
		}
	})
	t.Run("expired", func(t *testing.T) {
		b := e.browser("acme.example.test")
		state, csrf := good(b)
		txn, _ := e.st.AuthTransactions().Get(context.Background(), mustTenant(t, e, "acme").ID, state)
		txn.ExpiresAt = fixedNow().Add(-time.Second)
		_ = e.st.AuthTransactions().Delete(context.Background(), txn.TenantID, txn.ID)
		_ = e.st.AuthTransactions().Create(context.Background(), txn)
		rec := b.do(t, "POST", "/u/login", creds(state, csrf))
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "expired") {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("unknown state on GET", func(t *testing.T) {
		b := e.browser("acme.example.test")
		if rec := b.do(t, "GET", "/u/login?state=nope", nil); rec.Code != 400 {
			t.Fatalf("got %d", rec.Code)
		}
	})
}

func TestSignup(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "screen_hint", "signup")

	rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"bob@acme.test"}, "password": {"short"}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "at least 8") {
		t.Fatalf("weak password = %d %s", rec.Code, rec.Body)
	}
	rec = b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"ALICE@acme.test"}, "password": {"long enough pw"}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "already exists") {
		t.Fatalf("duplicate = %d %s", rec.Code, rec.Body)
	}
	rec = b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"bob@acme.test"}, "password": {"long enough pw"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Query().Get("code") == "" || b.cookies[session.CookieName] == nil {
		t.Fatalf("signup = %d %s", rec.Code, rec.Body)
	}
}

func TestSignupDisabled(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	q := url.Values{
		"client_id": {"closed"}, "redirect_uri": {"https://closed.acme.test/cb"}, "response_type": {"code"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	rec := b.do(t, "GET", "/authorize?"+q.Encode(), nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	page := b.do(t, "GET", loc.RequestURI(), nil)
	if strings.Contains(page.Body.String(), "/u/signup") {
		t.Fatal("signup link shown for a connection with signup disabled")
	}
	signup := b.do(t, "GET", "/u/signup?state="+loc.Query().Get("state"), nil)
	if signup.Code != http.StatusForbidden {
		t.Fatalf("signup page = %d", signup.Code)
	}
}

func mustTenant(t *testing.T, e *env, name string) *store.Tenant {
	t.Helper()
	tn, err := e.st.Tenants().GetByName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return tn
}
```

Append to `internal/config/config_test.go`:

```go
func TestLoginThrottleSettings(t *testing.T) {
	cfg, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://"})
	if err != nil || cfg.Security.LoginMaxAttempts != 10 || cfg.Security.LoginLockoutSeconds != 900 {
		t.Fatalf("defaults = %+v, %v", cfg.Security, err)
	}
	cfg, err = Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SECURITY__LOGIN_MAX_ATTEMPTS=5", "ZEROAUTHY_SECURITY__LOGIN_LOCKOUT_SECONDS=60"})
	if err != nil || cfg.Security.LoginMaxAttempts != 5 || cfg.Security.LoginLockoutSeconds != 60 {
		t.Fatalf("overrides = %+v, %v", cfg.Security, err)
	}
	if _, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SECURITY__LOGIN_MAX_ATTEMPTS=0"}); err == nil {
		t.Fatal("zero attempts accepted")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/login/ ./internal/config/`
Expected: FAIL: `undefined: Handlers` in login; `cfg.Security.LoginMaxAttempts undefined` in config.

- [ ] **Step 3: Add the config settings**

In `internal/config/config.go`, add these fields to `Security`:

```go
	// LoginMaxAttempts failed logins for one account within the lockout
	// window lock that account for LoginLockoutSeconds. Per-IP limits are
	// ten times higher.
	LoginMaxAttempts    int `koanf:"login_max_attempts"`
	LoginLockoutSeconds int `koanf:"login_lockout_seconds"`
```

Set the defaults in `defaults()`: `Security: Security{LoginMaxAttempts: 10, LoginLockoutSeconds: 900}`. In `validate()`, add:

```go
	if c.Security.LoginMaxAttempts <= 0 || c.Security.LoginLockoutSeconds <= 0 {
		errs = append(errs, errors.New("security.login_max_attempts and security.login_lockout_seconds must be positive"))
	}
```

- [ ] **Step 4: Implement the login package**

```go
// internal/login/ip.go
package login

import (
	"net"
	"net/http"
	"strings"
)

// clientIP is the address used for throttling. X-Forwarded-For is used
// only when the deployment trusts proxy headers.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			return strings.TrimSpace(strings.Split(fwd, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
```

```go
// internal/login/login.go

// Package login serves the hosted login and signup pages (/u/*).
package login

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

const maxFormBytes = 16 << 10

// User-facing messages (original wording).
const (
	msgBadCredentials = "Incorrect email/username or password."
	msgBlocked        = "This account has been blocked. Contact the application's support."
	msgTooMany        = "Too many attempts. Wait a few minutes and try again."
	msgExpired        = "Your login session has expired or is invalid. Return to the application and start again."
	msgNoConnection   = "No login method is enabled for this application."
	msgSignupDisabled = "Sign-up is not available for this application."
	msgUserExists     = "An account with this email or username already exists."
	msgServer         = "Something went wrong on our side. Please try again."
)

var errTxn = errors.New("login: invalid or expired transaction")

type Handlers struct {
	Store             store.Store
	Sessions          *session.Manager
	Authz             *authz.Handlers
	Database          *identity.Database
	UserThrottle      *identity.Throttle
	IPThrottle        *identity.Throttle
	TrustProxyHeaders bool
	Log               *slog.Logger
	Now               func() time.Time
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// flow is a validated login transaction and the connection it uses.
type flow struct {
	res  tenant.Resolved
	view ui.Tenant
	txn  *store.AuthTransaction
	conn *store.Connection
}

// load validates the transaction named by state: it must exist in this
// tenant, be unexpired, and be bound to this browser's za_txn cookie.
func (h *Handlers) load(r *http.Request, state string) (*flow, error) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok || state == "" {
		return nil, errTxn
	}
	txn, err := h.Store.AuthTransactions().Get(ctx, res.Tenant.ID, state)
	if err != nil {
		return nil, errTxn
	}
	c, err := r.Cookie(authz.TxnCookiePrefix + txn.ID)
	if err != nil || subtle.ConstantTimeCompare([]byte(secrets.HashToken(c.Value)), []byte(txn.CookieHash)) != 1 {
		return nil, errTxn
	}
	if !h.now().Before(txn.ExpiresAt) {
		return nil, errTxn
	}
	conn, err := h.connection(ctx, res.Tenant.ID, txn)
	if err != nil {
		return nil, err
	}
	return &flow{res: res, view: ui.TenantView(res.Tenant), txn: txn, conn: conn}, nil
}

var errNoConnection = errors.New("login: no enabled connection")

// connection picks the requested connection, or the first database
// connection (by name) enabled for the client.
func (h *Handlers) connection(ctx context.Context, tenantID string, txn *store.AuthTransaction) (*store.Connection, error) {
	conns, err := h.Store.Connections().List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	want := txn.Params["connection"]
	for _, c := range conns {
		if c.Strategy != store.StrategyDatabase || !slices.Contains(c.EnabledClients, txn.ClientID) {
			continue
		}
		if want == "" || c.Name == want {
			return c, nil
		}
	}
	return nil, errNoConnection
}

func (h *Handlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	view := ui.Tenant{}
	if res, ok := tenant.FromContext(r.Context()); ok {
		view = ui.TenantView(res.Tenant)
	}
	switch {
	case errors.Is(err, errTxn):
		ui.RenderError(w, http.StatusBadRequest, view, msgExpired)
	case errors.Is(err, errNoConnection):
		ui.RenderError(w, http.StatusBadRequest, view, msgNoConnection)
	default:
		h.log().ErrorContext(r.Context(), "login page", "err", err)
		ui.RenderError(w, http.StatusInternalServerError, view, msgServer)
	}
}

func signupURL(f *flow) string {
	if f.conn.DisableSignup {
		return ""
	}
	return "/u/signup?" + url.Values{"state": {f.txn.ID}}.Encode()
}

func (h *Handlers) LoginPage(w http.ResponseWriter, r *http.Request) {
	f, err := h.load(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	ui.RenderLogin(w, http.StatusOK, f.view, ui.LoginData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, Login: f.txn.Params["login_hint"], SignupURL: signupURL(f),
	})
}

// postedFlow parses a form POST and checks its transaction and CSRF token.
func (h *Handlers) postedFlow(w http.ResponseWriter, r *http.Request) (*flow, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		h.fail(w, r, errTxn)
		return nil, false
	}
	f, err := h.load(r, r.PostForm.Get("state"))
	if err != nil {
		h.fail(w, r, err)
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(f.txn.CSRFToken)) != 1 {
		h.fail(w, r, errTxn)
		return nil, false
	}
	return f, true
}

func (h *Handlers) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	login := r.PostForm.Get("username")
	data := ui.LoginData{State: f.txn.ID, CSRF: f.txn.CSRFToken, Login: login, SignupURL: signupURL(f)}

	userKey := "user|" + f.res.Tenant.ID + "|" + f.conn.Name + "|" + identity.NormalizeLogin(login)
	ipKey := "ip|" + f.res.Tenant.ID + "|" + clientIP(r, h.TrustProxyHeaders)
	if !h.UserThrottle.Allowed(userKey) || !h.IPThrottle.Allowed(ipKey) {
		data.Error = msgTooMany
		ui.RenderLogin(w, http.StatusTooManyRequests, f.view, data)
		return
	}

	user, err := h.Database.Login(ctx, f.conn, login, r.PostForm.Get("password"))
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials):
		h.UserThrottle.Failure(userKey)
		h.IPThrottle.Failure(ipKey)
		h.log().InfoContext(ctx, "login failed", "tenant", f.res.Tenant.ID, "connection", f.conn.Name)
		data.Error = msgBadCredentials
		ui.RenderLogin(w, http.StatusUnauthorized, f.view, data)
		return
	case errors.Is(err, identity.ErrUserBlocked):
		data.Error = msgBlocked
		ui.RenderLogin(w, http.StatusForbidden, f.view, data)
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}
	h.UserThrottle.Success(userKey)
	h.complete(w, r, f, user)
}

func (h *Handlers) SignupPage(w http.ResponseWriter, r *http.Request) {
	f, err := h.load(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if f.conn.DisableSignup {
		ui.RenderError(w, http.StatusForbidden, f.view, msgSignupDisabled)
		return
	}
	ui.RenderSignup(w, http.StatusOK, f.view, ui.SignupData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, Email: f.txn.Params["login_hint"],
		RequiresUsername: f.conn.RequiresUsername, LoginURL: "/u/login?" + url.Values{"state": {f.txn.ID}}.Encode(),
	})
}

func (h *Handlers) SignupSubmit(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	email, username := r.PostForm.Get("email"), r.PostForm.Get("username")
	data := ui.SignupData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, Email: email, Username: username,
		RequiresUsername: f.conn.RequiresUsername, LoginURL: "/u/login?" + url.Values{"state": {f.txn.ID}}.Encode(),
	}
	user, err := h.Database.Signup(r.Context(), f.conn, email, username, r.PostForm.Get("password"))
	var pe *identity.PolicyError
	switch {
	case errors.As(err, &pe):
		data.Error = capitalize(pe.Reason) + "."
		ui.RenderSignup(w, http.StatusBadRequest, f.view, data)
		return
	case errors.Is(err, identity.ErrUserExists):
		data.Error = msgUserExists
		ui.RenderSignup(w, http.StatusBadRequest, f.view, data)
		return
	case errors.Is(err, identity.ErrSignupDisabled):
		ui.RenderError(w, http.StatusForbidden, f.view, msgSignupDisabled)
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}
	h.complete(w, r, f, user)
}

// complete starts the session and hands back to /authorize processing.
func (h *Handlers) complete(w http.ResponseWriter, r *http.Request, f *flow, user *store.User) {
	ctx := r.Context()
	now := h.now()
	if err := h.Store.Users().RecordLogin(ctx, f.res.Tenant.ID, user.UserID, now); err != nil {
		h.log().WarnContext(ctx, "record login", "tenant", f.res.Tenant.ID, "err", err)
	}
	sess, err := h.Sessions.Start(ctx, w, r, f.res.Tenant, user.UserID, f.conn.Name, now)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.Authz.Resume(w, r, f.res, f.txn, sess)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
```

- [ ] **Step 5: Wire routes and dependencies**

In `internal/server/server.go`:
- add the `identity` and `login` imports;
- add these to `Deps`:

```go
	UserThrottle      *identity.Throttle
	IPThrottle        *identity.Throttle
	TrustProxyHeaders bool
```

- create the authz handlers once and share them:

```go
	az := &authz.Handlers{Store: d.Store, Sessions: d.Sessions, Log: d.Log}
	lg := &login.Handlers{
		Store: d.Store, Sessions: d.Sessions, Authz: az,
		Database:     &identity.Database{Store: d.Store},
		UserThrottle: d.UserThrottle, IPThrottle: d.IPThrottle,
		TrustProxyHeaders: d.TrustProxyHeaders, Log: d.Log,
	}
```

Use `authz: az` in the `authAPI` literal, and register the routes inside the tenant group after `HandlerWithOptions`:

```go
		tr.Get("/u/login", lg.LoginPage)
		tr.Post("/u/login", lg.LoginSubmit)
		tr.Get("/u/signup", lg.SignupPage)
		tr.Post("/u/signup", lg.SignupSubmit)
```

In `internal/app/app.go`, pass the new deps:

```go
			UserThrottle:      identity.NewThrottle(cfg.Security.LoginMaxAttempts, lockout, lockout),
			IPThrottle:        identity.NewThrottle(10*cfg.Security.LoginMaxAttempts, lockout, lockout),
			TrustProxyHeaders: cfg.Server.TrustProxyHeaders,
```

`lockout` is `time.Duration(cfg.Security.LoginLockoutSeconds) * time.Second`; declare it just before the `server.Deps` literal. The window is set equal to the lockout. In `internal/server/server_test.go` `newTestServer`, add `UserThrottle: identity.NewThrottle(10, time.Minute, time.Minute), IPThrottle: identity.NewThrottle(100, time.Minute, time.Minute)`.

- [ ] **Step 6: Run the tests**

Run: `gofmt -l . ; go vet ./... && go test ./...`
Expected: no gofmt output; `ok` everywhere.

- [ ] **Step 7: Record decision D-0007** by appending to `docs/compat/decisions.md`:

```markdown
## D-0007: Hosted login transactions and brute-force protection

- **Context:** The spec requires CSRF-bound login transactions and per-IP/per-user brute-force protection with configurable lockout.
- **Sources:** OWASP Authentication and CSRF Prevention cheat sheets; RFC 6749 §10.12 (CSRF).
- **Decision:**
  - Each login transaction is a server-side record (15 minutes) bound to the browser by an `HttpOnly; Secure; SameSite=Lax` cookie `za_txn_<id>` on path `/u`, and to the form by a CSRF token.
  - After `security.login_max_attempts` (default 10) failures for one (tenant, connection, login) within `security.login_lockout_seconds` (default 900), that login is locked for the same period. Per IP, the limit is 10× higher.
  - Counters are in-process.
  - Failed logins show one message whether the account exists or not.
- **Rationale:** Server-side transactions keep the authorize request out of the browser. The cookie binding defeats login CSRF. The per-account lockout limits guessing without letting one IP lock out every account.
```

- [ ] **Step 8: Commit**

```bash
git add internal/login internal/config internal/server internal/app docs/compat/decisions.md
git commit -m "feat(login): add hosted login and signup pages with CSRF binding and throttling"
```

---

### Task 12: Authorization code grant at /oauth/token

**Files:**
- Create: `internal/oauth/grant_authorization_code.go`, `internal/oauth/pkce.go`
- Create: `internal/oauth/grant_authorization_code_test.go`, `internal/oauth/pkce_test.go`
- Modify: `internal/oauth/token.go` (register the grant), `internal/oauth/errors.go` (`invalidGrant`), `internal/oauth/fixture_test.go` (seed users, connection, code-flow clients)
- Modify: `api/authentication.yaml` (`/oauth/token` description and `TokenRequest` properties)

**Interfaces:**
- Consumes:
  - `store.AuthCodes.Consume`, `store.ErrAlreadyUsed`, `store.Users`
  - `secrets.HashToken`, `Minter.AccessToken/IDToken`, `authenticateClient`
  - `tenant.Resolved.Issuer()`
- Produces:
  - `oauth.invalidGrant(desc) *Error` (400 `invalid_grant`)
  - `verifyPKCE(method, challenge, verifier string) bool`
  - `(*Handlers).authorizationCode` registered as `"authorization_code"` in `grantHandlers`
  - `userScopes(requested []string, rs *store.ResourceServer) []string`

- [ ] **Step 1: Extend the test fixture**

In `internal/oauth/fixture_test.go`, add the following to the `acme` tenant in `fixtureSeed`, below its existing clients and grants:

```yaml
      - {client_id: code-spa, app_type: spa, grant_types: [authorization_code], callbacks: ["https://app.acme.test/cb"], id_token_lifetime: 600}
      - {client_id: code-web, app_type: regular_web, client_secret: code-web-secret, grant_types: [authorization_code], callbacks: ["https://web.acme.test/cb"]}
    connections:
      - {name: Username-Password-Authentication, enabled_clients: [code-spa, code-web]}
    users:
      - {connection: Username-Password-Authentication, email: alice@acme.test, password: "alice password 1", email_verified: true, name: Alice}
```

> The new client lines go inside the `clients:` list. `connections:` and `users:` are new keys at the tenant level (siblings of `clients:`). Keep the YAML indentation consistent with the existing entries.

- [ ] **Step 2: Write the failing tests**

```go
// internal/oauth/pkce_test.go
package oauth

import "testing"

func TestVerifyPKCE(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 Appendix B
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !verifyPKCE("S256", challenge, verifier) {
		t.Fatal("RFC 7636 test vector rejected")
	}
	for name, v := range map[string]string{
		"wrong":     "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX",
		"too short": "abc",
		"bad chars": verifier[:42] + "!",
		"empty":     "",
	} {
		if verifyPKCE("S256", challenge, v) {
			t.Errorf("%s verifier accepted", name)
		}
	}
	if verifyPKCE("plain", verifier, verifier) {
		t.Error("plain method accepted")
	}
}
```

```go
// internal/oauth/grant_authorization_code_test.go
package oauth

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// issueCode stores a code for alice as /authorize would, and returns it.
func (f *fixture) issueCode(t *testing.T, clientID, redirectURI, audience string, scopes []string, challenge string) string {
	t.Helper()
	ctx := context.Background()
	tenantID := f.tenantID(t, "acme")
	u, err := f.st.Users().FindByLogin(ctx, tenantID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	code := secrets.RandomString(43)
	ac := &store.AuthCode{
		TenantID: tenantID, CodeHash: secrets.HashToken(code), ClientID: clientID, RedirectURI: redirectURI,
		UserID: u.UserID, SessionID: "sid-1", Scopes: scopes, Audience: audience, Nonce: "n-1",
		AuthTime: fixedNow().Add(-time.Minute), ExpiresAt: fixedNow().Add(time.Minute), CreatedAt: fixedNow(),
	}
	if challenge != "" {
		ac.CodeChallenge, ac.CodeChallengeMethod = challenge, "S256"
	}
	if err := f.st.AuthCodes().Create(ctx, ac); err != nil {
		t.Fatal(err)
	}
	return code
}

func codeForm(code, clientID, redirectURI, verifier string) url.Values {
	v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID}, "redirect_uri": {redirectURI}}
	if verifier != "" {
		v.Set("code_verifier", verifier)
	}
	return v
}

func TestAuthorizationCodeSPA(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "code-spa", "https://app.acme.test/cb", "https://api.acme.test",
		[]string{"openid", "profile", "email", "read:things", "undefined:scope", "offline_access"}, pkceChallenge)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)})
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	if body["scope"] != "openid profile email read:things" || body["token_type"] != "Bearer" || body["expires_in"] != float64(3600) {
		t.Fatalf("body = %v", body)
	}
	tenantID := f.tenantID(t, "acme")
	at, _ := verifyToken(t, f.keys, tenantID, body["access_token"].(string))
	aud, _ := at["aud"].([]any)
	if len(aud) != 2 || aud[0] != "https://api.acme.test" || aud[1] != "https://acme.example.test/userinfo" ||
		!strings.HasPrefix(at["sub"].(string), "auth0|") || at["azp"] != "code-spa" || at["gty"] != nil {
		t.Fatalf("access token claims = %v", at)
	}
	idt, _ := verifyToken(t, f.keys, tenantID, body["id_token"].(string))
	if idt["aud"] != "code-spa" || idt["nonce"] != "n-1" || idt["sid"] != "sid-1" || idt["email"] != "alice@acme.test" ||
		idt["name"] != "Alice" || idt["at_hash"] == nil || idt["exp"].(float64)-idt["iat"].(float64) != 600 || idt["sub"] != at["sub"] {
		t.Fatalf("id token claims = %v", idt)
	}
}

func TestAuthorizationCodeWithoutAudience(t *testing.T) {
	f := newFixture(t)
	// The fixture tenant has default_audience set; codes carry the audience
	// chosen at /authorize, so an empty audience here means "none".
	code := f.issueCode(t, "code-web", "https://web.acme.test/cb", "", []string{"openid", "read:things"}, "")
	form := codeForm(code, "code-web", "https://web.acme.test/cb", "")
	form.Set("client_secret", "code-web-secret")
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form})
	if rec.Code != 200 || body["scope"] != "openid" || body["expires_in"] != float64(86400) {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	if at["aud"] != "https://acme.example.test/userinfo" {
		t.Fatalf("aud = %v", at["aud"])
	}
}

func TestAuthorizationCodeNoOpenID(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "code-spa", "https://app.acme.test/cb", "https://api.acme.test", []string{"read:things"}, pkceChallenge)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)})
	if rec.Code != 200 || body["id_token"] != nil {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	if at["aud"] != "https://api.acme.test" {
		t.Fatalf("aud = %v (no openid scope: API audience only)", at["aud"])
	}
}

// Review focus 2.
func TestAuthorizationCodeMisuse(t *testing.T) {
	f := newFixture(t)
	spa := func() string {
		return f.issueCode(t, "code-spa", "https://app.acme.test/cb", "", []string{"openid"}, pkceChallenge)
	}

	t.Run("replay", func(t *testing.T) {
		code := spa()
		form := codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)
		if rec, _ := f.call(t, true, tokenCall{host: "acme.example.test", form: form}); rec.Code != 200 {
			t.Fatalf("first use = %d", rec.Code)
		}
		if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form}); rec.Code != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("replay = %d %v", rec.Code, body)
		}
	})

	cases := map[string]func() tokenCall{
		"unknown code": func() tokenCall {
			return tokenCall{host: "acme.example.test", form: codeForm("nope", "code-spa", "https://app.acme.test/cb", pkceVerifier)}
		},
		"other client": func() tokenCall {
			form := codeForm(spa(), "code-web", "https://app.acme.test/cb", pkceVerifier)
			form.Set("client_secret", "code-web-secret")
			return tokenCall{host: "acme.example.test", form: form}
		},
		"other redirect_uri": func() tokenCall {
			return tokenCall{host: "acme.example.test", form: codeForm(spa(), "code-spa", "https://app.acme.test/other", pkceVerifier)}
		},
		"missing redirect_uri": func() tokenCall {
			form := codeForm(spa(), "code-spa", "https://app.acme.test/cb", pkceVerifier)
			form.Del("redirect_uri")
			return tokenCall{host: "acme.example.test", form: form}
		},
		"missing verifier": func() tokenCall {
			return tokenCall{host: "acme.example.test", form: codeForm(spa(), "code-spa", "https://app.acme.test/cb", "")}
		},
		"wrong verifier": func() tokenCall {
			return tokenCall{host: "acme.example.test", form: codeForm(spa(), "code-spa", "https://app.acme.test/cb", strings.Repeat("a", 43))}
		},
		"other tenant": func() tokenCall {
			return tokenCall{host: "globex.example.test", form: codeForm(spa(), "code-spa", "https://app.acme.test/cb", pkceVerifier)}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			rec, body := f.call(t, true, mk())
			if rec.Code == 200 || body["access_token"] != nil {
				t.Fatalf("tokens issued: %d %v", rec.Code, body)
			}
			if e := body["error"]; e != "invalid_grant" && e != "invalid_client" {
				t.Fatalf("error = %v", e)
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		code := spa()
		f.h.Now = func() time.Time { return fixedNow().Add(2 * time.Minute) }
		defer func() { f.h.Now = fixedNow }()
		if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)}); rec.Code != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("expired = %d %v", rec.Code, body)
		}
	})

	t.Run("blocked user", func(t *testing.T) {
		code := spa()
		ctx := context.Background()
		u, _ := f.st.Users().FindByLogin(ctx, f.tenantID(t, "acme"), "Username-Password-Authentication", "alice@acme.test")
		u.Blocked = true
		_ = f.st.Users().Update(ctx, u)
		defer func() { u.Blocked = false; _ = f.st.Users().Update(ctx, u) }()
		if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)}); rec.Code != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("blocked = %d %v", rec.Code, body)
		}
	})
}
```

> "other tenant": the request goes to globex's host with a client ID that only exists in acme, so client authentication fails with `invalid_client`. The test accepts either error code; what matters is that no tokens are issued.

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/oauth/`
Expected: FAIL: `undefined: verifyPKCE`. Once that compiles, the token tests fail with `unsupported_grant_type`.

- [ ] **Step 4: Implement**

Append to `internal/oauth/errors.go`:

```go
func invalidGrant(desc string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_grant", Description: desc}
}
```

```go
// internal/oauth/pkce.go
package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"regexp"
)

// RFC 7636 §4.1: 43-128 characters from the unreserved set.
var codeVerifierPattern = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)

// verifyPKCE checks a code_verifier against the stored challenge. Only
// S256 is supported.
func verifyPKCE(method, challenge, verifier string) bool {
	if method != "S256" || !codeVerifierPattern.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}
```

```go
// internal/oauth/grant_authorization_code.go
package oauth

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// oidcScopes are the user-flow scopes zeroauthy grants without an API.
// offline_access is added when refresh tokens exist (milestone 5).
var oidcScopes = []string{"openid", "profile", "email"}

// userScopes keeps requested OIDC scopes and, when an API is the
// audience, requested scopes that API defines.
func userScopes(requested []string, rs *store.ResourceServer) []string {
	var out []string
	for _, s := range requested {
		ok := slices.Contains(oidcScopes, s)
		if !ok && rs != nil {
			ok = slices.ContainsFunc(rs.Scopes, func(d store.Scope) bool { return d.Value == s })
		}
		if ok && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// authorizationCode implements RFC 6749 §4.1.3 with RFC 7636 PKCE.
func (h *Handlers) authorizationCode(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	code := form.Get("code")
	if code == "" {
		return nil, invalidRequest("code is required")
	}
	tenantID := res.Tenant.ID
	now := h.now()
	ac, err := h.Store.AuthCodes().Consume(ctx, tenantID, secrets.HashToken(code), now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, invalidGrant("invalid authorization code")
	case errors.Is(err, store.ErrAlreadyUsed):
		h.log().WarnContext(ctx, "authorization code reused", "tenant", tenantID, "client_id", ac.ClientID, "user_id", ac.UserID)
		return nil, invalidGrant("invalid authorization code")
	case err != nil:
		h.log().ErrorContext(ctx, "consume authorization code", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if ac.ClientID != c.ClientID {
		return nil, invalidGrant("invalid authorization code")
	}
	if !now.Before(ac.ExpiresAt) {
		return nil, invalidGrant("authorization code expired")
	}
	if form.Get("redirect_uri") != ac.RedirectURI {
		return nil, invalidGrant("redirect_uri does not match the authorization request")
	}
	if ac.CodeChallenge != "" {
		if !verifyPKCE(ac.CodeChallengeMethod, ac.CodeChallenge, form.Get("code_verifier")) {
			return nil, invalidGrant("code_verifier does not match the code_challenge")
		}
	} else if c.TokenEndpointAuthMethod == store.AuthMethodNone {
		return nil, invalidGrant("PKCE is required for public applications")
	}

	user, err := h.Store.Users().Get(ctx, tenantID, ac.UserID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && user.Blocked) {
		return nil, invalidGrant("the user is not allowed to sign in")
	}
	if err != nil {
		return nil, serverError()
	}

	userinfo := res.Issuer() + "userinfo"
	var rs *store.ResourceServer
	lifetime := DefaultAccessTokenLifetime
	if ac.Audience != "" {
		rs, err = h.Store.ResourceServers().GetByIdentifier(ctx, tenantID, ac.Audience)
		if errors.Is(err, store.ErrNotFound) {
			return nil, invalidGrant("the requested audience no longer exists")
		}
		if err != nil {
			return nil, serverError()
		}
		if rs.TokenLifetime > 0 {
			lifetime = time.Duration(rs.TokenLifetime) * time.Second
		}
	}
	scopes := userScopes(ac.Scopes, rs)
	openid := slices.Contains(scopes, "openid")
	var audiences []string
	switch {
	case rs != nil && openid:
		audiences = []string{rs.Identifier, userinfo}
	case rs != nil:
		audiences = []string{rs.Identifier}
	default:
		audiences = []string{userinfo}
	}

	accessToken, err := h.Minter.AccessToken(ctx, AccessTokenParams{
		TenantID: tenantID, Issuer: res.Issuer(), Subject: user.UserID, Audience: audiences,
		ClientID: c.ClientID, Scopes: scopes, Lifetime: lifetime,
	})
	if err != nil {
		h.log().ErrorContext(ctx, "mint access token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	resp := &authapi.TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int(lifetime / time.Second)}
	if len(scopes) > 0 {
		s := strings.Join(scopes, " ")
		resp.Scope = &s
	}
	if openid {
		idToken, err := h.Minter.IDToken(ctx, IDTokenParams{
			TenantID: tenantID, Issuer: res.Issuer(), ClientID: c.ClientID, User: user, Scopes: scopes,
			Nonce: ac.Nonce, SessionID: ac.SessionID, AuthTime: ac.AuthTime, AccessToken: accessToken,
			Lifetime: time.Duration(c.IDTokenLifetime) * time.Second,
		})
		if err != nil {
			h.log().ErrorContext(ctx, "mint id token", "tenant", tenantID, "err", err)
			return nil, serverError()
		}
		resp.IdToken = &idToken
	}
	return resp, nil
}
```

In `internal/oauth/token.go`, add the grant to the map:

```go
var grantHandlers = map[string]grantHandler{
	"authorization_code": (*Handlers).authorizationCode,
	"client_credentials": (*Handlers).clientCredentials,
}
```

- [ ] **Step 5: Update the contract**

In `api/authentication.yaml`, add to `TokenRequest.properties`:

```yaml
        code:
          type: string
          description: Authorization code (grant_type=authorization_code).
        redirect_uri:
          type: string
          description: Must equal the redirect_uri of the authorization request.
        code_verifier:
          type: string
          description: PKCE verifier for the code_challenge sent to /authorize.
```

Then replace the grant table in the `/oauth/token` description with:

```yaml
        | `grant_type` | Purpose |
        |---|---|
        | `authorization_code` | Exchange a code from `/authorize` (with `code_verifier` when PKCE was used) for an access token and, with scope `openid`, an ID token |
        | `client_credentials` | Machine-to-machine access token for `audience` |
```

Add `https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3` and `https://www.rfc-editor.org/rfc/rfc7636#section-4.6` to its `x-source`. Run `go generate ./...`. The generated `TokenRequest` gains three fields; nothing else uses them.

- [ ] **Step 6: Run the tests**

Run: `go generate ./... && gofmt -l . ; go vet ./... && go test ./...`
Expected: `ok`, with no `contract:` violations.

- [ ] **Step 7: Record decision D-0008** by appending to `docs/compat/decisions.md`:

```markdown
## D-0008: Authorization codes and user-flow tokens

- **Context:** Code lifetime, replay handling, and the audience of user-flow access tokens.
- **Sources:** RFC 6749 §4.1.2 and §10.5; OAuth 2.0 Security BCP (RFC 9700) §4.5; OpenID Connect Core §5.3.1; Auth0 public docs on calling /userinfo with an access token.
- **Decision:**
  - Codes live 60 seconds, are single-use, and are stored hashed. A replayed code is rejected with `invalid_grant` and logged; revoking descendant tokens comes with refresh tokens.
  - User-flow access tokens are JWTs:
    - `aud` holds the API identifier and, when `openid` is granted, `https://{host}/userinfo`.
    - Without an API, `aud` is the userinfo URL only, and clients must treat the token as opaque.
    - Granted scopes are the requested `openid`/`profile`/`email` plus requested scopes the API defines. No `gty` claim is added.
- **Rationale:** A short single-use code limits interception. JWTs for userinfo-only tokens avoid server-side token storage while behaving like opaque tokens to clients.
```

- [ ] **Step 8: Commit**

```bash
git add internal/oauth api internal/gen docs/compat/decisions.md
git commit -m "feat(oauth): add the authorization code grant with PKCE and ID tokens"
```

---

### Task 13: /userinfo

**Files:**
- Modify: `api/authentication.yaml` (add `/userinfo` GET and POST), then regenerate
- Create: `internal/oidc/userinfo.go`, `internal/oidc/userinfo_test.go`
- Modify: `internal/oidc/handlers.go` (add a `Store` field), `internal/server/server.go` (forward `Userinfo` and `UserinfoPost`; pass `Store` to oidc)

**Interfaces:**
- Consumes: `keys.Manager.Verify`, `claims.ForUser`, `store.Users`, `tenant.FromContext`, `httpx.WriteJSON/WriteError`; go-jose `jwt.Claims` and `jwt.Expected`.
- Produces:
  - `oidc.Handlers{Keys, Store, Log, Now}`
  - `(*oidc.Handlers).Userinfo(w, r)` serves GET and POST
  - generated `ServerInterface` methods `Userinfo(w, r)` and `UserinfoPost(w, r)`

- [ ] **Step 1: Add the operations to the contract**

Under `paths:` in `api/authentication.yaml`:

```yaml
  /userinfo:
    get:
      operationId: userinfo
      tags: [Users]
      summary: Get the user's profile
      description: |
        Returns OpenID Connect claims about the user an access token was
        issued to. The access token must include `https://{tenant_domain}/userinfo`
        in its audience, which tokens requested with scope `openid` do. Claims
        follow the token's scopes: `profile` adds name, nickname, picture and
        updated_at; `email` adds email and email_verified.
      x-source:
        - https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
        - https://www.rfc-editor.org/rfc/rfc6750#section-2.1
        - https://auth0.com/docs/api/authentication
      security:
        - bearerAuth: []
      responses:
        "200":
          description: The user's claims.
          headers:
            Cache-Control:
              schema: {type: string, const: no-store}
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/UserInfo"
        "401":
          description: Missing or invalid access token.
          headers:
            WWW-Authenticate:
              schema: {type: string}
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/OAuthError"
        "404":
          $ref: "#/components/responses/UnknownTenant"
        default:
          $ref: "#/components/responses/ServerError"
    post:
      operationId: userinfoPost
      tags: [Users]
      summary: Get the user's profile (POST)
      description: Same as `GET /userinfo`.
      x-source:
        - https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
      security:
        - bearerAuth: []
      responses:
        "200":
          description: The user's claims.
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/UserInfo"
        "401":
          description: Missing or invalid access token.
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/OAuthError"
        "404":
          $ref: "#/components/responses/UnknownTenant"
        default:
          $ref: "#/components/responses/ServerError"
```

Under `components.securitySchemes`:

```yaml
    bearerAuth:
      type: http
      scheme: bearer
      description: An access token issued by this tenant.
```

Under `components.schemas`:

```yaml
    UserInfo:
      type: object
      required: [sub]
      properties:
        sub: {type: string}
        name: {type: string}
        nickname: {type: string}
        picture: {type: string}
        updated_at: {type: integer}
        email: {type: string}
        email_verified: {type: boolean}
      additionalProperties: true
```

Add the tag `- name: Users` (`description: Information about the signed-in user.`). Run `go generate ./...`.

- [ ] **Step 2: Write the failing test**

```go
// internal/oidc/userinfo_test.go
package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

var uiNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

type uiEnv struct {
	km  *keys.Manager
	srv http.Handler
}

func newUserinfoEnv(t *testing.T) *uiEnv {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	for _, tn := range []*store.Tenant{
		{ID: "ten_a", Name: "acme", Domains: []string{"acme.example.test"}},
		{ID: "ten_b", Name: "globex", Domains: []string{"globex.example.test"}},
	} {
		_ = st.Tenants().Create(ctx, tn)
	}
	_ = st.Users().Create(ctx, &store.User{
		TenantID: "ten_a", UserID: "auth0|1", Email: "alice@acme.test", EmailVerified: true, Name: "Alice",
		Identities: []store.Identity{{Connection: "DB", Provider: "auth0", UserID: "1"}}, UpdatedAt: uiNow,
	})
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{4}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	_ = km.Ensure(ctx, "ten_a")
	_ = km.Ensure(ctx, "ten_b")
	h := &Handlers{Keys: km, Store: st, Now: func() time.Time { return uiNow }}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /userinfo", h.Userinfo)
	mux.HandleFunc("POST /userinfo", h.Userinfo)
	return &uiEnv{km: km, srv: contract.Wrap(t, tenant.NewResolver(st.Tenants(), "", false).Middleware(mux))}
}

func (e *uiEnv) token(t *testing.T, tenantID string, claims map[string]any) string {
	t.Helper()
	base := map[string]any{
		"iss": "https://acme.example.test/", "sub": "auth0|1",
		"aud": []string{"https://api.test", "https://acme.example.test/userinfo"},
		"iat": uiNow.Unix(), "exp": uiNow.Add(time.Hour).Unix(), "scope": "openid email",
	}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	raw, err := e.km.Sign(context.Background(), tenantID, base)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (e *uiEnv) call(method, authz string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://acme.example.test/userinfo", nil)
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, r)
	return rec
}

func TestUserinfo(t *testing.T) {
	e := newUserinfoEnv(t)
	for _, method := range []string{"GET", "POST"} {
		rec := e.call(method, "Bearer "+e.token(t, "ten_a", nil))
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != 200 || body["sub"] != "auth0|1" || body["email"] != "alice@acme.test" || body["email_verified"] != true {
			t.Fatalf("%s = %d %v", method, rec.Code, body)
		}
		if _, ok := body["name"]; ok {
			t.Fatal("profile claim returned without profile scope")
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing no-store")
		}
	}
	// Scheme is case-insensitive (RFC 7235 §2.1).
	if rec := e.call("GET", "bearer "+e.token(t, "ten_a", nil)); rec.Code != 200 {
		t.Fatalf("lowercase scheme = %d", rec.Code)
	}
}

func TestUserinfoRejects(t *testing.T) {
	e := newUserinfoEnv(t)
	cases := map[string]string{
		"no header":        "",
		"basic scheme":     "Basic Zm9vOmJhcg==",
		"garbage":          "Bearer not-a-token",
		"other tenant key": "Bearer " + e.token(t, "ten_b", nil),
		"expired":          "Bearer " + e.token(t, "ten_a", map[string]any{"exp": uiNow.Add(-time.Second).Unix()}),
		"wrong issuer":     "Bearer " + e.token(t, "ten_a", map[string]any{"iss": "https://globex.example.test/"}),
		"api-only aud":     "Bearer " + e.token(t, "ten_a", map[string]any{"aud": "https://api.test"}),
		"unknown user":     "Bearer " + e.token(t, "ten_a", map[string]any{"sub": "auth0|missing"}),
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			rec := e.call("GET", header)
			if rec.Code != 401 || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
				t.Fatalf("got %d %v %s", rec.Code, rec.Header(), rec.Body)
			}
		})
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/oidc/`
Expected: FAIL: `h.Userinfo undefined`, `unknown field Store`.

- [ ] **Step 4: Implement**

In `internal/oidc/handlers.go`, extend `Handlers` and add a clock helper:

```go
type Handlers struct {
	Keys  *keys.Manager
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
```

Add the `store` and `time` imports.

```go
// internal/oidc/userinfo.go
package oidc

import (
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/claims"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Userinfo implements GET and POST /userinfo (OpenID Connect Core §5.3).
func (h *Handlers) Userinfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	res, ok := tenant.FromContext(ctx)
	if !ok {
		httpx.WriteError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	raw, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_request", "an access token is required")
		return
	}
	var std jwt.Claims
	var extra struct {
		Scope string `json:"scope"`
	}
	err := h.Keys.Verify(ctx, res.Tenant.ID, raw, &std, &extra)
	if err == nil {
		err = std.ValidateWithLeeway(jwt.Expected{
			Issuer:      res.Issuer(),
			AnyAudience: jwt.Audience{res.Issuer() + "userinfo"},
			Time:        h.now(),
		}, 0)
	}
	if err != nil {
		invalidToken(w)
		return
	}
	user, err := h.Store.Users().Get(ctx, res.Tenant.ID, std.Subject)
	if err != nil || user.Blocked {
		invalidToken(w)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, claims.ForUser(user, strings.Fields(extra.Scope)))
}

func invalidToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_token"`)
	httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "the access token is invalid or expired")
}

// bearerToken extracts an RFC 6750 §2.1 bearer token.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return "", false
	}
	return strings.TrimSpace(token), true
}
```

In `internal/server/server.go`, set `oidc: &oidc.Handlers{Keys: d.Keys, Store: d.Store, Log: d.Log}`, and add:

```go
func (a authAPI) Userinfo(w http.ResponseWriter, r *http.Request)     { a.oidc.Userinfo(w, r) }
func (a authAPI) UserinfoPost(w http.ResponseWriter, r *http.Request) { a.oidc.Userinfo(w, r) }
```

- [ ] **Step 5: Run the tests**

Run: `go generate ./... && gofmt -l . ; go vet ./... && go test ./...`
Expected: `ok`, with no `contract:` violations.

- [ ] **Step 6: Commit**

```bash
git add api internal/gen internal/oidc internal/server
git commit -m "feat(oidc): serve /userinfo for userinfo-audience access tokens"
```

---
### Task 14: CORS, discovery update, end-to-end flow test

**Files:**
- Create: `internal/server/cors.go`, `internal/server/flow_test.go`
- Modify: `internal/server/server.go` (middleware, OPTIONS routes)
- Modify: `internal/oidc/handlers.go`, `internal/oidc/handlers_test.go` (discovery fields)
- Modify: `api/authentication.yaml` (`OpenIDConfiguration` schema), then regenerate

**Interfaces:**
- Consumes: `store.Clients.List`, `tenant.FromContext`, and everything wired in Tasks 10–13.
- Produces:
  - `server.cors(st store.Store) func(http.Handler) http.Handler`
  - Discovery gains `userinfo_endpoint`, `response_modes_supported`, `code_challenge_methods_supported`, `scopes_supported` and `claims_supported`.
  - Discovery now lists `grant_types_supported: [authorization_code, client_credentials]` and `token_endpoint_auth_methods_supported: [client_secret_basic, client_secret_post, none]`.

- [ ] **Step 1: Update the discovery test** in `internal/oidc/handlers_test.go` `TestDiscovery`

Replace the `grant_types_supported` assertion with:

```go
	wantLists := map[string][]string{
		"grant_types_supported":                 {"authorization_code", "client_credentials"},
		"response_types_supported":              {"code"},
		"response_modes_supported":              {"query", "fragment", "form_post", "web_message"},
		"code_challenge_methods_supported":      {"S256"},
		"scopes_supported":                      {"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": {"client_secret_basic", "client_secret_post", "none"},
	}
	for k, want := range wantLists {
		var got []string
		for _, v := range doc[k].([]any) {
			got = append(got, v.(string))
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s = %v, want %v", k, got, want)
		}
	}
	if doc["userinfo_endpoint"] != "https://acme.example.test/userinfo" {
		t.Errorf("userinfo_endpoint = %v", doc["userinfo_endpoint"])
	}
	if len(doc["claims_supported"].([]any)) == 0 {
		t.Error("claims_supported is empty")
	}
```

Add `"strings"` to the test imports.

- [ ] **Step 2: Write the CORS and full-flow tests**

```go
// internal/server/flow_test.go
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const flowSeed = `
tenants:
  - name: flow
    domains: ["HOST"]
    resource_servers:
      - {identifier: "https://api.flow.test", name: API, scopes: [{value: "read:things"}]}
    clients:
      - client_id: spa
        app_type: spa
        grant_types: [authorization_code]
        callbacks: ["https://app.flow.test/cb"]
        web_origins: ["https://app.flow.test"]
        allowed_origins: ["https://app.flow.test"]
    connections:
      - {name: Username-Password-Authentication, enabled_clients: [spa]}
    users:
      - {connection: Username-Password-Authentication, email: alice@flow.test, password: "alice password 1", email_verified: true}
`

const (
	verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

type flowEnv struct {
	srv  *httptest.Server
	base string
}

func newFlowEnv(t *testing.T) *flowEnv {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{8}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	srv := httptest.NewTLSServer(New(Deps{
		Store: st, Keys: km, Resolver: tenant.NewResolver(st.Tenants(), "", false),
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sessions:     &session.Manager{Store: st},
		UserThrottle: identity.NewThrottle(10, time.Minute, time.Minute),
		IPThrottle:   identity.NewThrottle(100, time.Minute, time.Minute),
	}))
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()
	f, err := seed.Parse([]byte(strings.Replace(flowSeed, "HOST", host, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(ctx, st, f, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "flow")
	if err := km.Ensure(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	return &flowEnv{srv: srv, base: "https://" + host}
}

func (e *flowEnv) client(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	c := e.srv.Client()
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func authorizeURL(base string, extra ...string) string {
	q := url.Values{
		"client_id": {"spa"}, "redirect_uri": {"https://app.flow.test/cb"}, "response_type": {"code"},
		"scope": {"openid email read:things"}, "audience": {"https://api.flow.test"}, "state": {"s1"}, "nonce": {"n1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "auth0Client": {"eyJuYW1lIjoidGVzdCJ9"},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	return base + "/authorize?" + q.Encode()
}

func mustDo(t *testing.T, c *http.Client, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	req, _ := http.NewRequest("GET", u, nil)
	return mustDo(t, c, req)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func TestEndToEndCodeFlow(t *testing.T) {
	e := newFlowEnv(t)
	c := e.client(t)

	// 1. /authorize without a session goes to the login page.
	resp, _ := get(t, c, authorizeURL(e.base))
	loginURL, _ := resp.Location()
	if resp.StatusCode != 302 || loginURL.Path != "/u/login" {
		t.Fatalf("authorize = %d %v", resp.StatusCode, loginURL)
	}
	// 2. Log in.
	_, page := get(t, c, loginURL.String())
	csrf := csrfRe.FindStringSubmatch(page)
	if csrf == nil {
		t.Fatalf("no csrf: %s", page)
	}
	form := url.Values{"state": {loginURL.Query().Get("state")}, "csrf": {csrf[1]}, "username": {"alice@flow.test"}, "password": {"alice password 1"}}
	req, _ := http.NewRequest("POST", e.base+"/u/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, body := mustDo(t, c, req)
	cb, _ := resp.Location()
	if resp.StatusCode != 302 || cb.Host != "app.flow.test" || cb.Query().Get("state") != "s1" {
		t.Fatalf("login = %d %v %s", resp.StatusCode, cb, body)
	}
	// 3. Exchange the code from the SPA's origin.
	tf := url.Values{"grant_type": {"authorization_code"}, "client_id": {"spa"}, "code": {cb.Query().Get("code")},
		"redirect_uri": {"https://app.flow.test/cb"}, "code_verifier": {verifier}}
	req, _ = http.NewRequest("POST", e.base+"/oauth/token", strings.NewReader(tf.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://app.flow.test")
	resp, body = mustDo(t, c, req)
	if resp.StatusCode != 200 || resp.Header.Get("Access-Control-Allow-Origin") != "https://app.flow.test" {
		t.Fatalf("token = %d %v %s", resp.StatusCode, resp.Header, body)
	}
	var tok map[string]any
	_ = json.Unmarshal([]byte(body), &tok)
	if tok["id_token"] == nil || tok["scope"] != "openid email read:things" {
		t.Fatalf("token body = %v", tok)
	}
	// 4. /userinfo with the access token.
	req, _ = http.NewRequest("GET", e.base+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	resp, body = mustDo(t, c, req)
	if resp.StatusCode != 200 || !strings.Contains(body, `"email":"alice@flow.test"`) {
		t.Fatalf("userinfo = %d %s", resp.StatusCode, body)
	}
	// 5. Silent authentication with the session cookie.
	resp, body = get(t, c, authorizeURL(e.base, "prompt", "none", "response_mode", "web_message"))
	if resp.StatusCode != 200 || !strings.Contains(body, "authorization_response") || !strings.Contains(body, "code") || strings.Contains(body, "login_required") {
		t.Fatalf("silent auth = %d %s", resp.StatusCode, body)
	}
	// 6. Silent authentication without a session (review focus 5).
	resp, body = get(t, e.client(t), authorizeURL(e.base, "prompt", "none", "response_mode", "web_message"))
	if resp.StatusCode != 200 || !strings.Contains(body, "login_required") {
		t.Fatalf("silent auth without session = %d %s", resp.StatusCode, body)
	}
}

func TestCORS(t *testing.T) {
	e := newFlowEnv(t)
	c := e.client(t)
	preflight := func(path, origin string) *http.Response {
		req, _ := http.NewRequest("OPTIONS", e.base+path, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type, auth0-client")
		resp, _ := mustDo(t, c, req)
		return resp
	}
	for _, path := range []string{"/oauth/token", "/userinfo"} {
		resp := preflight(path, "https://app.flow.test")
		h := resp.Header
		if resp.StatusCode != 204 || h.Get("Access-Control-Allow-Origin") != "https://app.flow.test" ||
			!strings.Contains(h.Get("Access-Control-Allow-Methods"), "POST") ||
			h.Get("Access-Control-Allow-Headers") != "content-type, auth0-client" || !strings.Contains(h.Get("Vary"), "Origin") {
			t.Errorf("%s preflight = %d %v", path, resp.StatusCode, h)
		}
		resp = preflight(path, "https://evil.test")
		if resp.StatusCode != 403 || resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s evil preflight = %d %v", path, resp.StatusCode, resp.Header)
		}
	}
	resp, _ := get(t, c, e.base+"/.well-known/jwks.json")
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("jwks ACAO = %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/server/ ./internal/oidc/`
Expected: FAIL. The discovery lists differ, the token response lacks `Access-Control-Allow-Origin`, and the preflight returns 405.

- [ ] **Step 4: Implement**

```go
// internal/server/cors.go
package server

import (
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// cors applies CORS. Public metadata is readable from any origin. The
// token and userinfo endpoints accept an origin only if one of the
// tenant's clients lists it in allowed_origins or web_origins. Runs after
// tenant resolution.
func cors(st store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration", "/.well-known/jwks.json":
				w.Header().Set("Access-Control-Allow-Origin", "*")
				next.ServeHTTP(w, r)
				return
			case "/oauth/token", "/userinfo":
			default:
				next.ServeHTTP(w, r)
				return
			}
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Add("Vary", "Origin")
			res, ok := tenant.FromContext(r.Context())
			if !ok || !originAllowed(r, st, res.Tenant.ID, origin) {
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r) // no CORS headers: the browser blocks the response
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
				if h := r.Header.Get("Access-Control-Request-Headers"); h != "" {
					w.Header().Set("Access-Control-Allow-Headers", h)
				}
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func originAllowed(r *http.Request, st store.Store, tenantID, origin string) bool {
	clients, err := st.Clients().List(r.Context(), tenantID)
	if err != nil {
		return false
	}
	for _, c := range clients {
		if slices.Contains(c.AllowedOrigins, origin) || slices.Contains(c.WebOrigins, origin) {
			return true
		}
	}
	return false
}
```

In `internal/server/server.go`, change the tenant group's first line to `tr.Use(d.Resolver.Middleware, cors(d.Store))`. After `HandlerWithOptions`, register OPTIONS routes so preflights reach the middleware rather than chi's 405:

```go
		preflight := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
		tr.Options("/oauth/token", preflight)
		tr.Options("/userinfo", preflight)
```

> A preflight from an allowed origin is answered by the middleware before `preflight` runs. A preflight from a disallowed origin gets 403 from the middleware. `preflight` itself only runs for OPTIONS requests without an `Origin` header.

In `internal/oidc/handlers.go`, extend `Configuration` and the `Discovery` literal:

```go
type Configuration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}
```

```go
	httpx.WriteJSON(w, http.StatusOK, Configuration{
		Issuer:                            res.Issuer(),
		AuthorizationEndpoint:             base + "/authorize",
		TokenEndpoint:                     base + "/oauth/token",
		UserinfoEndpoint:                  base + "/userinfo",
		JWKSURI:                           base + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query", "fragment", "form_post", "web_message"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		GrantTypesSupported:               []string{"authorization_code", "client_credentials"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   []string{"openid", "profile", "email"},
		ClaimsSupported: []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "at_hash",
			"name", "nickname", "picture", "updated_at", "email", "email_verified"},
	})
```

In `api/authentication.yaml`, add these to `OpenIDConfiguration.properties`:

```yaml
        userinfo_endpoint: {type: string, format: uri}
        response_modes_supported: {type: array, items: {type: string}}
        code_challenge_methods_supported: {type: array, items: {type: string}}
        scopes_supported: {type: array, items: {type: string}}
        claims_supported: {type: array, items: {type: string}}
```

Also update the discovery operation's description to say that `authorization_endpoint` and `userinfo_endpoint` are now served. Then run `go generate ./...`.

- [ ] **Step 5: Run the tests**

Run: `go generate ./... && gofmt -l . ; go vet ./... && go test -race ./...`
Expected: `ok` everywhere, with no `contract:` violations.

- [ ] **Step 6: Record decision D-0009** by appending to `docs/compat/decisions.md`:

```markdown
## D-0009: CORS for browser applications

- **Context:** SPAs call `/oauth/token` and `/userinfo` cross-origin. A preflight does not say which client is calling.
- **Sources:** Fetch Standard (CORS protocol); Auth0 public docs describing "Allowed Web Origins" and "Allowed Origins (CORS)" application settings.
- **Decision:**
  - Discovery and JWKS send `Access-Control-Allow-Origin: *`.
  - `/oauth/token` and `/userinfo` echo the `Origin` back if any client of the tenant lists it in `allowed_origins` or `web_origins`, and preflights reflect the requested headers.
  - Other origins get no CORS headers (403 on preflight).
  - Credentials (cookies) are never allowed cross-origin.
- **Rationale:** Client authentication still happens on the actual request. CORS only decides which browser origins may read responses.
```

- [ ] **Step 7: Commit**

```bash
git add internal/server internal/oidc api internal/gen docs/compat/decisions.md
git commit -m "feat: add CORS, extend discovery, test the full code flow end to end"
```

---

### Task 15: auth0-spa-js end-to-end test, docs, follow-ups

**Files:**
- Modify: `tests/e2e/package.json` (and regenerate `package-lock.json`), `tests/e2e/seed.yaml`
- Create: `tests/e2e/spa/index.html`, `tests/e2e/spa/app.js`, `tests/e2e/spa-server.mjs`, `tests/e2e/playwright.config.mjs`, `tests/e2e/m4-spa-login.spec.mjs`, `tests/e2e/run-m4.sh`
- Modify: `Makefile`, `.github/workflows/ci.yml`, `.gitignore`, `README.md`, `docs/compat/matrix.md`, `docs/superpowers/plan-1-followups.md`

**Interfaces:**
- Consumes: the running server (Tasks 1–14), and `tests/e2e/config.yaml` from Plan 1 (port 8443, memory storage, seed).
- Produces: `make e2e` runs `run-m3.sh` and then `run-m4.sh`. `E2E_IN_CONTAINER=1 ./tests/e2e/run-m4.sh` runs Playwright inside `mcr.microsoft.com/playwright:v1.64.0-noble` (docker or podman, host network).

- [ ] **Step 1: Extend the e2e fixtures**

Add `"@auth0/auth0-spa-js": "2.28.3"` and `"@playwright/test": "1.64.0"` to `tests/e2e/package.json` `dependencies`. Run `(cd tests/e2e && npm install --no-audit --no-fund)` to update the lockfile.

Append to the `e2e` tenant in `tests/e2e/seed.yaml`. Merge the client into the existing `clients:` list, and add `connections:` and `users:` at the tenant level:

```yaml
      - client_id: e2e-spa
        name: E2E SPA
        app_type: spa
        grant_types: [authorization_code]
        callbacks: ["https://localhost:3443/"]
        web_origins: ["https://localhost:3443"]
        allowed_origins: ["https://localhost:3443"]
    connections:
      - name: Username-Password-Authentication
        enabled_clients: [e2e-spa]
    users:
      - connection: Username-Password-Authentication
        email: alice@e2e.local
        password: "Correct-Horse-Battery-9"
        email_verified: true
        name: Alice Example
```

Add `tests/e2e/test-results/` and `tests/e2e/playwright-report/` to `.gitignore` if they are not already there. The Plan 1 patterns use `**`; check that they match.

- [ ] **Step 2: Write the SPA and its server**

```html
<!-- tests/e2e/spa/index.html -->
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>zeroauthy e2e SPA</title></head>
<body>
<button id="login" type="button">Log in</button>
<pre id="out"></pre>
<script src="/auth0-spa-js.js"></script>
<script src="/app.js"></script>
</body>
</html>
```

```js
// tests/e2e/spa/app.js — a minimal app using auth0-spa-js exactly as its
// public README shows; only the domain points at zeroauthy.
(async () => {
  const started = performance.now();
  const client = await auth0.createAuth0Client({
    domain: 'localhost:8443',
    clientId: 'e2e-spa',
    authorizationParams: {
      redirect_uri: window.location.origin + '/',
      audience: 'https://api.e2e.local',
      scope: 'openid profile email read:things',
    },
  });
  const initMs = performance.now() - started;
  const params = new URLSearchParams(window.location.search);
  if (params.has('code') && params.has('state')) {
    await client.handleRedirectCallback();
    window.history.replaceState({}, '', '/');
  }
  window.__za = { client, initMs };
  document.getElementById('login').onclick = () => client.loginWithRedirect();
  document.body.dataset.ready = 'true';
})().catch((err) => {
  document.getElementById('out').textContent = String((err && (err.error_description || err.error || err.message)) || err);
  document.body.dataset.ready = 'error';
});
```

```js
// tests/e2e/spa-server.mjs — serves the SPA over HTTPS on localhost:3443
// using the test certificate from run-m4.sh.
import { createServer } from 'node:https';
import { readFile } from 'node:fs/promises';

const routes = {
  '/': ['spa/index.html', 'text/html; charset=utf-8'],
  '/app.js': ['spa/app.js', 'text/javascript'],
  '/auth0-spa-js.js': ['node_modules/@auth0/auth0-spa-js/dist/auth0-spa-js.production.js', 'text/javascript'],
};

const server = createServer(
  { cert: await readFile(process.env.E2E_CERT), key: await readFile(process.env.E2E_KEY) },
  async (req, res) => {
    const route = routes[new URL(req.url, 'https://localhost').pathname];
    if (!route) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': route[1], 'cache-control': 'no-store' });
    res.end(await readFile(new URL('./' + route[0], import.meta.url)));
  },
);
server.listen(3443, () => console.log('SPA on https://localhost:3443'));
```

- [ ] **Step 3: Write the Playwright test** (this is the failing test until the stack is complete)

```js
// tests/e2e/playwright.config.mjs
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: /m4-.*\.spec\.mjs/,
  timeout: 60_000,
  workers: 1,
  reporter: [['list']],
  use: { browserName: 'chromium', headless: true, ignoreHTTPSErrors: true, trace: 'retain-on-failure' },
});
```

```js
// tests/e2e/m4-spa-login.spec.mjs
// Black-box test (CLEAN_ROOM.md): @auth0/auth0-spa-js in a real browser
// against zeroauthy, and express-oauth2-jwt-bearer validating the token.
import { test, expect } from '@playwright/test';
import { once } from 'node:events';
import express from 'express';
import { auth } from 'express-oauth2-jwt-bearer';

const SPA = 'https://localhost:3443/';

async function ready(page) {
  await expect(page.locator('body')).toHaveAttribute('data-ready', /true|error/, { timeout: 20_000 });
  const state = await page.locator('body').getAttribute('data-ready');
  if (state !== 'true') throw new Error('SPA failed: ' + (await page.locator('#out').textContent()));
}

test('auth0-spa-js logs in with zeroauthy and calls an API', async ({ page }) => {
  await page.goto(SPA);
  await ready(page);
  // createAuth0Client's silent check must get an answer (login_required)
  // rather than wait for its timeout.
  expect(await page.evaluate(() => window.__za.initMs)).toBeLessThan(5_000);
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(false);

  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'not the password');
  await page.click('button[type=submit]');
  await expect(page.locator('[role=alert]')).toContainText('Incorrect');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  await page.click('button[type=submit]');
  await page.waitForURL(SPA);
  await ready(page);

  const user = await page.evaluate(() => window.__za.client.getUser());
  expect(user.email).toBe('alice@e2e.local');
  expect(user.name).toBe('Alice Example');
  const token = await page.evaluate(() => window.__za.client.getTokenSilently());

  const api = express();
  api.get('/me', auth({ issuerBaseURL: 'https://localhost:8443', audience: 'https://api.e2e.local' }), (req, res) =>
    res.json(req.auth.payload));
  const server = api.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const r = await fetch(`http://127.0.0.1:${server.address().port}/me`, { headers: { authorization: `Bearer ${token}` } });
    expect(r.status).toBe(200);
    const payload = await r.json();
    expect(payload.sub).toBe(user.sub);
    expect(payload.scope.split(' ')).toContain('read:things');
  } finally {
    server.close();
  }

  // After a reload the in-memory cache is gone; the SDK restores the
  // login through silent authentication with the session cookie.
  await page.reload();
  await ready(page);
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(true);
  expect((await page.evaluate(() => window.__za.client.getUser())).email).toBe('alice@e2e.local');
});
```

- [ ] **Step 4: Write the runner**

```bash
#!/usr/bin/env bash
# tests/e2e/run-m4.sh: build zeroauthy, serve it and a test SPA over TLS,
# and drive auth0-spa-js in Chromium with Playwright.
# E2E_IN_CONTAINER=1 runs Playwright in the official container image
# (docker or podman) instead of on the host.
set -euo pipefail
cd "$(dirname "$0")/../.."

work="$(mktemp -d)"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$work"; }
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
chmod 644 "$work/key.pem"

CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem" ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem" \
  "$work/zeroauthy" serve --config tests/e2e/config.yaml >"$work/server.log" 2>&1 &
pids+=($!)

cd tests/e2e
npm ci --no-audit --no-fund --silent
E2E_CERT="$work/cert.pem" E2E_KEY="$work/key.pem" node spa-server.mjs >"$work/spa.log" 2>&1 &
pids+=($!)

for url in https://localhost:8443/healthz https://localhost:3443/; do
  for _ in $(seq 1 50); do curl -sf --cacert "$work/cert.pem" "$url" >/dev/null && break; sleep 0.2; done
done

status=0
if [[ "${E2E_IN_CONTAINER:-0}" == 1 ]]; then
  runtime="$(command -v docker || command -v podman)"
  "$runtime" run --rm --network host --ipc host \
    -v "$PWD:/e2e" -v "$work:$work:ro" -w /e2e \
    -e NODE_EXTRA_CA_CERTS="$work/cert.pem" \
    mcr.microsoft.com/playwright:v1.64.0-noble npx playwright test || status=$?
else
  npx playwright install chromium >/dev/null
  NODE_EXTRA_CA_CERTS="$work/cert.pem" npx playwright test || status=$?
fi
if [[ $status -ne 0 ]]; then
  echo "--- zeroauthy log ---"; cat "$work/server.log"
  echo "--- spa log ---"; cat "$work/spa.log"
fi
exit $status
```

- [ ] **Step 5: Run it**

```bash
chmod +x tests/e2e/run-m4.sh
./tests/e2e/run-m4.sh
```

Expected: Playwright prints `1 passed`.

**If Chromium fails to launch on the host** (missing shared libraries), run `E2E_IN_CONTAINER=1 ./tests/e2e/run-m4.sh`. If the podman socket or image pull fails, stop and report BLOCKED with the exact error; the user has offered to install a container service.

**If the test fails, debug from our side only** (CLEAN_ROOM.md). Use:
- the zeroauthy log, which records each request path and status;
- the Playwright trace (`npx playwright show-trace test-results/**/trace.zip`);
- the browser console in the trace;
- the SDK's error text in `#out`.

Typical server-side causes:
- a CORS preflight rejected (look for 403 on `OPTIONS /oauth/token`);
- an `id_token` claim the SDK rejects (the error names the claim);
- a `web_message` page not posting where the SDK listens (check the trace's console and the `frame-ancestors` header).

Fix the server with a Go test for each fix, and add a decision entry for anything that resolves undocumented behavior. Never weaken the e2e assertions.

- [ ] **Step 6: Wire `make e2e` and CI**

In the `Makefile`, change the `e2e` recipe to:

```make
e2e:
	./tests/e2e/run-m3.sh
	./tests/e2e/run-m4.sh
```

In `.github/workflows/ci.yml`, in the `e2e` job, replace its last step with:

```yaml
      - run: npm ci --no-audit --no-fund
        working-directory: tests/e2e
      - run: npx playwright install --with-deps chromium
        working-directory: tests/e2e
      - run: make e2e
```

- [ ] **Step 7: Update the docs**

In `docs/compat/matrix.md`, replace the "Other Authentication API endpoints" row with:

```markdown
| `/authorize`: `response_type=code`, PKCE (S256), `response_mode` query / fragment / form_post / web_message, `prompt` none / login, `max_age`, `connection`, `screen_hint=signup`, `login_hint` | Implemented | Verified with @auth0/auth0-spa-js 2.28.3 (login, silent auth, reload) |
| `/oauth/token`: `authorization_code` | Implemented | ID token with `at_hash`, `sid`, `nonce` |
| `/userinfo` (GET, POST) | Implemented | |
| Hosted login: `/u/login`, `/u/signup` | Implemented | Database connections only |
| Logout, refresh tokens, implicit/hybrid flows, password reset, `/dbconnections/*`, password grants | Planned (milestones 5–6) | |
```

Also update the Discovery row's note: `/authorize` is now served.

In `README.md`:
- update the status line to say login with the hosted page and the authorization code + PKCE flow work (verified with auth0-spa-js);
- add a "Try the login page" snippet after the quick start:

````markdown
### Try the login page

With the quick-start server running, open:

```
https://localhost:8443/authorize?client_id=e2e-spa&response_type=code&redirect_uri=https://localhost:3443/&scope=openid%20profile&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=demo
```

and sign in as `alice@e2e.local` / `Correct-Horse-Battery-9` (test data from
`tests/e2e/seed.yaml`). You are redirected to `https://localhost:3443/?code=…`.
````

In `docs/superpowers/plan-1-followups.md`:
- remove the two rows this plan resolved: the `secrets.Verify` bounds (Task 1) and the `/docs` SRI + `aud: null` rows (Task 1);
- append to "Nice to have";
- append a new "Plan 2 follow-ups" section:

```markdown
## Plan 2 follow-ups

| Before | Item |
|---|---|
| SQL drivers (milestone 7) | Expired login transactions, authorization codes and sessions are never purged; add `DeleteExpired` to those stores and a periodic sweeper. |
| Multi-instance deployments | Login throttling is in-process; move counters to the store or a shared cache. |
| Large tenants | CORS origin checks list all clients per cross-origin request; index origins. |
| Hosted login (spec §7) | Template override directory; bcrypt hash verification and upgrade for imported users. |
| Refresh tokens (milestone 5) | On authorization-code replay, revoke refresh tokens issued from that code. |
```

- [ ] **Step 8: Run everything**

Run: `go test -race ./... && go vet ./... && test -z "$(gofmt -l .)" && make e2e && ./scripts/check-sources.sh api/authentication.yaml`
Expected: all Go packages `ok`; `e2e m3 client credentials: OK`; Playwright `1 passed`; every source `ok:`.

- [ ] **Step 9: Commit**

```bash
git add tests/e2e Makefile .github/workflows/ci.yml .gitignore README.md docs
git commit -m "test(e2e): verify auth0-spa-js login against zeroauthy; update docs"
```

---

## Plan Self-Review (completed by the planner)

**Spec coverage (milestone 4, plus the pulled-forward items):**

| Spec requirement | Task |
|---|---|
| §4 data model: Connection, User/Identity, LoginSession, AuthorizationCode (hashed), login transaction | 2, 3 |
| §6.2 `/authorize`: parameters, validation order, error page vs redirect, PKCE S256, `prompt`, `max_age`, `connection`, `screen_hint`, `login_hint`, `organization` rejection, default audience | 9, 10 |
| §6.2 response modes query/fragment/form_post/web_message (web_message pulled from milestone 5) | 7, 10 |
| §6.3 `authorization_code` grant, PKCE for public clients, code single-use | 12 |
| §6.4 ID token claims, `at_hash`, lifetimes; user-flow access token audiences | 6, 12 |
| §6.1 `/userinfo` | 13 |
| §7 hosted pages, branding, login transaction, CSRF, CSP nonce, frame-ancestors, session cookie flags and timeouts, brute-force protection, password policy | 4, 5, 7, 8, 11 |
| §6.4 CORS from client config (pulled forward) | 14 |
| §10 every new operation in the OpenAPI contract with `x-source` | 10, 12, 13, 14 |
| §1.2 auth0-spa-js success criterion (login, silent auth) | 15 |
| Plan 1 prerequisites: argon2 bounds, `/docs` SRI + CSP, empty-audience guard | 1 |

Deferred and recorded in Task 15's follow-ups: the template override directory, bcrypt import, purging expired records, and shared throttling. Deferred by spec order: logout, refresh tokens, and implicit/hybrid flows (milestone 5).

**Type consistency check:**
- `authz.TxnCookiePrefix`, `authz.Handlers.Resume(w, r, res, txn, sess)` and `session.Manager.Start(ctx, w, r, t, userID, connection, authTime)` are used identically in Tasks 10, 11 and 14.
- `server.Deps` fields are added in Tasks 10 (`Sessions`) and 11 (`UserThrottle`, `IPThrottle`, `TrustProxyHeaders`), and all of them are set in Task 14's `newFlowEnv`.
- The generated method names `Authorize(w, r, params)`, `Userinfo` and `UserinfoPost` match a spike against oapi-codegen v2.8.0.
- `store.Users.FindByLogin(ctx, tenantID, connection, login)` is used by identity, seed, oauth tests and authz tests with the same argument order.

**Review Focus:**
1. `redirect_uri` lookalikes are covered by Task 9 `TestValidateErrors`.
2. Code misuse is covered by Task 12 `TestAuthorizationCodeMisuse`.
3. Login CSRF and transaction binding are covered by Task 11 `TestTransactionBinding`.
4. Email case and whitespace are covered by Task 4 `TestSignupThenLogin` and Task 11 `TestLoginSuccess`.
5. `prompt=none` without a session is covered by Task 10 `TestPromptNoneWithoutSession` and Task 14 `TestEndToEndCodeFlow` step 6.
