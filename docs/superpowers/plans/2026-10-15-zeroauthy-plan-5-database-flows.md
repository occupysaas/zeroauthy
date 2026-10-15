# zeroauthy Plan 5: Password Grants, /dbconnections, Email and Password Reset (Milestone 6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unmodified node-auth0 (`auth0/legacy` `AuthenticationClient`) can, against zeroauthy:
- sign users up;
- log them in with the `password` and `password-realm` grants;
- refresh their tokens;
- request password-reset emails.

People can also reset their password through hosted, localized pages.

**Architecture:**
- **Store:**
  - reset tickets;
  - atomic per-user revocation of sessions and refresh tokens;
  - extra user profile fields;
  - the tenant `default_directory` setting.
- **Email:** a new `internal/email` package with a `Mailer` interface and three drivers: `log`, `dir` and `smtp`. Emails are localized through `i18n`.
- **Grants:** two new grants in `internal/oauth`. They reuse `identity.Database.Login`, the shared login throttles, and the existing user-token minting.
- **API endpoints:** a new `internal/dbconn` package serves `/dbconnections/signup` and `/dbconnections/change_password`. It owns ticket creation and email sending.
- **Hosted pages:** the reset pages live in `internal/login`, built from the Auth0 `reset-password` prompt screens.

**Tech Stack:** Go 1.26+ (`net/smtp`, `mime`, `mime/quotedprintable`), plus the existing stack. E2E uses the existing `auth0` 7.4.0 (`auth0/legacy`), Playwright and auth0-spa-js.

**Spec:** `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md` (§6.1, §6.3, §7, §8, §9). The approved planning notes for this milestone are in `/home/thomas/.claude/plans/i-would-like-to-curious-whale.md`.

## Global Constraints

All earlier constraints still apply:
- **Clean room:** take identifiers and wire behaviour from public docs, write all wording ourselves, and never read SDK source.
- **Storage:** tenant-scoped, and drivers return copies.
- **Contract:** spec-first; every OpenAPI operation needs `x-source`.
- **Responses:** JSON errors; `no-store` on token responses.
- **Pages:** hosted pages use a nonce CSP, are localized via `i18n`, and English is the final fallback.
- **Build gates:** `go test -race ./...`, `go vet` and `gofmt` stay clean.
- **Data stores:** databases run only in containers (none are needed in this plan).

**Strict 1:1 parity with Auth0's public docs.** The user decided this on 2026-10-14; see memory `auth0-parity-first`. Where Auth0's docs specify behaviour, match it exactly:

- `POST /oauth/token`:
  - `grant_type=password`: parameters `username`, `password`, `client_id`, `client_secret`, `audience`, `scope`.
  - `grant_type=http://auth0.com/oauth/grant-type/password-realm`: the same parameters plus `realm` (a connection name).
  - The end-user IP header is `auth0-forwarded-for`.
- `POST /dbconnections/signup`:
  - **Body:** `client_id`, `email`, `password` (required), `connection` (required), `username`, `given_name`, `family_name`, `name`, `nickname`, `picture`, `user_metadata`.
  - **`user_metadata` limits:** at most 10 properties; names of at most 100 characters; values must be strings of at most 500 characters.
  - **200 response:** `_id`, `email_verified`, `email`, `username`, `given_name`, `family_name`, `name`, `nickname`, `picture`.
  - **Errors:** 400 (missing or invalid parameters) and 409 (user already exists).
- `POST /dbconnections/change_password`:
  - **Body:** `email` (required), `connection` (required), `client_id`.
  - **200:** a plain-text sentence.
  - **400:** bad request.
  - **404:** user not found.
  - *Superseded (user decision, 2026-10-15, final fix wave):* an unknown user now gets the same 200 and no email, following the `@auth0/auth0-auth-js` README ("never reveals whether the email matches an existing user") instead of the API reference's 404. See D-0018.
- The tenant setting is named `default_directory`.

Where Auth0's docs are silent, the behaviour is our decision and gets a compat decision record. Such decisions include:
- error body shapes on `/dbconnections`;
- ticket lifetime;
- the throttling details.

**Our own text:**
- The `change_password` success sentence is "A password reset link has been sent to the email address." It is our own wording.
- Error descriptions are our own wording.

**Reset tickets:**
- 43 random characters (`secrets.RandomString(43)`), stored only as `secrets.HashToken`.
- Single use.
- 24-hour lifetime.
- The link is `https://{host}/u/reset-password?ticket=<ticket>`.

**Password reset ends the user's existing sign-ins.** It deletes every session of the user and revokes every refresh token of the user. The user decided this on 2026-10-14.

**Throttling:**
- **Password grants:** use the same user and IP throttles as the hosted login. The keys are built by `identity.UserThrottleKey` and `identity.IPThrottleKey`.
- **Client IP:** comes from `auth0-forwarded-for` only when the client authenticated with a secret. Otherwise it is the request IP (rightmost `X-Forwarded-For` when proxy headers are trusted).
- **When throttled:** respond 429 `too_many_requests`.

**Email:**
- `email.driver` is one of `log` (the default), `dir` or `smtp`.
- `email.from` is a required address (default `zeroauthy@localhost`).
- `email.dir` is required for the `dir` driver.
- The `smtp` driver takes `email.smtp.host`, `port`, `username`, `password` and `insecure`. STARTTLS is required unless `insecure: true` is set.
- Header fields containing CR or LF are rejected.

**Hosted reset pages:**
- The keys use Auth0's documented `reset-password` prompt identifiers.
- The prompt `zeroauthy` holds keys for anything Auth0 has no counterpart for.
- Email text lives under `zeroauthy.email-reset-password.*`.

## Review Focus

1. **A reset ticket that is replayed, used twice concurrently, or expired.** It shows the error page and the password is unchanged. A used ticket never works twice. (Task 1 `ConcurrentConsume`, Task 6)
2. **Password-grant brute force.** It is throttled together with the hosted login. A public client that sends `auth0-forwarded-for` cannot dodge the IP limit. (Task 3)
3. **Email header injection.** A recipient or subject containing `\r\n` is rejected and nothing is sent. (Task 2)
4. **After a reset, the old session cookie and the old refresh token both stop working.** (Task 6)
5. **The hosted "Forgot password?" page gives the same answer for known and unknown emails.** (Task 6)

The API endpoint's 404 is Auth0's documented behaviour (Task 5).

## Out of Scope

- Email verification emails.
- Passwordless.
- MFA (`mfa_required`).
- Breached-password checks.
- The `resource` parameter.
- DPoP.
- The `organization` parameter on `change_password`.
- The Management API's password-change tickets.

## File Map

```
internal/store/{types.go,store.go}, internal/store/memory/{password_reset_tickets.go,users.go,sessions.go,refresh_tokens.go,clone.go,memory.go}
pkg/storetest/{password_reset_tickets.go,users.go,sessions.go,refresh_tokens.go,tenants.go,storetest.go}
internal/app/{sweeper.go,app.go}, internal/config/config.go
internal/seed/{seed.go,validate.go,apply.go}
internal/email/{email.go,message.go,log.go,dir.go,smtp.go,reset.go,templates/*}   new
internal/identity/{database.go,throttle.go}, internal/httpx/clientip.go (moved from internal/login/ip.go)
internal/oauth/{grant_password.go,token.go,user_tokens.go,handlers.go}
internal/dbconn/{dbconn.go,signup.go,change_password.go,reset.go}   new
internal/login/{reset.go,login.go}, internal/ui/{ui.go,templates/reset_*.html,templates/login.html}
internal/i18n/locales/en.json, internal/i18n/catalog_test.go, internal/i18n/keys.go
internal/server/{server.go,cors.go}, internal/oidc/handlers.go, api/authentication.yaml
tests/e2e/{config.yaml,seed.yaml,m3-db-flows.mjs,run-m3.sh,run-browser.sh,m7-reset.spec.mjs}
docs/compat/{decisions.md,matrix.md}, docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md (§6.1), docs/superpowers/plan-1-followups.md
```

---


### Task 1: Store — reset tickets, per-user revocation, profile fields, default directory

**Files:**
- Modify: `internal/store/types.go`, `internal/store/store.go`
- Modify: `internal/store/memory/{memory.go,users.go,sessions.go,refresh_tokens.go,clone.go}`
- Create: `internal/store/memory/password_reset_tickets.go`
- Modify: `pkg/storetest/{storetest.go,users.go,sessions.go,refresh_tokens.go,tenants.go}`
- Create: `pkg/storetest/password_reset_tickets.go`
- Modify: `internal/app/sweeper.go`, `internal/app/sweeper_test.go`
- Modify: `internal/seed/{seed.go,validate.go,apply.go,seed_test.go}`

**Interfaces (produced):**

```go
// types.go
Tenant.DefaultDirectory string            // connection used by the password grant
User.GivenName, User.FamilyName string
User.UserMetadata map[string]any
type PasswordResetTicket struct {
	TenantID, ID, TokenHash, UserID, Connection, ClientID string
	Lang      string // ui language chosen when the ticket was requested
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}
// store.go
Store.PasswordResetTickets() PasswordResetTickets
type PasswordResetTickets interface {
	Create(ctx, t *PasswordResetTicket) error                              // ErrConflict: ID or TokenHash exists
	GetByTokenHash(ctx, tenantID, tokenHash string) (*PasswordResetTicket, error)
	Consume(ctx, tenantID, tokenHash string, at time.Time) (*PasswordResetTicket, error) // ErrNotFound; ErrAlreadyUsed (with record)
	DeleteExpired(ctx, before time.Time) (int, error)
}
Users.SetPasswordHash(ctx, tenantID, userID, connection, hash string, at time.Time) error // ErrNotFound if user or identity absent; sets UpdatedAt
Sessions.DeleteByUser(ctx, tenantID, userID string) (int, error)
RefreshTokens.RevokeByUser(ctx, tenantID, userID string, at time.Time) (int, error) // unrevoked tokens only
```

- [ ] **Step 1: Write the failing conformance tests**

Create `pkg/storetest/password_reset_tickets.go`:

```go
package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newTicket(tenantID, id, hash string) *store.PasswordResetTicket {
	return &store.PasswordResetTicket{
		TenantID: tenantID, ID: id, TokenHash: hash, UserID: "auth0|u1", Connection: "Database",
		ClientID: "spa", Lang: "fr", ExpiresAt: ts(24 * time.Hour), CreatedAt: ts(0),
	}
}

func testPasswordResetTickets(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CreateGetConsume", func(t *testing.T) {
		s := open(t, newStore)
		want := newTicket("ten_a", "pr1", "h1")
		mustNoErr(t, s.PasswordResetTickets().Create(ctx, want))
		mustErrIs(t, s.PasswordResetTickets().Create(ctx, newTicket("ten_a", "pr1", "h2")), store.ErrConflict)
		mustErrIs(t, s.PasswordResetTickets().Create(ctx, newTicket("ten_a", "pr2", "h1")), store.ErrConflict)
		got, err := s.PasswordResetTickets().GetByTokenHash(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		_, err = s.PasswordResetTickets().GetByTokenHash(ctx, "ten_b", "h1")
		mustErrIs(t, err, store.ErrNotFound)

		used, err := s.PasswordResetTickets().Consume(ctx, "ten_a", "h1", ts(time.Minute))
		mustNoErr(t, err)
		mustEqual(t, used.UsedAt != nil && used.UsedAt.Equal(ts(time.Minute)), true)
		again, err := s.PasswordResetTickets().Consume(ctx, "ten_a", "h1", ts(2*time.Minute))
		mustErrIs(t, err, store.ErrAlreadyUsed)
		mustEqual(t, again.UsedAt.Equal(ts(time.Minute)), true)
		_, err = s.PasswordResetTickets().Consume(ctx, "ten_a", "nope", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.PasswordResetTickets().Consume(ctx, "ten_b", "h1", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("ConcurrentConsume", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PasswordResetTickets().Create(ctx, newTicket("ten_a", "pr1", "h1")))
		const n = 10
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.PasswordResetTickets().Consume(ctx, "ten_a", "h1", ts(time.Minute))
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrAlreadyUsed):
			default:
				t.Fatalf("unexpected %v", err)
			}
		}
		mustEqual(t, ok, 1)
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		for i, exp := range []time.Duration{time.Hour, 48 * time.Hour} {
			tk := newTicket("ten_a", fmt.Sprintf("pr%d", i), fmt.Sprintf("h%d", i))
			tk.ExpiresAt = ts(exp)
			mustNoErr(t, s.PasswordResetTickets().Create(ctx, tk))
		}
		n, err := s.PasswordResetTickets().DeleteExpired(ctx, ts(24*time.Hour))
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		_, err = s.PasswordResetTickets().GetByTokenHash(ctx, "ten_a", "h1")
		mustNoErr(t, err)
	})
}
```

Register it in `pkg/storetest/storetest.go` `Run`:

```go
	t.Run("PasswordResetTickets", func(t *testing.T) { testPasswordResetTickets(t, newStore) })
```

In `pkg/storetest/users.go`, add these to `newUser`:

```go
		GivenName: "Given " + id, FamilyName: "Family " + id,
		UserMetadata: map[string]any{"plan": "pro", "nested": map[string]any{"a": []any{"x"}}},
```

Also append these subtests to `testUsers`:

```go
	t.Run("MetadataIsCopied", func(t *testing.T) {
		s := open(t, newStore)
		in := newUser("ten_a", "u1", "alice@example.test", "alice")
		mustNoErr(t, s.Users().Create(ctx, in))
		in.UserMetadata["plan"] = "mutated"
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		got.UserMetadata["nested"].(map[string]any)["a"] = "mutated"
		again, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, again.UserMetadata, map[string]any{"plan": "pro", "nested": map[string]any{"a": []any{"x"}}})
	})

	t.Run("SetPasswordHash", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u1", "alice@example.test", "alice")))
		mustNoErr(t, s.Users().SetPasswordHash(ctx, "ten_a", "auth0|u1", "Database", "$argon2id$new", ts(time.Hour)))
		got, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, got.Identities[0].PasswordHash, "$argon2id$new")
		mustEqual(t, got.UpdatedAt, ts(time.Hour))
		mustErrIs(t, s.Users().SetPasswordHash(ctx, "ten_a", "auth0|u1", "Other", "x", ts(0)), store.ErrNotFound)
		mustErrIs(t, s.Users().SetPasswordHash(ctx, "ten_a", "auth0|nobody", "Database", "x", ts(0)), store.ErrNotFound)
		mustErrIs(t, s.Users().SetPasswordHash(ctx, "ten_b", "auth0|u1", "Database", "x", ts(0)), store.ErrNotFound)
	})
```

Append to `testSessions`:

```go
	t.Run("DeleteByUser", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_a", "s1", "h1")))  // auth0|u1
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_a", "s2", "h2")))  // auth0|u1
		other := newSession("ten_a", "s3", "h3")
		other.UserID = "auth0|u2"
		mustNoErr(t, s.Sessions().Create(ctx, other))
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_b", "s4", "h4"))) // same user ID, other tenant
		n, err := s.Sessions().DeleteByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", "h3")
		mustNoErr(t, err)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_b", "h4")
		mustNoErr(t, err)
	})
```

Append to `testRefreshTokens`:

```go
	t.Run("RevokeByUser", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "a", "ha", "f1"))) // auth0|u1
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "b", "hb", "f2"))) // auth0|u1
		other := newRefreshToken("ten_a", "c", "hc", "f3")
		other.UserID = "auth0|u2"
		mustNoErr(t, s.RefreshTokens().Create(ctx, other))
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_b", "d", "hd", "f4")))
		mustNoErr(t, s.RefreshTokens().RevokeFamily(ctx, "ten_a", "f2", ts(time.Minute))) // already revoked
		n, err := s.RefreshTokens().RevokeByUser(ctx, "ten_a", "auth0|u1", ts(time.Hour))
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		mustEqual(t, getRT(t, s, "ten_a", "ha").RevokedAt.Equal(ts(time.Hour)), true)
		mustEqual(t, getRT(t, s, "ten_a", "hb").RevokedAt.Equal(ts(time.Minute)), true) // first revocation kept
		mustEqual(t, getRT(t, s, "ten_a", "hc").RevokedAt == nil, true)
		mustEqual(t, getRT(t, s, "ten_b", "hd").RevokedAt == nil, true)
	})
```

In `pkg/storetest/tenants.go` `newTenant`, add `DefaultDirectory: "Database",`.

Run: `go test ./internal/store/memory/`
Expected: FAIL to compile.

- [ ] **Step 2: Types, interfaces and memory driver**

Add the fields and the type to `internal/store/types.go` exactly as listed under Interfaces. Give each a doc comment.

Add the methods to `store.go`. Each doc comment states the behaviour from the Interfaces block. `Consume` returns the record together with `ErrAlreadyUsed`, and keeps the first `UsedAt`.

Memory driver:
- `memory.go`: add the map field `resetTickets map[key]*store.PasswordResetTicket` (keyed by tenant and ID), initialize it in `New`, and add the accessor `PasswordResetTickets()`.
- `password_reset_tickets.go`: model it on `auth_codes.go`, but with ID keys plus a hash lookup, as `refresh_tokens.go` does with `findByHash`. Clone with `cloneResetTicket`, which deep-copies `UsedAt`.
- `users.go` `SetPasswordHash`: under the lock, find the user, then the identity whose `Connection` matches. If either is absent, return `ErrNotFound`. Otherwise set `PasswordHash` and `UpdatedAt`.
- `sessions.go` `DeleteByUser` and `refresh_tokens.go` `RevokeByUser`: under the lock, iterate the map and filter by tenant and user. `RevokeByUser` counts only tokens that were not already revoked.
- `clone.go` `cloneUser`: add `out.UserMetadata = cloneJSON(u.UserMetadata)` with:

```go
// cloneJSON deep-copies JSON-like values (maps, slices, scalars).
func cloneJSON(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneJSONValue(v)
	}
	return out
}

func cloneJSONValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneJSON(x)
	case []any:
		c := make([]any, len(x))
		for i, e := range x {
			c[i] = cloneJSONValue(e)
		}
		return c
	default:
		return x
	}
}
```

Sweeper (`internal/app/sweeper.go`): add `{st.PasswordResetTickets().DeleteExpired, now}` to `jobs`. In `sweeper_test.go`, create one expired ticket and one live ticket, and raise the expected count by 1.

Seed:
- `seed.go`: add `DefaultDirectory string yaml:"default_directory"` to `Tenant`.
- `validate.go`, after the connections loop: if `DefaultDirectory != ""` and `conns[t.DefaultDirectory] == nil`, fail with `default_directory %q is not a connection of this tenant`.
- `apply.go`: set `tn.DefaultDirectory = in.DefaultDirectory` in both branches.
- `seed_test.go`:
  - Add a `TestValidation` case `{"tenants: [{name: a, default_directory: Nope}]", "default_directory"}`.
  - Extend `TestApplyConnectionsAndUsers`'s sample (`sampleWithUsers`) with `default_directory: Username-Password-Authentication`, and assert that the field is applied.

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: PASS. Any other `store.Store` test double compiles, because the new methods are promoted from the embedded store.

- [ ] **Step 3: Commit**

```bash
git add internal pkg
git commit -m "feat(store): password reset tickets, per-user revocation, profile fields, default directory"
```

---

### Task 2: The `email` package — Mailer, log/dir/SMTP drivers, config

**Files:**
- Create: `internal/email/email.go`, `message.go`, `log.go`, `dir.go`, `smtp.go`, `email_test.go`
- Modify: `internal/config/config.go`, `internal/config/config_test.go`
- Modify: `internal/app/app.go` (build the mailer; it is passed to the server in Task 5)

**Interfaces (produced):**

```go
package email
type Message struct{ To, Subject, Text, HTML string }
type Mailer interface{ Send(ctx context.Context, m Message) error }
func New(cfg config.Email, log *slog.Logger) (Mailer, error)
var ErrHeaderInjection error
// config
type Email struct {
	Driver string `koanf:"driver"` // log (default) | dir | smtp
	From   string `koanf:"from"`   // default "zeroauthy@localhost"
	Dir    string `koanf:"dir"`
	SMTP   SMTP   `koanf:"smtp"`
}
type SMTP struct {
	Host     string `koanf:"host"`
	Port     int    `koanf:"port"` // default 587
	Username string `koanf:"username"`
	Password string `koanf:"password"`
	Insecure bool   `koanf:"insecure"` // allow plaintext (no STARTTLS); for local test servers only
}
```

- [ ] **Step 1: Config**

In `internal/config/config.go`:
- add `Email Email koanf:"email"` to `Config`;
- add the two types above;
- give `defaults()` `Email: Email{Driver: "log", From: "zeroauthy@localhost", SMTP: SMTP{Port: 587}}`.

In `validate()`, add:

```go
	switch c.Email.Driver {
	case "log":
	case "dir":
		if c.Email.Dir == "" {
			errs = append(errs, errors.New("email.dir is required with email.driver dir"))
		}
	case "smtp":
		if c.Email.SMTP.Host == "" || c.Email.SMTP.Port <= 0 || c.Email.SMTP.Port > 65535 {
			errs = append(errs, errors.New("email.smtp.host and a valid email.smtp.port are required with email.driver smtp"))
		}
	default:
		errs = append(errs, fmt.Errorf("email.driver %q must be log, dir or smtp", c.Email.Driver))
	}
	if a, err := mail.ParseAddress(c.Email.From); err != nil || strings.ContainsAny(c.Email.From, "\r\n") || a.Address == "" {
		errs = append(errs, fmt.Errorf("email.from %q is not a valid address", c.Email.From))
	}
```

In `config_test.go`, add the following cases in the file's existing style:
- the default driver is `log`;
- `ZEROAUTHY_EMAIL__DRIVER=dir` without a dir is rejected;
- `smtp` without a host is rejected;
- a bad driver is rejected;
- a `From` containing `\n` is rejected;
- `ZEROAUTHY_EMAIL__SMTP__PORT=2525` is accepted.

- [ ] **Step 2: Failing tests for the package**

Create `internal/email/email_test.go`:

```go
package email

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

var msg = Message{To: "alice@example.test", Subject: "Réinitialiser", Text: "Open https://a.test/u/reset-password?ticket=abc=def", HTML: "<p>Open</p>"}

func TestBuildIsWellFormed(t *testing.T) {
	raw, err := build("zeroauthy@localhost", msg, time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"From: zeroauthy@localhost\r\n", "To: alice@example.test\r\n", "MIME-Version: 1.0\r\n",
		"Subject: =?utf-8?q?R=C3=A9initialiser?=\r\n", "multipart/alternative", "text/plain; charset=utf-8", "text/html; charset=utf-8",
		"Content-Transfer-Encoding: quoted-printable"} {
		if !strings.Contains(s, want) {
			t.Errorf("message lacks %q:\n%s", want, s)
		}
	}
}

func TestHeaderInjectionRejected(t *testing.T) {
	for _, bad := range []Message{
		{To: "a@x.test\r\nBcc: evil@x.test", Subject: "s", Text: "t"},
		{To: "a@x.test", Subject: "s\nBcc: evil@x.test", Text: "t"},
		{To: "not an address", Subject: "s", Text: "t"},
	} {
		if _, err := build("zeroauthy@localhost", bad, time.Now()); !errors.Is(err, ErrHeaderInjection) {
			t.Errorf("build(%q) err = %v, want ErrHeaderInjection", bad.To+"|"+bad.Subject, err)
		}
	}
}

func TestDirMailer(t *testing.T) {
	dir := t.TempDir()
	m, err := New(config.Email{Driver: "dir", Dir: dir, From: "zeroauthy@localhost"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.eml"))
	if len(files) != 1 {
		t.Fatalf("files = %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if !strings.Contains(string(b), "To: alice@example.test") {
		t.Fatalf("eml = %s", b)
	}
}

// fakeSMTP is a minimal SMTP server; tls=false means it does not offer
// STARTTLS.
func fakeSMTP(t *testing.T, got chan<- string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r, w := bufio.NewReader(c), bufio.NewWriter(c)
		say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
		say("220 fake ESMTP")
		var data strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250-fake")
				say("250 8BITMIME")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"), strings.HasPrefix(cmd, "RSET"), strings.HasPrefix(cmd, "NOOP"):
				say("250 ok")
			case cmd == "DATA":
				say("354 go")
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					data.WriteString(l)
				}
				say("250 queued")
				got <- data.String()
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("502 no")
			}
		}
	}()
	return ln.Addr().String()
}

func TestSMTPInsecureSends(t *testing.T) {
	got := make(chan string, 1)
	host, port, _ := net.SplitHostPort(fakeSMTP(t, got))
	m, err := New(config.Email{Driver: "smtp", From: "zeroauthy@localhost",
		SMTP: config.SMTP{Host: host, Port: atoi(port), Insecure: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if body := <-got; !strings.Contains(body, "To: alice@example.test") {
		t.Fatalf("server received %q", body)
	}
}

func TestSMTPRequiresSTARTTLS(t *testing.T) {
	host, port, _ := net.SplitHostPort(fakeSMTP(t, make(chan string, 1)))
	m, _ := New(config.Email{Driver: "smtp", From: "zeroauthy@localhost", SMTP: config.SMTP{Host: host, Port: atoi(port)}}, nil)
	if err := m.Send(context.Background(), msg); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v, want STARTTLS required", err)
	}
}
```

Add a small `atoi` helper in the test file using `strconv.Atoi`.

Run: `go test ./internal/email/`
Expected: FAIL (package missing).

- [ ] **Step 3: Implement**

`internal/email/email.go`:

```go
// Package email sends zeroauthy's emails through a configurable driver:
// log (development), dir (writes .eml files; tests) or smtp.
package email

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

// Message is one email. Text is required; HTML is optional.
type Message struct{ To, Subject, Text, HTML string }

type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// ErrHeaderInjection is returned for a recipient or subject that is not a
// single plain address or contains line breaks.
var ErrHeaderInjection = errors.New("email: invalid recipient or subject")

// New builds the configured mailer. log may be nil.
func New(cfg config.Email, log *slog.Logger) (Mailer, error) {
	if log == nil {
		log = slog.Default()
	}
	switch cfg.Driver {
	case "", "log":
		return &logMailer{from: cfg.From, log: log}, nil
	case "dir":
		return &dirMailer{from: cfg.From, dir: cfg.Dir}, nil
	case "smtp":
		return &smtpMailer{from: cfg.From, cfg: cfg.SMTP}, nil
	}
	return nil, fmt.Errorf("email: unknown driver %q", cfg.Driver)
}
```

`message.go`:

```go
package email

import (
	"bytes"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
)

// build renders m as an RFC 5322 message with a multipart/alternative body.
func build(from string, m Message, now time.Time) ([]byte, error) {
	if strings.ContainsAny(m.To+m.Subject, "\r\n") {
		return nil, ErrHeaderInjection
	}
	if a, err := mail.ParseAddress(m.To); err != nil || a.Name != "" || a.Address != m.To {
		return nil, ErrHeaderInjection
	}
	boundary := "za-" + secrets.RandomString(24)
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@zeroauthy>\r\nMIME-Version: 1.0\r\n",
		from, m.To, mime.QEncoding.Encode("utf-8", m.Subject), now.UTC().Format(time.RFC1123Z), secrets.RandomString(24))
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
	part := func(ctype, body string) {
		fmt.Fprintf(&b, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", boundary, ctype)
		w := quotedprintable.NewWriter(&b)
		_, _ = w.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
		_ = w.Close()
		b.WriteString("\r\n")
	}
	part("text/plain", m.Text)
	if m.HTML != "" {
		part("text/html", m.HTML)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}
```

`log.go`: `logMailer.Send` validates the message with `build`, then logs at Info: `"email (log driver)", "to", m.To, "subject", m.Subject, "text", m.Text`. The log driver is for development only. Its doc comment warns that reset links appear in logs.

`dir.go`: `dirMailer.Send` builds the message, then writes it to `<dir>/<unixnano>-<random8>.eml` with mode 0600. It creates the directory with 0700 if needed. Write to a temp file first, then rename into place, so readers never see a partial file.

`smtp.go`:

```go
package email

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"strconv"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

type smtpMailer struct {
	from string
	cfg  config.SMTP
}

func (s *smtpMailer) Send(ctx context.Context, m Message) error {
	raw, err := build(s.from, m, time.Now())
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	} else if !s.cfg.Insecure {
		return errors.New("email: SMTP server does not offer STARTTLS (set email.smtp.insecure only for local test servers)")
	}
	if s.cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(s.from); err != nil {
		return err
	}
	if err := c.Rcpt(m.To); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
```

`net/smtp` `PlainAuth` refuses to send credentials over an unencrypted connection unless the server is localhost, so auth stays safe.

In `internal/app/app.go` `build`, call `mailer, err := email.New(cfg.Email, log)` and return the error if it fails. Keep the mailer in a local variable; Task 5 passes it to `server.Deps`. Until then, discard it with `_ = mailer` and a comment saying Task 5 wires it in.

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/email internal/config internal/app
git commit -m "feat(email): mailer with log, dir and SMTP drivers"
```

---

### Task 3: `password` and `password-realm` grants

**Files:**
- Create: `internal/httpx/clientip.go`. It is moved from `internal/login/ip.go`; delete the old file and update its callers.
- Modify: `internal/identity/throttle.go` (key helpers), `internal/login/login.go` (use the helpers)
- Create: `internal/oauth/grant_password.go`, `internal/oauth/grant_password_test.go`
- Modify: `internal/oauth/{token.go,user_tokens.go,handlers.go,errors.go,fixture_test.go}`
- Modify: `internal/server/server.go` (pass the Database and throttles to the oauth handlers)
- Modify: `internal/oidc/handlers.go`, `handlers_test.go` (discovery grant types)
- Modify: `api/authentication.yaml` (grant table, `TokenRequest.username/password/realm`, a `429` response)

**Interfaces (produced):**
- `httpx.ClientIP(r *http.Request, trustProxy bool) string`
- `identity.UserThrottleKey(tenantID, connection, login string) string` and `identity.IPThrottleKey(tenantID, ip string) string`
- `oauth.Handlers` gains `Database *identity.Database`, `UserThrottle`, `IPThrottle *identity.Throttle` and `TrustProxyHeaders bool`.
- `oauth.GrantPasswordRealm = "http://auth0.com/oauth/grant-type/password-realm"`
- `userTokens.grantType string`. Its value becomes the access token's `gty` claim.

- [ ] **Step 1: Shared helpers**

Move `clientIP` to `internal/httpx/clientip.go` as the exported `ClientIP`, keeping its doc comment. Add these to `internal/identity/throttle.go`:

```go
// UserThrottleKey and IPThrottleKey name throttle buckets. The hosted
// login and the password grants share them, so attempts through either
// count against the same limits.
func UserThrottleKey(tenantID, connection, login string) string {
	return "user|" + tenantID + "|" + connection + "|" + NormalizeLogin(login)
}

func IPThrottleKey(tenantID, ip string) string { return "ip|" + tenantID + "|" + ip }
```

Update `internal/login/login.go` to use both helpers and `httpx.ClientIP`. Run `go test ./internal/login/`; it must still pass.

- [ ] **Step 2: Fixture and failing tests**

Change `fixtureSeed` in `internal/oauth/fixture_test.go` as follows:
- Give the `acme` tenant `default_directory: Username-Password-Authentication`.
- Add these clients:

```yaml
      - client_id: ropg
        app_type: regular_web
        client_secret: ropg-secret
        grant_types: [password, "http://auth0.com/oauth/grant-type/password-realm", refresh_token]
      - client_id: ropg-public
        app_type: native
        grant_types: [password]
```

- Add both clients to the connection's `enabled_clients`.
- Add a second connection: `{name: Other-DB, enabled_clients: [ropg]}`. Its user is `{connection: Other-DB, email: bob@acme.test, password: "bob password 12"}`.
- Add a blocked user: `{connection: Username-Password-Authentication, email: carol@acme.test, password: "carol password 1", blocked: true}`.

In `newFixture`, give `Handlers` these fields:

```go
Database:     &identity.Database{Store: st, Now: fixedNow},
UserThrottle: identity.NewThrottle(3, 15*time.Minute, 15*time.Minute),
IPThrottle:   identity.NewThrottle(30, 15*time.Minute, 15*time.Minute),
```

Create `internal/oauth/grant_password_test.go`:

```go
package oauth

import (
	"net/url"
	"strings"
	"testing"
)

func pw(clientID, secret, username, password string, extra ...string) url.Values {
	v := url.Values{"grant_type": {"password"}, "client_id": {clientID}, "username": {username}, "password": {password}}
	if secret != "" {
		v.Set("client_secret", secret)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func TestPasswordGrant(t *testing.T) {
	f := newFixture(t)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test",
		form: pw("ropg", "ropg-secret", "Alice@Acme.test ", "alice password 1", "audience", "https://api.acme.test", "scope", "openid read:things offline_access")})
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	if at["gty"] != "password" || at["azp"] != "ropg" || !strings.HasPrefix(at["sub"].(string), "auth0|") {
		t.Fatalf("access token = %v", at)
	}
	idt, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["id_token"].(string))
	if idt["sid"] != nil || idt["auth_time"] != float64(fixedNow().Unix()) || idt["email"] != nil {
		t.Fatalf("id token = %v", idt)
	}
	if body["refresh_token"] == nil || body["scope"] != "openid read:things offline_access" {
		t.Fatalf("body = %v", body)
	}
}

func TestPasswordRealmGrant(t *testing.T) {
	f := newFixture(t)
	form := pw("ropg", "ropg-secret", "bob@acme.test", "bob password 12")
	form.Set("grant_type", GrantPasswordRealm)
	form.Set("realm", "Other-DB")
	if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form}); rec.Code != 200 {
		t.Fatalf("realm grant = %d %v", rec.Code, body)
	}
	// bob is not in the default directory.
	if rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "bob@acme.test", "bob password 12")}); rec.Code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("default directory = %d %v", rec.Code, body)
	}
}

func TestPasswordGrantRejects(t *testing.T) {
	realm := func(r string) url.Values {
		v := pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1")
		v.Set("grant_type", GrantPasswordRealm)
		if r != "" {
			v.Set("realm", r)
		}
		return v
	}
	cases := map[string]struct {
		form   url.Values
		status int
		code   string
	}{
		"wrong password":        {pw("ropg", "ropg-secret", "alice@acme.test", "nope"), 400, "invalid_grant"},
		"unknown user":          {pw("ropg", "ropg-secret", "nobody@acme.test", "nope"), 400, "invalid_grant"},
		"blocked user":          {pw("ropg", "ropg-secret", "carol@acme.test", "carol password 1"), 400, "invalid_grant"},
		"missing password":      {pw("ropg", "ropg-secret", "alice@acme.test", ""), 400, "invalid_request"},
		"missing realm":         {realm(""), 400, "invalid_request"},
		"unknown realm":         {realm("Nope"), 400, "invalid_request"},
		"grant not allowed":     {pw("code-web", "code-web-secret", "alice@acme.test", "alice password 1"), 403, "unauthorized_client"},
		"bad client secret":     {pw("ropg", "wrong", "alice@acme.test", "alice password 1"), 401, "invalid_client"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: tc.form})
			if rec.Code != tc.status || body["error"] != tc.code {
				t.Fatalf("got %d %v; want %d %s", rec.Code, body, tc.status, tc.code)
			}
		})
	}
	// The wording is the same for unknown users and wrong passwords.
	f := newFixture(t)
	_, a := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "nope")})
	_, b := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "nobody@acme.test", "nope")})
	if a["error_description"] != b["error_description"] {
		t.Fatalf("descriptions differ: %v / %v", a, b)
	}
}

func TestPasswordGrantThrottle(t *testing.T) {
	f := newFixture(t)
	for range 3 {
		f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "nope")})
	}
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1")})
	if rec.Code != 429 || body["error"] != "too_many_requests" {
		t.Fatalf("after 3 failures = %d %v", rec.Code, body)
	}
}

// A public client cannot pick its own throttling IP with auth0-forwarded-for.
func TestForwardedForOnlyForConfidentialClients(t *testing.T) {
	f := newFixture(t)
	f.h.IPThrottle = identity.NewThrottle(2, 15*time.Minute, 15*time.Minute)
	for i := range 2 {
		call := tokenCall{host: "acme.example.test", form: pw("ropg-public", "", "nobody@acme.test", "nope"),
			header: map[string]string{"auth0-forwarded-for": fmt.Sprintf("10.0.0.%d", i)}}
		f.call(t, false, call)
	}
	call := tokenCall{host: "acme.example.test", form: pw("ropg-public", "", "alice@acme.test", "alice password 1"),
		header: map[string]string{"auth0-forwarded-for": "10.9.9.9"}}
	if rec, body := f.call(t, false, call); rec.Code != 429 {
		t.Fatalf("public client escaped the IP limit: %d %v", rec.Code, body)
	}
	// A confidential client's auth0-forwarded-for is honoured: a fresh IP is not throttled.
	call = tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1"),
		header: map[string]string{"auth0-forwarded-for": "10.9.9.9"}}
	if rec, body := f.call(t, false, call); rec.Code != 200 {
		t.Fatalf("confidential client with forwarded IP = %d %v", rec.Code, body)
	}
}
```

Add the `"fmt"`, `"time"` and `identity` imports. Add a `header map[string]string` field to `tokenCall`, and set those headers on the request in `(*fixture).call`.

Run: `go test ./internal/oauth/ -run 'Password|Forwarded'`
Expected: FAIL (`unsupported_grant_type`).

- [ ] **Step 3: Implement**

In `internal/oauth/errors.go`, add:

```go
func tooManyRequests() *Error {
	return &Error{Status: http.StatusTooManyRequests, Code: "too_many_requests", Description: "too many attempts; wait a few minutes and try again"}
}
```

In `user_tokens.go`, add a `grantType string` field to `userTokens` and pass `GrantType: ut.grantType` in `mintUserTokens`'s `AccessTokenParams`.

In `token.go`:
- Register `"password": (*Handlers).passwordGrant` and `GrantPasswordRealm: (*Handlers).passwordRealmGrant`.
- Let grants see the end-user IP: after `authenticateClient` succeeds, set `ctx := withClientIP(r.Context(), h.endUserIP(r, client))` and pass `ctx` to the grant.

Create `internal/oauth/grant_password.go`:

```go
package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// GrantPasswordRealm is Auth0's documented extension grant for the
// resource owner password flow with an explicit connection (realm).
const GrantPasswordRealm = "http://auth0.com/oauth/grant-type/password-realm"

const wrongCredentials = "wrong email/username or password"

type clientIPKey struct{}

func withClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

func clientIPFrom(ctx context.Context) string { s, _ := ctx.Value(clientIPKey{}).(string); return s }

// endUserIP is the address used for throttling. auth0-forwarded-for lets a
// confidential server-side client pass its end user's IP; a public client
// could forge it, so for those the request's own address is used.
func (h *Handlers) endUserIP(r *http.Request, c *store.Client) string {
	if c.TokenEndpointAuthMethod != store.AuthMethodNone {
		if ip := strings.TrimSpace(r.Header.Get("auth0-forwarded-for")); ip != "" {
			return ip
		}
	}
	return httpx.ClientIP(r, h.TrustProxyHeaders)
}

// passwordGrant authenticates against the tenant's default directory
// (Auth0 "Default Directory").
func (h *Handlers) passwordGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	if res.Tenant.DefaultDirectory == "" {
		return nil, invalidRequest("the tenant has no default directory; use the password-realm grant with realm")
	}
	return h.resourceOwner(ctx, res, c, form, res.Tenant.DefaultDirectory)
}

func (h *Handlers) passwordRealmGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	realm := form.Get("realm")
	if realm == "" {
		return nil, invalidRequest("realm is required")
	}
	return h.resourceOwner(ctx, res, c, form, realm)
}

// resourceOwner implements RFC 6749 §4.3 against one database connection.
func (h *Handlers) resourceOwner(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values, connName string) (*authapi.TokenResponse, *Error) {
	tenantID := res.Tenant.ID
	username, password := form.Get("username"), form.Get("password")
	if username == "" || password == "" {
		return nil, invalidRequest("username and password are required")
	}
	conn, err := h.Store.Connections().GetByName(ctx, tenantID, connName)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (conn.Strategy != store.StrategyDatabase || !slices.Contains(conn.EnabledClients, c.ClientID))) {
		return nil, invalidRequest("the connection does not exist or is not enabled for this client")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load connection", "tenant", tenantID, "err", err)
		return nil, serverError()
	}

	userKey := identity.UserThrottleKey(tenantID, conn.Name, username)
	ipKey := identity.IPThrottleKey(tenantID, clientIPFrom(ctx))
	if !h.IPThrottle.Attempt(ipKey) || !h.UserThrottle.Attempt(userKey) {
		return nil, tooManyRequests()
	}
	user, err := h.Database.Login(ctx, conn, username, password)
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials):
		h.log().InfoContext(ctx, "password grant failed", "tenant", tenantID, "client_id", c.ClientID, "connection", conn.Name)
		return nil, invalidGrant(wrongCredentials)
	case errors.Is(err, identity.ErrUserBlocked):
		h.UserThrottle.Success(userKey)
		h.IPThrottle.Refund(ipKey)
		return nil, invalidGrant("the user is blocked")
	case err != nil:
		h.UserThrottle.Refund(userKey)
		h.IPThrottle.Refund(ipKey)
		h.log().ErrorContext(ctx, "password grant", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	h.UserThrottle.Success(userKey)
	h.IPThrottle.Refund(ipKey)
	now := h.now().UTC()
	if err := h.Store.Users().RecordLogin(ctx, tenantID, user.UserID, now); err != nil {
		h.log().WarnContext(ctx, "record login", "tenant", tenantID, "err", err)
	}

	aud := form.Get("audience")
	if aud == "" {
		aud = res.Tenant.DefaultAudience
	}
	if aud != "" {
		// Like client_credentials: an unknown API is access_denied, not a bad grant.
		if _, err := h.Store.ResourceServers().GetByIdentifier(ctx, tenantID, aud); errors.Is(err, store.ErrNotFound) {
			return nil, accessDenied("unknown audience")
		} else if err != nil {
			h.log().ErrorContext(ctx, "load resource server", "tenant", tenantID, "err", err)
			return nil, serverError()
		}
	}
	rs, lifetime, oerr := h.audienceFor(ctx, tenantID, aud)
	if oerr != nil {
		return nil, oerr
	}
	scopes := userScopes(strings.Fields(form.Get("scope")), rs, offlineAllowed(c, rs))
	resp, oerr := h.mintUserTokens(ctx, res, c, userTokens{
		user: user, rs: rs, lifetime: lifetime, scopes: scopes, authTime: now, grantType: "password",
	})
	if oerr != nil {
		return nil, oerr
	}
	if slices.Contains(scopes, "offline_access") {
		absolute, _ := refreshLifetimes(c.RefreshToken)
		var expiresAt time.Time
		if absolute > 0 {
			expiresAt = now.Add(absolute)
		}
		rt, raw := h.newRefreshToken(c, tenantID, refreshGrant{
			familyID: "rtf_" + secrets.RandomString(32), userID: user.UserID,
			audience: aud, scopes: scopes, authTime: now, expiresAt: expiresAt,
		})
		if err := h.Store.RefreshTokens().Create(ctx, rt); err != nil {
			h.log().ErrorContext(ctx, "store refresh token", "tenant", tenantID, "err", err)
			return nil, serverError()
		}
		resp.RefreshToken = &raw
	}
	return resp, nil
}
```

Add `"time"` to the imports.

The grant follows OIDC Core §5.4: it gives no `email` or `profile` claims unless those scopes are requested. Requesting `openid` alone yields an ID token with only the standard claims, which is what `TestPasswordGrant` asserts.

In `internal/server/server.go`, construct the oauth `Handlers` with `Database: &identity.Database{Store: d.Store}`, `UserThrottle: d.UserThrottle`, `IPThrottle: d.IPThrottle` and `TrustProxyHeaders: d.TrustProxyHeaders`. Use the **same** throttle instances as `login.Handlers`.

Discovery: `GrantTypesSupported` becomes `{"authorization_code", "client_credentials", "refresh_token", "password", "http://auth0.com/oauth/grant-type/password-realm"}`. Update `TestDiscovery` to match.

In `api/authentication.yaml` `/oauth/token`:
- Add table rows for `password` and `http://auth0.com/oauth/grant-type/password-realm`. Describe `realm`, the default directory, and `auth0-forwarded-for` (honoured only for confidential clients).
- Add `x-source: https://auth0.com/docs/api/authentication/resource-owner-password-flow/get-token`.
- Add `TokenRequest` properties `username`, `password` and `realm`.
- Add a `"429": $ref OAuthErrorResponse` response.
- Run `go generate ./...`.

- [ ] **Step 4: Run and commit**

Run: `go test -race ./... && go vet ./... && gofmt -l . && go generate ./... && git diff --exit-code internal/gen`
Expected: PASS.

Append a decision record to `docs/compat/decisions.md`:

```markdown
## D-0017: Resource owner password grants

- **Context:** Auth0 documents the `password` grant, the `http://auth0.com/oauth/grant-type/password-realm` extension (realm = connection) and the `auth0-forwarded-for` header, but not error codes beyond success.
- **Sources:** RFC 6749 §4.3 and §5.2; https://auth0.com/docs/api/authentication/resource-owner-password-flow/get-token; OAuth 2.0 Security BCP (RFC 9700) §2.4.
- **Decision:**
  - `password` uses the tenant's `default_directory`; without one it is `invalid_request`.
  - The connection must be a database connection enabled for the client.
  - Wrong credentials and unknown users give the same `invalid_grant`; a blocked user gives `invalid_grant`.
  - Attempts share the hosted login's per-user and per-IP throttles and return `429 too_many_requests` when locked.
  - `auth0-forwarded-for` is honoured only for clients that authenticated with a secret.
  - Access tokens carry `gty: "password"`. ID tokens have `auth_time` = now and no `sid` (no browser session).
  - Refresh tokens follow the `offline_access` rules of D-0012 and start a new family.
- **Rationale:** It follows the documented parameters and RFC 6749 errors. Sharing the throttles prevents the API from being used to bypass hosted-login brute-force protection.
```

```bash
git add internal api docs/compat/decisions.md
git commit -m "feat(oauth): password and password-realm grants"
```

---

### Task 4: `POST /dbconnections/signup`

**Files:**
- Modify: `internal/identity/database.go` (`Signup` takes a `SignupInput`), `internal/login/login.go` (caller)
- Create: `internal/dbconn/dbconn.go`, `internal/dbconn/signup.go`, `internal/dbconn/signup_test.go`
- Modify: `api/authentication.yaml` (operation `dbconnectionsSignup`, schemas), regenerate
- Modify: `internal/server/server.go` (forwarder, `Deps` unchanged), `internal/server/cors.go` (add `/dbconnections/signup` and `/dbconnections/change_password` to the CORS paths, with preflight routes)

**Interfaces (produced):**

```go
// identity
type SignupInput struct {
	Email, Username, Password             string
	GivenName, FamilyName, Name, Nickname string
	Picture                               string
	UserMetadata                          map[string]any
}
func (d *Database) Signup(ctx context.Context, conn *store.Connection, in SignupInput) (*store.User, error)

// dbconn
type Handlers struct {
	Store             store.Store
	Database          *identity.Database
	Mailer            email.Mailer     // Task 5
	IPThrottle        *identity.Throttle
	SendThrottle      *identity.Throttle // Task 5: per-email reset sends
	TrustProxyHeaders bool
	Log               *slog.Logger
	Now               func() time.Time
	Go                func(func())     // Task 5: runs email sending; nil = go statement
}
func (h *Handlers) Signup(w http.ResponseWriter, r *http.Request)
```

- [ ] **Step 1: Extend `identity.Signup`**

Change the signature to `Signup(ctx, conn, in SignupInput)`. It keeps the existing validation, and also does the following:
- **Profile fields:** `Name` defaults to the email, and `Nickname` defaults to the part before `@`. `GivenName`, `FamilyName` and `Picture` are copied.
- **`Picture`:** if set, it must be an absolute `https` URL of at most 2000 characters. Otherwise return `&PolicyError{Reason: "picture must be an https URL"}`.
- **Length limits:** each of the name fields may be at most 300 characters. Otherwise return a `PolicyError`.
- **Metadata:** `UserMetadata` is stored as given. The handler validates its shape.

Update the hosted signup caller in `internal/login/login.go` to pass `identity.SignupInput{Email: email, Username: username, Password: ...}`. Add identity unit tests for the new defaults and the `Picture` rule, in `database_test.go` style.

- [ ] **Step 2: Failing handler tests**

Create `internal/dbconn/signup_test.go`. It has its own seed: a tenant `acme` with these resources:
- clients `app` (spa) and `other` (spa);
- connection `Username-Password-Authentication`, enabled for `app`;
- connection `Closed`, enabled for `app`, with `disable_signup: true`;
- connection `Not-Enabled`, enabled for `other`.

Also add an `env` helper that serves `POST /dbconnections/signup` behind `tenant.NewResolver` and `contract.Wrap`, and a `post(t, path, contentType, body string) (int, map[string]any, string)` helper.

```go
func TestSignupJSON(t *testing.T) {
	e := newEnv(t)
	code, body, _ := e.post(t, "/dbconnections/signup", "application/json", `{
		"client_id":"app","connection":"Username-Password-Authentication","email":"New@Acme.test","password":"a good password 1",
		"given_name":"Ada","family_name":"Lovelace","user_metadata":{"plan":"pro"}}`)
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	id, _ := body["_id"].(string)
	if id == "" || strings.Contains(id, "|") || body["email"] != "new@acme.test" || body["email_verified"] != false ||
		body["given_name"] != "Ada" || body["family_name"] != "Lovelace" {
		t.Fatalf("body = %v", body)
	}
	u, err := e.st.Users().Get(context.Background(), e.tenantID, "auth0|"+id)
	if err != nil || u.UserMetadata["plan"] != "pro" {
		t.Fatalf("stored user = %+v, %v", u, err)
	}
}

func TestSignupForm(t *testing.T) {
	e := newEnv(t)
	form := url.Values{"client_id": {"app"}, "connection": {"Username-Password-Authentication"}, "email": {"f@acme.test"}, "password": {"a good password 1"}}
	if code, body, _ := e.post(t, "/dbconnections/signup", "application/x-www-form-urlencoded", form.Encode()); code != 200 {
		t.Fatalf("form signup = %d %v", code, body)
	}
}

func TestSignupErrors(t *testing.T) {
	ok := `"client_id":"app","connection":"Username-Password-Authentication","email":"x@acme.test","password":"a good password 1"`
	cases := map[string]struct {
		body   string
		status int
		code   string
	}{
		"missing password":       {`{"client_id":"app","connection":"Username-Password-Authentication","email":"x@acme.test"}`, 400, "invalid_request"},
		"missing connection":     {`{"client_id":"app","email":"x@acme.test","password":"a good password 1"}`, 400, "invalid_request"},
		"missing client_id":      {`{"connection":"Username-Password-Authentication","email":"x@acme.test","password":"a good password 1"}`, 400, "invalid_request"},
		"unknown client":         {`{"client_id":"nope","connection":"Username-Password-Authentication","email":"x@acme.test","password":"a good password 1"}`, 400, "invalid_request"},
		"connection not enabled": {`{"client_id":"app","connection":"Not-Enabled","email":"x@acme.test","password":"a good password 1"}`, 400, "invalid_signup"},
		"signup disabled":        {`{"client_id":"app","connection":"Closed","email":"x@acme.test","password":"a good password 1"}`, 400, "invalid_signup"},
		"weak password":          {`{"client_id":"app","connection":"Username-Password-Authentication","email":"x@acme.test","password":"short"}`, 400, "invalid_password"},
		"bad email":              {`{"client_id":"app","connection":"Username-Password-Authentication","email":"nope","password":"a good password 1"}`, 400, "invalid_signup"},
		"metadata not string":    {`{` + ok + `,"user_metadata":{"n":1}}`, 400, "invalid_request"},
		"metadata too many":      {`{` + ok + `,"user_metadata":{"a":"1","b":"1","c":"1","d":"1","e":"1","f":"1","g":"1","h":"1","i":"1","j":"1","k":"1"}}`, 400, "invalid_request"},
		"metadata value too long": {`{` + ok + `,"user_metadata":{"a":"` + strings.Repeat("x", 501) + `"}}`, 400, "invalid_request"},
		"malformed json":         {`{`, 400, "invalid_request"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			code, body, _ := e.post(t, "/dbconnections/signup", "application/json", tc.body)
			if code != tc.status || body["error"] != tc.code || body["error_description"] == "" {
				t.Fatalf("got %d %v; want %d %s", code, body, tc.status, tc.code)
			}
		})
	}
}

func TestSignupConflict(t *testing.T) {
	e := newEnv(t)
	b := `{"client_id":"app","connection":"Username-Password-Authentication","email":"dup@acme.test","password":"a good password 1"}`
	e.post(t, "/dbconnections/signup", "application/json", b)
	if code, body, _ := e.post(t, "/dbconnections/signup", "application/json", b); code != 409 || body["error"] != "user_exists" {
		t.Fatalf("duplicate = %d %v", code, body)
	}
}

func TestSignupIPThrottle(t *testing.T) {
	e := newEnv(t)
	e.h.IPThrottle = identity.NewThrottle(1, time.Hour, time.Hour)
	b := func(n int) string {
		return fmt.Sprintf(`{"client_id":"app","connection":"Username-Password-Authentication","email":"t%d@acme.test","password":"a good password 1"}`, n)
	}
	e.post(t, "/dbconnections/signup", "application/json", b(1))
	if code, body, _ := e.post(t, "/dbconnections/signup", "application/json", b(2)); code != 429 || body["error"] != "too_many_requests" {
		t.Fatalf("second signup = %d %v", code, body)
	}
}
```

Run: `go test ./internal/dbconn/`
Expected: FAIL.

- [ ] **Step 3: Implement**

`internal/dbconn/dbconn.go`:
- Package doc: "serves the Authentication API's database-connection endpoints (`/dbconnections/*`)".
- The `Handlers` struct.
- The `now` and `log` helpers.
- `writeErr(w, status, code, desc)`, using `httpx.WriteError`.
- `parseBody(w, r) (map[string]any, bool)`, which accepts:
  - `application/json`: one object, at most 64 KiB, nothing after it;
  - `application/x-www-form-urlencoded`: each value is a string, and repeated keys are rejected.

  It writes a 400 `invalid_request` and returns false on any problem.

`internal/dbconn/signup.go`:

```go
// Signup implements POST /dbconnections/signup (D-0018).
func (h *Handlers) Signup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	body, ok := parseBody(w, r)
	if !ok {
		return
	}
	str := func(k string) (string, bool) {
		v, present := body[k]
		if !present || v == nil {
			return "", true
		}
		s, isStr := v.(string)
		return s, isStr
	}
	fields := map[string]string{}
	for _, k := range []string{"client_id", "connection", "email", "password", "username", "given_name", "family_name", "name", "nickname", "picture"} {
		s, ok := str(k)
		if !ok {
			writeErr(w, http.StatusBadRequest, "invalid_request", k+" must be a string")
			return
		}
		fields[k] = s
	}
	for _, k := range []string{"client_id", "connection", "password"} {
		if fields[k] == "" {
			writeErr(w, http.StatusBadRequest, "invalid_request", k+" is required")
			return
		}
	}
	meta, err := userMetadata(body["user_metadata"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tenantID := res.Tenant.ID
	if !h.IPThrottle.Attempt(identity.IPThrottleKey(tenantID, httpx.ClientIP(r, h.TrustProxyHeaders))) {
		writeErr(w, http.StatusTooManyRequests, "too_many_requests", "too many sign-ups from this address; try again later")
		return
	}
	if _, err := h.Store.Clients().Get(ctx, tenantID, fields["client_id"]); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusBadRequest, "invalid_request", "unknown client")
		return
	} else if err != nil {
		h.internal(w, r, "load client", err)
		return
	}
	conn, err := h.Store.Connections().GetByName(ctx, tenantID, fields["connection"])
	if errors.Is(err, store.ErrNotFound) || (err == nil && (conn.Strategy != store.StrategyDatabase || !slices.Contains(conn.EnabledClients, fields["client_id"]))) {
		writeErr(w, http.StatusBadRequest, "invalid_signup", "the connection does not exist or is not enabled for this application")
		return
	} else if err != nil {
		h.internal(w, r, "load connection", err)
		return
	}
	user, err := h.Database.Signup(ctx, conn, identity.SignupInput{
		Email: fields["email"], Username: fields["username"], Password: fields["password"],
		GivenName: fields["given_name"], FamilyName: fields["family_name"], Name: fields["name"],
		Nickname: fields["nickname"], Picture: fields["picture"], UserMetadata: meta,
	})
	var pe *identity.PolicyError
	switch {
	case errors.Is(err, identity.ErrSignupDisabled):
		writeErr(w, http.StatusBadRequest, "invalid_signup", "sign-up is disabled for this connection")
		return
	case errors.Is(err, identity.ErrUserExists):
		writeErr(w, http.StatusConflict, "user_exists", "the user already exists")
		return
	case errors.As(err, &pe) && pe.Key != "" && strings.HasPrefix(pe.Key, "zeroauthy.signup.password"):
		writeErr(w, http.StatusBadRequest, "invalid_password", pe.Reason)
		return
	case errors.As(err, &pe):
		writeErr(w, http.StatusBadRequest, "invalid_signup", pe.Reason)
		return
	case err != nil:
		h.internal(w, r, "sign up", err)
		return
	}
	out := map[string]any{"_id": strings.TrimPrefix(user.UserID, store.StrategyDatabase+"|"), "email_verified": user.EmailVerified, "email": user.Email}
	for k, v := range map[string]string{"username": user.Username, "given_name": user.GivenName, "family_name": user.FamilyName,
		"name": user.Name, "nickname": user.Nickname, "picture": user.Picture} {
		if v != "" {
			out[k] = v
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// userMetadata enforces Auth0's documented signup limits: at most ten
// properties, names up to 100 characters, string values up to 500.
func userMetadata(v any) (map[string]any, error) {
	if v == nil {
		return nil, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("user_metadata must be an object")
	}
	if len(m) > 10 {
		return nil, errors.New("user_metadata may have at most 10 properties")
	}
	for k, val := range m {
		s, ok := val.(string)
		if !ok || utf8.RuneCountInString(k) > 100 || utf8.RuneCountInString(s) > 500 {
			return nil, fmt.Errorf("user_metadata.%s must be a string of at most 500 characters with a name of at most 100", k)
		}
	}
	return m, nil
}
```

`h.internal` logs the error and writes a 500 `server_error`. Form bodies cannot carry `user_metadata` objects. That is acceptable, because Auth0 documents `user_metadata` as an object.

In `api/authentication.yaml`, add `/dbconnections/signup`:
- **Request:** `post` with `operationId: dbconnectionsSignup`, tag `Users`. Request bodies in JSON and form, using the `SignupRequest` schema with the documented fields.
- **Responses:**
  - `200`: `SignupResponse`, with `_id`, `email_verified`, `email` and the optional profile fields.
  - `400`, `409` and `429`: all `OAuthErrorResponse`.
  - `404` (UnknownTenant) and `default`.
- **`x-source`:** `https://auth0.com/docs/api/authentication/signup/create-a-new-user`.

Then:
- Run `go generate ./...`.
- Add the forwarder `func (a authAPI) DbconnectionsSignup(w, r) { a.dbconn.Signup(w, r) }`.
- Add `dbconn *dbconn.Handlers` to `authAPI`, constructed in `New` with the store, a `Database`, the shared `IPThrottle` and `TrustProxyHeaders`.
- Add the CORS paths and preflight routes.

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: PASS.

- [ ] **Step 4: Decision and commit**

Append to `docs/compat/decisions.md`:

```markdown
## D-0018: /dbconnections endpoints

- **Context:** Auth0 documents the request and success fields and the status codes of `/dbconnections/signup` (200, 400, 409) and `/dbconnections/change_password` (200 plain text, 400, 404). It does not document error bodies.
- **Sources:** https://auth0.com/docs/api/authentication/signup/create-a-new-user; https://auth0.com/docs/api/authentication/change-password/change-password.
- **Decision:**
  - **Error bodies:** they use zeroauthy's JSON error shape `{error, error_description}`:
    - `invalid_request`: missing or malformed parameters, or an unknown client;
    - `invalid_signup`: the connection is not enabled for the client, sign-up is disabled, or the profile is invalid;
    - `invalid_password`: the password policy is not met;
    - `user_exists` (409);
    - `too_many_requests` (429).
  - **`client_id` is required:** zeroauthy has no global client.
  - **Signup response:** `_id` is the user ID without the `auth0|` prefix.
  - **`change_password`:** it follows the documented status codes, including 404 for an unknown user (strict parity; the maintainer chose this over hiding which emails have accounts). Its 200 body is a plain-text sentence of our own wording. See D-0019 for reset tickets.
- **Rationale:** It follows every documented field and status. Undocumented error bodies use the shape all other zeroauthy endpoints use.
```

```bash
git add internal api docs/compat/decisions.md
git commit -m "feat(dbconn): POST /dbconnections/signup"
```

---

### Task 5: `POST /dbconnections/change_password`, reset tickets and the reset email

**Files:**
- Create: `internal/dbconn/change_password.go`, `internal/dbconn/reset.go`, `internal/dbconn/change_password_test.go`
- Create: `internal/email/reset.go`, `internal/email/templates/reset_password.txt`, `internal/email/templates/reset_password.html`, and tests in `internal/email/email_test.go`
- Modify: `internal/i18n/locales/en.json`, `internal/i18n/catalog_test.go` (also scan `../email/templates/*`)
- Modify: `internal/server/server.go` (`Deps.Mailer`; the dbconn `Mailer` and `SendThrottle`), `internal/app/app.go`
- Modify: `api/authentication.yaml` (operation `dbconnectionsChangePassword`), regenerate

**Interfaces (produced):**
- `const dbconn.TicketLifetime = 24 * time.Hour`
- `(*dbconn.Handlers).StartReset(ctx context.Context, res tenant.Resolved, conn *store.Connection, user *store.User, clientID, lang string) error`. It creates a ticket and sends the email synchronously. Callers run it through `h.Go`. Task 6 also uses it.
- `email.ResetPassword(l *i18n.Localizer, link string) Message`
- `server.Deps.Mailer email.Mailer`

- [ ] **Step 1: Catalog keys and email templates**

Add to `en.json` under `zeroauthy`:

```json
    "email-reset-password": {
      "subject": "Reset your ${companyName} password",
      "heading": "Reset your password",
      "body": "We received a request to reset the password for your ${companyName} account. The link below works once and expires in 24 hours. If you did not ask for this, you can ignore this email.",
      "button": "Choose a new password"
    }
```

The keys keep the usual three-part shape: `zeroauthy.email-reset-password.subject` and so on. The subject is rendered from Go code, so add `KeyEmailResetSubject = "zeroauthy.email-reset-password.subject"` to `internal/i18n/keys.go` for the catalog test.

Create `internal/email/templates/reset_password.txt`:

```
{{t .L "zeroauthy.email-reset-password.heading"}}

{{t .L "zeroauthy.email-reset-password.body"}}

{{.Link}}
```

Create `internal/email/templates/reset_password.html`. It is a small standalone HTML document with inline styles only:

```html
<!doctype html>
<html lang="{{.L.Lang}}" dir="{{.L.Dir}}"><body style="font-family:system-ui,sans-serif;color:#1f2933">
<h1 style="font-size:20px">{{t .L "zeroauthy.email-reset-password.heading"}}</h1>
<p>{{t .L "zeroauthy.email-reset-password.body"}}</p>
<p><a href="{{.Link}}" style="background:#3355cc;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none">{{t .L "zeroauthy.email-reset-password.button"}}</a></p>
</body></html>
```

`internal/email/reset.go` parses the text template with `text/template` and the HTML template with `html/template`, both using a `t` func of `(l *i18n.Localizer, key string, kv ...string) string`. It then returns:

```go
// ResetPassword renders the password-reset email in l's language.
func ResetPassword(l *i18n.Localizer, link string) Message
```

The `To` field is set by the caller. Test that the `${companyName}` substitution appears in the subject, and that the HTML escapes a hostile `companyName` (`<b>`).

Update `catalog_test.go` so its template glob also covers `../email/templates/*`. Keep its regex unchanged; `{{t .L "…"}}` already matches.

- [ ] **Step 2: Failing handler tests**

Create `internal/dbconn/change_password_test.go`. It reuses Task 4's env, with a recording mailer (`type recorder struct{ mu sync.Mutex; sent []email.Message }`), `h.Go = func(f func()) { f() }` so sends are synchronous, and a seeded user `alice@acme.test` plus a blocked user `carol@acme.test`.

```go
func TestChangePasswordSendsTicket(t *testing.T) {
	e := newEnv(t)
	code, _, text := e.post(t, "/dbconnections/change_password", "application/json",
		`{"client_id":"app","connection":"Username-Password-Authentication","email":"Alice@Acme.test"}`)
	if code != 200 || text == "" || strings.Contains(text, "{") {
		t.Fatalf("got %d %q", code, text)
	}
	if len(e.mail.sent) != 1 || e.mail.sent[0].To != "alice@acme.test" {
		t.Fatalf("sent = %+v", e.mail.sent)
	}
	link := regexp.MustCompile(`https://acme\.example\.test/u/reset-password\?ticket=([A-Za-z0-9]{43})`).FindStringSubmatch(e.mail.sent[0].Text)
	if link == nil {
		t.Fatalf("no reset link in %q", e.mail.sent[0].Text)
	}
	tk, err := e.st.PasswordResetTickets().GetByTokenHash(context.Background(), e.tenantID, secrets.HashToken(link[1]))
	if err != nil || tk.Connection != "Username-Password-Authentication" || tk.ClientID != "app" ||
		!tk.ExpiresAt.Equal(fixedNow().Add(TicketLifetime)) {
		t.Fatalf("ticket = %+v, %v", tk, err)
	}
}

func TestChangePasswordUnknownUserIs404(t *testing.T) {
	e := newEnv(t)
	code, body, _ := e.post(t, "/dbconnections/change_password", "application/json",
		`{"connection":"Username-Password-Authentication","email":"nobody@acme.test"}`)
	if code != 404 || body["error"] != "user_not_found" || len(e.mail.sent) != 0 {
		t.Fatalf("got %d %v, sent %d", code, body, len(e.mail.sent))
	}
}

func TestChangePasswordErrors(t *testing.T) {
	cases := map[string]struct {
		body   string
		status int
	}{
		"missing email":      {`{"connection":"Username-Password-Authentication"}`, 400},
		"missing connection": {`{"email":"alice@acme.test"}`, 400},
		"unknown connection": {`{"connection":"Nope","email":"alice@acme.test"}`, 400},
		"unknown client":     {`{"client_id":"nope","connection":"Username-Password-Authentication","email":"alice@acme.test"}`, 400},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			if code, body, _ := e.post(t, "/dbconnections/change_password", "application/json", tc.body); code != tc.status {
				t.Fatalf("got %d %v", code, body)
			}
		})
	}
}

func TestChangePasswordBlockedUserGetsNoEmail(t *testing.T) {
	e := newEnv(t)
	code, _, _ := e.post(t, "/dbconnections/change_password", "application/json",
		`{"connection":"Username-Password-Authentication","email":"carol@acme.test"}`)
	if code != 200 || len(e.mail.sent) != 0 {
		t.Fatalf("got %d, sent %d", code, len(e.mail.sent))
	}
}

func TestChangePasswordSendLimit(t *testing.T) {
	e := newEnv(t)
	e.h.SendThrottle = identity.NewThrottle(2, time.Hour, time.Hour)
	for range 3 {
		e.post(t, "/dbconnections/change_password", "application/json",
			`{"connection":"Username-Password-Authentication","email":"alice@acme.test"}`)
	}
	if len(e.mail.sent) != 2 {
		t.Fatalf("sent %d emails, want 2 (the third is silently skipped)", len(e.mail.sent))
	}
}
```

A blocked user still gets 200 with no email. Auth0 documents only "user not found" as a 404, so a blocked account is treated as existing.

Run: `go test ./internal/dbconn/ -run ChangePassword`
Expected: FAIL.

- [ ] **Step 3: Implement**

`internal/dbconn/reset.go`:

```go
// TicketLifetime is how long a password reset link works (D-0019).
const TicketLifetime = 24 * time.Hour

// StartReset creates a single-use ticket for user and emails the reset link.
func (h *Handlers) StartReset(ctx context.Context, res tenant.Resolved, conn *store.Connection, user *store.User, clientID, lang string) error {
	now := h.now().UTC()
	raw := secrets.RandomString(43)
	tk := &store.PasswordResetTicket{
		TenantID: res.Tenant.ID, ID: "prt_" + secrets.RandomString(24), TokenHash: secrets.HashToken(raw),
		UserID: user.UserID, Connection: conn.Name, ClientID: clientID, Lang: lang,
		ExpiresAt: now.Add(TicketLifetime), CreatedAt: now,
	}
	if err := h.Store.PasswordResetTickets().Create(ctx, tk); err != nil {
		return err
	}
	link := res.Issuer() + "u/reset-password?" + url.Values{"ticket": {raw}}.Encode()
	m := email.ResetPassword(i18n.New(res.Tenant, lang), link)
	m.To = user.Email
	return h.Mailer.Send(ctx, m)
}

func (h *Handlers) goRun(f func()) {
	if h.Go != nil {
		h.Go(f)
		return
	}
	go f()
}
```

`internal/dbconn/change_password.go` implements `ChangePassword(w, r)`:
1. Parse the body with `parseBody`. `email` and `connection` are required strings. `client_id` is optional, but if given it must exist; otherwise respond 400 `invalid_request`.
2. Apply the IP throttle: `IPThrottle.Attempt(IPThrottleKey(...))`. When it fails, respond 429.
3. Load the connection. It must exist and be a database connection; otherwise respond 400 `invalid_request` "unknown connection".
4. Look up the user with `Users().FindByLogin(ctx, tenantID, conn.Name, identity.NormalizeLogin(email))`.
   - On `ErrNotFound`, respond 404 with `{"error":"user_not_found","error_description":"the user does not exist"}`.
   - Any other error is a 500.
5. If the user is not blocked and `SendThrottle.Attempt("reset|"+tenantID+"|"+conn.Name+"|"+user.UserID)` succeeds, run the following through `h.goRun`. Use a detached `context.WithTimeout(context.Background(), 30*time.Second)`, because the request context ends with the response.
   - Call `StartReset` with `lang := i18n.Negotiate(res.Tenant, "", r.Header.Get("Accept-Language"))`.
   - Log any error at Error level. Never log the link.
6. Respond 200 with `Content-Type: text/plain; charset=utf-8` and the body `A password reset link has been sent to the email address.`

In `api/authentication.yaml`, add `/dbconnections/change_password`:
- `post` with `operationId: dbconnectionsChangePassword`.
- JSON and form request bodies with `email`, `connection`, `client_id`.
- Responses: `200` with `text/plain` (`{type: string}`); `400`, `404` and `429` as `OAuthErrorResponse`; `404` UnknownTenant is merged into the same `404` description; and `default`.
- `x-source` is the change-password doc URL.

Regenerate the code, then add the forwarder.

Wiring:
- Add `Mailer email.Mailer` to `server.Deps`.
- `internal/app/app.go` passes the mailer from Task 2 and removes the `_ = mailer`.
- The dbconn `Handlers` get `Mailer: d.Mailer` and `SendThrottle: identity.NewThrottle(3, time.Hour, time.Hour)`.
- In `internal/server/flow_test.go` and the other tests that build `server.Deps`, set `Mailer` to a no-op or recording mailer.

- [ ] **Step 4: Run and commit**

Run: `go test -race ./... && go vet ./... && gofmt -l . && go generate ./... && git diff --exit-code internal/gen`
Expected: PASS.

Append to `docs/compat/decisions.md`:

```markdown
## D-0019: Password reset tickets

- **Context:** Auth0 documents that `change_password` sends a reset email, and documents the hosted `reset-password` screens. It does not document ticket lifetime or what a reset does to existing sign-ins.
- **Sources:** https://auth0.com/docs/api/authentication/change-password/change-password; https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements (reset-password prompt); OWASP Forgot Password Cheat Sheet.
- **Decision:**
  - **Tickets:** 43 random characters, stored hashed, single use, valid for 24 hours. The link is `https://{tenant host}/u/reset-password?ticket=…`.
  - **Email:** it is sent in the background, so response time does not depend on mail delivery.
  - **Throttling:**
    - **Send limit:** at most 3 emails per user per hour. Extra requests still return 200 without sending.
    - **Request limit:** requests are limited per IP.
  - **Blocked users:** they get the 200 response but no email.
  - **Completing a reset:**
    - **Password:** sets a new argon2id hash.
    - **Other sign-ins:** deletes all of the user's sessions and revokes all of the user's refresh tokens. The maintainer chose this.
- **Rationale:** It follows the documented endpoint. Where the docs are silent, the choices follow OWASP guidance, so a reset locks out anyone holding an old session.
```

```bash
git add internal api docs/compat/decisions.md
git commit -m "feat(dbconn): change_password sends single-use reset links"
```

---

### Task 6: Hosted reset pages and "Forgot password?"

**Files:**
- Create: `internal/login/reset.go`, `internal/login/reset_test.go`
- Create: `internal/ui/templates/reset_request.html`, `reset_email_sent.html`, `reset_password.html`, `reset_success.html`, `reset_error.html`
- Modify: `internal/ui/ui.go` (page data and render functions), `internal/ui/templates/login.html` (the link), `internal/login/login.go` (`LoginData.ForgotURL`, `Handlers.Resets *dbconn.Handlers`)
- Modify: `internal/i18n/locales/en.json`, `internal/i18n/keys.go`
- Modify: `internal/server/server.go` (routes)

**Routes** (all tenant-scoped; the HTML pages use a nonce CSP):

| Method and path | Purpose |
|---|---|
| `GET /u/reset-password/request?state=<txn>` | Email form (screen `reset-password-request`). The language comes from the login transaction. |
| `POST /u/reset-password/request` | Validates `state` and CSRF using the login transaction (`postedFlow`). Calls `StartReset` through `h.Resets.goRun` only if the user exists and is not blocked, and subject to the send limit. **Always** renders the same `reset-password-email` screen. |
| `GET /u/reset-password?ticket=…` | Looks the ticket up without consuming it. If it is unknown, used or expired, renders the matching `reset-password-error` screen. Otherwise sets the `za_reset` cookie (a random CSRF value; `HttpOnly; Secure; SameSite=Strict; Path=/u/reset-password; Max-Age=900`) and renders the new-password form (screen `reset-password`). |
| `POST /u/reset-password` | Fields `ticket`, `csrf`, `password`, `password_confirm`. Steps, in order:<br>1. Constant-time CSRF check against `za_reset`.<br>2. Ticket lookup; on failure, the error screen.<br>3. The passwords must match (`password-mismatch`), then the connection's password policy is checked; either failure re-renders the form with the error **without** consuming the ticket.<br>4. `Consume`; `ErrAlreadyUsed` gives the "used" error screen, and expiry gives the "expired" screen.<br>5. Hash the password, `Users().SetPasswordHash`, `Sessions().DeleteByUser`, `RefreshTokens().RevokeByUser`.<br>6. Clear `za_reset` and the caller's `za_session` cookie (`session.Manager.End`), then render `reset-password-success`. |

The pages' language is the ticket's `Lang`, negotiated against the tenant's current enabled locales with `i18n.ForRequest(tenant, r, ticket.Lang)`.

**Catalog keys** (add to `en.json` under the Auth0 `reset-password` prompt, using the documented screen and key identifiers; the wording is our own):

```json
  "reset-password": {
    "reset-password-request": {
      "title": "Forgot your password?",
      "descriptionEmail": "Enter the email address of your ${companyName} account and we will send you a link to reset your password.",
      "emailPlaceholder": "Email",
      "buttonText": "Send reset link",
      "backToLoginLinkText": "Back to sign in"
    },
    "reset-password-email": {
      "title": "Check your email",
      "emailDescription": "If an account exists for that address, we have sent a link to reset its password. The link expires in 24 hours."
    },
    "reset-password": {
      "title": "Choose a new password",
      "description": "Enter a new password for your ${companyName} account.",
      "passwordPlaceholder": "New password",
      "reEnterpasswordPlaceholder": "Confirm new password",
      "buttonText": "Reset password",
      "password-mismatch": "The passwords do not match."
    },
    "reset-password-success": {
      "eventTitle": "Password changed",
      "description": "Your password has been changed. You can now sign in with your new password."
    },
    "reset-password-error": {
      "eventTitleExpired": "Link expired",
      "descriptionExpired": "This password reset link has expired. Request a new one.",
      "eventTitleUsed": "Link already used",
      "descriptionUsed": "This password reset link has already been used. Request a new one if you still need to.",
      "eventTitleGeneric": "Link not valid",
      "descriptionGeneric": "This password reset link is not valid. Request a new one."
    }
  }
```

Also add `"forgotPasswordText": "Forgot password?"` under `login.login`. That is Auth0's documented login-screen key. Add `KeyResetPasswordMismatch = "reset-password.reset-password.password-mismatch"` to `keys.go`. The policy-error messages reuse the existing `zeroauthy.signup.password-*` keys and the `signup.signup.password-policy-not-conformant` alias.

- [ ] **Step 1: Failing tests**

Create `internal/login/reset_test.go`. It reuses `newEnv`, extended so that the env has these pieces:
- `h.Resets`: a `dbconn.Handlers` with a recording mailer and synchronous `Go`.
- `GET/POST /u/reset-password/request` and `GET/POST /u/reset-password` registered on the mux.
- An `e.mail` recorder.

A helper `resetLink(t, e)` returns the ticket value from the most recent email.

```go
func TestForgotPasswordFlow(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	rec, state, csrf := b.begin(t, "ui_locales", "fr")
	if !strings.Contains(rec.Body.String(), "/u/reset-password/request?state=") {
		t.Fatal("login page lacks the forgot-password link")
	}
	// An unknown and a known address get the same page.
	unknown := b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"nobody@acme.test"}})
	known := b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"alice@acme.test"}})
	if unknown.Code != 200 || known.Code != 200 || stripNonce(unknown.Body.String()) != stripNonce(known.Body.String()) {
		t.Fatalf("responses differ: %d / %d", unknown.Code, known.Code)
	}
	if len(e.mail.sent) != 1 {
		t.Fatalf("sent %d emails, want 1", len(e.mail.sent))
	}
	ticket := resetLink(t, e)

	// The user also has a session and a refresh token that the reset must end.
	sessionCookie, rt := e.signedInElsewhere(t, "alice@acme.test")

	rec = b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || m == nil || !strings.Contains(rec.Body.String(), `lang="fr"`) {
		t.Fatalf("reset form = %d %s", rec.Code, rec.Body)
	}
	post := func(pw, confirm string) *httptest.ResponseRecorder {
		return b.do(t, "POST", "/u/reset-password", url.Values{"ticket": {ticket}, "csrf": {m[1]}, "password": {pw}, "password_confirm": {confirm}})
	}
	if rec := post("new password 123", "different 123"); rec.Code != 400 || !strings.Contains(rec.Body.String(), "do not match") {
		t.Fatalf("mismatch = %d", rec.Code)
	}
	if rec := post("short", "short"); rec.Code != 400 {
		t.Fatalf("weak password = %d", rec.Code)
	}
	if rec := post("new password 123", "new password 123"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Password changed") {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	// Logged out everywhere: the old session and refresh token are gone.
	if e.sessionAlive(t, sessionCookie) {
		t.Fatal("session survived the reset")
	}
	if got, _ := e.st.RefreshTokens().GetByTokenHash(context.Background(), mustTenant(t, e, "acme").ID, rt.TokenHash); got.RevokedAt == nil {
		t.Fatal("refresh token survived the reset")
	}
	// The ticket cannot be used again.
	if rec := post("another password 1", "another password 1"); rec.Code != 400 || !strings.Contains(rec.Body.String(), "already been used") {
		t.Fatalf("replay = %d %s", rec.Code, rec.Body)
	}
	// The new password works; the old one does not.
	u, err := e.h.Database.Login(context.Background(), e.conn(t), "alice@acme.test", "new password 123")
	if err != nil || u == nil {
		t.Fatalf("new password login: %v", err)
	}
}

func TestResetErrors(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	if rec := b.do(t, "GET", "/u/reset-password?ticket=nope", nil); rec.Code != 400 || !strings.Contains(rec.Body.String(), "not valid") {
		t.Fatalf("unknown ticket = %d", rec.Code)
	}
	ticket := e.issueTicket(t, "alice@acme.test", -time.Minute) // already expired
	if rec := b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil); rec.Code != 400 || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("expired ticket = %d", rec.Code)
	}
	live := e.issueTicket(t, "alice@acme.test", time.Hour)
	rec := b.do(t, "POST", "/u/reset-password", url.Values{"ticket": {live}, "csrf": {"forged"}, "password": {"new password 123"}, "password_confirm": {"new password 123"}})
	if rec.Code != 400 {
		t.Fatalf("forged csrf = %d", rec.Code)
	}
	if _, err := e.h.Database.Login(context.Background(), e.conn(t), "alice@acme.test", "alice password 1"); err != nil {
		t.Fatalf("password changed by a forged request: %v", err)
	}
}
```

Write the helpers in the test file:
- `stripNonce` removes `nonce="…"` and `'nonce-…'` values before comparing pages.
- `signedInElsewhere` starts a session with `e.h.Sessions.Start` and stores a refresh token for the user. It returns the cookie and the token record.
- `sessionAlive` uses `GetByTokenHash`.
- `issueTicket` creates a ticket directly in the store, with the given lifetime relative to `fixedNow`.
- `conn` loads the connection.

Run: `go test ./internal/login/ -run 'Forgot|Reset'`
Expected: FAIL.

- [ ] **Step 2: Implement**

`internal/ui/ui.go`:
- Add the page data types `ResetRequestData{State, CSRF, Email, LoginURL, RedirectURI string}`, `ResetFormData{Ticket, CSRF, Error string}`, and `ResetErrorData{Title, Description string}`.
- Add the render functions `RenderResetRequest`, `RenderResetEmailSent`, `RenderResetForm(w, status, t, d)`, `RenderResetSuccess` and `RenderResetError(w, status, t, d)`. Each parses `layout.html` with its own template, following the existing pages.
- The templates use `{{t .Tenant.L "reset-password.<screen>.<key>"}}` for every visible string. Model them on `login.html` and `signup.html`.
- The reset-password form posts to `/u/reset-password` with `form-action 'self'`, because the success page renders in place.
- The request form keeps the transaction's redirect origin in its form-action through `RedirectURI`, as the login page does.

`templates/login.html` gains this after the form:

```html
{{if .Data.ForgotURL}}<p class="alt"><a href="{{.Data.ForgotURL}}">{{t .Tenant.L "login.login.forgotPasswordText"}}</a></p>{{end}}
```

`internal/login/login.go`:
- `LoginData.ForgotURL` is `"/u/reset-password/request?" + url.Values{"state": {f.txn.ID}}.Encode()`. Set it when `h.Resets != nil`.
- Add the field `Resets *dbconn.Handlers`.

`internal/login/reset.go` implements the four handlers exactly as in the Routes table:
- It reuses `h.load` and `h.postedFlow` for the request page.
- It uses `subtle.ConstantTimeCompare` for the `za_reset` CSRF check.
- It uses `identity.CheckPassword(conn.PasswordPolicy, pw)` and `secrets.Hash` for the new password.
- The request handler looks up the user with `FindByLogin` on the transaction's connection (`f.conn`). If the user exists and is not blocked, and `h.Resets.SendThrottle` allows it, it calls `h.Resets.goRun` with a detached 30-second context to run `StartReset(…, f.txn.ClientID, i18n lang of f.view)`. In every case it renders the same "check your email" page.
- For status codes, the GET/POST error screens return 400 and the policy and mismatch re-renders return 400. Success returns 200.

In `internal/server/server.go`, register `GET/POST /u/reset-password/request` and `GET/POST /u/reset-password`. Pass `Resets: dbconnHandlers` to `login.Handlers`; this is the same instance the API uses, so the send throttle is shared.

- [ ] **Step 3: Run and commit**

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: PASS. The catalog test must pass, which proves every new key is used.

```bash
git add internal
git commit -m "feat(login): hosted password reset pages and forgot-password link"
```

---

### Task 7: E2E with node-auth0 and the browser, and docs

**Files:**
- Modify: `tests/e2e/config.yaml`, `tests/e2e/seed.yaml`, `tests/e2e/run-m3.sh`, `tests/e2e/run-browser.sh`
- Create: `tests/e2e/m3-db-flows.mjs`, `tests/e2e/m7-reset.spec.mjs`
- Modify: `docs/compat/matrix.md`, `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md` (§6.1 `change_password` row), `docs/superpowers/plan-1-followups.md`

- [ ] **Step 1: Configuration and seed**

Make the following changes:

- **`tests/e2e/config.yaml`:** add `email: {driver: dir, dir: /tmp/zeroauthy-e2e-mail}`.
- **Both runners** override the directory per run with `ZEROAUTHY_EMAIL__DIR="$work/mail"` and export `E2E_MAIL_DIR="$work/mail"` to the tests. Also add `$work/mail` to the container `-v` mounts in `run-browser.sh`.
- **`tests/e2e/seed.yaml`:**
  - set the tenant's `default_directory: Username-Password-Authentication`;
  - add a confidential client, and add `e2e-node` to the connection's `enabled_clients`:

```yaml
      - client_id: e2e-node
        name: E2E node-auth0
        app_type: regular_web
        client_secret: e2e-node-secret-not-for-production
        grant_types: [password, "http://auth0.com/oauth/grant-type/password-realm", refresh_token]
```

  - give the API `allow_offline_access: true`, unless it already has it.

- [ ] **Step 2: node-auth0 script**

Create `tests/e2e/m3-db-flows.mjs`. It is a black-box test: it uses only `auth0/legacy`'s documented `AuthenticationClient` API, as described in the node-auth0 README and API docs. Debug from the zeroauthy log, never from SDK source.

```js
// Black-box test (CLEAN_ROOM.md): node-auth0 AuthenticationClient against
// zeroauthy's database endpoints and password grants.
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { AuthenticationClient } from 'auth0/legacy';

const auth = new AuthenticationClient({
  domain: 'localhost:8443', clientId: 'e2e-node', clientSecret: 'e2e-node-secret-not-for-production',
});
const email = `node-${Date.now()}@e2e.local`;
const connection = 'Username-Password-Authentication';

// The calls below follow the documented AuthenticationClient API of the
// pinned auth0 7.4.0. If the response shape differs (for example a .data
// wrapper), adapt the property access only, based on the public docs.
const signedUp = await auth.database.signUp({ email, password: 'Node-Password-123', connection });
assert.ok(signedUp.data?._id ?? signedUp._id, 'signUp returns _id');

const tokens = await auth.oauth.passwordGrant({
  username: email, password: 'Node-Password-123', realm: connection,
  audience: 'https://api.e2e.local', scope: 'openid offline_access read:things',
});
const t1 = tokens.data ?? tokens;
assert.ok(t1.access_token && t1.refresh_token && t1.id_token, 'password-realm grant returns tokens');

const refreshed = await auth.oauth.refreshTokenGrant({ refresh_token: t1.refresh_token });
assert.ok((refreshed.data ?? refreshed).access_token, 'refresh works');

await auth.database.changePassword({ email, connection });
const files = (await readdir(process.env.E2E_MAIL_DIR)).filter((f) => f.endsWith('.eml'));
assert.ok(files.length >= 1, 'a reset email was written');

await assert.rejects(auth.database.changePassword({ email: 'nobody@e2e.local', connection }), 'unknown user is rejected (404)');
console.log('e2e m3 database flows: OK');
```

Add `node m3-db-flows.mjs` to `run-m3.sh` after the existing client-credentials script, with `E2E_MAIL_DIR` set.

`@auth0/auth0-auth-js` is also installed. If its public README documents a password or realm grant, call it the same way. If it does not, note in the report that this SDK does not support these flows ("as each SDK supports them", spec §1.2).

- [ ] **Step 3: Browser reset spec**

Create `tests/e2e/m7-reset.spec.mjs`:

```js
// Black-box test: the hosted forgot-password flow, reading the reset email
// written by zeroauthy's dir email driver.
import { test, expect } from '@playwright/test';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const SPA = 'https://localhost:3443/';

async function newestEmail(since) {
  const dir = process.env.E2E_MAIL_DIR;
  for (let i = 0; i < 50; i++) {
    const files = (await readdir(dir)).filter((f) => f.endsWith('.eml'));
    const fresh = [];
    for (const f of files) {
      const s = await stat(path.join(dir, f));
      if (s.mtimeMs >= since) fresh.push([s.mtimeMs, f]);
    }
    if (fresh.length) {
      fresh.sort((a, b) => b[0] - a[0]);
      return readFile(path.join(dir, fresh[0][1]), 'utf8');
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('no reset email arrived');
}

// decodeQP undoes quoted-printable encoding (soft breaks, =XX escapes).
const decodeQP = (s) => s.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

test('forgot password: email link, new password, sign in', async ({ page }) => {
  await page.goto(SPA);
  await expect(page.locator('body')).toHaveAttribute('data-ready', 'true', { timeout: 20_000 });
  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
  const since = Date.now() - 1000;
  await page.click('text=Forgot password?');
  await page.fill('#email', 'reset-me@e2e.local');
  await page.click('button[type=submit]');
  await expect(page.locator('h1')).toHaveText('Check your email');

  const mail = decodeQP(await newestEmail(since));
  const link = mail.match(/https:\/\/localhost:8443\/u\/reset-password\?ticket=[A-Za-z0-9]{43}/)[0];
  await page.goto(link);
  await page.fill('#password', 'Brand-New-Password-7');
  await page.fill('#password_confirm', 'Brand-New-Password-7');
  await page.click('button[type=submit]');
  await expect(page.locator('h1')).toHaveText('Password changed');

  await page.goto(SPA);
  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'reset-me@e2e.local');
  await page.fill('#password', 'Brand-New-Password-7');
  await page.click('button[type=submit]');
  await page.waitForURL(SPA);
});
```

The m4 spec and the other specs log in as `alice` with `Correct-Horse-Battery-9`. Changing her password would break any spec that runs after this one. So give this spec its own user: add `reset-me@e2e.local` (with password `Correct-Horse-Battery-9`) to `seed.yaml`, and use that address in place of `reset-me@e2e.local` in this spec. The reset page's inputs must use `id="password"` and `id="password_confirm"`, and the request form's input must use `id="email"`.

Run: `make e2e`
Expected: run-m3 prints both OK lines, and run-browser reports `6 passed`.

- [ ] **Step 4: Docs**

**`docs/compat/matrix.md`:** replace the milestone-6 "Planned" row with these rows:

```markdown
| `/oauth/token`: `password`, `http://auth0.com/oauth/grant-type/password-realm` | Implemented | Verified with node-auth0 `auth0/legacy` 7.4.0 (`passwordGrant` with realm) |
| `/dbconnections/signup` | Implemented | Verified with node-auth0 `auth0/legacy` 7.4.0 (`database.signUp`); undocumented error bodies use `{error, error_description}` (D-0018) |
| `/dbconnections/change_password` and hosted password reset (`/u/reset-password`) | Implemented | Verified with node-auth0 `auth0/legacy` 7.4.0 (`database.changePassword`) and in Chromium; 404 for unknown users as documented; reset ends all sessions and refresh tokens (D-0019) |
```

Adjust the wording to what the specs actually assert, as Plan 3 did.

**Spec §6.1:** change the `/dbconnections/change_password` row to: "Sends a reset email (single-use link, 24 h). Unknown users get 404, as Auth0 documents; the hosted 'Forgot password?' page always shows the same confirmation."

**`docs/superpowers/plan-1-followups.md`:** add a `## Plan 5 follow-ups` section listing:
- email verification emails;
- MFA (`mfa_required`);
- breached-password detection;
- the `organization` parameter on `change_password`;
- moving the send limit into the store, needed for multi-instance deployments.

- [ ] **Step 5: Verify and commit**

Run: `go test -race ./... && go vet ./... && gofmt -l . && make e2e`
Expected: everything passes.

```bash
git add tests/e2e docs
git commit -m "test(e2e): node-auth0 database flows and hosted password reset; docs"
```

---

## Plan Self-Review (completed by the planner)

**Spec coverage:** milestone 6 is covered:
- `password` and `password-realm`: Task 3.
- `/dbconnections/signup`: Task 4.
- `/dbconnections/change_password`: Task 5.
- Email: Tasks 2 and 5.
- Reset flow: Tasks 5 and 6.
- E2E with node-auth0: Task 7.
- Spec §8 (email config): Task 2.
- Spec §4 (user `given_name`, `family_name`, `user_metadata`): Task 1.

**Parity check against the docs fetched while planning:**
- Every documented parameter, response field and status code is listed under Global Constraints, and each one is used.
- `change_password` returns 404 per the docs. The user decided this.

**Rulings made while planning:**
1. `client_id` is required for signup, because there is no global client.
2. Signup with form bodies cannot carry `user_metadata`.
3. Blocked users get 200 from `change_password` but no email.
4. The email key screen is named `email-reset-password`, to keep three-part keys.
5. The reset spec uses its own user, so other specs keep their passwords.

**Type consistency:** these names are used identically across the tasks that reference them:
- `identity.UserThrottleKey`, `identity.IPThrottleKey`, `httpx.ClientIP` (Tasks 3, 4, 5 and 6);
- `dbconn.Handlers`, `StartReset`, `goRun` and `SendThrottle` (Tasks 4, 5 and 6);
- `store.PasswordResetTicket` (Tasks 1, 5 and 6);
- `email.Message` and `email.ResetPassword` (Tasks 2 and 5).

**Review Focus mapping:**
1. Task 1 `ConcurrentConsume`; Task 6 `TestForgotPasswordFlow` (replay) and `TestResetErrors`.
2. Task 3 `TestPasswordGrantThrottle` and `TestForwardedForOnlyForConfidentialClients`.
3. Task 2 `TestHeaderInjectionRejected`.
4. Task 6 `TestForgotPasswordFlow`: the session and refresh token are both gone after the reset.
5. Task 6 `TestForgotPasswordFlow`: known and unknown emails get the same page.
