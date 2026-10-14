# zeroauthy Plan 3: Refresh Tokens, Revocation and Logout (Milestone 5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unmodified `@auth0/auth0-react` keeps a user signed in with rotating refresh tokens and logs out. Unmodified `@auth0/nextjs-auth0` logs in, holds a session, retrieves an access token and logs out. zeroauthy detects refresh-token reuse and revokes the whole token family.

**Architecture:** The plan adds these pieces:
- A `RefreshTokens` repository whose `Rotate` method is atomic. It implements rotation, the reuse interval (leeway) and family revocation inside the driver, as spec §5.1 requires.
- Per-client refresh-token policy and tenant-level allowed logout URLs, both seedable.
- In `oauth`:
  - the code grant issues refresh tokens for `offline_access`;
  - a new `refresh_token` grant;
  - `POST /oauth/revoke`.
- In `oidc`: `GET /v2/logout` and `GET|POST /oidc/logout` (RP-Initiated Logout), with a confirmation page when the request carries no matching hint.

Login-session writes become atomic store methods. A background sweeper purges expired transactions, sessions, codes and refresh tokens. Every new operation is described in `api/authentication.yaml` first and wired through the generated `ServerInterface`.

**Tech Stack:**
- Go 1.26+ on the Plan 1–2 stack: chi, oapi-codegen v2.8, kin-openapi v0.150, go-jose v4, koanf v2, `html/template`.
- E2E on Node 22+ adds `@auth0/auth0-react` 2.28.2, `react`/`react-dom` 19.3.0 and `esbuild` 0.28.2 (to bundle the React test app), plus `@auth0/nextjs-auth0` 4.32.0 with `next` 15.5.27.

**Spec:** `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md`. This plan covers spec §13 milestone 5. `web_message`/`prompt=none` was pulled into Plan 2 and is already done.

It also closes these items from `docs/superpowers/plan-1-followups.md`:
- expired-record purging, which is marked "Now";
- revoking refresh tokens on code replay;
- last-writer-wins session writes, which were to be revisited at the logout milestone;
- the two residual findings from the Plan 2 final review: an unparsable callback panics, and `form_post` with a private-use scheme fails.

## Global Constraints

All Plan 1 and Plan 2 constraints still apply:
- clean room (CLEAN_ROOM.md); SDKs are black-box test clients only, so never read SDK source to debug;
- spec-first contract with an `x-source` on every operation;
- issuer `https://{host}/`;
- tenant-scoped storage, and drivers return copies;
- JSON error shape, with `Cache-Control: no-store` on token responses;
- token secrets stored only as `secrets.HashToken` (SHA-256 hex);
- hosted pages are original `html/template` with nonce CSP;
- databases run only in containers, never on the host.

New constraints:

- **Refresh tokens:**
  - Opaque, 48 random characters (`secrets.RandomString(48)`), stored only as `secrets.HashToken`.
  - Issued from the code grant only when all of these hold:
    - `offline_access` was requested;
    - the client's `grant_types` include `refresh_token`;
    - either no API is the audience, or the API has `allow_offline_access: true`.
- **Refresh-token policy** (per client; Auth0 Management API field names):
  - `rotation_type` is `rotating` or `non-rotating`. The default is `rotating` for `spa` and `non-rotating` otherwise.
  - `expiration_type` is `expiring` or `non-expiring`. The default is `expiring` when rotating and `non-expiring` otherwise.
  - `leeway`: seconds, default 0.
  - `token_lifetime` (absolute): default **31557600** s.
  - `idle_token_lifetime`: default **2592000** s.
  - Rotation requires `expiring`. SPAs must use `expiring`. The idle lifetime must not exceed the absolute lifetime.
- **Rotation:**
  - Every exchange of a rotating token returns a new refresh token in the same family. The absolute expiry is inherited, and the idle expiry restarts.
  - Presenting an already-rotated token is reuse unless it falls within `leeway` of the first rotation. Reuse revokes every token in the family and returns `invalid_grant`.
  - With `leeway` 0, any second use is reuse.
- **Code replay:** a replayed authorization code revokes the refresh-token family started from that code. The family ID is derived from the code hash.
- **Refresh grant:**
  - `scope` may only narrow the token's scopes; anything else is `invalid_scope`.
  - An `audience` that differs from the token's is `invalid_request`.
  - Another client's token, a revoked or expired token, or a blocked or deleted user gives `invalid_grant`.
  - A token presented by another client is never revoked or rotated.
- **Revocation:** `POST /oauth/revoke` (RFC 7009).
  - Unknown tokens return `200`.
  - Another client's token returns `400 invalid_grant`.
  - A known token revokes its whole family.
  - Only refresh tokens can be revoked; JWT access tokens cannot be.
- **Logout:**
  - Requests are validated *before* the session ends. An invalid request shows the error page with 400, does not log out, and never redirects.
  - Ending a session deletes the server record and clears `za_session` (`Max-Age=-1`, same attributes as when set).
  - Logout does not revoke refresh tokens.
  - `/v2/logout`:
    - `returnTo` is compared without its query string and fragment, with scheme and host case-insensitive. It is checked against the client's `allowed_logout_urls` when `client_id` is present, otherwise the tenant's.
    - With `client_id` and no `returnTo`, the user is redirected to the client's first allowed logout URL. Otherwise the logged-out page is shown.
  - `/oidc/logout`:
    - `post_logout_redirect_uri` must match an allowed logout URL exactly, including any query string. The list is the client's when a client is known (from `id_token_hint` or `client_id`), otherwise the tenant's.
    - `state` is appended to the redirect.
    - `id_token_hint` is accepted even after it has expired.
    - A confirmation page is shown when the browser has a session and neither `id_token_hint`'s `sid` nor `logout_hint` matches it.
    - Hints that contradict each other are a 400 error.
- **Session writes:** `Sessions.Update` is replaced by atomic `Touch` (idle expiry) and `AddClient`.
- **Purging:**
  - Every 10 minutes, delete expired login transactions, sessions and refresh tokens.
  - Delete authorization codes 24 hours after they expire, so a late replay still revokes its family.

## Review Focus

1. **Refresh-token reuse:**
   - After a token is rotated, presenting it again (outside the leeway) must fail. Afterwards its successor must fail too.
   - Concurrent exchanges of one token with leeway 0 must not leave two live successors.
   - Tests: Task 2 (`ConcurrentRotate`), Task 5, Task 9.
2. **Cross-client token use:** a refresh token presented to `/oauth/token` or `/oauth/revoke` by a different client must fail and leave the token untouched. Tests: Task 5 and Task 6.
3. **Logout open redirect:** these `returnTo` / `post_logout_redirect_uri` values must give a 400 page with no `Location` header and the session still alive:
   - lookalikes (an extra path segment, `.evil.test` suffixes, the URL embedded in another URL's path);
   - another client's URL;
   - `javascript:` URIs;
   - a query-string mismatch on `/oidc/logout`.

   Tests: Task 7 and Task 8.
4. **Logout with no session**, an already-deleted session, or a session-store failure:
   - With no session or an already-deleted one: the normal redirect or page, the cookie cleared, and no 500.
   - With a store failure: a 500 HTML page, never a redirect.

   Tests: Task 7.
5. **Privilege change after issuance:** each of these must make the refresh grant refuse:
   - the user is blocked;
   - the API is deleted;
   - a scope the token never had is requested.

   Tests: Task 5.

## Out of Scope (later plans)

- Password and password-realm grants, `/dbconnections/*`, email, password reset (milestone 6)
- Back-channel and front-channel logout, `federated` IdP logout (accepted and ignored), per-tenant toggles for the logout confirmation page
- Revoking refresh tokens at logout, session-bound refresh tokens, multi-resource refresh tokens (MRRT)
- SQL drivers (milestone 7). The storetest additions here are what they must pass.

## File Map

```
internal/store/{store.go,types.go}            + RefreshTokens, RefreshToken, RefreshTokenPolicy; Sessions.Touch/AddClient (Update removed); DeleteExpired on Sessions/AuthTransactions/AuthCodes; Tenant.AllowedLogoutURLs; Client.RefreshToken
internal/store/memory/{memory.go,sessions.go,auth_transactions.go,auth_codes.go,refresh_tokens.go,clone.go}
pkg/storetest/{storetest.go,sessions.go,auth_transactions.go,auth_codes.go,refresh_tokens.go,tenants.go,clients.go}
internal/session/session.go                    Touch/AddClient, Lookup, End
internal/app/{app.go,sweeper.go}               expired-record sweeper
internal/seed/{seed.go,validate.go,apply.go}   refresh_token policy, tenant allowed_logout_urls, URL syntax checks
internal/authz/{validate.go}                   AllowedURL; unparsable callbacks; form_post needs http(s)
internal/oauth/{refresh.go,user_tokens.go,grant_authorization_code.go,grant_refresh_token.go,revoke.go,token.go}
internal/oidc/{handlers.go,logout.go}          discovery fields; /v2/logout; /oidc/logout
internal/ui/{ui.go,templates/logged_out.html,templates/logout_confirm.html}
internal/server/{server.go,cors.go,flow_test.go}
api/authentication.yaml, internal/gen/authapi/authapi.gen.go
tests/e2e/{package.json,seed.yaml,spa-server.mjs,playwright.config.mjs,run-browser.sh (was run-m4.sh),react/*,next-app/*,m5-react.spec.mjs,m5-nextjs.spec.mjs}
Makefile, .gitignore, docs/compat/{decisions.md,matrix.md}, docs/superpowers/plan-1-followups.md
```

---
### Task 1: Atomic session writes and expired-record purging

Session writes become atomic store operations, so a concurrent logout or a second tab cannot lose a write (a Plan 2 follow-up). Expired transactions, sessions and codes are purged by a background sweeper. Today an unauthenticated `GET /authorize` creates a transaction that is never removed.

**Files:**
- Modify: `internal/store/store.go` (Sessions, AuthTransactions, AuthCodes interfaces)
- Modify: `internal/store/memory/sessions.go`, `internal/store/memory/auth_transactions.go`, `internal/store/memory/auth_codes.go`
- Modify: `pkg/storetest/sessions.go`, `pkg/storetest/auth_transactions.go`, `pkg/storetest/auth_codes.go`
- Modify: `internal/session/session.go`, `internal/session/session_test.go`
- Create: `internal/app/sweeper.go`, `internal/app/sweeper_test.go`
- Modify: `internal/app/app.go` (start the sweeper in `Serve`)

**Interfaces:**
- Consumes: `store.Store`, `session.Manager` (Plan 2).
- Produces:
  - `store.Sessions.Touch(ctx, tenantID, id string, idleExpiresAt time.Time) error`
  - `store.Sessions.AddClient(ctx, tenantID, id, clientID string) error`
  - `store.Sessions.DeleteExpired(ctx, before time.Time) (int, error)`
  - `store.AuthTransactions.DeleteExpired(ctx, before time.Time) (int, error)`
  - `store.AuthCodes.DeleteExpired(ctx, before time.Time) (int, error)`
  - `app.sweep(ctx, st store.Store, now time.Time) (int, error)`; Task 2 extends it with refresh tokens
  - `app.codeRetention` (24h) and `app.sweepInterval` (10m)
  - `Sessions.Update` is **removed**.

- [ ] **Step 1: Write the failing conformance tests**

In `pkg/storetest/sessions.go`, replace the block in `CRUD` from `want.ClientIDs = append(want.ClientIDs, "web")` through the end of the subtest with:

```go
		mustNoErr(t, s.Sessions().Touch(ctx, "ten_a", "s1", ts(4*24*time.Hour)))
		mustNoErr(t, s.Sessions().AddClient(ctx, "ten_a", "s1", "web"))
		mustNoErr(t, s.Sessions().AddClient(ctx, "ten_a", "s1", "web")) // idempotent
		want.ClientIDs = []string{"spa", "web"}
		want.IdleExpiresAt = ts(4 * 24 * time.Hour)
		got, _ = s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustEqual(t, got, want)
		mustErrIs(t, s.Sessions().Touch(ctx, "ten_b", "s1", ts(0)), store.ErrNotFound)
		mustErrIs(t, s.Sessions().AddClient(ctx, "ten_b", "s1", "x"), store.ErrNotFound)

		mustNoErr(t, s.Sessions().Delete(ctx, "ten_a", "s1"))
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.Sessions().Delete(ctx, "ten_a", "s1"), store.ErrNotFound)
		mustErrIs(t, s.Sessions().Touch(ctx, "ten_a", "s1", ts(0)), store.ErrNotFound)
		mustErrIs(t, s.Sessions().AddClient(ctx, "ten_a", "s1", "x"), store.ErrNotFound)
	})
```

Append these subtests inside `testSessions` (add `"fmt"`, `"sync"` and `"slices"` to the imports):

```go
	t.Run("ConcurrentAddClient", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_a", "s1", "hash1")))
		var wg sync.WaitGroup
		for i := range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = s.Sessions().AddClient(ctx, "ten_a", "s1", fmt.Sprintf("c%d", i))
			}()
		}
		wg.Wait()
		got, err := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustNoErr(t, err)
		mustEqual(t, len(got.ClientIDs), 21) // "spa" plus 20 distinct clients
		for i := range 20 {
			mustEqual(t, slices.Contains(got.ClientIDs, fmt.Sprintf("c%d", i)), true)
		}
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		live := newSession("ten_a", "live", "h-live")
		absolute := newSession("ten_a", "abs", "h-abs")
		absolute.ExpiresAt = ts(time.Hour)
		idle := newSession("ten_a", "idle", "h-idle")
		idle.IdleExpiresAt = ts(time.Hour)
		edge := newSession("ten_a", "edge", "h-edge")
		edge.IdleExpiresAt = ts(2 * time.Hour) // exactly at the cutoff: expired
		other := newSession("ten_b", "other", "h-other")
		other.IdleExpiresAt = ts(time.Hour)
		for _, x := range []*store.LoginSession{live, absolute, idle, edge, other} {
			mustNoErr(t, s.Sessions().Create(ctx, x))
		}
		n, err := s.Sessions().DeleteExpired(ctx, ts(2*time.Hour))
		mustNoErr(t, err)
		mustEqual(t, n, 4)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", "h-live")
		mustNoErr(t, err)
		for _, k := range [][2]string{{"ten_a", "h-abs"}, {"ten_a", "h-idle"}, {"ten_a", "h-edge"}, {"ten_b", "h-other"}} {
			_, err = s.Sessions().GetByTokenHash(ctx, k[0], k[1])
			mustErrIs(t, err, store.ErrNotFound)
		}
	})
```

Append to `testAuthTransactions`:

```go
	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		early := newAuthTransaction("ten_a", "t1") // expires ts(15m)
		late := newAuthTransaction("ten_a", "t2")
		late.ExpiresAt = ts(time.Hour)
		other := newAuthTransaction("ten_b", "t3")
		other.ExpiresAt = ts(time.Minute)
		for _, x := range []*store.AuthTransaction{early, late, other} {
			mustNoErr(t, s.AuthTransactions().Create(ctx, x))
		}
		n, err := s.AuthTransactions().DeleteExpired(ctx, ts(15*time.Minute))
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		_, err = s.AuthTransactions().Get(ctx, "ten_a", "t2")
		mustNoErr(t, err)
		_, err = s.AuthTransactions().Get(ctx, "ten_a", "t1")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.AuthTransactions().Get(ctx, "ten_b", "t3")
		mustErrIs(t, err, store.ErrNotFound)
	})
```

Append to `testAuthCodes`:

```go
	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		short := newAuthCode("ten_a", "h1") // expires ts(1m)
		long := newAuthCode("ten_a", "h2")
		long.ExpiresAt = ts(time.Hour)
		mustNoErr(t, s.AuthCodes().Create(ctx, short))
		mustNoErr(t, s.AuthCodes().Create(ctx, long))
		n, err := s.AuthCodes().DeleteExpired(ctx, ts(time.Minute))
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		_, err = s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.AuthCodes().Consume(ctx, "ten_a", "h2", ts(0))
		mustNoErr(t, err)
	})
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/store/memory/`
Expected: FAIL to compile (`Touch`, `AddClient`, `DeleteExpired` undefined).

- [ ] **Step 3: Change the interfaces**

In `internal/store/store.go`, replace the `Sessions` interface with:

```go
// Sessions stores login sessions, keyed by (TenantID, ID). TokenHash is
// unique within a tenant. Changes after creation are narrow atomic
// methods, so concurrent requests cannot overwrite each other's writes.
type Sessions interface {
	// Create returns ErrConflict if the ID or TokenHash exists.
	Create(ctx context.Context, s *LoginSession) error
	GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*LoginSession, error)
	// Touch sets IdleExpiresAt. It returns ErrNotFound if the session is
	// absent.
	Touch(ctx context.Context, tenantID, id string, idleExpiresAt time.Time) error
	// AddClient appends clientID to ClientIDs unless it is already there.
	// It returns ErrNotFound if the session is absent.
	AddClient(ctx context.Context, tenantID, id, clientID string) error
	// Delete returns ErrNotFound if absent.
	Delete(ctx context.Context, tenantID, id string) error
	// DeleteExpired removes, in every tenant, the sessions whose ExpiresAt
	// or IdleExpiresAt is not after before, and returns how many it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
```

Add to `AuthTransactions`:

```go
	// DeleteExpired removes, in every tenant, the transactions whose
	// ExpiresAt is not after before, and returns how many it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
```

Add to `AuthCodes`:

```go
	// DeleteExpired removes, in every tenant, the codes whose ExpiresAt is
	// not after before, used or not, and returns how many it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
```

- [ ] **Step 4: Implement them in the memory driver**

In `internal/store/memory/sessions.go`, delete `Update` and add (imports: `"slices"`, `"time"`):

```go
func (r sessions) Touch(_ context.Context, tenantID, id string, idleExpiresAt time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	s, ok := r.s.sessions[key{tenantID, id}]
	if !ok {
		return store.ErrNotFound
	}
	s.IdleExpiresAt = idleExpiresAt
	return nil
}

func (r sessions) AddClient(_ context.Context, tenantID, id, clientID string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	s, ok := r.s.sessions[key{tenantID, id}]
	if !ok {
		return store.ErrNotFound
	}
	if !slices.Contains(s.ClientIDs, clientID) {
		s.ClientIDs = append(slices.Clone(s.ClientIDs), clientID)
	}
	return nil
}

func (r sessions) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, s := range r.s.sessions {
		if !s.ExpiresAt.After(before) || !s.IdleExpiresAt.After(before) {
			delete(r.s.sessions, k)
			n++
		}
	}
	return n, nil
}
```

In `internal/store/memory/auth_transactions.go` (import `"time"`):

```go
func (r authTransactions) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, t := range r.s.transactions {
		if !t.ExpiresAt.After(before) {
			delete(r.s.transactions, k)
			n++
		}
	}
	return n, nil
}
```

In `internal/store/memory/auth_codes.go`:

```go
func (r authCodes) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, c := range r.s.authCodes {
		if !c.ExpiresAt.After(before) {
			delete(r.s.authCodes, k)
			n++
		}
	}
	return n, nil
}
```

- [ ] **Step 5: Move the session manager to the atomic methods**

In `internal/session/session.go`, `Current`: replace

```go
	_, idle := lifetimes(t)
	s.IdleExpiresAt = minTime(now.Add(idle), s.ExpiresAt)
	if err := m.Store.Sessions().Update(ctx, s); err != nil {
```

with

```go
	_, idle := lifetimes(t)
	idleAt := minTime(now.Add(idle), s.ExpiresAt)
	if err := m.Store.Sessions().Touch(ctx, t.ID, s.ID, idleAt); err != nil {
```

and after that `if` block (before `return s, nil`) add `s.IdleExpiresAt = idleAt`.

Replace `AddClient` with:

```go
// AddClient records that clientID received tokens through s.
func (m *Manager) AddClient(ctx context.Context, s *store.LoginSession, clientID string) error {
	if slices.Contains(s.ClientIDs, clientID) {
		return nil
	}
	if err := m.Store.Sessions().AddClient(ctx, s.TenantID, s.ID, clientID); err != nil {
		return err
	}
	s.ClientIDs = append(s.ClientIDs, clientID)
	return nil
}
```

In `internal/session/session_test.go`, the fake that simulates a concurrent delete now overrides `Touch`. Rename `notFoundOnUpdate` to `notFoundOnTouch` (with its uses) and replace the `Update` method with:

```go
func (notFoundSessions) Touch(context.Context, string, string, time.Time) error {
	return store.ErrNotFound
}
```

Run: `go build ./... && go vet ./...`
Expected: no errors. If anything still calls `Sessions().Update`, move it to `Touch` or `AddClient`.

- [ ] **Step 6: Write the failing sweeper test**

Create `internal/app/sweeper_test.go`:

```go
package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestSweepRemovesExpiredRecords(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	st := memory.New()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.AuthTransactions().Create(ctx, &store.AuthTransaction{TenantID: "t", ID: "old", ExpiresAt: now.Add(-time.Minute)}))
	must(st.AuthTransactions().Create(ctx, &store.AuthTransaction{TenantID: "t", ID: "new", ExpiresAt: now.Add(time.Minute)}))
	must(st.Sessions().Create(ctx, &store.LoginSession{TenantID: "t", ID: "old", TokenHash: "h1", ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(-time.Second)}))
	must(st.Sessions().Create(ctx, &store.LoginSession{TenantID: "t", ID: "new", TokenHash: "h2", ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour)}))
	// Codes are kept for codeRetention after expiry so late replays are
	// still recognized.
	must(st.AuthCodes().Create(ctx, &store.AuthCode{TenantID: "t", CodeHash: "recent", ExpiresAt: now.Add(-time.Hour)}))
	must(st.AuthCodes().Create(ctx, &store.AuthCode{TenantID: "t", CodeHash: "ancient", ExpiresAt: now.Add(-codeRetention - time.Minute)}))

	n, err := sweep(ctx, st, now)
	if err != nil || n != 3 {
		t.Fatalf("sweep = %d, %v; want 3, nil", n, err)
	}
	if _, err := st.AuthTransactions().Get(ctx, "t", "new"); err != nil {
		t.Errorf("live transaction removed: %v", err)
	}
	if _, err := st.Sessions().GetByTokenHash(ctx, "t", "h2"); err != nil {
		t.Errorf("live session removed: %v", err)
	}
	if _, err := st.AuthCodes().Consume(ctx, "t", "recent", now); err != nil {
		t.Errorf("recently expired code removed: %v", err)
	}
	if _, err := st.AuthCodes().Consume(ctx, "t", "ancient", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ancient code kept: %v", err)
	}
}
```

Run: `go test ./internal/app/ -run TestSweep`
Expected: FAIL (`sweep`, `codeRetention` undefined).

- [ ] **Step 7: Implement the sweeper**

Create `internal/app/sweeper.go`:

```go
package app

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// sweepInterval is how often expired records are purged.
const sweepInterval = 10 * time.Minute

// codeRetention keeps authorization codes this long after they expire, so
// a late replay is still recognized as a replay and revokes the tokens
// issued from the code.
const codeRetention = 24 * time.Hour

// sweep deletes expired records and returns how many it removed. A failure
// in one kind of record does not stop the others.
func sweep(ctx context.Context, st store.Store, now time.Time) (int, error) {
	jobs := []struct {
		del    func(context.Context, time.Time) (int, error)
		before time.Time
	}{
		{st.AuthTransactions().DeleteExpired, now},
		{st.Sessions().DeleteExpired, now},
		{st.AuthCodes().DeleteExpired, now.Add(-codeRetention)},
	}
	total := 0
	var errs []error
	for _, j := range jobs {
		n, err := j.del(ctx, j.before)
		total += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	return total, errors.Join(errs...)
}

// sweepLoop runs sweep every interval until ctx is cancelled.
func (a *App) sweepLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := sweep(ctx, a.store, time.Now().UTC())
			if err != nil {
				a.log.Error("purge expired records", "err", err)
			}
			if n > 0 {
				a.log.Debug("purged expired records", "count", n)
			}
		}
	}
}
```

In `internal/app/app.go`, `Serve`: after `a.log.Info("listening", ...)` add:

```go
	go a.sweepLoop(ctx, sweepInterval)
```

- [ ] **Step 8: Run all tests**

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: all packages pass, and vet and gofmt print nothing.

- [ ] **Step 9: Commit**

```bash
git add internal/store internal/session internal/app pkg/storetest
git commit -m "feat(store): atomic session writes and expired-record purging"
```

Then append to `docs/compat/decisions.md`, and commit with `git commit -am "docs: record expired-record purging decision"`:

```markdown
## D-0011: Purging expired records

- **Context:** Login transactions, sessions, authorization codes and refresh tokens expire but were never removed. Unauthenticated `/authorize` requests create transactions, so storage grew without bound.
- **Sources:** RFC 6749 §10.5 (codes are short-lived and single-use); OAuth 2.0 Security BCP (RFC 9700) §4.5 (code replay).
- **Decision:** A sweeper runs every 10 minutes in `serve`. It deletes expired transactions, sessions and refresh tokens. Authorization codes are kept for 24 hours after they expire, so a replay within that time is still recognized and revokes the tokens issued from the code.
- **Rationale:** It bounds storage. The code retention keeps replay detection meaningful beyond the 60-second code lifetime.
```

---

### Task 2: Refresh token store with atomic rotation

**Files:**
- Modify: `internal/store/types.go` (add `RefreshToken`)
- Modify: `internal/store/store.go` (add `RefreshTokens`, `Store.RefreshTokens()`)
- Create: `internal/store/memory/refresh_tokens.go`
- Modify: `internal/store/memory/memory.go`, `internal/store/memory/clone.go`
- Create: `pkg/storetest/refresh_tokens.go`
- Modify: `pkg/storetest/storetest.go`
- Modify: `internal/app/sweeper.go`, `internal/app/sweeper_test.go`

**Interfaces:**
- Consumes: `store.ErrNotFound`, `store.ErrConflict`, `store.ErrAlreadyUsed`.
- Produces, used by Tasks 4–6, 9 and 11:

```go
type RefreshToken struct {
	TenantID, ID, TokenHash, FamilyID, ClientID, UserID, SessionID string
	Scopes        []string
	Audience      string
	AuthTime      time.Time
	Rotating      bool
	ExpiresAt     time.Time  // family absolute expiry; zero = none
	IdleExpiresAt time.Time  // zero = none
	RotatedAt     *time.Time
	RevokedAt     *time.Time
	CreatedAt     time.Time
}
type RefreshTokens interface {
	Create(ctx, t *RefreshToken) error
	GetByTokenHash(ctx, tenantID, tokenHash string) (*RefreshToken, error)
	Rotate(ctx, tenantID, oldID string, next *RefreshToken, at time.Time, leeway time.Duration) error
	Touch(ctx, tenantID, id string, idleExpiresAt time.Time) error
	RevokeFamily(ctx, tenantID, familyID string, at time.Time) error
	DeleteExpired(ctx, before time.Time) (int, error)
}
```

- [ ] **Step 1: Write the failing conformance tests**

Create `pkg/storetest/refresh_tokens.go`:

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

func newRefreshToken(tenantID, id, hash, family string) *store.RefreshToken {
	return &store.RefreshToken{
		TenantID: tenantID, ID: id, TokenHash: hash, FamilyID: family,
		ClientID: "spa", UserID: "auth0|u1", SessionID: "s1",
		Scopes: []string{"openid", "offline_access"}, Audience: "https://api.test",
		AuthTime: ts(0), Rotating: true,
		ExpiresAt: ts(30 * 24 * time.Hour), IdleExpiresAt: ts(15 * 24 * time.Hour), CreatedAt: ts(0),
	}
}

func getRT(t *testing.T, s store.Store, tenantID, hash string) *store.RefreshToken {
	t.Helper()
	rt, err := s.RefreshTokens().GetByTokenHash(context.Background(), tenantID, hash)
	mustNoErr(t, err)
	return rt
}

func testRefreshTokens(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CreateGet", func(t *testing.T) {
		s := open(t, newStore)
		want := newRefreshToken("ten_a", "rt1", "h1", "f1")
		mustNoErr(t, s.RefreshTokens().Create(ctx, want))
		mustErrIs(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h2", "f1")), store.ErrConflict)
		mustErrIs(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt2", "h1", "f1")), store.ErrConflict)
		mustEqual(t, getRT(t, s, "ten_a", "h1"), want)
		_, err := s.RefreshTokens().GetByTokenHash(ctx, "ten_b", "h1")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_a", "nope")
		mustErrIs(t, err, store.ErrNotFound)
		// The same ID and hash in another tenant is not a conflict.
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_b", "rt1", "h1", "f1")))
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newRefreshToken("ten_a", "rt1", "h1", "f1")
		mustNoErr(t, s.RefreshTokens().Create(ctx, in))
		in.Scopes[0] = "mutated"
		got := getRT(t, s, "ten_a", "h1")
		got.Scopes[1] = "mutated-too"
		mustEqual(t, getRT(t, s, "ten_a", "h1").Scopes, []string{"openid", "offline_access"})
	})

	t.Run("RotateAndReuse", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h1", "f1")))
		next := newRefreshToken("ten_a", "rt2", "h2", "f1")
		mustNoErr(t, s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", next, ts(time.Minute), 0))
		mustEqual(t, getRT(t, s, "ten_a", "h2"), next)
		old := getRT(t, s, "ten_a", "h1")
		mustEqual(t, old.RotatedAt != nil && old.RotatedAt.Equal(ts(time.Minute)), true)
		mustEqual(t, old.RevokedAt == nil, true)

		// Reuse: nothing is stored and the whole family is revoked.
		err := s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt3", "h3", "f1"), ts(2*time.Minute), 0)
		mustErrIs(t, err, store.ErrAlreadyUsed)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_a", "h3")
		mustErrIs(t, err, store.ErrNotFound)
		for _, h := range []string{"h1", "h2"} {
			rt := getRT(t, s, "ten_a", h)
			mustEqual(t, rt.RevokedAt != nil && rt.RevokedAt.Equal(ts(2*time.Minute)), true)
		}
		// A revoked token cannot be rotated.
		err = s.RefreshTokens().Rotate(ctx, "ten_a", "rt2", newRefreshToken("ten_a", "rt4", "h4", "f1"), ts(3*time.Minute), 0)
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("RotateWithinLeeway", func(t *testing.T) {
		s := open(t, newStore)
		leeway := 30 * time.Second
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h1", "f1")))
		mustNoErr(t, s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt2", "h2", "f1"), ts(time.Minute), leeway))
		mustNoErr(t, s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt3", "h3", "f1"), ts(time.Minute+10*time.Second), leeway))
		mustEqual(t, getRT(t, s, "ten_a", "h1").RotatedAt.Equal(ts(time.Minute)), true) // first rotation time kept
		mustEqual(t, getRT(t, s, "ten_a", "h2").RevokedAt == nil, true)
		mustEqual(t, getRT(t, s, "ten_a", "h3").RevokedAt == nil, true)
		// At exactly RotatedAt+leeway the window has closed.
		err := s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt4", "h4", "f1"), ts(time.Minute+leeway), leeway)
		mustErrIs(t, err, store.ErrAlreadyUsed)
		for _, h := range []string{"h1", "h2", "h3"} {
			mustEqual(t, getRT(t, s, "ten_a", h).RevokedAt != nil, true)
		}
	})

	t.Run("RotateUnknownAndConflict", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h1", "f1")))
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt9", "h9", "f9")))
		err := s.RefreshTokens().Rotate(ctx, "ten_a", "nope", newRefreshToken("ten_a", "rt2", "h2", "f1"), ts(0), 0)
		mustErrIs(t, err, store.ErrNotFound)
		err = s.RefreshTokens().Rotate(ctx, "ten_b", "rt1", newRefreshToken("ten_b", "rt2", "h2", "f1"), ts(0), 0)
		mustErrIs(t, err, store.ErrNotFound)
		// A successor whose hash exists changes nothing.
		err = s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt2", "h9", "f1"), ts(0), 0)
		mustErrIs(t, err, store.ErrConflict)
		mustEqual(t, getRT(t, s, "ten_a", "h1").RotatedAt == nil, true)
		// A successor from another family is refused.
		err = s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt2", "h2", "f2"), ts(0), 0)
		mustErrIs(t, err, store.ErrConflict)
		mustEqual(t, getRT(t, s, "ten_a", "h1").RotatedAt == nil, true)
	})

	t.Run("ConcurrentRotate", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h1", "f1")))
		const n = 10
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				next := newRefreshToken("ten_a", fmt.Sprintf("next%d", i), fmt.Sprintf("hn%d", i), "f1")
				errs[i] = s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", next, ts(time.Minute), 0)
			}()
		}
		wg.Wait()
		ok, reused := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrAlreadyUsed):
				reused++
			default:
				t.Fatalf("unexpected error %v", err)
			}
		}
		mustEqual(t, ok, 1)
		mustEqual(t, reused, n-1)
		// The race was reuse, so even the winning successor is revoked.
		for i := range n {
			rt, err := s.RefreshTokens().GetByTokenHash(ctx, "ten_a", fmt.Sprintf("hn%d", i))
			if err == nil {
				mustEqual(t, rt.RevokedAt != nil, true)
			}
		}
	})

	t.Run("Touch", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h1", "f1")))
		mustNoErr(t, s.RefreshTokens().Touch(ctx, "ten_a", "rt1", ts(20*24*time.Hour)))
		mustEqual(t, getRT(t, s, "ten_a", "h1").IdleExpiresAt, ts(20*24*time.Hour))
		mustErrIs(t, s.RefreshTokens().Touch(ctx, "ten_a", "nope", ts(0)), store.ErrNotFound)
		mustErrIs(t, s.RefreshTokens().Touch(ctx, "ten_b", "rt1", ts(0)), store.ErrNotFound)
		mustNoErr(t, s.RefreshTokens().RevokeFamily(ctx, "ten_a", "f1", ts(time.Minute)))
		mustErrIs(t, s.RefreshTokens().Touch(ctx, "ten_a", "rt1", ts(0)), store.ErrNotFound)

		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt2", "h2", "f2")))
		mustNoErr(t, s.RefreshTokens().Rotate(ctx, "ten_a", "rt2", newRefreshToken("ten_a", "rt3", "h3", "f2"), ts(time.Minute), 0))
		mustErrIs(t, s.RefreshTokens().Touch(ctx, "ten_a", "rt2", ts(0)), store.ErrNotFound) // rotated
	})

	t.Run("RevokeFamily", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "a1", "ha1", "f1")))
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "a2", "ha2", "f1")))
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "b1", "hb1", "f2")))
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_b", "c1", "hc1", "f1")))
		mustNoErr(t, s.RefreshTokens().RevokeFamily(ctx, "ten_a", "f1", ts(5*time.Minute)))
		mustNoErr(t, s.RefreshTokens().RevokeFamily(ctx, "ten_a", "f1", ts(9*time.Minute))) // keeps the first time
		mustNoErr(t, s.RefreshTokens().RevokeFamily(ctx, "ten_a", "unknown", ts(0)))
		for _, h := range []string{"ha1", "ha2"} {
			rt := getRT(t, s, "ten_a", h)
			mustEqual(t, rt.RevokedAt != nil && rt.RevokedAt.Equal(ts(5*time.Minute)), true)
		}
		mustEqual(t, getRT(t, s, "ten_a", "hb1").RevokedAt == nil, true)
		mustEqual(t, getRT(t, s, "ten_b", "hc1").RevokedAt == nil, true)
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		live := newRefreshToken("ten_a", "live", "h-live", "f1")
		absolute := newRefreshToken("ten_a", "abs", "h-abs", "f2")
		absolute.ExpiresAt = ts(time.Hour)
		idle := newRefreshToken("ten_b", "idle", "h-idle", "f3")
		idle.IdleExpiresAt = ts(time.Hour)
		forever := newRefreshToken("ten_a", "forever", "h-forever", "f4")
		forever.ExpiresAt, forever.IdleExpiresAt = time.Time{}, time.Time{}
		for _, x := range []*store.RefreshToken{live, absolute, idle, forever} {
			mustNoErr(t, s.RefreshTokens().Create(ctx, x))
		}
		n, err := s.RefreshTokens().DeleteExpired(ctx, ts(2*time.Hour))
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		getRT(t, s, "ten_a", "h-live")
		getRT(t, s, "ten_a", "h-forever")
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_a", "h-abs")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_b", "h-idle")
		mustErrIs(t, err, store.ErrNotFound)
	})
}
```

In `pkg/storetest/storetest.go` `Run`, add after the AuthCodes line:

```go
	t.Run("RefreshTokens", func(t *testing.T) { testRefreshTokens(t, newStore) })
```

Run: `go test ./internal/store/memory/`
Expected: FAIL to compile (`store.RefreshToken` undefined).

- [ ] **Step 2: Add the type and interface**

Append to `internal/store/types.go`:

```go
// RefreshToken is an issued refresh token. A token and the tokens issued
// by rotating it form a family that shares FamilyID; reuse of a rotated
// token revokes the whole family.
type RefreshToken struct {
	TenantID  string
	ID        string // public identifier, used in logs
	TokenHash string // secrets.HashToken of the token
	FamilyID  string
	ClientID  string
	UserID    string
	SessionID string // the login session the family started in ("sid")
	Scopes    []string
	Audience  string    // API identifier; empty when the token is for /userinfo only
	AuthTime  time.Time // when the user authenticated; ID tokens carry it
	Rotating  bool
	// ExpiresAt is the family's absolute expiry. Zero means never.
	ExpiresAt time.Time
	// IdleExpiresAt is this token's inactivity expiry. Zero means never.
	IdleExpiresAt time.Time
	// RotatedAt is when the token was first exchanged for a successor.
	RotatedAt *time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}
```

In `internal/store/store.go`, add `RefreshTokens() RefreshTokens` to `Store` after `AuthCodes() AuthCodes`, and append:

```go
// RefreshTokens stores refresh tokens, keyed by (TenantID, ID). TokenHash
// is unique within a tenant. Rotation and reuse detection happen inside
// Rotate so that drivers can make them atomic.
type RefreshTokens interface {
	// Create returns ErrConflict if the ID or TokenHash exists.
	Create(ctx context.Context, t *RefreshToken) error
	GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*RefreshToken, error)
	// Rotate atomically exchanges the token oldID for next, which must have
	// the same TenantID and FamilyID (otherwise ErrConflict).
	//   - Absent or revoked: ErrNotFound, nothing changes.
	//   - next's ID or TokenHash exists: ErrConflict, nothing changes.
	//   - Not rotated yet: sets RotatedAt = at and stores next.
	//   - Already rotated and at is before RotatedAt+leeway (leeway > 0):
	//     stores next and keeps RotatedAt.
	//   - Already rotated otherwise: revokes every token of the family at
	//     `at`, stores nothing, and returns ErrAlreadyUsed.
	Rotate(ctx context.Context, tenantID, oldID string, next *RefreshToken, at time.Time, leeway time.Duration) error
	// Touch sets IdleExpiresAt of a token that is neither revoked nor
	// rotated; otherwise it returns ErrNotFound.
	Touch(ctx context.Context, tenantID, id string, idleExpiresAt time.Time) error
	// RevokeFamily sets RevokedAt = at on every unrevoked token of the
	// family. An unknown family is not an error.
	RevokeFamily(ctx context.Context, tenantID, familyID string, at time.Time) error
	// DeleteExpired removes, in every tenant, the tokens whose non-zero
	// ExpiresAt or IdleExpiresAt is not after before, and returns how many
	// it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
```

- [ ] **Step 3: Implement the memory driver**

In `internal/store/memory/memory.go`:
- add the field `refreshTokens map[key]*store.RefreshToken // by (tenant, ID)` to `Store`;
- initialize it in `New` with `refreshTokens: map[key]*store.RefreshToken{},`;
- add the accessor `func (s *Store) RefreshTokens() store.RefreshTokens { return refreshTokens{s} }`.

Append to `internal/store/memory/clone.go`:

```go
func cloneRefreshToken(t *store.RefreshToken) *store.RefreshToken {
	out := *t
	out.Scopes = slices.Clone(t.Scopes)
	if t.RotatedAt != nil {
		v := *t.RotatedAt
		out.RotatedAt = &v
	}
	if t.RevokedAt != nil {
		v := *t.RevokedAt
		out.RevokedAt = &v
	}
	return &out
}
```

Create `internal/store/memory/refresh_tokens.go`:

```go
package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type refreshTokens struct{ s *Store }

// taken reports whether t's ID or TokenHash is used. Called with the lock held.
func (r refreshTokens) taken(t *store.RefreshToken) bool {
	if _, ok := r.s.refreshTokens[key{t.TenantID, t.ID}]; ok {
		return true
	}
	_, ok := r.findByHash(t.TenantID, t.TokenHash)
	return ok
}

// findByHash is called with the lock held.
func (r refreshTokens) findByHash(tenantID, hash string) (*store.RefreshToken, bool) {
	for k, t := range r.s.refreshTokens {
		if k.tenant == tenantID && t.TokenHash == hash {
			return t, true
		}
	}
	return nil, false
}

func (r refreshTokens) Create(_ context.Context, t *store.RefreshToken) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if r.taken(t) {
		return store.ErrConflict
	}
	r.s.refreshTokens[key{t.TenantID, t.ID}] = cloneRefreshToken(t)
	return nil
}

func (r refreshTokens) GetByTokenHash(_ context.Context, tenantID, tokenHash string) (*store.RefreshToken, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	t, ok := r.findByHash(tenantID, tokenHash)
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneRefreshToken(t), nil
}

func (r refreshTokens) Rotate(_ context.Context, tenantID, oldID string, next *store.RefreshToken, at time.Time, leeway time.Duration) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	old, ok := r.s.refreshTokens[key{tenantID, oldID}]
	if !ok || old.RevokedAt != nil {
		return store.ErrNotFound
	}
	if next.TenantID != tenantID || next.FamilyID != old.FamilyID || r.taken(next) {
		return store.ErrConflict
	}
	if old.RotatedAt != nil {
		if leeway <= 0 || !at.Before(old.RotatedAt.Add(leeway)) {
			r.revokeFamily(tenantID, old.FamilyID, at)
			return store.ErrAlreadyUsed
		}
	} else {
		t := at
		old.RotatedAt = &t
	}
	r.s.refreshTokens[key{next.TenantID, next.ID}] = cloneRefreshToken(next)
	return nil
}

func (r refreshTokens) Touch(_ context.Context, tenantID, id string, idleExpiresAt time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	t, ok := r.s.refreshTokens[key{tenantID, id}]
	if !ok || t.RevokedAt != nil || t.RotatedAt != nil {
		return store.ErrNotFound
	}
	t.IdleExpiresAt = idleExpiresAt
	return nil
}

func (r refreshTokens) RevokeFamily(_ context.Context, tenantID, familyID string, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.revokeFamily(tenantID, familyID, at)
	return nil
}

// revokeFamily is called with the lock held.
func (r refreshTokens) revokeFamily(tenantID, familyID string, at time.Time) {
	for k, t := range r.s.refreshTokens {
		if k.tenant == tenantID && t.FamilyID == familyID && t.RevokedAt == nil {
			v := at
			t.RevokedAt = &v
		}
	}
}

func (r refreshTokens) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, t := range r.s.refreshTokens {
		if (!t.ExpiresAt.IsZero() && !t.ExpiresAt.After(before)) ||
			(!t.IdleExpiresAt.IsZero() && !t.IdleExpiresAt.After(before)) {
			delete(r.s.refreshTokens, k)
			n++
		}
	}
	return n, nil
}
```

Run: `go test -race ./internal/store/memory/`
Expected: PASS, including `TestConformance/RefreshTokens/ConcurrentRotate`.

- [ ] **Step 4: Sweep expired refresh tokens**

In `internal/app/sweeper.go`, add to `jobs`:

```go
		{st.RefreshTokens().DeleteExpired, now},
```

In `internal/app/sweeper_test.go`, before the call to `sweep`, add:

```go
	must(st.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: "t", ID: "old", TokenHash: "r1", ExpiresAt: now.Add(-time.Second)}))
	must(st.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: "t", ID: "forever", TokenHash: "r2"}))
```

Change the expected count from 3 to 4 (in the condition and the message). After the existing checks, add:

```go
	if _, err := st.RefreshTokens().GetByTokenHash(ctx, "t", "r2"); err != nil {
		t.Errorf("non-expiring refresh token removed: %v", err)
	}
```

- [ ] **Step 5: Run all tests**

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: all pass, and vet and gofmt print nothing. Any test double that embeds `store.Store` keeps compiling, because the method is promoted.

- [ ] **Step 6: Commit**

```bash
git add internal/store internal/app pkg/storetest
git commit -m "feat(store): refresh tokens with atomic rotation and family revocation"
```

---

### Task 3: Refresh-token policy, allowed logout URLs, URL validation

This task adds per-client refresh-token settings and tenant-level allowed logout URLs, and makes both seedable. It also closes the two residual Plan 2 findings:
- A registered callback that does not parse could reach `writeResponse` and panic.
- `response_mode=form_post` to a private-use scheme rendered a form that could never submit.

**Files:**
- Modify: `internal/store/types.go` (`Tenant.AllowedLogoutURLs`, `Client.RefreshToken`, `RefreshTokenPolicy`)
- Modify: `internal/store/memory/clone.go`
- Modify: `pkg/storetest/tenants.go`, `pkg/storetest/clients.go` (fixtures round-trip the new fields)
- Modify: `internal/seed/seed.go`, `internal/seed/validate.go`, `internal/seed/apply.go`, `internal/seed/seed_test.go`
- Modify: `internal/authz/validate.go`, `internal/authz/validate_test.go`, `internal/authz/handlers_test.go`

**Interfaces:**
- Produces:
  - `store.Tenant.AllowedLogoutURLs []string`
  - `store.Client.RefreshToken store.RefreshTokenPolicy{Rotating bool; Leeway int; Expiring bool; TokenLifetime int; IdleTokenLifetime int}`
  - seed keys `tenants[].allowed_logout_urls` and `clients[].refresh_token.{rotation_type, expiration_type, leeway, token_lifetime, idle_token_lifetime}`
  - `authz.AllowedURL(registered []string, uri string) bool` (used by Tasks 7–8)

- [ ] **Step 1: Store fields**

In `internal/store/types.go`, add to `Tenant` after `DefaultAudience`:

```go
	// AllowedLogoutURLs are where /v2/logout may send a browser when the
	// request names no client.
	AllowedLogoutURLs []string
```

Add to `Client` after `IDTokenLifetime`:

```go
	RefreshToken RefreshTokenPolicy
```

and append:

```go
// RefreshTokenPolicy configures the refresh tokens issued to a client.
// Field meanings follow Auth0's public application settings.
type RefreshTokenPolicy struct {
	// Rotating issues a new refresh token on every exchange; presenting a
	// rotated token again (after Leeway) revokes its whole family.
	Rotating bool
	// Leeway is how many seconds after its first rotation a token may still
	// be exchanged, for clients that retry. Zero means no reuse at all.
	Leeway int
	// Expiring false means the tokens never expire.
	Expiring bool
	// TokenLifetime is the family's absolute lifetime in seconds; zero means
	// the default (31557600) when Expiring.
	TokenLifetime int
	// IdleTokenLifetime is the inactivity lifetime in seconds; zero means
	// the default (2592000) when Expiring.
	IdleTokenLifetime int
}
```

In `internal/store/memory/clone.go` `cloneTenant`, add `c.AllowedLogoutURLs = slices.Clone(t.AllowedLogoutURLs)`. `RefreshToken` is a value, so `cloneClient` needs no change.

In `pkg/storetest/tenants.go` `newTenant`, add `AllowedLogoutURLs: []string{"https://" + name + ".example.test/bye"},`. In `pkg/storetest/clients.go` `newClient`, add:

```go
		RefreshToken: store.RefreshTokenPolicy{Rotating: true, Leeway: 5, Expiring: true, TokenLifetime: 86400, IdleTokenLifetime: 3600},
```

The existing round-trip assertions now cover the new fields.

Run: `go test ./internal/store/... ./pkg/...`
Expected: PASS.

- [ ] **Step 2: Write the failing seed tests**

In `internal/seed/seed_test.go`, add these cases to the `TestValidation` table:

```go
		"bad callback escape":     {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://a.test/cb%zz"]}]}]`, "not a valid URL"},
		"relative callback":       {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["/cb"]}]}]`, "absolute"},
		"callback fragment":       {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://a.test/cb#x"]}]}]`, "fragment"},
		"https without host":      {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https:/cb"]}]}]`, "no host"},
		"bad logout url":          {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, allowed_logout_urls: ["https://a.test/%zz"]}]}]`, "not a valid URL"},
		"bad tenant logout url":   {`tenants: [{name: a, allowed_logout_urls: ["bye"]}]`, "absolute"},
		"bad rotation type":       {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {rotation_type: sometimes}}]}]`, "rotation_type"},
		"bad expiration type":     {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {expiration_type: never}}]}]`, "expiration_type"},
		"rotation needs expiry":   {`tenants: [{name: a, clients: [{client_id: c, app_type: regular_web, client_secret: s, refresh_token: {rotation_type: rotating, expiration_type: non-expiring}}]}]`, "requires expiration_type expiring"},
		"spa non-expiring":        {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {rotation_type: non-rotating, expiration_type: non-expiring}}]}]`, "single-page"},
		"negative leeway":         {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {leeway: -1}}]}]`, "must not be negative"},
		"idle exceeds absolute":   {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {token_lifetime: 60, idle_token_lifetime: 120}}]}]`, "must not exceed"},
```

Append a new test:

```go
func TestApplyRefreshTokenPolicyAndLogoutURLs(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(`
tenants:
  - name: acme
    allowed_logout_urls: ["https://acme.test/bye"]
    clients:
      - {client_id: spa, app_type: spa, callbacks: ["com.example.app:/cb"]}
      - {client_id: web, app_type: regular_web, client_secret: s}
      - client_id: tuned
        app_type: regular_web
        client_secret: s
        allowed_logout_urls: ["https://web.acme.test/bye"]
        refresh_token: {rotation_type: rotating, leeway: 10, token_lifetime: 86400, idle_token_lifetime: 3600}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if len(tn.AllowedLogoutURLs) != 1 || tn.AllowedLogoutURLs[0] != "https://acme.test/bye" {
		t.Errorf("tenant allowed_logout_urls = %v", tn.AllowedLogoutURLs)
	}
	want := map[string]store.RefreshTokenPolicy{
		"spa":   {Rotating: true, Expiring: true},
		"web":   {Rotating: false, Expiring: false},
		"tuned": {Rotating: true, Expiring: true, Leeway: 10, TokenLifetime: 86400, IdleTokenLifetime: 3600},
	}
	for id, w := range want {
		c, err := st.Clients().Get(ctx, tn.ID, id)
		if err != nil {
			t.Fatal(err)
		}
		if c.RefreshToken != w {
			t.Errorf("%s refresh_token = %+v, want %+v", id, c.RefreshToken, w)
		}
	}
}
```

Run: `go test ./internal/seed/`
Expected: FAIL (unknown fields `allowed_logout_urls` on tenant and `refresh_token`, and the missing validations).

- [ ] **Step 3: Seed fields**

In `internal/seed/seed.go`, add to `Tenant` after `DefaultAudience`:

```go
	AllowedLogoutURLs   []string         `yaml:"allowed_logout_urls"`
```

Add to `Client` after `IDTokenLifetime`:

```go
	RefreshToken            RefreshToken `yaml:"refresh_token"`
```

and append:

```go
// RefreshToken is a client's refresh-token policy. Values follow Auth0's
// public application settings; empty types take defaults in validate.
type RefreshToken struct {
	RotationType      string `yaml:"rotation_type"`   // rotating | non-rotating
	ExpirationType    string `yaml:"expiration_type"` // expiring | non-expiring
	Leeway            int    `yaml:"leeway"`
	TokenLifetime     int    `yaml:"token_lifetime"`
	IdleTokenLifetime int    `yaml:"idle_token_lifetime"`
}
```

- [ ] **Step 4: Validation**

In `internal/seed/validate.go`, add this helper:

```go
// checkURL reports why raw cannot be registered as a redirect target: it
// must parse, be absolute, have no fragment, and http(s) URLs need a host.
// Wildcard hosts (https://*.example.com/cb) parse like any other host.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return fmt.Errorf("%q is not a valid URL", raw)
	case u.Scheme == "":
		return fmt.Errorf("%q must be an absolute URL", raw)
	case strings.Contains(raw, "#"):
		return fmt.Errorf("%q must not contain a fragment", raw)
	case (u.Scheme == "http" || u.Scheme == "https") && u.Host == "":
		return fmt.Errorf("%q has no host", raw)
	}
	return nil
}
```

In `(*Tenant).validate`, after the `fail` closure, add:

```go
	for _, u := range t.AllowedLogoutURLs {
		if err := checkURL(u); err != nil {
			fail("allowed_logout_urls: %v", err)
		}
	}
```

In the client loop, at the top of `for _, cb := range c.Callbacks {` add:

```go
			if err := checkURL(cb); err != nil {
				fail("client %q: callback %v", c.ClientID, err)
				continue
			}
```

After the callbacks loop, add:

```go
		for _, u := range c.AllowedLogoutURLs {
			if err := checkURL(u); err != nil {
				fail("client %q: allowed_logout_urls: %v", c.ClientID, err)
			}
		}
```

After the `if !public && c.ClientSecret == ""` block, add:

```go
		rt := &c.RefreshToken
		if rt.RotationType == "" {
			rt.RotationType = "non-rotating"
			if store.AppType(c.AppType) == store.AppTypeSPA {
				rt.RotationType = "rotating"
			}
		}
		if rt.ExpirationType == "" {
			rt.ExpirationType = "non-expiring"
			if rt.RotationType == "rotating" {
				rt.ExpirationType = "expiring"
			}
		}
		switch {
		case rt.RotationType != "rotating" && rt.RotationType != "non-rotating":
			fail("client %q: refresh_token.rotation_type %q must be rotating or non-rotating", c.ClientID, rt.RotationType)
		case rt.ExpirationType != "expiring" && rt.ExpirationType != "non-expiring":
			fail("client %q: refresh_token.expiration_type %q must be expiring or non-expiring", c.ClientID, rt.ExpirationType)
		case rt.RotationType == "rotating" && rt.ExpirationType != "expiring":
			fail("client %q: refresh_token rotation requires expiration_type expiring", c.ClientID)
		case store.AppType(c.AppType) == store.AppTypeSPA && rt.ExpirationType != "expiring":
			fail("client %q: single-page applications require expiring refresh tokens", c.ClientID)
		}
		if rt.Leeway < 0 || rt.TokenLifetime < 0 || rt.IdleTokenLifetime < 0 {
			fail("client %q: refresh_token leeway and lifetimes must not be negative", c.ClientID)
		}
		if rt.TokenLifetime > 0 && rt.IdleTokenLifetime > rt.TokenLifetime {
			fail("client %q: refresh_token.idle_token_lifetime must not exceed token_lifetime", c.ClientID)
		}
```

The client loop ranges by index (`c := &t.Clients[i]`), so these defaults are written back to the file that `Apply` reads.

- [ ] **Step 5: Apply**

In `internal/seed/apply.go`, set the tenant field in both the create and update branches. Next to `tn.FriendlyName, tn.Domains, tn.DefaultAudience = ...`, add:

```go
		tn.AllowedLogoutURLs = slices.Clone(in.AllowedLogoutURLs)
```

In `applyClient`, after `c.IDTokenLifetime = in.IDTokenLifetime`, add:

```go
	c.RefreshToken = store.RefreshTokenPolicy{
		Rotating:          in.RefreshToken.RotationType == "rotating",
		Leeway:            in.RefreshToken.Leeway,
		Expiring:          in.RefreshToken.ExpirationType == "expiring",
		TokenLifetime:     in.RefreshToken.TokenLifetime,
		IdleTokenLifetime: in.RefreshToken.IdleTokenLifetime,
	}
```

Run: `go test ./internal/seed/`
Expected: PASS.

- [ ] **Step 6: Write the failing authz tests**

Append to `internal/authz/validate_test.go`:

```go
func TestUnparsableRegisteredCallbackIsRejected(t *testing.T) {
	// Seed validation now refuses such callbacks, but a callback stored by
	// another path must still never reach writeResponse.
	if callbackAllowed([]string{"https://a.test/cb%zz"}, "https://a.test/cb%zz") {
		t.Fatal("an unparsable registered callback was accepted")
	}
}

func TestAllowedURL(t *testing.T) {
	reg := []string{"https://app.acme.test/bye", "https://*.preview.acme.test/bye", "com.example.app:/bye"}
	for uri, want := range map[string]bool{
		"https://app.acme.test/bye":          true,
		"https://pr-1.preview.acme.test/bye": true,
		"com.example.app:/bye":               true,
		"https://app.acme.test/bye/":         false,
		"https://evil.test/bye":              false,
	} {
		if got := AllowedURL(reg, uri); got != want {
			t.Errorf("AllowedURL(%q) = %v, want %v", uri, got, want)
		}
	}
}
```

Append to `internal/authz/handlers_test.go`:

```go
func TestFormPostRequiresHTTPCallback(t *testing.T) {
	e := newEnv(t)
	q := with(goodQuery(), "redirect_uri", "com.example.app:/oauth2redirect", "response_mode", "form_post")
	u := location(t, e.get(t, q))
	if u.Scheme != "com.example.app" || u.Query().Get("error") != "invalid_request" ||
		!strings.Contains(u.Query().Get("error_description"), "form_post") {
		t.Fatalf("redirect = %v", u)
	}
}
```

Run: `go test ./internal/authz/`
Expected: FAIL (`AllowedURL` undefined).

- [ ] **Step 7: Implement**

In `internal/authz/validate.go`, `callbackAllowed`: replace

```go
	if slices.Contains(callbacks, uri) {
		return true
	}
```

with

```go
	if slices.Contains(callbacks, uri) {
		_, err := url.Parse(uri) // writeResponse parses it again
		return err == nil
	}
```

Add after `callbackAllowed`:

```go
// AllowedURL reports whether uri matches one of registered under the
// callback rules: an exact match, or the https single-label wildcard host.
// Logout uses it for return URLs.
func AllowedURL(registered []string, uri string) bool { return callbackAllowed(registered, uri) }
```

In `validate`, directly after the `web_message` origin check, add:

```go
	if req.ResponseMode == "form_post" && !strings.HasPrefix(req.RedirectURI, "https://") && !strings.HasPrefix(req.RedirectURI, "http://") {
		// A browser form cannot post to a native app's private-use scheme.
		req.ResponseMode = "query"
		return client, errInvalidRequest("response_mode=form_post requires an http or https redirect_uri"), true
	}
```

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: PASS, and vet and gofmt print nothing.

- [ ] **Step 8: Commit**

```bash
git add internal/store internal/seed internal/authz pkg/storetest
git commit -m "feat(seed): refresh-token policy, allowed logout URLs, URL validation"
```

---

### Task 4: Issue refresh tokens from the authorization code grant

**Files:**
- Create: `internal/oauth/refresh.go` (policy helpers and refresh token construction)
- Create: `internal/oauth/user_tokens.go` (shared user-flow minting, extracted from the code grant)
- Modify: `internal/oauth/grant_authorization_code.go`
- Modify: `internal/oauth/fixture_test.go`, `internal/oauth/grant_authorization_code_test.go`
- Modify: `docs/compat/decisions.md`

**Interfaces:**
- Consumes:
  - `store.RefreshTokens` (Task 2)
  - `store.Client.RefreshToken`, `store.RefreshTokenPolicy` (Task 3)
  - `Minter.AccessToken`, `Minter.IDToken` (Plan 2)
- Produces, used by Tasks 5, 6 and 9:
  - `DefaultRefreshTokenLifetime` (31557600 s) and `DefaultRefreshTokenIdleLifetime` (2592000 s)
  - `familyForCode(codeHash string) string`
  - `offlineAllowed(c *store.Client, rs *store.ResourceServer) bool`
  - `refreshLifetimes(p store.RefreshTokenPolicy) (absolute, idle time.Duration)`
  - `refreshExpired(rt *store.RefreshToken, now time.Time) bool`
  - `type refreshGrant struct{ familyID, userID, sessionID, audience string; scopes []string; authTime, expiresAt time.Time }`
  - `(*Handlers).newRefreshToken(c *store.Client, tenantID string, g refreshGrant) (*store.RefreshToken, string)`
  - `(*Handlers).activeUser(ctx, tenantID, userID string) (*store.User, *Error)`
  - `(*Handlers).audienceFor(ctx, tenantID, aud string) (*store.ResourceServer, time.Duration, *Error)`
  - `type userTokens struct{ user *store.User; rs *store.ResourceServer; lifetime time.Duration; scopes []string; nonce, sessionID string; authTime time.Time }`
  - `(*Handlers).mintUserTokens(ctx, res tenant.Resolved, c *store.Client, ut userTokens) (*authapi.TokenResponse, *Error)`
  - `userScopes(requested []string, rs *store.ResourceServer, offline bool) []string`

- [ ] **Step 1: Extend the test fixture**

In `internal/oauth/fixture_test.go` `fixtureSeed`:
- In the `https://api.acme.test` resource server, add the line `allow_offline_access: true` after `token_lifetime: 3600`.
- After the `code-web` client, add:

```yaml
      - {client_id: rt-spa, app_type: spa, grant_types: [authorization_code, refresh_token], callbacks: ["https://rt.acme.test/cb"]}
      - client_id: rt-web
        app_type: regular_web
        client_secret: rt-web-secret
        grant_types: [authorization_code, refresh_token]
        callbacks: ["https://rtweb.acme.test/cb"]
        refresh_token: {rotation_type: non-rotating, expiration_type: expiring, token_lifetime: 86400, idle_token_lifetime: 3600}
```

- Change the connection to `{name: Username-Password-Authentication, enabled_clients: [code-spa, code-web, rt-spa, rt-web]}`.

- [ ] **Step 2: Write the failing tests**

Append to `internal/oauth/grant_authorization_code_test.go` (add `"slices"` to the imports if missing):

```go
func TestCodeIssuesRefreshToken(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	code := f.issueCode(t, "rt-spa", "https://rt.acme.test/cb", "https://api.acme.test",
		[]string{"openid", "offline_access", "read:things"}, pkceChallenge)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier)})
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	if body["scope"] != "openid offline_access read:things" {
		t.Errorf("scope = %v", body["scope"])
	}
	raw, _ := body["refresh_token"].(string)
	if len(raw) != 48 {
		t.Fatalf("refresh_token = %q", raw)
	}
	rt, err := f.st.RefreshTokens().GetByTokenHash(ctx, f.tenantID(t, "acme"), secrets.HashToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	if rt.ClientID != "rt-spa" || rt.FamilyID != familyForCode(secrets.HashToken(code)) || !rt.Rotating ||
		rt.SessionID != "sid-1" || rt.Audience != "https://api.acme.test" ||
		!rt.AuthTime.Equal(fixedNow().Add(-time.Minute)) ||
		!rt.ExpiresAt.Equal(fixedNow().Add(DefaultRefreshTokenLifetime)) ||
		!rt.IdleExpiresAt.Equal(fixedNow().Add(DefaultRefreshTokenIdleLifetime)) ||
		!slices.Equal(rt.Scopes, []string{"openid", "offline_access", "read:things"}) {
		t.Fatalf("stored refresh token = %+v", rt)
	}
}

func TestRefreshTokenOnlyWhenAllowed(t *testing.T) {
	cases := []struct {
		name, client, redirect, audience string
		scopes                           []string
		want                             bool
	}{
		{"client without refresh_token grant", "code-spa", "https://app.acme.test/cb", "https://api.acme.test", []string{"openid", "offline_access"}, false},
		{"API without offline access", "rt-spa", "https://rt.acme.test/cb", "https://billing.acme.test", []string{"openid", "offline_access"}, false},
		{"offline_access not requested", "rt-spa", "https://rt.acme.test/cb", "https://api.acme.test", []string{"openid"}, false},
		{"no API", "rt-spa", "https://rt.acme.test/cb", "", []string{"openid", "offline_access"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			code := f.issueCode(t, tc.client, tc.redirect, tc.audience, tc.scopes, pkceChallenge)
			rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, tc.client, tc.redirect, pkceVerifier)})
			if rec.Code != 200 {
				t.Fatalf("status %d: %v", rec.Code, body)
			}
			_, got := body["refresh_token"]
			offline := slices.Contains(strings.Fields(body["scope"].(string)), "offline_access")
			if got != tc.want || offline != tc.want {
				t.Fatalf("refresh_token present = %v, offline_access in scope = %v; want %v (%v)", got, offline, tc.want, body)
			}
		})
	}
}

func TestCodeReplayRevokesRefreshTokens(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "rt-spa", "https://rt.acme.test/cb", "https://api.acme.test",
		[]string{"openid", "offline_access"}, pkceChallenge)
	form := codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form})
	if rec.Code != 200 {
		t.Fatalf("first exchange: %d %v", rec.Code, body)
	}
	raw := body["refresh_token"].(string)
	rec, body = f.call(t, true, tokenCall{host: "acme.example.test", form: form})
	if rec.Code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("replay: %d %v", rec.Code, body)
	}
	rt, err := f.st.RefreshTokens().GetByTokenHash(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(raw))
	if err != nil || rt.RevokedAt == nil {
		t.Fatalf("refresh token after code replay = %+v, %v; want revoked", rt, err)
	}
}
```

Run: `go test ./internal/oauth/ -run 'Refresh|Replay'`
Expected: FAIL (`familyForCode`, `DefaultRefreshTokenLifetime` undefined).

- [ ] **Step 3: Refresh token helpers**

Create `internal/oauth/refresh.go`:

```go
package oauth

import (
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Refresh token lifetimes when a client's policy is expiring but sets no
// value (D-0012).
const (
	DefaultRefreshTokenLifetime     = 31557600 * time.Second
	DefaultRefreshTokenIdleLifetime = 2592000 * time.Second
)

// familyForCode is the refresh token family started by an authorization
// code. Deriving it from the code hash lets a replayed code revoke the
// family without the code record pointing at it.
func familyForCode(codeHash string) string {
	return "rtf_" + secrets.HashToken("family:" + codeHash)[:32]
}

// offlineAllowed reports whether refresh tokens may be issued: the client
// must be allowed the refresh_token grant and, when an API is the
// audience, the API must allow offline access.
func offlineAllowed(c *store.Client, rs *store.ResourceServer) bool {
	return slices.Contains(c.GrantTypes, "refresh_token") && (rs == nil || rs.AllowOfflineAccess)
}

// refreshLifetimes returns the absolute and idle lifetimes for a policy;
// zero means the token does not expire that way.
func refreshLifetimes(p store.RefreshTokenPolicy) (absolute, idle time.Duration) {
	if !p.Expiring {
		return 0, 0
	}
	absolute, idle = DefaultRefreshTokenLifetime, DefaultRefreshTokenIdleLifetime
	if p.TokenLifetime > 0 {
		absolute = time.Duration(p.TokenLifetime) * time.Second
	}
	if p.IdleTokenLifetime > 0 {
		idle = time.Duration(p.IdleTokenLifetime) * time.Second
	}
	return absolute, idle
}

// refreshExpired reports whether rt has passed its absolute or idle expiry.
func refreshExpired(rt *store.RefreshToken, now time.Time) bool {
	return (!rt.ExpiresAt.IsZero() && !now.Before(rt.ExpiresAt)) ||
		(!rt.IdleExpiresAt.IsZero() && !now.Before(rt.IdleExpiresAt))
}

// refreshGrant is what a refresh token carries forward through rotation.
type refreshGrant struct {
	familyID, userID, sessionID, audience string
	scopes                                []string
	authTime                              time.Time
	// expiresAt is the family's absolute expiry; zero means none.
	expiresAt time.Time
}

// newRefreshToken builds a refresh token record for c and returns it with
// the token value. The idle expiry starts now and never passes expiresAt.
func (h *Handlers) newRefreshToken(c *store.Client, tenantID string, g refreshGrant) (*store.RefreshToken, string) {
	now := h.now().UTC()
	_, idle := refreshLifetimes(c.RefreshToken)
	raw := secrets.RandomString(48)
	rt := &store.RefreshToken{
		TenantID:  tenantID,
		ID:        "rt_" + secrets.RandomString(24),
		TokenHash: secrets.HashToken(raw),
		FamilyID:  g.familyID,
		ClientID:  c.ClientID,
		UserID:    g.userID,
		SessionID: g.sessionID,
		Scopes:    slices.Clone(g.scopes),
		Audience:  g.audience,
		AuthTime:  g.authTime,
		Rotating:  c.RefreshToken.Rotating,
		ExpiresAt: g.expiresAt,
		CreatedAt: now,
	}
	if idle > 0 {
		rt.IdleExpiresAt = now.Add(idle)
		if !g.expiresAt.IsZero() && rt.IdleExpiresAt.After(g.expiresAt) {
			rt.IdleExpiresAt = g.expiresAt
		}
	}
	return rt, raw
}
```

- [ ] **Step 4: Extract user-flow minting**

Create `internal/oauth/user_tokens.go`. Its content moves out of `authorizationCode` unchanged except for the parameters:

```go
package oauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// oidcScopes are the user-flow scopes zeroauthy grants without an API.
var oidcScopes = []string{"openid", "profile", "email"}

// userScopes keeps requested OIDC scopes, offline_access when refresh
// tokens may be issued, and, when an API is the audience, requested scopes
// that API defines.
func userScopes(requested []string, rs *store.ResourceServer, offline bool) []string {
	var out []string
	for _, s := range requested {
		ok := slices.Contains(oidcScopes, s) || (offline && s == "offline_access")
		if !ok && rs != nil {
			ok = slices.ContainsFunc(rs.Scopes, func(d store.Scope) bool { return d.Value == s })
		}
		if ok && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// activeUser loads the user a grant was issued to. A deleted or blocked
// user gets invalid_grant.
func (h *Handlers) activeUser(ctx context.Context, tenantID, userID string) (*store.User, *Error) {
	user, err := h.Store.Users().Get(ctx, tenantID, userID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && user.Blocked) {
		return nil, invalidGrant("the user is not allowed to sign in")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load user", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	return user, nil
}

// audienceFor loads the API named by aud ("" means none) and the lifetime
// of access tokens issued for it.
func (h *Handlers) audienceFor(ctx context.Context, tenantID, aud string) (*store.ResourceServer, time.Duration, *Error) {
	if aud == "" {
		return nil, DefaultAccessTokenLifetime, nil
	}
	rs, err := h.Store.ResourceServers().GetByIdentifier(ctx, tenantID, aud)
	if errors.Is(err, store.ErrNotFound) {
		return nil, 0, invalidGrant("the requested audience no longer exists")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load resource server", "tenant", tenantID, "err", err)
		return nil, 0, serverError()
	}
	lifetime := DefaultAccessTokenLifetime
	if rs.TokenLifetime > 0 {
		lifetime = time.Duration(rs.TokenLifetime) * time.Second
	}
	return rs, lifetime, nil
}

// userTokens describes the tokens of one user-flow token response.
type userTokens struct {
	user      *store.User
	rs        *store.ResourceServer // nil: the token is for /userinfo only
	lifetime  time.Duration
	scopes    []string
	nonce     string
	sessionID string
	authTime  time.Time
}

// mintUserTokens returns an access token and, with scope openid, an ID
// token (D-0008).
func (h *Handlers) mintUserTokens(ctx context.Context, res tenant.Resolved, c *store.Client, ut userTokens) (*authapi.TokenResponse, *Error) {
	tenantID := res.Tenant.ID
	userinfo := res.Issuer() + "userinfo"
	openid := slices.Contains(ut.scopes, "openid")
	var audiences []string
	switch {
	case ut.rs != nil && openid:
		audiences = []string{ut.rs.Identifier, userinfo}
	case ut.rs != nil:
		audiences = []string{ut.rs.Identifier}
	default:
		audiences = []string{userinfo}
	}
	accessToken, err := h.Minter.AccessToken(ctx, AccessTokenParams{
		TenantID: tenantID, Issuer: res.Issuer(), Subject: ut.user.UserID, Audience: audiences,
		ClientID: c.ClientID, Scopes: ut.scopes, Lifetime: ut.lifetime,
	})
	if err != nil {
		h.log().ErrorContext(ctx, "mint access token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	resp := &authapi.TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int(ut.lifetime / time.Second)}
	if len(ut.scopes) > 0 {
		s := strings.Join(ut.scopes, " ")
		resp.Scope = &s
	}
	if openid {
		idToken, err := h.Minter.IDToken(ctx, IDTokenParams{
			TenantID: tenantID, Issuer: res.Issuer(), ClientID: c.ClientID, User: ut.user, Scopes: ut.scopes,
			Nonce: ut.nonce, SessionID: ut.sessionID, AuthTime: ut.authTime, AccessToken: accessToken,
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

- [ ] **Step 5: Rewrite the code grant on top of it**

In `internal/oauth/grant_authorization_code.go`, delete `oidcScopes` and `userScopes`, which now live in `user_tokens.go`. Replace the `case errors.Is(err, store.ErrAlreadyUsed):` branch with:

```go
	case errors.Is(err, store.ErrAlreadyUsed):
		// RFC 9700 §4.5: a replayed code may be stolen; revoke what it issued.
		h.log().WarnContext(ctx, "authorization code reused; revoking its refresh tokens", "tenant", tenantID, "client_id", ac.ClientID, "user_id", ac.UserID)
		if err := h.Store.RefreshTokens().RevokeFamily(ctx, tenantID, familyForCode(ac.CodeHash), now); err != nil {
			h.log().ErrorContext(ctx, "revoke refresh tokens of a replayed code", "tenant", tenantID, "err", err)
		}
		return nil, invalidGrant("invalid authorization code")
```

Replace everything from `user, err := h.Store.Users().Get(ctx, tenantID, ac.UserID)` to the end of the function with:

```go
	user, oerr := h.activeUser(ctx, tenantID, ac.UserID)
	if oerr != nil {
		return nil, oerr
	}
	rs, lifetime, oerr := h.audienceFor(ctx, tenantID, ac.Audience)
	if oerr != nil {
		return nil, oerr
	}
	scopes := userScopes(ac.Scopes, rs, offlineAllowed(c, rs))
	resp, oerr := h.mintUserTokens(ctx, res, c, userTokens{
		user: user, rs: rs, lifetime: lifetime, scopes: scopes,
		nonce: ac.Nonce, sessionID: ac.SessionID, authTime: ac.AuthTime,
	})
	if oerr != nil {
		return nil, oerr
	}
	if slices.Contains(scopes, "offline_access") {
		absolute, _ := refreshLifetimes(c.RefreshToken)
		var expiresAt time.Time
		if absolute > 0 {
			expiresAt = now.UTC().Add(absolute)
		}
		rt, raw := h.newRefreshToken(c, tenantID, refreshGrant{
			familyID: familyForCode(ac.CodeHash), userID: user.UserID, sessionID: ac.SessionID,
			audience: ac.Audience, scopes: scopes, authTime: ac.AuthTime, expiresAt: expiresAt,
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

Then remove imports that are now unused, as `goimports`/`go build` reports.

Run: `go test -race ./internal/oauth/`
Expected: PASS. The existing code-grant tests are unchanged and must still pass. `TestAuthorizationCodeSPA` still expects no `offline_access`, because `code-spa` lacks the `refresh_token` grant.

- [ ] **Step 6: Record the decision**

Append to `docs/compat/decisions.md`:

```markdown
## D-0012: Refresh token issuance, rotation and lifetimes

- **Context:** Public docs describe refresh token rotation, reuse detection and expiration settings. They do not pin down every condition for issuing a token or every default.
- **Sources:** RFC 6749 §6; OAuth 2.0 Security BCP (RFC 9700) §4.14 (refresh token protection) and §4.5 (code replay); https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation; https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-expiration.
- **Decision:**
  - **Issuance:** a refresh token is issued only when all of these hold:
    - `offline_access` is requested;
    - the client's `grant_types` include `refresh_token`;
    - either no API is the audience, or the API allows offline access.
    The response's `scope` then includes `offline_access`.
  - **Policy:**
    - `rotation_type` defaults to `rotating` for SPAs and `non-rotating` otherwise.
    - Rotating tokens must expire.
    - SPAs may not use non-expiring tokens.
    - Expiring tokens default to an absolute lifetime of 31557600 s (the documented maximum, since no default is documented) and an idle lifetime of 2592000 s (the documented default).
  - **Rotation:**
    - Each exchange returns a new token in the same family. It inherits the absolute expiry and starts a new idle period.
    - Presenting a rotated token again after the `leeway` (default 0 s) revokes the whole family and returns `invalid_grant`.
  - **Code replay:** a replayed authorization code revokes the family started from it.
- **Rationale:** These follow the documented settings and the security BCP. Rotation and reuse detection are a single atomic store operation, so concurrent requests cannot fork a family.
```

- [ ] **Step 7: Commit**

```bash
git add internal/oauth docs/compat/decisions.md
git commit -m "feat(oauth): issue refresh tokens for offline_access; code replay revokes them"
```

---

### Task 5: The `refresh_token` grant

**Files:**
- Create: `internal/oauth/grant_refresh_token.go`, `internal/oauth/grant_refresh_token_test.go`
- Modify: `internal/oauth/token.go` (register the grant)
- Modify: `internal/oidc/handlers.go`, `internal/oidc/handlers_test.go` (discovery: grant type and scope)
- Modify: `api/authentication.yaml` (token operation description, `TokenRequest.refresh_token`, x-source)

**Interfaces:**
- Consumes: everything Task 4 produces, plus `store.RefreshTokens.{GetByTokenHash, Rotate, Touch}`.
- Produces:
  - `(*Handlers).refreshToken`, registered as grant `refresh_token`
  - test helpers `(*fixture).issueRefresh(t, clientID string, scopes []string, audience string) (string, *store.RefreshToken)` and `refreshForm(clientID, token string, extra ...string) url.Values` (used by Task 6)

- [ ] **Step 1: Write the failing tests**

Create `internal/oauth/grant_refresh_token_test.go`:

```go
package oauth

import (
	"context"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const acmeAPI = "https://api.acme.test"

// issueRefresh stores a refresh token for alice under clientID's policy, as
// the code grant would, and returns its value and record.
func (f *fixture) issueRefresh(t *testing.T, clientID string, scopes []string, audience string) (string, *store.RefreshToken) {
	t.Helper()
	ctx := context.Background()
	tenantID := f.tenantID(t, "acme")
	u, err := f.st.Users().FindByLogin(ctx, tenantID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.st.Clients().Get(ctx, tenantID, clientID)
	if err != nil {
		t.Fatal(err)
	}
	raw := secrets.RandomString(48)
	absolute, idle := refreshLifetimes(c.RefreshToken)
	rt := &store.RefreshToken{
		TenantID: tenantID, ID: "rt_" + secrets.RandomString(24), TokenHash: secrets.HashToken(raw),
		FamilyID: "rtf_" + secrets.RandomString(16), ClientID: clientID, UserID: u.UserID, SessionID: "sid-1",
		Scopes: scopes, Audience: audience, AuthTime: fixedNow().Add(-time.Hour),
		Rotating: c.RefreshToken.Rotating, CreatedAt: fixedNow(),
	}
	if absolute > 0 {
		rt.ExpiresAt = fixedNow().Add(absolute)
	}
	if idle > 0 {
		rt.IdleExpiresAt = fixedNow().Add(idle)
	}
	if err := f.st.RefreshTokens().Create(ctx, rt); err != nil {
		t.Fatal(err)
	}
	return raw, rt
}

func refreshForm(clientID, token string, extra ...string) url.Values {
	v := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {token}}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func (f *fixture) refresh(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form})
	return rec.Code, body
}

func (f *fixture) storedRT(t *testing.T, raw string) *store.RefreshToken {
	t.Helper()
	rt, err := f.st.RefreshTokens().GetByTokenHash(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func TestRefreshRotates(t *testing.T) {
	f := newFixture(t)
	tenantID := f.tenantID(t, "acme")
	raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "profile", "offline_access", "read:things"}, acmeAPI)

	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: refreshForm("rt-spa", raw)})
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	next, _ := body["refresh_token"].(string)
	if len(next) != 48 || next == raw || body["scope"] != "openid profile offline_access read:things" {
		t.Fatalf("body = %v", body)
	}
	at, _ := verifyToken(t, f.keys, tenantID, body["access_token"].(string))
	if aud, _ := at["aud"].([]any); len(aud) != 2 || aud[0] != acmeAPI || at["azp"] != "rt-spa" {
		t.Fatalf("access token = %v", at)
	}
	idt, _ := verifyToken(t, f.keys, tenantID, body["id_token"].(string))
	if idt["aud"] != "rt-spa" || idt["sid"] != "sid-1" || idt["nonce"] != nil || idt["at_hash"] == nil ||
		idt["auth_time"] != float64(fixedNow().Add(-time.Hour).Unix()) || idt["sub"] != at["sub"] {
		t.Fatalf("id token = %v", idt)
	}
	if old := f.storedRT(t, raw); old.RotatedAt == nil || old.RevokedAt != nil {
		t.Fatalf("old token = %+v", old)
	}
	succ := f.storedRT(t, next)
	if succ.FamilyID != rt.FamilyID || !succ.ExpiresAt.Equal(rt.ExpiresAt) ||
		!succ.IdleExpiresAt.Equal(fixedNow().Add(DefaultRefreshTokenIdleLifetime)) || !slices.Equal(succ.Scopes, rt.Scopes) {
		t.Fatalf("successor = %+v", succ)
	}

	// Reuse of the rotated token revokes the family, successor included.
	if code, body := f.refresh(t, refreshForm("rt-spa", raw)); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("reuse = %d %v", code, body)
	}
	if code, body := f.refresh(t, refreshForm("rt-spa", next)); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("successor after reuse = %d %v", code, body)
	}
}

func TestRefreshLeeway(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c, _ := f.st.Clients().Get(ctx, f.tenantID(t, "acme"), "rt-spa")
	c.RefreshToken.Leeway = 30
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, "")
	code1, b1 := f.refresh(t, refreshForm("rt-spa", raw))
	code2, b2 := f.refresh(t, refreshForm("rt-spa", raw)) // a retry inside the leeway
	if code1 != 200 || code2 != 200 || b1["refresh_token"] == b2["refresh_token"] {
		t.Fatalf("within leeway: %d %v / %d %v", code1, b1, code2, b2)
	}
	f.h.Now = func() time.Time { return fixedNow().Add(31 * time.Second) }
	if code, body := f.refresh(t, refreshForm("rt-spa", raw)); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("after leeway = %d %v", code, body)
	}
	if code, _ := f.refresh(t, refreshForm("rt-spa", b1["refresh_token"].(string))); code != 400 {
		t.Fatalf("successor after reuse = %d; want 400", code)
	}
}

func TestRefreshNonRotating(t *testing.T) {
	f := newFixture(t)
	raw, rt := f.issueRefresh(t, "rt-web", []string{"openid", "offline_access"}, "")
	if rt.Rotating || !rt.IdleExpiresAt.Equal(fixedNow().Add(time.Hour)) {
		t.Fatalf("fixture token = %+v", rt)
	}
	at := fixedNow().Add(30 * time.Minute)
	f.h.Now = func() time.Time { return at }
	code, body := f.refresh(t, refreshForm("rt-web", raw, "client_secret", "rt-web-secret"))
	if code != 200 || body["refresh_token"] != nil || body["id_token"] == nil {
		t.Fatalf("refresh = %d %v", code, body)
	}
	if got := f.storedRT(t, raw); !got.IdleExpiresAt.Equal(at.Add(time.Hour)) || got.RotatedAt != nil {
		t.Fatalf("after use = %+v; want idle expiry slid to %v", got, at.Add(time.Hour))
	}
	if code, _ := f.refresh(t, refreshForm("rt-web", raw, "client_secret", "rt-web-secret")); code != 200 {
		t.Fatalf("second use = %d", code)
	}
	f.h.Now = func() time.Time { return at.Add(time.Hour + time.Second) }
	if code, body := f.refresh(t, refreshForm("rt-web", raw, "client_secret", "rt-web-secret")); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("idle-expired = %d %v", code, body)
	}
}

func TestRefreshNarrowsScope(t *testing.T) {
	f := newFixture(t)
	raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access", "read:things"}, acmeAPI)
	code, body := f.refresh(t, refreshForm("rt-spa", raw, "scope", "read:things read:things"))
	if code != 200 || body["scope"] != "read:things" || body["id_token"] != nil {
		t.Fatalf("narrowed refresh = %d %v", code, body)
	}
	at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	if at["aud"] != acmeAPI {
		t.Fatalf("aud = %v; want the API only", at["aud"])
	}
	if succ := f.storedRT(t, body["refresh_token"].(string)); !slices.Equal(succ.Scopes, rt.Scopes) {
		t.Fatalf("successor scopes = %v; want the original %v", succ.Scopes, rt.Scopes)
	}
}

func TestRefreshByAnotherClientLeavesTokenUntouched(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, "")
	if code, body := f.refresh(t, refreshForm("rt-web", raw, "client_secret", "rt-web-secret")); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("other client = %d %v", code, body)
	}
	if got := f.storedRT(t, raw); got.RotatedAt != nil || got.RevokedAt != nil {
		t.Fatalf("token changed by another client's attempt: %+v", got)
	}
	if code, body := f.refresh(t, refreshForm("rt-spa", raw)); code != 200 {
		t.Fatalf("owner after foreign attempt = %d %v", code, body)
	}
}

func TestRefreshRejects(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		prepare func(f *fixture, raw string, rt *store.RefreshToken) url.Values
		status  int
		code    string
	}{
		"missing token": {func(*fixture, string, *store.RefreshToken) url.Values {
			return url.Values{"grant_type": {"refresh_token"}, "client_id": {"rt-spa"}}
		}, 400, "invalid_request"},
		"unknown token": {func(*fixture, string, *store.RefreshToken) url.Values {
			return refreshForm("rt-spa", "not-a-real-token")
		}, 400, "invalid_grant"},
		"revoked": {func(f *fixture, raw string, rt *store.RefreshToken) url.Values {
			_ = f.st.RefreshTokens().RevokeFamily(ctx, rt.TenantID, rt.FamilyID, fixedNow())
			return refreshForm("rt-spa", raw)
		}, 400, "invalid_grant"},
		"absolute expiry": {func(f *fixture, raw string, rt *store.RefreshToken) url.Values {
			f.h.Now = func() time.Time { return rt.ExpiresAt }
			return refreshForm("rt-spa", raw)
		}, 400, "invalid_grant"},
		"idle expiry": {func(f *fixture, raw string, rt *store.RefreshToken) url.Values {
			f.h.Now = func() time.Time { return rt.IdleExpiresAt }
			return refreshForm("rt-spa", raw)
		}, 400, "invalid_grant"},
		"blocked user": {func(f *fixture, raw string, rt *store.RefreshToken) url.Values {
			u, _ := f.st.Users().Get(ctx, rt.TenantID, rt.UserID)
			u.Blocked = true
			_ = f.st.Users().Update(ctx, u)
			return refreshForm("rt-spa", raw)
		}, 400, "invalid_grant"},
		"deleted API": {func(f *fixture, raw string, rt *store.RefreshToken) url.Values {
			rs, _ := f.st.ResourceServers().GetByIdentifier(ctx, rt.TenantID, acmeAPI)
			_ = f.st.ResourceServers().Delete(ctx, rt.TenantID, rs.ID)
			return refreshForm("rt-spa", raw)
		}, 400, "invalid_grant"},
		"scope escalation": {func(_ *fixture, raw string, _ *store.RefreshToken) url.Values {
			return refreshForm("rt-spa", raw, "scope", "openid write:things")
		}, 400, "invalid_scope"},
		"audience mismatch": {func(_ *fixture, raw string, _ *store.RefreshToken) url.Values {
			return refreshForm("rt-spa", raw, "audience", "https://billing.acme.test")
		}, 400, "invalid_request"},
		"client without refresh grant": {func(_ *fixture, raw string, _ *store.RefreshToken) url.Values {
			return refreshForm("code-spa", raw)
		}, 403, "unauthorized_client"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access", "read:things"}, acmeAPI)
			code, body := f.refresh(t, tc.prepare(f, raw, rt))
			if code != tc.status || body["error"] != tc.code {
				t.Fatalf("got %d %v; want %d %s", code, body, tc.status, tc.code)
			}
		})
	}
}
```

Run: `go test ./internal/oauth/ -run Refresh`
Expected: FAIL (`unsupported_grant_type` for `refresh_token`).

- [ ] **Step 2: Implement the grant**

Create `internal/oauth/grant_refresh_token.go`:

```go
package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// refreshToken implements RFC 6749 §6 with rotation and reuse detection
// (RFC 9700 §4.14, D-0012).
func (h *Handlers) refreshToken(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	raw := form.Get("refresh_token")
	if raw == "" {
		return nil, invalidRequest("refresh_token is required")
	}
	tenantID := res.Tenant.ID
	now := h.now().UTC()
	invalid := invalidGrant("invalid refresh token")

	rt, err := h.Store.RefreshTokens().GetByTokenHash(ctx, tenantID, secrets.HashToken(raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalid
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load refresh token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if rt.ClientID != c.ClientID {
		// Never rotate or revoke on behalf of a client that does not own the token.
		h.log().WarnContext(ctx, "refresh token presented by another client", "tenant", tenantID, "client_id", c.ClientID, "owner", rt.ClientID)
		return nil, invalid
	}
	if rt.RevokedAt != nil || refreshExpired(rt, now) {
		return nil, invalid
	}
	if aud := form.Get("audience"); aud != "" && aud != rt.Audience {
		return nil, invalidRequest("audience does not match the refresh token")
	}
	scopes := rt.Scopes
	if requested := strings.Fields(form.Get("scope")); len(requested) > 0 {
		scopes = nil
		for _, s := range requested {
			if !slices.Contains(rt.Scopes, s) {
				return nil, invalidScope(fmt.Sprintf("scope %q was not granted to this refresh token", s))
			}
			if !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
	}

	user, oerr := h.activeUser(ctx, tenantID, rt.UserID)
	if oerr != nil {
		return nil, oerr
	}
	rs, lifetime, oerr := h.audienceFor(ctx, tenantID, rt.Audience)
	if oerr != nil {
		return nil, oerr
	}
	// Re-filter in case the API dropped a scope since the token was issued.
	scopes = userScopes(scopes, rs, true)
	resp, oerr := h.mintUserTokens(ctx, res, c, userTokens{
		user: user, rs: rs, lifetime: lifetime, scopes: scopes,
		sessionID: rt.SessionID, authTime: rt.AuthTime,
	})
	if oerr != nil {
		return nil, oerr
	}

	// The minted tokens are only sent once the refresh token is consumed.
	if rt.Rotating {
		next, nextRaw := h.newRefreshToken(c, tenantID, refreshGrant{
			familyID: rt.FamilyID, userID: rt.UserID, sessionID: rt.SessionID, audience: rt.Audience,
			scopes: rt.Scopes, authTime: rt.AuthTime, expiresAt: rt.ExpiresAt,
		})
		next.Rotating = true
		err := h.Store.RefreshTokens().Rotate(ctx, tenantID, rt.ID, next, now, time.Duration(c.RefreshToken.Leeway)*time.Second)
		switch {
		case errors.Is(err, store.ErrAlreadyUsed):
			h.log().WarnContext(ctx, "refresh token reuse detected; family revoked",
				"tenant", tenantID, "client_id", c.ClientID, "user_id", rt.UserID, "family", rt.FamilyID)
			return nil, invalid
		case errors.Is(err, store.ErrNotFound):
			return nil, invalid
		case err != nil:
			h.log().ErrorContext(ctx, "rotate refresh token", "tenant", tenantID, "err", err)
			return nil, serverError()
		}
		resp.RefreshToken = &nextRaw
		return resp, nil
	}

	if _, idle := refreshLifetimes(c.RefreshToken); idle > 0 {
		idleAt := now.Add(idle)
		if !rt.ExpiresAt.IsZero() && idleAt.After(rt.ExpiresAt) {
			idleAt = rt.ExpiresAt
		}
		if err := h.Store.RefreshTokens().Touch(ctx, tenantID, rt.ID, idleAt); errors.Is(err, store.ErrNotFound) {
			return nil, invalid
		} else if err != nil {
			h.log().ErrorContext(ctx, "extend refresh token", "tenant", tenantID, "err", err)
			return nil, serverError()
		}
	}
	return resp, nil
}
```

The successor sets `next.Rotating = true` explicitly, so a token rotates for its whole life even if the client's policy later changes.

In `internal/oauth/token.go`, add to `grantHandlers`:

```go
	"refresh_token":      (*Handlers).refreshToken,
```

and update the comment above it to name the grants still to come: password, password-realm and device_code.

Run: `go test -race ./internal/oauth/`
Expected: PASS.

- [ ] **Step 3: Contract and discovery**

In `api/authentication.yaml`, for `/oauth/token` `post`:
- Add this row to the grant table in `description`:

```markdown
        | `refresh_token` | Exchange a refresh token (from a request with scope `offline_access`) for new tokens. Rotating refresh tokens return a new `refresh_token`; reusing a rotated token revokes all tokens derived from the same login. `scope` may narrow the original scopes. |
```

- Add these entries to `x-source`:

```yaml
        - https://www.rfc-editor.org/rfc/rfc6749#section-6
        - https://auth0.com/docs/secure/tokens/refresh-tokens/use-refresh-tokens
        - https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
```

In `components.schemas.TokenRequest.properties`, add:

```yaml
        refresh_token:
          type: string
          description: Refresh token (grant_type=refresh_token).
```

In `internal/oidc/handlers.go`:
- set `GrantTypesSupported` to `[]string{"authorization_code", "client_credentials", "refresh_token"}`;
- set `ScopesSupported` to `[]string{"openid", "profile", "email", "offline_access"}`.

In `internal/oidc/handlers_test.go` `TestDiscovery`, update `wantLists` to match:
- `"grant_types_supported": {"authorization_code", "client_credentials", "refresh_token"}`
- `"scopes_supported": {"openid", "profile", "email", "offline_access"}`

Run: `go generate ./... && go test -race ./... && go vet ./... && gofmt -l . && git diff --stat internal/gen`
Expected: PASS, and vet and gofmt print nothing. The generated code changes only in the `TokenRequest` type (the new `RefreshToken` field).

- [ ] **Step 4: Commit**

```bash
git add internal/oauth internal/oidc api internal/gen
git commit -m "feat(oauth): refresh_token grant with rotation and reuse detection"
```

---

### Task 6: `POST /oauth/revoke`

**Files:**
- Modify: `api/authentication.yaml` (operation `oauthRevoke`, schema `RevokeRequest`, discovery `revocation_endpoint`)
- Regenerate: `internal/gen/authapi/authapi.gen.go`
- Create: `internal/oauth/revoke.go`, `internal/oauth/revoke_test.go`
- Modify: `internal/server/server.go` (forwarder, preflight), `internal/server/cors.go` (path list)
- Modify: `internal/oidc/handlers.go`, `internal/oidc/handlers_test.go` (`revocation_endpoint`)
- Modify: `docs/compat/decisions.md`

**Interfaces:**
- Consumes:
  - `parseTokenRequest` and `authenticateClient` (Plan 1)
  - `store.RefreshTokens.{GetByTokenHash, RevokeFamily}`
  - test helpers `issueRefresh`, `refreshForm` and `(*fixture).refresh` (Task 5)
- Produces:
  - `(*oauth.Handlers).OauthRevoke(w, r)`
  - generated `authapi.ServerInterface.OauthRevoke`
  - `oidc.Configuration.RevocationEndpoint`

- [ ] **Step 1: Contract**

In `api/authentication.yaml`, add after the `/oauth/token` path:

```yaml
  /oauth/revoke:
    post:
      operationId: oauthRevoke
      tags: [Tokens]
      summary: Revoke a refresh token
      description: |
        Revokes a refresh token together with every refresh token derived
        from the same login (its rotation family). The client authenticates
        as at `/oauth/token`. An unknown token is not an error (RFC 7009),
        so the response does not reveal whether a token existed. Access
        tokens are self-contained JWTs and cannot be revoked; they expire.
      x-source:
        - https://www.rfc-editor.org/rfc/rfc7009
        - https://auth0.com/docs/api/authentication
        - https://auth0.com/docs/secure/tokens/refresh-tokens/revoke-refresh-tokens
      security:
        - clientSecretBasic: []
        - {}
      requestBody:
        required: true
        content:
          application/x-www-form-urlencoded:
            schema:
              $ref: "#/components/schemas/RevokeRequest"
          application/json:
            schema:
              $ref: "#/components/schemas/RevokeRequest"
      responses:
        "200":
          description: The token was revoked, or was not a known refresh token.
        "400":
          $ref: "#/components/responses/OAuthErrorResponse"
        "401":
          $ref: "#/components/responses/OAuthErrorResponse"
        "404":
          $ref: "#/components/responses/UnknownTenant"
        default:
          $ref: "#/components/responses/ServerError"
```

Under `components.schemas`, add:

```yaml
    RevokeRequest:
      type: object
      required: [token]
      properties:
        token:
          type: string
          description: The refresh token to revoke.
        token_type_hint:
          type: string
          description: Accepted and ignored; only refresh tokens can be revoked.
        client_id:
          type: string
        client_secret:
          type: string
```

In `OpenIDConfiguration.properties`, add `revocation_endpoint: {type: string, format: uri}`.

Run: `go generate ./... && go build ./...`
Expected: the build fails because `authAPI` does not implement `OauthRevoke`, which proves the generated interface picked up the operation.

- [ ] **Step 2: Write the failing tests**

Create `internal/oauth/revoke_test.go`:

```go
package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

func (f *fixture) revoke(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	h := contract.WrapResponses(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthRevoke)))
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestRevokeRevokesFamily(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, "")
	_, body := f.refresh(t, refreshForm("rt-spa", raw)) // rotate once so the family has two tokens
	next := body["refresh_token"].(string)

	code, body := f.revoke(t, url.Values{"client_id": {"rt-spa"}, "token": {next}})
	if code != 200 || body != nil {
		t.Fatalf("revoke = %d %v", code, body)
	}
	for _, tok := range []string{raw, next} {
		if got := f.storedRT(t, tok); got.RevokedAt == nil {
			t.Errorf("token in the family not revoked: %+v", got)
		}
	}
	if code, body := f.refresh(t, refreshForm("rt-spa", next)); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("refresh after revoke = %d %v", code, body)
	}
}

func TestRevokeVariants(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, "")
	cases := map[string]struct {
		form   url.Values
		status int
		code   string
	}{
		"unknown token":     {url.Values{"client_id": {"rt-spa"}, "token": {"no-such-token"}}, 200, ""},
		"another client":    {url.Values{"client_id": {"rt-web"}, "client_secret": {"rt-web-secret"}, "token": {raw}}, 400, "invalid_grant"},
		"missing token":     {url.Values{"client_id": {"rt-spa"}}, 400, "invalid_request"},
		"bad client secret": {url.Values{"client_id": {"rt-web"}, "client_secret": {"wrong"}, "token": {raw}}, 401, "invalid_client"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			code, body := f.revoke(t, tc.form)
			if code != tc.status || (tc.code != "" && body["error"] != tc.code) {
				t.Fatalf("got %d %v; want %d %s", code, body, tc.status, tc.code)
			}
		})
	}
	if got := f.storedRT(t, raw); got.RevokedAt != nil {
		t.Fatalf("a failed revocation changed the token: %+v", got)
	}
}
```

Run: `go test ./internal/oauth/ -run Revoke`
Expected: FAIL (`f.h.OauthRevoke` undefined).

- [ ] **Step 3: Implement**

Create `internal/oauth/revoke.go`:

```go
package oauth

import (
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// OauthRevoke implements POST /oauth/revoke (RFC 7009). Only refresh
// tokens are stored, so only they can be revoked; revoking one revokes its
// whole family (D-0013).
func (h *Handlers) OauthRevoke(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		writeError(w, serverError())
		return
	}
	if oerr := h.revoke(w, r, res); oerr != nil {
		writeError(w, oerr)
		return
	}
	noStore(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) revoke(w http.ResponseWriter, r *http.Request, res tenant.Resolved) *Error {
	ctx := r.Context()
	tenantID := res.Tenant.ID
	form, oerr := parseTokenRequest(w, r)
	if oerr != nil {
		return oerr
	}
	c, oerr := h.authenticateClient(ctx, r, form, tenantID)
	if oerr != nil {
		return oerr
	}
	token := form.Get("token")
	if token == "" {
		return invalidRequest("token is required")
	}
	rt, err := h.Store.RefreshTokens().GetByTokenHash(ctx, tenantID, secrets.HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil // RFC 7009 §2.2: unknown tokens are not an error
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load refresh token", "tenant", tenantID, "err", err)
		return serverError()
	}
	if rt.ClientID != c.ClientID {
		return invalidGrant("the token was not issued to this client")
	}
	if err := h.Store.RefreshTokens().RevokeFamily(ctx, tenantID, rt.FamilyID, h.now().UTC()); err != nil {
		h.log().ErrorContext(ctx, "revoke refresh tokens", "tenant", tenantID, "err", err)
		return serverError()
	}
	h.log().InfoContext(ctx, "refresh tokens revoked", "tenant", tenantID, "client_id", c.ClientID, "family", rt.FamilyID)
	return nil
}
```

- [ ] **Step 4: Wire it**

In `internal/server/server.go`:
- add the forwarder `func (a authAPI) OauthRevoke(w http.ResponseWriter, r *http.Request) { a.oauth.OauthRevoke(w, r) }`;
- add `tr.Options("/oauth/revoke", preflight)` next to the other preflight routes.

In `internal/server/cors.go`, change `case "/oauth/token", "/userinfo":` to `case "/oauth/token", "/oauth/revoke", "/userinfo":` and update the function comment.

In `internal/oidc/handlers.go`:
- add the field `RevocationEndpoint string `json:"revocation_endpoint"`` to `Configuration` after `TokenEndpoint`;
- set `RevocationEndpoint: base + "/oauth/revoke",` in `Discovery`.

In `internal/oidc/handlers_test.go` `TestDiscovery`, add `"revocation_endpoint": "https://acme.example.test/oauth/revoke",` to `want`.

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: PASS, and vet and gofmt print nothing.

- [ ] **Step 5: Decision and commit**

Append to `docs/compat/decisions.md`:

```markdown
## D-0013: Token revocation

- **Context:** `/oauth/revoke` revokes refresh tokens. Public docs do not say what happens for a token issued to another client or for access tokens.
- **Sources:** RFC 7009 §2.1–2.2; RFC 6749 §5.2 (`invalid_grant` covers a grant "issued to another client"); https://auth0.com/docs/secure/tokens/refresh-tokens/revoke-refresh-tokens.
- **Decision:**
  - The client authenticates as at the token endpoint.
  - An unknown token returns `200` with an empty body.
  - A token issued to another client returns `400 invalid_grant` and is left untouched.
  - A known token revokes its whole rotation family.
  - `token_type_hint` is ignored. Access tokens are JWTs and are not revocable, so presenting one is the same as presenting an unknown token.
- **Rationale:** It follows RFC 7009. Family-wide revocation matches what reuse detection does, so a revoked login cannot continue through an earlier successor.
```

```bash
git add api internal/gen internal/oauth internal/server internal/oidc docs/compat/decisions.md
git commit -m "feat(oauth): POST /oauth/revoke revokes a refresh token family"
```

---

### Task 7: Ending sessions and `GET /v2/logout`

**Files:**
- Modify: `internal/session/session.go`, `internal/session/session_test.go` (`End`)
- Create: `internal/ui/templates/logged_out.html`
- Modify: `internal/ui/ui.go`, `internal/ui/ui_test.go` (`RenderLoggedOut`)
- Create: `internal/oidc/logout.go`, `internal/oidc/logout_test.go`
- Modify: `internal/oidc/handlers.go` (`Sessions` field; package comment)
- Modify: `api/authentication.yaml` (operation `logout`); regenerate
- Modify: `internal/server/server.go` (forwarder; pass `Sessions` to `oidc.Handlers`)
- Modify: `docs/compat/decisions.md`

**Interfaces:**
- Consumes:
  - `authz.AllowedURL` (Task 3)
  - `store.Tenant.AllowedLogoutURLs`, `store.Client.AllowedLogoutURLs`
  - `ui.RenderError` and `ui.TenantView` (Plan 2)
- Produces:
  - `(*session.Manager).End(ctx, w, r, t *store.Tenant) (*store.LoginSession, error)`
  - `ui.RenderLoggedOut(w http.ResponseWriter, t ui.Tenant)`
  - `oidc.Handlers.Sessions *session.Manager`
  - `(*oidc.Handlers).Logout(w, r)`
  - helpers in `internal/oidc/logout.go`, all used by Task 8: `redirect`, `(*Handlers).endSession`, the `msgLogout*` constants, and the test env `newLogoutEnv`

- [ ] **Step 1: Write the failing session test**

Append to `internal/session/session_test.go`:

```go
func TestEnd(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	s, err := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()

	rec = httptest.NewRecorder()
	ended, err := m.End(ctx, rec, requestWith(cookies), tn)
	if err != nil || ended == nil || ended.ID != s.ID {
		t.Fatalf("End = %+v, %v", ended, err)
	}
	cleared := rec.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != CookieName || cleared[0].MaxAge >= 0 || !cleared[0].Secure ||
		!cleared[0].HttpOnly || cleared[0].SameSite != http.SameSiteNoneMode || cleared[0].Path != "/" {
		t.Fatalf("clearing cookie = %+v", cleared)
	}
	if got, err := m.Current(ctx, requestWith(cookies), tn); err != nil || got != nil {
		t.Fatalf("session survived End: %+v, %v", got, err)
	}
	// Ending again, or without a cookie, is not an error and still clears.
	rec = httptest.NewRecorder()
	if ended, err := m.End(ctx, rec, requestWith(cookies), tn); err != nil || ended != nil || len(rec.Result().Cookies()) != 1 {
		t.Fatalf("second End = %+v, %v, %v", ended, err, rec.Result().Cookies())
	}
	if ended, err := m.End(ctx, httptest.NewRecorder(), requestWith(nil), tn); err != nil || ended != nil {
		t.Fatalf("End without cookie = %+v, %v", ended, err)
	}
}
```

Run: `go test ./internal/session/`
Expected: FAIL (`m.End` undefined).

- [ ] **Step 2: Implement `End`**

Append to `internal/session/session.go`:

```go
// End deletes the request's session, if any, and clears the cookie. It
// returns the ended session, or nil if there was none.
func (m *Manager) End(ctx context.Context, w http.ResponseWriter, r *http.Request, t *store.Tenant) (*store.LoginSession, error) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode,
	})
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
	if err := m.Store.Sessions().Delete(ctx, t.ID, s.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	return s, nil
}
```

Run: `go test ./internal/session/`
Expected: PASS.

- [ ] **Step 3: Logged-out page**

Create `internal/ui/templates/logged_out.html`:

```html
{{define "title"}}You are logged out{{end}}
{{define "content"}}
<p>Your session has ended.</p>
<p class="alt">You can close this window.</p>
{{end}}
```

In `internal/ui/ui.go`, add `"logged_out"` to `pages`:

```go
		"logged_out": template.Must(template.ParseFS(files, "templates/layout.html", "templates/logged_out.html")),
```

and add:

```go
// RenderLoggedOut writes the page shown after a logout with nowhere to
// return to.
func RenderLoggedOut(w http.ResponseWriter, t Tenant) {
	render(w, http.StatusOK, "logged_out", t, nil, "'none'")
}
```

Append to `internal/ui/ui_test.go`:

```go
func TestRenderLoggedOut(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderLoggedOut(rec, Tenant{Name: "Acme"})
	csp := rec.Header().Get("Content-Security-Policy")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "logged out") ||
		!strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "form-action 'none'") {
		t.Fatalf("logged-out page = %d %q %s", rec.Code, csp, rec.Body)
	}
}
```

Run: `go test ./internal/ui/`
Expected: PASS. If `ui_test.go` lacks the `httptest` or `strings` import, add it.

- [ ] **Step 4: Contract**

In `api/authentication.yaml`, add after `/userinfo`:

```yaml
  /v2/logout:
    get:
      operationId: logout
      tags: [Login]
      summary: Log the user out
      description: |
        Ends the user's session with this tenant, then redirects to
        `returnTo`. With `client_id`, `returnTo` must be one of that
        application's allowed logout URLs; without it, one of the tenant's.
        The query string and fragment of `returnTo` are not compared, and the
        scheme and host are case-insensitive. With `client_id` and no
        `returnTo`, the application's first allowed logout URL is used;
        otherwise a logged-out page is shown.

        An unknown `client_id` or a `returnTo` that is not allowed shows an
        error page; the session is not ended and nothing is redirected.
        Refresh tokens are not revoked by logout.
      x-source:
        - https://auth0.com/docs/api/authentication
        - https://auth0.com/docs/authenticate/login/logout
        - https://auth0.com/docs/authenticate/login/logout/redirect-users-after-logout
      parameters:
        - {name: returnTo, in: query, schema: {type: string}, description: Where to send the browser after logout.}
        - {name: client_id, in: query, schema: {type: string}, description: The application asking for the logout.}
        - {name: federated, in: query, schema: {type: string}, description: Accepted and ignored; there are no upstream identity providers yet.}
      responses:
        "302":
          description: Logged out; redirect to `returnTo`.
        "200":
          description: Logged out; no return URL.
          content:
            text/html:
              schema: {type: string}
        "400":
          description: Unknown application or return URL not allowed. Not logged out.
          content:
            text/html:
              schema: {type: string}
        "404":
          $ref: "#/components/responses/UnknownTenant"
        "500":
          description: Error page.
          content:
            text/html:
              schema: {type: string}
```

Run: `go generate ./...`. The generated interface now has `Logout(w http.ResponseWriter, r *http.Request, params LogoutParams)`.

- [ ] **Step 5: Write the failing handler tests**

Create `internal/oidc/logout_test.go`:

```go
package oidc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

var logoutNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

type logoutEnv struct {
	st  store.Store
	km  *keys.Manager
	sm  *session.Manager
	tn  *store.Tenant
	mux *http.ServeMux
	srv http.Handler
}

// newLogoutEnv serves the logout endpoints for tenant acme. wrap lets a
// test substitute failing stores behind the session manager.
func newLogoutEnv(t *testing.T, wrap func(store.Store) store.Store) *logoutEnv {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	tn := &store.Tenant{ID: "ten_a", Name: "acme", Domains: []string{"acme.example.test"}, AllowedLogoutURLs: []string{"https://acme.test/bye"}}
	for _, x := range []*store.Tenant{tn, {ID: "ten_b", Name: "globex", Domains: []string{"globex.example.test"}}} {
		if err := st.Tenants().Create(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []*store.Client{
		{TenantID: "ten_a", ClientID: "spa", AllowedLogoutURLs: []string{
			"https://app.acme.test/bye", "https://app.acme.test/bye?from=oidc", "https://*.preview.acme.test/bye"}},
		{TenantID: "ten_a", ClientID: "other", AllowedLogoutURLs: []string{"https://other.acme.test/bye"}},
		{TenantID: "ten_a", ClientID: "wild-first", AllowedLogoutURLs: []string{"https://*.preview.acme.test/bye", "https://wild.acme.test/bye"}},
		{TenantID: "ten_a", ClientID: "no-urls"},
	} {
		if err := st.Clients().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	for _, id := range []string{"ten_a", "ten_b"} {
		if err := km.Ensure(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if wrap == nil {
		wrap = func(s store.Store) store.Store { return s }
	}
	clock := func() time.Time { return logoutNow }
	sm := &session.Manager{Store: wrap(st), Now: clock}
	h := &Handlers{Keys: km, Store: st, Sessions: sm, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: clock}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/logout", h.Logout)
	return &logoutEnv{st: st, km: km, sm: &session.Manager{Store: st, Now: clock}, tn: tn, mux: mux,
		srv: contract.Wrap(t, tenant.NewResolver(st.Tenants(), "", false).Middleware(mux))}
}

// login starts a session for auth0|1 and returns its cookie and record.
func (e *logoutEnv) login(t *testing.T) (*http.Cookie, *store.LoginSession) {
	t.Helper()
	rec := httptest.NewRecorder()
	s, err := e.sm.Start(context.Background(), rec, httptest.NewRequest("GET", "/", nil), e.tn, "auth0|1", "DB", logoutNow)
	if err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()[0], s
}

func (e *logoutEnv) do(t *testing.T, method, target string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, "https://acme.example.test"+target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, r)
	return rec
}

func (e *logoutEnv) alive(t *testing.T, s *store.LoginSession) bool {
	t.Helper()
	_, err := e.st.Sessions().GetByTokenHash(context.Background(), s.TenantID, s.TokenHash)
	return err == nil
}

func clearsSessionCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.CookieName && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func v2(q url.Values) string { return "/v2/logout?" + q.Encode() }

func TestV2LogoutRedirects(t *testing.T) {
	cases := map[string]struct {
		q    url.Values
		want string
	}{
		"client URL":           {url.Values{"client_id": {"spa"}, "returnTo": {"https://app.acme.test/bye"}}, "https://app.acme.test/bye"},
		"query not compared":   {url.Values{"client_id": {"spa"}, "returnTo": {"https://app.acme.test/bye?lang=en"}}, "https://app.acme.test/bye?lang=en"},
		"host case-insensitive": {url.Values{"client_id": {"spa"}, "returnTo": {"https://APP.acme.test/bye"}}, "https://APP.acme.test/bye"},
		"wildcard":             {url.Values{"client_id": {"spa"}, "returnTo": {"https://pr-7.preview.acme.test/bye"}}, "https://pr-7.preview.acme.test/bye"},
		"tenant URL":           {url.Values{"returnTo": {"https://acme.test/bye"}}, "https://acme.test/bye"},
		"first client URL":     {url.Values{"client_id": {"spa"}}, "https://app.acme.test/bye"},
		"first concrete URL":   {url.Values{"client_id": {"wild-first"}}, "https://wild.acme.test/bye"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			ck, s := e.login(t)
			rec := e.do(t, "GET", v2(tc.q), nil, ck)
			if rec.Code != 302 || rec.Header().Get("Location") != tc.want {
				t.Fatalf("got %d %q; want 302 %q", rec.Code, rec.Header().Get("Location"), tc.want)
			}
			if e.alive(t, s) || !clearsSessionCookie(rec) {
				t.Fatal("session not ended")
			}
		})
	}
}

func TestV2LogoutWithoutReturnTo(t *testing.T) {
	for name, q := range map[string]url.Values{"no client": {}, "client without URLs": {"client_id": {"no-urls"}}} {
		t.Run(name, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			ck, s := e.login(t)
			rec := e.do(t, "GET", v2(q), nil, ck)
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), "logged out") || e.alive(t, s) || !clearsSessionCookie(rec) {
				t.Fatalf("got %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestV2LogoutRefusesUnlistedReturnTo(t *testing.T) {
	cases := map[string]url.Values{
		"extra path segment":     {"client_id": {"spa"}, "returnTo": {"https://app.acme.test/bye/more"}},
		"suffix host":            {"client_id": {"spa"}, "returnTo": {"https://app.acme.test.evil.test/bye"}},
		"embedded in path":       {"client_id": {"spa"}, "returnTo": {"https://evil.test/https://app.acme.test/bye"}},
		"another client's URL":   {"client_id": {"spa"}, "returnTo": {"https://other.acme.test/bye"}},
		"tenant URL with client": {"client_id": {"spa"}, "returnTo": {"https://acme.test/bye"}},
		"client URL, no client":  {"returnTo": {"https://app.acme.test/bye"}},
		"javascript":             {"client_id": {"spa"}, "returnTo": {"javascript:alert(1)"}},
		"userinfo":               {"client_id": {"spa"}, "returnTo": {"https://evil.test@app.acme.test/bye"}},
		"unknown client":         {"client_id": {"nope"}, "returnTo": {"https://app.acme.test/bye"}},
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			ck, s := e.login(t)
			rec := e.do(t, "GET", v2(q), nil, ck)
			if rec.Code != 400 || rec.Header().Get("Location") != "" {
				t.Fatalf("got %d Location=%q", rec.Code, rec.Header().Get("Location"))
			}
			if !e.alive(t, s) || clearsSessionCookie(rec) {
				t.Fatal("an invalid logout request ended the session")
			}
		})
	}
}

func TestV2LogoutWithoutSession(t *testing.T) {
	e := newLogoutEnv(t, nil)
	ck, _ := e.login(t)
	q := url.Values{"client_id": {"spa"}, "returnTo": {"https://app.acme.test/bye"}}
	for i, cookies := range [][]*http.Cookie{nil, {ck}, {ck}} { // no cookie, then the same session twice
		rec := e.do(t, "GET", v2(q), nil, cookies...)
		if rec.Code != 302 || !clearsSessionCookie(rec) {
			t.Fatalf("call %d: got %d", i, rec.Code)
		}
	}
}

type failingSessionStore struct{ store.Store }

func (f failingSessionStore) Sessions() store.Sessions { return failingSessions{f.Store.Sessions()} }

type failingSessions struct{ store.Sessions }

func (failingSessions) GetByTokenHash(context.Context, string, string) (*store.LoginSession, error) {
	return nil, errors.New("database unavailable")
}

func TestV2LogoutStoreFailure(t *testing.T) {
	e := newLogoutEnv(t, func(s store.Store) store.Store { return failingSessionStore{s} })
	ck, _ := e.login(t)
	rec := e.do(t, "GET", v2(url.Values{"client_id": {"spa"}, "returnTo": {"https://app.acme.test/bye"}}), nil, ck)
	if rec.Code != 500 || rec.Header().Get("Location") != "" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("got %d %v", rec.Code, rec.Header())
	}
}
```

Run: `go test ./internal/oidc/`
Expected: FAIL (`Sessions` field and `h.Logout` undefined).

- [ ] **Step 6: Implement**

In `internal/oidc/handlers.go`:
- change the package comment to `// Package oidc serves OpenID Connect metadata (discovery, JWKS), /userinfo and the logout endpoints.`;
- add `Sessions *session.Manager` to `Handlers` and import `internal/session`.

Create `internal/oidc/logout.go`:

```go
package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// User-facing messages (original wording).
const (
	msgLogoutUnknownClient = "The application that asked to log you out is not registered. You are still logged in."
	msgLogoutURL           = "The address to return to after logout is not allowed for this application. You are still logged in."
	msgLogoutInvalid       = "The logout request was not valid. You are still logged in."
	msgLogoutServer        = "Something went wrong on our side. Please try again."
)

// Logout implements GET /v2/logout (D-0014). The request is validated
// before the session ends; an invalid request changes nothing.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	view := ui.TenantView(res.Tenant)
	q := r.URL.Query()
	returnTo := q.Get("returnTo")
	allowed := res.Tenant.AllowedLogoutURLs
	if id := q.Get("client_id"); id != "" {
		c, err := h.Store.Clients().Get(ctx, res.Tenant.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			ui.RenderError(w, http.StatusBadRequest, view, msgLogoutUnknownClient)
			return
		}
		if err != nil {
			h.log().ErrorContext(ctx, "load client", "tenant", res.Tenant.ID, "err", err)
			ui.RenderError(w, http.StatusInternalServerError, view, msgLogoutServer)
			return
		}
		allowed = c.AllowedLogoutURLs
		if returnTo == "" {
			returnTo = firstConcrete(allowed)
		}
	}
	if returnTo != "" && !returnToAllowed(allowed, returnTo) {
		ui.RenderError(w, http.StatusBadRequest, view, msgLogoutURL)
		return
	}
	if !h.endSession(w, r, res, view) {
		return
	}
	if returnTo == "" {
		ui.RenderLoggedOut(w, view)
		return
	}
	redirect(w, r, returnTo)
}

// returnToAllowed applies the /v2/logout rule: the query string and
// fragment of returnTo are not compared, and scheme and host are
// case-insensitive.
func returnToAllowed(allowed []string, returnTo string) bool {
	u, err := url.Parse(returnTo)
	if err != nil || u.Scheme == "" || u.User != nil {
		return false
	}
	u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = "", false, "", ""
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	return authz.AllowedURL(allowed, u.String())
}

// firstConcrete returns the first allowed URL that is not a wildcard
// pattern, or "".
func firstConcrete(allowed []string) string {
	for _, u := range allowed {
		if !strings.Contains(u, "*") {
			return u
		}
	}
	return ""
}

// endSession ends the browser's session. On a store failure it renders the
// error page and returns false.
func (h *Handlers) endSession(w http.ResponseWriter, r *http.Request, res tenant.Resolved, view ui.Tenant) bool {
	ctx := r.Context()
	s, err := h.Sessions.End(ctx, w, r, res.Tenant)
	if err != nil {
		h.log().ErrorContext(ctx, "end session", "tenant", res.Tenant.ID, "err", err)
		ui.RenderError(w, http.StatusInternalServerError, view, msgLogoutServer)
		return false
	}
	if s != nil {
		h.log().InfoContext(ctx, "logged out", "tenant", res.Tenant.ID, "session", s.ID, "user_id", s.UserID)
	}
	return true
}

func redirect(w http.ResponseWriter, r *http.Request, to string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, to, http.StatusFound)
}
```

In `internal/server/server.go`:
- add the forwarder `func (a authAPI) Logout(w http.ResponseWriter, r *http.Request, _ authapi.LogoutParams) { a.oidc.Logout(w, r) }`;
- set `Sessions: d.Sessions` in the `oidc.Handlers` literal.

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: PASS, and vet and gofmt print nothing.

- [ ] **Step 7: Decision and commit**

Append to `docs/compat/decisions.md`:

```markdown
## D-0014: Logout

- **Context:** Public docs describe `/v2/logout` and `/oidc/logout` and their allowed logout URLs. Some edge cases are not covered: a request with no client and no return URL, what an invalid request does to the session, and refresh tokens.
- **Sources:**
  - https://auth0.com/docs/authenticate/login/logout/redirect-users-after-logout
  - https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0
  - OpenID Connect RP-Initiated Logout 1.0 §2–§3
  - RFC 9700 §4.11 (open redirection)
- **Decision:**
  - Every logout request is validated before the session ends. An invalid request shows an error page (400), keeps the session, and never redirects.
  - **`/v2/logout`:**
    - `returnTo` is checked against the client's allowed logout URLs when `client_id` is present, otherwise the tenant's.
    - It is compared without its query string and fragment, with scheme and host case-insensitive. The single-label wildcard host form is allowed.
    - With `client_id` and no `returnTo`, the browser goes to the client's first non-wildcard allowed logout URL. With neither, a logged-out page is shown.
    - `federated` is ignored.
  - **`/oidc/logout`:** see D-0015.
  - Logout deletes the server-side session and clears the cookie. Refresh tokens are not revoked; applications revoke them at `/oauth/revoke`.
- **Rationale:** Validating first means a malformed or malicious link can neither redirect elsewhere nor log the user out while claiming failure. Keeping refresh tokens matches the public docs, which describe revocation as a separate step.
```

```bash
git add api internal/gen internal/session internal/ui internal/oidc internal/server docs/compat/decisions.md
git commit -m "feat(oidc): GET /v2/logout with validated returnTo"
```

---

### Task 8: `GET|POST /oidc/logout` (RP-Initiated Logout) with confirmation

**Files:**
- Modify: `internal/session/session.go`, `internal/session/session_test.go` (`Lookup`)
- Create: `internal/ui/templates/logout_confirm.html`
- Modify: `internal/ui/ui.go`, `internal/ui/ui_test.go` (`RenderLogoutConfirm`)
- Create: `internal/oidc/rp_logout.go`
- Modify: `internal/oidc/logout_test.go` (register routes; add tests)
- Modify: `internal/oidc/handlers.go`, `internal/oidc/handlers_test.go` (`end_session_endpoint`)
- Modify: `api/authentication.yaml` (operations `oidcLogout`, `oidcLogoutPost`; schema `OidcLogoutRequest`; discovery field); regenerate
- Modify: `internal/server/server.go` (forwarders)
- Modify: `docs/compat/decisions.md`

**Interfaces:**
- Consumes:
  - from Task 7: `endSession`, `redirect`, the `msgLogout*` constants, `newLogoutEnv`, `logoutEnv.{login,do,alive}` and `clearsSessionCookie`
  - `keys.Manager.Verify` and `keys.ErrInvalidToken`
  - `authz.AllowedURL`
- Produces:
  - `(*session.Manager).Lookup(ctx, r, t) (*store.LoginSession, error)`, which does not slide the idle expiry
  - `ui.LogoutConfirmData{CSRF string; Fields url.Values; RedirectURI string}`
  - `ui.RenderLogoutConfirm(w, t ui.Tenant, d ui.LogoutConfirmData)`
  - `(*oidc.Handlers).OidcLogout(w, r)` for both methods
  - `oidc.Configuration.EndSessionEndpoint`

- [ ] **Step 1: Write the failing `Lookup` test**

Append to `internal/session/session_test.go`:

```go
func TestLookupDoesNotSlide(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	s, err := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	c.t = c.t.Add(time.Hour)
	got, err := m.Lookup(ctx, requestWith(cookies), tn)
	if err != nil || got == nil || got.ID != s.ID || !got.IdleExpiresAt.Equal(s.IdleExpiresAt) {
		t.Fatalf("Lookup = %+v, %v", got, err)
	}
	stored, _ := m.Store.Sessions().GetByTokenHash(ctx, tn.ID, s.TokenHash)
	if !stored.IdleExpiresAt.Equal(s.IdleExpiresAt) {
		t.Fatal("Lookup extended the idle expiry")
	}
	c.t = s.IdleExpiresAt
	if got, err := m.Lookup(ctx, requestWith(cookies), tn); err != nil || got != nil {
		t.Fatalf("expired Lookup = %+v, %v", got, err)
	}
	if got, err := m.Lookup(ctx, requestWith(nil), tn); err != nil || got != nil {
		t.Fatalf("Lookup without cookie = %+v, %v", got, err)
	}
}
```

Run: `go test ./internal/session/`
Expected: FAIL (`m.Lookup` undefined).

- [ ] **Step 2: Implement `Lookup`**

Append to `internal/session/session.go`:

```go
// Lookup returns the request's unexpired session for t, or nil, without
// extending it. Logout uses it to decide whether to ask for confirmation.
func (m *Manager) Lookup(ctx context.Context, r *http.Request, t *store.Tenant) (*store.LoginSession, error) {
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
		return nil, nil
	}
	return s, nil
}
```

Run: `go test ./internal/session/`
Expected: PASS.

- [ ] **Step 3: Confirmation page**

Create `internal/ui/templates/logout_confirm.html`:

```html
{{define "title"}}Log out?{{end}}
{{define "content"}}
<p>An application asked to end your session. Do you want to log out?</p>
<form method="post" action="/oidc/logout">
<input type="hidden" name="csrf" value="{{.Data.CSRF}}">
<input type="hidden" name="confirm" value="yes">
{{range $name, $values := .Data.Fields}}{{range $values}}<input type="hidden" name="{{$name}}" value="{{.}}">
{{end}}{{end}}<button type="submit">Log out</button>
</form>
{{end}}
```

In `internal/ui/ui.go`, add to `pages`:

```go
		"logout_confirm": template.Must(template.ParseFS(files, "templates/layout.html", "templates/logout_confirm.html")),
```

and add:

```go
// LogoutConfirmData is the logout confirmation page.
type LogoutConfirmData struct {
	CSRF   string
	Fields url.Values // the logout request, posted again on confirmation
	// RedirectURI is where the browser goes after logout; its origin is
	// allowed as a form-action (D-0010).
	RedirectURI string
}

// RenderLogoutConfirm asks the user to confirm an RP-initiated logout.
func RenderLogoutConfirm(w http.ResponseWriter, t Tenant, d LogoutConfirmData) {
	render(w, http.StatusOK, "logout_confirm", t, d, formActionFor(d.RedirectURI))
}
```

Append to `internal/ui/ui_test.go` (add the `"net/url"` import if missing):

```go
func TestRenderLogoutConfirm(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderLogoutConfirm(rec, Tenant{Name: "Acme"}, LogoutConfirmData{
		CSRF:        "tok",
		Fields:      url.Values{"state": {`"><script>alert(1)</script>`}, "client_id": {"spa"}},
		RedirectURI: "https://app.acme.test/bye",
	})
	body, csp := rec.Body.String(), rec.Header().Get("Content-Security-Policy")
	if rec.Code != 200 || !strings.Contains(body, `name="csrf" value="tok"`) || !strings.Contains(body, `name="client_id" value="spa"`) ||
		strings.Contains(body, "<script>alert(1)") || !strings.Contains(csp, "form-action 'self' https://app.acme.test;") {
		t.Fatalf("confirmation page = %d %q\n%s", rec.Code, csp, body)
	}
}
```

Run: `go test ./internal/ui/`
Expected: PASS.

- [ ] **Step 4: Contract**

In `api/authentication.yaml`, add after `/v2/logout`:

```yaml
  /oidc/logout:
    get:
      operationId: oidcLogout
      tags: [Login]
      summary: Log the user out (OpenID Connect RP-Initiated Logout)
      description: |
        Ends the user's session and redirects to `post_logout_redirect_uri`
        with `state`. The URI must exactly match (including any query
        string) an allowed logout URL of the application named by
        `id_token_hint` or `client_id`, or of the tenant when neither is
        given. `id_token_hint` may be expired.

        If the browser has a session and neither the hint's `sid` nor
        `logout_hint` matches it, a confirmation page is shown first.
        Invalid requests (a bad or foreign `id_token_hint`, contradicting
        hints, an unknown application, an unregistered URI) show an error
        page and do not end the session.
      x-source:
        - https://openid.net/specs/openid-connect-rpinitiated-1_0.html
        - https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0
      parameters:
        - {name: id_token_hint, in: query, schema: {type: string}, description: An ID token this tenant issued to the user.}
        - {name: logout_hint, in: query, schema: {type: string}, description: The session ID (`sid`) to end.}
        - {name: client_id, in: query, schema: {type: string}, description: The application asking for the logout.}
        - {name: post_logout_redirect_uri, in: query, schema: {type: string}, description: Where to send the browser after logout.}
        - {name: state, in: query, schema: {type: string}, description: Returned unchanged on the redirect.}
        - {name: ui_locales, in: query, schema: {type: string}, description: Accepted and ignored.}
      responses:
        "302":
          description: Logged out; redirect to `post_logout_redirect_uri`.
        "200":
          description: Logged-out page, or the logout confirmation page.
          content:
            text/html:
              schema: {type: string}
        "400":
          description: Invalid logout request. Not logged out.
          content:
            text/html:
              schema: {type: string}
        "404":
          $ref: "#/components/responses/UnknownTenant"
        "500":
          description: Error page.
          content:
            text/html:
              schema: {type: string}
    post:
      operationId: oidcLogoutPost
      tags: [Login]
      summary: Log the user out (form post)
      description: Same as `GET /oidc/logout` with the parameters in a form body. The confirmation page posts here with `confirm=yes` and its `csrf` token.
      x-source:
        - https://openid.net/specs/openid-connect-rpinitiated-1_0.html
      requestBody:
        required: true
        content:
          application/x-www-form-urlencoded:
            schema:
              $ref: "#/components/schemas/OidcLogoutRequest"
      responses:
        "302":
          description: Logged out; redirect to `post_logout_redirect_uri`.
        "200":
          description: Logged-out page, or the logout confirmation page.
          content:
            text/html:
              schema: {type: string}
        "400":
          description: Invalid logout request. Not logged out.
          content:
            text/html:
              schema: {type: string}
        "404":
          $ref: "#/components/responses/UnknownTenant"
        "500":
          description: Error page.
          content:
            text/html:
              schema: {type: string}
```

Under `components.schemas`, add:

```yaml
    OidcLogoutRequest:
      type: object
      properties:
        id_token_hint: {type: string}
        logout_hint: {type: string}
        client_id: {type: string}
        post_logout_redirect_uri: {type: string}
        state: {type: string}
        ui_locales: {type: string}
        confirm:
          type: string
          description: Set by the confirmation page.
        csrf:
          type: string
          description: Set by the confirmation page.
```

In `OpenIDConfiguration.properties`, add `end_session_endpoint: {type: string, format: uri}`.

Run: `go generate ./...`. The interface gains `OidcLogout(w, r, params OidcLogoutParams)` and `OidcLogoutPost(w, r)`.

- [ ] **Step 5: Write the failing handler tests**

In `internal/oidc/logout_test.go` `newLogoutEnv`, after `mux.HandleFunc("GET /v2/logout", h.Logout)`, add:

```go
	mux.HandleFunc("GET /oidc/logout", h.OidcLogout)
	mux.HandleFunc("POST /oidc/logout", h.OidcLogout)
```

Append to the file (add `"regexp"` to the imports):

```go
// idToken signs an ID token for auth0|1 issued to spa, with overrides
// (a nil value deletes the claim).
func (e *logoutEnv) idToken(t *testing.T, tenantID string, over map[string]any) string {
	t.Helper()
	c := map[string]any{"iss": "https://acme.example.test/", "sub": "auth0|1", "aud": "spa",
		"iat": logoutNow.Unix(), "exp": logoutNow.Add(time.Hour).Unix()}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	raw, err := e.km.Sign(context.Background(), tenantID, c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rp(q url.Values) string { return "/oidc/logout?" + q.Encode() }

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func TestOidcLogoutWithMatchingHint(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			ck, s := e.login(t)
			q := url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"sid": s.ID})},
				"post_logout_redirect_uri": {"https://app.acme.test/bye"}, "state": {"xyz"}}
			var rec *httptest.ResponseRecorder
			if method == "GET" {
				rec = e.do(t, "GET", rp(q), nil, ck)
			} else {
				rec = e.do(t, "POST", "/oidc/logout", q, ck)
			}
			if rec.Code != 302 || rec.Header().Get("Location") != "https://app.acme.test/bye?state=xyz" {
				t.Fatalf("got %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body)
			}
			if e.alive(t, s) || !clearsSessionCookie(rec) {
				t.Fatal("session not ended")
			}
		})
	}
}

func TestOidcLogoutAccepted(t *testing.T) {
	cases := map[string]struct {
		q    func(e *logoutEnv, s *store.LoginSession) url.Values
		code int
		loc  string
	}{
		"expired hint": {func(e *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"sid": s.ID,
				"iat": logoutNow.Add(-2 * time.Hour).Unix(), "exp": logoutNow.Add(-time.Hour).Unix()})},
				"post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		}, 302, "https://app.acme.test/bye"},
		"logout_hint with tenant URL": {func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"logout_hint": {s.ID}, "post_logout_redirect_uri": {"https://acme.test/bye"}}
		}, 302, "https://acme.test/bye"},
		"registered query kept": {func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"spa"}, "logout_hint": {s.ID}, "state": {"s1"},
				"post_logout_redirect_uri": {"https://app.acme.test/bye?from=oidc"}}
		}, 302, "https://app.acme.test/bye?from=oidc&state=s1"},
		"no redirect uri": {func(e *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"sid": s.ID})}}
		}, 200, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			ck, s := e.login(t)
			rec := e.do(t, "GET", rp(tc.q(e, s)), nil, ck)
			if rec.Code != tc.code || rec.Header().Get("Location") != tc.loc || e.alive(t, s) {
				t.Fatalf("got %d %q alive=%v %s", rec.Code, rec.Header().Get("Location"), e.alive(t, s), rec.Body)
			}
		})
	}
}

func TestOidcLogoutWithoutSessionSkipsConfirmation(t *testing.T) {
	e := newLogoutEnv(t, nil)
	rec := e.do(t, "GET", rp(url.Values{"client_id": {"spa"}, "post_logout_redirect_uri": {"https://app.acme.test/bye"}}), nil)
	if rec.Code != 302 || rec.Header().Get("Location") != "https://app.acme.test/bye" {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestOidcLogoutConfirmation(t *testing.T) {
	e := newLogoutEnv(t, nil)
	ck, s := e.login(t)
	params := url.Values{"client_id": {"spa"}, "post_logout_redirect_uri": {"https://app.acme.test/bye"}, "state": {"st"}}

	// No hint: ask first.
	rec := e.do(t, "GET", rp(params), nil, ck)
	m := csrfField.FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || m == nil || !e.alive(t, s) ||
		!strings.Contains(rec.Header().Get("Content-Security-Policy"), "form-action 'self' https://app.acme.test;") {
		t.Fatalf("confirmation = %d alive=%v %s", rec.Code, e.alive(t, s), rec.Body)
	}
	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "za_logout" {
			csrfCookie = c
		}
	}
	if csrfCookie == nil || !csrfCookie.HttpOnly || !csrfCookie.Secure || csrfCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("confirmation cookie = %+v", csrfCookie)
	}
	confirm := func(token string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		f := url.Values{"confirm": {"yes"}, "csrf": {token}}
		for k, v := range params {
			f[k] = v
		}
		return e.do(t, "POST", "/oidc/logout", f, cookies...)
	}
	// A forged confirmation fails and keeps the session.
	if rec := confirm("wrong", ck, csrfCookie); rec.Code != 400 || !e.alive(t, s) {
		t.Fatalf("wrong token = %d", rec.Code)
	}
	if rec := confirm(m[1], ck); rec.Code != 400 || !e.alive(t, s) {
		t.Fatalf("missing cookie = %d", rec.Code)
	}
	// The real confirmation logs out.
	rec = confirm(m[1], ck, csrfCookie)
	if rec.Code != 302 || rec.Header().Get("Location") != "https://app.acme.test/bye?state=st" || e.alive(t, s) {
		t.Fatalf("confirmed = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestOidcLogoutHintForAnotherSessionAsksFirst(t *testing.T) {
	e := newLogoutEnv(t, nil)
	ck, s := e.login(t)
	q := url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"sid": "some-other-session"})},
		"post_logout_redirect_uri": {"https://app.acme.test/bye"}}
	if rec := e.do(t, "GET", rp(q), nil, ck); rec.Code != 200 || csrfField.FindString(rec.Body.String()) == "" || !e.alive(t, s) {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestOidcLogoutRejects(t *testing.T) {
	cases := map[string]func(e *logoutEnv, s *store.LoginSession) url.Values{
		"garbage hint": func(*logoutEnv, *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {"not-a-jwt"}, "post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		},
		"hint from another tenant": func(e *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {e.idToken(t, "ten_b", map[string]any{"iss": "https://globex.example.test/", "sid": s.ID})},
				"post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		},
		"hint with foreign issuer": func(e *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"iss": "https://evil.test/", "sid": s.ID})},
				"post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		},
		"hint for another client": func(e *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"sid": s.ID})}, "client_id": {"other"},
				"post_logout_redirect_uri": {"https://other.acme.test/bye"}}
		},
		"unregistered uri": func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"spa"}, "logout_hint": {s.ID}, "post_logout_redirect_uri": {"https://evil.test/bye"}}
		},
		"another client's uri": func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"spa"}, "logout_hint": {s.ID}, "post_logout_redirect_uri": {"https://other.acme.test/bye"}}
		},
		"query differs": func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"spa"}, "logout_hint": {s.ID}, "post_logout_redirect_uri": {"https://app.acme.test/bye?from=x"}}
		},
		"client uri without client": func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"logout_hint": {s.ID}, "post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		},
		"contradicting hints": func(e *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"sid": s.ID})}, "logout_hint": {"another-sid"},
				"post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		},
		"unknown client": func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"nope"}, "logout_hint": {s.ID}, "post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		},
		"javascript uri": func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"spa"}, "logout_hint": {s.ID}, "post_logout_redirect_uri": {"javascript:alert(1)"}}
		},
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			ck, s := e.login(t)
			rec := e.do(t, "GET", rp(q(e, s)), nil, ck)
			if rec.Code != 400 || rec.Header().Get("Location") != "" || !e.alive(t, s) || clearsSessionCookie(rec) {
				t.Fatalf("got %d Location=%q alive=%v", rec.Code, rec.Header().Get("Location"), e.alive(t, s))
			}
		})
	}
}
```

Run: `go test ./internal/oidc/`
Expected: FAIL (`h.OidcLogout` undefined).

- [ ] **Step 6: Implement**

Create `internal/oidc/rp_logout.go`:

```go
package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// logoutCSRFCookie binds a logout confirmation form to the browser that
// was shown it.
const logoutCSRFCookie = "za_logout"

const maxLogoutFormBytes = 16 << 10

// confirmedFields are the request parameters the confirmation page posts
// back.
var confirmedFields = []string{"id_token_hint", "logout_hint", "client_id", "post_logout_redirect_uri", "state"}

// OidcLogout implements OpenID Connect RP-Initiated Logout 1.0 at GET and
// POST /oidc/logout (D-0015). The request is validated before anything
// changes; without a hint that matches the browser's session the user is
// asked to confirm.
func (h *Handlers) OidcLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	view := ui.TenantView(res.Tenant)
	fail := func(status int, msg string) { ui.RenderError(w, status, view, msg) }
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxLogoutFormBytes)
	}
	if err := r.ParseForm(); err != nil {
		fail(http.StatusBadRequest, msgLogoutInvalid)
		return
	}
	p := r.Form
	confirmed := r.Method == http.MethodPost && p.Get("confirm") == "yes"
	if confirmed && !confirmationValid(r, p.Get("csrf")) {
		fail(http.StatusBadRequest, msgLogoutInvalid)
		return
	}

	clientID, hintSID := p.Get("client_id"), ""
	if raw := p.Get("id_token_hint"); raw != "" {
		aud, sid, ok, err := h.idTokenHint(ctx, res, raw)
		if err != nil {
			h.log().ErrorContext(ctx, "verify id_token_hint", "tenant", res.Tenant.ID, "err", err)
			fail(http.StatusInternalServerError, msgLogoutServer)
			return
		}
		if !ok || (clientID != "" && clientID != aud) {
			fail(http.StatusBadRequest, msgLogoutInvalid)
			return
		}
		clientID, hintSID = aud, sid
	}
	logoutHint := p.Get("logout_hint")
	if hintSID != "" && logoutHint != "" && hintSID != logoutHint {
		fail(http.StatusBadRequest, msgLogoutInvalid)
		return
	}

	allowed := res.Tenant.AllowedLogoutURLs
	if clientID != "" {
		c, err := h.Store.Clients().Get(ctx, res.Tenant.ID, clientID)
		if errors.Is(err, store.ErrNotFound) {
			fail(http.StatusBadRequest, msgLogoutUnknownClient)
			return
		}
		if err != nil {
			h.log().ErrorContext(ctx, "load client", "tenant", res.Tenant.ID, "err", err)
			fail(http.StatusInternalServerError, msgLogoutServer)
			return
		}
		allowed = c.AllowedLogoutURLs
	}
	target := p.Get("post_logout_redirect_uri")
	if target != "" && !authz.AllowedURL(allowed, target) {
		fail(http.StatusBadRequest, msgLogoutURL)
		return
	}

	sess, err := h.Sessions.Lookup(ctx, r, res.Tenant)
	if err != nil {
		h.log().ErrorContext(ctx, "load session", "tenant", res.Tenant.ID, "err", err)
		fail(http.StatusInternalServerError, msgLogoutServer)
		return
	}
	hinted := sess != nil && ((hintSID != "" && hintSID == sess.ID) || (logoutHint != "" && logoutHint == sess.ID))
	if sess != nil && !hinted && !confirmed {
		h.renderLogoutConfirm(w, view, p, target)
		return
	}
	if confirmed {
		http.SetCookie(w, &http.Cookie{Name: logoutCSRFCookie, Value: "", Path: "/oidc/logout", MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	}
	if !h.endSession(w, r, res, view) {
		return
	}
	if target == "" {
		ui.RenderLoggedOut(w, view)
		return
	}
	if state := p.Get("state"); state != "" {
		u, _ := url.Parse(target) // AllowedURL accepted it, so it parses
		q := u.Query()
		q.Set("state", state)
		u.RawQuery = q.Encode()
		target = u.String()
	}
	redirect(w, r, target)
}

// idTokenHint verifies an ID token this tenant issued and returns its
// audience and sid. Expired tokens are accepted (RP-Initiated Logout §2).
// ok is false for tokens that are invalid; err is set only for internal
// failures.
func (h *Handlers) idTokenHint(ctx context.Context, res tenant.Resolved, raw string) (aud, sid string, ok bool, err error) {
	var std jwt.Claims
	var extra struct {
		SID string `json:"sid"`
	}
	if err := h.Keys.Verify(ctx, res.Tenant.ID, raw, &std, &extra); err != nil {
		if errors.Is(err, keys.ErrInvalidToken) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	if std.Issuer != res.Issuer() || len(std.Audience) != 1 {
		return "", "", false, nil
	}
	return std.Audience[0], extra.SID, true, nil
}

func (h *Handlers) renderLogoutConfirm(w http.ResponseWriter, view ui.Tenant, p url.Values, target string) {
	token := secrets.RandomString(32)
	http.SetCookie(w, &http.Cookie{Name: logoutCSRFCookie, Value: token, Path: "/oidc/logout", MaxAge: 600,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	fields := url.Values{}
	for _, k := range confirmedFields {
		if v := p.Get(k); v != "" {
			fields.Set(k, v)
		}
	}
	ui.RenderLogoutConfirm(w, view, ui.LogoutConfirmData{CSRF: token, Fields: fields, RedirectURI: target})
}

// confirmationValid reports whether the posted csrf token equals the
// browser's za_logout cookie.
func confirmationValid(r *http.Request, csrf string) bool {
	c, err := r.Cookie(logoutCSRFCookie)
	return err == nil && c.Value != "" && csrf != "" && subtle.ConstantTimeCompare([]byte(c.Value), []byte(csrf)) == 1
}
```

In `internal/oidc/handlers.go`:
- add `EndSessionEndpoint string `json:"end_session_endpoint"`` to `Configuration` after `JWKSURI`;
- set `EndSessionEndpoint: base + "/oidc/logout",` in `Discovery`.

In `internal/oidc/handlers_test.go` `TestDiscovery`, add `"end_session_endpoint": "https://acme.example.test/oidc/logout",` to `want`.

In `internal/server/server.go`, add:

```go
func (a authAPI) OidcLogout(w http.ResponseWriter, r *http.Request, _ authapi.OidcLogoutParams) {
	a.oidc.OidcLogout(w, r)
}
func (a authAPI) OidcLogoutPost(w http.ResponseWriter, r *http.Request) { a.oidc.OidcLogout(w, r) }
```

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: PASS, and vet and gofmt print nothing.

- [ ] **Step 7: Decision and commit**

Append to `docs/compat/decisions.md`:

```markdown
## D-0015: RP-Initiated Logout (`/oidc/logout`)

- **Context:** Public docs list the `/oidc/logout` parameters, a confirmation prompt when no hint matches the session, exact matching of `post_logout_redirect_uri`, and errors for inconsistent hints. They do not say how the confirmation is protected or how expired hints are treated.
- **Sources:** OpenID Connect RP-Initiated Logout 1.0 §2–§3; https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0; OWASP CSRF Prevention Cheat Sheet.
- **Decision:**
  - **Hints:**
    - `id_token_hint` must be signed by the tenant's published keys and carry the tenant issuer. Expiry is ignored.
    - Its single audience names the client, and must equal `client_id` if both are sent.
    - Its `sid` and `logout_hint` must agree when both are present.
  - **Allowed URLs:**
    - `post_logout_redirect_uri` must match exactly (including the query string) an allowed logout URL. The list is the client's when a client is known, otherwise the tenant's.
    - `state` is added to the redirect's query.
  - **Confirmation:**
    - When the browser has a session and no hint matches it, a confirmation page is shown.
    - The page posts back with a CSRF token. The token is bound to an `HttpOnly; Secure; SameSite=Strict` cookie `za_logout` on path `/oidc/logout` that lives 10 minutes.
    - Without a session there is nothing to confirm, and the request proceeds.
  - `ui_locales` is ignored.
- **Rationale:** It follows the documented behavior. The confirmation stops cross-site requests from silently ending sessions, and the CSRF binding stops them from auto-submitting the confirmation.
```

```bash
git add api internal/gen internal/session internal/ui internal/oidc internal/server docs/compat/decisions.md
git commit -m "feat(oidc): RP-initiated logout at /oidc/logout with confirmation"
```

---

### Task 9: In-process flow test: refresh, reuse, revoke, logout

This task drives the real router over TLS, the same way Plan 2's `TestEndToEndCodeFlow` does. It proves that the pieces are wired together: the contract, CORS, cookies, and the generated routes for the new operations.

**Files:**
- Modify: `internal/server/flow_test.go`

**Interfaces:**
- Consumes: the whole server (`server.New`), plus `newFlowEnv`, `authorizeURL`, `mustDo`, `fetch` and `csrfRe` from Plan 2.
- Produces: the test helpers `(*flowEnv).codeFlow` and `(*flowEnv).postForm`.

- [ ] **Step 1: Extend the flow seed**

In `flowSeed`:
- add `allow_offline_access: true` to the resource server:
  `- {identifier: "https://api.flow.test", name: API, allow_offline_access: true, scopes: [{value: "read:things"}]}`
- set the `spa` client's `grant_types: [authorization_code, refresh_token]`;
- add `allowed_logout_urls: ["https://app.flow.test/bye"]` to the `spa` client.

Run: `go test ./internal/server/`
Expected: PASS (the existing tests are unaffected).

- [ ] **Step 2: Write the test**

Append to `internal/server/flow_test.go`:

```go
// postForm posts a form from the SPA's origin and decodes a JSON reply.
func (e *flowEnv) postForm(t *testing.T, c *http.Client, path string, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://app.flow.test")
	resp, body := mustDo(t, c, req)
	var out map[string]any
	_ = json.Unmarshal([]byte(body), &out)
	return resp, out
}

// codeFlow runs /authorize (logging in if needed) and exchanges the code.
func (e *flowEnv) codeFlow(t *testing.T, c *http.Client, extra ...string) map[string]any {
	t.Helper()
	resp, _ := fetch(t, c, authorizeURL(e.base, extra...))
	loc, _ := resp.Location()
	if loc != nil && loc.Path == "/u/login" {
		_, page := fetch(t, c, loc.String())
		csrf := csrfRe.FindStringSubmatch(page)
		if csrf == nil {
			t.Fatalf("no csrf: %s", page)
		}
		form := url.Values{"state": {loc.Query().Get("state")}, "csrf": {csrf[1]}, "username": {"alice@flow.test"}, "password": {"alice password 1"}}
		req, _ := http.NewRequest("POST", e.base+"/u/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, _ = mustDo(t, c, req)
		loc, _ = resp.Location()
	}
	if loc == nil || loc.Host != "app.flow.test" || loc.Query().Get("code") == "" {
		t.Fatalf("authorize ended at %v (status %d)", loc, resp.StatusCode)
	}
	resp, tok := e.postForm(t, c, "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"spa"},
		"code": {loc.Query().Get("code")}, "redirect_uri": {"https://app.flow.test/cb"}, "code_verifier": {verifier}})
	if resp.StatusCode != 200 {
		t.Fatalf("code exchange = %d %v", resp.StatusCode, tok)
	}
	return tok
}

func TestEndToEndRefreshAndLogout(t *testing.T) {
	e := newFlowEnv(t)
	c := e.client(t)
	refresh := func(token string) (*http.Response, map[string]any) {
		return e.postForm(t, c, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {token}})
	}

	// 1. offline_access yields a refresh token.
	tok := e.codeFlow(t, c, "scope", "openid offline_access read:things")
	first, _ := tok["refresh_token"].(string)
	if first == "" || tok["scope"] != "openid offline_access read:things" {
		t.Fatalf("token response = %v", tok)
	}
	// 2. Refreshing rotates, cross-origin, with an ID token.
	resp, body := refresh(first)
	second, _ := body["refresh_token"].(string)
	if resp.StatusCode != 200 || second == "" || second == first || body["id_token"] == nil ||
		resp.Header.Get("Access-Control-Allow-Origin") != "https://app.flow.test" {
		t.Fatalf("refresh = %d %v %v", resp.StatusCode, resp.Header, body)
	}
	// 3. Reusing the rotated token revokes the family.
	if resp, body := refresh(first); resp.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("reuse = %d %v", resp.StatusCode, body)
	}
	if resp, body := refresh(second); resp.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("successor after reuse = %d %v", resp.StatusCode, body)
	}
	// 4. The session still works: a new login gives a new family, which
	//    /oauth/revoke ends.
	tok = e.codeFlow(t, c, "scope", "openid offline_access")
	third := tok["refresh_token"].(string)
	if resp, body := e.postForm(t, c, "/oauth/revoke", url.Values{"client_id": {"spa"}, "token": {third}}); resp.StatusCode != 200 {
		t.Fatalf("revoke = %d %v", resp.StatusCode, body)
	}
	if resp, _ := refresh(third); resp.StatusCode != 400 {
		t.Fatalf("refresh after revoke = %d", resp.StatusCode)
	}
	// 5. /v2/logout ends the session and returns to the app.
	resp, _ = fetch(t, c, e.base+"/v2/logout?"+url.Values{"client_id": {"spa"}, "returnTo": {"https://app.flow.test/bye"}}.Encode())
	if loc, _ := resp.Location(); resp.StatusCode != 302 || loc.String() != "https://app.flow.test/bye" {
		t.Fatalf("logout = %d %v", resp.StatusCode, loc)
	}
	// 6. Silent authentication now reports login_required.
	resp, page := fetch(t, c, authorizeURL(e.base, "prompt", "none", "response_mode", "web_message"))
	if resp.StatusCode != 200 || !strings.Contains(page, "login_required") {
		t.Fatalf("silent auth after logout = %d %s", resp.StatusCode, page)
	}
	// 7. Discovery advertises the new endpoints.
	_, doc := fetch(t, c, e.base+"/.well-known/openid-configuration")
	for _, want := range []string{`"end_session_endpoint":"` + e.base + `/oidc/logout"`, `"revocation_endpoint":"` + e.base + `/oauth/revoke"`, `"refresh_token"`, `"offline_access"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("discovery lacks %s", want)
		}
	}
}
```

- [ ] **Step 3: Run it**

Run: `go test -race ./internal/server/ -run TestEndToEndRefreshAndLogout -v`
Expected: PASS. If a step fails, find the cause with superpowers:systematic-debugging before changing anything. This test is the first to exercise the generated routes and CORS for the new operations together.

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: PASS, and vet and gofmt print nothing.

- [ ] **Step 4: Commit**

```bash
git add internal/server/flow_test.go
git commit -m "test(server): end-to-end refresh rotation, reuse, revoke and logout"
```

---

### Task 10: E2E — `@auth0/auth0-react` with rotating refresh tokens and logout

This is a black-box test (CLEAN_ROOM.md). The React app uses only the SDK's documented public API. When something fails, debug from zeroauthy's log and the browser's network traffic, never from SDK source.

**Files:**
- Rename: `tests/e2e/run-m4.sh` → `tests/e2e/run-browser.sh`, then extend it
- Modify: `Makefile` (`e2e` target)
- Modify: `tests/e2e/package.json`, `tests/e2e/package-lock.json`
- Modify: `tests/e2e/seed.yaml`, `tests/e2e/spa-server.mjs`, `tests/e2e/playwright.config.mjs`
- Create: `tests/e2e/react/index.html`, `tests/e2e/react/app.jsx`, `tests/e2e/m5-react.spec.mjs`

**Interfaces:**
- Consumes: the zeroauthy server with Tasks 1–9.
- Produces:
  - `tests/e2e/run-browser.sh`, which runs every `m*-*.spec.mjs` Playwright spec; Task 11 adds the Next.js app to it
  - the `E2E_REACT_BUNDLE` environment variable read by `spa-server.mjs`

- [ ] **Step 1: Dependencies**

```bash
cd tests/e2e
npm install --save-exact @auth0/auth0-react@2.28.2 react@19.3.0 react-dom@19.3.0 esbuild@0.28.2
cd ../..
```

Expected: `package.json` lists the four packages at exactly those versions, and `package-lock.json` is updated. `npm ls @auth0/auth0-spa-js` shows a single 2.28.x copy. If npm installs a second copy for auth0-react, that is acceptable; note it in the report.

- [ ] **Step 2: Seed the React client**

In `tests/e2e/seed.yaml`:
- add `allow_offline_access: true` to the `https://api.e2e.local` resource server, after `token_lifetime: 3600`;
- add this client after `e2e-spa`:

```yaml
      - client_id: e2e-react
        name: E2E React
        app_type: spa
        grant_types: [authorization_code, refresh_token]
        callbacks: ["https://localhost:3443/react/"]
        allowed_logout_urls: ["https://localhost:3443/react/"]
        web_origins: ["https://localhost:3443"]
        allowed_origins: ["https://localhost:3443"]
```

- change the connection to `enabled_clients: [e2e-spa, e2e-react]`.

The SPA defaults give rotating, expiring refresh tokens with leeway 0.

- [ ] **Step 3: The React app**

Create `tests/e2e/react/index.html`:

```html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>zeroauthy e2e React</title></head>
<body>
<div id="root"></div>
<script src="/react/app.js"></script>
</body>
</html>
```

Create `tests/e2e/react/app.jsx`:

```jsx
// tests/e2e/react/app.jsx: a minimal app using @auth0/auth0-react as its
// public README shows. Only the domain points at zeroauthy.
import React from 'react';
import { createRoot } from 'react-dom/client';
import { Auth0Provider, useAuth0 } from '@auth0/auth0-react';

const home = window.location.origin + '/react/';

function App() {
  const auth = useAuth0();
  // Expose the hook's public API to the Playwright test.
  window.__za = auth;
  if (auth.isLoading) return <p>Loading</p>;
  if (auth.error) return <p id="error" data-ready="error">{auth.error.message}</p>;
  if (!auth.isAuthenticated) {
    return <button id="login" data-ready="true" onClick={() => auth.loginWithRedirect()}>Log in</button>;
  }
  return (
    <div data-ready="true">
      <p id="email">{auth.user.email}</p>
      <button id="logout" onClick={() => auth.logout({ logoutParams: { returnTo: home } })}>Log out</button>
    </div>
  );
}

createRoot(document.getElementById('root')).render(
  <Auth0Provider
    domain="localhost:8443"
    clientId="e2e-react"
    useRefreshTokens
    cacheLocation="localstorage"
    authorizationParams={{ redirect_uri: home, audience: 'https://api.e2e.local', scope: 'openid profile email read:things' }}
  >
    <App />
  </Auth0Provider>,
);
```

- [ ] **Step 4: Serve it**

In `tests/e2e/spa-server.mjs`, add these routes to `routes`:

```js
  '/react/': ['react/index.html', 'text/html; charset=utf-8'],
  '/react/app.js': [process.env.E2E_REACT_BUNDLE, 'text/javascript'],
```

Change the handler's file read so that absolute paths (the bundle in the temp dir) are read as-is:

```js
    const file = route[0].startsWith('/') ? route[0] : new URL('./' + route[0], import.meta.url);
    res.writeHead(200, { 'content-type': route[1], 'cache-control': 'no-store' });
    res.end(await readFile(file));
```

- [ ] **Step 5: One runner for all browser specs**

```bash
git mv tests/e2e/run-m4.sh tests/e2e/run-browser.sh
```

Replace the contents of `tests/e2e/run-browser.sh` with:

```bash
#!/usr/bin/env bash
# tests/e2e/run-browser.sh: build zeroauthy, serve it and the test apps over
# TLS, and drive the browser SDK specs (m*-*.spec.mjs) with Playwright.
# E2E_IN_CONTAINER=1 runs Playwright in the official container image
# (docker or podman) instead of on the host.
set -euo pipefail
cd "$(dirname "$0")/../.."

work="$(mktemp -d)"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$work"; }
trap cleanup EXIT

# wait_for URL: poll until it answers, failing fast after ~20 s.
wait_for() {
  for _ in $(seq 1 100); do
    curl -sf --cacert "$work/cert.pem" -o /dev/null "$1" && return 0
    sleep 0.2
  done
  echo "timed out waiting for $1" >&2
  return 1
}

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
npx esbuild react/app.jsx --bundle --minify --format=iife --jsx=automatic \
  --define:process.env.NODE_ENV='"production"' --outfile="$work/react.js" --log-level=warning
E2E_CERT="$work/cert.pem" E2E_KEY="$work/key.pem" E2E_REACT_BUNDLE="$work/react.js" \
  node spa-server.mjs >"$work/spa.log" 2>&1 &
pids+=($!)

status=0
wait_for https://localhost:8443/healthz && wait_for https://localhost:3443/ || status=$?

if [[ $status -eq 0 ]]; then
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
fi
if [[ $status -ne 0 ]]; then
  for log in "$work"/*.log; do echo "--- $(basename "$log") ---"; cat "$log"; done
fi
exit $status
```

In `Makefile`, change the `e2e` recipe's second line from `./tests/e2e/run-m4.sh` to `./tests/e2e/run-browser.sh`.

In `tests/e2e/playwright.config.mjs`, change `testMatch` to `/m\d+-.*\.spec\.mjs/`.

- [ ] **Step 6: The spec**

Create `tests/e2e/m5-react.spec.mjs`:

```js
// Black-box test (CLEAN_ROOM.md): @auth0/auth0-react in a real browser
// against zeroauthy, using rotating refresh tokens, then logging out.
import { test, expect } from '@playwright/test';

const APP = 'https://localhost:3443/react/';
const TOKEN = 'https://localhost:8443/oauth/token';

const isTokenCall = (r) => r.url() === TOKEN && r.request().method() === 'POST';

async function ready(page) {
  await expect(page.locator('[data-ready]')).toHaveAttribute('data-ready', /true|error/, { timeout: 20_000 });
  const err = page.locator('#error');
  if (await err.count()) throw new Error('React app failed: ' + (await err.textContent()));
}

// replay posts a refresh token directly, as an attacker holding it would.
async function replay(refreshToken) {
  const r = await fetch(TOKEN, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ grant_type: 'refresh_token', client_id: 'e2e-react', refresh_token: refreshToken }),
  });
  return { status: r.status, body: await r.json() };
}

test('auth0-react rotates refresh tokens, detects reuse and logs out', async ({ page }) => {
  await page.goto(APP);
  await ready(page);
  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  const [codeExchange] = await Promise.all([page.waitForResponse(isTokenCall), page.click('button[type=submit]')]);
  await page.waitForURL(APP);
  await ready(page);
  await expect(page.locator('#email')).toHaveText('alice@e2e.local');

  const first = await codeExchange.json();
  expect(first.refresh_token).toBeTruthy();
  expect(first.scope.split(' ')).toContain('offline_access');

  // Bypassing the cache makes the SDK use its refresh token.
  const [refreshCall] = await Promise.all([
    page.waitForResponse(isTokenCall),
    page.evaluate(() => window.__za.getAccessTokenSilently({ cacheMode: 'off' })),
  ]);
  expect(refreshCall.request().postData()).toContain('refresh_token');
  const second = await refreshCall.json();
  expect(refreshCall.status()).toBe(200);
  expect(second.refresh_token).toBeTruthy();
  expect(second.refresh_token).not.toBe(first.refresh_token);

  // With localStorage caching, a reload keeps the user signed in.
  await page.reload();
  await ready(page);
  await expect(page.locator('#email')).toHaveText('alice@e2e.local');

  // Replaying the rotated token is reuse: it fails, and so does its successor.
  const reused = await replay(first.refresh_token);
  expect(reused.status).toBe(400);
  expect(reused.body.error).toBe('invalid_grant');
  expect((await replay(second.refresh_token)).status).toBe(400);

  // Logout ends the zeroauthy session: logging in again shows the form.
  await page.click('#logout');
  await page.waitForURL(APP);
  await ready(page);
  await expect(page.locator('#login')).toBeVisible();
  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
});
```

- [ ] **Step 7: Run it**

Run: `./tests/e2e/run-browser.sh`
Expected: `2 passed` (the m4 spa-js spec and m5-react).

If Chromium cannot run on the host, run `E2E_IN_CONTAINER=1 ./tests/e2e/run-browser.sh`. If that also fails, stop and report BLOCKED.

If the React spec fails, use superpowers:systematic-debugging. Start from the zeroauthy log (printed on failure) and Playwright's trace (`npx playwright show-trace` on the file under `test-results/`). Look at the requests the SDK sent and what zeroauthy answered. Black-box observation of the wire is allowed; reading SDK source is not. A server change needs a failing Go test first.

- [ ] **Step 8: Commit**

```bash
git add Makefile tests/e2e
git commit -m "test(e2e): auth0-react with rotating refresh tokens and logout"
```

---

### Task 11: E2E — `@auth0/nextjs-auth0`, then docs and follow-ups

This is a black-box test, under the same rules as Task 10. The Next.js app follows the SDK's public README (v4: `Auth0Client`, middleware, `/auth/*` routes).

**Files:**
- Modify: `tests/e2e/package.json`, `tests/e2e/package-lock.json`, `tests/e2e/seed.yaml`, `tests/e2e/run-browser.sh`
- Create: `tests/e2e/next-app/lib/auth0.js`, `tests/e2e/next-app/middleware.js`, `tests/e2e/next-app/app/layout.js`, `tests/e2e/next-app/app/page.js`, `tests/e2e/next-app/app/api/token/route.js`, `tests/e2e/next-app/next.config.mjs`
- Create: `tests/e2e/m5-nextjs.spec.mjs`
- Modify: `.gitignore`
- Modify: `docs/compat/matrix.md`, `docs/superpowers/plan-1-followups.md`, `README.md` (only if it lists supported features)

**Interfaces:**
- Consumes: `run-browser.sh` and the `wait_for` helper (Task 10); the zeroauthy server.
- Produces: the final milestone 5 verification.

- [ ] **Step 1: Dependencies and seed**

```bash
cd tests/e2e
npm install --save-exact @auth0/nextjs-auth0@4.32.0 next@15.5.27
cd ../..
```

In `tests/e2e/seed.yaml`, add this client:

```yaml
      - client_id: e2e-next
        name: E2E Next.js
        app_type: regular_web
        client_secret: e2e-next-secret-not-for-production
        token_endpoint_auth_method: client_secret_post
        grant_types: [authorization_code, refresh_token]
        callbacks: ["http://localhost:3000/auth/callback"]
        allowed_logout_urls: ["http://localhost:3000", "http://localhost:3000/"]
```

Add `e2e-next` to the connection's `enabled_clients`.

The client is registered for `client_secret_post`. If the server log shows `client authentication failed: method mismatch ... used=client_secret_basic`, the SDK uses Basic. Change the seed to `client_secret_basic`, which is an observation of the wire and allowed, and note it in the report.

- [ ] **Step 2: The Next.js app**

Create `tests/e2e/next-app/next.config.mjs`:

```js
// Kept explicit so `next build` does not infer settings from the parent
// package.
export default { reactStrictMode: true };
```

Create `tests/e2e/next-app/lib/auth0.js`:

```js
// Configured from AUTH0_* and APP_BASE_URL environment variables set by
// run-browser.sh, as the SDK's README describes.
import { Auth0Client } from '@auth0/nextjs-auth0/server';

export const auth0 = new Auth0Client({
  authorizationParameters: {
    audience: 'https://api.e2e.local',
    scope: 'openid profile email offline_access read:things',
  },
});
```

Create `tests/e2e/next-app/middleware.js`:

```js
import { auth0 } from './lib/auth0';

export async function middleware(request) {
  return await auth0.middleware(request);
}

export const config = {
  runtime: 'nodejs',
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

Create `tests/e2e/next-app/app/layout.js`:

```jsx
export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
```

Create `tests/e2e/next-app/app/page.js`:

```jsx
import { auth0 } from '../lib/auth0';

export const dynamic = 'force-dynamic';

export default async function Home() {
  const session = await auth0.getSession();
  if (!session) {
    return <main><a id="login" href="/auth/login">Log in</a></main>;
  }
  return (
    <main>
      <p id="email">{session.user.email}</p>
      <a id="logout" href="/auth/logout">Log out</a>
    </main>
  );
}
```

Create `tests/e2e/next-app/app/api/token/route.js`:

```js
import { auth0 } from '../../../lib/auth0';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const { token } = await auth0.getAccessToken();
    return Response.json({ token });
  } catch (err) {
    return Response.json({ error: String(err.code || err.message) }, { status: 401 });
  }
}
```

In `.gitignore`, under `# Tooling`, add `tests/e2e/next-app/.next/`.

- [ ] **Step 3: Build and serve it from the runner**

In `tests/e2e/run-browser.sh`, after the `node spa-server.mjs` block and before `status=0`, add:

```bash
export NEXT_TELEMETRY_DISABLED=1
npx next build next-app >"$work/next-build.log" 2>&1 || { cat "$work/next-build.log"; exit 1; }
AUTH0_DOMAIN=localhost:8443 AUTH0_CLIENT_ID=e2e-next \
  AUTH0_CLIENT_SECRET=e2e-next-secret-not-for-production \
  AUTH0_SECRET="$(openssl rand -hex 32)" APP_BASE_URL=http://localhost:3000 \
  NODE_EXTRA_CA_CERTS="$work/cert.pem" \
  npx next start next-app -p 3000 >"$work/next.log" 2>&1 &
pids+=($!)
```

Change the readiness line to:

```bash
wait_for https://localhost:8443/healthz && wait_for https://localhost:3443/ && wait_for http://localhost:3000/ || status=$?
```

`wait_for` passes `--cacert`, which is harmless for plain http.

- [ ] **Step 4: The spec**

Create `tests/e2e/m5-nextjs.spec.mjs`:

```js
// Black-box test (CLEAN_ROOM.md): @auth0/nextjs-auth0 server-side against
// zeroauthy: login, session, access token, logout.
import { test, expect } from '@playwright/test';
import { once } from 'node:events';
import express from 'express';
import { auth } from 'express-oauth2-jwt-bearer';

const APP = 'http://localhost:3000/';

test('nextjs-auth0 logs in, gets an access token and logs out', async ({ page }) => {
  const logoutCalls = [];
  page.on('request', (r) => {
    if (/localhost:8443\/(oidc|v2)\/logout/.test(r.url())) logoutCalls.push(r.url());
  });

  await page.goto(APP);
  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  await page.click('button[type=submit]');
  await page.waitForURL(APP);
  await expect(page.locator('#email')).toHaveText('alice@e2e.local');

  // The SDK returns the access token held in its session.
  const r = await page.request.get(APP + 'api/token');
  expect(r.status()).toBe(200);
  const { token } = await r.json();
  const api = express();
  api.get('/me', auth({ issuerBaseURL: 'https://localhost:8443', audience: 'https://api.e2e.local' }), (req, res) =>
    res.json(req.auth.payload));
  const server = api.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const me = await fetch(`http://127.0.0.1:${server.address().port}/me`, { headers: { authorization: `Bearer ${token}` } });
    expect(me.status).toBe(200);
    expect((await me.json()).scope.split(' ')).toContain('read:things');
  } finally {
    server.close();
  }

  // Logout goes through zeroauthy (end_session_endpoint is advertised) and back.
  await page.click('#logout');
  await page.waitForURL(APP);
  await expect(page.locator('#login')).toBeVisible();
  expect(logoutCalls.length).toBeGreaterThan(0);

  // The zeroauthy session is gone too: logging in again shows the form.
  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
});
```

- [ ] **Step 5: Run everything**

Run: `make e2e`
Expected:
- `run-m3.sh` prints its OK line;
- `run-browser.sh` reports `3 passed` (m4-spa-login, m5-nextjs, m5-react).

Debug failures as in Task 10. When nextjs-auth0 fails server-side, look in `next.log`, which the runner prints on failure. Two failure modes are likely:
- a TLS error from the Next.js server to zeroauthy, which means `NODE_EXTRA_CA_CERTS` did not reach the server process;
- a client-authentication method mismatch (Step 1).

Record which logout endpoint the SDK used (`logoutCalls` in the trace). If it is `/oidc/logout` with no `id_token_hint` and the confirmation page appeared, the test fails at `waitForURL(APP)`. In that case, report the observed request in DONE_WITH_CONCERNS rather than weakening the confirmation rule.

- [ ] **Step 6: Docs**

In `docs/compat/matrix.md`:
- replace the row starting `| Logout, refresh tokens, implicit/hybrid flows, ...` with:

```markdown
| `/oauth/token`: `refresh_token` (rotation, reuse detection, leeway) | Implemented | Verified with @auth0/auth0-react 2.28.2 and @auth0/nextjs-auth0 4.32.0 |
| `/oauth/revoke` | Implemented | Refresh tokens (whole family); JWT access tokens are not revocable |
| `/v2/logout`, `/oidc/logout` (RP-Initiated Logout with confirmation) | Implemented | Verified with @auth0/auth0-react 2.28.2 and @auth0/nextjs-auth0 4.32.0; `federated` ignored; no back-/front-channel logout |
| Implicit/hybrid flows, password reset, `/dbconnections/*`, password grants | Planned (milestone 6) | |
```

- in the discovery row's notes, mention `end_session_endpoint` and `revocation_endpoint`.

In `docs/superpowers/plan-1-followups.md`:
- delete these rows of the "Plan 2 follow-ups" table: the "Now (memory driver) and SQL drivers" purge row, which is done in Task 1; and the "Refresh tokens (milestone 5)" row, which is done in Task 4;
- delete these bullets: "Session writes are last-writer-wins", which is fixed in Task 1; and both bullets under "From the Plan 2 final fix-wave re-review", which are fixed in Task 3;
- add this section:

```markdown
## Plan 3 follow-ups

| Before | Item |
|---|---|
| SQL drivers (milestone 7) | `RefreshTokens.Rotate` must be one transaction (select-for-update on the old token, insert next, or revoke the family); `storetest` `ConcurrentRotate` must pass under `-race` against every SQL dialect. `DeleteExpired` needs indexes on expiry columns. |
| Multi-instance deployments | The sweeper runs in every `serve` process; harmless (deletes are idempotent) but redundant. |
```

If `README.md` lists implemented endpoints, add `/oauth/revoke`, `/v2/logout` and `/oidc/logout`, and the refresh-token grant.

Run: `go test -race ./... && go vet ./... && gofmt -l . && go generate ./... && git diff --exit-code internal/gen`
Expected: PASS, and vet and gofmt print nothing. Generated code is unchanged.

- [ ] **Step 7: Commit**

```bash
git add .gitignore tests/e2e docs README.md
git commit -m "test(e2e): nextjs-auth0 login, access token and logout; docs for milestone 5"
```

---

## Plan Self-Review (completed by the planner)

**Spec coverage (spec §13 milestone 5, §6.1, §6.3, §4):**
- Refresh token rotation: Tasks 2, 4 and 5.
- `RefreshTokens.Rotate` as a single atomic method (§5.1): Task 2.
- RefreshToken entity fields (§4): Task 2. There is no separate `rotated_at`/`revoked` boolean; pointer timestamps cover both.
- `/oauth/revoke` with RFC 7009 `200` for unknown tokens: Task 6.
- `/v2/logout` with `returnTo` allowlist: Task 7.
- `/oidc/logout` (RP-initiated): Task 8.
- `web_message`/`prompt=none`: Plan 2. It is re-checked after logout in Task 9.
- E2E: auth0-react (Task 10) and nextjs-auth0 (Task 11).
- The reused-code revocation promised in §6.3 (`authorization_code` row): Task 4.

**Follow-ups closed:**
- purging and session write atomicity: Task 1;
- code replay revocation: Task 4;
- residual callback panic and `form_post` scheme: Task 3.

**Type consistency checked:**
- `store.RefreshToken` and `RefreshTokens` method signatures are identical in Tasks 2, 4, 5 and 6.
- The fields `Sessions.Touch`/`AddClient` (Task 1) are used by `session.Manager` (Task 1).
- `session.End` (Task 7) and `Lookup` (Task 8).
- `authz.AllowedURL` (Task 3), used in Tasks 7 and 8.
- `refreshForm`/`issueRefresh`/`refresh`/`storedRT` (Task 5), used in Task 6.
- `newLogoutEnv`/`login`/`do`/`alive`/`clearsSessionCookie` (Task 7), used in Task 8.
- `wait_for` (Task 10), used in Task 11.

**Review Focus mapping:**
1. Task 2 `ConcurrentRotate`, Task 5 `TestRefreshRotates`/`TestRefreshLeeway`, and Task 9 step 3.
2. Task 5 `TestRefreshByAnotherClientLeavesTokenUntouched` and Task 6 `another client`.
3. Task 7 `TestV2LogoutRefusesUnlistedReturnTo` and Task 8 `TestOidcLogoutRejects`.
4. Task 7 `TestV2LogoutWithoutSession` and `TestV2LogoutStoreFailure`.
5. Task 5 `TestRefreshRejects` (blocked user, deleted API, scope escalation).
