package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/oauth"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// versionFlowSeed is flowSeed with a password-grant client that gets
// rotating refresh tokens and a machine client that may update users and
// delete their sessions.
var versionFlowSeed = strings.Replace(strings.Replace(strings.Replace(flowSeed, "    clients:\n", `    clients:
      - {client_id: admin, app_type: non_interactive, client_secret: admin-s3cret, grant_types: [client_credentials]}
      - client_id: ropg
        app_type: regular_web
        client_secret: ropg-s3cret
        grant_types: ["http://auth0.com/oauth/grant-type/password-realm", refresh_token]
        refresh_token: {rotation_type: rotating, expiration_type: expiring}
`, 1), "    client_grants:\n", `    client_grants:
      - {client_id: admin, audience: "https://HOST/api/v2/", scopes: ["read:users", "update:users", "delete:sessions"]}
`, 1), "enabled_clients: [spa, tv, spa2]", "enabled_clients: [spa, tv, spa2, ropg]", 1)

// pauseStore holds the next WithTx, once armed, until the test releases
// it. A grant's next WithTx is its minting transaction, so the hold sits
// between the grant's user check and the mint.
type pauseStore struct {
	store.Store
	armed   atomic.Bool
	reached chan struct{}
	release chan struct{}
}

func (p *pauseStore) arm() {
	p.reached, p.release = make(chan struct{}), make(chan struct{})
	p.armed.Store(true)
}

func (p *pauseStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	if p.armed.CompareAndSwap(true, false) {
		close(p.reached)
		<-p.release
	}
	return p.Store.WithTx(ctx, fn)
}

type versionEnv struct {
	*flowEnv
	pause *pauseStore
	alice *store.User
	admin string
}

func newVersionEnv(t *testing.T) *versionEnv {
	t.Helper()
	p := &pauseStore{}
	e := newFlowEnvSeed(t, versionFlowSeed, func(d *Deps) {
		p.Store = d.Store
		d.Store = p
	})
	ctx := context.Background()
	tn, _ := e.st.Tenants().GetByName(ctx, "flow")
	users, _ := e.st.Users().FindByEmail(ctx, tn.ID, "alice@flow.test")
	if len(users) != 1 {
		t.Fatalf("alice: %v", users)
	}
	resp, out := e.postForm(t, e.client(t), "/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"admin"},
		"client_secret": {"admin-s3cret"}, "audience": {e.base + "/api/v2/"}})
	admin, _ := out["access_token"].(string)
	if resp.StatusCode != 200 || admin == "" {
		t.Fatalf("admin token = %d %v", resp.StatusCode, out)
	}
	return &versionEnv{flowEnv: e, pause: p, alice: users[0], admin: admin}
}

// tokenResult is a token endpoint answer collected off the test goroutine.
type tokenResult struct {
	status int
	body   map[string]any
	err    error
}

// token posts form to /oauth/token. It is safe off the test goroutine.
func (e *versionEnv) token(c *http.Client, form url.Values) tokenResult {
	req, _ := http.NewRequest("POST", e.base+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		return tokenResult{err: err}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return tokenResult{status: resp.StatusCode, body: out}
}

func passwordForm(password string) url.Values {
	return url.Values{"grant_type": {oauth.GrantPasswordRealm}, "realm": {"Username-Password-Authentication"},
		"client_id": {"ropg"}, "client_secret": {"ropg-s3cret"}, "username": {"alice@flow.test"}, "password": {password},
		"scope": {"openid offline_access"}, "audience": {"https://api.flow.test"}}
}

func refreshForm(token string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {"ropg"}, "client_secret": {"ropg-s3cret"}, "refresh_token": {token}}
}

// paused runs form against the token endpoint, holds it at its minting
// transaction, runs between, then lets it finish and returns its answer.
func (e *versionEnv) paused(t *testing.T, form url.Values, between func()) tokenResult {
	t.Helper()
	e.pause.arm()
	done := make(chan tokenResult, 1)
	c := e.client(t)
	go func() { done <- e.token(c, form) }()
	select {
	case <-e.pause.reached:
	case r := <-done:
		t.Fatalf("the grant finished without reaching its minting transaction: %d %v %v", r.status, r.body["error"], r.err)
	}
	between()
	close(e.pause.release)
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r
}

// mgmt calls the Management API as the admin client.
func (e *versionEnv) mgmt(t *testing.T, method, path string, body any) (int, string) {
	t.Helper()
	var rd io.Reader = strings.NewReader("")
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, e.base+"/api/v2"+path, rd)
	req.Header.Set("Authorization", "Bearer "+e.admin)
	req.Header.Set("Content-Type", "application/json")
	resp, out := mustDo(t, e.client(t), req)
	return resp.StatusCode, out
}

// reset completes a password reset of alice on the hosted page.
func (e *versionEnv) reset(t *testing.T, password string) {
	t.Helper()
	ctx := context.Background()
	raw := secrets.RandomString(32)
	err := e.st.PasswordResetTickets().Create(ctx, &store.PasswordResetTicket{TenantID: e.alice.TenantID, ID: "prt_" + secrets.RandomString(8),
		TokenHash: secrets.HashToken(raw), UserID: e.alice.UserID, Connection: "Username-Password-Authentication",
		ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	c := e.client(t)
	_, page := fetch(t, c, e.base+"/u/reset-password?ticket="+url.QueryEscape(raw))
	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no reset form: %s", page)
	}
	form := url.Values{"ticket": {raw}, "csrf": {m[1]}, "password": {password}, "password_confirm": {password}}
	req, _ := http.NewRequest("POST", e.base+"/u/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, body := mustDo(t, c, req); resp.StatusCode != 200 {
		t.Fatalf("reset = %d %s", resp.StatusCode, body)
	}
}

func wantInvalidGrant(t *testing.T, what string, r tokenResult, desc string) {
	t.Helper()
	if r.status != 400 || r.body["error"] != "invalid_grant" || r.body["error_description"] != desc {
		t.Fatalf("%s = %d %v, want invalid_grant %q", what, r.status, r.body, desc)
	}
	if _, ok := r.body["refresh_token"]; ok {
		t.Fatalf("%s returned a refresh token", what)
	}
}

// A password grant that checked the old password before a reset completed
// mints nothing after it: the reset changed the user's Version.
func TestPasswordGrantRacingReset(t *testing.T) {
	e := newVersionEnv(t)
	r := e.paused(t, passwordForm("alice password 1"), func() { e.reset(t, "brand new password 2") })
	wantInvalidGrant(t, "password grant across a reset", r, "the user is blocked")
	ts, _ := e.st.RefreshTokens().ListByUser(context.Background(), e.alice.TenantID, e.alice.UserID)
	if len(ts) != 0 {
		t.Fatalf("refresh tokens after the reset: %d", len(ts))
	}
	if r := e.token(e.client(t), passwordForm("brand new password 2")); r.status != 200 {
		t.Fatalf("password grant with the new password = %d %v", r.status, r.body)
	}
}

// The same, with the user blocked through the Management API.
func TestPasswordGrantRacingBlock(t *testing.T) {
	e := newVersionEnv(t)
	r := e.paused(t, passwordForm("alice password 1"), func() {
		if code, body := e.mgmt(t, "PATCH", "/users/"+url.PathEscape(e.alice.UserID), map[string]any{"blocked": true}); code != 200 {
			t.Fatalf("block = %d %s", code, body)
		}
	})
	wantInvalidGrant(t, "password grant across a block", r, "the user is blocked")
}

// A refresh that loaded the user before DELETE /users/{id}/sessions bumped
// its Version is refused. The token itself is not revoked (U8), so it
// refreshes again afterwards.
func TestRefreshRacingDeleteSessions(t *testing.T) {
	e := newVersionEnv(t)
	first := e.token(e.client(t), passwordForm("alice password 1"))
	rt, _ := first.body["refresh_token"].(string)
	if first.status != 200 || rt == "" {
		t.Fatalf("password grant = %d %v", first.status, first.body)
	}
	r := e.paused(t, refreshForm(rt), func() {
		if code, body := e.mgmt(t, "DELETE", "/users/"+url.PathEscape(e.alice.UserID)+"/sessions", nil); code != 202 {
			t.Fatalf("delete sessions = %d %s", code, body)
		}
	})
	wantInvalidGrant(t, "refresh across a sessions delete", r, "the user is not allowed to sign in")
	if r := e.token(e.client(t), refreshForm(rt)); r.status != 200 || r.body["refresh_token"] == nil {
		t.Fatalf("refresh after the delete = %d %v", r.status, r.body)
	}
}

// D-0043: a password change through PATCH revokes nothing, so a refresh
// token issued before it still refreshes.
func TestRefreshAfterPatchPassword(t *testing.T) {
	e := newVersionEnv(t)
	first := e.token(e.client(t), passwordForm("alice password 1"))
	rt, _ := first.body["refresh_token"].(string)
	if first.status != 200 || rt == "" {
		t.Fatalf("password grant = %d %v", first.status, first.body)
	}
	if code, body := e.mgmt(t, "PATCH", "/users/"+url.PathEscape(e.alice.UserID),
		map[string]any{"password": "patched password 3", "connection": "Username-Password-Authentication"}); code != 200 {
		t.Fatalf("patch password = %d %s", code, body)
	}
	if r := e.token(e.client(t), refreshForm(rt)); r.status != 200 || r.body["refresh_token"] == nil {
		t.Fatalf("refresh after the password change = %d %v", r.status, r.body)
	}
}
