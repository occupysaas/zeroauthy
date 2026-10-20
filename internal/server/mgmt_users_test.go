package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
)

// usersSeed is mgmtSeed with a database connection, a custom database
// connection and a client allowed every user scope.
var usersSeed = strings.Replace(strings.Replace(mgmtSeed, "    clients:\n", `    connections:
      - {name: Username-Password-Authentication}
    clients:
      - {client_id: users, app_type: non_interactive, client_secret: users-s3cret, grant_types: [client_credentials]}
      - {client_id: usersro, app_type: non_interactive, client_secret: usersro-s3cret, grant_types: [client_credentials]}
`, 1), "    client_grants:\n", `    client_grants:
      - {client_id: users, audience: "https://acme.example.test/api/v2/", scopes: ["read:users", "create:users", "update:users", "delete:users", "update:users_app_metadata"]}
      - {client_id: usersro, audience: "https://acme.example.test/api/v2/", scopes: ["read:users", "update:users"]}
`, 1)

const usersBase = "https://acme.example.test/api/v2/users"

type usersAPI struct {
	t     *testing.T
	h     http.Handler
	st    store.Store
	token string
}

func newUsersAPI(t *testing.T, adjust func(*Deps)) *usersAPI {
	t.Helper()
	return newUsersAPIOn(t, memory.New(), adjust)
}

func newUsersAPIOn(t *testing.T, st store.Store, adjust func(*Deps)) *usersAPI {
	t.Helper()
	h, st := newMgmtEnvOn(t, st, usersSeed, adjust)
	return &usersAPI{t: t, h: h, st: st, token: clientToken(t, h, "acme.example.test", acmeMgmtAPI, "users", "users-s3cret")}
}

func (a *usersAPI) do(method, target string, body any) (*httptest.ResponseRecorder, map[string]any) {
	a.t.Helper()
	return a.doAs(a.token, method, target, body)
}

func (a *usersAPI) doAs(token, method, target string, body any) (*httptest.ResponseRecorder, map[string]any) {
	a.t.Helper()
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func (a *usersAPI) tenantID() string {
	tn, _ := a.st.Tenants().GetByName(context.Background(), "acme")
	return tn.ID
}

// Review Focus 3: a PATCH that changes the email to one another user of the
// connection has is 409, runs no change_email script and changes nothing;
// email and password together are refused before anything runs.
func TestPatchUserEmailConflictAtomic(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	count := func(name string, result any) func([]any) (any, error) {
		return func([]any) (any, error) {
			mu.Lock()
			defer mu.Unlock()
			calls[name]++
			return result, nil
		}
	}
	fe := &customdb.FuncExecutor{Funcs: map[string]func([]any) (any, error){
		store.ScriptChangeEmail:    count(store.ScriptChangeEmail, true),
		store.ScriptChangePassword: count(store.ScriptChangePassword, true),
	}}
	var a *usersAPI
	a = newUsersAPI(t, func(d *Deps) { d.Scripts = &customdb.Client{Exec: fe, Wrapper: d.Wrapper} })
	ctx := context.Background()
	tid := a.tenantID()

	// A custom database connection (not import mode) with two users.
	legacy := &store.Connection{TenantID: tid, ID: "con_legacy", Name: "Legacy-Db", Strategy: store.StrategyDatabase,
		EnabledDatabaseCustomization: true, CustomScripts: map[string]string{
			store.ScriptChangeEmail: "function changeEmail() {}", store.ScriptChangePassword: "function changePassword() {}",
		}, CreatedAt: time.Now()}
	if err := a.st.Connections().Create(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	for _, u := range []struct{ id, email string }{{"L1", "one@legacy.test"}, {"L2", "two@legacy.test"}} {
		err := a.st.Users().Create(ctx, &store.User{TenantID: tid, UserID: "auth0|" + u.id, Email: u.email, Name: u.email, Nickname: u.id,
			Identities: []store.Identity{{Connection: legacy.Name, Provider: store.StrategyDatabase, UserID: u.id}}, CreatedAt: time.Now(), UpdatedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
	}
	before, _ := a.st.Users().Get(ctx, tid, "auth0|L2")
	rec, out := a.do("PATCH", usersBase+"/"+url.PathEscape("auth0|L2"), map[string]any{"email": "ONE@legacy.test"})
	if rec.Code != 409 || out["errorCode"] != "auth0_idp_error" || out["message"] != "The user already exists." {
		t.Fatalf("conflict = %d %s", rec.Code, rec.Body)
	}
	rec, _ = a.do("PATCH", usersBase+"/"+url.PathEscape("auth0|L2"), map[string]any{"email": "one@legacy.test", "password": "another horse 2"})
	if rec.Code != 400 {
		t.Fatalf("email and password = %d %s", rec.Code, rec.Body)
	}
	if len(calls) != 0 {
		t.Fatalf("scripts ran: %v", calls)
	}
	after, _ := a.st.Users().Get(ctx, tid, "auth0|L2")
	if after.Email != before.Email || !after.UpdatedAt.Equal(before.UpdatedAt) || after.Version != before.Version {
		t.Fatalf("user changed: %+v -> %+v", before, after)
	}

	// The same on a plain database connection: the password is not changed.
	for _, email := range []string{"one@db.test", "two@db.test"} {
		if rec, _ := a.do("POST", usersBase, map[string]any{"connection": "Username-Password-Authentication", "email": email, "password": "first horse 1"}); rec.Code != 201 {
			t.Fatalf("create = %d %s", rec.Code, rec.Body)
		}
	}
	users, _ := a.st.Users().FindByEmail(ctx, tid, "two@db.test")
	two := users[0]
	rec, _ = a.do("PATCH", usersBase+"/"+url.PathEscape(two.UserID), map[string]any{"email": "one@db.test"})
	if rec.Code != 409 {
		t.Fatalf("db conflict = %d %s", rec.Code, rec.Body)
	}
	rec, _ = a.do("PATCH", usersBase+"/"+url.PathEscape(two.UserID), map[string]any{"email": "one@db.test", "password": "another horse 2"})
	if rec.Code != 400 {
		t.Fatalf("db email and password = %d %s", rec.Code, rec.Body)
	}
	conn, _ := a.st.Connections().GetByName(ctx, tid, "Username-Password-Authentication")
	db := &identity.Database{Store: a.st}
	if _, err := db.Login(ctx, conn, "two@db.test", "first horse 1"); err != nil {
		t.Fatalf("the old password stopped working: %v", err)
	}
	if _, err := db.Login(ctx, conn, "two@db.test", "another horse 2"); err == nil {
		t.Fatal("the new password was set")
	}
	if len(calls) != 0 {
		t.Fatalf("scripts ran: %v", calls)
	}
}

// Review Focus 5: what people type into a search box gives Auth0's result
// or a 400, never a 500 or a driver's text.
func TestSearchBadInputIs400(t *testing.T) {
	t.Run("memory", func(t *testing.T) { searchBadInput(t, newUsersAPI(t, nil)) })
	t.Run("sqlite", func(t *testing.T) {
		ctx := context.Background()
		st, err := sqlstore.Open(ctx, "sqlite://"+filepath.Join(t.TempDir(), "z.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		searchBadInput(t, newUsersAPIOn(t, st, nil))
	})
}

func searchBadInput(t *testing.T, a *usersAPI) {
	for _, email := range []string{"alice@ex.test", "a+b@ex.test"} {
		if rec, _ := a.do("POST", usersBase, map[string]any{"connection": "Username-Password-Authentication", "email": email, "password": "first horse 1"}); rec.Code != 201 {
			t.Fatalf("create = %d %s", rec.Code, rec.Body)
		}
	}
	want := map[string]int{"alice": 1, "a+b@ex.test": -1, "email:a+b@ex.test": 1, `email:"a+b@ex.test"`: 1, "alice ": 1, " alice": 1, "ex.test": 2}
	for _, q := range []string{
		"alice", "a+b@ex.test", "email:a+b@ex.test", `email:"a+b@ex.test"`, "alice ", " alice", "ex.test",
		`"unbalanced`, `email:"x`, "(alice", "alice)", "((", "))", "email:", "AND", "alice AND", "OR bob", "NOT", "-",
		"*", "**", `\`, `email:\`, "app_metadata:pro", "user_metadata.color:re*", "app_metadata.n:[1 TO 2]",
		"logins_count:>abc", "created_at:[2026-13-45 TO *]", "bogus:x", "name:'x'", "%", "_", "email:%@ex.test",
		"'; DROP TABLE users; --", "user_id:auth0|x", `user_id:"auth0|x"`, "identities.connection:Username-Password-Authentication",
		strings.Repeat("(", 100) + "a" + strings.Repeat(")", 100), "a\x00b", "é", "email:ALICE@EX.TEST",
	} {
		searchCase(t, a, q, want)
	}
	// Raw NUL and invalid UTF-8 (Postgres refuses both with SQLSTATE 22021).
	for _, raw := range []string{"%00", "a%00b", "email:%00", "%FF", "name:%C3", "%FF%FE"} {
		rec, out := a.do("GET", usersBase+"?q="+raw, nil)
		if rec.Code != 400 || out["message"] != "invalid query: undefined" {
			t.Errorf("q=%s: %d %s", raw, rec.Code, rec.Body)
		}
		if _, has := out["errorCode"]; has {
			t.Errorf("q=%s: errorCode %v", raw, out["errorCode"])
		}
	}
}

// searchCase runs one search: a query in want must answer 200 with that
// many users (-1: any count); any other answers 200 or a 400 with an
// "invalid query" message, never a driver's text.
func searchCase(t *testing.T, a *usersAPI, q string, want map[string]int) {
	t.Helper()
	rec, out := a.do("GET", usersBase+"?q="+url.QueryEscape(q), nil)
	body := rec.Body.String()
	n, expected := want[q]
	switch {
	case expected && rec.Code != 200:
		t.Errorf("%q: status %d, want 200 (%s)", q, rec.Code, body)
	case rec.Code == 200:
		var list []any
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Errorf("%q: 200 but not a list: %s", q, body)
		}
		if expected && n >= 0 && len(list) != n {
			t.Errorf("%q: %d users, want %d", q, len(list), n)
		}
	case rec.Code == 400:
		if code, has := out["errorCode"]; has && code != "invalid_query_string" {
			t.Errorf("%q: errorCode %v", q, code)
		}
		msg, _ := out["message"].(string)
		if !strings.HasPrefix(msg, "invalid query") {
			t.Errorf("%q: message %q", q, msg)
		}
	default:
		t.Errorf("%q: status %d %s", q, rec.Code, body)
	}
	for _, leak := range []string{"sql", "SQL", "store:", "pq:", "syntax error", "panic"} {
		if strings.Contains(body, leak) {
			t.Errorf("%q: response mentions %q: %s", q, leak, body)
		}
	}
}

// The app_metadata scope split over real tokens.
func TestUsersScopesOverHTTP(t *testing.T) {
	a := newUsersAPI(t, nil)
	ro := clientToken(t, a.h, "acme.example.test", acmeMgmtAPI, "usersro", "usersro-s3cret")
	rec, out := a.doAs(ro, "POST", usersBase, map[string]any{"connection": "Username-Password-Authentication", "email": "x@ex.test", "password": "first horse 1"})
	if rec.Code != 403 || out["errorCode"] != "insufficient_scope" {
		t.Fatalf("create with read/update only = %d %s", rec.Code, rec.Body)
	}
	rec, out = a.do("POST", usersBase, map[string]any{"connection": "Username-Password-Authentication", "email": "x@ex.test", "password": "first horse 1", "app_metadata": map[string]any{"plan": "pro"}})
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	id := url.PathEscape(out["user_id"].(string))
	if rec, out := a.doAs(ro, "GET", usersBase+"/"+id, nil); rec.Code != 200 || out["app_metadata"] == nil {
		t.Errorf("read = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := a.doAs(ro, "PATCH", usersBase+"/"+id, map[string]any{"app_metadata": map[string]any{"plan": "free"}}); rec.Code != 403 {
		t.Errorf("patch app_metadata with update:users = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := a.doAs(ro, "PATCH", usersBase+"/"+id, map[string]any{"given_name": "X"}); rec.Code != 200 {
		t.Errorf("patch given_name with update:users = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := a.doAs(ro, "DELETE", usersBase+"/"+id, nil); rec.Code != 403 {
		t.Errorf("delete without delete:users = %d", rec.Code)
	}
	if rec, _ := a.do("GET", usersBase+"/"+url.PathEscape("auth0|x")+"%2Fy", nil); rec.Code != 404 {
		t.Errorf("escaped ID = %d %s", rec.Code, rec.Body)
	}
}

// deleteFlowSeed is flowSeed with a machine client that may delete users.
var deleteFlowSeed = strings.Replace(strings.Replace(flowSeed, "    clients:\n", `    clients:
      - {client_id: admin, app_type: non_interactive, client_secret: admin-s3cret, grant_types: [client_credentials]}
`, 1), "    client_grants:\n", `    client_grants:
      - {client_id: admin, audience: "https://HOST/api/v2/", scopes: ["delete:users", "read:users"]}
`, 1)

// Review Focus 4: a reset link, an auth code, a device code and a refresh
// token taken before the user is deleted all fail after it.
func TestDeleteUserMidFlow(t *testing.T) {
	e := newFlowEnvSeed(t, deleteFlowSeed, nil)
	ctx := context.Background()
	c := e.client(t)
	tn, _ := e.st.Tenants().GetByName(ctx, "flow")
	users, _ := e.st.Users().FindByEmail(ctx, tn.ID, "alice@flow.test")
	alice := users[0]

	// A refresh token.
	tok := e.codeFlow(t, c, "scope", "openid offline_access read:things")
	refreshToken, _ := tok["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatalf("no refresh token: %v", tok)
	}
	// An auth code, not exchanged.
	resp, _ := fetch(t, c, authorizeURL(e.base))
	cb, _ := resp.Location()
	code := ""
	if cb != nil {
		code = cb.Query().Get("code")
	}
	if code == "" {
		t.Fatalf("no code: %d %v", resp.StatusCode, cb)
	}
	// A device code the user approved, not polled.
	dc := e.client(t)
	resp, dev := e.postForm(t, dc, "/oauth/device/code", url.Values{"client_id": {"tv"}, "scope": {"openid"}})
	if resp.StatusCode != 200 {
		t.Fatalf("device code = %d %v", resp.StatusCode, dev)
	}
	u, _ := url.Parse(dev["verification_uri_complete"].(string))
	resp, _ = fetch(t, dc, e.base+u.RequestURI())
	loc, _ := resp.Location()
	_, body := fetch(t, dc, loc.String())
	post := func(cl *http.Client, path string, form url.Values) *http.Response {
		req, _ := http.NewRequest("POST", e.base+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r, _ := mustDo(t, cl, req)
		return r
	}
	resp = post(dc, "/device/confirmation", url.Values{"state": {loc.Query().Get("state")}, "csrf": {csrfRe.FindStringSubmatch(body)[1]}, "action": {"confirm"}})
	loc, _ = resp.Location()
	_, body = fetch(t, dc, e.base+loc.RequestURI())
	resp = post(dc, "/u/login", url.Values{"state": {loc.Query().Get("state")}, "csrf": {csrfRe.FindStringSubmatch(body)[1]}, "username": {"alice@flow.test"}, "password": {"alice password 1"}})
	if loc, _ = resp.Location(); loc == nil || loc.Path != "/device/success" {
		t.Fatalf("device login = %d %v", resp.StatusCode, loc)
	}
	// A reset link.
	raw := secrets.RandomString(32)
	err := e.st.PasswordResetTickets().Create(ctx, &store.PasswordResetTicket{TenantID: tn.ID, ID: "prt_mid", TokenHash: secrets.HashToken(raw),
		UserID: alice.UserID, Connection: "Username-Password-Authentication", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	resetURL := e.base + "/u/reset-password?ticket=" + url.QueryEscape(raw)
	if resp, _ := fetch(t, e.client(t), resetURL); resp.StatusCode != 200 {
		t.Fatalf("reset page before the delete = %d", resp.StatusCode)
	}

	// Delete the user through the Management API.
	adminTok := ""
	{
		resp, out := e.postForm(t, e.client(t), "/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"admin"},
			"client_secret": {"admin-s3cret"}, "audience": {e.base + "/api/v2/"}})
		adminTok, _ = out["access_token"].(string)
		if resp.StatusCode != 200 || adminTok == "" {
			t.Fatalf("admin token = %d %v", resp.StatusCode, out)
		}
	}
	req, _ := http.NewRequest("DELETE", e.base+"/api/v2/users/"+url.PathEscape(alice.UserID), nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	if resp, body := mustDo(t, e.client(t), req); resp.StatusCode != 204 {
		t.Fatalf("delete = %d %s", resp.StatusCode, body)
	}

	// Everything taken before the delete fails.
	if resp, page := fetch(t, e.client(t), resetURL); resp.StatusCode != 400 || strings.Contains(page, `name="password"`) {
		t.Errorf("reset page after the delete = %d", resp.StatusCode)
	}
	resp, out := e.postForm(t, e.client(t), "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"spa"},
		"code": {code}, "redirect_uri": {"https://app.flow.test/cb"}, "code_verifier": {verifier}})
	if resp.StatusCode != 400 || out["error"] != "invalid_grant" {
		t.Errorf("code exchange = %d %v", resp.StatusCode, out)
	}
	resp, out = e.postForm(t, e.client(t), "/oauth/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {"tv"}, "device_code": {dev["device_code"].(string)}})
	// The device grant answers its errors with 403, as Auth0 does.
	if resp.StatusCode != 403 || out["error"] != "invalid_grant" {
		t.Errorf("device poll = %d %v", resp.StatusCode, out)
	}
	resp, out = e.postForm(t, e.client(t), "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {refreshToken}})
	if resp.StatusCode != 400 || out["error"] != "invalid_grant" {
		t.Errorf("refresh = %d %v", resp.StatusCode, out)
	}
}

// linkFlowSeed is flowSeed with a second user and a client allowed to read,
// link and unlink users.
var linkFlowSeed = strings.Replace(strings.Replace(strings.Replace(flowSeed, "    clients:\n", `    clients:
      - {client_id: admin, app_type: non_interactive, client_secret: admin-s3cret, grant_types: [client_credentials]}
`, 1), "    client_grants:\n", `    client_grants:
      - {client_id: admin, audience: "https://HOST/api/v2/", scopes: ["read:users", "update:users"]}
`, 1), "    users:\n", `    users:
      - {connection: Username-Password-Authentication, email: bob@flow.test, password: "bob password 2", email_verified: true}
`, 1)

// idTokenSub returns the sub claim of a token response's id_token.
func idTokenSub(t *testing.T, tok map[string]any) string {
	t.Helper()
	raw, _ := tok["id_token"].(string)
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("no id_token: %v", tok)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	return c.Sub
}

// Review Focus 2: after a link and an unlink, the secondary logs in with
// its own password again, as itself, with a fresh Version; what it held
// before the link (sessions, refresh tokens) is gone. While linked, its
// credentials log in as the primary.
func TestUnlinkRestoresLogin(t *testing.T) {
	e := newFlowEnvSeed(t, linkFlowSeed, nil)
	ctx := context.Background()
	tn, _ := e.st.Tenants().GetByName(ctx, "flow")
	find := func(email string) *store.User {
		us, _ := e.st.Users().FindByEmail(ctx, tn.ID, email)
		if len(us) != 1 {
			t.Fatalf("users with %s: %v", email, us)
		}
		return us[0]
	}
	alice, bob := find("alice@flow.test"), find("bob@flow.test")

	// Bob's session and refresh token from before the link.
	tok := e.codeFlowAs(t, e.client(t), "bob@flow.test", "bob password 2", "scope", "openid offline_access read:things")
	oldRefresh, _ := tok["refresh_token"].(string)
	if oldRefresh == "" || idTokenSub(t, tok) != bob.UserID {
		t.Fatalf("bob's first login = %v", tok)
	}

	admin := ""
	{
		resp, out := e.postForm(t, e.client(t), "/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"admin"},
			"client_secret": {"admin-s3cret"}, "audience": {e.base + "/api/v2/"}})
		admin, _ = out["access_token"].(string)
		if resp.StatusCode != 200 || admin == "" {
			t.Fatalf("admin token = %d %v", resp.StatusCode, out)
		}
	}
	call := func(method, path string, body any) (int, string) {
		t.Helper()
		var rd *strings.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = strings.NewReader(string(b))
		} else {
			rd = strings.NewReader("")
		}
		req, _ := http.NewRequest(method, e.base+"/api/v2"+path, rd)
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("Content-Type", "application/json")
		resp, out := mustDo(t, e.client(t), req)
		return resp.StatusCode, out
	}
	bobBare := strings.TrimPrefix(bob.UserID, "auth0|")
	if code, body := call("POST", "/users/"+url.PathEscape(alice.UserID)+"/identities", map[string]any{"provider": "auth0", "user_id": bobBare}); code != 201 {
		t.Fatalf("link = %d %s", code, body)
	}

	refresh := func(token string) (int, map[string]any) {
		resp, out := e.postForm(t, e.client(t), "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {token}})
		return resp.StatusCode, out
	}
	if code, out := refresh(oldRefresh); code != 400 || out["error"] != "invalid_grant" {
		t.Errorf("bob's refresh after the link = %d %v", code, out)
	}
	// Bob's credentials now log in as alice.
	tok = e.codeFlowAs(t, e.client(t), "bob@flow.test", "bob password 2")
	if sub := idTokenSub(t, tok); sub != alice.UserID {
		t.Errorf("login with bob's credentials while linked: sub %s, want the primary %s", sub, alice.UserID)
	}

	if code, body := call("DELETE", "/users/"+url.PathEscape(alice.UserID)+"/identities/auth0/"+url.PathEscape(bobBare), nil); code != 200 {
		t.Fatalf("unlink = %d %s", code, body)
	}
	re, err := e.st.Users().Get(ctx, tn.ID, bob.UserID)
	if err != nil {
		t.Fatalf("bob after unlink: %v", err)
	}
	if re.Version < 1 || !re.CreatedAt.After(bob.CreatedAt) || re.LoginsCount != 0 {
		t.Errorf("recreated bob: Version %d, created_at %v (was %v), logins %d", re.Version, re.CreatedAt, bob.CreatedAt, re.LoginsCount)
	}
	if ss, _ := e.st.Sessions().ListByUser(ctx, tn.ID, bob.UserID); len(ss) != 0 {
		t.Errorf("bob's sessions survived the link: %d", len(ss))
	}
	if ts, _ := e.st.RefreshTokens().ListByUser(ctx, tn.ID, bob.UserID); len(ts) != 0 {
		t.Errorf("bob's refresh tokens survived the link: %d", len(ts))
	}
	if code, out := refresh(oldRefresh); code != 400 || out["error"] != "invalid_grant" {
		t.Errorf("bob's old refresh after the unlink = %d %v", code, out)
	}
	// Bob logs in as himself with his own password; alice is unchanged.
	tok = e.codeFlowAs(t, e.client(t), "bob@flow.test", "bob password 2", "scope", "openid offline_access")
	if sub := idTokenSub(t, tok); sub != bob.UserID {
		t.Errorf("bob's login after unlink: sub %s, want %s", sub, bob.UserID)
	}
	if code, out := refresh(tok["refresh_token"].(string)); code != 200 {
		t.Errorf("bob's new refresh token = %d %v", code, out)
	}
	tok = e.codeFlowAs(t, e.client(t), "alice@flow.test", "alice password 1")
	if sub := idTokenSub(t, tok); sub != alice.UserID {
		t.Errorf("alice's login: sub %s", sub)
	}
}
