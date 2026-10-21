package mgmt_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/userrules"
)

const dbConn = "Username-Password-Authentication"

var allUserScopes = []string{"read:users", "create:users", "update:users", "delete:users", "update:users_app_metadata"}

// recordingSender is a VerificationSender that records its calls.
type recordingSender struct {
	mu   sync.Mutex
	sent []string // user IDs
}

func (s *recordingSender) SendVerification(_ context.Context, _ string, u *store.User, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, u.UserID)
	return nil
}

type usersEnv struct {
	*clientsEnv
	conn *store.Connection
	logs *bytes.Buffer
}

func newUsersEnv(t *testing.T) *usersEnv {
	t.Helper()
	e := &usersEnv{clientsEnv: newClientsEnv(t), logs: &bytes.Buffer{}}
	e.h.Log = slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.conn = &store.Connection{TenantID: e.tn.ID, ID: "con_db", Name: dbConn, Strategy: store.StrategyDatabase, CreatedAt: now}
	if err := e.st.Connections().Create(context.Background(), e.conn); err != nil {
		t.Fatal(err)
	}
	return e
}

// legacy adds a custom database connection running funcs, in import mode or
// not, and wires the handlers' script client.
func (e *usersEnv) legacy(t *testing.T, name string, importMode bool, funcs map[string]func([]any) (any, error)) (*store.Connection, *customdb.FuncExecutor) {
	t.Helper()
	fe := &customdb.FuncExecutor{Funcs: funcs}
	c := &store.Connection{TenantID: e.tn.ID, ID: "con_" + strings.ToLower(strings.ReplaceAll(name, "-", "")), Name: name, Strategy: store.StrategyDatabase,
		EnabledDatabaseCustomization: true, ImportMode: importMode, CustomScripts: map[string]string{}, CreatedAt: now}
	for _, s := range store.ScriptNames {
		c.CustomScripts[s] = "function " + s + "() {}"
	}
	if err := e.st.Connections().Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	e.h.Scripts = &customdb.Client{Exec: fe, Wrapper: e.w}
	return c, fe
}

func (e *usersEnv) do(t *testing.T, caller mgmt.Caller, method, target string, body any, fn http.HandlerFunc) (*httptest.ResponseRecorder, any) {
	t.Helper()
	return e.call(t, e.tn, caller, method, target, body, fn)
}

func (e *usersEnv) create(t *testing.T, body any, scopes ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	if scopes == nil {
		scopes = allUserScopes
	}
	rec, out := e.do(t, m2mCaller(scopes...), "POST", "/api/v2/users", body, e.h.CreateUser)
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *usersEnv) mustCreate(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	if _, ok := body["connection"]; !ok {
		body["connection"] = dbConn
	}
	if _, ok := body["password"]; !ok {
		body["password"] = "correct horse 1"
	}
	rec, out := e.create(t, body)
	if rec.Code != 201 {
		t.Fatalf("create %v = %d %s", body, rec.Code, rec.Body)
	}
	return out
}

func (e *usersEnv) get(t *testing.T, id, query string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.do(t, m2mCaller("read:users"), "GET", "/api/v2/users/"+url.PathEscape(id)+query, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetUser(w, r, id, mgmtapi.GetUserParams{})
	})
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *usersEnv) patch(t *testing.T, id string, body any, scopes ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	if scopes == nil {
		scopes = allUserScopes
	}
	rec, out := e.do(t, m2mCaller(scopes...), "PATCH", "/api/v2/users/"+url.PathEscape(id), body, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateUser(w, r, id) })
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *usersEnv) del(t *testing.T, id string) *httptest.ResponseRecorder {
	t.Helper()
	rec, _ := e.do(t, m2mCaller("delete:users"), "DELETE", "/api/v2/users/"+url.PathEscape(id), nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteUser(w, r, id) })
	return rec
}

func (e *usersEnv) list(t *testing.T, query string) (*httptest.ResponseRecorder, any) {
	t.Helper()
	return e.do(t, m2mCaller("read:users"), "GET", "/api/v2/users"+query, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetUsers(w, r, mgmtapi.GetUsersParams{})
	})
}

func (e *usersEnv) byEmail(t *testing.T, query string) (*httptest.ResponseRecorder, any) {
	t.Helper()
	return e.do(t, m2mCaller("read:users"), "GET", "/api/v2/users-by-email"+query, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetUsersByEmail(w, r, mgmtapi.GetUsersByEmailParams{})
	})
}

func wantUserError(t *testing.T, what string, rec *httptest.ResponseRecorder, out map[string]any, status int, code, message string) {
	t.Helper()
	if rec.Code != status {
		t.Errorf("%s: status %d, want %d (%s)", what, rec.Code, status, rec.Body)
		return
	}
	gotCode, has := out["errorCode"]
	switch {
	case code == "" && has:
		t.Errorf("%s: errorCode %v, want none", what, gotCode)
	case code != "" && gotCode != code:
		t.Errorf("%s: errorCode %v, want %s (%s)", what, gotCode, code, rec.Body)
	}
	if message != "" && out["message"] != message {
		t.Errorf("%s: message %q, want %q", what, out["message"], message)
	}
}

var (
	generatedUserID = regexp.MustCompile(`^auth0\|[0-9a-f]{24}$`)
	millisUTC       = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$`)
)

// U1: the shape of a user created with only connection, email and password.
func TestCreateUserShape(t *testing.T) {
	e := newUsersEnv(t)
	rec, out := e.create(t, map[string]any{"connection": dbConn, "email": "Bea.Obs@Example.COM", "password": "correct horse 1"})
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	id, _ := out["user_id"].(string)
	if !generatedUserID.MatchString(id) || out["email"] != "bea.obs@example.com" || out["email_verified"] != false ||
		out["name"] != "bea.obs@example.com" || out["nickname"] != "bea.obs" || out["picture"] != userrules.DefaultPicture("bea.obs@example.com") {
		t.Fatalf("user = %v", out)
	}
	for _, k := range []string{"created_at", "updated_at"} {
		if s, _ := out[k].(string); !millisUTC.MatchString(s) {
			t.Errorf("%s = %v", k, out[k])
		}
	}
	ids, _ := out["identities"].([]any)
	if len(ids) != 1 {
		t.Fatalf("identities = %v", out["identities"])
	}
	ident := ids[0].(map[string]any)
	if ident["connection"] != dbConn || ident["user_id"] != strings.TrimPrefix(id, "auth0|") || ident["provider"] != "auth0" || ident["isSocial"] != false || len(ident) != 4 {
		t.Errorf("identity = %v", ident)
	}
	for _, absent := range []string{"blocked", "given_name", "family_name", "user_metadata", "app_metadata", "username",
		"last_login", "last_ip", "logins_count", "phone_number", "phone_verified", "password", "password_hash"} {
		if v, ok := out[absent]; ok {
			t.Errorf("%s is present: %v", absent, v)
		}
	}
	if strings.Contains(rec.Body.String(), "argon2") || strings.Contains(rec.Body.String(), "correct horse") ||
		strings.Contains(e.logs.String(), "argon2") || strings.Contains(e.logs.String(), "correct horse") {
		t.Errorf("a password or hash leaked:\n%s\n%s", rec.Body, e.logs)
	}
	if !strings.Contains(e.logs.String(), "create user") || !strings.Contains(e.logs.String(), "actor=m2m") {
		t.Errorf("the write is not logged with its actor:\n%s", e.logs)
	}
	// The stored user logs in with the password.
	u, err := (&identity.Database{Store: e.st}).Login(context.Background(), e.conn, "bea.obs@example.com", "correct horse 1")
	if err != nil || u.UserID != id {
		t.Fatalf("login = %v, %v", u, err)
	}
}

// U1: login fields appear after the first login.
func TestUserLoginFields(t *testing.T) {
	e := newUsersEnv(t)
	id := e.mustCreate(t, map[string]any{"email": "a@x.test"})["user_id"].(string)
	at := time.Date(2026, 10, 19, 8, 30, 0, 123e6, time.UTC)
	if err := e.st.Users().RecordLogin(context.Background(), e.tn.ID, id, at, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	_, out := e.get(t, id, "")
	if out["last_login"] != "2026-10-19T08:30:00.123Z" || out["last_ip"] != "203.0.113.9" || out["logins_count"] != float64(1) {
		t.Fatalf("user = %v", out)
	}
}

// U2: create errors.
func TestCreateUserErrors(t *testing.T) {
	e := newUsersEnv(t)
	e.mustCreate(t, map[string]any{"email": "taken@x.test"})
	for _, tc := range []struct {
		name    string
		body    any
		status  int
		code    string
		message string
	}{
		{"no connection", map[string]any{"email": "a@x.test", "password": "correct horse 1"}, 400, "invalid_body", userrules.MissingConnectionMessage},
		{"unknown connection", map[string]any{"connection": "Nope", "email": "a@x.test", "password": "correct horse 1"}, 400, "inexistent_connection", "The connection does not exist."},
		{"bad email", map[string]any{"connection": dbConn, "email": "not-an-email", "password": "correct horse 1"}, 400, "invalid_body", ""},
		{"unknown property", map[string]any{"connection": dbConn, "email": "a@x.test", "password": "correct horse 1", "colour": "blue"}, 400, "invalid_body", ""},
		{"wrong type", map[string]any{"connection": dbConn, "email": 12, "password": "correct horse 1"}, 400, "invalid_body", ""},
		{"not an object", `[1]`, 400, "invalid_body", ""},
		{"weak password", map[string]any{"connection": dbConn, "email": "a@x.test", "password": "short"}, 400, "", "PasswordStrengthError: Password is too weak"},
		{"username not allowed", map[string]any{"connection": dbConn, "email": "a@x.test", "password": "correct horse 1", "username": "bea"}, 400, "operation_not_supported", ""},
		{"phone not allowed", map[string]any{"connection": dbConn, "email": "a@x.test", "password": "correct horse 1", "phone_number": "+15550100"}, 400, "invalid_body", ""},
		{"duplicate", map[string]any{"connection": dbConn, "email": "TAKEN@x.test", "password": "correct horse 1"}, 409, "auth0_idp_error", "The user already exists."},
		{"user_id with a space", map[string]any{"connection": dbConn, "email": "a@x.test", "password": "correct horse 1", "user_id": "a b"}, 400, "invalid_body", ""},
	} {
		rec, out := e.create(t, tc.body)
		wantUserError(t, tc.name, rec, out, tc.status, tc.code, tc.message)
	}
}

// U2: a supplied user_id is always prefixed; fields are taken as sent.
func TestCreateUserAsSent(t *testing.T) {
	e := newUsersEnv(t)
	out := e.mustCreate(t, map[string]any{"email": "s@x.test", "user_id": "auth0|x", "blocked": true, "email_verified": true,
		"name": "Bea Obs", "nickname": "bo", "given_name": "Bea", "family_name": "Obs", "picture": "https://img.test/b.png",
		"user_metadata": map[string]any{"color": "red"}, "app_metadata": map[string]any{"plan": "pro"}})
	ident := out["identities"].([]any)[0].(map[string]any)
	if out["user_id"] != "auth0|auth0|x" || ident["user_id"] != "auth0|x" || out["blocked"] != true || out["email_verified"] != true ||
		out["name"] != "Bea Obs" || out["nickname"] != "bo" || out["given_name"] != "Bea" || out["family_name"] != "Obs" ||
		out["picture"] != "https://img.test/b.png" || out["user_metadata"].(map[string]any)["color"] != "red" ||
		out["app_metadata"].(map[string]any)["plan"] != "pro" {
		t.Fatalf("user = %v", out)
	}
	rec, got := e.create(t, map[string]any{"connection": dbConn, "email": "t@x.test", "password": "correct horse 1", "user_id": "auth0|x"})
	wantUserError(t, "same user_id", rec, got, 409, "auth0_idp_error", "The user already exists.")
}

// D-0043: writing app_metadata needs update:users_app_metadata; reading it
// needs only read:users.
func TestUserAppMetadataScopes(t *testing.T) {
	e := newUsersEnv(t)
	body := func() map[string]any {
		return map[string]any{"connection": dbConn, "email": "m" + secrets.RandomHex(3) + "@x.test", "password": "correct horse 1", "app_metadata": map[string]any{"plan": "pro"}}
	}
	rec, out := e.create(t, body(), "create:users")
	wantUserError(t, "create without the metadata scope", rec, out, 403, "insufficient_scope", "")
	if rec, _ := e.create(t, body(), "create:users", "create:users_app_metadata"); rec.Code != 201 {
		t.Errorf("create with create:users_app_metadata = %d %s", rec.Code, rec.Body)
	}
	rec, out = e.create(t, body(), "create:users", "update:users_app_metadata")
	if rec.Code != 201 {
		t.Fatalf("create with update:users_app_metadata = %d %s", rec.Code, rec.Body)
	}
	id := out["user_id"].(string)
	if _, got := e.get(t, id, ""); got["app_metadata"].(map[string]any)["plan"] != "pro" {
		t.Errorf("read:users does not see app_metadata: %v", got)
	}
	rec, out = e.patch(t, id, map[string]any{"app_metadata": map[string]any{"plan": "free"}}, "update:users")
	wantUserError(t, "patch app_metadata with update:users", rec, out, 403, "insufficient_scope", "")
	rec, out = e.patch(t, id, map[string]any{"app_metadata": map[string]any{"plan": "free"}, "name": "N"}, "update:users_app_metadata")
	wantUserError(t, "patch name with the metadata scope only", rec, out, 403, "insufficient_scope", "")
	if rec, out = e.patch(t, id, map[string]any{"app_metadata": map[string]any{"plan": "free"}}, "update:users_app_metadata"); rec.Code != 200 || out["app_metadata"].(map[string]any)["plan"] != "free" {
		t.Errorf("patch app_metadata alone = %d %v", rec.Code, out)
	}
	if rec, _ = e.patch(t, id, map[string]any{"name": "N"}, "update:users"); rec.Code != 200 {
		t.Errorf("patch name with update:users = %d %s", rec.Code, rec.Body)
	}
}

// U12: path IDs.
func TestUserPathIDs(t *testing.T) {
	e := newUsersEnv(t)
	rec, out := e.get(t, "nope", "")
	wantUserError(t, "malformed", rec, out, 400, "invalid_uri", "Object didn't pass validation for format user-id: nope")
	rec, out = e.get(t, "auth0|000000000000000000000000", "")
	wantUserError(t, "unknown", rec, out, 404, "inexistent_user", "The user does not exist.")
	rec, out = e.patch(t, "|x", map[string]any{"name": "x"})
	wantUserError(t, "patch malformed", rec, out, 400, "invalid_uri", "")
	rec, out = e.patch(t, "auth0|000000000000000000000000", map[string]any{"name": "x"})
	wantUserError(t, "patch unknown", rec, out, 404, "inexistent_user", "")
	if rec := e.del(t, "auth0"); rec.Code != 400 {
		t.Errorf("delete malformed = %d", rec.Code)
	}
}

func TestGetUserFields(t *testing.T) {
	e := newUsersEnv(t)
	id := e.mustCreate(t, map[string]any{"email": "f@x.test"})["user_id"].(string)
	if _, out := e.get(t, id, "?fields=email,user_id"); len(out) != 2 || out["email"] != "f@x.test" {
		t.Errorf("include = %v", out)
	}
	if _, out := e.get(t, id, "?fields=identities,picture&include_fields=false"); out["identities"] != nil || out["picture"] != nil || out["email"] != "f@x.test" {
		t.Errorf("exclude = %v", out)
	}
}

// U3: the metadata merge, email changes and the email+password refusal.
func TestPatchUser(t *testing.T) {
	e := newUsersEnv(t)
	id := e.mustCreate(t, map[string]any{"email": "p@x.test", "email_verified": true,
		"user_metadata": map[string]any{"keep": 1, "drop": 2, "obj": map[string]any{"a": 1}}})["user_id"].(string)
	rec, out := e.patch(t, id, map[string]any{"user_metadata": map[string]any{"drop": nil, "obj": map[string]any{"b": 2}, "new": "x"}})
	md, _ := out["user_metadata"].(map[string]any)
	if rec.Code != 200 || md["keep"] != float64(1) || md["new"] != "x" || md["drop"] != nil || len(md["obj"].(map[string]any)) != 1 || md["obj"].(map[string]any)["b"] != float64(2) {
		t.Fatalf("merge = %d %v", rec.Code, out)
	}
	if _, out = e.patch(t, id, map[string]any{"user_metadata": map[string]any{}}); out["user_metadata"] == nil || len(out["user_metadata"].(map[string]any)) != 0 {
		t.Errorf("{} empties: %v", out["user_metadata"])
	}
	if _, out = e.patch(t, id, map[string]any{"email": "New@x.test"}); out["email"] != "new@x.test" || out["email_verified"] != false {
		t.Errorf("email change = %v", out)
	}
	if _, out = e.patch(t, id, map[string]any{"email": "newer@x.test", "email_verified": true}); out["email_verified"] != true {
		t.Errorf("email change with email_verified = %v", out)
	}
	rec, out = e.patch(t, id, map[string]any{"email": "x@x.test", "password": "another horse 2"})
	wantUserError(t, "email and password", rec, out, 400, "operation_not_supported", "")
	rec, out = e.patch(t, id, map[string]any{"colour": "blue"})
	wantUserError(t, "unknown property", rec, out, 400, "invalid_body", "")
	rec, out = e.patch(t, id, map[string]any{"password": "short"})
	wantUserError(t, "weak password", rec, out, 400, "", "PasswordStrengthError: Password is too weak")
	rec, out = e.patch(t, id, map[string]any{"username": "bea"})
	wantUserError(t, "username", rec, out, 400, "operation_not_supported", "")
	if _, out = e.patch(t, id, map[string]any{"blocked": true}); out["blocked"] != true {
		t.Errorf("block = %v", out)
	}
	// Logged deviation (D-0043): Auth0 shows blocked:false once it has been
	// set; zeroauthy cannot tell that from never set, so leaves it out.
	if _, out = e.patch(t, id, map[string]any{"blocked": false}); out["blocked"] != nil {
		t.Errorf("unblock: blocked is %v", out["blocked"])
	}
}

// U3/D-0043: a password change and a block revoke nothing.
func TestPatchUserRevokesNothing(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	id := e.mustCreate(t, map[string]any{"email": "r@x.test"})["user_id"].(string)
	rt := &store.RefreshToken{TenantID: e.tn.ID, ID: "rt1", TokenHash: "h1", FamilyID: "f1", ClientID: "app", UserID: id, CreatedAt: now}
	if err := e.st.RefreshTokens().Create(ctx, rt); err != nil {
		t.Fatal(err)
	}
	if rec, _ := e.patch(t, id, map[string]any{"password": "another horse 2"}); rec.Code != 200 {
		t.Fatalf("password change = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.patch(t, id, map[string]any{"blocked": true}); rec.Code != 200 {
		t.Fatalf("block = %d %s", rec.Code, rec.Body)
	}
	if got, err := e.st.RefreshTokens().ListByUser(ctx, e.tn.ID, id); err != nil || len(got) != 1 {
		t.Fatalf("refresh tokens = %v, %v", got, err)
	}
	if strings.Contains(e.logs.String(), "another horse") || strings.Contains(e.logs.String(), "argon2") {
		t.Errorf("the password leaked into the log:\n%s", e.logs)
	}
	_, _ = e.patch(t, id, map[string]any{"blocked": false})
	if _, err := (&identity.Database{Store: e.st}).Login(ctx, e.conn, "r@x.test", "another horse 2"); err != nil {
		t.Errorf("login with the new password: %v", err)
	}
}

// The password history applies to a PATCH.
func TestPatchUserPasswordHistory(t *testing.T) {
	e := newUsersEnv(t)
	e.conn.PasswordOptions.History = store.PasswordHistory{Active: true, Size: 3}
	if err := e.st.Connections().Update(context.Background(), e.conn); err != nil {
		t.Fatal(err)
	}
	id := e.mustCreate(t, map[string]any{"email": "h@x.test", "password": "first horse 1"})["user_id"].(string)
	rec, out := e.patch(t, id, map[string]any{"password": "first horse 1"})
	wantUserError(t, "reused password", rec, out, 400, "", "")
	if rec, _ := e.patch(t, id, map[string]any{"password": "second horse 2"}); rec.Code != 200 {
		t.Fatalf("new password = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.patch(t, id, map[string]any{"password": "second horse 2"}); rec.Code != 400 {
		t.Errorf("reusing the patched password = %d", rec.Code)
	}
}

func TestPatchUserEmailConflict(t *testing.T) {
	e := newUsersEnv(t)
	e.mustCreate(t, map[string]any{"email": "one@x.test"})
	id := e.mustCreate(t, map[string]any{"email": "two@x.test"})["user_id"].(string)
	rec, out := e.patch(t, id, map[string]any{"email": "one@x.test"})
	wantUserError(t, "email in use", rec, out, 409, "auth0_idp_error", "The user already exists.")
	if _, got := e.get(t, id, ""); got["email"] != "two@x.test" {
		t.Errorf("email changed anyway: %v", got)
	}
}

// U12: delete answers 204, also when the user is gone.
func TestDeleteUser(t *testing.T) {
	e := newUsersEnv(t)
	id := e.mustCreate(t, map[string]any{"email": "d@x.test"})["user_id"].(string)
	if rec := e.del(t, id); rec.Code != 204 || rec.Body.Len() != 0 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.get(t, id, ""); rec.Code != 404 {
		t.Errorf("get after delete = %d", rec.Code)
	}
	if rec := e.del(t, id); rec.Code != 204 {
		t.Errorf("second delete = %d", rec.Code)
	}
	if !strings.Contains(e.logs.String(), "delete user") {
		t.Errorf("the delete is not logged:\n%s", e.logs)
	}
}

func listUsers(t *testing.T, out any) []map[string]any {
	t.Helper()
	arr, ok := out.([]any)
	if !ok {
		t.Fatalf("not an array: %v", out)
	}
	var users []map[string]any
	for _, u := range arr {
		users = append(users, u.(map[string]any))
	}
	return users
}

// U4: search, paging, sort and search_engine.
func TestListUsers(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	var ids []string
	for _, b := range []map[string]any{
		{"email": "alice@ex.test", "name": "Alice Obs", "app_metadata": map[string]any{"plan": "pro"}},
		{"email": "bob@ex.test", "app_metadata": map[string]any{"plan": "free"}},
		{"email": "carol@other.test"},
	} {
		ids = append(ids, e.mustCreate(t, b)["user_id"].(string))
	}
	// Default order: last_login descending, never logged in last.
	_ = e.st.Users().RecordLogin(ctx, e.tn.ID, ids[2], now.Add(time.Hour), "")
	_ = e.st.Users().RecordLogin(ctx, e.tn.ID, ids[1], now.Add(2*time.Hour), "")
	rec, out := e.list(t, "")
	users := listUsers(t, out)
	if rec.Code != 200 || len(users) != 3 || users[0]["user_id"] != ids[1] || users[1]["user_id"] != ids[2] || users[2]["user_id"] != ids[0] {
		t.Fatalf("default order = %d %v", rec.Code, out)
	}
	for q, want := range map[string]int{
		"?q=" + url.QueryEscape(`app_metadata.plan:pro`):                 1,
		"?q=" + url.QueryEscape(`email:ALICE@ex.test`):                   1,
		"?q=" + url.QueryEscape(`ex.test`):                               2,
		"?q=" + url.QueryEscape(`email:*@ex.test`) + "&search_engine=v2": 2,
		"?q=alice&search_engine=v3":                                      1,
		"?connection=" + dbConn:                                          3,
		"?connection=Other":                                              0,
	} {
		rec, out := e.list(t, q)
		if rec.Code != 200 || len(listUsers(t, out)) != want {
			t.Errorf("%s = %d %s, want %d users", q, rec.Code, rec.Body, want)
		}
	}
	rec, out = e.list(t, "?sort=email:1&fields=email")
	users = listUsers(t, out)
	if rec.Code != 200 || users[0]["email"] != "alice@ex.test" || users[2]["email"] != "carol@other.test" || len(users[0]) != 1 {
		t.Errorf("sort by email = %v", out)
	}
	if rec, _ := e.list(t, "?sort=app_metadata.plan:1"); rec.Code != 200 {
		t.Errorf("metadata sort = %d %s", rec.Code, rec.Body)
	}
	rec, out = e.list(t, "?include_totals=true&per_page=2&page=1")
	m, _ := out.(map[string]any)
	if rec.Code != 200 || m["start"] != float64(2) || m["limit"] != float64(2) || m["length"] != float64(1) || m["total"] != float64(3) || len(m["users"].([]any)) != 1 {
		t.Errorf("totals = %v", out)
	}
	for _, tc := range []struct {
		query, code, message string
	}{
		{"?search_engine=v1", "operation_not_supported", "You are not allowed to use search_engine=v1."},
		{"?search_engine=v9", "invalid_query_string", ""},
		{"?per_page=101", "invalid_query_string", ""},
		{"?per_page=100&page=10", "invalid_paging", ""},
		{"?sort=email", "invalid_query_string", ""},
		{"?q=" + url.QueryEscape("bogus_field:x"), "", "invalid query: field 'bogus_field' is not searchable"},
		{"?q=" + url.QueryEscape(`email:"x`), "", "invalid query: undefined"},
	} {
		rec, out := e.list(t, tc.query)
		m, _ := out.(map[string]any)
		wantUserError(t, tc.query, rec, m, 400, tc.code, tc.message)
	}
	if rec, out := e.list(t, "?page=999&per_page=1"); rec.Code != 200 || len(listUsers(t, out)) != 0 {
		t.Errorf("page 999 = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "argon2") {
		t.Error("a hash leaked")
	}
}

// U5: users-by-email is case-sensitive.
func TestUsersByEmail(t *testing.T) {
	e := newUsersEnv(t)
	id := e.mustCreate(t, map[string]any{"email": "Case@x.test"})["user_id"].(string)
	rec, out := e.byEmail(t, "?email=case@x.test")
	if users := listUsers(t, out); rec.Code != 200 || len(users) != 1 || users[0]["user_id"] != id {
		t.Fatalf("lowercase = %d %s", rec.Code, rec.Body)
	}
	if _, out := e.byEmail(t, "?email=CASE@x.test"); len(listUsers(t, out)) != 0 {
		t.Errorf("uppercase found %v", out)
	}
	if rec, out := e.byEmail(t, "?email=nobody@x.test"); rec.Code != 200 || len(listUsers(t, out)) != 0 {
		t.Errorf("unknown = %d %s", rec.Code, rec.Body)
	}
	if _, out := e.byEmail(t, "?email=case@x.test&fields=email"); len(listUsers(t, out)[0]) != 1 {
		t.Errorf("fields = %v", out)
	}
	for _, q := range []string{"", "?email=", "?email=not-an-email"} {
		rec, out := e.byEmail(t, q)
		m, _ := out.(map[string]any)
		wantUserError(t, "users-by-email"+q, rec, m, 400, "invalid_query_string", "")
	}
}

// verify_email sends the verification email; by default for an unverified
// email.
func TestCreateUserVerifyEmail(t *testing.T) {
	e := newUsersEnv(t)
	// No sender: nothing happens, nothing fails.
	e.mustCreate(t, map[string]any{"email": "nosender@x.test", "verify_email": true})
	s := &recordingSender{}
	e.h.Verification = s
	a := e.mustCreate(t, map[string]any{"email": "a@x.test"})["user_id"].(string)
	e.mustCreate(t, map[string]any{"email": "b@x.test", "verify_email": false})
	e.mustCreate(t, map[string]any{"email": "c@x.test", "email_verified": true})
	d := e.mustCreate(t, map[string]any{"email": "d@x.test", "email_verified": true, "verify_email": true})["user_id"].(string)
	if len(s.sent) != 2 || s.sent[0] != a || s.sent[1] != d {
		t.Fatalf("sent = %v", s.sent)
	}
	// An email change sends one, unless verify_email is false.
	if rec, _ := e.patch(t, a, map[string]any{"email": "a2@x.test"}); rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	_, _ = e.patch(t, d, map[string]any{"email": "d2@x.test", "verify_email": false})
	if len(s.sent) != 3 || s.sent[2] != a {
		t.Fatalf("sent after patches = %v", s.sent)
	}
}

func scriptCalls(fe *customdb.FuncExecutor) []string {
	var out []string
	for _, r := range fe.Requests() {
		out = append(out, r.Script)
	}
	return out
}

// A custom database connection not in import mode: create runs the create
// script first, then learns the legacy user_id.
func TestCreateUserCustomDB(t *testing.T) {
	e := newUsersEnv(t)
	var created map[string]any
	conn, fe := e.legacy(t, "Legacy-Db", false, map[string]func([]any) (any, error){
		store.ScriptGetUser: func(a []any) (any, error) {
			if created == nil || a[0] != created["email"] {
				return nil, nil
			}
			return map[string]any{"user_id": "L42", "email": created["email"]}, nil
		},
		store.ScriptCreate: func(a []any) (any, error) {
			u := a[0].(map[string]any)
			switch u["email"] {
			case "boom@x.test":
				return nil, &customdb.ScriptError{Kind: customdb.KindError, Message: "database down"}
			case "dup@x.test":
				return nil, &customdb.ScriptError{Kind: customdb.KindValidation, Code: "user_exists", Message: "exists"}
			}
			created = u
			return nil, nil
		},
	})
	rec, out := e.create(t, map[string]any{"connection": conn.Name, "email": "new@x.test", "password": "correct horse 1", "user_metadata": map[string]any{"k": "v"}})
	if rec.Code != 201 || out["user_id"] != "auth0|L42" || out["identities"].([]any)[0].(map[string]any)["user_id"] != "L42" {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if created["password"] != "correct horse 1" || created["connection"] != conn.Name || created["user_metadata"].(map[string]any)["k"] != "v" {
		t.Errorf("create script got %v", created)
	}
	if got := scriptCalls(fe); strings.Join(got, ",") != "get_user,create,get_user" {
		t.Errorf("scripts = %v", got)
	}
	rec, out = e.create(t, map[string]any{"connection": conn.Name, "email": "boom@x.test", "password": "correct horse 1"})
	wantUserError(t, "thrown error", rec, out, 400, "auth0_idp_error", "database down")
	if users, _ := e.st.Users().FindByEmail(context.Background(), e.tn.ID, "boom@x.test"); len(users) != 0 {
		t.Errorf("a user was stored after the script failed: %v", users)
	}
	rec, out = e.create(t, map[string]any{"connection": conn.Name, "email": "dup@x.test", "password": "correct horse 1"})
	wantUserError(t, "user_exists", rec, out, 409, "auth0_idp_error", "The user already exists.")
	rec, out = e.create(t, map[string]any{"connection": conn.Name, "email": "new@x.test", "password": "correct horse 1"})
	wantUserError(t, "known to get_user", rec, out, 409, "auth0_idp_error", "The user already exists.")
}

// Import mode writes only to the local store.
func TestUsersImportModeRunsNoScripts(t *testing.T) {
	e := newUsersEnv(t)
	conn, fe := e.legacy(t, "Import-Db", true, map[string]func([]any) (any, error){})
	rec, out := e.create(t, map[string]any{"connection": conn.Name, "email": "i@x.test", "password": "correct horse 1"})
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	id := out["user_id"].(string)
	if rec, _ := e.patch(t, id, map[string]any{"email": "i2@x.test"}); rec.Code != 200 {
		t.Fatalf("email change = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.patch(t, id, map[string]any{"password": "another horse 2"}); rec.Code != 200 {
		t.Fatalf("password change = %d %s", rec.Code, rec.Body)
	}
	if rec := e.del(t, id); rec.Code != 204 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if got := fe.Requests(); len(got) != 0 {
		t.Errorf("scripts ran: %v", scriptCalls(fe))
	}
}

// legacyUser stores a user of conn as a legacy login would have.
func (e *usersEnv) legacyUser(t *testing.T, conn *store.Connection, legacyID, email string) string {
	t.Helper()
	u := &store.User{TenantID: e.tn.ID, UserID: "auth0|" + legacyID, Email: email, Name: email, Nickname: "n",
		Identities: []store.Identity{{Connection: conn.Name, Provider: store.StrategyDatabase, UserID: legacyID}}, CreatedAt: now, UpdatedAt: now}
	if err := e.st.Users().Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u.UserID
}

func TestPatchAndDeleteUserCustomDB(t *testing.T) {
	e := newUsersEnv(t)
	var args [][]any
	fail := false
	record := func(result any) func([]any) (any, error) {
		return func(a []any) (any, error) {
			args = append(args, a)
			if fail {
				return nil, &customdb.ScriptError{Kind: customdb.KindError, Message: "legacy store refused"}
			}
			return result, nil
		}
	}
	conn, _ := e.legacy(t, "Legacy-Db", false, map[string]func([]any) (any, error){
		store.ScriptChangeEmail:    record(true),
		store.ScriptChangePassword: record(true),
		store.ScriptDelete:         record(nil),
	})
	id := e.legacyUser(t, conn, "L1", "old@x.test")

	rec, out := e.patch(t, id, map[string]any{"email": "new@x.test"})
	if rec.Code != 200 || out["email"] != "new@x.test" {
		t.Fatalf("email change = %d %s", rec.Code, rec.Body)
	}
	if len(args) != 1 || args[0][0] != "old@x.test" || args[0][1] != "new@x.test" || args[0][2] != false {
		t.Errorf("change_email args = %v", args)
	}
	if rec, _ = e.patch(t, id, map[string]any{"password": "another horse 2"}); rec.Code != 200 {
		t.Fatalf("password change = %d %s", rec.Code, rec.Body)
	}
	if len(args) != 2 || args[1][0] != "new@x.test" || args[1][1] != "another horse 2" {
		t.Errorf("change_password args = %v", args)
	}
	u, _ := e.st.Users().Get(context.Background(), e.tn.ID, id)
	if u.Identities[0].PasswordHash != "" {
		t.Error("a legacy user got a local password hash")
	}

	fail = true
	rec, out = e.patch(t, id, map[string]any{"email": "third@x.test"})
	wantUserError(t, "change_email throws", rec, out, 400, "auth0_idp_error", "legacy store refused")
	rec, out = e.patch(t, id, map[string]any{"password": "third horse 3"})
	wantUserError(t, "change_password throws", rec, out, 400, "auth0_idp_error", "")
	if rec := e.del(t, id); rec.Code != 400 {
		t.Errorf("delete with a failing script = %d %s", rec.Code, rec.Body)
	}
	if _, got := e.get(t, id, ""); got["email"] != "new@x.test" {
		t.Errorf("user after failures = %v", got)
	}
	fail = false
	if rec := e.del(t, id); rec.Code != 204 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if last := args[len(args)-1]; len(last) != 1 || last[0] != "L1" {
		t.Errorf("delete args = %v", last)
	}
	if rec, _ := e.get(t, id, ""); rec.Code != 404 {
		t.Errorf("get after delete = %d", rec.Code)
	}
}

// A change_email or change_password that answers false changes nothing.
func TestPatchUserCustomDBNotChanged(t *testing.T) {
	e := newUsersEnv(t)
	conn, _ := e.legacy(t, "Legacy-Db", false, map[string]func([]any) (any, error){
		store.ScriptChangeEmail:    func([]any) (any, error) { return false, nil },
		store.ScriptChangePassword: func([]any) (any, error) { return false, nil },
	})
	id := e.legacyUser(t, conn, "L2", "keep@x.test")
	if rec, _ := e.patch(t, id, map[string]any{"email": "other@x.test"}); rec.Code != 400 {
		t.Errorf("email change = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.patch(t, id, map[string]any{"password": "another horse 2"}); rec.Code != 400 {
		t.Errorf("password change = %d %s", rec.Code, rec.Body)
	}
	if _, got := e.get(t, id, ""); got["email"] != "keep@x.test" {
		t.Errorf("user = %v", got)
	}
}

// No script runtime: the write fails as unavailable and nothing is stored.
func TestUsersCustomDBNoRuntime(t *testing.T) {
	e := newUsersEnv(t)
	conn, _ := e.legacy(t, "Legacy-Db", false, nil)
	e.h.Scripts = nil
	rec, out := e.create(t, map[string]any{"connection": conn.Name, "email": "n@x.test", "password": "correct horse 1"})
	wantUserError(t, "no runtime", rec, out, 503, "script_runtime_unavailable", "")
}

// Review Focus 5: NUL and invalid UTF-8 never reach the store, in path IDs
// or in body strings (Postgres refuses both with SQLSTATE 22021).
func TestUsersRefuseNULAndInvalidUTF8(t *testing.T) {
	e := newUsersEnv(t)
	id := e.mustCreate(t, map[string]any{"email": "u@x.test"})["user_id"].(string)
	for _, bad := range []string{"auth0|a\x00b", "auth0|a\xffb"} {
		rec, out := e.get(t, bad, "")
		wantUserError(t, "get "+bad, rec, out, 400, "invalid_uri", strings.ToValidUTF8("Object didn't pass validation for format user-id: "+bad, "\ufffd"))
		rec, out = e.patch(t, bad, map[string]any{"name": "x"})
		wantUserError(t, "patch "+bad, rec, out, 400, "invalid_uri", "")
		if rec := e.del(t, bad); rec.Code != 400 {
			t.Errorf("delete %q = %d", bad, rec.Code)
		}
	}
	base := `"connection":"` + dbConn + `","email":"v@x.test","password":"correct horse 1"`
	for _, body := range []string{
		`{` + base + `,"name":"a\u0000b"}`,
		`{` + base + `,"name":"a` + "\xff" + `b"}`,
		`{` + base + `,"user_metadata":{"k\u0000":"v"}}`,
		`{` + base + `,"user_metadata":{"k":["ok","v\u0000"]}}`,
		`{"connection":"` + dbConn + `","email":"v\u0000@x.test","password":"correct horse 1"}`,
	} {
		rec, out := e.create(t, body)
		wantUserError(t, "create "+body, rec, out, 400, "invalid_body", "Payload validation error: strings must be valid UTF-8 without NUL characters.")
		rec, out = e.patch(t, id, strings.Replace(body, base+",", "", 1))
		wantUserError(t, "patch "+body, rec, out, 400, "invalid_body", "")
	}
}

// failingConnections fails every connection lookup by name.
type failingConnections struct{ store.Connections }

func (failingConnections) GetByName(context.Context, string, string) (*store.Connection, error) {
	return nil, errors.New("connection lookup failed")
}

type failingConnStore struct{ store.Store }

func (s failingConnStore) Connections() store.Connections {
	return failingConnections{s.Store.Connections()}
}

// A store error while loading the user's connection fails the delete: no
// script runs and the user stays.
func TestDeleteUserConnectionLoadError(t *testing.T) {
	e := newUsersEnv(t)
	conn, fe := e.legacy(t, "Legacy-Db", false, map[string]func([]any) (any, error){
		store.ScriptDelete: func([]any) (any, error) { return nil, nil },
	})
	id := e.legacyUser(t, conn, "L9", "l9@x.test")
	e.h.Store = failingConnStore{e.st}
	if rec := e.del(t, id); rec.Code != 500 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if got := fe.Requests(); len(got) != 0 {
		t.Errorf("scripts ran: %v", scriptCalls(fe))
	}
	if _, err := e.st.Users().Get(context.Background(), e.tn.ID, id); err != nil {
		t.Errorf("the user was deleted: %v", err)
	}
}

// A PATCH that sets the password replaces an imported hash, and no response
// shows one.
func TestPatchUserPasswordClearsImportedHash(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	id := e.mustCreate(t, map[string]any{"email": "imp@x.test"})["user_id"].(string)
	u, err := e.st.Users().Get(ctx, e.tn.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	const imported = `{"algorithm":"bcrypt","hash":{"value":"$2b$10$secretsecretsecret"}}`
	u.Identities[0].PasswordHash, u.Identities[0].ImportedHash = "", imported
	if err := e.st.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if rec, got := e.get(t, id, ""); rec.Code != 200 || strings.Contains(rec.Body.String(), "secretsecret") || strings.Contains(rec.Body.String(), "bcrypt") || got["password_hash"] != nil {
		t.Fatalf("imported hash shown: %s", rec.Body)
	}
	if rec, _ := e.patch(t, id, map[string]any{"password": "fresh horse 12"}); rec.Code != 200 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	u, _ = e.st.Users().Get(ctx, e.tn.ID, id)
	if id := u.Identities[0]; id.ImportedHash != "" || !strings.HasPrefix(id.PasswordHash, "$argon2id$") {
		t.Fatalf("identity = %+v", id)
	}
}
