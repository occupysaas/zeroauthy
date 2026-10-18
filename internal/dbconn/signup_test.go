package dbconn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }

const seedYAML = `
tenants:
  - name: acme
    domains: [acme.example.test]
    clients:
      - {client_id: app, app_type: spa}
      - {client_id: other, app_type: spa}
    connections:
      - {name: Username-Password-Authentication, enabled_clients: [app]}
      - {name: Closed, enabled_clients: [app], disable_signup: true}
      - {name: Not-Enabled, enabled_clients: [other]}
      - name: Legacy-DB
        enabled_clients: [app]
        enabledDatabaseCustomization: true
        customScripts: {login: "x", get_user: "x", create: "x", change_password: "x"}
    users:
      - {connection: Username-Password-Authentication, email: alice@acme.test, username: alice1, password: "alice password 1"}
      - {connection: Username-Password-Authentication, email: carol@acme.test, password: "carol password 1", blocked: true}
`

type env struct {
	st       store.Store
	h        *Handlers
	tenantID string
	strict   bool
	mail     *recorder
	// scripts runs the Legacy-DB connection's scripts; tests set Funcs.
	scripts *customdb.FuncExecutor
	logs    *bytes.Buffer
}

// recorder is a Mailer that keeps what it is asked to send.
type recorder struct {
	mu   sync.Mutex
	sent []email.Message
}

func (r *recorder) Send(_ context.Context, m email.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, m)
	return nil
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := memory.New()
	f, err := seed.Parse([]byte(seedYAML))
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(context.Background(), st, f, fixedNow, wrapper); err != nil {
		t.Fatal(err)
	}
	tn, err := st.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	mail := &recorder{}
	scripts := &customdb.FuncExecutor{Funcs: map[string]func([]any) (any, error){}}
	logs := &bytes.Buffer{} // handlers run synchronously in these tests
	log := slog.New(slog.NewTextHandler(logs, nil))
	return &env{st: st, tenantID: tn.ID, strict: true, mail: mail, scripts: scripts, logs: logs, h: &Handlers{
		Store: st, Now: fixedNow, Mailer: mail, Go: func(f func()) { f() }, Log: log,
		SendThrottle: identity.NewThrottle(100, time.Hour, time.Hour),
		Database:     &identity.Database{Store: st, Now: fixedNow, Log: log, Scripts: &customdb.Client{Exec: scripts}},
		IPThrottle:   identity.NewThrottle(100, time.Hour, time.Hour),
	}}
}

// post sends a request to the signup endpoint and decodes the JSON reply.
// Requests are checked against the spec unless e.strict is false.
func (e *env) post(t *testing.T, path, contentType, body string) (int, map[string]any, string) {
	t.Helper()
	handler := e.h.Signup
	if path == "/dbconnections/change_password" {
		handler = e.h.ChangePassword
	}
	var h http.Handler = tenant.NewResolver(e.st.Tenants(), "", false).Middleware(http.HandlerFunc(handler))
	if e.strict {
		h = contract.Wrap(t, h)
	} else {
		h = contract.WrapResponses(t, h)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Host = "acme.example.test"
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	raw, _ := io.ReadAll(rec.Result().Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return rec.Code, out, string(raw)
}

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
	rep := strings.Repeat
	// loose marks cases whose request violates the OpenAPI request schema.
	cases := map[string]struct {
		ct, body    string
		loose       bool
		status      int
		code        string
		descContain string
	}{
		"missing password":        {body: `{"client_id":"app","connection":"Username-Password-Authentication","email":"x@acme.test"}`, loose: true, status: 400, code: "invalid_request"},
		"missing connection":      {body: `{"client_id":"app","email":"x@acme.test","password":"a good password 1"}`, loose: true, status: 400, code: "invalid_request"},
		"missing client_id":       {body: `{"connection":"Username-Password-Authentication","email":"x@acme.test","password":"a good password 1"}`, loose: true, status: 400, code: "invalid_request"},
		"missing email":           {body: `{"client_id":"app","connection":"Username-Password-Authentication","password":"a good password 1"}`, loose: true, status: 400, code: "invalid_request"},
		"unknown client":          {body: `{"client_id":"nope","connection":"Username-Password-Authentication","email":"x@acme.test","password":"a good password 1"}`, status: 400, code: "invalid_request"},
		"connection not enabled":  {body: `{"client_id":"app","connection":"Not-Enabled","email":"x@acme.test","password":"a good password 1"}`, status: 400, code: "invalid_signup"},
		"signup disabled":         {body: `{"client_id":"app","connection":"Closed","email":"x@acme.test","password":"a good password 1"}`, status: 400, code: "invalid_signup"},
		"weak password":           {body: `{"client_id":"app","connection":"Username-Password-Authentication","email":"x@acme.test","password":"short"}`, status: 400, code: "invalid_password"},
		"bad email":               {body: `{"client_id":"app","connection":"Username-Password-Authentication","email":"nope","password":"a good password 1"}`, status: 400, code: "invalid_signup"},
		"email over 254 bytes":    {body: `{"client_id":"app","connection":"Username-Password-Authentication","email":"` + rep("e", 250) + `@acme.test","password":"a good password 1"}`, status: 400, code: "invalid_signup"},
		"bad picture":             {body: `{` + ok + `,"picture":"http://img.acme.test/p.png"}`, status: 400, code: "invalid_signup"},
		"name too long":           {body: `{` + ok + `,"name":"` + rep("n", 301) + `"}`, loose: true, status: 400, code: "invalid_signup"},
		"client_id not a string":  {body: `{"client_id":1,"connection":"Username-Password-Authentication","email":"x@acme.test","password":"a good password 1"}`, loose: true, status: 400, code: "invalid_request", descContain: "must be a string"},
		"metadata not string":     {body: `{` + ok + `,"user_metadata":{"n":1}}`, loose: true, status: 400, code: "invalid_request"},
		"metadata array":          {body: `{` + ok + `,"user_metadata":["a"]}`, loose: true, status: 400, code: "invalid_request", descContain: "must be an object"},
		"metadata too many":       {body: `{` + ok + `,"user_metadata":{"a":"1","b":"1","c":"1","d":"1","e":"1","f":"1","g":"1","h":"1","i":"1","j":"1","k":"1"}}`, loose: true, status: 400, code: "invalid_request"},
		"metadata value too long": {body: `{` + ok + `,"user_metadata":{"a":"` + rep("x", 501) + `"}}`, loose: true, status: 400, code: "invalid_request"},
		"metadata name too long":  {body: `{` + ok + `,"user_metadata":{"` + rep("k", 101) + `":"v"}}`, status: 400, code: "invalid_request"},
		"malformed json":          {body: `{`, loose: true, status: 400, code: "invalid_request"},
		"null body":               {body: `null`, loose: true, status: 400, code: "invalid_request"},
		"array body":              {body: `[]`, loose: true, status: 400, code: "invalid_request"},
		"trailing data":           {body: `{` + ok + `} {}`, loose: true, status: 400, code: "invalid_request"},
		"trailing garbage":        {body: `{` + ok + `}x`, loose: true, status: 400, code: "invalid_request"},
		"body over 64 KiB":        {body: `{` + ok + `,"nickname":"` + rep("x", 64<<10) + `"}`, loose: true, status: 400, code: "invalid_request"},
		"repeated form key":       {ct: "application/x-www-form-urlencoded", body: "client_id=app&client_id=app&connection=Username-Password-Authentication&email=x@acme.test&password=a+good+password+1", loose: true, status: 400, code: "invalid_request"},
		"unsupported media type":  {ct: "text/plain", body: `{` + ok + `}`, loose: true, status: 400, code: "invalid_request"},
		"missing content type":    {ct: "-", body: `{` + ok + `}`, loose: true, status: 400, code: "invalid_request"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.strict = !tc.loose
			ct := tc.ct
			switch ct {
			case "":
				ct = "application/json"
			case "-":
				ct = ""
			}
			code, body, _ := e.post(t, "/dbconnections/signup", ct, tc.body)
			if code != tc.status || body["error"] != tc.code || body["error_description"] == "" {
				t.Fatalf("got %d %v; want %d %s", code, body, tc.status, tc.code)
			}
			if d, _ := body["error_description"].(string); !strings.Contains(d, tc.descContain) {
				t.Fatalf("description %q lacks %q", d, tc.descContain)
			}
			if strings.Contains(fmt.Sprint(body["error_description"]), "kkkkk") {
				t.Fatalf("description echoes the metadata key: %v", body)
			}
		})
	}
}

func TestSignupMetadataLimitsAccepted(t *testing.T) {
	e := newEnv(t)
	props := make([]string, 0, 10)
	for i := 0; i < 9; i++ {
		props = append(props, fmt.Sprintf(`"p%d":"v"`, i))
	}
	props = append(props, `"long":"`+strings.Repeat("x", 500)+`"`)
	body := `{"client_id":"app","connection":"Username-Password-Authentication","email":"m@acme.test","password":"a good password 1","user_metadata":{` + strings.Join(props, ",") + `}}`
	if code, b, _ := e.post(t, "/dbconnections/signup", "application/json", body); code != 200 {
		t.Fatalf("10 properties / 500 characters = %d %v", code, b)
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

func TestLegacySignup(t *testing.T) {
	e := newEnv(t)
	legacy := map[string]any{}
	e.scripts.Funcs[store.ScriptGetUser] = func(args []any) (any, error) {
		if args[0] == "old@legacy.test" {
			return map[string]any{"user_id": "1", "email": "old@legacy.test"}, nil
		}
		return nil, nil
	}
	e.scripts.Funcs[store.ScriptCreate] = func(args []any) (any, error) {
		legacy = args[0].(map[string]any)
		return nil, nil
	}
	e.scripts.Funcs[store.ScriptLogin] = func(args []any) (any, error) {
		return map[string]any{"user_id": "legacy-77", "email": args[0]}, nil
	}
	code, body, _ := e.post(t, "/dbconnections/signup", "application/json",
		`{"client_id":"app","connection":"Legacy-DB","email":"new@legacy.test","password":"a good password 1"}`)
	if code != 200 || body["_id"] != "legacy-77" || legacy["client_id"] != "app" || legacy["tenant"] != "acme" {
		t.Fatalf("signup = %d %v; create got %v", code, body, legacy)
	}
	code, body, _ = e.post(t, "/dbconnections/signup", "application/json",
		`{"client_id":"app","connection":"Legacy-DB","email":"old@legacy.test","password":"a good password 1"}`)
	if code != 409 || body["error"] != "user_exists" {
		t.Fatalf("existing = %d %v", code, body)
	}
}

func TestLegacySignupScriptErrors(t *testing.T) {
	e := newEnv(t)
	e.scripts.Funcs[store.ScriptGetUser] = func([]any) (any, error) { return nil, nil }
	var createErr error
	e.scripts.Funcs[store.ScriptCreate] = func([]any) (any, error) { return nil, createErr }
	post := func() (int, map[string]any) {
		code, body, _ := e.post(t, "/dbconnections/signup", "application/json",
			`{"client_id":"app","connection":"Legacy-DB","email":"new@legacy.test","password":"a good password 1"}`)
		return code, body
	}
	createErr = &customdb.ScriptError{Kind: customdb.KindUnauthorized, Message: "sign-ups are closed"}
	if code, body := post(); code != 401 || body["error"] != "unauthorized" || body["error_description"] != "sign-ups are closed" {
		t.Fatalf("unauthorized = %d %v", code, body)
	}
	createErr = &customdb.ScriptError{Kind: customdb.KindValidation, Code: "bad_domain", Message: "that domain is not allowed"}
	if code, body := post(); code != 400 || body["error"] != "invalid_signup" || body["error_description"] != "that domain is not allowed" {
		t.Fatalf("validation = %d %v", code, body)
	}
	createErr = customdb.ErrTimeout
	if code, body := post(); code != 500 || body["error"] != "server_error" {
		t.Fatalf("script error = %d %v", code, body)
	}
}

// useImportMode puts the Legacy-DB connection in import mode.
func (e *env) useImportMode(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	c, err := e.st.Connections().GetByName(ctx, e.tenantID, "Legacy-DB")
	if err != nil {
		t.Fatal(err)
	}
	c.ImportMode = true
	if err := e.st.Connections().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
}

// In import mode a sign-up is refused when get_user knows the user, and is
// otherwise stored locally without calling create.
func TestImportSignup(t *testing.T) {
	e := newEnv(t)
	e.useImportMode(t)
	e.scripts.Funcs[store.ScriptGetUser] = func(args []any) (any, error) {
		if args[0] == "old@legacy.test" {
			return map[string]any{"user_id": "1", "email": "old@legacy.test"}, nil
		}
		return nil, nil
	}
	e.scripts.Funcs[store.ScriptCreate] = func([]any) (any, error) {
		t.Error("create called in import mode")
		return nil, nil
	}
	code, body, _ := e.post(t, "/dbconnections/signup", "application/json",
		`{"client_id":"app","connection":"Legacy-DB","email":"old@legacy.test","password":"a good password 1"}`)
	if code != 409 || body["error"] != "user_exists" {
		t.Fatalf("existing = %d %v", code, body)
	}
	code, body, _ = e.post(t, "/dbconnections/signup", "application/json",
		`{"client_id":"app","connection":"Legacy-DB","email":"new@legacy.test","password":"a good password 1"}`)
	if code != 200 {
		t.Fatalf("signup = %d %v", code, body)
	}
	id, _ := body["_id"].(string)
	u, err := e.st.Users().Get(context.Background(), e.tenantID, "auth0|"+id)
	if err != nil || u.Email != "new@legacy.test" || u.Identities[0].Connection != "Legacy-DB" || u.Identities[0].PasswordHash == "" {
		t.Fatalf("local user = %+v, %v", u, err)
	}
}

// The connection's dictionary, personal data and username rules apply to
// /dbconnections/signup.
func TestSignupPasswordAndUsernameRules(t *testing.T) {
	e := newEnv(t)
	e.strict = false
	ctx := context.Background()
	c, err := e.st.Connections().GetByName(ctx, e.tenantID, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	c.PasswordOptions.Dictionary = store.PasswordDictionary{Active: true, Default: store.DictionaryEn10k, Custom: []string{"Acme-House-1"}}
	c.PasswordOptions.ProfileData = store.PasswordProfileData{Active: true, BlockedFields: []string{"email"}}
	c.RequiresUsername, c.UsernameMin = true, 4
	if err := e.st.Connections().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	post := func(email, username, password string) (int, map[string]any) {
		body := `{"client_id":"app","connection":"Username-Password-Authentication","email":"` + email +
			`","username":"` + username + `","password":"` + password + `"}`
		code, out, _ := e.post(t, "/dbconnections/signup", "application/json", body)
		return code, out
	}
	for name, tc := range map[string]struct{ email, user, pw, code string }{
		"dictionary":    {"x@acme.test", "xavier", "password1", "invalid_password"},
		"custom word":   {"x@acme.test", "xavier", "ACME-house-1", "invalid_password"},
		"personal data": {"zelda@acme.test", "zed1", "my-ZELDA-pass", "invalid_password"},
		"short name":    {"x@acme.test", "xyz", "a good password 1", "invalid_signup"},
	} {
		if code, out := post(tc.email, tc.user, tc.pw); code != 400 || out["error"] != tc.code {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if code, out := post("x@acme.test", "xavier", "a good password 1"); code != 200 {
		t.Fatalf("valid signup = %d %v", code, out)
	}
}
