package dbconn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
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
`

type env struct {
	st       store.Store
	h        *Handlers
	tenantID string
	strict   bool
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := memory.New()
	f, err := seed.Parse([]byte(seedYAML))
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
	return &env{st: st, tenantID: tn.ID, strict: true, h: &Handlers{
		Store: st, Now: fixedNow,
		Database:   &identity.Database{Store: st, Now: fixedNow},
		IPThrottle: identity.NewThrottle(100, time.Hour, time.Hour),
	}}
}

// post sends a request to the signup endpoint and decodes the JSON reply.
// Requests are checked against the spec unless e.strict is false.
func (e *env) post(t *testing.T, path, contentType, body string) (int, map[string]any, string) {
	t.Helper()
	var h http.Handler = tenant.NewResolver(e.st.Tenants(), "", false).Middleware(http.HandlerFunc(e.h.Signup))
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
