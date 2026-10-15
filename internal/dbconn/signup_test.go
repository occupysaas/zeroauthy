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
	req.Header.Set("Content-Type", contentType)
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
	cases := map[string]struct {
		body   string
		status int
		code   string
	}{
		"missing password":        {`{"client_id":"app","connection":"Username-Password-Authentication","email":"x@acme.test"}`, 400, "invalid_request"},
		"missing connection":      {`{"client_id":"app","email":"x@acme.test","password":"a good password 1"}`, 400, "invalid_request"},
		"missing client_id":       {`{"connection":"Username-Password-Authentication","email":"x@acme.test","password":"a good password 1"}`, 400, "invalid_request"},
		"unknown client":          {`{"client_id":"nope","connection":"Username-Password-Authentication","email":"x@acme.test","password":"a good password 1"}`, 400, "invalid_request"},
		"connection not enabled":  {`{"client_id":"app","connection":"Not-Enabled","email":"x@acme.test","password":"a good password 1"}`, 400, "invalid_signup"},
		"signup disabled":         {`{"client_id":"app","connection":"Closed","email":"x@acme.test","password":"a good password 1"}`, 400, "invalid_signup"},
		"weak password":           {`{"client_id":"app","connection":"Username-Password-Authentication","email":"x@acme.test","password":"short"}`, 400, "invalid_password"},
		"bad email":               {`{"client_id":"app","connection":"Username-Password-Authentication","email":"nope","password":"a good password 1"}`, 400, "invalid_signup"},
		"metadata not string":     {`{` + ok + `,"user_metadata":{"n":1}}`, 400, "invalid_request"},
		"metadata too many":       {`{` + ok + `,"user_metadata":{"a":"1","b":"1","c":"1","d":"1","e":"1","f":"1","g":"1","h":"1","i":"1","j":"1","k":"1"}}`, 400, "invalid_request"},
		"metadata value too long": {`{` + ok + `,"user_metadata":{"a":"` + strings.Repeat("x", 501) + `"}}`, 400, "invalid_request"},
		"malformed json":          {`{`, 400, "invalid_request"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.strict = false // these requests deliberately violate the request schema
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
