package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/zeroauthy/zeroauthy/api"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// mgmtContract checks responses against api/management.yaml.
type mgmtContract struct {
	t      *testing.T
	router routers.Router
}

func newMgmtContract(t *testing.T) *mgmtContract {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromData(api.ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	// Route on the test tenant's host instead of the spec's template.
	doc.Servers = openapi3.Servers{{URL: "https://acme.example.test"}, {URL: "https://" + mgmtSystemHost}}
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		t.Fatal(err)
	}
	return &mgmtContract{t: t, router: router}
}

// do sends the request through h and validates the response against the
// operation's declared responses.
func (c *mgmtContract) do(h http.Handler, method, target, token string, body any) (int, []byte) {
	c.t.Helper()
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	route, params, err := c.router.FindRoute(httptest.NewRequest(method, target, nil))
	if err != nil {
		c.t.Fatalf("%s %s: not in the contract: %v", method, target, err)
	}
	in := &openapi3filter.RequestValidationInput{
		Request: req, PathParams: params, Route: route,
		Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
	}
	out := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: in,
		Status:                 rec.Code,
		Header:                 rec.Header(),
		Body:                   io.NopCloser(bytes.NewReader(rec.Body.Bytes())),
		Options:                &openapi3filter.Options{IncludeResponseStatus: true},
	}
	if err := openapi3filter.ValidateResponse(context.Background(), out); err != nil {
		c.t.Errorf("%s %s → %d %s: %v", method, target, rec.Code, rec.Body, err)
	}
	return rec.Code, rec.Body.Bytes()
}

func TestManagementContract(t *testing.T) {
	h, st := newMgmtEnv(t)
	c := newMgmtContract(t)
	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	reader := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	base := "https://acme.example.test/api/v2/clients"

	code, body := c.do(h, "POST", base, admin, map[string]any{"name": "Contract", "app_type": "spa", "callbacks": []string{"https://c.test/cb"}})
	var created map[string]any
	_ = json.Unmarshal(body, &created)
	id, _ := created["client_id"].(string)
	if code != 201 || id == "" {
		t.Fatalf("create = %d %s", code, body)
	}
	c.do(h, "POST", base, admin, map[string]any{"name": "Server", "third_party_security_mode": "strict", "is_first_party": false})
	c.do(h, "POST", base, admin, map[string]any{"colour": "blue"})
	c.do(h, "POST", base, reader, map[string]any{"name": "x"})
	c.do(h, "POST", base, "not-a-token", map[string]any{"name": "x"})
	c.do(h, "GET", base, admin, nil)
	c.do(h, "GET", base+"?include_totals=true&per_page=1", admin, nil)
	c.do(h, "GET", base+"?per_page=500", admin, nil)
	c.do(h, "GET", base+"/"+id, reader, nil)
	c.do(h, "GET", base+"/nope", reader, nil)
	c.do(h, "PATCH", base+"/"+id, admin, map[string]any{"web_origins": []string{"https://c.test"}})
	c.do(h, "PATCH", base+"/"+id, admin, map[string]any{"is_first_party": false})
	c.do(h, "POST", base+"/"+id+"/rotate-secret", admin, nil)
	c.do(h, "DELETE", base+"/"+id, admin, nil)
	c.do(h, "DELETE", base+"/"+id, admin, nil)

	rsBase := "https://acme.example.test/api/v2/resource-servers"
	code, body = c.do(h, "POST", rsBase, admin, map[string]any{"identifier": "https://api.contract.test/", "name": "Contract", "scopes": []map[string]any{{"value": "read:x", "description": "Read"}}})
	var api map[string]any
	_ = json.Unmarshal(body, &api)
	rsID, _ := api["id"].(string)
	if code != 201 || rsID == "" {
		t.Fatalf("create API = %d %s", code, body)
	}
	c.do(h, "POST", rsBase, admin, map[string]any{"identifier": "bare"})
	c.do(h, "POST", rsBase, admin, map[string]any{"identifier": "https://api.contract.test/"})
	c.do(h, "POST", rsBase, admin, map[string]any{"identifier": acmeMgmtAPI})
	c.do(h, "POST", rsBase, admin, map[string]any{"identifier": "x", "signing_alg": "HS256"})
	c.do(h, "POST", rsBase, reader, map[string]any{"identifier": "y"})
	c.do(h, "GET", rsBase, admin, nil)
	c.do(h, "GET", rsBase+"?include_totals=true&per_page=1&identifiers=bare&identifiers=nope", admin, nil)
	c.do(h, "GET", rsBase+"?fields=name&include_fields=false", admin, nil)
	c.do(h, "GET", rsBase+"?take=5", admin, nil)
	c.do(h, "GET", rsBase+"/"+rsID, reader, nil)
	c.do(h, "GET", rsBase+"/"+url.PathEscape("https://api.contract.test/"), reader, nil)
	c.do(h, "GET", rsBase+"/nope", reader, nil)
	c.do(h, "PATCH", rsBase+"/"+rsID, admin, map[string]any{"token_lifetime": 600, "scopes": []map[string]any{{"value": "read:y"}}})
	c.do(h, "PATCH", rsBase+"/"+rsID, admin, map[string]any{"identifier": "https://elsewhere.test"})
	c.do(h, "PATCH", rsBase+"/nope", admin, map[string]any{})
	c.do(h, "DELETE", rsBase+"/"+rsID, reader, nil)
	c.do(h, "DELETE", rsBase+"/"+rsID, admin, nil)
	c.do(h, "DELETE", rsBase+"/"+rsID, admin, nil)
	code, body = c.do(h, "GET", rsBase+"/"+url.PathEscape(acmeMgmtAPI), admin, nil)
	_ = json.Unmarshal(body, &api)
	if code != 200 || api["is_system"] != true {
		t.Fatalf("get the Management API = %d %s", code, body)
	}
	c.do(h, "DELETE", rsBase+"/"+api["id"].(string), admin, nil)

	cgBase := "https://acme.example.test/api/v2/client-grants"
	code, body = c.do(h, "POST", rsBase, admin, map[string]any{"identifier": "https://api.grants.test/", "scopes": []map[string]any{{"value": "read:x"}, {"value": "write:x"}}})
	if code != 201 {
		t.Fatalf("create API = %d %s", code, body)
	}
	code, body = c.do(h, "POST", cgBase, admin, map[string]any{"client_id": "m2m", "audience": "https://api.grants.test/", "scope": []string{"read:x"}})
	var grant map[string]any
	_ = json.Unmarshal(body, &grant)
	gid, _ := grant["id"].(string)
	if code != 201 || gid == "" {
		t.Fatalf("create grant = %d %s", code, body)
	}
	c.do(h, "POST", cgBase, admin, map[string]any{"client_id": "admin", "audience": "https://api.grants.test/", "allow_all_scopes": true})
	c.do(h, "POST", cgBase, admin, map[string]any{"client_id": "m2m", "audience": "https://api.grants.test/", "subject_type": "user", "scope": []string{}})
	c.do(h, "POST", cgBase, admin, map[string]any{"client_id": "m2m", "audience": "https://api.grants.test/", "scope": []string{}})
	c.do(h, "POST", cgBase, admin, map[string]any{"client_id": "nope", "audience": "https://api.grants.test/", "scope": []string{}})
	c.do(h, "POST", cgBase, admin, map[string]any{"client_id": "m2m", "audience": "https://nope.test", "scope": []string{}})
	c.do(h, "POST", cgBase, admin, map[string]any{"client_id": "m2m", "audience": "https://api.grants.test/", "subject_type": "user", "scope": []string{"nope"}})
	c.do(h, "POST", cgBase, admin, map[string]any{"client_id": "m2m"})
	c.do(h, "POST", cgBase, reader, map[string]any{"client_id": "m2m", "audience": "https://api.grants.test/", "scope": []string{}})
	c.do(h, "GET", cgBase, admin, nil)
	c.do(h, "GET", cgBase+"?include_totals=true&per_page=1&client_id=m2m&audience="+url.QueryEscape("https://api.grants.test/"), admin, nil)
	code, body = c.do(h, "GET", cgBase+"?take=1", admin, nil)
	var cp map[string]any
	_ = json.Unmarshal(body, &cp)
	next, _ := cp["next"].(string)
	if code != 200 || next == "" {
		t.Fatalf("checkpoint page = %d %s", code, body)
	}
	c.do(h, "GET", cgBase+"?take=1&from="+next, admin, nil)
	c.do(h, "GET", cgBase+"?take=100&include_totals=true", admin, nil)
	c.do(h, "GET", cgBase+"?from=garbage", admin, nil)
	c.do(h, "GET", cgBase+"?take=0", admin, nil)
	c.do(h, "GET", cgBase+"?subject_type=client", admin, nil)
	c.do(h, "GET", cgBase+"?subject_type=robot&client_id=m2m", admin, nil)
	c.do(h, "GET", cgBase+"/"+gid, reader, nil)
	c.do(h, "GET", cgBase+"/cgr_0000000000000000", admin, nil)
	c.do(h, "GET", cgBase+"/nope", admin, nil)
	c.do(h, "PATCH", cgBase+"/"+gid, admin, map[string]any{"scope": []string{"read:x", "write:x"}})
	c.do(h, "PATCH", cgBase+"/"+gid, admin, map[string]any{"allow_all_scopes": true})
	c.do(h, "PATCH", cgBase+"/"+gid, admin, map[string]any{"scope": []string{"nope"}})
	c.do(h, "PATCH", cgBase+"/"+gid, admin, map[string]any{})
	c.do(h, "PATCH", cgBase+"/"+gid, admin, map[string]any{"audience": "x"})
	c.do(h, "PATCH", cgBase+"/cgr_0000000000000000", admin, map[string]any{"scope": []string{}})
	c.do(h, "PATCH", cgBase+"/nope", admin, map[string]any{"scope": []string{}})
	c.do(h, "DELETE", cgBase+"/"+gid, reader, nil)
	c.do(h, "DELETE", cgBase+"/"+gid, admin, nil)
	c.do(h, "DELETE", cgBase+"/"+gid, admin, nil)
	c.do(h, "DELETE", cgBase+"/nope", admin, nil)

	cnBase := "https://acme.example.test/api/v2/connections"
	code, body = c.do(h, "POST", cnBase, admin, map[string]any{"name": "Contract-Db", "strategy": "auth0", "enabled_clients": []string{"m2m"}, "options": map[string]any{
		"enabledDatabaseCustomization": true, "customScripts": map[string]any{"login": "function login(e,p,cb){cb(null,{})}"}, "configuration": map[string]any{"K": "v"}, "unknown_key": []any{1, "a"},
	}})
	var conn map[string]any
	_ = json.Unmarshal(body, &conn)
	cnID, _ := conn["id"].(string)
	if code != 201 || cnID == "" {
		t.Fatalf("create connection = %d %s", code, body)
	}
	c.do(h, "POST", cnBase, admin, map[string]any{"name": "Contract-Plain", "strategy": "auth0"})
	c.do(h, "POST", cnBase, admin, map[string]any{"name": "Contract-Db", "strategy": "auth0"})
	c.do(h, "POST", cnBase, admin, map[string]any{"name": "Other", "strategy": "samlp"})
	c.do(h, "POST", cnBase, admin, map[string]any{"name": "Ghosts", "strategy": "auth0", "enabled_clients": []string{"ghost"}})
	c.do(h, "POST", cnBase, reader, map[string]any{"name": "Reader", "strategy": "auth0"})
	c.do(h, "GET", cnBase, admin, nil)
	c.do(h, "GET", cnBase+"?include_totals=true&per_page=1&name=Contract-Db&strategy=auth0&strategy=samlp", admin, nil)
	c.do(h, "GET", cnBase+"?fields=name&include_fields=true", admin, nil)
	c.do(h, "GET", cnBase+"?per_page=101", admin, nil)
	code, body = c.do(h, "GET", cnBase+"?take=1", admin, nil)
	cp = nil
	_ = json.Unmarshal(body, &cp)
	next, _ = cp["next"].(string)
	if code != 200 || next == "" {
		t.Fatalf("connection checkpoint page = %d %s", code, body)
	}
	c.do(h, "GET", cnBase+"?take=1&from="+next, admin, nil)
	c.do(h, "GET", cnBase+"?from=garbage", admin, nil)
	c.do(h, "GET", cnBase+"/"+cnID, reader, nil)
	c.do(h, "GET", cnBase+"/"+cnID, admin, nil)
	c.do(h, "GET", cnBase+"/"+cnID+"?fields=options&include_fields=false", admin, nil)
	c.do(h, "GET", cnBase+"/con_0000000000000000", admin, nil)
	c.do(h, "GET", cnBase+"/nope", admin, nil)
	c.do(h, "PATCH", cnBase+"/"+cnID, admin, map[string]any{"options": map[string]any{"disable_signup": true}})
	c.do(h, "PATCH", cnBase+"/"+cnID, admin, map[string]any{"display_name": "Contract"})
	c.do(h, "PATCH", cnBase+"/"+cnID, admin, map[string]any{"name": "Renamed"})
	c.do(h, "PATCH", cnBase+"/"+cnID, admin, map[string]any{})
	c.do(h, "PATCH", cnBase+"/con_0000000000000000", admin, map[string]any{"display_name": "x"})
	c.do(h, "PATCH", cnBase+"/nope", admin, map[string]any{"display_name": "x"})
	c.do(h, "PATCH", cnBase+"/"+cnID, reader, map[string]any{"display_name": "x"})
	c.do(h, "GET", cnBase+"/"+cnID+"/clients", admin, nil)
	c.do(h, "GET", cnBase+"/"+cnID+"/clients?take=1&from=garbage", admin, nil)
	c.do(h, "GET", cnBase+"/con_0000000000000000/clients", admin, nil)
	c.do(h, "PATCH", cnBase+"/"+cnID+"/clients", admin, []map[string]any{{"client_id": "admin", "status": true}})
	c.do(h, "PATCH", cnBase+"/"+cnID+"/clients", admin, []map[string]any{{"client_id": "ghost", "status": true}})
	c.do(h, "PATCH", cnBase+"/"+cnID+"/clients", admin, []map[string]any{})
	c.do(h, "PATCH", cnBase+"/"+cnID+"/clients", reader, []map[string]any{{"client_id": "admin", "status": true}})
	c.do(h, "PATCH", cnBase+"/nope/clients", admin, []map[string]any{{"client_id": "admin", "status": true}})
	c.do(h, "DELETE", cnBase+"/"+cnID, reader, nil)
	c.do(h, "DELETE", cnBase+"/"+cnID, admin, nil)
	c.do(h, "DELETE", cnBase+"/"+cnID, admin, nil)
	c.do(h, "DELETE", cnBase+"/nope", admin, nil)

	op, _ := operatorToken(t, st, "op@example.test")
	sys := "https://" + mgmtSystemHost + "/api/system"
	c.do(h, "GET", sys+"/tenants", op, nil)
	c.do(h, "POST", sys+"/tenants", op, map[string]any{"name": "globex", "domains": []string{"login.globex.test"}})
	c.do(h, "POST", sys+"/tenants", op, map[string]any{"name": "globex", "domains": []string{"login.globex.test"}})
	c.do(h, "PATCH", sys+"/tenants/globex", op, map[string]any{"friendly_name": "Globex"})
	c.do(h, "PATCH", sys+"/tenants/nope", op, map[string]any{"friendly_name": "Globex"})
	c.do(h, "DELETE", sys+"/tenants/globex?confirm=globex", op, nil)
	c.do(h, "GET", sys+"/operators", op, nil)
	code, body = c.do(h, "POST", sys+"/operators", op, map[string]any{"email": "new@example.test"})
	var invite map[string]any
	_ = json.Unmarshal(body, &invite)
	if code != 201 {
		t.Fatalf("invite = %d %s", code, body)
	}
	c.do(h, "DELETE", sys+"/operators/"+url.PathEscape(invite["user_id"].(string)), op, nil)
	c.do(h, "GET", sys+"/tenants", reader, nil)
}

func TestManagementContractUsers(t *testing.T) {
	a := newUsersAPI(t, nil)
	c := newMgmtContract(t)
	ro := clientToken(t, a.h, "acme.example.test", acmeMgmtAPI, "usersro", "usersro-s3cret")
	conn := "Username-Password-Authentication"

	code, body := c.do(a.h, "POST", usersBase, a.token, map[string]any{"connection": conn, "email": "Contract@Example.test", "password": "first horse 1",
		"given_name": "Con", "user_metadata": map[string]any{"a": 1}, "app_metadata": map[string]any{"plan": "pro"}})
	var created map[string]any
	_ = json.Unmarshal(body, &created)
	id, _ := created["user_id"].(string)
	if code != 201 || id == "" {
		t.Fatalf("create user = %d %s", code, body)
	}
	if err := a.st.Users().RecordLogin(context.Background(), a.tenantID(), id, time.Now(), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	c.do(a.h, "POST", usersBase, a.token, map[string]any{"connection": conn, "email": "blocked@example.test", "password": "first horse 1", "blocked": true, "user_id": "own-id"})
	c.do(a.h, "POST", usersBase, a.token, map[string]any{"connection": conn, "email": "contract@example.test", "password": "first horse 1"})
	c.do(a.h, "POST", usersBase, a.token, map[string]any{"email": "x@example.test", "password": "first horse 1"})
	c.do(a.h, "POST", usersBase, a.token, map[string]any{"connection": "Nope", "email": "x@example.test", "password": "first horse 1"})
	c.do(a.h, "POST", usersBase, a.token, map[string]any{"connection": conn, "email": "x@example.test", "password": "short"})
	c.do(a.h, "POST", usersBase, ro, map[string]any{"connection": conn, "email": "x@example.test", "password": "first horse 1"})
	c.do(a.h, "POST", usersBase, "not-a-token", map[string]any{"connection": conn})
	c.do(a.h, "GET", usersBase, a.token, nil)
	c.do(a.h, "GET", usersBase+"?include_totals=true&per_page=1&sort=email:1", a.token, nil)
	c.do(a.h, "GET", usersBase+"?q="+url.QueryEscape("email:contract@example.test")+"&search_engine=v3&fields=email", a.token, nil)
	c.do(a.h, "GET", usersBase+"?q="+url.QueryEscape("bogus:x"), a.token, nil)
	c.do(a.h, "GET", usersBase+"?search_engine=v1", a.token, nil)
	c.do(a.h, "GET", usersBase+"?per_page=100&page=10", a.token, nil)
	c.do(a.h, "GET", usersBase+"?connection="+conn, a.token, nil)
	c.do(a.h, "GET", usersBase+"/"+url.PathEscape(id), ro, nil)
	c.do(a.h, "GET", usersBase+"/"+url.PathEscape(id)+"?fields=identities&include_fields=false", ro, nil)
	c.do(a.h, "GET", usersBase+"/nope", ro, nil)
	c.do(a.h, "GET", usersBase+"/"+url.PathEscape("auth0|000000000000000000000000"), ro, nil)
	c.do(a.h, "PATCH", usersBase+"/"+url.PathEscape(id), a.token, map[string]any{"email": "contract2@example.test", "user_metadata": map[string]any{"a": nil}})
	c.do(a.h, "PATCH", usersBase+"/"+url.PathEscape(id), a.token, map[string]any{"password": "second horse 2"})
	c.do(a.h, "PATCH", usersBase+"/"+url.PathEscape(id), a.token, map[string]any{"email": "blocked@example.test"})
	c.do(a.h, "PATCH", usersBase+"/"+url.PathEscape(id), a.token, map[string]any{"colour": "blue"})
	c.do(a.h, "PATCH", usersBase+"/"+url.PathEscape(id), ro, map[string]any{"app_metadata": map[string]any{}})
	c.do(a.h, "PATCH", usersBase+"/"+url.PathEscape("auth0|000000000000000000000000"), a.token, map[string]any{"name": "x"})
	c.do(a.h, "GET", "https://acme.example.test/api/v2/users-by-email?email=contract2@example.test", a.token, nil)
	c.do(a.h, "GET", "https://acme.example.test/api/v2/users-by-email?email=nope", a.token, nil)
	c.do(a.h, "GET", "https://acme.example.test/api/v2/users-by-email", a.token, nil)
	code, body = c.do(a.h, "POST", usersBase, a.token, map[string]any{"connection": conn, "email": "second@example.test", "password": "first horse 1"})
	var second map[string]any
	_ = json.Unmarshal(body, &second)
	sid, _ := second["user_id"].(string)
	if code != 201 || sid == "" {
		t.Fatalf("create second user = %d %s", code, body)
	}
	bare := strings.TrimPrefix(sid, "auth0|")
	idents := usersBase + "/" + url.PathEscape(id) + "/identities"
	if code, body := c.do(a.h, "POST", idents, a.token, map[string]any{"provider": "auth0", "user_id": bare}); code != 201 {
		t.Fatalf("link = %d %s", code, body)
	}
	c.do(a.h, "GET", usersBase+"/"+url.PathEscape(id), ro, nil)
	c.do(a.h, "POST", idents, a.token, map[string]any{"provider": "auth0", "user_id": bare})
	c.do(a.h, "POST", idents, a.token, map[string]any{"provider": "auth0", "user_id": strings.TrimPrefix(id, "auth0|")})
	c.do(a.h, "POST", idents, a.token, map[string]any{"provider": "auth0", "user_id": "000000000000000000000000"})
	c.do(a.h, "POST", idents, a.token, map[string]any{"provider": "auth0"})
	c.do(a.h, "POST", idents, a.token, map[string]any{"link_with": "not-a-jwt"})
	c.do(a.h, "POST", usersBase+"/"+url.PathEscape("auth0|000000000000000000000000")+"/identities", a.token, map[string]any{"provider": "auth0", "user_id": bare})
	c.do(a.h, "POST", idents, ro, map[string]any{"provider": "auth0", "user_id": bare})
	if code, body := c.do(a.h, "DELETE", idents+"/auth0/"+url.PathEscape(bare), a.token, nil); code != 200 {
		t.Fatalf("unlink = %d %s", code, body)
	}
	c.do(a.h, "DELETE", idents+"/auth0/"+url.PathEscape(bare), a.token, nil)
	c.do(a.h, "DELETE", idents+"/auth0/"+url.PathEscape(strings.TrimPrefix(id, "auth0|")), a.token, nil)
	c.do(a.h, "DELETE", usersBase+"/nope/identities/auth0/x", a.token, nil)
	sessionsAndGrantsContract(t, c, a, ro, id)
	c.do(a.h, "DELETE", usersBase+"/"+url.PathEscape(id), ro, nil)
	c.do(a.h, "DELETE", usersBase+"/"+url.PathEscape(id), a.token, nil)
	c.do(a.h, "DELETE", usersBase+"/"+url.PathEscape(id), a.token, nil)
	c.do(a.h, "DELETE", usersBase+"/nope", a.token, nil)
}

// sessionsAndGrantsContract exercises the session, refresh token and grant
// operations of user id (U8, U9).
func sessionsAndGrantsContract(t *testing.T, c *mgmtContract, a *usersAPI, ro, id string) {
	t.Helper()
	ctx, tid := context.Background(), a.tenantID()
	now := time.Now().UTC()
	if err := a.st.Sessions().Create(ctx, &store.LoginSession{TenantID: tid, ID: "contract-session", TokenHash: "h1", UserID: id, Connection: "Username-Password-Authentication",
		AuthenticatedAt: now, ClientIDs: []string{"spa"}, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now, LastInteractedAt: now,
		InitialIP: "192.0.2.1", InitialUserAgent: "ua", LastIP: "192.0.2.2", LastUserAgent: "ua2"}); err != nil {
		t.Fatal(err)
	}
	if err := a.st.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: tid, ID: "contract-token", TokenHash: "h2", FamilyID: "f", ClientID: "spa", UserID: id,
		SessionID: "contract-session", Scopes: []string{"openid"}, Audience: "https://api.acme.test", ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := a.st.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: tid, ID: "contract-token2", TokenHash: "h3", FamilyID: "f2", ClientID: "spa", UserID: id,
		Scopes: []string{"openid"}, CreatedAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.st.UserGrants().Upsert(ctx, &store.UserGrant{TenantID: tid, ID: "contract-grant", ClientID: "spa", UserID: id, Audience: "https://api.acme.test",
		Scopes: []string{"read:things", "openid"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	us := usersBase + "/" + url.PathEscape(id)
	base := "https://acme.example.test/api/v2/"
	c.do(a.h, "GET", us+"/sessions", a.token, nil)
	c.do(a.h, "GET", us+"/sessions?take=1", a.token, nil)
	c.do(a.h, "GET", us+"/sessions?take=101", a.token, nil)
	c.do(a.h, "GET", us+"/sessions?from=garbage", a.token, nil)
	c.do(a.h, "GET", us+"/sessions", ro, nil)
	c.do(a.h, "GET", usersBase+"/nope/sessions", a.token, nil)
	c.do(a.h, "GET", usersBase+"/"+url.PathEscape("auth0|000000000000000000000000")+"/sessions", a.token, nil)
	c.do(a.h, "GET", base+"sessions/contract-session", a.token, nil)
	c.do(a.h, "GET", base+"sessions/nope", a.token, nil)
	c.do(a.h, "GET", base+"sessions/contract-session", ro, nil)
	c.do(a.h, "GET", us+"/refresh-tokens", a.token, nil)
	c.do(a.h, "GET", us+"/refresh-tokens?take=1", a.token, nil)
	c.do(a.h, "GET", us+"/refresh-tokens?take=101", a.token, nil)
	c.do(a.h, "GET", us+"/refresh-tokens", ro, nil)
	c.do(a.h, "GET", base+"refresh-tokens/contract-token", a.token, nil)
	c.do(a.h, "GET", base+"refresh-tokens/contract-token2", a.token, nil)
	c.do(a.h, "GET", base+"refresh-tokens/nope", a.token, nil)
	c.do(a.h, "GET", base+"grants", a.token, nil)
	c.do(a.h, "GET", base+"grants?include_totals=true&user_id="+url.QueryEscape(id), a.token, nil)
	c.do(a.h, "GET", base+"grants?user_id=nobody", a.token, nil)
	c.do(a.h, "GET", base+"grants", ro, nil)
	c.do(a.h, "DELETE", base+"sessions/contract-session", ro, nil)
	if code, body := c.do(a.h, "DELETE", base+"sessions/contract-session", a.token, nil); code != 202 || strings.TrimSpace(string(body)) != "{}" {
		t.Errorf("delete session = %d %s", code, body)
	}
	c.do(a.h, "DELETE", base+"sessions/contract-session", a.token, nil)
	if code, _ := c.do(a.h, "DELETE", us+"/sessions", a.token, nil); code != 202 {
		t.Errorf("delete user sessions = %d", code)
	}
	c.do(a.h, "DELETE", usersBase+"/nope/sessions", a.token, nil)
	c.do(a.h, "DELETE", usersBase+"/"+url.PathEscape("auth0|000000000000000000000000")+"/sessions", a.token, nil)
	if code, _ := c.do(a.h, "DELETE", base+"refresh-tokens/contract-token", a.token, nil); code != 202 {
		t.Errorf("delete token = %d", code)
	}
	c.do(a.h, "DELETE", base+"refresh-tokens/nope", a.token, nil)
	if code, _ := c.do(a.h, "DELETE", us+"/refresh-tokens", a.token, nil); code != 202 {
		t.Errorf("delete user tokens = %d", code)
	}
	c.do(a.h, "DELETE", us+"/refresh-tokens", ro, nil)
	c.do(a.h, "DELETE", base+"grants/contract-grant", ro, nil)
	if code, _ := c.do(a.h, "DELETE", base+"grants/contract-grant", a.token, nil); code != 204 {
		t.Errorf("delete grant = %d", code)
	}
	c.do(a.h, "DELETE", base+"grants?user_id="+url.QueryEscape(id), a.token, nil)
	c.do(a.h, "DELETE", base+"grants", a.token, nil)
}
