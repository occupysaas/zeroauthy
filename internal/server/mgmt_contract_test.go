package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/zeroauthy/zeroauthy/api"
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
