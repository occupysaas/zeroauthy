package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/scim"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The SCIM 2.0 routes are served on tenant hosts (Plan 37c), and a SCIM
// DELETE removes the user as the Management API does.
func TestSCIMRoutes(t *testing.T) {
	e := newFlowEnv(t)
	ctx := t.Context()
	tn, err := e.st.Tenants().GetByName(ctx, "flow")
	if err != nil {
		t.Fatal(err)
	}
	conn := &store.Connection{TenantID: tn.ID, ID: "con_scim0123456789", Name: "corp-scim", Strategy: "okta", Extra: map[string]any{"domain": "corp.okta.test"}}
	if err := e.st.Connections().Create(ctx, conn); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	d := e.st.Directory()
	if err := d.CreateSCIMConfig(ctx, &store.SCIMConfig{TenantID: tn.ID, ConnectionID: conn.ID, UserIDAttribute: scim.DefaultUserIDAttribute, Mapping: scim.DefaultMapping(), CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	token := "scim-test-token-for-routes"
	if err := d.CreateSCIMToken(ctx, &store.SCIMToken{TenantID: tn.ID, ConnectionID: conn.ID, ID: "tok_routes", Hash: scim.HashToken(token), Scopes: []string{"get:users", "post:users", "delete:users"}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	c := e.client(t)
	call := func(method, path, body string) *http.Response {
		req, _ := http.NewRequest(method, e.base+"/scim/v2/connections/"+conn.ID+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", scim.MediaType)
		resp, _ := mustDo(t, c, req)
		return resp
	}
	if resp := call("POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"00u1","userName":"jdoe@corp.test","emails":[{"primary":true,"value":"jdoe@corp.test"}]}`); resp.StatusCode != 201 ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), scim.MediaType) {
		t.Fatalf("create %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp := call("GET", "/Users?filter=userName%20eq%20%22jdoe@corp.test%22", ""); resp.StatusCode != 200 {
		t.Fatalf("list %d", resp.StatusCode)
	}
	if resp := call("DELETE", "/Users/okta|corp-scim|00u1", ""); resp.StatusCode != 204 {
		t.Fatalf("delete %d", resp.StatusCode)
	}
	if _, err := e.st.Users().Get(ctx, tn.ID, "okta|corp-scim|00u1"); err == nil {
		t.Fatal("user survived the SCIM DELETE")
	}
	req, _ := http.NewRequest("GET", e.base+"/scim/v2/connections/"+conn.ID+"/Users", nil)
	if resp, _ := mustDo(t, c, req); resp.StatusCode != 401 {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
}
