package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// The resource server operations through the whole server: scopes per
// route, reading by URL-encoded identifier, the identifiers filter, and an
// API created through the API serving client credentials tokens.
func TestManagementResourceServersThroughServer(t *testing.T) {
	h, st := newMgmtEnv(t)
	reader := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	admin := clientToken(t, h, "login.acme.test", acmeMgmtAPI, "admin", "admin-s3cret")
	base := "https://acme.example.test/api/v2/resource-servers"
	const aud = "https://api.orders.test/v1"

	rec, _ := sendJSON(h, "POST", base, reader, map[string]any{"identifier": aud})
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "insufficient_scope") {
		t.Fatalf("create with read:resource_servers = %d %s", rec.Code, rec.Body)
	}
	rec, created := sendJSON(h, "POST", "https://login.acme.test/api/v2/resource-servers", admin, map[string]any{
		"identifier": aud, "name": "Orders", "scopes": []map[string]any{{"value": "read:orders", "description": "Read"}, {"value": "write:orders"}},
	})
	id, _ := created["id"].(string)
	if rec.Code != 201 || id == "" || created["identifier"] != aud {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	rec, body := sendJSON(h, "POST", base, admin, map[string]any{"identifier": aud})
	if rec.Code != 409 || body["errorCode"] != "resource_server_conflict" {
		t.Errorf("duplicate = %d %s", rec.Code, rec.Body)
	}

	// By ID, and by the URL-encoded identifier (auth0-cli reads by audience).
	for _, key := range []string{id, url.PathEscape(aud)} {
		rec, body = sendJSON(h, "GET", base+"/"+key, reader, nil)
		if rec.Code != 200 || body["id"] != id {
			t.Errorf("get %s = %d %s", key, rec.Code, rec.Body)
		}
	}
	rec, body = sendJSON(h, "GET", base+"/nope", reader, nil)
	if rec.Code != 404 || body["errorCode"] != "inexistent_resource_server" {
		t.Errorf("get unknown = %d %s", rec.Code, rec.Body)
	}

	// Listing: the Management API first, the identifiers filter, no paging by checkpoint.
	req := httptest.NewRequest("GET", base+"?include_totals=true&identifiers="+url.QueryEscape(aud)+"&identifiers=nope", nil)
	req.Header.Set("Authorization", "Bearer "+reader)
	lrec := httptest.NewRecorder()
	h.ServeHTTP(lrec, req)
	if lrec.Code != 200 || !strings.Contains(lrec.Body.String(), `"resource_servers"`) || !strings.Contains(lrec.Body.String(), `"total":1`) {
		t.Errorf("list = %d %s", lrec.Code, lrec.Body)
	}
	for _, q := range []string{"?from=x", "?take=3"} {
		rec, body = sendJSON(h, "GET", base+q, reader, nil)
		if rec.Code != 400 || body["errorCode"] != "invalid_query_string" {
			t.Errorf("list %s = %d %s", q, rec.Code, rec.Body)
		}
	}

	// A client grant makes the API serve tokens; removing a scope removes it
	// from the grant, and the token endpoint then no longer offers it.
	tn, _ := st.Tenants().GetByName(context.Background(), "acme")
	if err := st.ClientGrants().Create(context.Background(), &store.ClientGrant{TenantID: tn.ID, ID: "cg_orders", ClientID: "m2m",
		Audience: aud, Scopes: []string{"read:orders", "write:orders"}, SubjectType: store.SubjectTypeClient}); err != nil {
		t.Fatal(err)
	}
	token := func() (int, map[string]any) {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"m2m"}, "client_secret": {"s3cret"}, "audience": {aud}}
		req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		trec := httptest.NewRecorder()
		h.ServeHTTP(trec, req)
		var out map[string]any
		_ = json.Unmarshal(trec.Body.Bytes(), &out)
		return trec.Code, out
	}
	if code, tok := token(); code != 200 || tok["scope"] != "read:orders write:orders" {
		t.Fatalf("token = %d %v", code, tok)
	}
	rec, body = sendJSON(h, "PATCH", base+"/"+id, admin, map[string]any{"scopes": []map[string]any{{"value": "read:orders"}}})
	if rec.Code != 200 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	if code, tok := token(); code != 200 || tok["scope"] != "read:orders" {
		t.Errorf("token after removing a scope = %d %v", code, tok)
	}
	rec, body = sendJSON(h, "PATCH", base+"/"+id, admin, map[string]any{"identifier": "https://elsewhere.test"})
	if rec.Code != 400 || body["errorCode"] != "invalid_body" {
		t.Errorf("patch identifier = %d %s", rec.Code, rec.Body)
	}

	// Delete: the reader may not; the admin may, twice.
	if rec, _ = sendJSON(h, "DELETE", base+"/"+id, reader, nil); rec.Code != 403 {
		t.Errorf("delete with read:resource_servers = %d", rec.Code)
	}
	for i := 0; i < 2; i++ {
		if rec, _ = sendJSON(h, "DELETE", base+"/"+id, admin, nil); rec.Code != 204 || rec.Body.Len() != 0 {
			t.Errorf("delete #%d = %d %q", i, rec.Code, rec.Body)
		}
	}
	rec, body = sendJSON(h, "GET", base+"/"+id, admin, nil)
	if rec.Code != 404 || body["errorCode"] != "inexistent_resource_server" {
		t.Errorf("get after delete = %d %s", rec.Code, rec.Body)
	}
	if _, err := st.ClientGrants().Find(context.Background(), tn.ID, "m2m", aud, store.SubjectTypeClient); err == nil {
		t.Error("the client grant survived the API")
	}
	if code, tok := token(); code == 200 {
		t.Errorf("a token was issued for the deleted API: %v", tok)
	}

	// The tenant's Management API cannot be deleted through the API.
	rec, body = sendJSON(h, "GET", base+"/"+url.PathEscape(acmeMgmtAPI), admin, nil)
	sysID, _ := body["id"].(string)
	if rec.Code != 200 || body["is_system"] != true || sysID == "" {
		t.Fatalf("the Management API is not readable by identifier: %d %s", rec.Code, rec.Body)
	}
	rec, body = sendJSON(h, "DELETE", base+"/"+sysID, admin, nil)
	if rec.Code != 400 || body["errorCode"] != "delete_system_resource_server" {
		t.Errorf("delete the Management API = %d %s", rec.Code, rec.Body)
	}
}

// Review focus 2: deleting an API takes its client grants and the consents
// for its audience with it, and refresh tokens issued for it stop
// refreshing; the access tokens already issued stay valid until they expire.
func TestDeleteResourceServerCascades(t *testing.T) {
	e := newFlowEnv(t)
	c := e.client(t)
	tok := e.codeFlow(t, c, "scope", "openid offline_access read:things")
	rt, _ := tok["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh token: %v", tok)
	}
	ctx := context.Background()
	tn, _ := e.st.Tenants().GetByName(ctx, "flow")
	api, err := e.st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://api.flow.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.UserGrants().Upsert(ctx, &store.UserGrant{TenantID: tn.ID, ID: "ug_flow", ClientID: "partner", UserID: "auth0|u1",
		Audience: "https://api.flow.test", Scopes: []string{"read:things"}}); err != nil {
		t.Fatal(err)
	}
	if grants, _, _ := e.st.ClientGrants().List(ctx, tn.ID, store.ClientGrantFilter{Audience: api.Identifier}, store.Page{}); len(grants) != 1 {
		t.Fatalf("%d client grants before the delete, want 1", len(grants))
	}

	h := &mgmt.Handlers{Store: e.st, Wrapper: e.w}
	req := httptest.NewRequest("DELETE", e.base+"/api/v2/resource-servers/"+api.ID, nil)
	req = req.WithContext(mgmt.WithCaller(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: tn, Host: tn.Domains[0]}),
		mgmt.Caller{Kind: mgmt.M2M, ClientID: "test", Scopes: []string{"delete:resource_servers"}}))
	rec := httptest.NewRecorder()
	mgmtAPI{h}.DeleteResourceServer(rec, req, api.ID)
	if rec.Code != 204 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}

	if resp, body := e.postForm(t, c, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {rt}}); resp.StatusCode == 200 {
		t.Fatalf("refresh after delete = %d %v", resp.StatusCode, body)
	}
	if grants, _, _ := e.st.ClientGrants().List(ctx, tn.ID, store.ClientGrantFilter{Audience: api.Identifier}, store.Page{}); len(grants) != 0 {
		t.Errorf("%d client grants survived", len(grants))
	}
	if _, err := e.st.UserGrants().Find(ctx, tn.ID, "partner", "auth0|u1", api.Identifier); err == nil {
		t.Error("the user grant survived")
	}
	// Authorizing for the deleted audience fails; the session and the
	// tenant's other applications are unaffected.
	resp, _ := fetch(t, c, authorizeURL(e.base, "scope", "openid read:things"))
	if loc, _ := resp.Location(); loc != nil && loc.Query().Get("code") != "" {
		t.Errorf("authorize for the deleted API issued a code: %v", loc)
	}
}
