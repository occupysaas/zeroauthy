package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const acmeMgmtAPI = "https://acme.example.test/api/v2/"

func sendJSON(h http.Handler, method, target, token string, body any) (*httptest.ResponseRecorder, map[string]any) {
	var rd *bytes.Reader
	if body == nil {
		rd = bytes.NewReader(nil)
	} else {
		data, _ := json.Marshal(body)
		rd = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, target, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func tokenStatus(h http.Handler, id, secret string) int {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}, "audience": {acmeMgmtAPI}}
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// The clients operations through the whole server: scopes per route, a
// created client's secret working at the token endpoint, and rotation
// refusing the old secret at once (M4).
func TestManagementClientsThroughServer(t *testing.T) {
	h, st := newMgmtEnv(t)
	reader := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	admin := clientToken(t, h, "login.acme.test", acmeMgmtAPI, "admin", "admin-s3cret")

	rec, _ := sendJSON(h, "POST", "https://acme.example.test/api/v2/clients", reader, map[string]any{"name": "x"})
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "insufficient_scope") {
		t.Fatalf("create with read:clients = %d %s", rec.Code, rec.Body)
	}
	rec, created := sendJSON(h, "POST", "https://login.acme.test/api/v2/clients", admin,
		map[string]any{"name": "Worker", "app_type": "non_interactive", "grant_types": []string{"client_credentials"}})
	id, _ := created["client_id"].(string)
	secret, _ := created["client_secret"].(string)
	if rec.Code != 201 || id == "" || len(secret) != 64 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}

	// The reader sees it, without the secret, on either host.
	req := httptest.NewRequest("GET", "https://acme.example.test/api/v2/clients?include_totals=true", nil)
	req.Header.Set("Authorization", "Bearer "+reader)
	lrec := httptest.NewRecorder()
	h.ServeHTTP(lrec, req)
	var page struct {
		Clients []map[string]any `json:"clients"`
		Total   int              `json:"total"`
	}
	if err := json.Unmarshal(lrec.Body.Bytes(), &page); err != nil || lrec.Code != 200 || page.Total != 3 {
		t.Fatalf("list = %d %s", lrec.Code, lrec.Body)
	}
	for _, c := range page.Clients {
		if c["client_secret"] != nil {
			t.Errorf("client %v listed with its secret", c["client_id"])
		}
	}

	// The new client authenticates with its sealed secret once granted.
	tn, _ := st.Tenants().GetByName(context.Background(), "acme")
	if err := st.ClientGrants().Create(context.Background(), &store.ClientGrant{TenantID: tn.ID, ID: "cg_worker",
		ClientID: id, Audience: acmeMgmtAPI, Scopes: []string{"read:clients"}, SubjectType: store.SubjectTypeClient}); err != nil {
		t.Fatal(err)
	}
	if code := tokenStatus(h, id, secret); code != 200 {
		t.Fatalf("token with the created secret = %d", code)
	}
	rec, rotated := sendJSON(h, "POST", "https://acme.example.test/api/v2/clients/"+id+"/rotate-secret", admin, nil)
	if rec.Code != 200 || rotated["client_secret"] == secret {
		t.Fatalf("rotate = %d %s", rec.Code, rec.Body)
	}
	if code := tokenStatus(h, id, secret); code != 401 {
		t.Errorf("token with the old secret after rotation = %d, want 401", code)
	}
	if code := tokenStatus(h, id, rotated["client_secret"].(string)); code != 200 {
		t.Errorf("token with the new secret = %d", code)
	}

	// Unknown methods and paths answer in Auth0's shape.
	rec, body := sendJSON(h, "PUT", "https://acme.example.test/api/v2/clients/"+id, admin, map[string]any{})
	if rec.Code != 404 || body["statusCode"] != float64(404) {
		t.Errorf("PUT = %d %s", rec.Code, rec.Body)
	}
	rec, _ = sendJSON(h, "DELETE", "https://acme.example.test/api/v2/clients/"+id, reader, nil)
	if rec.Code != 403 {
		t.Errorf("delete with read:clients = %d", rec.Code)
	}
	rec, _ = sendJSON(h, "DELETE", "https://acme.example.test/api/v2/clients/"+id, admin, nil)
	if rec.Code != 204 {
		t.Errorf("delete = %d %s", rec.Code, rec.Body)
	}
	rec, body = sendJSON(h, "GET", "https://acme.example.test/api/v2/clients/"+id, admin, nil)
	if rec.Code != 404 || body["errorCode"] != "inexistent_client" {
		t.Errorf("get after delete = %d %s", rec.Code, rec.Body)
	}
}

// Review Focus 3: deleting a client whose user is signed in revokes its
// refresh tokens, and the session goes on working for the tenant's other
// clients, logout included.
func TestDeleteClientInUse(t *testing.T) {
	e := newFlowEnv(t)
	c := e.client(t)
	tok := e.codeFlow(t, c, "scope", "openid offline_access read:things")
	rt, _ := tok["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh token: %v", tok)
	}

	ctx := context.Background()
	tn, _ := e.st.Tenants().GetByName(ctx, "flow")
	h := &mgmt.Handlers{Store: e.st, Wrapper: e.w}
	req := httptest.NewRequest("DELETE", e.base+"/api/v2/clients/spa", nil)
	req = req.WithContext(mgmt.WithCaller(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: tn, Host: tn.Domains[0]}),
		mgmt.Caller{Kind: mgmt.M2M, ClientID: "test", Scopes: []string{"delete:clients"}}))
	rec := httptest.NewRecorder()
	mgmtAPI{h}.DeleteClient(rec, req, "spa")
	if rec.Code != 204 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}

	if resp, body := e.postForm(t, c, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {rt}}); resp.StatusCode == 200 {
		t.Fatalf("refresh after delete = %d %v", resp.StatusCode, body)
	}
	conn, _ := e.st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	for _, id := range conn.EnabledClients {
		if id == "spa" {
			t.Fatal("spa still enabled on the connection")
		}
	}

	// The session still signs the user in to another application silently.
	q := url.Values{"client_id": {"spa2"}, "redirect_uri": {"https://app2.flow.test/cb"}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"s2"}, "nonce": {"n2"}, "prompt": {"none"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	resp, page := fetch(t, c, e.base+"/authorize?"+q.Encode())
	loc, _ := resp.Location()
	if resp.StatusCode != 302 || loc == nil || loc.Host != "app2.flow.test" || loc.Query().Get("code") == "" {
		t.Fatalf("silent authorize for spa2 = %d %v %s", resp.StatusCode, loc, page)
	}
	resp, _ = fetch(t, c, e.base+"/v2/logout?"+url.Values{"client_id": {"spa2"}, "returnTo": {"https://app2.flow.test/bye"}}.Encode())
	if loc, _ := resp.Location(); resp.StatusCode != 302 || loc == nil || loc.String() != "https://app2.flow.test/bye" {
		t.Fatalf("logout = %d %v", resp.StatusCode, loc)
	}
}
