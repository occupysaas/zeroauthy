package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// grantToken asks the token endpoint for a client credentials token and
// returns the status and body.
func grantToken(h http.Handler, id, secret, aud, scope string) (int, map[string]any) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}, "audience": {aud}}
	if scope != "" {
		form.Set("scope", scope)
	}
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// The client grant operations through the whole server: scopes per route,
// and a grant created through the API making the token endpoint issue
// exactly its scopes, following later changes.
func TestManagementClientGrantsThroughServer(t *testing.T) {
	h, _ := newMgmtEnv(t)
	reader := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	admin := clientToken(t, h, "login.acme.test", acmeMgmtAPI, "admin", "admin-s3cret")
	rsBase := "https://acme.example.test/api/v2/resource-servers"
	base := "https://acme.example.test/api/v2/client-grants"
	const aud = "https://api.orders.test/v1"

	rec, _ := sendJSON(h, "POST", rsBase, admin, map[string]any{"identifier": aud, "scopes": []map[string]any{{"value": "read:orders"}, {"value": "write:orders"}}})
	if rec.Code != 201 {
		t.Fatalf("create API = %d %s", rec.Code, rec.Body)
	}
	rec, app := sendJSON(h, "POST", "https://acme.example.test/api/v2/clients", admin, map[string]any{"name": "Orders worker", "app_type": "non_interactive"})
	cid, _ := app["client_id"].(string)
	secret, _ := app["client_secret"].(string)
	if rec.Code != 201 || cid == "" || secret == "" {
		t.Fatalf("create client = %d %s", rec.Code, rec.Body)
	}
	if code, _ := grantToken(h, cid, secret, aud, ""); code == 200 {
		t.Fatal("a token was issued before any grant")
	}

	// Scopes per route.
	if rec, body := sendJSON(h, "POST", base, reader, map[string]any{"client_id": cid, "audience": aud, "scope": []string{}}); rec.Code != 403 || body["errorCode"] != "insufficient_scope" {
		t.Errorf("create with read scopes = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := sendJSON(h, "GET", base, reader, nil); rec.Code != 403 {
		t.Errorf("list without read:client_grants = %d", rec.Code)
	}
	if rec, _ := sendJSON(h, "GET", base, "", nil); rec.Code != 401 {
		t.Errorf("list without a token = %d", rec.Code)
	}

	rec, grant := sendJSON(h, "POST", "https://login.acme.test/api/v2/client-grants", admin, map[string]any{"client_id": cid, "audience": aud, "scope": []string{"read:orders"}})
	id, _ := grant["id"].(string)
	if rec.Code != 201 || !strings.HasPrefix(id, "cgr_") || len(id) != 20 {
		t.Fatalf("create grant = %d %s", rec.Code, rec.Body)
	}
	if rec, body := sendJSON(h, "POST", base, admin, map[string]any{"client_id": cid, "audience": aud, "scope": []string{}}); rec.Code != 409 || body["errorCode"] != "client_grant_conflict" {
		t.Errorf("duplicate = %d %s", rec.Code, rec.Body)
	}

	// Exactly the grant's scopes.
	if code, tok := grantToken(h, cid, secret, aud, ""); code != 200 || tok["scope"] != "read:orders" {
		t.Fatalf("token = %d %v", code, tok)
	}
	if code, _ := grantToken(h, cid, secret, aud, "write:orders"); code == 200 {
		t.Error("a token was issued for a scope the grant lacks")
	}
	rec, body := sendJSON(h, "PATCH", base+"/"+id, admin, map[string]any{"scope": []string{"read:orders", "write:orders"}})
	if rec.Code != 200 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	if code, tok := grantToken(h, cid, secret, aud, ""); code != 200 || tok["scope"] != "read:orders write:orders" {
		t.Errorf("token after patch = %d %v", code, tok)
	}
	if code, tok := grantToken(h, cid, secret, aud, "write:orders"); code != 200 || tok["scope"] != "write:orders" {
		t.Errorf("narrowed token = %d %v", code, tok)
	}

	// allow_all_scopes: every scope the API defines when the token is issued,
	// scopes added later included.
	rec, body = sendJSON(h, "PATCH", base+"/"+id, admin, map[string]any{"allow_all_scopes": true})
	if _, has := body["scope"]; rec.Code != 200 || has || body["allow_all_scopes"] != true {
		t.Fatalf("patch allow_all_scopes = %d %s", rec.Code, rec.Body)
	}
	if code, tok := grantToken(h, cid, secret, aud, ""); code != 200 || tok["scope"] != "read:orders write:orders" {
		t.Errorf("allow_all token = %d %v", code, tok)
	}
	rec, apiBody := sendJSON(h, "GET", rsBase+"/"+url.PathEscape(aud), admin, nil)
	if rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	apiID := apiBody["id"].(string)
	if rec, _ := sendJSON(h, "PATCH", rsBase+"/"+apiID, admin, map[string]any{"scopes": []map[string]any{{"value": "read:orders"}, {"value": "delete:orders"}}}); rec.Code != 200 {
		t.Fatalf("patch API = %d %s", rec.Code, rec.Body)
	}
	if code, tok := grantToken(h, cid, secret, aud, ""); code != 200 || tok["scope"] != "read:orders delete:orders" {
		t.Errorf("allow_all token after the API changed = %d %v", code, tok)
	}

	// The list: auth0-cli's go-auth0 sends include_totals=true&take=50.
	rec, list := sendJSON(h, "GET", base+"?include_totals=true&take=50", admin, nil)
	grants, _ := list["client_grants"].([]any)
	if _, has := list["next"]; rec.Code != 200 || len(grants) != 3 || has {
		t.Errorf("list = %d %s", rec.Code, rec.Body)
	}
	rec, _ = sendJSON(h, "GET", base+"?client_id="+cid+"&audience="+url.QueryEscape(aud)+"&subject_type=client", admin, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), id) {
		t.Errorf("filtered list = %d %s", rec.Code, rec.Body)
	}
	if rec, body := sendJSON(h, "GET", base+"?subject_type=client", admin, nil); rec.Code != 400 || body["errorCode"] != nil {
		t.Errorf("subject_type alone = %d %s", rec.Code, rec.Body)
	}
	if rec, body := sendJSON(h, "GET", base+"?take=abc", admin, nil); rec.Code != 400 || body["errorCode"] != "invalid_query_string" {
		t.Errorf("take=abc = %d %s", rec.Code, rec.Body)
	}

	// Deleting the grant ends token issuance.
	for i := range 2 {
		if rec, _ := sendJSON(h, "DELETE", base+"/"+id, admin, nil); rec.Code != 204 {
			t.Errorf("delete #%d = %d", i, rec.Code)
		}
	}
	if code, _ := grantToken(h, cid, secret, aud, ""); code == 200 {
		t.Error("a token was issued after the grant was deleted")
	}
	if rec, body := sendJSON(h, "GET", base+"/"+id, admin, nil); rec.Code != 404 || body["errorCode"] != "inexistent_client_grant" {
		t.Errorf("get after delete = %d %s", rec.Code, rec.Body)
	}
	if rec, body := sendJSON(h, "GET", base+"/not-an-id", admin, nil); rec.Code != 400 || body["errorCode"] != "invalid_uri" {
		t.Errorf("get malformed = %d %s", rec.Code, rec.Body)
	}
}

// A grant of the Management API through the API gives a working
// Management API token, with allow_all_scopes covering every scope.
func TestManagementAPIGrantThroughServer(t *testing.T) {
	h, _ := newMgmtEnv(t)
	admin := clientToken(t, h, "login.acme.test", acmeMgmtAPI, "admin", "admin-s3cret")
	base := "https://acme.example.test/api/v2/client-grants"
	rec, app := sendJSON(h, "POST", "https://acme.example.test/api/v2/clients", admin, map[string]any{"name": "Ops", "app_type": "non_interactive"})
	cid, secret := app["client_id"].(string), app["client_secret"].(string)
	if rec.Code != 201 {
		t.Fatal(rec.Body)
	}
	for _, aud := range []string{"urn:zeroauthy:management", "https://globex.example.test/api/v2/"} {
		if rec, body := sendJSON(h, "POST", base, admin, map[string]any{"client_id": cid, "audience": aud, "scope": []string{}}); rec.Code != 400 || body["errorCode"] != "invalid_body" {
			t.Errorf("grant of %s = %d %s", aud, rec.Code, rec.Body)
		}
	}
	if rec, body := sendJSON(h, "POST", base, admin, map[string]any{"client_id": cid, "audience": acmeMgmtAPI, "subject_type": "user", "scope": []string{"read:clients"}}); rec.Code != 400 || body["errorCode"] != "invalid_body" {
		t.Errorf("user grant of the Management API = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := sendJSON(h, "POST", base, admin, map[string]any{"client_id": cid, "audience": acmeMgmtAPI, "allow_all_scopes": true}); rec.Code != 201 {
		t.Fatalf("allow_all_scopes grant of the Management API = %d %s", rec.Code, rec.Body)
	}
	code, tok := grantToken(h, cid, secret, acmeMgmtAPI, "")
	scopes := strings.Fields(tok["scope"].(string))
	if code != 200 || !slices.Contains(scopes, "read:clients") || !slices.Contains(scopes, "delete:client_grants") {
		t.Fatalf("token = %d %v", code, tok)
	}
	rec, _ = sendJSON(h, "GET", "https://acme.example.test/api/v2/clients", tok["access_token"].(string), nil)
	if rec.Code != 200 {
		t.Errorf("list clients with the new token = %d %s", rec.Code, rec.Body)
	}
}

// An ordinary API whose identifier has the form of a Management API's can be
// granted like any other, and serves tokens.
func TestManagementClientGrantLookalikeAPI(t *testing.T) {
	h, _ := newMgmtEnv(t)
	admin := clientToken(t, h, "login.acme.test", acmeMgmtAPI, "admin", "admin-s3cret")
	const aud = "https://api.example.com/api/v2/"
	if rec, _ := sendJSON(h, "POST", "https://acme.example.test/api/v2/resource-servers", admin, map[string]any{"identifier": aud, "scopes": []map[string]any{{"value": "read:things"}}}); rec.Code != 201 {
		t.Fatalf("create API = %d %s", rec.Code, rec.Body)
	}
	rec, app := sendJSON(h, "POST", "https://acme.example.test/api/v2/clients", admin, map[string]any{"name": "Worker", "app_type": "non_interactive"})
	cid, secret := app["client_id"].(string), app["client_secret"].(string)
	if rec.Code != 201 {
		t.Fatal(rec.Body)
	}
	if rec, _ := sendJSON(h, "POST", "https://acme.example.test/api/v2/client-grants", admin, map[string]any{"client_id": cid, "audience": aud, "scope": []string{"read:things"}}); rec.Code != 201 {
		t.Fatalf("grant = %d %s", rec.Code, rec.Body)
	}
	if code, tok := grantToken(h, cid, secret, aud, ""); code != 200 || tok["scope"] != "read:things" {
		t.Errorf("token = %d %v", code, tok)
	}
}
