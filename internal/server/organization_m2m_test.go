package server

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOrganizationM2MWire(t *testing.T) {
	a := newOrgManagement(t)
	h, admin := a.h, a.admin
	reader := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	const base = "https://acme.example.test/api/v2"
	const aud = "https://machine.example.test"
	if rec, _ := sendJSON(h, "POST", base+"/resource-servers", admin, map[string]any{"identifier": aud, "scopes": []map[string]any{{"value": "read"}}}); rec.Code != 201 {
		t.Fatalf("api %d %s", rec.Code, rec.Body)
	}
	rec, c := sendJSON(h, "POST", base+"/clients", admin, map[string]any{"name": "machine", "app_type": "non_interactive"})
	if rec.Code != 201 {
		t.Fatal(rec.Body)
	}
	rec, org := sendJSON(h, "POST", base+"/organizations", admin, map[string]any{"name": "machine"})
	if rec.Code != 201 {
		t.Fatal(rec.Body)
	}
	orgID := org["id"].(string)
	rec, g := sendJSON(h, "POST", base+"/client-grants", admin, map[string]any{"client_id": c["client_id"], "audience": aud, "scope": []string{"read"}, "organization_usage": "require"})
	if rec.Code != 201 {
		t.Fatal(rec.Body)
	}
	gid := g["id"].(string)
	path := base + "/organizations/" + orgID + "/client-grants"
	for _, route := range []struct {
		method, path string
		body         any
	}{{"POST", path, map[string]any{"grant_id": gid}}, {"DELETE", path + "/" + gid, nil}, {"GET", base + "/client-grants/" + gid + "/organizations", nil}} {
		if rec, _ := sendJSON(h, route.method, route.path, reader, route.body); rec.Code != 403 {
			t.Fatalf("route scope %s %s = %d", route.method, route.path, rec.Code)
		}
	}
	if rec, _ := sendJSON(h, "POST", path, admin, map[string]any{"grant_id": gid}); rec.Code != 201 {
		t.Fatalf("associate %d %s", rec.Code, rec.Body)
	}
	if rec, body := sendJSON(h, "GET", base+"/client-grants/"+gid+"/organizations?include_totals=true", admin, nil); rec.Code != 200 || body["total"] != float64(1) {
		t.Fatalf("reverse %d %s", rec.Code, rec.Body)
	}
	// The real server's signer and policy repositories share a memory store.
	// Signing inside the policy transaction would deadlock this request.
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c["client_id"].(string)}, "client_secret": {c["client_secret"].(string)}, "audience": {aud}, "organization": {orgID}}
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tok := httptest.NewRecorder()
	h.ServeHTTP(tok, req)
	var body map[string]any
	if err := json.Unmarshal(tok.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if tok.Code != 200 || body["scope"] != "read" || body["refresh_token"] != nil || body["id_token"] != nil {
		t.Fatalf("token %d %v", tok.Code, body)
	}
	if rec, _ := sendJSON(h, "DELETE", path+"/"+gid, admin, nil); rec.Code != 204 {
		t.Fatalf("delete %d %s", rec.Code, rec.Body)
	}
}
