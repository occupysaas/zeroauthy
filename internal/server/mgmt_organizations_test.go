package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var orgMgmtScopes = []string{
	"read:organizations", "create:organizations", "update:organizations", "delete:organizations",
	"read:organization_connections", "create:organization_connections", "update:organization_connections", "delete:organization_connections",
	"read:organization_client_grants",
}

// orgAPI calls the Management API of a server seeded with an admin client
// holding every organization scope.
type orgAPI struct {
	t     *testing.T
	h     http.Handler
	c     *mgmtContract
	admin string
}

func newOrgManagement(t *testing.T) *orgAPI {
	t.Helper()
	quoted := `"` + strings.Join(orgMgmtScopes, `", "`) + `", `
	seedText := strings.Replace(usersSeed, `"read:connections", "create:connections"`, quoted+`"read:connections", "create:connections"`, 1)
	h, _ := newMgmtEnvSeed(t, seedText, nil)
	return &orgAPI{t: t, h: h, c: newMgmtContract(t), admin: clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")}
}

// call sends the request and validates the response against the contract.
func (a *orgAPI) call(method, path, token string, body any) (int, map[string]any, []byte) {
	a.t.Helper()
	code, raw := a.c.do(a.h, method, "https://acme.example.test/api/v2"+path, token, body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return code, out, raw
}

// token asks the real token endpoint for a narrowed Management API token.
func (a *orgAPI) token(scopes []string) string {
	a.t.Helper()
	form := "grant_type=client_credentials&client_id=admin&client_secret=admin-s3cret&audience=" + url.QueryEscape(acmeMgmtAPI) + "&scope=" + url.QueryEscape(strings.Join(scopes, " "))
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	tok, _ := out["access_token"].(string)
	if rec.Code != 200 || tok == "" {
		a.t.Fatalf("token=%d %s", rec.Code, rec.Body)
	}
	return tok
}

// TestOrganizationsRoutes drives every organization route through the real
// router and validates each response against api/management.yaml.
func TestOrganizationsRoutes(t *testing.T) {
	a := newOrgManagement(t)
	call, admin := a.call, a.admin
	code, _, raw := call("GET", "/connections", admin, nil)
	if code != 200 {
		t.Fatalf("connections=%d %s", code, raw)
	}
	var list []map[string]any
	_ = json.Unmarshal(raw, &list)
	dbID := ""
	for _, c := range list {
		if c["name"] == "Username-Password-Authentication" {
			dbID = c["id"].(string)
		}
	}
	if dbID == "" {
		t.Fatalf("no database connection in %s", raw)
	}
	code, org, raw := call("POST", "/organizations", admin, map[string]any{
		"name": "routes", "branding": map[string]any{"logo_url": "https://cdn.example.test/l.png"}, "metadata": map[string]any{"k": "v"},
		"enabled_connections": []any{map[string]any{"connection_id": dbID, "assign_membership_on_login": true}},
	})
	if code != 201 {
		t.Fatalf("create=%d %s", code, raw)
	}
	id := org["id"].(string)
	for _, c := range []struct {
		method, path string
		body         any
		want         int
	}{
		{"POST", "/organizations", map[string]any{"name": "routes"}, 409},
		{"POST", "/organizations", map[string]any{"name": "Bad"}, 400},
		{"POST", "/organizations", map[string]any{"name": "ghost", "enabled_connections": []any{map[string]any{"connection_id": "con_ghost0000000001"}}}, 404},
		{"GET", "/organizations", nil, 200},
		{"GET", "/organizations?include_totals=true&per_page=1", nil, 200},
		{"GET", "/organizations?take=1&include_totals=true", nil, 200},
		{"GET", "/organizations?sort=name:-1", nil, 200},
		{"GET", "/organizations?per_page=500", nil, 400},
		{"GET", "/organizations?page=abc", nil, 400},
		{"GET", "/organizations/" + id, nil, 200},
		{"GET", "/organizations/name/routes", nil, 200},
		{"GET", "/organizations/name/Routes", nil, 400},
		{"GET", "/organizations/org_0000000000000000", nil, 404},
		{"GET", "/organizations/bad", nil, 400},
		{"PATCH", "/organizations/" + id, map[string]any{"metadata": nil, "branding": map[string]any{}}, 200},
		{"PATCH", "/organizations/" + id, map[string]any{}, 400},
		{"GET", "/organizations/" + id + "/enabled_connections", nil, 200},
		{"GET", "/organizations/" + id + "/enabled_connections?include_totals=true", nil, 200},
		{"GET", "/organizations/" + id + "/enabled_connections/" + dbID, nil, 200},
		{"PATCH", "/organizations/" + id + "/enabled_connections/" + dbID, map[string]any{"is_signup_enabled": true}, 200},
		{"PATCH", "/organizations/" + id + "/enabled_connections/" + dbID, map[string]any{"show_as_button": false}, 400},
		{"POST", "/organizations/" + id + "/enabled_connections", map[string]any{"connection_id": dbID}, 409},
		{"GET", "/organizations/" + id + "/connections", nil, 200},
		{"GET", "/organizations/" + id + "/connections?include_totals=true&is_enabled=true", nil, 200},
		{"GET", "/organizations/" + id + "/connections/" + dbID, nil, 200},
		{"PATCH", "/organizations/" + id + "/connections/" + dbID, map[string]any{"is_enabled": true, "organization_access_level": "none"}, 200},
		{"PATCH", "/organizations/" + id + "/connections/" + dbID, map[string]any{"organization_access_level": "full"}, 400},
		{"GET", "/organizations/" + id + "/client-grants", nil, 200},
		{"GET", "/organizations/" + id + "/client-grants?include_totals=true&grant_ids=a&grant_ids=b", nil, 200},
		{"DELETE", "/organizations/" + id + "/connections/" + dbID, nil, 204},
		{"POST", "/organizations/" + id + "/connections", map[string]any{"connection_id": dbID, "is_enabled": true}, 201},
		{"DELETE", "/organizations/" + id + "/enabled_connections/" + dbID, nil, 204},
		{"POST", "/organizations/" + id + "/enabled_connections", map[string]any{"connection_id": dbID}, 201},
		{"DELETE", "/organizations/" + id, nil, 204},
		{"DELETE", "/organizations/" + id, nil, 404},
		{"GET", "/organizations/" + id + "/client-grants", nil, 404},
	} {
		if code, _, raw := call(c.method, c.path, admin, c.body); code != c.want {
			t.Errorf("%s %s=%d %s, want %d", c.method, c.path, code, raw, c.want)
		}
	}
}

// TestOrganizationsScopes is the 401/403 matrix of every organization route,
// with tokens narrowed at the real token endpoint.
func TestOrganizationsScopes(t *testing.T) {
	a := newOrgManagement(t)
	call, admin := a.call, a.admin
	_, org, _ := call("POST", "/organizations", admin, map[string]any{"name": "scopes"})
	id := org["id"].(string)
	o := "/organizations/" + id
	cases := []struct{ method, path, scope string }{
		{"GET", "/organizations", "read:organizations"}, {"POST", "/organizations", "create:organizations"},
		{"GET", o, "read:organizations"}, {"GET", "/organizations/name/scopes", "read:organizations"},
		{"PATCH", o, "update:organizations"}, {"DELETE", o, "delete:organizations"},
		{"GET", o + "/enabled_connections", "read:organization_connections"}, {"POST", o + "/enabled_connections", "create:organization_connections"},
		{"GET", o + "/enabled_connections/con_x", "read:organization_connections"}, {"PATCH", o + "/enabled_connections/con_x", "update:organization_connections"},
		{"DELETE", o + "/enabled_connections/con_x", "delete:organization_connections"},
		{"GET", o + "/connections", "read:organization_connections"}, {"POST", o + "/connections", "create:organization_connections"},
		{"GET", o + "/connections/con_x", "read:organization_connections"}, {"PATCH", o + "/connections/con_x", "update:organization_connections"},
		{"DELETE", o + "/connections/con_x", "delete:organization_connections"},
		{"GET", o + "/client-grants", "read:organization_client_grants"},
	}
	for _, c := range cases {
		t.Run(c.method+c.path, func(t *testing.T) {
			if code, _, raw := call(c.method, c.path, "", map[string]any{}); code != 401 {
				t.Fatalf("no token=%d %s", code, raw)
			}
			var others []string
			for _, s := range orgMgmtScopes {
				if s != c.scope {
					others = append(others, s)
				}
			}
			if code, out, raw := call(c.method, c.path, a.token(others), map[string]any{}); code != 403 || out["errorCode"] != "insufficient_scope" {
				t.Fatalf("without %s=%d %s", c.scope, code, raw)
			}
			if code, _, raw := call(c.method, c.path, a.token([]string{c.scope}), map[string]any{}); code == 401 || code == 403 {
				t.Fatalf("with only %s=%d %s", c.scope, code, raw)
			}
		})
	}
	// enabled_connections on create also needs create:organization_connections.
	body := map[string]any{"name": "conditional", "enabled_connections": []any{}}
	if code, out, raw := call("POST", "/organizations", a.token([]string{"create:organizations"}), body); code != 403 || out["errorCode"] != "insufficient_scope" {
		t.Fatalf("conditional=%d %s", code, raw)
	}
	if code, _, raw := call("POST", "/organizations", a.token([]string{"create:organizations", "create:organization_connections"}), body); code != 201 {
		t.Fatalf("conditional with scope=%d %s", code, raw)
	}
}
