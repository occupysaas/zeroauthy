package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newRBACManagement(t *testing.T) (http.Handler, store.Store, string) {
	t.Helper()
	seedText := strings.Replace(usersSeed, `"read:connections", "create:connections"`, `"read:roles", "create:roles", "update:roles", "delete:roles", "read:role_members", "create:role_members", "delete:role_members", "read:users", "create:users", "update:users", "read:connections", "create:connections"`, 1)
	h, st := newMgmtEnvSeed(t, seedText, nil)
	return h, st, clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
}

func TestRBACManagementContract(t *testing.T) {
	h, st, token := newRBACManagement(t)
	base := "https://acme.example.test/api/v2"
	call := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		rec, out := sendJSON(h, method, base+path, token, body)
		if rec.Code != want {
			t.Fatalf("%s %s=%d %s; want %d", method, path, rec.Code, rec.Body, want)
		}
		return out
	}
	role := call("POST", "/roles", map[string]any{"name": "Editor", "description": "draft"}, 200)
	id, _ := role["id"].(string)
	if !strings.HasPrefix(id, "rol_") {
		t.Fatalf("role=%v", role)
	}
	call("GET", "/roles/"+id, nil, 200)
	got := call("PATCH", "/roles/"+id, map[string]any{"description": ""}, 200)
	if got["name"] != "Editor" || got["description"] != "" {
		t.Fatal(got)
	}
	call("POST", "/roles", map[string]any{"name": "Editor"}, 409)
	call("POST", "/roles", map[string]any{"name": "editor"}, 200)
	list := call("GET", "/roles?include_totals=true&name_filter=EDIT&per_page=1", nil, 200)
	if list["total"] != float64(2) || len(list["roles"].([]any)) != 1 {
		t.Fatal(list)
	}
	api := call("POST", "/resource-servers", map[string]any{"identifier": "https://rbac.test", "name": "RBAC", "scopes": []any{map[string]any{"value": "read:x"}, map[string]any{"value": "write:x"}}, "enforce_policies": true, "token_dialect": "rfc9068_profile_authz"}, 201)
	if api["enforce_policies"] != true || api["token_dialect"] != "rfc9068_profile_authz" {
		t.Fatal(api)
	}
	user := call("POST", "/users", map[string]any{"connection": "Username-Password-Authentication", "email": "rbac@example.test", "password": "Str0ng!!Password"}, 201)
	uid := user["user_id"].(string)
	keys := map[string]any{"permissions": []any{map[string]any{"resource_server_identifier": "https://rbac.test", "permission_name": "read:x"}}}
	call("POST", "/roles/"+id+"/permissions", keys, 201)
	call("GET", "/roles/"+id+"/permissions?include_totals=true", nil, 200)
	call("POST", "/roles/"+id+"/users", map[string]any{"users": []string{uid}}, 200)
	call("GET", "/roles/"+id+"/users?include_totals=true", nil, 200)
	call("POST", "/users/"+uid+"/roles", map[string]any{"roles": []string{id}}, 204)
	call("GET", "/users/"+uid+"/roles?include_totals=true", nil, 200)
	call("POST", "/users/"+uid+"/permissions", keys, 201)
	perms := call("GET", "/users/"+uid+"/permissions?include_totals=true", nil, 200)
	entries := perms["permissions"].([]any)
	if len(entries) != 1 {
		t.Fatal(perms)
	}
	sources := entries[0].(map[string]any)["sources"].([]any)
	if len(sources) != 2 {
		t.Fatal(perms)
	}
	call("DELETE", "/users/"+uid+"/permissions", keys, 204)
	still := call("GET", "/users/"+uid+"/permissions?include_totals=true", nil, 200)
	if still["total"] != float64(1) {
		t.Fatal(still)
	}
	call("DELETE", "/users/"+uid+"/roles", map[string]any{"roles": []string{id}}, 204)
	call("DELETE", "/roles/"+id+"/permissions", keys, 200)
	call("DELETE", "/roles/"+id, nil, 200)
	call("GET", "/roles/"+id, nil, 404)
	// Persistence is tenant scoped; invalid writes do not recreate the deleted role.
	tn, _ := st.Tenants().GetByName(context.Background(), "acme")
	if _, err := st.RBAC().GetRole(context.Background(), tn.ID, id); err != store.ErrNotFound {
		t.Fatalf("deleted=%v", err)
	}
}

func TestRBACManagementValidationAndScopes(t *testing.T) {
	h, _, admin := newRBACManagement(t)
	base := "https://acme.example.test/api/v2"
	rec, role := sendJSON(h, "POST", base+"/roles", admin, map[string]any{"name": "Editors"})
	if rec.Code != 200 {
		t.Fatalf("create=%d %s", rec.Code, rec.Body)
	}
	id := role["id"].(string)
	limited := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "usersro", "usersro-s3cret")
	for _, path := range []string{"/roles/" + id + "/users", "/users/nope/roles"} {
		rec, _ := sendJSON(h, "GET", base+path, limited, nil)
		if rec.Code != 403 {
			t.Errorf("all-of %s=%d %s", path, rec.Code, rec.Body)
		}
	}
	for _, path := range []string{"/roles", "/roles/" + id, "/roles/" + id + "/permissions", "/roles/" + id + "/users", "/users/nope/roles", "/users/nope/permissions"} {
		rec, _ := sendJSON(h, "GET", base+path, "", nil)
		if rec.Code != 401 {
			t.Errorf("unauth %s=%d", path, rec.Code)
		}
	}
	for _, body := range []any{map[string]any{"name": nil}, map[string]any{"name": " "}, map[string]any{"name": strings.Repeat("x", 129)}, map[string]any{"name": "ok", "unknown": true}} {
		rec, _ := sendJSON(h, "POST", base+"/roles", admin, body)
		if rec.Code != 400 {
			t.Errorf("invalid=%d %s", rec.Code, rec.Body)
		}
	}
	for _, q := range []string{"?per_page=101", "?page=-1", "?take=1", "?type=organization", "?owner_id=org_a", "?unknown=true"} {
		rec, _ := sendJSON(h, "GET", base+"/roles"+q, admin, nil)
		if rec.Code != 400 {
			t.Errorf("query %s=%d %s", q, rec.Code, rec.Body)
		}
	}
	for _, body := range []any{map[string]any{"description": nil}, map[string]any{"owner_id": "org_a"}} {
		rec, _ := sendJSON(h, "PATCH", base+"/roles/"+id, admin, body)
		if rec.Code != 400 {
			t.Errorf("patch=%d %s", rec.Code, rec.Body)
		}
	}
	// A role belonging to one tenant cannot be read on another tenant host.
	req := httptest.NewRequest("GET", base+"/roles", nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	r := httptest.NewRecorder()
	h.ServeHTTP(r, req)
	var list []any
	if json.Unmarshal(r.Body.Bytes(), &list) != nil || len(list) != 1 {
		t.Fatalf("list=%d %s", r.Code, r.Body)
	}
}

func TestRBACAllOperationScopes(t *testing.T) {
	h, _, _ := newRBACManagement(t)
	const base = "https://acme.example.test/api/v2"
	cases := []struct {
		method, path string
		scopes       []string
	}{
		{"GET", "/roles", []string{"read:roles"}}, {"POST", "/roles", []string{"create:roles"}},
		{"GET", "/roles/missing", []string{"read:roles"}}, {"PATCH", "/roles/missing", []string{"update:roles"}}, {"DELETE", "/roles/missing", []string{"delete:roles"}},
		{"GET", "/roles/missing/permissions", []string{"read:roles"}}, {"POST", "/roles/missing/permissions", []string{"update:roles"}}, {"DELETE", "/roles/missing/permissions", []string{"update:roles"}},
		{"GET", "/roles/missing/users", []string{"read:users", "read:roles", "read:role_members"}}, {"POST", "/roles/missing/users", []string{"update:roles", "create:role_members"}},
		{"GET", "/users/missing/roles", []string{"read:users", "read:roles", "read:role_members"}}, {"POST", "/users/missing/roles", []string{"update:users", "create:role_members"}}, {"DELETE", "/users/missing/roles", []string{"update:users", "delete:role_members"}},
		{"GET", "/users/missing/permissions", []string{"read:users"}}, {"POST", "/users/missing/permissions", []string{"update:users"}}, {"DELETE", "/users/missing/permissions", []string{"update:users"}},
	}
	for _, c := range cases {
		t.Run(c.method+c.path, func(t *testing.T) {
			rec, _ := sendJSON(h, c.method, base+c.path, "", map[string]any{})
			if rec.Code != 401 {
				t.Fatalf("unauthorized=%d %s", rec.Code, rec.Body)
			}
			for omit := range c.scopes {
				scopes := []string{"read:clients"}
				for i, s := range c.scopes {
					if i != omit {
						scopes = append(scopes, s)
					}
				}
				// Ask the actual token endpoint for a narrower valid Management token.
				form := "grant_type=client_credentials&client_id=admin&client_secret=admin-s3cret&audience=" + url.QueryEscape(acmeMgmtAPI) + "&scope=" + url.QueryEscape(strings.Join(scopes, " "))
				req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				tokRec := httptest.NewRecorder()
				h.ServeHTTP(tokRec, req)
				var out map[string]any
				_ = json.Unmarshal(tokRec.Body.Bytes(), &out)
				if tokRec.Code != 200 {
					t.Fatalf("token=%d %s", tokRec.Code, tokRec.Body)
				}
				rec, _ := sendJSON(h, c.method, base+c.path, out["access_token"].(string), map[string]any{})
				if rec.Code != 403 {
					t.Errorf("without %s=%d %s", c.scopes[omit], rec.Code, rec.Body)
				}
			}
		})
	}
}

func TestRBACSystemBoundary(t *testing.T) {
	h, _, token := newRBACManagement(t)
	base := "https://acme.example.test/api/v2"
	rec, api := sendJSON(h, "GET", base+"/resource-servers/"+url.PathEscape(acmeMgmtAPI), token, nil)
	if rec.Code != 200 {
		t.Fatalf("system read=%d %s", rec.Code, rec.Body)
	}
	for _, body := range []any{map[string]any{"enforce_policies": true}, map[string]any{"token_dialect": "rfc9068_profile"}} {
		rec, _ := sendJSON(h, "PATCH", base+"/resource-servers/"+api["id"].(string), token, body)
		if rec.Code != 400 {
			t.Errorf("system patch=%d %s", rec.Code, rec.Body)
		}
	}
	rec, role := sendJSON(h, "POST", base+"/roles", token, map[string]any{"name": "Forbidden"})
	if rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	rec, _ = sendJSON(h, "POST", base+"/roles/"+role["id"].(string)+"/permissions", token, map[string]any{"permissions": []any{map[string]any{"resource_server_identifier": acmeMgmtAPI, "permission_name": "read:users"}}})
	if rec.Code != 400 {
		t.Errorf("system assign=%d %s", rec.Code, rec.Body)
	}
}

func TestRBACCheckpointAndScopeCleanup(t *testing.T) {
	h, _, token := newRBACManagement(t)
	base := "https://acme.example.test/api/v2"
	rec, role := sendJSON(h, "POST", base+"/roles", token, map[string]any{"name": "Paging"})
	if rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	id := role["id"].(string)
	users := []string{}
	for _, email := range []string{"page1@example.test", "page2@example.test"} {
		rec, u := sendJSON(h, "POST", base+"/users", token, map[string]any{"connection": "Username-Password-Authentication", "email": email, "password": "Str0ng!!Password"})
		if rec.Code != 201 {
			t.Fatal(rec.Body)
		}
		users = append(users, u["user_id"].(string))
	}
	rec, _ = sendJSON(h, "POST", base+"/roles/"+id+"/users", token, map[string]any{"users": users})
	if rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	rec, page := sendJSON(h, "GET", base+"/roles/"+id+"/users?take=1&include_totals=true", token, nil)
	if rec.Code != 200 || page["next"] == nil {
		t.Fatalf("page=%d %s", rec.Code, rec.Body)
	}
	first := page["users"].([]any)[0].(map[string]any)
	for k := range first {
		if k != "user_id" && k != "email" && k != "name" && k != "picture" {
			t.Fatalf("private summary field %s", k)
		}
	}
	rec, last := sendJSON(h, "GET", base+"/roles/"+id+"/users?take=1&from="+url.QueryEscape(page["next"].(string)), token, nil)
	if rec.Code != 200 || last["next"] != nil || len(last["users"].([]any)) != 1 {
		t.Fatalf("last=%d %s", rec.Code, rec.Body)
	}
	for _, q := range []string{"?take=1&page=0", "?from=malformed", "?take=101"} {
		rec, _ := sendJSON(h, "GET", base+"/roles/"+id+"/users"+q, token, nil)
		if rec.Code != 400 {
			t.Errorf("checkpoint %s=%d %s", q, rec.Code, rec.Body)
		}
	}
	// A mixed valid/missing reference must not assign the valid edge.
	rec, api := sendJSON(h, "POST", base+"/resource-servers", token, map[string]any{"identifier": "https://cleanup.test", "scopes": []any{map[string]any{"value": "read:x"}}})
	if rec.Code != 201 {
		t.Fatal(rec.Body)
	}
	key := map[string]any{"resource_server_identifier": "https://cleanup.test", "permission_name": "read:x"}
	rec, _ = sendJSON(h, "POST", base+"/roles/"+id+"/permissions", token, map[string]any{"permissions": []any{key, map[string]any{"resource_server_identifier": "https://cleanup.test", "permission_name": "missing"}}})
	if rec.Code != 400 {
		t.Fatalf("invalid batch=%d %s", rec.Code, rec.Body)
	}
	rec, empty := sendJSON(h, "GET", base+"/roles/"+id+"/permissions?include_totals=true", token, nil)
	if rec.Code != 200 || empty["total"] != float64(0) {
		t.Fatalf("partial batch=%d %s", rec.Code, rec.Body)
	}
	for _, path := range []string{"/roles/" + id + "/permissions", "/users/" + users[0] + "/permissions"} {
		rec, _ = sendJSON(h, "POST", base+path, token, map[string]any{"permissions": []any{key, key}})
		if rec.Code != 201 {
			t.Fatal(rec.Body)
		}
	}
	for _, scopes := range [][]any{{}, {map[string]any{"value": "read:x"}}} {
		rec, _ := sendJSON(h, "PATCH", base+"/resource-servers/"+api["id"].(string), token, map[string]any{"scopes": scopes})
		if rec.Code != 200 {
			t.Fatal(rec.Body)
		}
	}
	for _, path := range []string{"/roles/" + id + "/permissions", "/users/" + users[0] + "/permissions"} {
		rec, out := sendJSON(h, "GET", base+path+"?include_totals=true", token, nil)
		if rec.Code != 200 || out["total"] != float64(0) {
			t.Errorf("resurrected rights=%d %s", rec.Code, rec.Body)
		}
	}
}
