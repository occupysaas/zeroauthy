package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
)

func TestOrganizationClientAssociationsRouteScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}})
	for _, item := range []struct{ method, path, scope string }{
		{"GET", "", "read:organization_clients"}, {"POST", "", "create:organization_clients"}, {"DELETE", "", "delete:organization_clients"}, {"GET", "/client", "read:organization_clients"}, {"PATCH", "/client", "update:organization_clients"},
	} {
		for _, authenticated := range []bool{false, true} {
			r := httptest.NewRequest(item.method, "/api/v2/organizations/org_0000000000000001/clients"+item.path, nil)
			want := 401
			if authenticated {
				r = r.WithContext(mgmt.WithCaller(r.Context(), mgmt.Caller{Kind: mgmt.M2M, Scopes: []string{"read:organizations"}}))
				want = 403
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatalf("%s %s auth=%v got %d want %d", item.method, item.path, authenticated, w.Code, want)
			}
		}
	}
}
func TestOrganizationClientAssociationsRoutes(t *testing.T) {
	a := newOrgManagement(t)
	status, org, _ := a.call("POST", "/organizations", a.admin, map[string]any{"name": "clients", "is_app_entitlement_active": true})
	if status != 201 {
		t.Fatal(status, org)
	}
	id := org["id"].(string)
	path := "/organizations/" + id + "/clients"
	// Generated SDK-shaped DTOs preserve explicit false and use collection bodies.
	body := mgmtapi.AssociateOrganizationClientsJSONRequestBody{Clients: []mgmtapi.IICreateOrganizationClientRequestItem{{ClientId: "admin", UseForMemberAccess: false}}}
	status, _, raw := a.call("POST", path, a.admin, body)
	if status != 201 {
		t.Fatalf("POST %d %s", status, raw)
	}
	var created mgmtapi.IICreateOrganizationClientsResponseContent
	if err := json.Unmarshal(raw, &created); err != nil || len(created) != 1 || created[0].UseForMemberAccess {
		t.Fatalf("SDK result %s %v", raw, err)
	}
	for _, key := range []string{"client_secret", "secrets", "sealed", "hash"} {
		if strings.Contains(string(raw), `"`+key+`"`) {
			t.Fatalf("secret exposed: %s", raw)
		}
	}
	status, _, raw = a.call("GET", path+"?take=1", a.admin, nil)
	if status != 200 {
		t.Fatalf("list %d %s", status, raw)
	}
	var listed mgmtapi.IIListOrganizationClientsResponseContent
	if err := json.Unmarshal(raw, &listed); err != nil || len(listed.Clients) != 1 {
		t.Fatalf("SDK list %s %v", raw, err)
	}
	status, _, raw = a.call("GET", path+"/admin", a.admin, nil)
	if status != 200 {
		t.Fatalf("get %d %s", status, raw)
	}
	on := true
	status, _, raw = a.call("PATCH", path+"/admin", a.admin, mgmtapi.UpdateOrganizationClientJSONRequestBody{UseForMemberAccess: &on})
	if status != 200 {
		t.Fatalf("patch %d %s", status, raw)
	}
	status, _, raw = a.call("GET", "/organizations?include_client_association_for=admin", a.admin, nil)
	if status != 200 || !strings.Contains(string(raw), `"client":{"use_for_member_access":true}`) {
		t.Fatalf("annotation %d %s", status, raw)
	}
	status, _, raw = a.call("DELETE", path, a.admin, mgmtapi.DeleteOrganizationClientsJSONRequestBody{Clients: []string{"admin"}})
	if status != http.StatusNoContent {
		t.Fatalf("delete %d %s", status, raw)
	}
}
