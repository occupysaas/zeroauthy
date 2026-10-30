package server

import (
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"net/http/httptest"
	"testing"
)

func TestOrganizationDiscoveryRouteScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}})
	for _, item := range []struct{ method, path, scope string }{
		{"GET", "", "read:organization_discovery_domains"}, {"POST", "", "create:organization_discovery_domains"}, {"DELETE", "/domain", "delete:organization_discovery_domains"}, {"GET", "/domain", "read:organization_discovery_domains"}, {"GET", "/name/example.com", "read:organization_discovery_domains"}, {"PATCH", "/client", "update:organization_discovery_domains"},
	} {
		for _, authenticated := range []bool{false, true} {
			r := httptest.NewRequest(item.method, "/api/v2/organizations/org_0000000000000001/discovery-domains"+item.path, nil)
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

func TestOrganizationDiscoveryRoutes(t *testing.T) {
	a := newOrgManagement(t)
	status, org, raw := a.call("POST", "/organizations", a.admin, map[string]any{"name": "discovery"})
	if status != 201 {
		t.Fatalf("%d %s", status, raw)
	}
	path := "/organizations/" + org["id"].(string) + "/discovery-domains"
	status, d, raw := a.call("POST", path, a.admin, map[string]any{"domain": "Example.COM"})
	if status != 201 {
		t.Fatalf("%d %s", status, raw)
	}
	id := d["id"].(string)
	for _, suffix := range []string{"/" + id, "/name/EXAMPLE.COM", "?take=1"} {
		status, _, raw = a.call("GET", path+suffix, a.admin, nil)
		if status != 200 {
			t.Fatalf("%s %d %s", suffix, status, raw)
		}
	}
	status, _, raw = a.call("PATCH", path+"/"+id, a.admin, map[string]any{"status": "verified"})
	if status != 200 {
		t.Fatalf("%d %s", status, raw)
	}
	status, _, raw = a.call("DELETE", path+"/"+id, a.admin, nil)
	if status != 204 {
		t.Fatalf("%d %s", status, raw)
	}
}
