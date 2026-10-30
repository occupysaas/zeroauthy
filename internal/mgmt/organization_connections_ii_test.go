package mgmt_test

import (
	"strings"
	"testing"
)

func TestOrganizationConnectionsIIViews(t *testing.T) {
	e := newOrgEnv(t)
	id := e.create(map[string]any{"name": "connections-ii"}, 201)["id"].(string)
	base := "/organizations/" + id + "/connections"
	legacy := "/organizations/" + id + "/enabled_connections"
	c := e.obj("POST", base, map[string]any{"connection_id": orgDB, "is_enabled": false, "organization_connection_name": "Local database", "organization_access_level": "full", "organization_member_access_level": "readonly"}, e.addConn(id, true), 201)
	if c["is_enabled"] != false || c["organization_connection_name"] != "Local database" || c["organization_access_level"] != "full" {
		t.Fatalf("create: %v", c)
	}
	if len(e.list(base, e.conns(id, true))) != 1 || len(e.list(legacy, e.conns(id, false))) != 0 {
		t.Fatal("disabled association views")
	}
	e.fail("GET", legacy+"/"+orgDB, nil, e.conn("GET", id, orgDB, false), 404, "")
	e.obj("POST", legacy, map[string]any{"connection_id": orgOIDC}, e.addConn(id, false), 201)
	page := e.obj("GET", legacy+"?per_page=1&include_totals=true", nil, e.conns(id, false), 200)
	if page["total"] != float64(1) || len(page["enabled_connections"].([]any)) != 1 {
		t.Fatalf("filtered page %v", page)
	}
	e.obj("POST", legacy, map[string]any{"connection_id": orgDB}, e.addConn(id, false), 201)
	c = e.obj("GET", base+"/"+orgDB, nil, e.conn("GET", id, orgDB, true), 200)
	if c["is_enabled"] != true || c["organization_connection_name"] != "Local database" || c["organization_access_level"] != "full" {
		t.Fatalf("reenable %v", c)
	}
	c = e.obj("PATCH", base+"/"+orgDB, map[string]any{"is_enabled": nil, "organization_connection_name": nil, "organization_access_level": nil, "organization_member_access_level": nil}, e.conn("PATCH", id, orgDB, true), 200)
	if c["is_enabled"] != true || c["organization_connection_name"] != "org-db" || c["organization_access_level"] != "none" || c["organization_member_access_level"] != "none" {
		t.Fatalf("null reset %v", c)
	}
	c = e.obj("GET", base+"/"+orgDB, nil, e.conn("GET", id, orgDB, true), 200)
	if c["organization_connection_name"] != "org-db" || c["organization_member_access_level"] != "none" {
		t.Fatalf("persisted null reset %v", c)
	}
	for _, level := range []string{"none", "readonly", "limited", "full"} {
		c = e.obj("PATCH", base+"/"+orgDB, map[string]any{"organization_access_level": level, "organization_member_access_level": level}, e.conn("PATCH", id, orgDB, true), 200)
		if c["organization_access_level"] != level || c["organization_member_access_level"] != level {
			t.Fatal(c)
		}
	}
	for _, body := range []map[string]any{{"is_enabled": "false"}, {"organization_access_level": "admin"}, {"organization_member_access_level": true}, {"organization_connection_name": 5}, {"organization_connection_name": ""}, {"organization_connection_name": strings.Repeat("a", 51)}, {"unknown": true}} {
		e.fail("PATCH", base+"/"+orgDB, body, e.conn("PATCH", id, orgDB, true), 400, "invalid_body")
	}
	for _, q := range []string{"is_enabled=0", "unknown=true", "is_enabled=null", "is_enabled=", "is_enabled=true&is_enabled=false", "is_enabled=%zz", "is_enabled=true;unknown=true"} {
		e.fail("GET", base+"?"+q, nil, e.conns(id, true), 400, "invalid_query_string")
	}
	for _, method := range []string{"GET", "PATCH", "DELETE"} {
		e.fail(method, base+"/"+orgDB+"?unknown=true", map[string]any{}, e.conn(method, id, orgDB, true), 400, "invalid_query_string")
	}
	e.fail("POST", base+"?unknown=true", map[string]any{"connection_id": orgDB2}, e.addConn(id, true), 400, "invalid_query_string")

	e.obj("DELETE", legacy+"/"+orgDB, nil, e.conn("DELETE", id, orgDB, false), 204)
	e.fail("GET", base+"/"+orgDB, nil, e.conn("GET", id, orgDB, true), 404, "")
}
