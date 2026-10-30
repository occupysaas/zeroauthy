package server

import (
	"encoding/json"
	"testing"
)

func TestOrganizationConnectionsIIMetadataNeverGrantsScope(t *testing.T) {
	a := newOrgManagement(t)
	code, _, raw := a.call("GET", "/connections", a.admin, nil)
	if code != 200 {
		t.Fatalf("connections %d", code)
	}
	var conns []map[string]any
	if err := json.Unmarshal(raw, &conns); err != nil {
		t.Fatal(err)
	}
	id := conns[0]["id"].(string)
	code, org, raw := a.call("POST", "/organizations", a.admin, map[string]any{"name": "metadata-scope"})
	if code != 201 {
		t.Fatalf("org %d %s", code, raw)
	}
	path := "/organizations/" + org["id"].(string) + "/connections"
	code, _, raw = a.call("POST", path, a.admin, map[string]any{"connection_id": id, "organization_access_level": "full", "organization_member_access_level": "full"})
	if code != 201 {
		t.Fatalf("association %d %s", code, raw)
	}
	for _, method := range []string{"GET", "PATCH", "DELETE"} {
		code, out, raw := a.call(method, path+"/"+id, a.token([]string{"read:organizations"}), map[string]any{})
		if code != 403 || out["errorCode"] != "insufficient_scope" {
			t.Fatalf("metadata scope bypass %s %d %s", method, code, raw)
		}
	}
}
