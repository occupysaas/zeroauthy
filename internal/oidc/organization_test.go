package oidc

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Dropping either signed organization claim must be observable at userinfo;
// it echoes the token snapshot rather than re-resolving a renamed organization.
func TestOrganizationUserinfo(t *testing.T) {
	e := newUserinfoEnv(t)
	for _, name := range []string{"", "acme-corp"} {
		claims := map[string]any{"org_id": "org_ABCDEFGHIJKLMNOP"}
		if name != "" {
			claims["org_name"] = name
		}
		raw := e.token(t, "ten_a", claims)
		rec := e.call(http.MethodGet, "Bearer "+raw)
		if rec.Code != 200 {
			t.Fatalf("status=%d", rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["org_id"] != "org_ABCDEFGHIJKLMNOP" {
			t.Fatalf("org_id=%v", body["org_id"])
		}
		if name != "" && body["org_name"] != name {
			t.Fatalf("org_name=%v", body["org_name"])
		}
		if name == "" && body["org_name"] != nil {
			t.Fatal("invented org_name")
		}
	}
}
