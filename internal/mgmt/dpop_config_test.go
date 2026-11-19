package mgmt_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"log/slog"
	"net/http"
	"testing"
)

func TestDPoPConfiguration(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Log = slog.New(slog.DiscardHandler)
	rec, out := e.call(t, e.tn, m2mCaller(allClientScopes...), "POST", "/api/v2/clients", map[string]any{"name": "proof", "app_type": "spa", "require_proof_of_possession": true}, e.h.CreateClient)
	if rec.Code != 201 {
		t.Fatalf("create %d %v", rec.Code, out)
	}
	id := out.(map[string]any)["client_id"].(string)
	c, err := e.st.Clients().Get(context.Background(), e.tn.ID, id)
	if err != nil || !c.RequireProofOfPossession {
		t.Fatal("client requirement lost")
	}
	rec, out = e.call(t, e.tn, m2mCaller("create:resource_servers"), "POST", "/api/v2/resource-servers", map[string]any{"identifier": "https://proof.example", "proof_of_possession": map[string]any{"mechanism": "dpop", "required": true, "required_for": "public_clients"}}, e.h.CreateResourceServer)
	if rec.Code != 201 {
		t.Fatalf("api %d %v", rec.Code, out)
	}
	rid := out.(map[string]any)["id"].(string)
	rec, out = e.call(t, e.tn, m2mCaller("read:resource_servers"), "GET", "/api/v2/resource-servers/"+rid, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetResourceServer(w, r, rid, mgmtapi.GetResourceServerParams{})
	})
	if rec.Code != 200 || out.(map[string]any)["proof_of_possession"].(map[string]any)["required"] != true {
		t.Fatal("API requirement lost")
	}
	rec, _ = e.call(t, e.tn, m2mCaller("update:resource_servers"), "PATCH", "/api/v2/resource-servers/"+rid, map[string]any{"proof_of_possession": nil}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateResourceServer(w, r, rid) })
	if rec.Code != 200 {
		t.Fatal("clear failed")
	}
	rs, _ := e.st.ResourceServers().Get(context.Background(), e.tn.ID, rid)
	if rs.ProofOfPossession != nil {
		t.Fatal("not cleared")
	}
}
