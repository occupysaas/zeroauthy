package mgmt_test

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
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

func TestORTResourceServerConfiguration(t *testing.T) {
	e := newClientsEnv(t)
	rec, out := e.call(t, e.tn, m2mCaller("create:resource_servers"), "POST", "/api/v2/resource-servers", map[string]any{"identifier": "https://online.example", "allow_online_access": true, "allow_online_access_with_ephemeral_sessions": true}, e.h.CreateResourceServer)
	if rec.Code != 201 {
		t.Fatalf("create %d", rec.Code)
	}
	rs := out.(map[string]any)
	if rs["allow_online_access"] != true || rs["allow_online_access_with_ephemeral_sessions"] != true {
		t.Fatal("online flags not returned")
	}
	id := rs["id"].(string)
	rec, _ = e.call(t, e.tn, m2mCaller("update:resource_servers"), "PATCH", "/api/v2/resource-servers/"+id, map[string]any{"allow_online_access": false}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateResourceServer(w, r, id) })
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	got, err := e.st.ResourceServers().Get(t.Context(), e.tn.ID, id)
	if err != nil || got.AllowOnlineAccess || !got.AllowOnlineAccessWithEphemeralSessions {
		t.Fatal("patch lost flag state")
	}
}

func TestORTConfigurationCapability(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe error
		want  int
	}{{"legacy", store.ErrRefreshTokensIIUnavailable, 400}, {"lost", store.ErrRefreshTokensIISupportLost, 500}, {"transport", errors.New("temporary probe failure"), 500}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newClientsEnv(t)
			e.h.Log = slog.New(slog.DiscardHandler)
			e.h.Store = grantCascadeStore{Store: e.st, probe: tc.probe}
			rec, _ := e.call(t, e.tn, m2mCaller("create:resource_servers"), "POST", "/api/v2/resource-servers", map[string]any{"identifier": "https://unsupported-online.example", "allow_online_access": true}, e.h.CreateResourceServer)
			if rec.Code != tc.want {
				t.Fatalf("status %d want %d", rec.Code, tc.want)
			}
		})
	}
}
