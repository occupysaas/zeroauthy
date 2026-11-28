package mgmt_test

import (
	"net/http"
	"testing"
)

func TestScriptContextOneWay(t *testing.T) {
	e := newClientsEnv(t)
	rec, v := e.call(t, e.tn, m2mCaller(), "POST", "/connections", map[string]any{"name": "ContextDB", "strategy": "auth0", "options": map[string]any{"enable_script_context": true}}, e.h.CreateConnection)
	if rec.Code != 201 {
		t.Fatalf("%d %v", rec.Code, v)
	}
	id := v.(map[string]any)["id"].(string)
	update := func(options map[string]any) int {
		r, _ := e.call(t, e.tn, m2mCaller(), "PATCH", "/connections/"+id, map[string]any{"options": options}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateConnection(w, r, id) })
		return r.Code
	}
	if status := update(map[string]any{"enable_script_context": false}); status != 400 {
		t.Fatalf("disable=%d", status)
	}
	if status := update(map[string]any{"requires_username": false}); status != 200 {
		t.Fatalf("replacement=%d", status)
	}
}
