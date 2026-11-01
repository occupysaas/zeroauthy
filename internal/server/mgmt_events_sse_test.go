package server

import (
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSSEScope(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}})
	for _, authenticated := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/api/v2/events", nil)
		want := 401
		if authenticated {
			want = 403
			r = r.WithContext(mgmt.WithCaller(r.Context(), mgmt.Caller{Kind: mgmt.M2M, Scopes: []string{"read:clients"}}))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatal(w.Code, w.Body)
		}
	}
}
func TestSSEServerAuthenticationAndLiveGrant(t *testing.T) {
	seed := strings.Replace(eventSeed(), `"read:event_streams"`, `"read:events", "read:event_streams"`, 1)
	h, st := newMgmtEnvSeed(t, seed, nil)
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	w, _ := send(h, http.MethodGet, "https://acme.example.test/api/v2/events?event_type=unknown", map[string]string{"Authorization": "Bearer " + token})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_request") {
		t.Fatal(w.Code, w.Body)
	}
	admin, _ := operatorToken(t, st, "sse-admin@example.test")
	limited, uid := operatorToken(t, st, "sse-limited@example.test")
	w, _ = sendJSON(h, "GET", "https://acme.example.test/api/v2/events?from=bad", limited, nil)
	if w.Code != 400 {
		t.Fatal(w.Code, w.Body)
	}
	w, _ = sendJSON(h, "PATCH", "https://"+mgmtSystemHost+"/api/system/operators/"+uid, admin, map[string]any{"tenants": []string{}})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w, _ = sendJSON(h, "GET", "https://acme.example.test/api/v2/events?from=bad", limited, nil)
	if w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
}
