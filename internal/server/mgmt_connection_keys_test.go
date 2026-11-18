package server

import (
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"net/http/httptest"
	"testing"
)

func TestKeysScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}})
	for _, tc := range []struct {
		method, path string
		scopes       []string
	}{{"GET", "/keys", nil}, {"POST", "/keys", nil}, {"POST", "/keys/rotate", []string{"create:connections_keys"}}, {"POST", "/keys/rotate", []string{"update:connections_keys"}}} {
		r := httptest.NewRequest(tc.method, "/api/v2/connections/con_one"+tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal(w.Code)
		}
		r = r.WithContext(mgmt.WithCaller(r.Context(), mgmt.Caller{Kind: mgmt.M2M, Scopes: tc.scopes}))
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("%s %s: %d", tc.method, tc.path, w.Code)
		}
	}
}
