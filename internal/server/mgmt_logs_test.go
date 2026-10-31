package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
)

func TestLogsAPIRouteScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}})
	for _, path := range []string{"/api/v2/logs", "/api/v2/logs/invalid", "/api/v2/users/auth0%7Cu/logs"} {
		for _, scopes := range [][]string{nil, {"read:users"}} {
			r := httptest.NewRequest("GET", path, nil)
			want := 401
			if scopes != nil {
				want = 403
				r = r.WithContext(mgmt.WithCaller(r.Context(), mgmt.Caller{Kind: mgmt.M2M, Scopes: scopes}))
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal(path, w.Code, w.Body)
			}
		}
	}
}
func TestLogsAPIRealCheckpointBinding(t *testing.T) {
	seed := strings.Replace(usersSeed, `"read:connections", "create:connections"`, `"read:logs", "read:logs_users", "read:connections", "create:connections"`, 1)
	h, _ := newMgmtEnvSeed(t, seed, nil)
	tok := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	for _, tc := range []struct {
		query string
		want  int
	}{{"take=1&page=bad&per_page=bad&include_totals=bad&include_fields=bad&sort=bad&q=bad:&fields=bad", 200}, {"from=bad&take=1", 400}, {"take=0", 400}, {"take=1&page=bad&page=bad", 200}, {"take=1&take=1", 400}, {"take=1&unknown=x", 400}, {"page=10&per_page=100", 400}} {
		r := httptest.NewRequest("GET", "https://acme.example.test/api/v2/logs?"+tc.query, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s got%d want%d %s", tc.query, w.Code, tc.want, w.Body)
		}
	}
	for _, scope := range []string{"read:logs", "read:logs_users"} {
		r := httptest.NewRequest("GET", "/api/v2/users/auth0%7Cu/logs", nil)
		r = r.WithContext(mgmt.WithCaller(r.Context(), mgmt.Caller{Kind: mgmt.M2M, Scopes: []string{scope}}))
		w := httptest.NewRecorder()
		mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}}).ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatal(scope, w.Code, w.Body)
		}
	}
}
