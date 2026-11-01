package server

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	}{{"take=1&page=bad&per_page=bad&include_totals=bad&include_fields=bad&sort=bad&q=bad:&fields=bad", 200}, {"from=bad&take=1", 400}, {"take=0", 400}, {"take=1&page=bad&page=bad", 200}, {"take=1&take=1", 400}, {"take=1&unknown=x", 200}, {"from=" + strings.Repeat("0", 55) + "1&take=100&search_engine=v3&q=*&sort=date:1", 200}, {"take=1&search_engine=v3&search_engine=bad&unknown=x&unknown=y", 200}, {"search_engine=v2", 400}, {"page=10&per_page=100", 400}} {
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

func TestLogsSearchEngineSelectorThroughServer(t *testing.T) {
	seed := strings.Replace(usersSeed, `"read:connections", "create:connections"`, `"read:logs", "read:logs_users", "read:connections", "create:connections"`, 1)
	h, st := newMgmtEnvSeed(t, seed, nil)
	tok := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	tn, err := st.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if err = st.Users().Create(context.Background(), &store.User{TenantID: tn.ID, UserID: "auth0|selector"}); err != nil {
		t.Fatal(err)
	}
	if err = st.Logs().AppendLogs(context.Background(), []store.LogEvent{
		{TenantID: tn.ID, Type: "s", Date: time.Now(), UserID: "auth0|selector", Body: []byte(`{"description":"selected success"}`)},
		{TenantID: tn.ID, Type: "f", Date: time.Now(), Body: []byte(`{"description":"excluded failure"}`)},
	}, nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, query string
		status            int
		total             bool
	}{
		{"baseline", "logs", "per_page=1", 200, false},
		{"selector", "logs", "per_page=1&search_engine=v3", 200, false},
		{"CLI filtered page", "logs", "search_engine=v3&q=type:s&include_totals=true&per_page=1&page=0&sort=date:1", 200, true},
		{"empty", "logs", "search_engine=", 400, false},
		{"v2", "logs", "search_engine=v2", 400, false},
		{"case", "logs", "search_engine=V3", 400, false},
		{"unknown", "logs", "search_engine=future", 400, false},
		{"duplicate same", "logs", "search_engine=v3&search_engine=v3", 400, false},
		{"duplicate mixed", "logs", "search_engine=v3&search_engine=v2", 400, false},
		{"strict other parameter", "logs", "search_engine=v3&unknown=x", 400, false},
		{"take precedence", "logs", "take=1&search_engine=v2&search_engine=bad&q=bad:", 200, false},
		{"from precedence", "logs", "from=" + store.FormatLogID(1) + "&search_engine=v2&search_engine=bad&page=bad", 200, false},
		{"strict checkpoint take", "logs", "take=1&take=1&search_engine=v3", 400, false},
		{"user normal page", "users/auth0%7Cselector/logs", "per_page=1", 200, false},
		{"user selector unsupported", "users/auth0%7Cselector/logs", "search_engine=v3", 400, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, out := sendRaw(h, "GET", "https://acme.example.test/api/v2/"+tc.path+"?"+tc.query, tok, nil)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d %s", w.Code, tc.status, w.Body)
			}
			if tc.status == 400 && errCode(out) != "invalid_query_string" {
				t.Fatal(out)
			}
			if tc.total {
				page := out.(map[string]any)
				rows := page["logs"].([]any)
				if page["total"] != float64(1) || len(rows) != 1 || rows[0].(map[string]any)["type"] != "s" || rows[0].(map[string]any)["description"] != "selected success" {
					t.Fatal(out)
				}
			}
		})
	}
}
