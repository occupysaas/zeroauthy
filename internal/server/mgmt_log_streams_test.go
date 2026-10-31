package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestLogStreamAPIRouteScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}})
	for _, route := range []struct{ method, path string }{{"GET", "/api/v2/log-streams"}, {"POST", "/api/v2/log-streams"}, {"GET", "/api/v2/log-streams/id"}, {"PATCH", "/api/v2/log-streams/id"}, {"DELETE", "/api/v2/log-streams/id"}} {
		for _, authenticated := range []bool{false, true} {
			r := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
			want := 401
			if authenticated {
				want = 403
				r = r.WithContext(mgmt.WithCaller(r.Context(), mgmt.Caller{Kind: mgmt.M2M, Scopes: []string{"read:clients"}}))
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatalf("%s %s got%d want%d %s", route.method, route.path, w.Code, want, w.Body)
			}
		}
	}
}
func TestLogStreamsThroughServer(t *testing.T) {
	seed := strings.Replace(usersSeed, `"read:connections", "create:connections"`, `"read:log_streams", "create:log_streams", "update:log_streams", "delete:log_streams", "read:connections", "create:connections"`, 1)
	h, st := newMgmtEnvSeed(t, seed, nil)
	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	reader := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	body := map[string]any{"type": "http", "sink": map[string]any{"httpEndpoint": "https://collector.example.test/logs", "httpAuthorization": "SENTINEL_STREAM_SECRET"}}
	w, _ := sendJSON(h, "POST", "https://acme.example.test/api/v2/log-streams", reader, body)
	if w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
	w, out := sendJSON(h, "POST", "https://acme.example.test/api/v2/log-streams", admin, body)
	if w.Code != 201 || strings.Contains(w.Body.String(), "SENTINEL_") {
		t.Fatal(w.Code, w.Body)
	}
	id, _ := out["id"].(string)
	if id == "" {
		t.Fatal("missing id")
	}
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{{"GET", "", nil, 200}, {"GET", "/" + id, nil, 200}, {"PATCH", "/" + id, map[string]any{"name": "Renamed"}, 200}, {"DELETE", "/" + id, nil, 204}, {"GET", "/" + id, nil, 404}} {
		w, _ = sendJSON(h, tc.method, "https://acme.example.test/api/v2/log-streams"+tc.path, admin, tc.body)
		if w.Code != tc.want {
			t.Fatal(tc.method, tc.path, w.Code, w.Body)
		}
	}
	var scopes []store.Scope
	tenants, err := st.Tenants().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, tn := range tenants {
		if tn.Name == "acme" {
			rs, err := st.ResourceServers().GetByIdentifier(t.Context(), tn.ID, acmeMgmtAPI)
			if err != nil {
				t.Fatal(err)
			}
			scopes = rs.Scopes
		}
	}
	for _, wanted := range []string{"read:log_streams", "create:log_streams", "update:log_streams", "delete:log_streams"} {
		found := false
		for _, s := range scopes {
			if s.Value == wanted {
				found = true
			}
		}
		if !found {
			t.Fatal("missing provisioned scope", wanted)
		}
	}
}
func TestLogStreamsThroughServerUnavailable(t *testing.T) {
	seed := strings.Replace(usersSeed, `"read:connections", "create:connections"`, `"read:log_streams", "create:log_streams", "update:log_streams", "delete:log_streams", "read:connections", "create:connections"`, 1)
	h, _ := newMgmtEnvSeed(t, seed, func(d *Deps) { d.Store = serverStreamsUnavailable{d.Store} })
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	for _, tc := range []struct{ method, path string }{{"GET", ""}, {"POST", ""}, {"GET", "/id"}, {"PATCH", "/id"}, {"DELETE", "/id"}} {
		w, _ := sendJSON(h, tc.method, "https://acme.example.test/api/v2/log-streams"+tc.path, token, map[string]any{})
		if w.Code != http.StatusNotImplemented || !strings.Contains(w.Body.String(), "logs_unavailable") {
			t.Fatal(tc.method, w.Code, w.Body)
		}
	}
}

type serverStreamsUnavailable struct{ store.Store }

func (s serverStreamsUnavailable) Logs() store.Logs { return store.UnimplementedLogs{} }

func (s serverStreamsUnavailable) CheckLogsSupport(context.Context) error {
	return store.ErrLogsUnavailable
}
func TestLogStreamsInsecureHTTPOptInThroughServer(t *testing.T) {
	seed := strings.Replace(usersSeed, `"read:connections", "create:connections"`, `"create:log_streams", "read:connections", "create:connections"`, 1)
	for _, allow := range []bool{false, true} {
		t.Run(strconv.FormatBool(allow), func(t *testing.T) {
			h, _ := newMgmtEnvSeed(t, seed, func(d *Deps) { d.LogsConfig.Streams.AllowInsecureHTTP = allow })
			token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
			w, _ := sendJSON(h, "POST", "https://acme.example.test/api/v2/log-streams", token, map[string]any{"type": "http", "sink": map[string]any{"httpEndpoint": "http://collector.example.test/logs"}})
			want := 400
			if allow {
				want = 201
			}
			if w.Code != want {
				t.Fatal(w.Code, w.Body)
			}
		})
	}
}

func (s serverStreamsUnavailable) LogsSupported() bool { return false }
