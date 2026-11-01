package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestEventStreamAPIRouteScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}})
	for _, route := range []struct{ method, path string }{{"GET", "/api/v2/event-streams"}, {"POST", "/api/v2/event-streams"}, {"GET", "/api/v2/event-streams/est_1234567890123456789012"}, {"PATCH", "/api/v2/event-streams/est_1234567890123456789012"}, {"DELETE", "/api/v2/event-streams/est_1234567890123456789012"}} {
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
				t.Fatalf("%s %s: got %d want %d %s", route.method, route.path, w.Code, want, w.Body)
			}
		}
	}
}
func eventSeed() string {
	return strings.Replace(usersSeed, `"read:connections", "create:connections"`, `"read:event_streams", "create:event_streams", "update:event_streams", "delete:event_streams", "read:connections", "create:connections"`, 1)
}
func TestEventStreamsThroughServer(t *testing.T) {
	h, st := newMgmtEnvSeed(t, eventSeed(), nil)
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	reader := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	body := map[string]any{"name": "Example", "subscriptions": []any{map[string]any{"event_type": "user.created"}}, "destination": map[string]any{"type": "webhook", "configuration": map[string]any{"webhook_endpoint": "https://collector.example.test/events", "webhook_authorization": map[string]any{"method": "bearer", "token": "EVENT_SECRET_SENTINEL"}}}}
	w, _ := sendJSON(h, "POST", "https://acme.example.test/api/v2/event-streams", reader, body)
	if w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
	w, out := sendJSON(h, "POST", "https://acme.example.test/api/v2/event-streams", token, body)
	if w.Code != 201 || strings.Contains(w.Body.String(), "EVENT_SECRET") {
		t.Fatal(w.Code, w.Body)
	}
	id := out["id"].(string)
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{{"GET", "", nil, 200}, {"GET", "/" + id, nil, 200}, {"PATCH", "/" + id, map[string]any{"name": "Renamed"}, 200}, {"DELETE", "/" + id, nil, 204}, {"GET", "/" + id, nil, 404}} {
		w, _ := sendJSON(h, tc.method, "https://acme.example.test/api/v2/event-streams"+tc.path, token, tc.body)
		if w.Code != tc.want {
			t.Fatal(tc.method, w.Code, w.Body)
		}
	}
	tenants, err := st.Tenants().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, tn := range tenants {
		if tn.Name != "acme" {
			continue
		}
		rs, err := st.ResourceServers().GetByIdentifier(t.Context(), tn.ID, acmeMgmtAPI)
		if err != nil {
			t.Fatal(err)
		}
		for _, scope := range []string{"read:event_streams", "create:event_streams", "update:event_streams", "delete:event_streams", "read:event_deliveries", "update:event_deliveries", "read:events"} {
			found := false
			for _, s := range rs.Scopes {
				if s.Value == scope {
					found = true
				}
			}
			if !found {
				t.Fatal("missing scope", scope)
			}
		}
	}
}

type serverEventsUnavailable struct{ store.Store }

func (s serverEventsUnavailable) Events() store.Events { return store.UnimplementedEvents{} }
func (s serverEventsUnavailable) CheckEventsSupport(context.Context) error {
	return store.ErrEventsUnavailable
}
func (s serverEventsUnavailable) EventsSupported() bool { return false }
func TestEventStreamsThroughServerUnavailable(t *testing.T) {
	h, _ := newMgmtEnvSeed(t, eventSeed(), func(d *Deps) { d.Store = serverEventsUnavailable{d.Store} })
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	for _, tc := range []struct{ method, path string }{{"GET", ""}, {"POST", ""}, {"GET", "/est_1234567890123456789012"}, {"PATCH", "/est_1234567890123456789012"}, {"DELETE", "/est_1234567890123456789012"}} {
		w, _ := sendJSON(h, tc.method, "https://acme.example.test/api/v2/event-streams"+tc.path, token, map[string]any{})
		if w.Code != 501 || !strings.Contains(w.Body.String(), "events_unavailable") {
			t.Fatal(tc.method, w.Code, w.Body)
		}
	}
}

func TestEventStreamOperatorLiveGrant(t *testing.T) {
	h, st := newMgmtEnvSeed(t, eventSeed(), nil)
	admin, _ := operatorToken(t, st, "events-admin@example.test")
	limited, uid := operatorToken(t, st, "events-limited@example.test")
	w, _ := sendJSON(h, "GET", "https://acme.example.test/api/v2/event-streams", limited, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w, _ = sendJSON(h, "PATCH", "https://"+mgmtSystemHost+"/api/system/operators/"+uid, admin, map[string]any{"tenants": []string{}})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w, _ = sendJSON(h, "GET", "https://acme.example.test/api/v2/event-streams", limited, nil)
	if w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestEventStreamHTTPConfigThroughServer(t *testing.T) {
	for _, allow := range []bool{false, true} {
		h, _ := newMgmtEnvSeed(t, eventSeed(), func(d *Deps) { d.EventsConfig.AllowInsecureHTTP = allow; d.EventsConfig.MaxStreams = 1 })
		token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
		body := map[string]any{"name": "Example", "subscriptions": []any{map[string]any{"event_type": "user.created"}}, "destination": map[string]any{"type": "webhook", "configuration": map[string]any{"webhook_endpoint": "http://collector.example.test/events", "webhook_authorization": map[string]any{"method": "bearer", "token": "secret"}}}}
		w, _ := sendJSON(h, "POST", "https://acme.example.test/api/v2/event-streams", token, body)
		want := 400
		if allow {
			want = 201
		}
		if w.Code != want {
			t.Fatal(allow, w.Code, w.Body)
		}
		if allow {
			body["name"] = "Over quota"
			w, _ = sendJSON(h, "POST", "https://acme.example.test/api/v2/event-streams", token, body)
			if w.Code != 409 {
				t.Fatal(w.Code, w.Body)
			}
		}
	}
}

func TestEventStreamQueryErrorCodesThroughServer(t *testing.T) {
	h, _ := newMgmtEnvSeed(t, eventSeed(), nil)
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	for _, query := range []string{"take=bad", "take=101", "take=1&take=2", "unknown=yes", "from=invalid"} {
		w, out := sendJSON(h, "GET", "https://acme.example.test/api/v2/event-streams?"+query, token, nil)
		if w.Code != 400 || out["errorCode"] != "invalid_request" {
			t.Fatal(query, w.Code, w.Body)
		}
	}
}
