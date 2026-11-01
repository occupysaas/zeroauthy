package server

import (
	"github.com/zeroauthy/zeroauthy/internal/eventstream"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestDeliveriesScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{Store: serverEventsUnavailable{}}})
	for _, route := range []struct {
		method, path string
		allowed      []string
	}{
		{"POST", "/test", []string{"update:event_streams"}},
		{"GET", "/deliveries", []string{"read:event_streams", "read:event_deliveries"}},
		{"GET", "/deliveries/evt_1234567890123456789012", []string{"read:event_deliveries"}},
		{"POST", "/redeliver", []string{"update:event_deliveries"}},
		{"POST", "/redeliver/evt_1234567890123456789012", []string{"update:event_deliveries"}},
	} {
		for _, scope := range []string{"", "read:clients", "read:event_streams", "read:event_deliveries", "update:event_streams", "update:event_deliveries"} {
			r := httptest.NewRequest(route.method, "/api/v2/event-streams/est_1234567890123456789012"+route.path, strings.NewReader(`{}`))
			want := 403
			if scope == "" {
				want = 401
			} else {
				r = r.WithContext(mgmt.WithCaller(r.Context(), mgmt.Caller{Kind: mgmt.M2M, Scopes: []string{scope}}))
				for _, s := range route.allowed {
					if scope == s {
						want = 501
					}
				}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatalf("%s %s scope %q: %d want %d %s", route.method, route.path, scope, w.Code, want, w.Body)
			}
		}
	}
}
func deliverySeed() string {
	return strings.Replace(eventSeed(), `"read:event_streams", "create:event_streams"`, `"read:event_deliveries", "update:event_deliveries", "read:event_streams", "create:event_streams"`, 1)
}
func TestDeliveriesThroughServerLiveAuth(t *testing.T) {
	h, st := newMgmtEnvSeed(t, deliverySeed(), nil)
	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	reader := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	id := "est_1234567890123456789012"
	tns, err := st.Tenants().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, tn := range tns {
		if tn.Name == "acme" {
			if err = st.Events().CreateEventStream(t.Context(), &store.EventStream{TenantID: tn.ID, ID: id, Name: "Scope", Status: "disabled", DestType: "eventbridge"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{{"GET", "/deliveries", nil, 200}, {"GET", "/deliveries/evt_1234567890123456789012", nil, 404}, {"POST", "/redeliver", nil, 409}, {"POST", "/redeliver/evt_1234567890123456789012", nil, 404}, {"POST", "/test", map[string]any{"event_type": "user.created"}, 400}} {
		w, _ := sendJSON(h, tc.method, "https://acme.example.test/api/v2/event-streams/"+id+tc.path, admin, tc.body)
		if w.Code != tc.want {
			t.Fatal(tc.path, w.Code, w.Body)
		}
		w, _ = sendJSON(h, tc.method, "https://acme.example.test/api/v2/event-streams/"+id+tc.path, reader, tc.body)
		if w.Code != 403 {
			t.Fatal(tc.path, w.Code, w.Body)
		}
	}
	operator, _ := operatorToken(t, st, "delivery-admin@example.test")
	limited, uid := operatorToken(t, st, "delivery-limited@example.test")
	w, _ := sendJSON(h, "GET", "https://acme.example.test/api/v2/event-streams/"+id+"/deliveries", limited, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w, _ = sendJSON(h, "PATCH", "https://"+mgmtSystemHost+"/api/system/operators/"+uid, operator, map[string]any{"tenants": []string{}})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w, _ = sendJSON(h, "GET", "https://acme.example.test/api/v2/event-streams/"+id+"/deliveries", limited, nil)
	if w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
	for _, q := range []string{"take=bad", "take=1&take=2", "date_from=2026-01-01T00:00:00.0Z", "unknown=yes"} {
		w, out := sendJSON(h, "GET", "https://acme.example.test/api/v2/event-streams/"+id+"/deliveries?"+q, admin, nil)
		if w.Code != 400 || out["errorCode"] != "invalid_request" {
			t.Fatal(q, w.Code, w.Body)
		}
	}
}
func TestDeliveriesServerUnavailable(t *testing.T) {
	h, _ := newMgmtEnvSeed(t, deliverySeed(), func(d *Deps) { d.Store = serverEventsUnavailable{d.Store} })
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	for _, tc := range []struct{ method, path string }{{"GET", "deliveries"}, {"GET", "deliveries/evt_1234567890123456789012"}, {"POST", "test"}, {"POST", "redeliver"}, {"POST", "redeliver/evt_1234567890123456789012"}} {
		w, _ := sendJSON(h, tc.method, "https://acme.example.test/api/v2/event-streams/est_1234567890123456789012/"+tc.path, token, map[string]any{})
		if w.Code != 501 {
			t.Fatal(tc.path, w.Code, w.Body)
		}
	}
}

type serverDeliveryTransport struct{}

func (serverDeliveryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}
func TestSendTestEventThroughServerSharedWorker(t *testing.T) {
	h, _ := newMgmtEnvSeed(t, deliverySeed(), func(d *Deps) {
		d.EventDeliverer = eventstream.NewWorker(d.Store, d.Wrapper, d.EventsConfig, &http.Client{Transport: serverDeliveryTransport{}}, nil, nil)
	})
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	body := map[string]any{"name": "Test route", "subscriptions": []any{map[string]any{"event_type": "user.created"}}, "destination": map[string]any{"type": "webhook", "configuration": map[string]any{"webhook_endpoint": "https://receiver.example.test/events", "webhook_authorization": map[string]any{"method": "bearer", "token": "SERVER_EVENT_SECRET"}}}}
	w, out := sendJSON(h, "POST", "https://acme.example.test/api/v2/event-streams", token, body)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	id := out["id"].(string)
	w, out = sendJSON(h, "POST", "https://acme.example.test/api/v2/event-streams/"+id+"/test", token, map[string]any{"event_type": "user.created"})
	if w.Code != 202 || out["status"] != "success" || strings.Contains(w.Body.String(), "SERVER_EVENT_SECRET") {
		t.Fatal(w.Code, w.Body)
	}
}
