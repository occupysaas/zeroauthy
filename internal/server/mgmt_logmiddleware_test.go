package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logs"
)

type managementRouteRecorder struct{ events []logs.Event }

func (c *managementRouteRecorder) Record(_ context.Context, e logs.Event) {
	c.events = append(c.events, e)
}
func TestManagementEventsAfterAuthAndBeforeScope(t *testing.T) {
	recorder := &managementRouteRecorder{}
	h, _ := newMgmtEnvWith(t, func(d *Deps) { d.Recorder = recorder })
	admin := clientToken(t, h, "acme.example.test", "https://acme.example.test/api/v2/", "admin", "admin-s3cret")
	reader := m2mToken(t, h, "acme.example.test", "https://acme.example.test/api/v2/")
	for _, tc := range []struct {
		token        string
		status       int
		event, actor string
	}{{admin, 201, "sapi", "admin"}, {reader, 403, "fapi", "m2m"}, {"", 401, "", ""}} {
		recorder.events = nil
		r := httptest.NewRequest("POST", "https://acme.example.test/api/v2/clients", strings.NewReader(`{"name":"created"}`))
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		if tc.event == "" {
			if len(recorder.events) != 0 {
				t.Fatalf("unauthenticated event %+v", recorder.events)
			}
			continue
		}
		if len(recorder.events) != 1 || recorder.events[0].Type != tc.event || recorder.events[0].ClientID != tc.actor {
			t.Fatalf("events=%+v", recorder.events)
		}
	}
}
func TestManagementAPIReadNoEventForLogList(t *testing.T) {
	recorder := &managementRouteRecorder{}
	h, _ := newMgmtEnvWith(t, func(d *Deps) { d.Recorder = recorder })
	reader := m2mToken(t, h, "acme.example.test", "https://acme.example.test/api/v2/")
	recorder.events = nil
	w, _ := send(h, http.MethodGet, "https://acme.example.test/api/v2/logs", map[string]string{"Authorization": "Bearer " + reader})
	if w.Code != 403 || len(recorder.events) != 0 {
		t.Fatalf("%d events=%+v", w.Code, recorder.events)
	}
}
