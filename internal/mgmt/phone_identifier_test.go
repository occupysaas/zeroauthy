package mgmt_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func phoneIdentifierOptions() map[string]any {
	return map[string]any{"attributes": map[string]any{"phone_number": map[string]any{"identifier": map[string]any{"active": true}}}}
}
func TestEnablePhoneIdentifierRefusedOnConflicts(t *testing.T) {
	for _, numbers := range [][]string{{"bad"}, {"+1 415 555 0100", "+14155550100"}} {
		t.Run(numbers[0], func(t *testing.T) {
			e := newUsersEnv(t)
			ctx := context.Background()
			for i, n := range numbers {
				u := &store.User{TenantID: e.tn.ID, UserID: []string{"auth0|a", "auth0|b"}[i], PhoneNumber: n, Identities: []store.Identity{{Provider: "auth0", Connection: dbConn, UserID: []string{"a", "b"}[i]}}}
				if err := e.st.Users().Create(ctx, u); err != nil {
					t.Fatal(err)
				}
			}
			r, _ := e.do(t, m2mCaller("update:connections"), "PATCH", "/api/v2/connections/"+e.conn.ID, map[string]any{"options": phoneIdentifierOptions()}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateConnection(w, r, e.conn.ID) })
			if r.Code != 400 || !strings.Contains(r.Body.String(), "conflicts") || strings.Contains(r.Body.String(), "4155550100") {
				t.Fatalf("%d %s", r.Code, r.Body)
			}
			c, _ := e.st.Connections().Get(ctx, e.tn.ID, e.conn.ID)
			if store.PhoneIdentifierActive(c) {
				t.Fatal("enabled conflicting identifier")
			}
			u, _ := e.st.Users().Get(ctx, e.tn.ID, "auth0|a")
			if u.PhoneNumber != numbers[0] {
				t.Fatal("rewrote user")
			}
		})
	}
}
func TestEnablePhoneIdentifierSucceedsClean(t *testing.T) {
	e := newUsersEnv(t)
	r, _ := e.do(t, m2mCaller("update:connections"), "PATCH", "/api/v2/connections/"+e.conn.ID, map[string]any{"options": phoneIdentifierOptions()}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateConnection(w, r, e.conn.ID) })
	if r.Code != 200 {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	c, _ := e.st.Connections().Get(t.Context(), e.tn.ID, e.conn.ID)
	if !store.PhoneIdentifierActive(c) {
		t.Fatal("not active")
	}
}

func TestPhoneChangeLogsScpnAndEvent(t *testing.T) {
	e := newUsersEnv(t)
	capture := logSetup(e.clientsEnv)
	e.conn.Extra = phoneIdentifierOptions()
	if err := e.st.Connections().Update(t.Context(), e.conn); err != nil {
		t.Fatal(err)
	}
	u := e.mustCreate(t, map[string]any{"connection": dbConn, "email": "phone@example.test", "password": "A-secret-password-42", "phone_number": "+14155550100", "phone_verified": true})
	e.h.Store = events.Wrap(e.st, events.Config{})
	r, _ := e.patch(t, u["user_id"].(string), map[string]any{"phone_number": "+1 415 555 0101"})
	if r.Code != 200 {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	stored, _ := e.st.Users().Get(t.Context(), e.tn.ID, u["user_id"].(string))
	if stored.PhoneNumber != "+14155550101" || stored.PhoneVerified {
		t.Fatalf("phone=%q verified=%v", stored.PhoneNumber, stored.PhoneVerified)
	}
	rows, err := e.h.Store.Events().EventsAfter(t.Context(), e.tn.ID, 0, []string{"user.updated"}, 100, time.Now().Add(time.Hour))
	if err != nil || len(rows) != 1 {
		t.Fatalf("user.updated count=%d err=%v", len(rows), err)
	}
	if strings.Contains(string(rows[0].Body), "+14155550101") {
		t.Fatal("event leaked phone")
	}
	found := false
	for _, event := range capture.events {
		found = found || event.Type == "scpn"
	}
	if !found {
		t.Fatal("missing scpn")
	}
}
func TestPhoneChangeFailureLogsFcpn(t *testing.T) {
	e := newUsersEnv(t)
	capture := logSetup(e.clientsEnv)
	u := e.mustCreate(t, map[string]any{"connection": dbConn, "email": "phone@example.test", "password": "A-secret-password-42"})
	r, _ := e.patch(t, u["user_id"].(string), map[string]any{"phone_number": "invalid"})
	if r.Code != 400 {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	found := false
	for _, event := range capture.events {
		found = found || event.Type == "fcpn"
	}
	if !found {
		t.Fatal("missing fcpn")
	}
}
