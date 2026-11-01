package dbconn

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/protection"
)

type eventRecorder struct{ events []logs.Event }

func (c *eventRecorder) Record(_ context.Context, e logs.Event) { c.events = append(c.events, e) }
func TestDatabaseConnectionEvents(t *testing.T) {
	for _, tc := range []struct {
		body, code string
		status     int
	}{{`{"client_id":"app","connection":"Username-Password-Authentication","email":"new@acme.test","password":"new password 1"}`, "ss", 200}, {`{"client_id":"app","connection":"Closed","email":"new@acme.test","password":"new password 1"}`, "fs", 400}} {
		t.Run(tc.code, func(t *testing.T) {
			e := newEnv(t)
			c := &eventRecorder{}
			e.h.Recorder = c
			status, _, _ := e.post(t, "/dbconnections/signup", "application/json", tc.body)
			if status != tc.status {
				t.Fatalf("status=%d", status)
			}
			if len(c.events) != 1 {
				t.Fatalf("events=%+v", c.events)
			}
			got := c.events[0]
			if got.Type != tc.code || got.ClientID != "app" || got.Connection == "" || got.ConnectionID == "" || got.Strategy != "auth0" || got.StrategyType != "database" || got.Description == "" || (tc.code == "ss" && got.UserID == "") {
				t.Fatalf("event=%+v", got)
			}
		})
	}
}

func TestPasswordResetInitiationEvents(t *testing.T) {
	for _, tc := range []struct{ body, code string }{{`{"client_id":"app","connection":"Username-Password-Authentication","email":"missing@acme.test"}`, "scpr"}, {`{"client_id":"app","connection":"Not-Enabled","email":"alice@acme.test"}`, "fcpr"}} {
		t.Run(tc.code, func(t *testing.T) {
			e := newEnv(t)
			c := &eventRecorder{}
			e.h.Recorder = c
			e.post(t, "/dbconnections/change_password", "application/json", tc.body)
			if len(c.events) != 1 {
				t.Fatalf("events=%+v", c.events)
			}
			got := c.events[0]
			if got.Type != tc.code || got.ClientID != "app" || got.ConnectionID == "" || got.Strategy != "auth0" || got.StrategyType != "database" || got.Description == "" {
				t.Fatalf("event=%+v", got)
			}
		})
	}
}

func TestSignupBreachEvents(t *testing.T) {
	e := newEnv(t)
	capture := &eventRecorder{}
	e.h.Recorder = capture
	tn, _ := e.st.Tenants().Get(context.Background(), e.tenantID)
	tn.ProtectionSettings.BreachedPassword.Enabled = true
	tn.ProtectionSettings.BreachedPassword.Stage.PreUserRegistration.Shields = []string{"block"}
	if err := e.st.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	e.h.Protection = &protection.Service{Store: e.st, BreachChecker: &breachStub{hit: true}}
	e.post(t, "/dbconnections/signup", "application/json", `{"client_id":"app","connection":"Username-Password-Authentication","email":"new@acme.test","password":"new password 1"}`)
	if len(capture.events) != 2 || capture.events[0].Type != "signup_pwd_leak" || capture.events[1].Type != "fs" {
		t.Fatalf("events=%+v", capture.events)
	}
	for _, got := range capture.events {
		if got.ClientID != "app" || got.ConnectionID == "" || got.Strategy != "auth0" || got.StrategyType != "database" || got.Description == "" {
			t.Fatalf("event=%+v", got)
		}
	}
}
