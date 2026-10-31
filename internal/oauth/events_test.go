package oauth

import (
	"context"
	"net/url"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type eventRecorder struct{ events []logs.Event }

func (c *eventRecorder) Record(_ context.Context, e logs.Event) { c.events = append(c.events, e) }
func TestGrantEvents(t *testing.T) {
	for _, tc := range []struct {
		form  url.Values
		codes []string
	}{{cc("m2m", "m2m-secret", "audience", "https://api.acme.test"), []string{"seccft"}}, {cc("m2m", "m2m-secret", "audience", "https://missing.test"), []string{"feccft"}}, {url.Values{"grant_type": {"password"}, "client_id": {"ropg"}, "client_secret": {"ropg-secret"}, "username": {"alice@acme.test"}, "password": {"bad password"}}, []string{"fp", "fepft"}}} {
		t.Run(tc.codes[0], func(t *testing.T) {
			f := newFixture(t)
			c := &eventRecorder{}
			f.h.Recorder = c
			f.call(t, true, tokenCall{host: "acme.example.test", form: tc.form})
			if len(c.events) != len(tc.codes) {
				t.Fatalf("events=%+v", c.events)
			}
			for i, code := range tc.codes {
				got := c.events[i]
				if got.Type != code || got.TenantID == "" || got.ClientID != tc.form.Get("client_id") || got.Description == "" {
					t.Fatalf("event=%+v", got)
				}
			}
		})
	}
}

func TestTokenExchangeOutcomeEvents(t *testing.T) {
	for _, tc := range []struct {
		name, code, client string
		form               func(*testing.T, *fixture) url.Values
		user               bool
	}{
		{"authorization code success", "seacft", "code-spa", func(t *testing.T, f *fixture) url.Values {
			return codeForm(f.issueCode(t, "code-spa", "https://app.acme.test/cb", acmeAPI, []string{"openid"}, pkceChallenge), "code-spa", "https://app.acme.test/cb", pkceVerifier)
		}, true},
		{"authorization code failed", "feacft", "code-spa", func(t *testing.T, f *fixture) url.Values {
			return codeForm("invalid", "code-spa", "https://app.acme.test/cb", pkceVerifier)
		}, false},
		{"refresh success", "sertft", "rt-spa", func(t *testing.T, f *fixture) url.Values {
			raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid"}, acmeAPI)
			return refreshForm("rt-spa", raw)
		}, true},
		{"refresh failed", "fertft", "rt-spa", func(t *testing.T, f *fixture) url.Values { return refreshForm("rt-spa", "invalid") }, false},
		{"password success", "sepft", "ropg", func(t *testing.T, f *fixture) url.Values {
			return url.Values{"grant_type": {"password"}, "client_id": {"ropg"}, "client_secret": {"ropg-secret"}, "username": {"alice@acme.test"}, "password": {"alice password 1"}}
		}, true},
		{"device success", "sede", "dev", func(t *testing.T, f *fixture) url.Values {
			raw, _ := f.newDeviceCode(t, "dev", store.DeviceCodeApproved, f.aliceID(t), []string{"openid"})
			return deviceForm("dev", raw)
		}, true},
		{"device refused", "fede", "dev", func(t *testing.T, f *fixture) url.Values {
			raw, _ := f.newDeviceCode(t, "dev", store.DeviceCodeDenied, "", nil)
			return deviceForm("dev", raw)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			c := &eventRecorder{}
			f.h.Recorder = c
			f.call(t, true, tokenCall{host: "acme.example.test", form: tc.form(t, f)})
			if len(c.events) != 1 {
				t.Fatalf("events=%+v", c.events)
			}
			got := c.events[0]
			if got.Type != tc.code || got.ClientID != tc.client || got.TenantID == "" || got.Description == "" || tc.user && got.UserID == "" {
				t.Fatalf("event=%+v", got)
			}
		})
	}
}

func TestRefreshReuseAndRevokeEvents(t *testing.T) {
	f := newFixture(t)
	c := &eventRecorder{}
	f.h.Recorder = c
	raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, acmeAPI)
	f.refresh(t, refreshForm("rt-spa", raw))
	c.events = nil
	f.refresh(t, refreshForm("rt-spa", raw))
	if len(c.events) != 2 || c.events[0].Type != "ferrt" || c.events[0].UserID != rt.UserID || c.events[1].Type != "fertft" {
		t.Fatalf("reuse events=%+v", c.events)
	}
	raw, rt = f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, acmeAPI)
	c.events = nil
	f.revoke(t, url.Values{"client_id": {"rt-spa"}, "token": {raw}})
	f.revoke(t, url.Values{"client_id": {"rt-spa"}, "token": {"not-found"}})
	if len(c.events) != 1 || c.events[0].Type != "srrt" || c.events[0].UserID != rt.UserID {
		t.Fatalf("revoke events=%+v", c.events)
	}
}
func TestDevicePendingHasNoFailureEvent(t *testing.T) {
	f := newFixture(t)
	c := &eventRecorder{}
	f.h.Recorder = c
	raw, _ := f.newDeviceCode(t, "dev", store.DeviceCodePending, "", nil)
	f.call(t, false, tokenCall{host: "acme.example.test", form: deviceForm("dev", raw)})
	f.call(t, false, tokenCall{host: "acme.example.test", form: deviceForm("dev", raw)})
	if len(c.events) != 0 {
		t.Fatalf("poll events=%+v", c.events)
	}
}

func TestAuthorizationRequestFailureEvents(t *testing.T) {
	for _, tc := range []struct {
		code, client string
		call         func(*testing.T, *fixture)
	}{
		{"fdeaz", "dev", func(t *testing.T, f *fixture) {
			f.deviceCode(t, acmeHost, formType, url.Values{"client_id": {"dev"}, "audience": {"https://missing.test"}}.Encode())
		}},
		{"fpar", "par-web", func(t *testing.T, f *fixture) {
			f.par(t, acmeHost, formType, parForm("redirect_uri", "https://wrong.test/cb").Encode())
		}},
	} {
		t.Run(tc.code, func(t *testing.T) {
			f := newFixture(t)
			c := &eventRecorder{}
			f.h.Recorder = c
			tc.call(t, f)
			if len(c.events) != 1 {
				t.Fatalf("events=%+v", c.events)
			}
			got := c.events[0]
			if got.Type != tc.code || got.ClientID != tc.client || got.Description == "" || got.Hostname != acmeHost || got.TenantID == "" || got.IP == "" {
				t.Fatalf("event=%+v", got)
			}
		})
	}
}

func TestPasswordFailureClassificationEvents(t *testing.T) {
	for _, tc := range []struct{ login, password, code string }{{"missing@acme.test", "bad password", "fu"}, {"carol@acme.test", "carol password 1", "f"}, {"alice@acme.test", "alice password 1", "pwd_leak"}} {
		t.Run(tc.code, func(t *testing.T) {
			f := newFixture(t)
			capture := &eventRecorder{}
			f.h.Recorder = capture
			if tc.code == "pwd_leak" {
				tn, _ := f.st.Tenants().Get(context.Background(), f.tenantID(t, "acme"))
				tn.ProtectionSettings.BreachedPassword.Enabled = true
				tn.ProtectionSettings.BreachedPassword.Shields = []string{"block"}
				if err := f.st.Tenants().Update(context.Background(), tn); err != nil {
					t.Fatal(err)
				}
				f.h.Protection = &protection.Service{Store: f.st, BreachChecker: &breachStub{}}
			}
			f.pwCall(t, pw("ropg", "ropg-secret", tc.login, tc.password))
			if len(capture.events) != 2 {
				t.Fatalf("events=%+v", capture.events)
			}
			got := capture.events[0]
			if got.Type != tc.code || got.ClientID != "ropg" || got.ConnectionID == "" || got.Connection != "Username-Password-Authentication" || got.Strategy != "auth0" || got.StrategyType != "database" || got.Description == "" || capture.events[1].Type != "fepft" {
				t.Fatalf("events=%+v", capture.events)
			}
		})
	}
}

func TestActionExecutionLinksOnGrantEvents(t *testing.T) {
	for _, tc := range []struct{ name, script, code string }{{"success", "", "sepft"}, {"deny", "api.access.deny('blocked','denied');", "fepft"}, {"throw", "throw Error('private failure');", "fepft"}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newActionsFixture(t)
			capture := &eventRecorder{}
			f.h.Recorder = capture
			f.actions.PostLogin(t, f.tid, "event-link", `exports.onExecutePostLogin=(event,api)=>{`+tc.script+`};`)
			f.token(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1"))
			if len(capture.events) != 1 {
				t.Fatalf("events=%+v", capture.events)
			}
			got := capture.events[0]
			if got.Type != tc.code || got.UserID == "" || len(got.ExecutionIDs) != 1 {
				t.Fatalf("event=%+v", got)
			}
			if _, err := f.st.Actions().GetExecution(context.Background(), f.tid, got.ExecutionIDs[0]); err != nil {
				t.Fatal("execution link does not resolve", err)
			}
		})
	}
}
