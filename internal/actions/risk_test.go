package actions

import (
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestRiskAssessment(t *testing.T) {
	for _, known := range []bool{false, true} {
		for _, blocked := range []bool{false, true} {
			r := AssessRisk(RiskInput{KnownDevice: known, BlockedIP: blocked})
			want := "low"
			if known && !blocked {
				want = "high"
			}
			if r.Confidence != want {
				t.Fatalf("known=%v blocked=%v: %+v", known, blocked, r)
			}
			for _, name := range []string{"ImpossibleTravel", "AgentDetection"} {
				if r.Assessments[name].Confidence != "neutral" {
					t.Fatal(r)
				}
			}
			device := "unknown_device"
			if known {
				device = "match"
			}
			ip := "not_found_on_deny_list"
			if blocked {
				ip = "found_on_deny_list"
			}
			if r.Assessments["NewDevice"].Code != device || r.Assessments["UntrustedIP"].Code != ip {
				t.Fatal(r)
			}
		}
	}
}
func eventInput() *PostLoginInput {
	return &PostLoginInput{Tenant: tenant.Resolved{Tenant: &store.Tenant{ID: "t"}}, User: &store.User{UserID: "u"}, Connection: &store.Connection{Strategy: "auth0"}}
}
func eventFor(in *PostLoginInput) map[string]any {
	return postLoginEvent(in, nil, newAccum(TriggerPostLogin, nil, nil, false))
}
func TestEventCustomDomain(t *testing.T) {
	in := eventInput()
	if _, ok := eventFor(in)["custom_domain"]; ok {
		t.Fatal("canonical domain")
	}
	in.CustomDomain = &customdomain.PublicDomain{Domain: "login.example.test", Metadata: map[string]string{"env": "test"}}
	if got := eventFor(in)["custom_domain"].(map[string]any); got["domain"] != "login.example.test" || got["domain_metadata"].(map[string]string)["env"] != "test" {
		t.Fatal(got)
	}
}
func TestSecurityContextTrustedOnly(t *testing.T) {
	r := httptest.NewRequest("GET", "https://tenant.test", nil)
	r.Header.Set("X-JA3", "untrusted")
	r.Header.Set("Proxy-JA4", "trusted")
	if got := SecurityContext(r, "", ""); got["ja3"] != nil || got["ja4"] != nil {
		t.Fatal(got)
	}
	if got := SecurityContext(r, "X-JA3", "Proxy-JA4"); got["ja3"] != "untrusted" || got["ja4"] != "trusted" {
		t.Fatal(got)
	}
	r.Header.Set("X-JA3", string(make([]byte, 1025)))
	if SecurityContext(r, "X-JA3", "")["ja3"] != nil {
		t.Fatal("unbounded fingerprint")
	}
}
func TestEventUserFields(t *testing.T) {
	in := eventInput()
	now := time.Now().UTC()
	in.User.LastPasswordReset = &now
	in.EnrolledFactors = []map[string]any{{"type": "otp"}, {"type": "phone"}}
	u := eventFor(in)["user"].(map[string]any)
	if u["last_password_reset"] != rfc3339(now) || !reflect.DeepEqual(u["multifactor"], []string{"google-authenticator", "guardian"}) {
		t.Fatal(u)
	}
	in.Connection.Strategy = "google-oauth2"
	if _, ok := eventFor(in)["user"].(map[string]any)["last_password_reset"]; ok {
		t.Fatal("social password reset")
	}
}
func TestEventSessionMembers(t *testing.T) {
	in := eventInput()
	in.Session = &store.LoginSession{ID: "sid", UserID: "u", ClientIDs: []string{"c"}, CookieMode: "non-persistent", InitialIP: "192.0.2.1", LastUserAgent: "ua"}
	s := eventFor(in)["session"].(map[string]any)
	for _, k := range []string{"id", "user_id", "clients", "cookie", "device", "created_at", "updated_at", "authenticated_at", "last_interacted_at", "expires_at", "idle_expires_at", "metadata"} {
		if _, ok := s[k]; !ok {
			t.Error(k)
		}
	}
	if _, ok := s["actor"]; ok {
		t.Fatal("invented actor")
	}
}
func TestEventRefreshTokenMembers(t *testing.T) {
	in := eventInput()
	in.RefreshToken = &store.RefreshToken{ID: "rt", ClientID: "c", SessionID: "sid", UserID: "u", Rotating: true, Audience: "api", Scopes: []string{"read"}, Device: &store.RefreshTokenDevice{InitialIP: "192.0.2.1"}}
	rt := eventFor(in)["refresh_token"].(map[string]any)
	for _, k := range []string{"id", "client_id", "session_id", "user_id", "rotating", "device", "resource_servers", "created_at", "metadata"} {
		if _, ok := rt[k]; !ok {
			t.Error(k)
		}
	}
	if _, ok := rt["token_hash"]; ok {
		t.Fatal("credential")
	}
}
func TestEventTransactionIDs(t *testing.T) {
	in := eventInput()
	in.Transaction.ID = "txn"
	in.Transaction.LinkingID = "link"
	in.Request.CorrelationID = "corr"
	for range 2 {
		tx := eventFor(in)["transaction"].(map[string]any)
		if tx["linking_id"] != "link" || tx["correlation_id"] != "corr" {
			t.Fatal(tx)
		}
	}
}
