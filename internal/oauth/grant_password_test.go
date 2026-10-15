package oauth

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
)

func pw(clientID, secret, username, password string, extra ...string) url.Values {
	v := url.Values{"grant_type": {"password"}, "client_id": {clientID}, "username": {username}, "password": {password}}
	if secret != "" {
		v.Set("client_secret", secret)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func TestPasswordGrant(t *testing.T) {
	f := newFixture(t)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test",
		form: pw("ropg", "ropg-secret", "Alice@Acme.test ", "alice password 1", "audience", "https://api.acme.test", "scope", "openid read:things offline_access")})
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	if at["gty"] != "password" || at["azp"] != "ropg" || !strings.HasPrefix(at["sub"].(string), "auth0|") {
		t.Fatalf("access token = %v", at)
	}
	idt, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["id_token"].(string))
	if idt["sid"] != nil || idt["auth_time"] != float64(fixedNow().Unix()) || idt["email"] != nil {
		t.Fatalf("id token = %v", idt)
	}
	if body["refresh_token"] == nil || body["scope"] != "openid read:things offline_access" {
		t.Fatalf("body = %v", body)
	}
}

func TestPasswordRealmGrant(t *testing.T) {
	f := newFixture(t)
	form := pw("ropg", "ropg-secret", "bob@acme.test", "bob password 12")
	form.Set("grant_type", GrantPasswordRealm)
	form.Set("realm", "Other-DB")
	if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form}); rec.Code != 200 {
		t.Fatalf("realm grant = %d %v", rec.Code, body)
	}
	// bob is not in the default directory.
	if rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "bob@acme.test", "bob password 12")}); rec.Code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("default directory = %d %v", rec.Code, body)
	}
}

func TestPasswordGrantRejects(t *testing.T) {
	realm := func(r string) url.Values {
		v := pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1")
		v.Set("grant_type", GrantPasswordRealm)
		if r != "" {
			v.Set("realm", r)
		}
		return v
	}
	cases := map[string]struct {
		form   url.Values
		status int
		code   string
	}{
		"wrong password":    {pw("ropg", "ropg-secret", "alice@acme.test", "nope"), 400, "invalid_grant"},
		"unknown user":      {pw("ropg", "ropg-secret", "nobody@acme.test", "nope"), 400, "invalid_grant"},
		"blocked user":      {pw("ropg", "ropg-secret", "carol@acme.test", "carol password 1"), 400, "invalid_grant"},
		"missing password":  {pw("ropg", "ropg-secret", "alice@acme.test", ""), 400, "invalid_request"},
		"missing realm":     {realm(""), 400, "invalid_request"},
		"unknown realm":     {realm("Nope"), 400, "invalid_request"},
		"grant not allowed": {pw("code-web", "code-web-secret", "alice@acme.test", "alice password 1"), 403, "unauthorized_client"},
		"bad client secret": {pw("ropg", "wrong", "alice@acme.test", "alice password 1"), 401, "invalid_client"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: tc.form})
			if rec.Code != tc.status || body["error"] != tc.code {
				t.Fatalf("got %d %v; want %d %s", rec.Code, body, tc.status, tc.code)
			}
		})
	}
	// The wording is the same for unknown users and wrong passwords.
	f := newFixture(t)
	_, a := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "nope")})
	_, b := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "nobody@acme.test", "nope")})
	if a["error_description"] != b["error_description"] {
		t.Fatalf("descriptions differ: %v / %v", a, b)
	}
}

func TestPasswordGrantThrottle(t *testing.T) {
	f := newFixture(t)
	for range 3 {
		f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "nope")})
	}
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1")})
	if rec.Code != 429 || body["error"] != "too_many_requests" {
		t.Fatalf("after 3 failures = %d %v", rec.Code, body)
	}
}

// A public client cannot pick its own throttling IP with auth0-forwarded-for.
func TestForwardedForOnlyForConfidentialClients(t *testing.T) {
	f := newFixture(t)
	f.h.IPThrottle = identity.NewThrottle(2, 15*time.Minute, 15*time.Minute)
	for i := range 2 {
		call := tokenCall{host: "acme.example.test", form: pw("ropg-public", "", "nobody@acme.test", "nope"),
			header: map[string]string{"auth0-forwarded-for": fmt.Sprintf("10.0.0.%d", i)}}
		f.call(t, false, call)
	}
	call := tokenCall{host: "acme.example.test", form: pw("ropg-public", "", "alice@acme.test", "alice password 1"),
		header: map[string]string{"auth0-forwarded-for": "10.9.9.9"}}
	if rec, body := f.call(t, false, call); rec.Code != 429 {
		t.Fatalf("public client escaped the IP limit: %d %v", rec.Code, body)
	}
	// A confidential client's auth0-forwarded-for is honoured: a fresh IP is not throttled.
	call = tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1"),
		header: map[string]string{"auth0-forwarded-for": "10.9.9.9"}}
	if rec, body := f.call(t, false, call); rec.Code != 200 {
		t.Fatalf("confidential client with forwarded IP = %d %v", rec.Code, body)
	}
}

// auth0-forwarded-for is used only when it is an IP address; otherwise a
// confidential client could mint a fresh throttle key per request.
func TestForwardedForMustBeAnIP(t *testing.T) {
	f := newFixture(t)
	f.h.IPThrottle = identity.NewThrottle(2, 15*time.Minute, 15*time.Minute)
	for i := range 2 {
		f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "nobody@acme.test", "nope"),
			header: map[string]string{"auth0-forwarded-for": fmt.Sprintf("not-an-ip-%d", i)}})
	}
	call := tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1"),
		header: map[string]string{"auth0-forwarded-for": "not-an-ip-x"}}
	if rec, body := f.call(t, false, call); rec.Code != 429 {
		t.Fatalf("invalid forwarded IPs escaped the IP limit: %d %v", rec.Code, body)
	}
}
