package dbconn

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
)

func TestChangePasswordSendsTicket(t *testing.T) {
	e := newEnv(t)
	code, _, text := e.post(t, "/dbconnections/change_password", "application/json",
		`{"client_id":"app","connection":"Username-Password-Authentication","email":"Alice@Acme.test"}`)
	if code != 200 || text == "" || strings.Contains(text, "{") {
		t.Fatalf("got %d %q", code, text)
	}
	if len(e.mail.sent) != 1 || e.mail.sent[0].To != "alice@acme.test" {
		t.Fatalf("sent = %+v", e.mail.sent)
	}
	link := regexp.MustCompile(`https://acme\.example\.test/u/reset-password\?ticket=([A-Za-z0-9]{43})`).FindStringSubmatch(e.mail.sent[0].Text)
	if link == nil {
		t.Fatalf("no reset link in %q", e.mail.sent[0].Text)
	}
	tk, err := e.st.PasswordResetTickets().GetByTokenHash(context.Background(), e.tenantID, secrets.HashToken(link[1]))
	if err != nil || tk.Connection != "Username-Password-Authentication" || tk.ClientID != "app" ||
		!tk.ExpiresAt.Equal(fixedNow().Add(TicketLifetime)) {
		t.Fatalf("ticket = %+v, %v", tk, err)
	}
}

// An unknown address gets the same answer as a known one, so the endpoint
// does not reveal which addresses have accounts (D-0018).
func TestChangePasswordUnknownUserLooksTheSame(t *testing.T) {
	e := newEnv(t)
	knownCode, _, known := e.post(t, "/dbconnections/change_password", "application/json",
		`{"connection":"Username-Password-Authentication","email":"alice@acme.test"}`)
	if len(e.mail.sent) != 1 {
		t.Fatalf("known user: sent %d emails, want 1", len(e.mail.sent))
	}
	unknownCode, _, unknown := e.post(t, "/dbconnections/change_password", "application/json",
		`{"connection":"Username-Password-Authentication","email":"nobody@acme.test"}`)
	if knownCode != 200 || unknownCode != knownCode || unknown != known {
		t.Fatalf("known = %d %q, unknown = %d %q", knownCode, known, unknownCode, unknown)
	}
	if len(e.mail.sent) != 1 {
		t.Fatalf("unknown user: sent %d emails in total, want still 1", len(e.mail.sent))
	}
}

// The endpoint takes an email address; a username does not match.
func TestChangePasswordUsernameSendsNothing(t *testing.T) {
	e := newEnv(t)
	code, _, _ := e.post(t, "/dbconnections/change_password", "application/json",
		`{"connection":"Username-Password-Authentication","email":"alice1"}`)
	if code != 200 || len(e.mail.sent) != 0 {
		t.Fatalf("got %d, sent %d", code, len(e.mail.sent))
	}
}

func TestChangePasswordErrors(t *testing.T) {
	cases := map[string]struct {
		body   string
		loose  bool // the request violates the OpenAPI request schema
		status int
	}{
		"missing email":      {`{"connection":"Username-Password-Authentication"}`, true, 400},
		"missing connection": {`{"email":"alice@acme.test"}`, true, 400},
		"unknown connection": {`{"connection":"Nope","email":"alice@acme.test"}`, false, 400},
		"unknown client":     {`{"client_id":"nope","connection":"Username-Password-Authentication","email":"alice@acme.test"}`, false, 400},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.strict = !tc.loose
			if code, body, _ := e.post(t, "/dbconnections/change_password", "application/json", tc.body); code != tc.status {
				t.Fatalf("got %d %v", code, body)
			}
		})
	}
}

func TestChangePasswordBlockedUserGetsNoEmail(t *testing.T) {
	e := newEnv(t)
	code, _, _ := e.post(t, "/dbconnections/change_password", "application/json",
		`{"connection":"Username-Password-Authentication","email":"carol@acme.test"}`)
	if code != 200 || len(e.mail.sent) != 0 {
		t.Fatalf("got %d, sent %d", code, len(e.mail.sent))
	}
}

func TestChangePasswordSendLimit(t *testing.T) {
	e := newEnv(t)
	e.h.SendThrottle = identity.NewThrottle(2, time.Hour, time.Hour)
	for range 3 {
		e.post(t, "/dbconnections/change_password", "application/json",
			`{"connection":"Username-Password-Authentication","email":"alice@acme.test"}`)
	}
	if len(e.mail.sent) != 2 {
		t.Fatalf("sent %d emails, want 2 (the third is silently skipped)", len(e.mail.sent))
	}
}

func TestChangePasswordIPThrottle(t *testing.T) {
	e := newEnv(t)
	e.h.IPThrottle = identity.NewThrottle(2, time.Hour, time.Hour)
	var code int
	var body map[string]any
	for range 3 {
		code, body, _ = e.post(t, "/dbconnections/change_password", "application/json",
			`{"connection":"Username-Password-Authentication","email":"alice@acme.test"}`)
	}
	if code != 429 || body["error"] != "too_many_requests" || len(e.mail.sent) != 2 {
		t.Fatalf("third request = %d %v, sent %d", code, body, len(e.mail.sent))
	}
}
