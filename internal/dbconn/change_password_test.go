package dbconn

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
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
		"not enabled":        {`{"client_id":"other","connection":"Username-Password-Authentication","email":"alice@acme.test"}`, false, 400},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.strict = !tc.loose
			if code, body, _ := e.post(t, "/dbconnections/change_password", "application/json", tc.body); code != tc.status || body["error"] != "invalid_request" {
				t.Fatalf("got %d %v", code, body)
			}
			if len(e.mail.sent) != 0 {
				t.Fatalf("sent %d emails", len(e.mail.sent))
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

// An address over the email length cap cannot belong to a user: it gets the
// usual 200 and no email, and never reaches the store (MySQL would reject it).
func TestChangePasswordOverlongEmail(t *testing.T) {
	e := newEnv(t)
	code, _, text := e.post(t, "/dbconnections/change_password", "application/json",
		`{"connection":"Username-Password-Authentication","email":"`+strings.Repeat("e", 300)+`@acme.test"}`)
	if code != 200 || text == "" || len(e.mail.sent) != 0 {
		t.Fatalf("got %d %q, sent %d", code, text, len(e.mail.sent))
	}
}

func TestLegacyChangePassword(t *testing.T) {
	e := newEnv(t)
	var getUserErr error
	e.scripts.Funcs[store.ScriptGetUser] = func(args []any) (any, error) {
		if getUserErr != nil {
			return nil, getUserErr
		}
		if args[0] == "dave@legacy.test" {
			return map[string]any{"user_id": 42, "email": "dave@legacy.test"}, nil
		}
		return nil, nil
	}
	post := func(email string) (int, string) {
		code, _, text := e.post(t, "/dbconnections/change_password", "application/json",
			`{"client_id":"app","connection":"Legacy-DB","email":"`+email+`"}`)
		return code, text
	}
	knownCode, known := post("Dave@legacy.test")
	if knownCode != 200 || len(e.mail.sent) != 1 || e.mail.sent[0].To != "dave@legacy.test" {
		t.Fatalf("known = %d, sent %+v", knownCode, e.mail.sent)
	}
	if u, err := e.st.Users().Get(context.Background(), e.tenantID, "auth0|42"); err != nil || u.Identities[0].PasswordHash != "" {
		t.Fatalf("local user = %+v, %v", u, err)
	}
	if code, text := post("nobody@legacy.test"); code != knownCode || text != known || len(e.mail.sent) != 1 {
		t.Fatalf("unknown = %d %q, sent %d", code, text, len(e.mail.sent))
	}
	getUserErr = customdb.ErrUnavailable
	if code, text := post("dave@legacy.test"); code != knownCode || text != known || len(e.mail.sent) != 1 {
		t.Fatalf("failing get_user = %d %q, sent %d", code, text, len(e.mail.sent))
	}
	if !strings.Contains(e.logs.String(), "custom database script failed") {
		t.Fatalf("failure not logged: %s", e.logs)
	}
	getUserErr = &customdb.ScriptError{Kind: customdb.KindUnauthorized, Message: "no"}
	if code, text := post("dave@legacy.test"); code != knownCode || text != known || len(e.mail.sent) != 1 {
		t.Fatalf("unauthorized get_user = %d %q, sent %d", code, text, len(e.mail.sent))
	}
}
