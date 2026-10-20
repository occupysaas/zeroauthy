package mgmt_test

import (
	"context"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	resetTicketURL  = regexp.MustCompile(`^https://login\.acme\.test/u/reset-verify\?ticket=([A-Za-z0-9]{32})#$`)
	verifyTicketURL = regexp.MustCompile(`^https://login\.acme\.test/u/email-verification\?ticket=([A-Za-z0-9]{32})#$`)
)

func (e *usersEnv) passwordTicket(t *testing.T, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.do(t, m2mCaller("create:user_tickets"), "POST", "/api/v2/tickets/password-change", body, e.h.CreatePasswordChangeTicket)
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *usersEnv) verifyTicket(t *testing.T, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.do(t, m2mCaller("create:user_tickets"), "POST", "/api/v2/tickets/email-verification", body, e.h.CreateEmailVerificationTicket)
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *usersEnv) resetTicket(t *testing.T, link string) *store.PasswordResetTicket {
	t.Helper()
	m := resetTicketURL.FindStringSubmatch(link)
	if m == nil {
		t.Fatalf("ticket = %q", link)
	}
	tk, err := e.st.PasswordResetTickets().GetByTokenHash(context.Background(), e.tn.ID, secrets.HashToken(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func (e *usersEnv) verificationTicket(t *testing.T, link string) *store.EmailVerificationTicket {
	t.Helper()
	m := verifyTicketURL.FindStringSubmatch(link)
	if m == nil {
		t.Fatalf("ticket = %q", link)
	}
	tk, err := e.st.EmailVerificationTickets().GetByTokenHash(context.Background(), e.tn.ID, secrets.HashToken(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func wantTicketError(t *testing.T, what string, rec *httptest.ResponseRecorder, out map[string]any, status int, code, message string) {
	t.Helper()
	if rec.Code != status || (code != "" && out["errorCode"] != code) || (message != "" && out["message"] != message) {
		t.Errorf("%s = %d %s, want %d %s %q", what, rec.Code, rec.Body, status, code, message)
	}
}

const ttlMessage = "Payload validation error: 'Value -1 is less than minimum 0' on property ttl_sec (Number of seconds for which the ticket is valid before expiration. If unspecified or set to 0, this value defaults to 432000 seconds (5 days))."

// U6: the password-change ticket's fields, its two body forms and errors.
func TestPasswordChangeTicket(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "alice@x.test"})
	id := u["user_id"].(string)

	rec, out := e.passwordTicket(t, map[string]any{"user_id": id, "result_url": "https://app.test/done", "mark_email_as_verified": true,
		"includeEmailInRedirect": true})
	if rec.Code != 201 || len(out) != 1 {
		t.Fatalf("by user_id = %d %s", rec.Code, rec.Body)
	}
	link := out["ticket"].(string)
	tk := e.resetTicket(t, link)
	if tk.UserID != id || tk.Connection != dbConn || tk.ResultURL != "https://app.test/done" || !tk.MarkEmailVerified || !tk.IncludeEmailInRedirect ||
		tk.ExpiresAt.Sub(tk.CreatedAt) != 432000*time.Second || tk.UsedAt != nil {
		t.Fatalf("ticket = %+v", tk)
	}
	if strings.Contains(e.logs.String(), strings.TrimSuffix(strings.SplitN(link, "ticket=", 2)[1], "#")) {
		t.Fatal("the ticket token was logged")
	}
	if !strings.Contains(e.logs.String(), "create password change ticket") || !strings.Contains(e.logs.String(), "actor=m2m") {
		t.Fatalf("no audit line: %s", e.logs)
	}

	// email + connection_id, with a client and a TTL.
	rec, out = e.passwordTicket(t, map[string]any{"email": "Alice@x.test", "connection_id": e.conn.ID, "ttl_sec": 60, "client_id": "m2m-app"})
	if rec.Code != 404 || out["errorCode"] != "inexistent_client" {
		t.Fatalf("unknown client = %d %s", rec.Code, rec.Body)
	}
	if err := e.st.Clients().Create(context.Background(), &store.Client{TenantID: e.tn.ID, ClientID: "app1", Name: "App", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	rec, out = e.passwordTicket(t, map[string]any{"email": "alice@x.test", "connection_id": e.conn.ID, "ttl_sec": 60, "client_id": "app1"})
	if rec.Code != 201 {
		t.Fatalf("by email = %d %s", rec.Code, rec.Body)
	}
	tk = e.resetTicket(t, out["ticket"].(string))
	if tk.UserID != id || tk.ClientID != "app1" || tk.ExpiresAt.Sub(tk.CreatedAt) != time.Minute || tk.MarkEmailVerified {
		t.Fatalf("ticket = %+v", tk)
	}
	rec, out = e.passwordTicket(t, map[string]any{"user_id": id, "ttl_sec": 0})
	if rec.Code != 201 || e.resetTicket(t, out["ticket"].(string)).ExpiresAt.Sub(e.resetTicket(t, out["ticket"].(string)).CreatedAt) != 432000*time.Second {
		t.Fatalf("ttl_sec 0 = %d %s", rec.Code, rec.Body)
	}

	for _, c := range []struct {
		name          string
		body          any
		status        int
		code, message string
	}{
		{"email alone", map[string]any{"email": "alice@x.test"}, 400, "invalid_body", "Payload validation error: 'Missing required property: connection_id'."},
		{"empty", map[string]any{}, 400, "invalid_body", "Payload validation error: 'Missing required property: email'."},
		{"unknown user", map[string]any{"user_id": "auth0|000000000000000000000000"}, 404, "inexistent_user", "The user does not exist."},
		{"unknown email", map[string]any{"email": "nobody@x.test", "connection_id": e.conn.ID}, 404, "inexistent_user", ""},
		{"result_url with client_id", map[string]any{"user_id": id, "result_url": "https://app.test/", "client_id": "app1"}, 400, "invalid_body",
			"result_url cannot be used together with client_id"},
		{"negative ttl", map[string]any{"user_id": id, "ttl_sec": -1}, 400, "invalid_body", ttlMessage},
		{"unknown property", map[string]any{"user_id": id, "colour": "blue"}, 400, "invalid_body", ""},
		{"wrong type", map[string]any{"user_id": id, "mark_email_as_verified": "yes"}, 400, "invalid_body", ""},
		{"fractional ttl", map[string]any{"user_id": id, "ttl_sec": 1.5}, 400, "invalid_body", ""},
		{"bad result_url", map[string]any{"user_id": id, "result_url": "not a url"}, 400, "invalid_body", ""},
		{"not an object", "[]", 400, "invalid_body", ""},
	} {
		rec, out := e.passwordTicket(t, c.body)
		wantTicketError(t, c.name, rec, out, c.status, c.code, c.message)
	}
}

// U6: the email verification ticket's fields and errors.
func TestEmailVerificationTicket(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "bob@x.test", "verify_email": false})
	id := u["user_id"].(string)
	if err := e.st.Clients().Create(context.Background(), &store.Client{TenantID: e.tn.ID, ClientID: "app1", Name: "App", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}

	rec, out := e.verifyTicket(t, map[string]any{"user_id": id, "result_url": "https://app.test/verified?x=1", "includeEmailInRedirect": true,
		"identity": map[string]any{"user_id": strings.TrimPrefix(id, "auth0|"), "provider": "auth0"}})
	if rec.Code != 201 || len(out) != 1 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	tk := e.verificationTicket(t, out["ticket"].(string))
	if tk.UserID != id || tk.Connection != dbConn || tk.ResultURL != "https://app.test/verified?x=1" || !tk.IncludeEmailInRedirect ||
		tk.ExpiresAt.Sub(tk.CreatedAt) != 432000*time.Second {
		t.Fatalf("ticket = %+v", tk)
	}
	if !strings.Contains(e.logs.String(), "create email verification ticket") {
		t.Fatalf("no audit line: %s", e.logs)
	}
	rec, out = e.verifyTicket(t, map[string]any{"user_id": id, "client_id": "app1", "ttl_sec": 120})
	if rec.Code != 201 {
		t.Fatalf("with client = %d %s", rec.Code, rec.Body)
	}
	if tk := e.verificationTicket(t, out["ticket"].(string)); tk.ClientID != "app1" || tk.ExpiresAt.Sub(tk.CreatedAt) != 2*time.Minute || tk.IncludeEmailInRedirect {
		t.Fatalf("ticket = %+v", tk)
	}

	for _, c := range []struct {
		name          string
		body          any
		status        int
		code, message string
	}{
		{"no user_id", map[string]any{}, 400, "invalid_body", "Payload validation error: 'Missing required property: user_id'."},
		{"unknown user", map[string]any{"user_id": "auth0|000000000000000000000000"}, 404, "inexistent_user", "The user does not exist."},
		{"negative ttl", map[string]any{"user_id": id, "ttl_sec": -1}, 400, "invalid_body", ttlMessage},
		{"unknown property", map[string]any{"user_id": id, "mark_email_as_verified": true}, 400, "invalid_body", ""},
		{"result_url with client_id", map[string]any{"user_id": id, "result_url": "https://app.test/", "client_id": "app1"}, 400, "invalid_body",
			"result_url cannot be used together with client_id"},
		{"bad identity", map[string]any{"user_id": id, "identity": "auth0"}, 400, "invalid_body", ""},
		{"identity of another user", map[string]any{"user_id": id, "identity": map[string]any{"user_id": "nope", "provider": "auth0"}}, 400, "invalid_body", ""},
	} {
		rec, out := e.verifyTicket(t, c.body)
		wantTicketError(t, c.name, rec, out, c.status, c.code, c.message)
	}
}

// An email change drops the user's open verification links, so a link
// sent to the old address cannot verify the new one.
func TestEmailChangeDropsVerificationTickets(t *testing.T) {
	e := newUsersEnv(t)
	id := e.mustCreate(t, map[string]any{"email": "old@x.test", "verify_email": false})["user_id"].(string)
	rec, out := e.verifyTicket(t, map[string]any{"user_id": id})
	if rec.Code != 201 {
		t.Fatalf("ticket = %d %s", rec.Code, rec.Body)
	}
	link := out["ticket"].(string)
	e.verificationTicket(t, link)
	if rec, _ := e.patch(t, id, map[string]any{"email": "new@x.test", "verify_email": false}); rec.Code != 200 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	raw := verifyTicketURL.FindStringSubmatch(link)[1]
	if _, err := e.st.EmailVerificationTickets().GetByTokenHash(context.Background(), e.tn.ID, secrets.HashToken(raw)); err == nil {
		t.Fatal("the verification ticket survived the email change")
	}
}
