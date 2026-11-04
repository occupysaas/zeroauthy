package mgmt_test

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// POST /api/v2/users on a passwordless connection creates a password-less
// user identified by email or E.164 phone number; it is never treated as a
// database connection.
func TestCreatePasswordlessUser(t *testing.T) {
	e := newUsersEnv(t)
	for _, c := range []*store.Connection{
		{TenantID: e.tn.ID, ID: "con_email", Name: "email", Strategy: "email", CreatedAt: now},
		{TenantID: e.tn.ID, ID: "con_sms", Name: "sms", Strategy: "sms", CreatedAt: now},
	} {
		if err := e.st.Connections().Create(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	rec, out := e.create(t, map[string]any{"connection": "email", "email": "Ada@Example.test", "email_verified": true})
	if rec.Code != 201 || !strings.HasPrefix(out["user_id"].(string), "email|") || out["email"] != "ada@example.test" || out["email_verified"] != true {
		t.Fatalf("email user = %d %v", rec.Code, out)
	}
	ids := out["identities"].([]any)
	if id := ids[0].(map[string]any); id["provider"] != "email" || id["connection"] != "email" || id["isSocial"] != false {
		t.Fatalf("identity = %v", id)
	}
	if rec, out := e.create(t, map[string]any{"connection": "email", "email": "ada@example.test"}); rec.Code != 409 {
		t.Fatalf("duplicate email = %d %v", rec.Code, out)
	}
	rec, out = e.create(t, map[string]any{"connection": "sms", "phone_number": "+1 415 555 0123", "phone_verified": true})
	if rec.Code != 201 || !strings.HasPrefix(out["user_id"].(string), "sms|") || out["phone_number"] != "+14155550123" || out["phone_verified"] != true {
		t.Fatalf("sms user = %d %v", rec.Code, out)
	}
	if rec, out := e.create(t, map[string]any{"connection": "sms", "phone_number": "+14155550123"}); rec.Code != 409 {
		t.Fatalf("duplicate phone = %d %v", rec.Code, out)
	}
	for name, body := range map[string]map[string]any{
		"password":       {"connection": "email", "email": "b@example.test", "password": "correct horse 1"},
		"missing email":  {"connection": "email"},
		"missing phone":  {"connection": "sms"},
		"invalid phone":  {"connection": "sms", "phone_number": "4155550123"},
		"phone on email": {"connection": "email", "email": "c@example.test", "phone_number": "+14155550199"},
	} {
		if rec, out := e.create(t, body); rec.Code != 400 {
			t.Errorf("%s = %d %v", name, rec.Code, out)
		}
	}
}
