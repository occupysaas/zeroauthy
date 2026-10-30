package dbconn

import (
	"context"
	"testing"
)

func TestCaptchaDirectSignupReset(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tn, err := e.st.Tenants().Get(ctx, e.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	tn.ProtectionSettings.Bot.ChallengePasswordPolicy = "always"
	tn.ProtectionSettings.Bot.ChallengePasswordResetPolicy = "always"
	if err := e.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	// Normal supported reset payload remains subject to the challenge policy.
	status, body, _ := e.post(t, "/dbconnections/change_password", "application/json", `{"client_id":"app","connection":"Username-Password-Authentication","email":"new@acme.test"}`)
	if status != 401 || body["error"] != "requires_verification" {
		t.Fatal("valid reset payload", status, body)
	}
	// These hostile inputs deliberately include unsupported proof/password
	// fields. Check the actual response without declaring those fields part of
	// the request contract. An invented CAPTCHA must never satisfy the gate.
	e.strict = false
	for _, path := range []string{"signup", "change_password"} {
		status, body, _ := e.post(t, "/dbconnections/"+path, "application/json", `{"client_id":"app","connection":"Username-Password-Authentication","email":"new@acme.test","password":"a good password 1","captcha":"invented-proof"}`)
		if status != 401 || body["error"] != "requires_verification" {
			t.Fatal(path, status, body)
		}
	}
}
