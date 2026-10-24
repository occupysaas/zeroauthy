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
	for _, path := range []string{"signup", "change_password"} {
		status, body, _ := e.post(t, "/dbconnections/"+path, "application/json", `{"client_id":"app","connection":"Username-Password-Authentication","email":"new@acme.test","password":"a good password 1","captcha":"invented-proof"}`)
		if status != 401 || body["error"] != "requires_verification" {
			t.Fatal(path, status, body)
		}
	}
}
