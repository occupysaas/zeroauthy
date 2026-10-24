package oauth

import (
	"context"
	"testing"
)

func TestCaptchaDirectPassword(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tn, err := f.st.Tenants().Get(ctx, f.tenantID(t, "acme"))
	if err != nil {
		t.Fatal(err)
	}
	tn.ProtectionSettings.Bot.ChallengePasswordPolicy = "always"
	if err := f.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	form := pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1")
	form.Set("captcha", "invented-proof")
	status, body := f.pwCall(t, form)
	if status != 401 || body["error"] != "requires_verification" || body["access_token"] != nil {
		t.Fatal(status, body)
	}
}
