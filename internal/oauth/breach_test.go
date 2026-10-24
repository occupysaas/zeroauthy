package oauth

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/passhash/passhashtest"
	"github.com/zeroauthy/zeroauthy/internal/protection"
)

type breachStub struct {
	calls int
	err   error
}

func (c *breachStub) Check(context.Context, string) (bool, error) { c.calls++; return true, c.err }

// These status/code assertions are local A5 fallbacks, not observed Auth0 parity.
func TestBreachImportedLogin(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		f := newFixture(t)
		u := f.setImportedHash(t, passhashtest.PBKDF2("imported pw 12"))
		ctx := context.Background()
		tn, _ := f.st.Tenants().Get(ctx, u.TenantID)
		tn.ProtectionSettings.BreachedPassword.Enabled = true
		tn.ProtectionSettings.BreachedPassword.Shields = []string{"block"}
		f.st.Tenants().Update(ctx, tn)
		c := &breachStub{}
		want := 401
		wantCode := "password_leaked"
		if unavailable {
			c.err = protection.ErrBreachUnavailable
			want = 503
			wantCode = "temporarily_unavailable"
		}
		f.h.Protection = &protection.Service{Store: f.st, BreachChecker: c}
		if code, _ := f.pwCall(t, pw("ropg", "ropg-secret", "alice@acme.test", "wrong")); code != 400 || c.calls != 0 {
			t.Fatal("unproved password checked", code, c.calls)
		}
		code, body := f.pwCall(t, pw("ropg", "ropg-secret", "alice@acme.test", "imported pw 12"))
		if code != want || body["error"] != wantCode || body["access_token"] != nil || body["refresh_token"] != nil || c.calls != 1 {
			t.Fatal(code, body, c.calls)
		}
		upgraded, err := f.st.Users().Get(ctx, u.TenantID, u.UserID)
		if err != nil || upgraded.Identities[0].ImportedHash != "" || !strings.HasPrefix(upgraded.Identities[0].PasswordHash, "$argon2id$") {
			t.Fatal("verified imported hash upgrade lost", err)
		}
	}
}
