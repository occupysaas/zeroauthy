package oauth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Auth0 answers a wrong password and an unusable refresh token with 403
// invalid_grant and fixed descriptions (D-0061):
//   - docs/compat/observations/organizations.md §6 (password-realm, wrong
//     password: 403 invalid_grant) and management-jobs.md J6
//     ("Wrong email or password.");
//   - docs/compat/observations/management-users.md U8 ("Unknown or invalid
//     refresh token.") and
//     https://support.auth0.com/center/s/article/troubleshoot-refresh-token-unknown-or-invalid-before-expiry-403-unknown-or-invalid-refresh-token
//     (HTTP 403).
func TestInvalidGrantAuth0Shape(t *testing.T) {
	t.Run("password", func(t *testing.T) {
		realm := pw("ropg", "ropg-secret", "alice@acme.test", "nope")
		realm.Set("grant_type", GrantPasswordRealm)
		realm.Set("realm", "Username-Password-Authentication")
		for name, form := range map[string]map[string][]string{
			"password wrong password":       pw("ropg", "ropg-secret", "alice@acme.test", "nope"),
			"password unknown user":         pw("ropg", "ropg-secret", "nobody@acme.test", "nope"),
			"password-realm wrong password": realm,
		} {
			t.Run(name, func(t *testing.T) {
				f := newFixture(t)
				rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form})
				if rec.Code != 403 || body["error"] != "invalid_grant" || body["error_description"] != "Wrong email or password." {
					t.Fatalf("got %d %v; want 403 invalid_grant \"Wrong email or password.\"", rec.Code, body)
				}
			})
		}
	})

	ctx := context.Background()
	for name, prepare := range map[string]func(f *fixture, raw string, rt *store.RefreshToken) string{
		"unknown": func(*fixture, string, *store.RefreshToken) string { return "not-a-real-token" },
		"revoked": func(f *fixture, raw string, rt *store.RefreshToken) string {
			_ = f.st.RefreshTokens().RevokeFamily(ctx, rt.TenantID, rt.FamilyID, fixedNow())
			return raw
		},
		"expired": func(f *fixture, raw string, rt *store.RefreshToken) string {
			f.h.Now = func() time.Time { return rt.ExpiresAt }
			return raw
		},
		"reused": func(f *fixture, raw string, _ *store.RefreshToken) string {
			if code, body := f.refresh(t, refreshForm("rt-spa", raw)); code != 200 {
				t.Fatalf("rotate = %d %v", code, body)
			}
			return raw
		},
	} {
		// OIDC conformance (OIDCC-3.1.3.4, oidcc-refresh-token) requires 400,
		// so that is the default; compatibility.auth0_refresh_error_status
		// opts into Auth0's 403. The description is Auth0's either way.
		for _, auth0Status := range []bool{false, true} {
			want := 400
			if auth0Status {
				want = 403
			}
			t.Run(fmt.Sprintf("refresh %s status %d", name, want), func(t *testing.T) {
				f := newFixture(t)
				f.h.Auth0RefreshErrorStatus = auth0Status
				raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access", "read:things"}, acmeAPI)
				code, body := f.refresh(t, refreshForm("rt-spa", prepare(f, raw, rt)))
				if code != want || body["error"] != "invalid_grant" || body["error_description"] != "Unknown or invalid refresh token." {
					t.Fatalf("got %d %v; want %d invalid_grant \"Unknown or invalid refresh token.\"", code, body, want)
				}
			})
		}
	}
}
