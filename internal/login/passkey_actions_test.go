package login

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The same account has a passkey and an OTP factor. Only the proven first
// factor, rather than enrollment or client input, may trigger the Action skip.
func TestHostedSkipMFAAfterPasskeyAction(t *testing.T) {
	for _, first := range []string{"passkey", "pwd"} {
		t.Run(first, func(t *testing.T) {
			e, u, device, _ := passkeyEnv(t)
			ctx := context.Background()
			wrapper, err := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
			if err != nil {
				t.Fatal(err)
			}
			a := actionstest.NewOffline(t, e.st, wrapper)
			a.PostLogin(t, u.TenantID, "skip-passkey-mfa", `exports.onExecutePostLogin=(event,api)=>{
			  api.user.setAppMetadata('action_first_factor',event.authentication.methods[0].name);
			  if(event.authentication.methods.some(method=>method.name==='passkey'))api.multifactor.enable('none');
			};`)
			e.h.Authz.Actions, e.h.Authz.Wrapper = a.Engine, wrapper
			g, err := e.st.MFA().GetGuardian(ctx, u.TenantID)
			if err != nil {
				t.Fatal(err)
			}
			g.Factors, g.Policies = map[string]bool{"otp": true}, []string{"all-applications"}
			if err := e.st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
				t.Fatal(err)
			}
			if err := e.st.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: u.TenantID, UserID: u.UserID, ID: "otp", Type: "totp", Confirmed: true}); err != nil {
				t.Fatal(err)
			}
			b := e.browser("acme.example.test")
			var result *httptest.ResponseRecorder
			if first == "passkey" {
				form, _ := passkeyForm(t, b, device)
				result = b.do(t, "POST", "/u/login/passkey", form)
			} else {
				_, state, csrf := b.begin(t)
				step := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {u.Email}})
				if step.Code != http.StatusSeeOther || !strings.HasPrefix(step.Header().Get("Location"), "/u/login/password?") {
					t.Fatalf("identifier=%d %s %s", step.Code, step.Header().Get("Location"), step.Body)
				}
				page := b.do(t, "GET", step.Header().Get("Location"), nil)
				csrf = csrfField.FindStringSubmatch(page.Body.String())[1]
				result = b.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "password": {"alice password 1"}, "passkey": {"true"}})
			}
			loc, err := url.Parse(result.Header().Get("Location"))
			if err != nil || result.Code != http.StatusFound {
				t.Fatalf("login=%d %s %s err=%v", result.Code, result.Header().Get("Location"), result.Body, err)
			}
			if first == "passkey" {
				if loc.Host != "app.acme.test" || loc.Query().Get("code") == "" || loc.Query().Get("error") != "" {
					t.Fatalf("Action did not skip MFA: %s", loc)
				}
			} else if loc.Path != "/u/mfa" || loc.Query().Get("state") == "" || loc.Query().Get("code") != "" {
				t.Fatalf("password bypassed MFA: %s", loc)
			}
			cookie := b.cookies[session.CookieName]
			if cookie == nil {
				t.Fatal("missing first-factor session")
			}
			s, err := e.st.Sessions().GetByTokenHash(ctx, u.TenantID, secrets.HashToken(cookie.Value))
			if err != nil || len(s.AuthMethods) != 1 || s.AuthMethods[0].Name != first || !s.MFAAt.IsZero() {
				t.Fatalf("first factor became MFA: %+v err=%v", s, err)
			}
			saved, err := e.st.Users().Get(ctx, u.TenantID, u.UserID)
			if err != nil || saved.AppMetadata["action_first_factor"] != first {
				t.Fatalf("Action did not observe proven first factor: %+v err=%v", saved, err)
			}
		})
	}
}
