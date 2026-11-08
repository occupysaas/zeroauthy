package actions_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// First-factor records must survive projection without becoming MFA or exposing
// their private type. MFA comes exclusively from the session's completed proof.
func TestAuthenticationMethodsFromSession(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "session-methods", `exports.onExecutePostLogin=(event,api)=>api.idToken.setCustomClaim('urn:methods',event.authentication.methods);`, nil, false)
	h.bind("t1", trigLogin, a)
	first := time.Date(2026, 11, 7, 9, 10, 11, 123456789, time.FixedZone("offset", -5*60*60))
	mfaAt := time.Date(2026, 11, 7, 14, 11, 12, 987654321, time.UTC)
	method := func(name, timestamp string) map[string]any {
		return map[string]any{"name": name, "timestamp": timestamp}
	}
	tests := []struct {
		name string
		sess *store.LoginSession
		want []any
	}{
		{"no session", nil, []any{}},
		{"legacy without MFA", &store.LoginSession{AuthenticatedAt: first}, []any{}},
		{"legacy with MFA", &store.LoginSession{AuthenticatedAt: first, MFAAt: mfaAt}, []any{method("mfa", "2026-11-07T14:11:12.987654321Z")}},
		{"unrecognized methods", &store.LoginSession{AuthMethods: []store.AuthMethod{{Name: "webauthn", At: first}, {Name: "unknown", At: first}, {Name: "", At: first}, {Name: "mfa", Type: "webauthn-roaming", At: first}}}, []any{}},
		{"MFA timestamp is authoritative", &store.LoginSession{AuthMethods: []store.AuthMethod{{Name: "mfa", At: first}, {Name: "webauthn", At: first}, {Name: "mfa", At: first}}, MFAAt: mfaAt}, []any{method("mfa", "2026-11-07T14:11:12.987654321Z")}},
	}
	for _, name := range []string{"pwd", "passkey", "federated", "email", "sms"} {
		for _, completed := range []bool{false, true} {
			s := &store.LoginSession{AuthMethods: []store.AuthMethod{{Name: name, Type: "private-first-factor", At: first}, {Name: "mfa", Type: "webauthn-platform", At: first}}}
			want := []any{method(name, "2026-11-07T14:10:11.123456789Z")}
			if completed {
				s.MFAAt = mfaAt
				want = append(want, method("mfa", "2026-11-07T14:11:12.987654321Z"))
			}
			tests = append(tests, struct {
				name string
				sess *store.LoginSession
				want []any
			}{fmt.Sprintf("%s/MFA=%t", name, completed), s, want})
		}
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := h.loginInput("t1")
			in.Session = tc.sess
			r, err := h.eng.PostLogin(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if got := r.Effects.IDClaims["urn:methods"]; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("methods=%#v, want %#v", got, tc.want)
			}
		})
	}
}

// Projection must omit pending factors, passkeys and all credential material.
func TestEnrolledFactorsWebAuthn(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for i, typ := range []string{"webauthn-roaming", "webauthn-platform", "passkey"} {
		for _, confirmed := range []bool{false, true} {
			a := &store.Authenticator{TenantID: "t1", UserID: "auth0|u1", ID: fmt.Sprintf("factor-%d-%t", i, confirmed), Type: typ, Confirmed: confirmed,
				RPID: "t1.example.test", CredentialID: []byte(fmt.Sprintf("private-credential-%d-%t", i, confirmed)), PublicKey: []byte("private-key"), PublicData: []byte(`{"user_handle":"private-handle"}`), SealedSecret: []byte("private-secret"), Name: "private nickname"}
			if err := h.st.MFA().CreateAuthenticator(ctx, a); err != nil {
				t.Fatal(err)
			}
		}
	}
	a := h.action("t1", trigLogin, "webauthn-factors", `exports.onExecutePostLogin=(event,api)=>api.idToken.setCustomClaim('urn:factors',event.user.enrolledFactors);`, nil, false)
	h.bind("t1", trigLogin, a)
	r := h.mustPostLogin("t1")
	got, ok := r.Effects.IDClaims["urn:factors"].([]any)
	if !ok || len(got) != 2 {
		t.Fatalf("factors=%#v", r.Effects.IDClaims["urn:factors"])
	}
	want := map[string]bool{"webauthn-roaming": true, "webauthn-platform": true}
	for _, item := range got {
		factor, ok := item.(map[string]any)
		if !ok || len(factor) != 1 || !want[fmt.Sprint(factor["type"])] {
			t.Fatalf("unexpected public factor: %#v", item)
		}
		delete(want, fmt.Sprint(factor["type"]))
	}
	if len(want) != 0 {
		t.Fatalf("missing factors: %v", want)
	}
}

// A real Action's conditional skip must reach the same policy decision used by
// hosted authorization; a password session retains its required OTP challenge.
func TestSkipMFAAfterPasskeyAction(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "skip-passkey-mfa", `exports.onExecutePostLogin=(event,api)=>{if(event.authentication.methods.some(method=>method.name==='passkey'))api.multifactor.enable('none');};`, nil, false)
	h.bind("t1", trigLogin, a)
	for _, name := range []string{"passkey", "pwd"} {
		t.Run(name, func(t *testing.T) {
			in := h.loginInput("t1")
			in.Session = &store.LoginSession{AuthMethods: []store.AuthMethod{{Name: name, At: h.clock()}}}
			r, err := h.eng.PostLogin(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if name == "passkey" && (r.Effects.MFA == nil || r.Effects.MFA.Provider != "none") || name == "pwd" && r.Effects.MFA != nil {
				t.Fatalf("conditional MFA effects=%+v", r.Effects.MFA)
			}
			req, err := mfa.Decide(mfa.DecideInput{Settings: &store.GuardianSettings{Policies: []string{"all-applications"}, Factors: map[string]bool{"otp": true}}, Effects: r.Effects.MFA,
				User: in.User, Authenticators: []store.Authenticator{{Type: "totp", Confirmed: true}}})
			if err != nil || req.Required != (name == "pwd") || req.Enroll || name == "pwd" && !reflect.DeepEqual(req.Factors, []string{"otp"}) {
				t.Fatalf("requirement=%+v err=%v", req, err)
			}
			if !in.Session.MFAAt.IsZero() || len(in.Session.AuthMethods) != 1 || in.Session.AuthMethods[0].Name != name {
				t.Fatalf("Action altered first-factor session: %+v", in.Session)
			}
		})
	}
}

// A continuation must use the current session and newly confirmed factors while
// preserving the challenge effect accumulated before the external redirect.
func TestAuthenticationMethodsFromSessionContinuation(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "passkey-continuation", `exports.onExecutePostLogin=(event,api)=>{
	  api.authentication.challengeWith({type:'webauthn-roaming'});
	  api.redirect.sendUserTo('https://external.test/');
	};exports.onContinuePostLogin=(event,api)=>{
	  api.idToken.setCustomClaim('urn:methods',event.authentication.methods);
	  api.idToken.setCustomClaim('urn:factors',event.user.enrolledFactors);
	};`, nil, false)
	h.bind("t1", trigLogin, a)
	in := h.loginInput("t1")
	in.CanRedirect = true
	in.Tenant.Tenant.SettingsExtra = map[string]any{"customize_mfa_in_postlogin_action": true}
	in.Session = &store.LoginSession{ID: "passkey-continuation", TenantID: "t1", UserID: in.User.UserID, ExpiresAt: h.clock().Add(time.Hour),
		AuthMethods: []store.AuthMethod{{Name: "passkey", At: time.Date(2026, 11, 7, 14, 0, 0, 0, time.UTC)}}}
	r, err := h.eng.PostLogin(context.Background(), in)
	if err != nil || r.Redirect == nil {
		t.Fatalf("redirect=%+v err=%v", r, err)
	}
	ctx := context.Background()
	for _, typ := range []string{"webauthn-roaming", "webauthn-platform", "passkey"} {
		if err := h.st.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "t1", UserID: in.User.UserID, ID: typ, Type: typ, Confirmed: true}); err != nil {
			t.Fatal(err)
		}
	}
	// Supply a distinct live snapshot: reusing the sealed original must fail the
	// MFA timestamp and enrolled-factor assertions below.
	current := *in.Session
	current.MFAAt = time.Date(2026, 11, 7, 14, 1, 0, 0, time.UTC)
	current.AuthMethods = append(append([]store.AuthMethod{}, current.AuthMethods...), store.AuthMethod{Name: "mfa", Type: "webauthn-roaming", At: current.MFAAt})
	r, err = h.eng.ContinuePostLogin(ctx, "t1", r.Redirect.Query["state"], &current, actions.RequestInfo{Hostname: in.Tenant.Host, Origin: in.Tenant.Origin()})
	if err != nil {
		t.Fatal(err)
	}
	wantMethods := []any{map[string]any{"name": "passkey", "timestamp": "2026-11-07T14:00:00Z"}, map[string]any{"name": "mfa", "timestamp": "2026-11-07T14:01:00Z"}}
	wantFactors := []any{map[string]any{"type": "webauthn-platform"}, map[string]any{"type": "webauthn-roaming"}}
	if !reflect.DeepEqual(r.Effects.IDClaims["urn:methods"], wantMethods) || !reflect.DeepEqual(r.Effects.IDClaims["urn:factors"], wantFactors) ||
		r.Effects.MFA == nil || r.Effects.MFA.Mode != "challenge" || !reflect.DeepEqual(r.Effects.MFA.Factors, [][]string{{"webauthn-roaming"}}) {
		t.Fatalf("continuation effects=%+v", r.Effects)
	}
}
