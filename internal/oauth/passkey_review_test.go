package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

// Native first-factor possession cannot erase an enrolled current-RP MFA key
// merely because native MFA cannot challenge WebAuthn factors.
func TestPasskeyMFAConfidenceRP(t *testing.T) {
	for _, tc := range []struct {
		name, typ, rp, fallback string
		unavailable             bool
	}{
		{name: "roaming_owned", typ: "webauthn-roaming", rp: "native.example.test"},
		{name: "platform_owned", typ: "webauthn-platform", rp: "native.example.test"},
		{name: "foreign", typ: "webauthn-roaming", rp: "other.example.test"},
		{name: "recovery", typ: "webauthn-roaming", rp: "native.example.test", fallback: "recovery-code"},
		{name: "otp", typ: "webauthn-roaming", rp: "native.example.test", fallback: "otp"},
		{name: "capability_absent", typ: "webauthn-roaming", rp: "native.example.test", unavailable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := nativeFixture(t)
			device, _ := nativeSignup(t, f)
			ctx := context.Background()
			tid := f.tenantID(t, "acme")
			u, err := f.st.Users().FindByLogin(ctx, tid, "Username-Password-Authentication", "native@acme.test")
			if err != nil {
				t.Fatal(err)
			}
			g, _ := f.st.MFA().GetGuardian(ctx, tid)
			g.Factors = map[string]bool{"otp": true, "recovery-code": tc.fallback == "recovery-code", "webauthn-roaming": true, "webauthn-platform": true}
			g.Policies = []string{"confidence-score"}
			if err = f.st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
				t.Fatal(err)
			}
			f.h.MFA = mfa.NewService(f.st, f.wrapper, &mfaMail{}, nil, f.h.Log, func() time.Time { return f.h.now() })
			var secret, recovery string
			if tc.fallback != "" {
				enrollment, e := f.h.MFA.BeginEnroll(ctx, tid, u.UserID, "otp", "")
				if e != nil {
					t.Fatal(e)
				}
				confirmed, e := f.h.MFA.ConfirmEnroll(ctx, tid, u.UserID, enrollment, mfa.Proof{Code: otpAt(enrollment.Secret, f.h.now())})
				if e != nil {
					t.Fatal(e)
				}
				secret, recovery = enrollment.Secret, confirmed.RecoveryCode
				if tc.fallback == "recovery-code" {
					if err = f.st.MFA().DeleteAuthenticator(ctx, tid, u.UserID, enrollment.AuthenticatorID); err != nil {
						t.Fatal(err)
					}
				}
			}
			key := &store.Authenticator{TenantID: tid, UserID: u.UserID, ID: "owned-mfa", Type: tc.typ, Confirmed: true, RPID: tc.rp, CredentialID: []byte("owned-key"), PublicKey: []byte("stored-key")}
			if err = f.st.MFA().CreateAuthenticator(ctx, key); err != nil {
				t.Fatal(err)
			}
			c, _ := f.st.Clients().Get(ctx, tid, "ropg")
			c.GrantTypes = append(c.GrantTypes, otpGrant, recoveryGrant)
			if err = f.st.Clients().Update(ctx, c); err != nil {
				t.Fatal(err)
			}
			f.h.Now = func() time.Time { return fixedNow().Add(31 * time.Second) }
			form, _ := nativeLogin(t, f, device, "https://native.example.test")
			if tc.unavailable {
				f.h.Store = nativeUnavailable{f.st}
				w, b := f.native(t, "/passkey/challenge", "native.example.test", map[string]any{"client_id": "ropg", "client_secret": "ropg-secret"}, false)
				if w.Code != 404 || b["error"] != "not_found" {
					t.Fatalf("native capability gate %d error=%v", w.Code, b["error"])
				}
			}
			w, b := f.native(t, "/oauth/token", "native.example.test", form, true)
			if tc.unavailable {
				if w.Code != 400 || b["error"] != "invalid_grant" || b["access_token"] != nil {
					t.Fatalf("unavailable native grant %d error=%v", w.Code, b["error"])
				}
				return
			}
			if tc.rp == "other.example.test" {
				if w.Code != 200 {
					t.Fatalf("foreign MFA key affected native login %d error=%v", w.Code, b["error"])
				}
				return
			}
			if tc.fallback == "" {
				if w.Code != 403 || b["error"] != "access_denied" || b["access_token"] != nil {
					t.Fatalf("owned key bypassed confidence MFA %d error=%v", w.Code, b["error"])
				}
				return
			}
			if w.Code != 403 || b["error"] != "mfa_required" || b["access_token"] != nil {
				t.Fatalf("existing alternate required %d error=%v", w.Code, b["error"])
			}
			token := b["mfa_token"].(string)
			tn, _ := f.st.Tenants().Get(ctx, tid)
			_, pending, e := f.h.pendingMFAToken(ctx, tenant.Resolved{Tenant: tn, Host: "native.example.test"}, token, "ropg")
			if e != nil || pending.Requirement.Enroll || len(pending.Requirement.Factors) != 1 || pending.Requirement.Factors[0] != tc.fallback {
				t.Fatalf("existing proof requirement %+v %v", pending, e)
			}
			form = mfaForm(otpGrant, token, "otp", otpAt(secret, f.h.now()))
			if tc.fallback == "recovery-code" {
				form = mfaForm(recoveryGrant, token, "recovery_code", recovery)
			}
			w, b = f.native(t, "/oauth/token", "native.example.test", form, true)
			if w.Code != 200 || b["access_token"] == nil {
				t.Fatalf("alternate proof %d error=%v", w.Code, b["error"])
			}
		})
	}
}

func TestPasskeyFlexibleUsername(t *testing.T) {
	for _, kind := range []string{"required_stored", "required_missing", "existing", "invalid", "inactive"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := nativeFixture(t)
			ctx := context.Background()
			tid := f.tenantID(t, "acme")
			conn, _ := f.st.Connections().GetByName(ctx, tid, "Username-Password-Authentication")
			conn.RequiresUsername = false
			conn.Extra["attributes"] = map[string]any{"username": map[string]any{"identifier": map[string]any{"active": kind != "inactive"}, "signup": map[string]any{"status": "required"}}}
			if err := f.st.Connections().Update(ctx, conn); err != nil {
				t.Fatal(err)
			}
			body := nativeBody()
			profile := body["user_profile"].(map[string]any)
			profile["username"] = " Native_Name "
			if kind == "required_missing" {
				delete(profile, "username")
			}
			if kind == "invalid" {
				profile["username"] = "invalid/name"
			}
			if kind == "existing" {
				u, _ := f.st.Users().Get(ctx, tid, f.aliceID(t))
				u.Username = "native_name"
				if err := f.st.Users().Update(ctx, u); err != nil {
					t.Fatal(err)
				}
			}
			w, b := f.native(t, "/passkey/register", "native.example.test", body, false)
			if kind != "required_stored" {
				if w.Code != 400 || b["error"] != "invalid_request" {
					t.Fatalf("username %s %d error=%v", kind, w.Code, b["error"])
				}
				if kind == "existing" && b["error_description"] != "The user already exists" {
					t.Fatalf("existence not checked %v", b)
				}
				return
			}
			if w.Code != 200 {
				t.Fatalf("username options %d error=%v", w.Code, b["error"])
			}
			device := webauthntest.New(webauthntest.Options{})
			raw := device.Create(nativeOptions(t, b), "https://native.example.test")
			w, b = f.native(t, "/oauth/token", "native.example.test", nativeToken(b["auth_session"].(string), raw), true)
			if w.Code != 200 {
				t.Fatalf("username registration %d error=%v", w.Code, b["error"])
			}
			u, err := f.st.Users().FindByLogin(ctx, tid, conn.Name, "native_name")
			if err != nil || u.Username != "native_name" || u.Email != "native@acme.test" {
				t.Fatalf("flexible username not stored/searchable %+v %v", u, err)
			}
		})
	}
}

func TestPasskeyMetadataStringValues(t *testing.T) {
	for _, form := range []bool{false, true} {
		for _, value := range []any{nil, true, 42, []any{}, map[string]any{}, "", "value"} {
			t.Run(fmt.Sprintf("form_%v/%T_%v", form, value, value), func(t *testing.T) {
				f, _ := nativeFixture(t)
				body := nativeBody()
				body["user_metadata"] = map[string]any{"field": value}
				var request any = body
				if form {
					profile, _ := json.Marshal(body["user_profile"])
					metadata, _ := json.Marshal(body["user_metadata"])
					request = url.Values{"client_id": {"ropg"}, "client_secret": {"ropg-secret"}, "user_profile": {string(profile)}, "user_metadata": {string(metadata)}}
				}
				w, b := f.native(t, "/passkey/register", "native.example.test", request, form)
				if _, ok := value.(string); ok {
					if w.Code != 200 {
						t.Fatalf("valid string refused %d error=%v", w.Code, b["error"])
					}
				} else if w.Code != 400 || b["error"] != "invalid_request" {
					t.Fatalf("non-string metadata accepted %d error=%v", w.Code, b["error"])
				}
			})
		}
	}
}
