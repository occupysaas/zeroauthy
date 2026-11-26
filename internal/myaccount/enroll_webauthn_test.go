package myaccount

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/authmethods"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

const origin = "https://" + host

// withWebAuthn adds the passkey service, the client and an MFA service.
func (e *env) withWebAuthn(t *testing.T) {
	t.Helper()
	e.withMFA(t)
	e.h.Passkeys = passkey.NewService(e.st, rpid.Policy{}, func() time.Time { return e.now })
	if err := e.st.Clients().Create(context.Background(), &store.Client{TenantID: e.tn.ID, ClientID: "app", Name: "App", AppType: store.AppTypeSPA, IsFirstParty: true, WebOrigins: []string{"https://app.example.test"}}); err != nil {
		t.Fatal(err)
	}
	e.route = e.h.Routes()
}

func (e *env) enablePasskeys(t *testing.T) {
	t.Helper()
	e.conn.Extra = map[string]any{"authentication_methods": map[string]any{"passkey": map[string]any{"enabled": true}, "password": map[string]any{"enabled": true}}}
	if err := e.st.Connections().Update(context.Background(), e.conn); err != nil {
		t.Fatal(err)
	}
	enableIdentifierFirst(t, e)
}

// creation parses authn_params_public_key into creation options.
func creation(t *testing.T, raw any) webauthn.CreationOptions {
	t.Helper()
	b, _ := json.Marshal(raw)
	var o struct {
		Challenge string
		RP        struct{ ID string }
		User      struct{ ID, Name, DisplayName string }
		Selection struct {
			AuthenticatorAttachment, ResidentKey, UserVerification string
		} `json:"authenticatorSelection"`
	}
	if err := json.Unmarshal(b, &o); err != nil || o.Challenge == "" {
		t.Fatalf("options %s: %v", b, err)
	}
	ch, _ := base64.RawURLEncoding.DecodeString(o.Challenge)
	handle, _ := base64.RawURLEncoding.DecodeString(o.User.ID)
	return webauthn.CreationOptions{Challenge: ch, RPID: o.RP.ID, UserID: handle, UserName: o.User.Name, DisplayName: o.User.DisplayName, Attachment: o.Selection.AuthenticatorAttachment, ResidentKey: o.Selection.ResidentKey, UserVerification: o.Selection.UserVerification}
}

func attest(t *testing.T, a *webauthntest.Authenticator, o webauthn.CreationOptions, from string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(a.Create(o, from), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEnrollPasskey(t *testing.T) {
	e := newEnv(t)
	e.withWebAuthn(t)
	if rec, out := e.start(t, map[string]any{"type": "passkey"}); rec.Code != 400 || out["type"] != "factor_not_enabled" {
		t.Fatalf("passkeys off = %d %v", rec.Code, out)
	}
	e.enablePasskeys(t)
	rec, out := e.start(t, map[string]any{"type": "passkey", "connection": "Username-Password-Authentication", "identity_user_id": "alice1"})
	if rec.Code != 202 || out["id"] != nil {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); !strings.HasSuffix(loc, "/authentication-methods/passkey%7Cnew") {
		t.Errorf("Location %q", loc)
	}
	o := creation(t, out["authn_params_public_key"])
	if o.RPID != host || o.ResidentKey != "required" {
		t.Fatalf("options %+v", o)
	}
	cred := attest(t, webauthntest.New(webauthntest.Options{Transports: []string{"internal"}}), o, origin)
	rec, got := e.verify(t, "passkey|new", map[string]any{"auth_session": out["auth_session"], "authn_response": cred})
	if rec.Code != 201 || got["type"] != "passkey" || got["identity_user_id"] != "alice1" || got["relying_party_id"] != host {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "passkey%7Cdev_") {
		t.Errorf("Location %q", loc)
	}
	if b, _ := json.Marshal(cred); strings.Contains(e.logs.String(), string(b)) || strings.Contains(e.logs.String(), cred["response"].(map[string]any)["attestationObject"].(string)) {
		t.Error("attestation logged")
	}
	// The client's own web origin under the RP ID is accepted too; others are not.
	_, out = e.start(t, map[string]any{"type": "passkey"})
	if rec, _ := e.verify(t, "passkey|new", map[string]any{"auth_session": out["auth_session"], "authn_response": attest(t, webauthntest.New(webauthntest.Options{}), creation(t, out["authn_params_public_key"]), "https://evil.example.test")}); rec.Code != 400 {
		t.Fatalf("foreign origin = %d %s", rec.Code, rec.Body)
	}
	// An identity the user does not have.
	if rec, _ := e.start(t, map[string]any{"type": "passkey", "identity_user_id": "someone-else"}); rec.Code != 400 {
		t.Fatalf("other identity = %d", rec.Code)
	}
	// The per-user limit.
	for i := 0; i < 20; i++ {
		e.addAuthenticator(t, store.Authenticator{ID: fmt.Sprintf("passkey|dev_x%d", i), Type: "passkey", Confirmed: true, CredentialID: []byte{byte(i), 9}, PublicKey: []byte{1}, RPID: "other.test", PublicData: []byte(`{"identity_user_id":"alice1","user_handle":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`)})
	}
	if rec, out := e.start(t, map[string]any{"type": "passkey"}); rec.Code != 409 {
		t.Fatalf("over the limit = %d %v", rec.Code, out)
	}
}

func TestEnrollWebAuthnRoaming(t *testing.T) {
	e := newEnv(t)
	e.withWebAuthn(t)
	e.guardian(t, "webauthn-roaming")
	rec, out := e.start(t, map[string]any{"type": "webauthn-roaming"})
	if rec.Code != 202 || !strings.HasPrefix(fmt.Sprint(out["id"]), "webauthn-roaming|") {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	o := creation(t, out["authn_params_public_key"])
	if o.Attachment != "cross-platform" {
		t.Fatalf("attachment %q", o.Attachment)
	}
	id := out["id"].(string)
	rec, got := e.verify(t, id, map[string]any{"auth_session": out["auth_session"], "authn_response": attest(t, webauthntest.New(webauthntest.Options{Attachment: "cross-platform"}), o, origin)})
	if rec.Code != 201 || got["id"] != id || got["type"] != "webauthn-roaming" || got["confirmed"] != true {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body)
	}
	if a := e.method(t, id); !a.Confirmed || a.RPID != host {
		t.Fatalf("stored %+v", a)
	}
	all, _ := e.st.MFA().ListAuthenticators(context.Background(), e.tn.ID, e.user.UserID)
	for _, a := range all {
		if a.Type == "recovery-code" {
			t.Fatal("hidden recovery code created")
		}
	}
}

func TestEnrollWebAuthnPlatform(t *testing.T) {
	e := newEnv(t)
	e.withWebAuthn(t)
	e.guardian(t, "webauthn-platform", "otp")
	// Platform authenticators need another factor first.
	if rec, _ := e.start(t, map[string]any{"type": "webauthn-platform"}); rec.Code != 400 {
		t.Fatalf("first factor = %d", rec.Code)
	}
	e.addAuthenticator(t, store.Authenticator{ID: "totp|dev_t", Type: "totp", Confirmed: true})
	rec, out := e.start(t, map[string]any{"type": "webauthn-platform"})
	if rec.Code != 202 {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	o := creation(t, out["authn_params_public_key"])
	if o.Attachment != "platform" {
		t.Fatalf("attachment %q", o.Attachment)
	}
	rec, got := e.verify(t, out["id"].(string), map[string]any{"auth_session": out["auth_session"], "authn_response": attest(t, webauthntest.New(webauthntest.Options{Attachment: "platform", UV: true}), o, origin)})
	if rec.Code != 201 || got["type"] != "webauthn-platform" {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body)
	}
}

type breached struct{ password string }

func (b breached) Check(_ context.Context, pw string) (bool, error) { return pw == b.password, nil }

// Review Focus 4: a password change through verify runs the whole policy.
func TestMyAccountPasswordPolicy(t *testing.T) {
	e := newEnv(t)
	e.withMFA(t)
	ctx := context.Background()
	e.conn.PasswordOptions = store.PasswordOptions{
		Complexity: store.PasswordComplexity{MinLength: 12, CharacterTypes: []string{"lowercase", "uppercase", "number"}},
		History:    store.PasswordHistory{Active: true, Size: 3},
		Dictionary: store.PasswordDictionary{Active: true, Default: "en_10k"},
	}
	if err := e.st.Connections().Update(ctx, e.conn); err != nil {
		t.Fatal(err)
	}
	old := "Correct-Horse-1"
	hash, _ := secrets.Hash(old)
	if err := e.st.Users().SetPasswordHash(ctx, e.tn.ID, e.user.UserID, e.conn.Name, hash, e.now); err != nil {
		t.Fatal(err)
	}
	if err := identity.RecordPassword(ctx, e.st, e.conn, e.user.UserID, hash); err != nil {
		t.Fatal(err)
	}
	e.tn.ProtectionSettings.BreachedPassword = store.BreachedPasswordPolicy{Enabled: true, Stage: store.BreachedPasswordStages{PreChangePassword: store.ProtectionShields{Shields: []string{"block"}}}}
	e.tn.ProtectionSettingsInitialized = true
	if err := e.st.Tenants().Update(ctx, e.tn); err != nil {
		t.Fatal(err)
	}
	e.h.Protection = &protection.Service{Store: e.st, BreachChecker: breached{"Breached-Passw0rd"}, Now: func() time.Time { return e.now }}
	if err := e.st.Sessions().Create(ctx, &store.LoginSession{TenantID: e.tn.ID, ID: "sess1", UserID: e.user.UserID, CreatedAt: e.now, ExpiresAt: e.now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	start := func() map[string]any {
		rec, out := e.start(t, map[string]any{"type": "password"})
		if rec.Code != 202 || out["id"] != "password|new" || !strings.HasSuffix(rec.Header().Get("Location"), "/password%7Cnew") {
			t.Fatalf("start = %d %s", rec.Code, rec.Body)
		}
		return out
	}
	out := start()
	pol, _ := out["policy"].(map[string]any)
	cx, _ := pol["complexity"].(map[string]any)
	hist, _ := pol["history"].(map[string]any)
	if cx["min_length"] != float64(12) || hist["active"] != true || hist["size"] != float64(3) || pol["dictionary"].(map[string]any)["active"] != true {
		t.Fatalf("policy %v", pol)
	}
	for _, bad := range []string{"short", old, "Breached-Passw0rd"} {
		out := start()
		rec, p := e.verify(t, "password|new", map[string]any{"auth_session": out["auth_session"], "new_password": bad})
		if rec.Code != 400 || p["validation_errors"] == nil {
			t.Errorf("%q = %d %v", bad, rec.Code, p)
		}
	}
	good := "Fresh-Battery-Staple-9"
	out = start()
	rec, got := e.verify(t, "password|new", map[string]any{"auth_session": out["auth_session"], "new_password": good})
	if rec.Code != 201 || got["id"] != authmethods.PasswordID("alice1") || got["last_password_reset"] == nil {
		t.Fatalf("good = %d %s", rec.Code, rec.Body)
	}
	u, _ := e.st.Users().Get(ctx, e.tn.ID, e.user.UserID)
	if u.Version <= e.user.Version || !verifies(u.Identities[0].PasswordHash, good) {
		t.Fatalf("password not changed: %+v", u.Identities[0])
	}
	if _, err := e.st.Sessions().Get(ctx, e.tn.ID, "sess1"); err != store.ErrNotFound {
		t.Fatalf("session after change: %v", err)
	}
	for _, s := range []string{good, old, "Breached-Passw0rd"} {
		if strings.Contains(e.logs.String(), s) {
			t.Errorf("password %q logged", s)
		}
	}
}

func verifies(hash, pw string) bool { ok, err := secrets.Verify(hash, pw); return ok && err == nil }
