package myaccount

import (
	"context"
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/authmethods"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (e *env) patch(t *testing.T, id string, body any) (int, map[string]any) {
	t.Helper()
	rec, out := e.do(t, e.token(t), "PATCH", "/authentication-methods/"+pathID(id), body)
	return rec.Code, out
}

func (e *env) del(t *testing.T, id string) int {
	t.Helper()
	rec, _ := e.do(t, e.token(t), "DELETE", "/authentication-methods/"+pathID(id), nil)
	return rec.Code
}

func TestPatchName(t *testing.T) {
	e := newEnv(t)
	e.addAuthenticator(t, store.Authenticator{ID: "totp|dev_t", Type: "totp", Confirmed: true})
	pk := passkeyAuthenticator("passkey|dev_p", 1)
	e.addAuthenticator(t, pk)
	for _, id := range []string{"totp|dev_t", "passkey|dev_p"} {
		name := strings.Repeat("ü", 100)
		if code, out := e.patch(t, id, map[string]any{"name": name}); code != 200 || out["name"] != name || out["id"] != id {
			t.Fatalf("%s rename = %d %v", id, code, out)
		}
		if e.method(t, id).Name != name {
			t.Fatalf("%s name not stored", id)
		}
		if code, _ := e.patch(t, id, map[string]any{"name": strings.Repeat("x", 101)}); code != 400 {
			t.Errorf("%s 101 characters = %d", id, code)
		}
	}
	for _, name := range []string{"", "bad\nname"} {
		if code, _ := e.patch(t, "totp|dev_t", map[string]any{"name": name}); code != 400 {
			t.Errorf("name %q = %d", name, code)
		}
	}
	if code, _ := e.patch(t, authmethods.PasswordID("alice1"), map[string]any{"name": "x"}); code != 400 {
		t.Errorf("rename password = %d", code)
	}
	if code, _ := e.patch(t, "totp|dev_missing", map[string]any{"name": "x"}); code != 404 {
		t.Errorf("missing = %d", code)
	}
}

func TestPatchPhonePreference(t *testing.T) {
	e := newEnv(t)
	e.addAuthenticator(t, store.Authenticator{ID: "phone|dev_s", Type: "phone", Confirmed: true, Phone: "+15555550100", PhoneMethod: "sms"})
	e.addAuthenticator(t, store.Authenticator{ID: "totp|dev_t", Type: "totp", Confirmed: true})
	if code, out := e.patch(t, "phone|dev_s", map[string]any{"preferred_authentication_method": "voice"}); code != 200 || out["preferred_authentication_method"] != "voice" {
		t.Fatalf("voice = %d %v", code, out)
	}
	if e.method(t, "phone|dev_s").PhoneMethod != "voice" {
		t.Fatal("not stored")
	}
	if code, _ := e.patch(t, "phone|dev_s", map[string]any{"preferred_authentication_method": "fax"}); code != 400 {
		t.Errorf("fax = %d", code)
	}
	if code, _ := e.patch(t, "totp|dev_t", map[string]any{"preferred_authentication_method": "sms"}); code != 400 {
		t.Errorf("preference on totp = %d", code)
	}
}

func TestPatchUnknownField(t *testing.T) {
	e := newEnv(t)
	e.addAuthenticator(t, store.Authenticator{ID: "totp|dev_t", Type: "totp", Confirmed: true})
	for _, body := range []any{map[string]any{"confirmed": false}, map[string]any{"name": 7}, map[string]any{}} {
		if code, _ := e.patch(t, "totp|dev_t", body); code != 400 {
			t.Errorf("%v = %d", body, code)
		}
	}
}

func TestDeleteMethod(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addAuthenticator(t, store.Authenticator{ID: "totp|dev_t", Type: "totp", Confirmed: true})
	e.addAuthenticator(t, store.Authenticator{ID: "recovery-code|dev_r", Type: "recovery-code", Confirmed: true, CodeHash: "h"})
	for _, id := range []string{"totp|dev_t", "recovery-code|dev_r"} {
		if code := e.del(t, id); code != 204 {
			t.Fatalf("delete %s = %d", id, code)
		}
		mgmt, _ := authmethods.Authenticators(ctx, e.st, e.tn.ID, e.user.UserID)
		if slices.ContainsFunc(mgmt, func(a store.Authenticator) bool { return a.ID == id }) {
			t.Fatalf("%s still listed by the Management API", id)
		}
		_, out := e.do(t, e.token(t), "GET", "/authentication-methods", nil)
		for _, m := range methodList(t, out) {
			if m["id"] == id {
				t.Fatalf("%s still listed", id)
			}
		}
	}
	if code := e.del(t, "totp|dev_t"); code != 404 {
		t.Errorf("second delete = %d", code)
	}
	// Another user's method is not found and stays.
	bob := newUser(t, e.st, e.tn.ID, "auth0|bob1", "bob@acme.test", e.now)
	e.addAuthenticator(t, store.Authenticator{ID: "totp|dev_bob", Type: "totp", Confirmed: true, UserID: bob.UserID})
	if code := e.del(t, "totp|dev_bob"); code != 404 {
		t.Errorf("bob's = %d", code)
	}
	if _, err := e.st.MFA().GetAuthenticator(ctx, e.tn.ID, bob.UserID, "totp|dev_bob"); err != nil {
		t.Fatal(err)
	}
}

func passkeyAuthenticator(id string, n byte) store.Authenticator {
	return store.Authenticator{ID: id, Type: "passkey", Confirmed: true, CredentialID: []byte{n, 7}, PublicKey: []byte{1}, RPID: host,
		PublicData: []byte(`{"identity_user_id":"alice1","user_handle":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`)}
}

// Review Focus 5: the last way to sign in cannot be deleted.
func TestDeleteLastFirstFactor(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	pw := authmethods.PasswordID("alice1")
	if code := e.del(t, pw); code != 409 {
		t.Fatalf("only password = %d", code)
	}
	e.addAuthenticator(t, passkeyAuthenticator("passkey|dev_a", 1))
	// With a passkey, the password may go; then the passkey is the last.
	if code := e.del(t, pw); code != 204 {
		t.Fatalf("password with a passkey = %d", code)
	}
	u, _ := e.st.Users().Get(ctx, e.tn.ID, e.user.UserID)
	if len(authmethods.Passwords(u)) != 0 {
		t.Fatalf("password kept: %+v", u.Identities)
	}
	if code := e.del(t, "passkey|dev_a"); code != 409 {
		t.Fatalf("last passkey = %d", code)
	}
	e.addAuthenticator(t, passkeyAuthenticator("passkey|dev_b", 2))
	if code := e.del(t, "passkey|dev_a"); code != 204 {
		t.Fatalf("one of two passkeys = %d", code)
	}
	if code := e.del(t, "passkey|dev_b"); code != 409 {
		t.Fatalf("remaining passkey = %d", code)
	}
	// Second factors never count: deleting them is always allowed (Y8).
	e.addAuthenticator(t, store.Authenticator{ID: "email|dev_e", Type: "email", Confirmed: true, Email: "alice@acme.test"})
	if code := e.del(t, "email|dev_e"); code != 204 {
		t.Fatalf("second factor = %d", code)
	}
}
