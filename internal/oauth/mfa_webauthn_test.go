package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
	"testing"
)

func TestMFAAPIWebAuthn(t *testing.T) {
	f, _ := mfaFixture(t)
	ctx := context.Background()
	tid, uid := f.tenantID(t, "acme"), f.aliceID(t)
	tok := f.mfaRequired(t)
	for i, typ := range []string{"webauthn-roaming", "webauthn-platform", "passkey", "webauthn-roaming"} {
		a := &store.Authenticator{TenantID: tid, UserID: uid, ID: fmt.Sprintf("%s|%d", typ, i), Type: typ, Name: typ, Confirmed: i != 3, RPID: "acme.example.test", CredentialID: []byte{byte(i + 1)}, PublicKey: []byte{1}}
		if err := f.st.MFA().CreateAuthenticator(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	w, _ := f.mfaAPI(t, "GET", "/mfa/authenticators", tok, "")
	if w.Code != 200 {
		t.Fatal(w.Body)
	}
	var list []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0]["authenticator_type"] == "passkey" {
		t.Fatalf("list %s", w.Body)
	}
	for _, a := range list {
		body := fmt.Sprintf(`{"client_id":"ropg","client_secret":"ropg-secret","mfa_token":%q,"challenge_type":"otp","authenticator_id":%q}`, tok, a["id"])
		w, _ = f.mfaAPI(t, "POST", "/mfa/challenge", "", body)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "unsupported authenticator type") {
			t.Fatalf("challenge %d %s", w.Code, w.Body)
		}
	}
	for _, typ := range []string{"webauthn-roaming", "webauthn-platform"} {
		w, _ = f.mfaAPI(t, "POST", "/mfa/associate", tok, `{"authenticator_types":["`+typ+`"]}`)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "unsupported authenticator type") {
			t.Fatalf("associate %d %s", w.Code, w.Body)
		}
	}
	raw, err := f.h.Minter.AccessToken(ctx, AccessTokenParams{TenantID: tid, Issuer: "https://acme.example.test/", Subject: uid, Audience: []string{"https://acme.example.test/mfa/"}, ClientID: "ropg", Scopes: []string{"remove:authenticators"}})
	if err != nil {
		t.Fatal(err)
	}
	w, _ = f.mfaAPI(t, "DELETE", "/mfa/authenticators/passkey|2", raw, "")
	if w.Code != 404 {
		t.Fatalf("passkey deleted %d %s", w.Code, w.Body)
	}
	for _, a := range list {
		w, _ = f.mfaAPI(t, "DELETE", "/mfa/authenticators/"+a["id"].(string), raw, "")
		if w.Code != 204 {
			t.Fatalf("delete %d %s", w.Code, w.Body)
		}
	}
}
