package ui

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginIDPasskeyMarkup(t *testing.T) {
	w := httptest.NewRecorder()
	RenderLoginIdentifier(w, 200, Tenant{Name: "Tenant"}, LoginStageData{LoginData: LoginData{State: "state", CSRF: "csrf"}, Passkey: &WebAuthnData{ChallengeID: "</script><script>bad()</script>", PublicKey: json.RawMessage(`{"challenge":"AQID","allowCredentials":[]}`), Mediation: "both"}})
	body := w.Body.String()
	checkNonce(t, w.Header().Get("Content-Security-Policy"), body)
	if strings.Contains(body, "<script>bad()") || !strings.Contains(body, `autocomplete="username webauthn"`) || !strings.Contains(body, "Sign in with a passkey") {
		t.Fatalf("unsafe or missing markup: %s", body)
	}
	if strings.Contains(body, "fetch(") {
		t.Fatal("script must use a normal form post")
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'nonce-") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP relaxed %s", csp)
	}
}
