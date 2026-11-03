package server

import (
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

func phoneSeed() string {
	return strings.Replace(usersSeed, `"read:connections", "create:connections"`, `"read:phone_providers", "create:phone_providers", "update:phone_providers", "delete:phone_providers", "read:phone_templates", "create:phone_templates", "update:phone_templates", "delete:phone_templates", "read:connections", "create:connections"`, 1)
}

func TestPhoneScopesRegistered(t *testing.T) {
	for _, s := range []string{"read:phone_providers", "create:phone_providers", "update:phone_providers", "delete:phone_providers", "read:phone_templates", "create:phone_templates", "update:phone_templates", "delete:phone_templates"} {
		if !tenantsetup.IsManagementAPIScope(s) {
			t.Fatalf("%s is not a Management API scope", s)
		}
	}
}

// A real M2M caller holding a client grant, and an operator, reach the phone
// routes; revoking the grant takes effect on the next request of the same token.
func TestPhoneRoutesGrantAndLiveRevocation(t *testing.T) {
	h, st := newMgmtEnvSeed(t, phoneSeed(), nil)
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	const base = "https://acme.example.test/api/v2/branding/phone/"
	w, _ := sendJSON(h, "GET", base+"providers", token, nil)
	if w.Code != 200 {
		t.Fatalf("m2m read: %d %s", w.Code, w.Body)
	}
	w, _ = sendJSON(h, "GET", base+"templates", token, nil)
	if w.Code != 200 {
		t.Fatalf("m2m templates: %d %s", w.Code, w.Body)
	}
	// A caller whose grant lacks the phone scopes is refused on every phone route.
	ro := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "usersro", "usersro-s3cret")
	for _, rt := range phoneRoutes {
		if w, _ = sendJSON(h, rt.method, "https://acme.example.test"+rt.path, ro, map[string]any{}); w.Code != 403 {
			t.Fatalf("%s %s without scope: %d", rt.method, rt.path, w.Code)
		}
	}
	op, _ := operatorToken(t, st, "phone-op@example.test")
	if w, _ = sendJSON(h, "GET", base+"providers", op, nil); w.Code != 200 {
		t.Fatalf("operator read: %d %s", w.Code, w.Body)
	}
	w, _ = sendJSON(h, "POST", base+"providers", op, map[string]any{"name": "twilio", "credentials": map[string]any{"auth_token": "t"}, "configuration": map[string]any{"sid": "AC1", "default_from": "+15550001111", "delivery_methods": []string{"text"}}})
	if w.Code != 201 {
		t.Fatalf("operator create: %d %s", w.Code, w.Body)
	}
	tn, _ := st.Tenants().GetByName(t.Context(), "acme")
	g, err := st.ClientGrants().Find(t.Context(), tn.ID, "admin", acmeMgmtAPI, store.SubjectTypeClient)
	if err != nil {
		t.Fatal(err)
	}
	g.Scopes = []string{"read:clients"}
	if err := st.ClientGrants().Update(t.Context(), g); err != nil {
		t.Fatal(err)
	}
	if w, _ = sendJSON(h, "GET", base+"providers", token, nil); w.Code != 403 {
		t.Fatalf("read after revoke: %d %s", w.Code, w.Body)
	}
	if w, _ = sendJSON(h, "POST", base+"templates", token, map[string]any{"type": "otp_verify"}); w.Code != 403 {
		t.Fatalf("write after revoke: %d %s", w.Code, w.Body)
	}
}
