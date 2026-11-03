package mgmt_test

import (
	"context"
	"strings"
	"testing"
)

func TestEnrollmentsObfuscatePhone(t *testing.T) {
	e, uid := mfaUser(t)
	r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "phone", "phone_number": "+14155550100", "preferred_authentication_method": "sms"}, "")
	if r.Code != 201 {
		t.Fatalf("create: %d %s", r.Code, r.Body)
	}
	id := out.(map[string]any)["id"].(string)
	enrollment := strings.Split(id, "|")[1]
	read := func() []string {
		t.Helper()
		var bodies []string
		for _, c := range []struct{ op, uid, id string }{{"GetUserEnrollments", uid, ""}, {"GetAuthenticationMethods", uid, ""}, {"GetAuthenticationMethod", uid, id}, {"GetGuardianEnrollment", enrollment, ""}} {
			r, _ := mfaCall(t, e.clientsEnv, c.op, c.uid, c.id, nil, "")
			if r.Code != 200 {
				t.Fatalf("%s: %d %s", c.op, r.Code, r.Body)
			}
			bodies = append(bodies, r.Body.String())
		}
		return bodies
	}
	// Auth0's documented default (disable_management_api_sms_obfuscation
	// true) returns the number as stored.
	for _, b := range read() {
		if !strings.Contains(b, `"+14155550100"`) {
			t.Fatalf("default should not obfuscate: %s", b)
		}
	}
	tn, err := e.st.Tenants().Get(context.Background(), e.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tn.SettingsExtra == nil {
		tn.SettingsExtra = map[string]any{}
	}
	tn.SettingsExtra["flags"] = map[string]any{"disable_management_api_sms_obfuscation": false}
	if err = e.st.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	e.tn = tn // The fixture resolves tenants manually; refresh for the next request.
	for _, b := range read() {
		if strings.Contains(b, "4155550100") || !strings.Contains(b, `"XXXXXXXX0100"`) {
			t.Fatalf("not obfuscated: %s", b)
		}
	}
}

func TestGuardianPhoneSettingsLogCode(t *testing.T) {
	e := newClientsEnv(t)
	capture := logSetup(e)
	for _, c := range []struct {
		op   string
		body any
	}{
		{"SetGuardianFactorsPhoneMessageTypes", map[string]any{"message_types": []string{"sms", "voice"}}},
		{"SetGuardianFactorsPhoneSelectedProvider", map[string]any{"provider": "twilio"}},
		{"SetGuardianFactorsSmsSelectedProvider", map[string]any{"provider": "auth0"}},
	} {
		if r, _ := mfaCall(t, e, c.op, "", "", c.body, ""); r.Code != 200 {
			t.Fatalf("%s: %d %s", c.op, r.Code, r.Body)
		}
	}
	types := map[string]int{}
	for _, event := range capture.events {
		types[event.Type]++
	}
	if types["gd_phone_settings_update"] != 3 || types["gd_tenant_update"] != 0 {
		t.Fatal(types)
	}
}
