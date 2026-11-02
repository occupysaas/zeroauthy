package mgmt_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"strings"
	"testing"
)

func TestGuardianStoredBindingAndPatchPreservesSecret(t *testing.T) {
	e := newClientsEnv(t)
	path := mfarules.Route("SetGuardianFactorsPushNotificationProvidersApns").Path
	r, _ := mfaCall(t, e, "SetGuardianFactorsPushNotificationProvidersApns", "", "", map[string]any{"sandbox": false, "p12": "PRIVATE-APNS-CERTIFICATE"}, "")
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	r, _ = mfaCall(t, e, "UpdateGuardianFactorsPushNotificationProvidersApns", "", "", map[string]any{"sandbox": true}, "")
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	g, _ := e.st.MFA().GetGuardian(context.Background(), e.tn.ID)
	raw, err := keys.OpenBound(e.w, "guardian-provider/v1", []string{e.tn.ID, path}, g.SealedSecrets[path])
	if err != nil {
		t.Fatal(err)
	}
	var secret map[string]any
	if json.Unmarshal(raw, &secret) != nil || secret["p12"] != "PRIVATE-APNS-CERTIFICATE" {
		t.Fatal("patch lost secret")
	}
	for _, binding := range [][]string{{e.sys.ID, path}, {e.tn.ID, "/guardian/factors/push-notification/providers/fcm"}} {
		if _, err = keys.OpenBound(e.w, "guardian-provider/v1", binding, g.SealedSecrets[path]); err == nil {
			t.Fatal("provider envelope accepted wrong binding")
		}
	}
	r, out := mfaCall(t, e, "GetGuardianFactorsPushNotificationProvidersApns", "", "", nil, "")
	if r.Code != 200 || out.(map[string]any)["sandbox"] != true {
		t.Fatal(r.Body)
	}
}
func TestGuardianStoredValidation(t *testing.T) {
	e := newClientsEnv(t)
	for _, tc := range []struct {
		op   string
		body any
	}{{"SetGuardianFactorsEmailSettings", map[string]any{"otp_length": 3, "otp_expiration_time": 300}}, {"SetGuardianFactorsEmailSettings", map[string]any{"otp_length": 6}}, {"SetGuardianFactorsSmsSelectedProvider", map[string]any{"provider": "unknown"}}, {"SetGuardianFactorsPhoneMessageTypes", map[string]any{"message_types": []string{"email"}}}, {"SetGuardianFactorsDuoSettings", map[string]any{"skey": ""}}, {"SetGuardianFactorsPushNotificationProvidersApns", map[string]any{"sandbox": "true"}}, {"SetGuardianFactorsPushNotificationProvidersFcmv1", map[string]any{"server_credentials": 12}}} {
		r, _ := mfaCall(t, e, tc.op, "", "", tc.body, "")
		if r.Code != 400 {
			t.Fatalf("%s: %d %s", tc.op, r.Code, r.Body)
		}
	}
}
func TestAuthMethodsPhonePreferredPreservesReplay(t *testing.T) {
	e, uid := mfaUser(t)
	r, out := mfaCall(t, e.clientsEnv, "SetAuthenticationMethods", uid, "", []any{map[string]any{"type": "phone", "phone_number": "+123456789", "preferred_authentication_method": "sms"}}, "")
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	id := out.([]any)[0].(map[string]any)["id"].(string)
	if err := e.st.MFA().AcceptSignCount(context.Background(), e.tn.ID, uid, id, 3, now); err != nil {
		t.Fatal(err)
	}
	r, out = mfaCall(t, e.clientsEnv, "UpdateAuthenticationMethod", uid, id, map[string]any{"name": "Phone", "preferred_authentication_method": "voice"}, "")
	if r.Code != 200 || out.(map[string]any)["preferred_authentication_method"] != "voice" {
		t.Fatal(r.Body)
	}
	a, _ := e.st.MFA().GetAuthenticator(context.Background(), e.tn.ID, uid, id)
	if a.SignCount != 3 || a.LastAuthAt != now {
		t.Fatal("metadata update erased proof state", a)
	}
}
func TestGuardianAdminAuditCodes(t *testing.T) {
	e := newClientsEnv(t)
	capture := logSetup(e)
	r, _ := mfaCall(t, e, "SetGuardianFactor", "", "otp", map[string]any{"enabled": true}, "")
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	r, _ = mfaCall(t, e, "SetGuardianFactorsEmailSettings", "", "", map[string]any{"otp_length": 6, "otp_expiration_time": 300}, "")
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	types := map[string]int{}
	for _, event := range capture.events {
		types[event.Type]++
	}
	if types["gd_tenant_update"] != 1 || types["gd_email_settings_update"] != 1 || types["sapi"] != 2 {
		t.Fatal(types)
	}
}

func TestAuthMethodsRejectPrivateCOSE(t *testing.T) {
	e, uid := mfaUser(t)
	public, err := base64.RawURLEncoding.DecodeString("pQECAyYgASFYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIlggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	public[0] = 0xa6
	private := append(public, 0x23, 0x58, 0x20)
	private = append(private, make([]byte, 32)...)
	r, _ := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "webauthn-roaming", "key_id": "AQID", "public_key": base64.RawURLEncoding.EncodeToString(private), "relying_party_identifier": "example.test"}, "")
	if r.Code != 400 {
		t.Fatalf("private COSE material accepted: %d", r.Code)
	}
}

func TestGuardianStoredDefaultsMatchSchemas(t *testing.T) {
	e := newClientsEnv(t)
	for _, route := range mfarules.Inventory().Routes {
		if route.Method != "GET" || !strings.HasPrefix(route.Path, "/guardian/") || strings.Contains(route.Path, "{") {
			continue
		}
		t.Run(route.Operation, func(t *testing.T) {
			r, _ := mfaCall(t, e, route.Operation, "", "", nil, "")
			if r.Code != 200 {
				t.Fatal(r.Body)
			}
		})
	}
}
