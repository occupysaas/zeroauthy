package mgmt_test

import (
	"context"
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/zeroauthy/zeroauthy/api"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func mfaCall(t *testing.T, e *clientsEnv, op, uid, id string, body any, query string) (*httptest.ResponseRecorder, any) {
	t.Helper()
	c := mfarules.Route(op)
	path := strings.ReplaceAll(strings.ReplaceAll(c.Path, "{id}", uid), "{authentication_method_id}", id)
	path = strings.ReplaceAll(path, "{name}", id)
	path = strings.ReplaceAll(path, "{provider}", id)
	rec, out := e.call(t, e.tn, m2mCaller(c.Scopes...), c.Method, "/api/v2"+path+query, body, func(w http.ResponseWriter, r *http.Request) { e.h.MFAOperation(w, r, op, uid, id) })
	if rec.Code >= 200 && rec.Code < 300 && rec.Code != 204 {
		assertMFASchema(t, op, rec.Code, out)
	}
	return rec, out
}
func TestGuardianFactorsListAndPut(t *testing.T) {
	e := newClientsEnv(t)
	r, out := mfaCall(t, e, "GetGuardianFactors", "", "", nil, "")
	if r.Code != 200 || len(out.([]any)) != 8 {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	for i, f := range mfarules.Factors() {
		if out.([]any)[i].(map[string]any)["name"] != f.Name {
			t.Fatal(out)
		}
	}
	for _, name := range []string{"duo", "push-notification"} {
		r, out = mfaCall(t, e, "SetGuardianFactor", "", name, map[string]any{"enabled": true}, "")
		if r.Code != 200 || out.(map[string]any)["enabled"] != true {
			t.Fatalf("%d %s", r.Code, r.Body)
		}
	}
}
func TestGuardianPoliciesValidation(t *testing.T) {
	e := newClientsEnv(t)
	for _, b := range []any{[]string{"all-applications", "confidence-score"}, []string{"unknown"}, nil} {
		r, _ := mfaCall(t, e, "SetGuardianPolicies", "", "", b, "")
		if r.Code != 400 {
			t.Fatalf("%d %s", r.Code, r.Body)
		}
	}
	r, _ := mfaCall(t, e, "SetGuardianPolicies", "", "", []string{"all-applications"}, "")
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
}
func TestGuardianStoredRoutesSecretsWriteOnly(t *testing.T) {
	e := newClientsEnv(t)
	for _, tc := range []struct{ op, key string }{{"SetGuardianFactorsSmsProvidersTwilio", "auth_token"}, {"SetGuardianFactorsPhoneProvidersTwilio", "auth_token"}, {"SetGuardianFactorsPushNotificationProvidersApns", "p12"}, {"SetGuardianFactorsPushNotificationProvidersFcm", "server_key"}, {"SetGuardianFactorsPushNotificationProvidersFcmv1", "server_credentials"}, {"SetGuardianFactorsPushNotificationProvidersSns", "aws_secret_access_key"}, {"SetGuardianFactorsDuoSettings", "skey"}} {
		t.Run(tc.op, func(t *testing.T) {
			r, _ := mfaCall(t, e, tc.op, "", "", map[string]any{tc.key: "PRIVATE-MFA-CREDENTIAL"}, "")
			if r.Code != 200 || strings.Contains(r.Body.String(), "PRIVATE") {
				t.Fatalf("%d %s", r.Code, r.Body)
			}
			g, _ := e.st.MFA().GetGuardian(context.Background(), e.tn.ID)
			path := mfarules.Route(tc.op).Path
			if strings.Contains(string(g.Stored[path]), "PRIVATE") || len(g.SealedSecrets[path]) == 0 {
				t.Fatal("provider secret not sealed")
			}
		})
	}
}
func mfaUser(t *testing.T) (*usersEnv, string) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "mfa@example.test", "email_verified": true})
	return e, u["user_id"].(string)
}
func TestAuthMethodsCRUD(t *testing.T) {
	e, uid := mfaUser(t)
	for _, b := range []any{map[string]any{"type": "totp", "totp_secret": "JBSWY3DPEHPK3PXP"}, map[string]any{"type": "email", "email": "mfa@example.test"}, map[string]any{"type": "webauthn-roaming", "key_id": "AQID", "public_key": "pQECAyYgASFYILcoes0rNGrjTOXVEqXyq9CPe41x3PDQohuYsMQiLmHyIlggt4P6gUXrCQdKoWIfVcnC3BXZGdtI1ZqT9O7H8fsUcrA", "relying_party_identifier": "example.test"}} {
		r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", b, "")
		if r.Code != 201 {
			t.Fatalf("create: %d %s", r.Code, r.Body)
		}
		id := out.(map[string]any)["id"].(string)
		r, _ = mfaCall(t, e.clientsEnv, "UpdateAuthenticationMethod", uid, id, map[string]any{"name": "New name"}, "")
		if r.Code != 200 {
			t.Fatal(r.Body)
		}
	}
	r, out := mfaCall(t, e.clientsEnv, "GetAuthenticationMethods", uid, "", nil, "?page=1&per_page=2&include_totals=true")
	if r.Code != 200 || out.(map[string]any)["total"] != float64(3) || len(out.(map[string]any)["authenticators"].([]any)) != 1 {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	r, _ = mfaCall(t, e.clientsEnv, "SetAuthenticationMethods", uid, "", []any{map[string]any{"type": "email", "email": "new@example.test"}}, "")
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	r, _ = mfaCall(t, e.clientsEnv, "DeleteAuthenticationMethods", uid, "", nil, "")
	if r.Code != 204 {
		t.Fatal(r.Body)
	}
}
func TestAuthMethodsTOTPSecretWriteOnly(t *testing.T) {
	e, uid := mfaUser(t)
	r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "totp", "totp_secret": "JBSWY3DPEHPK3PXP"}, "")
	if r.Code != 201 || strings.Contains(r.Body.String(), "JBSW") {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	a, err := e.st.MFA().GetAuthenticator(context.Background(), e.tn.ID, uid, out.(map[string]any)["id"].(string))
	if err != nil || len(a.SealedSecret) == 0 || !a.Confirmed {
		t.Fatal(a, err)
	}
}
func TestAuthMethodsCrossTenant404(t *testing.T) {
	e, uid := mfaUser(t)
	e.tn = e.sys
	r, _ := mfaCall(t, e.clientsEnv, "GetAuthenticationMethods", uid, "", nil, "")
	if r.Code != 404 {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
}
func TestRecoveryCodeRegeneration(t *testing.T) {
	e, uid := mfaUser(t)
	mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "email", "email": "mfa@example.test"}, "")
	var previous string
	for range 2 {
		r, out := mfaCall(t, e.clientsEnv, "CreateUserRecoveryCode", uid, "", nil, "")
		if r.Code != 200 {
			t.Fatal(r.Body)
		}
		code := out.(map[string]any)["recovery_code"].(string)
		if len(code) != 24 || code == previous {
			t.Fatal(code)
		}
		previous = code
		all, _ := e.st.MFA().ListAuthenticators(context.Background(), e.tn.ID, uid)
		hash := ""
		for _, a := range all {
			if a.Type == "recovery-code" {
				hash = a.CodeHash
			}
		}
		if len(all) != 2 || hash != secrets.HashToken(code) {
			t.Fatal(all)
		}
	}
}
func TestInvalidateRememberBrowser(t *testing.T) {
	e, uid := mfaUser(t)
	r, _ := mfaCall(t, e.clientsEnv, "CreateUserRememberBrowser", uid, "", nil, "")
	u, _ := e.st.Users().Get(context.Background(), e.tn.ID, uid)
	if r.Code != 204 || u.RememberBrowserEpoch != 1 {
		t.Fatalf("%d %+v", r.Code, u)
	}
}
func TestDeleteMultifactorProvider(t *testing.T) {
	e, uid := mfaUser(t)
	mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "totp", "totp_secret": "JBSWY3DPEHPK3PXP"}, "")
	r, _ := mfaCall(t, e.clientsEnv, "DeleteUserMultifactor", uid, "google-authenticator", nil, "")
	a, _ := e.st.MFA().ListAuthenticators(context.Background(), e.tn.ID, uid)
	if r.Code != 204 || len(a) != 0 {
		t.Fatal(r.Code, a)
	}
}
func TestDeleteAuthenticators(t *testing.T) {
	e, uid := mfaUser(t)
	mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "email", "email": "mfa@example.test"}, "")
	mfaCall(t, e.clientsEnv, "CreateUserRecoveryCode", uid, "", nil, "")
	r, _ := mfaCall(t, e.clientsEnv, "DeleteUserAuthenticators", uid, "", nil, "")
	a, _ := e.st.MFA().ListAuthenticators(context.Background(), e.tn.ID, uid)
	if r.Code != 204 || len(a) != 0 {
		t.Fatal(r.Code, a)
	}
}
func TestUserMultifactorField(t *testing.T) {
	e, uid := mfaUser(t)
	mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "email", "email": "mfa@example.test"}, "")
	r, u := e.get(t, uid, "")
	if r.Code != 200 || len(u["multifactor"].([]any)) != 1 {
		t.Fatal(r.Body)
	}
}
func TestEnrollmentGetDelete(t *testing.T) {
	e, uid := mfaUser(t)
	_, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "email", "email": "mfa@example.test"}, "")
	id := strings.Split(out.(map[string]any)["id"].(string), "|")[1]
	r, _ := mfaCall(t, e.clientsEnv, "GetGuardianEnrollment", id, "", nil, "")
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	r, _ = mfaCall(t, e.clientsEnv, "DeleteGuardianEnrollment", id, "", nil, "")
	if r.Code != 204 {
		t.Fatal(r.Body)
	}
}
func TestEnrollmentTicket(t *testing.T) {
	e, uid := mfaUser(t)
	r, out := mfaCall(t, e.clientsEnv, "CreateGuardianEnrollmentTicket", "", "", map[string]any{"user_id": uid, "factor": "otp", "allow_multiple_enrollments": true}, "")
	if r.Code != 200 || !strings.Contains(out.(map[string]any)["ticket_url"].(string), "/u/mfa-enroll-ticket?ticket=") {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
}

type noMFA struct{ store.Store }

func (noMFA) MFA() store.MFA { return store.UnimplementedMFA{} }
func TestMFAUnavailable501(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Store = noMFA{e.st}
	r, _ := mfaCall(t, e, "GetGuardianFactors", "", "", nil, "")
	if r.Code != 501 || !strings.Contains(r.Body.String(), "mfa_unavailable") {
		t.Fatal(r.Body)
	}
	r, out := mfaCall(t, e, "GetGuardianPolicies", "", "", nil, "")
	if r.Code != 200 || len(out.([]any)) != 0 {
		t.Fatal(r.Body)
	}
}

func TestAuthMethodsValidationAndAtomicReplace(t *testing.T) {
	e, uid := mfaUser(t)
	r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "totp", "totp_secret": "JBSWY3DPEHPK3PXP"}, "")
	if r.Code != 201 {
		t.Fatal(r.Body)
	}
	id := out.(map[string]any)["id"].(string)
	for _, b := range []any{map[string]any{"type": "webauthn-roaming", "key_id": "AQID", "public_key": "AQID", "relying_party_identifier": "example.test"}, map[string]any{"type": "webauthn-roaming", "key_id": "AQID", "public_key": "pQECAyYgASFYILcoes0rNGrjTOXVEqXyq9CPe41x3PDQohuYsMQiLmHyIlggt4P6gUXrCQdKoWIfVcnC3BXZGdtI1ZqT9O7H8fsUcrA", "relying_party_identifier": "https://evil.test/path"}} {
		r, _ = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", b, "")
		if r.Code != 400 {
			t.Fatalf("invalid key/RP accepted: %d %s", r.Code, r.Body)
		}
	}
	r, _ = mfaCall(t, e.clientsEnv, "SetAuthenticationMethods", uid, "", []any{map[string]any{"type": "email", "email": "valid@example.test"}, map[string]any{"type": "totp", "totp_secret": "INVALID!"}}, "")
	if r.Code != 400 {
		t.Fatal(r.Body)
	}
	a, err := e.st.MFA().GetAuthenticator(context.Background(), e.tn.ID, uid, id)
	if err != nil || a == nil {
		t.Fatal("failed replacement removed existing method")
	}
}
func TestAuthMethodsPublicMetadataRoundTrip(t *testing.T) {
	e, uid := mfaUser(t)
	r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "webauthn-roaming", "key_id": "AQID", "public_key": "pQECAyYgASFYILcoes0rNGrjTOXVEqXyq9CPe41x3PDQohuYsMQiLmHyIlggt4P6gUXrCQdKoWIfVcnC3BXZGdtI1ZqT9O7H8fsUcrA", "relying_party_identifier": "example.test", "aaguid": "00000000-0000-0000-0000-000000000001", "credential_device_type": "multi_device", "credential_backed_up": true, "transports": []string{"usb"}}, "")
	if r.Code != 201 || out.(map[string]any)["credential_backed_up"] != true {
		t.Fatalf("metadata did not round trip: %d %s", r.Code, r.Body)
	}
}

type mfaReadError struct{ store.MFA }

func (mfaReadError) ListAuthenticators(context.Context, string, string) ([]store.Authenticator, error) {
	return nil, store.ErrInvalid
}

type mfaReadErrorStore struct{ store.Store }

func (s mfaReadErrorStore) MFA() store.MFA { return mfaReadError{s.Store.MFA()} }
func TestUserMultifactorReadFailure(t *testing.T) {
	e, uid := mfaUser(t)
	e.h.Store = mfaReadErrorStore{e.st}
	r, _ := e.get(t, uid, "")
	if r.Code != 500 {
		t.Fatalf("MFA store failure silently rendered empty enrollment: %d", r.Code)
	}
}

var mfaSpecOnce sync.Once
var mfaSpec *openapi3.T
var mfaSpecErr error

func assertMFASchema(t *testing.T, op string, status int, out any) {
	t.Helper()
	mfaSpecOnce.Do(func() { mfaSpec, mfaSpecErr = openapi3.NewLoader().LoadFromData(api.ManagementYAML) })
	if mfaSpecErr != nil {
		t.Fatal(mfaSpecErr)
	}
	route := mfarules.Route(op)
	resp := route.Responses[fmt.Sprint(status)].(map[string]any)
	content := resp["content"].(map[string]any)["application/json"].(map[string]any)
	ref := content["schema"].(map[string]any)["$ref"].(string)
	name := strings.TrimPrefix(ref, "#/components/schemas/")
	if err := mfaSpec.Components.Schemas[name].Value.VisitJSON(out, openapi3.VisitAsResponse()); err != nil {
		t.Fatalf("%s response violates frozen schema: %v", op, err)
	}
}
func TestDeleteAuthenticatorsInvalidatesRememberBrowser(t *testing.T) {
	e, uid := mfaUser(t)
	mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "email", "email": "mfa@example.test"}, "")
	r, _ := mfaCall(t, e.clientsEnv, "DeleteUserAuthenticators", uid, "", nil, "")
	u, _ := e.st.Users().Get(context.Background(), e.tn.ID, uid)
	if r.Code != 204 || u.RememberBrowserEpoch != 1 {
		t.Fatalf("deletion retained remembered MFA: %d epoch%d", r.Code, u.RememberBrowserEpoch)
	}
}
func TestUserMultifactorLinkingKeepsPrimaryMethods(t *testing.T) {
	e, primary := mfaUser(t)
	secondary := e.mustCreate(t, map[string]any{"email": "secondary-mfa@example.test"})["user_id"].(string)
	for _, uid := range []string{primary, secondary} {
		r, _ := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "email", "email": "factor@example.test"}, "")
		if r.Code != 201 {
			t.Fatal(r.Body)
		}
	}
	before, err := e.st.MFA().ListAuthenticators(context.Background(), e.tn.ID, primary)
	if err != nil {
		t.Fatal(err)
	}
	e.mustLink(t, primary, secondary)
	after, err := e.st.MFA().ListAuthenticators(context.Background(), e.tn.ID, primary)
	if err != nil || len(after) != 1 || after[0].ID != before[0].ID {
		t.Fatal("primary methods changed", after, err)
	}
	other, err := e.st.MFA().ListAuthenticators(context.Background(), e.tn.ID, secondary)
	if err != nil || len(other) != 0 {
		t.Fatal("secondary factors survived linking", other, err)
	}
}

func TestAuthMethodsZeroPageSize(t *testing.T) {
	e, uid := mfaUser(t)
	r, _ := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "email", "email": "mfa@example.test"}, "")
	if r.Code != 201 {
		t.Fatal(r.Body)
	}
	for _, totals := range []bool{false, true} {
		r, out := mfaCall(t, e.clientsEnv, "GetAuthenticationMethods", uid, "", nil, fmt.Sprintf("?page=2&per_page=0&include_totals=%t", totals))
		if r.Code != 200 {
			t.Fatalf("zero page size rejected: %d %s", r.Code, r.Body)
		}
		if totals {
			m := out.(map[string]any)
			if m["limit"] != float64(0) || m["start"] != float64(0) || m["total"] != float64(1) || len(m["authenticators"].([]any)) != 0 {
				t.Fatal(m)
			}
		} else if len(out.([]any)) != 0 {
			t.Fatal(out)
		}
	}
}
