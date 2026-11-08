package mfarules_test

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
)

// Contract omissions must fail before downstream runtime tasks consume them.
func TestMFAInventory(t *testing.T) {
	want := []mfarules.Factor{{Name: "push-notification", Status: "not_planned"}, {Name: "sms", Status: "enforced"}, {Name: "email", Status: "enforced"}, {Name: "duo", Status: "not_planned"}, {Name: "otp", Status: "enforced"}, {Name: "webauthn-roaming", Status: "enforced"}, {Name: "webauthn-platform", Status: "enforced"}, {Name: "recovery-code", Status: "enforced"}}
	if !reflect.DeepEqual(mfarules.Factors(), want) {
		t.Fatalf("factors: %+v", mfarules.Factors())
	}
	paths := map[string][]string{
		"/guardian/factors": {"GET"}, "/guardian/factors/{name}": {"PUT"}, "/guardian/policies": {"GET", "PUT"},
		"/guardian/enrollments/{id}": {"GET", "DELETE"}, "/guardian/enrollments/ticket": {"POST"},
		"/guardian/factors/sms/templates": {"GET", "PUT"}, "/guardian/factors/phone/templates": {"GET", "PUT"},
		"/guardian/factors/sms/providers/twilio": {"GET", "PUT"}, "/guardian/factors/phone/providers/twilio": {"GET", "PUT"},
		"/guardian/factors/sms/selected-provider": {"GET", "PUT"}, "/guardian/factors/phone/selected-provider": {"GET", "PUT"},
		"/guardian/factors/phone/message-types": {"GET", "PUT"}, "/guardian/factors/duo/settings": {"GET", "PUT", "PATCH"},
		"/guardian/factors/push-notification/providers/apns":    {"GET", "PUT", "PATCH"},
		"/guardian/factors/push-notification/providers/fcm":     {"PUT", "PATCH"},
		"/guardian/factors/push-notification/providers/fcmv1":   {"PUT", "PATCH"},
		"/guardian/factors/push-notification/providers/sns":     {"GET", "PUT", "PATCH"},
		"/guardian/factors/push-notification/selected-provider": {"GET", "PUT"},
		"/guardian/settings": {"GET", "PUT"}, "/guardian/factors/phone/settings": {"GET", "PUT"}, "/guardian/factors/email/settings": {"GET", "PUT"},
		"/users/{id}/authentication-methods":                            {"GET", "POST", "PUT", "DELETE"},
		"/users/{id}/authentication-methods/{authentication_method_id}": {"GET", "PATCH", "DELETE"},
		"/users/{id}/enrollments":                                       {"GET"}, "/users/{id}/authenticators": {"DELETE"},
		"/users/{id}/multifactor/{provider}": {"DELETE"}, "/users/{id}/recovery-code-regeneration": {"POST"},
		"/users/{id}/multifactor/actions/invalidate-remember-browser": {"POST"},
		"/mfa/associate": {"POST"}, "/mfa/challenge": {"POST"}, "/mfa/authenticators": {"GET"}, "/mfa/authenticators/{id}": {"DELETE"},
	}
	for path, methods := range paths {
		for _, method := range methods {
			r := mfarules.Route(method + " " + path)
			if r.Path != path || r.Method != method || r.Source == "" || r.Scopes == nil || r.Parameters == nil || r.Body == nil || len(r.Errors) == 0 {
				t.Errorf("incomplete %s %s: %+v", method, path, r)
			}
			if path[1:4] != "mfa" && len(r.Scopes) == 0 {
				t.Errorf("management scope missing: %s", path)
			}
		}
	}
	for _, grant := range []string{"mfa-otp", "mfa-oob", "mfa-recovery-code"} {
		r := mfarules.Route(grant)
		if r.Path != "/oauth/token" || r.Body == nil || r.Errors["invalid_grant"] == "" {
			t.Errorf("missing grant %s", grant)
		}
	}
	if mfarules.MethodIDPattern != `^[a-z-]+\|dev_[A-Za-z0-9]{20}$` || mfarules.EnrollmentIDPattern != `^dev_[A-Za-z0-9]{20}$` {
		t.Fatal("ID formats")
	}
	types := mfarules.MethodTypes()
	if len(types) == 0 {
		t.Fatal("method types missing")
	}
	for _, typ := range types {
		if typ.Type == "totp" && (!typ.Creatable || !slices.Contains(typ.Secret, "totp_secret")) {
			t.Fatal("totp secret not marked write-only")
		}
	}
	screens := map[string][]string{"mfa": {"mfa-begin-enroll-options", "mfa-enroll-result", "mfa-login-options"}, "mfa-otp": {"mfa-otp-enrollment-qr", "mfa-otp-enrollment-code", "mfa-otp-challenge"}, "mfa-email": {"mfa-email-challenge", "mfa-email-list"}, "mfa-recovery-code": {"mfa-recovery-code-enrollment", "mfa-recovery-code-challenge"}}
	if !reflect.DeepEqual(mfarules.Screens(), screens) {
		t.Fatal("prompt contract")
	}
	for _, name := range []string{"api.multifactor.enable", "api.authentication.challengeWith", "api.authentication.challengeWithAny", "api.authentication.enrollWith", "api.authentication.enrollWithAny"} {
		m := mfarules.ActionMember(name)
		if m.Name != name || m.Source == "" || m.Arguments == nil {
			t.Errorf("missing Actions schema %s", name)
		}
	}
	if mfarules.DeployHandlers()["guardianFactorProviders"] != "tool-unsupported" {
		t.Error("guardianFactorProviders must stay tool-unsupported until the pinned CLI stops reading provider.data (D-0059)")
	}
	for _, name := range []string{"guardianFactors", "guardianFactorTemplates", "guardianPolicies", "guardianPhoneFactorSelectedProvider", "guardianPhoneFactorMessageTypes", "guardianPhoneFactorSettings", "guardianEmailFactorSettings", "guardianSettings"} {
		if mfarules.DeployHandlers()[name] != "included" {
			t.Errorf("handler missing: %s", name)
		}
	}
	l := mfarules.Limits
	if l.TOTPDigits != 6 || l.TOTPStepSeconds != 30 || l.TOTPWindow != 1 || l.RecoveryCodeLength != 24 || l.MFATokenSeconds != 600 || l.EmailCodeSeconds != 300 || l.EmailCodeAttempts != 5 || l.EmailCodeDigits != 6 || l.EnrollmentTicketDays != 7 || l.RememberBrowserDays != 30 || l.DeviceWindowDays != 30 || l.FailedAttempts != 10 || l.ThrottleWindowSeconds != 900 || l.EmailSends != 5 || l.EmailResendSeconds != 30 {
		t.Fatalf("incomplete limits %+v", l)
	}
}

func TestPlan33DeferredLogOwners(t *testing.T) {
	for _, c := range logrules.Codes() {
		if (len(c.Type) >= 11 && c.Type[:11] == "gd_send_sms") || (len(c.Type) >= 13 && c.Type[:13] == "gd_send_voice") || c.Type == "gd_phone_settings_update" {
			if c.Plan != 34 || !c.Emitted {
				t.Errorf("phone code owner %+v", c)
			}
		}
		if len(c.Type) >= 10 && c.Type[:10] == "gd_send_pn" {
			if c.Plan != 0 || c.Emitted || c.Note != "not_planned: Guardian push delivery requires Auth0's app." {
				t.Errorf("push code owner %+v", c)
			}
		}
	}
}

func TestPlan33LogCodes(t *testing.T) {
	// Each catalog entry now names its real runtime or administration emitter.
	for _, code := range []string{"gd_start_auth", "gd_auth_succeed", "gd_auth_failed", "gd_start_enroll", "gd_start_enroll_failed", "gd_enrollment_complete", "gd_unenroll", "gd_update_device_account", "gd_recovery_succeed", "gd_recovery_failed", "gd_send_email", "gd_send_email_verification", "gd_auth_email_verification", "gd_otp_rate_limit_exceed", "gd_tenant_update", "gd_email_settings_update", "mfar", "fertft", "feotpft", "feoobft", "fercft"} {
		found := false
		for _, c := range logrules.Codes() {
			if c.Type == code {
				found = true
				owner := 33
				if code == "fertft" {
					owner = 31
				} // Existing refresh-token producer retains its owner.
				if c.Plan != owner || !c.Emitted || c.Status != "emitted" {
					t.Errorf("%s not emitted by Plan %d", code, owner)
				}
				if len(c.Triggers) == 0 {
					t.Errorf("%s has no real emitter provenance", code)
				}
				for _, trigger := range c.Triggers {
					source, err := os.ReadFile(filepath.Join("../..", trigger.File))
					if err != nil {
						t.Errorf("%s emitter: %v", code, err)
						continue
					}
					if trigger.Function == "" || !strings.Contains(string(source), trigger.Function+"(") {
						t.Errorf("%s missing producer %s in %s", code, trigger.Function, trigger.File)
					}
				}
			}
		}
		if !found {
			t.Errorf("missing code %s", code)
		}
	}
}

func TestMFAInventorySemantics(t *testing.T) {
	for _, method := range []string{"GET", "DELETE"} {
		r := mfarules.Route(method + " /guardian/enrollments/{id}")
		if r.Errors["404"] == "" || r.Responses["404"] == nil {
			t.Errorf("%s enrollment missing 404", method)
		}
	}
	if got := mfarules.Route("PUT /guardian/policies").Body["maxItems"]; got != float64(1) {
		t.Errorf("policy maxItems = %v", got)
	}
	for _, method := range []string{"PUT", "PATCH"} {
		r := mfarules.Route(method + " /guardian/factors/push-notification/providers/fcmv1")
		props, ok := r.Body["properties"].(map[string]any)
		if !ok {
			t.Errorf("%s missing properties", method)
			continue
		}
		secret, ok := props["server_credentials"].(map[string]any)
		if !ok || secret["writeOnly"] != true {
			t.Errorf("%s credentials not write-only", method)
		}
	}
	if got := mfarules.Inventory().Discovery["mfa_grants"]; got != "unresolved" {
		t.Errorf("discovery must remain unresolved, got %q", got)
	}
}
