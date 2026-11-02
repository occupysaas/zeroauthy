package ui

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMFAScreens(t *testing.T) {
	for _, page := range []string{"mfa_options", "mfa_enroll_options", "mfa_otp_enroll", "mfa_otp_enroll_code", "mfa_otp_challenge", "mfa_email_challenge", "mfa_email_list", "mfa_recovery_enroll", "mfa_recovery_challenge", "mfa_result"} {
		t.Run(page, func(t *testing.T) {
			r := httptest.NewRecorder()
			RenderMFA(r, 200, Tenant{}, page, MFAData{State: "s", CSRF: "c", Action: "/u/mfa", QR: "", Secret: "MANUAL", Options: []MFAOption{{"otp", "App"}}})
			if r.Code != 200 || strings.Contains(r.Body.String(), "ZgotmplZ") || strings.Contains(r.Body.String(), "mfa-otp.") {
				t.Fatalf("render %d %s", r.Code, r.Body)
			}
			if r.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cacheable MFA page")
			}
		})
	}
}
