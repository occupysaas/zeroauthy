package ui

import (
	"html/template"
	"net/http"
)

type MFAOption struct{ Factor, Label string }
type MFAData struct {
	State, CSRF, Action, Error, Secret, RecoveryCode, AnotherURL, Prefix string
	Revision                                                             int64
	QR                                                                   template.HTML
	Options                                                              []MFAOption
	AllowRemember, Email, Recovery, Enroll, CodeScreen                   bool
}

func MFAScreen(page string) (string, string) {
	switch page {
	case "mfa_options":
		return "mfa", "mfa-login-options"
	case "mfa_enroll_options":
		return "mfa", "mfa-begin-enroll-options"
	case "mfa_otp_enroll":
		return "mfa-otp", "mfa-otp-enrollment-qr"
	case "mfa_otp_enroll_code":
		return "mfa-otp", "mfa-otp-enrollment-code"
	case "mfa_otp_challenge":
		return "mfa-otp", "mfa-otp-challenge"
	case "mfa_email_challenge":
		return "mfa-email", "mfa-email-challenge"
	case "mfa_email_list":
		return "mfa-email", "mfa-email-list"
	case "mfa_recovery_enroll":
		return "mfa-recovery-code", "mfa-recovery-code-enrollment"
	case "mfa_recovery_challenge":
		return "mfa-recovery-code", "mfa-recovery-code-challenge"
	default:
		return "mfa", "mfa-enroll-result"
	}
}
func RenderMFA(w http.ResponseWriter, status int, t Tenant, page string, d MFAData) {
	p, s := MFAScreen(page)
	d.Prefix = p + "." + s + "."
	render(w, status, page, t, d, "'self'")
}
func init() {
	for page, file := range map[string]string{"mfa_options": "options", "mfa_enroll_options": "options", "mfa_otp_enroll": "otp_enroll", "mfa_otp_enroll_code": "otp_enroll", "mfa_otp_challenge": "otp_challenge", "mfa_email_challenge": "email_challenge", "mfa_email_list": "options", "mfa_recovery_enroll": "recovery_enroll", "mfa_recovery_challenge": "recovery_challenge", "mfa_result": "result"} {
		pages[page] = parsePage("templates/layout.html", "templates/mfa_"+file+".html")
	}
}
