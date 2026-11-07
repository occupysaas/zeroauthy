package i18n

import (
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"testing"
)

var templateKey = regexp.MustCompile(`\{\{-?\s*t\s+\.(?:Tenant\.)?L\s+"([^"]+)"`)

// usedKeys collects keys named in templates and the Key* constants.
func usedKeys(t *testing.T) []string {
	t.Helper()
	var used []string
	var files []string
	for _, g := range []string{"../ui/templates/*.html", "../email/templates/*"} {
		m, err := filepath.Glob(g)
		if err != nil || len(m) == 0 {
			t.Fatalf("templates %s: %v", g, err)
		}
		files = append(files, m...)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range templateKey.FindAllStringSubmatch(string(b), -1) {
			used = append(used, m[1])
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), "keys.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			s, _ := strconv.Unquote(lit.Value)
			used = append(used, s)
		}
		return true
	})
	// MFA templates share a data-driven prompt/screen prefix. These suffixes
	// occur in the shared templates or the proof/option error paths.
	for prompt, screens := range mfarules.Screens() {
		for _, screen := range screens {
			for _, suffix := range []string{"title", "description", "buttonText", "codeLabel", "rememberMeText", "tryAnotherMethodText", "resendActionText", "qrCodeLabel", "manualEntryText", "acknowledgeText", "alreadyShownText", "successText", "otpText", "emailText", "recovery-codeText", "invalidCode", "tooManyAttempts"} {
				used = append(used, prompt+"."+screen+"."+suffix)
			}
		}
	}
	used = append(used, "mfa.mfa-enroll-result.invalidTicket")
	// WebAuthn MFA shares dynamic templates, with screen-specific controls.
	for screen, suffixes := range map[string][]string{
		"mfa.mfa-detect-browser-capabilities":                           {"title", "description", "buttonText"},
		"mfa-webauthn.mfa-webauthn-platform-enrollment":                 {"title", "description", "continueButtonText", "snoozeEnrollmentButtonText", "refuseAddingDeviceText", "skipAddingDeviceText", "rememberMeText", "tryAnotherMethodText"},
		"mfa-webauthn.mfa-webauthn-platform-challenge":                  {"title", "description", "buttonText", "rememberMeText", "tryAnotherMethodText"},
		"reset-password.reset-password-mfa-webauthn-platform-challenge": {"title", "description", "buttonText", "tryAnotherMethodText"},
		"mfa.mfa-login-options":                                         {"webauthn-roamingText", "webauthn-platformText"},
		"mfa.mfa-begin-enroll-options":                                  {"webauthn-roamingText", "webauthn-platformText"},
		"mfa-webauthn.mfa-webauthn-roaming-enrollment":                  {"title", "description", "buttonText", "rememberMeText", "tryAnotherMethodText"},
		"mfa-webauthn.mfa-webauthn-roaming-challenge":                   {"title", "description", "buttonText", "rememberMeText", "tryAnotherMethodText"},
		"mfa-webauthn.mfa-webauthn-change-key-nickname":                 {"title", "description", "buttonText", "nameLabel", "tryAnotherMethodText"},
		"mfa-webauthn.mfa-webauthn-enrollment-success":                  {"title", "description", "buttonText"},
		"mfa-webauthn.mfa-webauthn-error":                               {"title", "description", "buttonText", "rememberMeText", "tryAnotherMethodText", "too-many-webauthn-challenge-attempts-error"},
		"mfa-webauthn.mfa-webauthn-not-available-error":                 {"title", "description", "tryAnotherMethodText"},
		"reset-password.reset-password-mfa-webauthn-roaming-challenge":  {"title", "description", "buttonText", "tryAnotherMethodText"},
	} {
		for _, suffix := range suffixes {
			used = append(used, screen+"."+suffix)
		}
	}

	// Hosted passwordless code screens share one template with a screen
	// prefix (internal/login passwordlessCodeSuffixes).
	for _, screen := range []string{"login-passwordless-email-code", "login-passwordless-sms-otp"} {
		for _, suffix := range []string{"pageTitle", "title", "description", "codePlaceholder", "buttonText", "resendText", "resendActionText", "editText", "logoAltText", "invalid-code"} {
			used = append(used, "login-passwordless."+screen+"."+suffix)
		}
	}
	return used
}

// aliasKeys are Auth0 keys used from Go code only as tenant custom text;
// they have no built-in text, so they are deliberately absent from en.json.
var aliasKeys = []string{KeyPasswordPolicyAlias}

func TestCatalogMatchesUsage(t *testing.T) {
	used := usedKeys(t)
	for _, k := range used {
		if slices.Contains(aliasKeys, k) {
			if _, ok := catalogs["en"][k]; ok {
				t.Errorf("alias key %q must not be in en.json", k)
			}
			continue
		}
		if _, ok := catalogs["en"][k]; !ok {
			t.Errorf("key %q is used but missing from en.json", k)
		}
	}
	for _, k := range EnglishKeys() {
		if !slices.Contains(used, k) {
			t.Errorf("en.json key %q is never used", k)
		}
	}
}

// Every other catalog may only contain English keys, with the same
// placeholders.
func TestOtherCatalogsMatchEnglish(t *testing.T) {
	for tag, texts := range catalogs {
		if tag == "en" {
			continue
		}
		for k, v := range texts {
			en, ok := catalogs["en"][k]
			if !ok {
				t.Errorf("%s: unknown key %q", tag, k)
				continue
			}
			if !slices.Equal(Placeholders(en), Placeholders(v)) {
				t.Errorf("%s: %q placeholders %v, English has %v", tag, k, Placeholders(v), Placeholders(en))
			}
		}
	}
}
