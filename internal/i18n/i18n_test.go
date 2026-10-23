package i18n

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

// withCatalog installs an extra built-in catalog for one test.
func withCatalog(t *testing.T, tag string, texts map[string]string) {
	t.Helper()
	catalogs[tag] = texts
	t.Cleanup(func() { delete(catalogs, tag) })
}

// Enabled returns a copy: changing it must not change the tenant.
func TestEnabledReturnsACopy(t *testing.T) {
	tn := &store.Tenant{EnabledLocales: []string{"en", "fr"}}
	Enabled(tn)[0] = "xx"
	if tn.EnabledLocales[0] != "en" {
		t.Fatalf("tenant locales changed: %v", tn.EnabledLocales)
	}
}

func TestNegotiate(t *testing.T) {
	tn := &store.Tenant{EnabledLocales: []string{"en", "fr", "pt-BR"}}
	cases := []struct {
		name, ui, accept, want string
	}{
		{"default when nothing asked", "", "", "en"},
		{"ui_locales first entry", "fr de", "", "fr"},
		{"ui_locales case-insensitive", "PT-br", "", "pt-BR"},
		{"ui_locales region falls back to enabled base", "fr-CA", "", "fr"},
		{"only the first ui_locales entry counts", "de fr", "", "en"},
		{"disabled ui_locales falls through to Accept-Language", "de", "fr;q=0.9", "fr"},
		{"Accept-Language q order", "", "de, pt-BR;q=0.8, fr;q=0.9", "fr"},
		{"Accept-Language region to base", "", "fr-CH", "fr"},
		{"q=0 excluded", "", "fr;q=0", "en"},
		{"wildcard ignored", "", "*", "en"},
		{"garbage header", "", "!!!,,;;q=x", "en"},
		{"garbage ui_locales", "%%%", "", "en"},
		{"long header", "", strings.Repeat("xx-YY, ", 500) + "fr", "fr"},
		{"entries past 1024 ignored", "", strings.Repeat("xx-YY, ", 1024) + "fr", "en"},
		{"q name is case-insensitive", "", "fr;Q=0", "en"},
		{"Q weight orders entries", "", "fr;Q=0.1, pt-BR;Q=0.5", "pt-BR"},
		{"spaces around q =", "", "fr;q = 0.1, pt-BR ; q = 0.5", "pt-BR"},
		{"spaces around q = 0", "", "fr ; q = 0", "en"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Negotiate(tn, tc.ui, tc.accept); got != tc.want {
				t.Fatalf("Negotiate(%q, %q) = %q, want %q", tc.ui, tc.accept, got, tc.want)
			}
		})
	}
	if got := Negotiate(&store.Tenant{}, "fr", "fr"); got != "en" {
		t.Fatalf("tenant without enabled_locales = %q, want en", got)
	}
	if got := Negotiate(&store.Tenant{EnabledLocales: []string{"de", "en"}}, "", ""); got != "de" {
		t.Fatalf("tenant default = %q, want de", got)
	}
}

func TestLookupFallback(t *testing.T) {
	withCatalog(t, "fr", map[string]string{"login.login.title": "Connexion", "login.login.buttonText": "Continuer"})
	withCatalog(t, "fr-ca", map[string]string{"login.login.title": "Se connecter"})
	tn := &store.Tenant{Name: "acme", CustomText: store.CustomText{
		"login": {"fr-CA": {"login": {"buttonText": "Poursuivre"}}},
	}}
	l := New(tn, "fr-CA")
	for key, want := range map[string]string{
		"login.login.buttonText":       "Poursuivre",   // 1. tenant custom text
		"login.login.title":            "Se connecter", // 2. built-in fr-CA
		"login.login.signupActionText": "New here?",    // 4. English
		"zeroauthy.error.server-error": "Something went wrong on our side. Please try again.",
	} {
		if got := l.T(key); got != want {
			t.Errorf("T(%q) = %q, want %q", key, got, want)
		}
	}
	delete(catalogs, "fr-ca")
	if got := New(tn, "fr-CA").T("login.login.title"); got != "Connexion" { // 3. base language
		t.Errorf("base fallback = %q, want Connexion", got)
	}
	if got := New(nil, "en").T("no.such.key"); got != "no.such.key" {
		t.Errorf("unknown key = %q", got)
	}
}

func TestVariables(t *testing.T) {
	l := New(&store.Tenant{Name: "acme", FriendlyName: "Acme Corp"}, "en").WithVar("clientName", "Shop")
	if got := l.T("login.login.description"); got != "Sign in to Acme Corp to continue to Shop." {
		t.Fatalf("description = %q", got)
	}
	if got := l.T("zeroauthy.signup.password-too-short", "min", "12"); got != "Password must be at least 12 characters." {
		t.Fatalf("with kv = %q", got)
	}
	if got := New(&store.Tenant{Name: "acme"}, "en").T("login.login.description"); got != "Sign in to acme to continue to ." {
		t.Fatalf("unset variable must render empty: %q", got)
	}
	base := New(&store.Tenant{Name: "acme"}, "en")
	_ = base.WithVar("clientName", "x")
	if got := base.T("login.login.description"); strings.Contains(got, "x.") {
		t.Fatal("WithVar mutated the original localizer")
	}
}

func TestNilAndDefaultLocalizer(t *testing.T) {
	var l *Localizer
	if l.T("login.login.title") != "Sign in" || l.Lang() != "en" || l.Dir() != "ltr" {
		t.Fatal("nil localizer must behave as English")
	}
	if Default().T("logout.logout.acceptButtonText") != "Log out" {
		t.Fatal("Default must be English")
	}
}

func TestDir(t *testing.T) {
	for lang, want := range map[string]string{"en": "ltr", "fr-CA": "ltr", "ar": "rtl", "he-IL": "rtl", "fa": "rtl", "ur": "rtl"} {
		if got := New(nil, lang).Dir(); got != want {
			t.Errorf("Dir(%s) = %s, want %s", lang, got, want)
		}
	}
}

func TestForRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "fr-FR,fr;q=0.9")
	tn := &store.Tenant{EnabledLocales: []string{"en", "fr"}}
	if got := ForRequest(tn, r, "").Lang(); got != "fr" {
		t.Fatalf("Accept-Language = %q", got)
	}
	if got := ForRequest(tn, r, "en").Lang(); got != "en" {
		t.Fatalf("ui_locales must win: %q", got)
	}
}

func TestPlaceholders(t *testing.T) {
	got := Placeholders("Hi ${b} and ${a}, ${b}! $notvar ${}")
	if strings.Join(got, ",") != "a,b" {
		t.Fatalf("Placeholders = %v", got)
	}
}

func TestValidateLocales(t *testing.T) {
	if err := ValidateLocales([]string{"en", "fr-CA", "pt-BR"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"en", "en"}, {"not a tag"}, {""}, {"EN", "en"}} {
		if err := ValidateLocales(bad); err == nil {
			t.Errorf("ValidateLocales(%q) accepted", bad)
		}
	}
}

func TestValidateCustomText(t *testing.T) {
	ok := store.CustomText{"login": {"fr": {"login": {"title": "Connexion à ${companyName}", "buttonText": "Continuer"}}}}
	if err := ValidateCustomText([]string{"en", "fr"}, ok); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		enabled []string
		ct      store.CustomText
		want    string
	}{
		"language not enabled":                    {[]string{"en"}, ok, `"fr" is not an enabled locale`},
		"unknown zeroauthy screen":                {nil, store.CustomText{"zeroauthy": {"en": {"nope": {"title": "x"}}}}, "unknown key"},
		"unknown zeroauthy key":                   {nil, store.CustomText{"zeroauthy": {"en": {"error": {"titel": "x"}}}}, "unknown key"},
		"ignored Auth0 key, language not enabled": {[]string{"en"}, store.CustomText{"login": {"fr": {"login": {"forgotPasswordText": "x"}}}}, `"fr" is not an enabled locale`},
		"ignored Auth0 key, empty text":           {nil, store.CustomText{"login": {"en": {"login": {"forgotPasswordText": ""}}}}, "is empty"},
		"foreign variable":                        {nil, store.CustomText{"login": {"en": {"login": {"title": "Hi ${userName}"}}}}, "${userName}"},
		"bad language tag":                        {[]string{"en", "not a tag"}, store.CustomText{"login": {"not a tag": {"login": {"title": "x"}}}}, "not a tag"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidateCustomText(tc.enabled, tc.ct)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestEnglishCatalogShape(t *testing.T) {
	keys := EnglishKeys()
	if len(keys) == 0 {
		t.Fatal("no English keys")
	}
	for _, k := range keys {
		if strings.Count(k, ".") != 2 || catalogs["en"][k] == "" {
			t.Errorf("bad key or empty text: %q", k)
		}
	}
}

func TestGoKeysExist(t *testing.T) {
	for _, k := range []string{
		KeyWrongCredentials, KeyUserBlocked, KeyPasswordChangeRequired, KeyEmailInUse, KeyInvalidUsername,
		KeyTooManyAttempts, KeyPasswordTooLong, KeyPasswordTooShort, KeyPasswordClasses,
		KeyPasswordTypes, KeyPasswordIdentical, KeyPasswordSequential, KeyPasswordInHistory, KeyPasswordDictionary,
		KeyPasswordPersonalInfo, KeyUsernameTooShort, KeyUsernameTooLong,
		KeyErrSessionExpired, KeyErrNoConnection, KeyErrSignupDisabled, KeyErrServer,
		KeyErrInvalidRequest, KeyErrLogoutUnknownClient, KeyErrLogoutURL, KeyErrLogoutInvalid,
		KeyResetPasswordMismatch, KeyResetErrExpiredTitle, KeyResetErrExpired, KeyResetErrUsedTitle,
		KeyResetErrUsed, KeyResetErrGenericTitle, KeyResetErrGeneric, KeyResetNotChanged,
	} {
		if catalogs["en"][k] == "" {
			t.Errorf("key %q missing from en.json", k)
		}
	}
}

func TestCustomTextLanguageCaseInsensitive(t *testing.T) {
	tn := &store.Tenant{CustomText: store.CustomText{
		"login": {"fr-ca": {"login": {"buttonText": "Poursuivre"}}},
	}}
	if got := New(tn, "fr-CA").T("login.login.buttonText"); got != "Poursuivre" {
		t.Fatalf("fr-ca custom text for fr-CA = %q", got)
	}
}

func TestValidateCustomTextCaseDuplicateLanguages(t *testing.T) {
	ct := store.CustomText{"login": {
		"fr": {"login": {"title": "a"}},
		"FR": {"login": {"title": "b"}},
	}}
	err := ValidateCustomText([]string{"en", "fr"}, ct)
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("err = %v, want duplicate-language rejection", err)
	}
}

func TestValidateCustomTextRejectsEmptyText(t *testing.T) {
	for _, text := range []string{"", "   \t"} {
		ct := store.CustomText{"login": {"en": {"login": {"buttonText": text}}}}
		err := ValidateCustomText(nil, ct)
		if err == nil || !strings.Contains(err.Error(), "login.login.buttonText") || !strings.Contains(err.Error(), "empty") {
			t.Errorf("text %q: err = %v, want an empty-text error naming the key", text, err)
		}
	}
}

func TestEmptyCustomTextFallsBackToCatalog(t *testing.T) {
	tn := &store.Tenant{CustomText: store.CustomText{
		"login": {"en": {"login": {"buttonText": "", "title": "  "}}},
	}}
	l := New(tn, "en")
	if got := l.T("login.login.buttonText"); got != "Continue" {
		t.Errorf("empty custom text = %q, want the catalog's Continue", got)
	}
	if got := l.T("login.login.title"); got != "Sign in" {
		t.Errorf("blank custom text = %q, want the catalog's Sign in", got)
	}
}

// Documented Auth0 keys for screens zeroauthy does not render are accepted
// and ignored, so a configuration written for Auth0 still loads.
func TestValidateCustomTextAcceptsUnrenderedAuth0Keys(t *testing.T) {
	ct := store.CustomText{
		"login":              {"en": {"login": {"federatedConnectionButtonText": "Use ${unknownVar}"}}},
		"reset-password":     {"en": {"reset-password-request": {"pageTitle": "Reset"}}},
		"signup":             {"en": {"signup": {"password-policy-not-conformant": "Weak password."}}},
		"login-passwordless": {"en": {"login-passwordless-email-code": {"title": "Code"}}},
	}
	if err := ValidateCustomText(nil, ct); err != nil {
		t.Fatalf("unrendered Auth0 keys rejected: %v", err)
	}
}

func TestHasCustom(t *testing.T) {
	tn := &store.Tenant{CustomText: store.CustomText{"login": {"en": {"login": {"title": "Hi", "buttonText": ""}}}}}
	l := New(tn, "en")
	if !l.HasCustom("login.login.title") || l.HasCustom("login.login.buttonText") || l.HasCustom("login.login.description") {
		t.Fatal("HasCustom must report only non-empty custom text")
	}
	var nilL *Localizer
	if nilL.HasCustom("login.login.title") {
		t.Fatal("nil localizer has no custom text")
	}
}

func TestValidateLocalesRejectsNonCanonicalAndSpecialTags(t *testing.T) {
	for tag, want := range map[string]string{
		"und":       "undetermined",
		"x-foo":     "private-use",
		"i-klingon": "grandfathered",
		"i-default": "grandfathered",
		"en_US":     `use "en-US"`,
		"fr-ca":     `use "fr-CA"`,
		"EN":        `use "en"`,
		"iw":        `use "he"`,
	} {
		err := ValidateLocales([]string{tag})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateLocales(%q) = %v, want it to contain %q", tag, err, want)
		}
	}
}

// The device-flow prompt has every key Auth0 documents for its four screens.
func TestDeviceFlowKeys(t *testing.T) {
	screens := map[string][]string{
		"device-code-activation": {"pageTitle", "title", "description", "placeholder", "buttonText", "logoAltText",
			"invalid-code", "invalid-expired-code", "no-code"},
		"device-code-confirmation": {"pageTitle", "title", "description", "inputCodeLabel", "confirmationText",
			"confirmButtonText", "cancelButtonText", "logoAltText"},
		"device-code-activation-allowed": {"pageTitle", "eventTitle", "description"},
		"device-code-activation-denied":  {"pageTitle", "eventTitle", "description"},
	}
	for screen, keys := range screens {
		for _, k := range keys {
			if catalogs["en"]["device-flow."+screen+"."+k] == "" {
				t.Errorf("device-flow.%s.%s missing from en.json", screen, k)
			}
		}
	}
	for _, k := range []string{KeyDeviceNoCode, KeyDeviceInvalidCode, KeyDeviceInvalidExpiredCode, "zeroauthy.consent.externalDeviceApp"} {
		if catalogs["en"][k] == "" {
			t.Errorf("key %q missing from en.json", k)
		}
	}
}

func TestTenantSettingsHostedLocaleFallback(t *testing.T) {
	tn, err := tenantrules.Apply(&store.Tenant{}, map[string]any{"enabled_locales": []string{"fr", "am"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := Negotiate(tn, "", "de"); got != "fr" {
		t.Fatalf("default locale %q", got)
	}
	if got := Negotiate(tn, "am", ""); got != "am" {
		t.Fatalf("documented locale %q", got)
	}
	// An accepted locale without a local translation retains catalog fallback.
	req := httptest.NewRequest("GET", "https://tenant.test", nil)
	if l := ForRequest(tn, req, "am"); l.T("login.login.title") == "login.login.title" {
		t.Fatal("missing hosted fallback")
	}
}
