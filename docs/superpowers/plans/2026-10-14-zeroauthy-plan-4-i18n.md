# zeroauthy Plan 4: Internationalization of Hosted Pages

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hosted pages render in the language that the application (`ui_locales`) or the browser (`Accept-Language`) asks for, provided the tenant enables it. Tenants can override text per language in Auth0's documented custom-text shape. Plan 4 ships English only; contributors add languages without changing code.

**Architecture:**
- A new `internal/i18n` package handles:
  - the embedded catalogs (`locales/<tag>.json`, shaped prompt → screen → key);
  - language negotiation;
  - a `Localizer` that looks up text, falls back to English, and substitutes `${variables}`;
  - validation of tenant custom text.
- Tenants gain `EnabledLocales` and `CustomText`, and both are seedable.
- The `ui` templates call `{{t .Tenant.L "prompt.screen.key"}}`.
- Each handler builds a `Localizer` per request and passes it in through `ui.TenantView`.
- `/authorize` keeps `ui_locales` in the login transaction.

**Tech Stack:**
- Go 1.26+, `golang.org/x/text/language`: already in `go.mod` as indirect, so this plan makes it a direct dependency.
- `html/template` and `embed`.
- E2E: the existing Playwright and `@auth0/auth0-spa-js` 2.28.3 setup.

**Spec:** `docs/superpowers/specs/2026-10-14-zeroauthy-i18n-design.md`

## Global Constraints

Plans 1–3 constraints still apply:
- clean room: SDKs are black-box test clients;
- spec-first contract;
- tenant-scoped storage, and drivers return copies;
- hosted pages are original `html/template` pages with a nonce CSP;
- `go test -race ./...`, `go vet` and `gofmt` stay clean.

New constraints:

- **Clean room:** only *identifiers* come from Auth0's public docs, namely the prompt, screen and key names and the `${variable}` syntax. All default wording is original. Strings that already exist keep their current English wording exactly.
- **Language selection** (spec §3):
  1. The **first** entry of `ui_locales`, if the tenant enables it.
  2. Otherwise, the `Accept-Language` entries in q-value order; the first one the tenant enables wins.
  3. Otherwise, the tenant default, which is the first entry of `enabled_locales`. When `enabled_locales` is unset it is treated as `[en]`.
  4. "Enables" means either an exact, case-insensitive tag match, or that the request's base language is itself enabled (for example, `fr-CA` is matched by an enabled `fr`).
- **Text lookup** (spec §4), for chosen language L:
  1. tenant custom text for L;
  2. the built-in catalog for L;
  3. the built-in catalog for L's base language;
  4. the built-in English catalog.

  A page never shows an empty string. A key missing from every catalog renders as the key itself, but the catalog test makes that impossible in practice.
- **Keys** are `prompt.screen.key`.
  - Where Auth0 documents a matching screen, use its names: `login.login.*`, `signup.signup.*`, `logout.logout.*`.
  - Everything else lives under the prompt `zeroauthy`.
- **Variables:**
  - `${companyName}` is the tenant's friendly name, or its name if no friendly name is set.
  - `${clientName}` is the application's name, or its client ID if it has no name.
  - Page-specific variables such as `${min}` and `${count}` come from the message.
  - An unset variable renders as an empty string.
  - All text is HTML-escaped by the templates.
- **Custom text validation:**
  - Locales must be valid BCP 47 tags.
  - Custom text may only target enabled languages.
  - Prompt, screen and key names must exist in `en.json`.
  - An override may use only the variables that the English string for that key uses.
- **Pages:**
  - `<html lang>` is the chosen tag.
  - `dir="rtl"` is set when the base language is `ar`, `he`, `fa` or `ur`, and `dir="ltr"` otherwise.

## Review Focus

1. **Hostile or odd `Accept-Language`:**
   - Inputs: garbage, an empty header, `*`, entries with `q=0`, and a very long list.
   - Expected: the tenant default, never a 500.
   - Covered in: Task 1, `TestNegotiate`.
2. **A disabled first `ui_locales` entry:**
   - Input: the first entry is disabled but a later one is enabled.
   - Expected: the later entries are ignored, as Auth0 documents, and selection moves on to `Accept-Language`.
   - Covered in: Task 1.
3. **Custom text containing HTML or script:**
   - Expected: escaped on every page; a `${var}` value is escaped too.
   - Covered in: Task 3, `TestCustomTextIsEscaped`.
4. **An override using a variable the English string lacks:**
   - Expected: the seed rejects it.
   - Covered in: Task 1 (validator) and Task 2 (seed).
5. **A page re-rendered after a failed POST:**
   - Expected: it stays in the transaction's `ui_locales` language, including the error message.
   - Covered in: Task 4.

## Out of Scope

- Non-English catalogs.
- Emails (milestone 6).
- `PUT /prompts/{prompt}/custom-text/{language}` (sub-project 3).
- RTL styling beyond `dir`. The current CSS has no left/right-specific properties; Task 3 verifies this.
- OAuth `error_description` values. They are protocol text and stay English. The `/authorize` error page shows a localized message plus the English technical detail.

## File Map

```
internal/i18n/{catalog.go,negotiate.go,localizer.go,validate.go,keys.go}   new package
internal/i18n/locales/en.json                                             English catalog
internal/i18n/{i18n_test.go,catalog_test.go}
internal/store/{types.go}, internal/store/memory/clone.go, pkg/storetest/tenants.go
internal/seed/{seed.go,validate.go,apply.go,seed_test.go}
internal/identity/{identity.go,database.go}                               PolicyError gains Key/Vars
internal/ui/{ui.go,ui_test.go}, internal/ui/templates/*.html
internal/authz/{request.go,response.go,handlers.go}
internal/login/login.go, internal/oidc/{logout.go,rp_logout.go}
internal/{login,authz,oidc}/*_test.go                                     localization tests (Task 4)
tests/e2e/{seed.yaml,m6-i18n.spec.mjs}
docs/compat/{decisions.md,matrix.md}, docs/i18n.md, README.md
```

---

### Task 1: The `i18n` package: catalog, negotiation, localizer, validation

**Files:**
- Create: `internal/i18n/catalog.go`, `negotiate.go`, `localizer.go`, `validate.go`, `keys.go`, `locales/en.json`, `i18n_test.go`
- Modify: `internal/store/types.go` (add the `CustomText` type and the two `Tenant` fields; Task 2 handles copying and seeding them)
- Modify: `go.mod` (`golang.org/x/text` becomes a direct dependency; run `go mod tidy`)

**Interfaces (produced):**

```go
// store
type CustomText map[string]map[string]map[string]map[string]string // prompt → language → screen → key → text
// Tenant gains: EnabledLocales []string; CustomText CustomText

// i18n
func Negotiate(t *store.Tenant, uiLocales, acceptLanguage string) string
func Enabled(t *store.Tenant) []string
type Localizer struct{ /* unexported */ }
func Default() *Localizer                                  // English, no tenant
func New(t *store.Tenant, lang string) *Localizer
func ForRequest(t *store.Tenant, r *http.Request, uiLocales string) *Localizer
func (l *Localizer) WithVar(name, value string) *Localizer // returns a copy
func (l *Localizer) T(key string, kv ...string) string     // kv: name, value pairs; nil-safe
func (l *Localizer) Lang() string                          // nil-safe ("en")
func (l *Localizer) Dir() string                           // "ltr" | "rtl", nil-safe
func EnglishKeys() []string
func Placeholders(text string) []string
func ValidateLocales(tags []string) error
func ValidateCustomText(enabled []string, ct store.CustomText) error
// keys.go: Key* string constants (listed below)
```

- [ ] **Step 1: Store fields**

In `internal/store/types.go`, add the following to `Tenant` after `AllowedLogoutURLs`:

```go
	// EnabledLocales are the languages hosted pages may use; the first is
	// the default. Empty means ["en"].
	EnabledLocales []string
	// CustomText overrides hosted-page text per language.
	CustomText CustomText
```

Then append:

```go
// CustomText holds a tenant's text overrides, shaped like Auth0's
// documented prompt custom text: prompt → language → screen → key → text.
type CustomText map[string]map[string]map[string]map[string]string
```

- [ ] **Step 2: The English catalog**

Create `internal/i18n/locales/en.json`. Strings that already exist keep their current wording; new strings are original.

```json
{
  "login": {
    "login": {
      "title": "Sign in",
      "description": "Sign in to ${companyName} to continue to ${clientName}.",
      "usernamePlaceholder": "Email or username",
      "passwordPlaceholder": "Password",
      "buttonText": "Continue",
      "signupActionText": "New here?",
      "signupActionLinkText": "Create an account",
      "wrong-credentials": "Incorrect email/username or password.",
      "user-blocked": "This account has been blocked. Contact the application's support."
    }
  },
  "signup": {
    "signup": {
      "title": "Create your account",
      "description": "Sign up for ${companyName} to continue to ${clientName}.",
      "emailPlaceholder": "Email",
      "usernamePlaceholder": "Username",
      "passwordPlaceholder": "Password",
      "buttonText": "Sign up",
      "loginActionText": "Already have an account?",
      "loginActionLinkText": "Sign in",
      "email-in-use": "An account with this email or username already exists.",
      "invalid-username": "Usernames are 1-64 characters: letters, digits, and _ . + -"
    }
  },
  "logout": {
    "logout": {
      "pageTitle": "Log out",
      "title": "Log out?",
      "description": "An application asked to end your session. Do you want to log out?",
      "acceptButtonText": "Log out"
    }
  },
  "zeroauthy": {
    "layout": {
      "logoAltText": "${companyName}"
    },
    "common": {
      "too-many-attempts": "Too many attempts. Wait a few minutes and try again."
    },
    "signup": {
      "password-too-long": "This password is too long.",
      "password-too-short": "Use a password of at least ${min} characters.",
      "password-character-classes": "Use at least ${count} of: lowercase letters, uppercase letters, digits, symbols."
    },
    "error": {
      "title": "Something went wrong",
      "description": "Return to the application and try again.",
      "session-expired": "Your login session has expired or is invalid. Return to the application and start again.",
      "no-connection": "No login method is enabled for this application.",
      "signup-disabled": "Sign-up is not available for this application.",
      "server-error": "Something went wrong on our side. Please try again.",
      "invalid-request": "The application sent a request that could not be completed.",
      "logout-unknown-client": "The application that asked to log you out is not registered. You are still logged in.",
      "logout-url-not-allowed": "The address to return to after logout is not allowed for this application. You are still logged in.",
      "logout-invalid": "The logout request was not valid. You are still logged in."
    },
    "logged-out": {
      "title": "You are logged out",
      "description": "Your session has ended.",
      "hint": "You can close this window."
    },
    "form-post": {
      "title": "Continuing…",
      "buttonText": "Continue"
    }
  }
}
```

- [ ] **Step 3: Write the failing tests**

Create `internal/i18n/i18n_test.go`:

```go
package i18n

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// withCatalog installs an extra built-in catalog for one test.
func withCatalog(t *testing.T, tag string, texts map[string]string) {
	t.Helper()
	catalogs[tag] = texts
	t.Cleanup(func() { delete(catalogs, tag) })
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
		"login.login.buttonText":          "Poursuivre",   // 1. tenant custom text
		"login.login.title":               "Se connecter", // 2. built-in fr-CA
		"login.login.signupActionText":    "New here?",    // 4. English
		"zeroauthy.error.server-error":    "Something went wrong on our side. Please try again.",
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
	if got := l.T("zeroauthy.signup.password-too-short", "min", "12"); got != "Use a password of at least 12 characters." {
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
		"language not enabled": {[]string{"en"}, ok, `"fr" is not an enabled locale`},
		"unknown prompt":       {nil, store.CustomText{"nope": {"en": {"login": {"title": "x"}}}}, "unknown key"},
		"unknown screen":       {nil, store.CustomText{"login": {"en": {"nope": {"title": "x"}}}}, "unknown key"},
		"unknown key":          {nil, store.CustomText{"login": {"en": {"login": {"nope": "x"}}}}, "unknown key"},
		"foreign variable":     {nil, store.CustomText{"login": {"en": {"login": {"title": "Hi ${userName}"}}}}, "${userName}"},
		"bad language tag":     {[]string{"en", "not a tag"}, store.CustomText{"login": {"not a tag": {"login": {"title": "x"}}}}, "not a tag"},
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
```

Run: `go test ./internal/i18n/`
Expected: FAIL to build (undefined: `catalogs`, `Negotiate`, …).

- [ ] **Step 4: Implement**

`internal/i18n/catalog.go`:

```go
// Package i18n localizes hosted pages: embedded catalogs, language
// negotiation, text lookup with English fallback, and validation of tenant
// custom text (D-0016).
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

//go:embed locales/*.json
var localeFiles embed.FS

// catalogs maps a lowercase language tag (the file name) to its texts,
// flattened to "prompt.screen.key".
var catalogs = mustLoadCatalogs()

func mustLoadCatalogs() map[string]map[string]string {
	entries, err := localeFiles.ReadDir("locales")
	if err != nil {
		panic(err)
	}
	out := map[string]map[string]string{}
	for _, e := range entries {
		raw, err := localeFiles.ReadFile("locales/" + e.Name())
		if err != nil {
			panic(err)
		}
		var nested map[string]map[string]map[string]string
		if err := json.Unmarshal(raw, &nested); err != nil {
			panic(fmt.Sprintf("i18n: locales/%s: %v", e.Name(), err))
		}
		flat := map[string]string{}
		for prompt, screens := range nested {
			for screen, keys := range screens {
				for k, v := range keys {
					flat[prompt+"."+screen+"."+k] = v
				}
			}
		}
		out[strings.ToLower(strings.TrimSuffix(e.Name(), ".json"))] = flat
	}
	if _, ok := out["en"]; !ok {
		panic("i18n: locales/en.json is missing")
	}
	return out
}

// EnglishKeys returns every key of the English catalog, sorted.
func EnglishKeys() []string {
	keys := make([]string, 0, len(catalogs["en"]))
	for k := range catalogs["en"] {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
```

`internal/i18n/negotiate.go`:

```go
package i18n

import (
	"strings"

	"golang.org/x/text/language"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Enabled returns the tenant's enabled locales; the first is the default.
func Enabled(t *store.Tenant) []string {
	if t == nil || len(t.EnabledLocales) == 0 {
		return []string{"en"}
	}
	return t.EnabledLocales
}

// Negotiate picks the page language and returns it as written in the
// tenant's enabled locales (D-0016): the first ui_locales entry, then
// Accept-Language by weight, then the tenant default.
func Negotiate(t *store.Tenant, uiLocales, acceptLanguage string) string {
	enabled := Enabled(t)
	if f := strings.Fields(uiLocales); len(f) > 0 {
		if l, ok := match(enabled, f[0]); ok {
			return l
		}
	}
	if tags, _, err := language.ParseAcceptLanguage(acceptLanguage); err == nil {
		for _, tag := range tags {
			if l, ok := match(enabled, tag.String()); ok {
				return l
			}
		}
	}
	return enabled[0]
}

// match finds want among enabled: an exact (case-insensitive) match, else
// an enabled entry equal to want's base language (fr-CA → fr).
func match(enabled []string, want string) (string, bool) {
	tag, err := language.Parse(want)
	if err != nil || tag == language.Und {
		return "", false
	}
	for _, e := range enabled {
		if strings.EqualFold(e, tag.String()) {
			return e, true
		}
	}
	base, _ := tag.Base()
	for _, e := range enabled {
		if strings.EqualFold(e, base.String()) {
			return e, true
		}
	}
	return "", false
}

// baseOf returns the lowercase base language of a tag ("fr-CA" → "fr").
func baseOf(tag string) string {
	t, err := language.Parse(tag)
	if err != nil {
		return strings.ToLower(tag)
	}
	b, _ := t.Base()
	return b.String()
}
```

`internal/i18n/localizer.go`:

```go
package i18n

import (
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// rtlBases are base languages written right to left.
var rtlBases = []string{"ar", "he", "fa", "ur"}

var placeholder = regexp.MustCompile(`\$\{([A-Za-z][A-Za-z0-9_]*)\}`)

// Localizer renders text for one tenant and language. A nil *Localizer
// behaves as Default().
type Localizer struct {
	lang   string
	custom map[string]string // tenant overrides for lang, "prompt.screen.key" → text
	vars   map[string]string
}

var english = &Localizer{lang: "en"}

// Default is English with no tenant.
func Default() *Localizer { return english }

// New returns a localizer for tenant t (which may be nil) and lang.
func New(t *store.Tenant, lang string) *Localizer {
	l := &Localizer{lang: lang, custom: map[string]string{}, vars: map[string]string{}}
	if t == nil {
		return l
	}
	name := t.FriendlyName
	if name == "" {
		name = t.Name
	}
	l.vars["companyName"] = name
	for prompt, langs := range t.CustomText {
		for screen, keys := range langs[lang] {
			for k, v := range keys {
				l.custom[prompt+"."+screen+"."+k] = v
			}
		}
	}
	return l
}

// ForRequest negotiates the language from uiLocales and the request's
// Accept-Language header.
func ForRequest(t *store.Tenant, r *http.Request, uiLocales string) *Localizer {
	return New(t, Negotiate(t, uiLocales, r.Header.Get("Accept-Language")))
}

// WithVar returns a copy of l with a variable set.
func (l *Localizer) WithVar(name, value string) *Localizer {
	if l == nil {
		l = english
	}
	c := *l
	c.vars = maps.Clone(l.vars)
	if c.vars == nil {
		c.vars = map[string]string{}
	}
	c.vars[name] = value
	return &c
}

func (l *Localizer) Lang() string {
	if l == nil || l.lang == "" {
		return "en"
	}
	return l.lang
}

func (l *Localizer) Dir() string {
	if slices.Contains(rtlBases, baseOf(l.Lang())) {
		return "rtl"
	}
	return "ltr"
}

// T returns the text for key (D-0016 lookup order) with variables
// substituted; kv are extra name, value pairs.
func (l *Localizer) T(key string, kv ...string) string {
	if l == nil {
		l = english
	}
	text, ok := l.custom[key]
	if !ok {
		text, ok = builtin(l.Lang(), key)
	}
	if !ok {
		return key
	}
	vars := maps.Clone(l.vars)
	if vars == nil {
		vars = map[string]string{}
	}
	for i := 0; i+1 < len(kv); i += 2 {
		vars[kv[i]] = kv[i+1]
	}
	return placeholder.ReplaceAllStringFunc(text, func(m string) string {
		return vars[m[2:len(m)-1]]
	})
}

func builtin(lang, key string) (string, bool) {
	for _, c := range []string{strings.ToLower(lang), baseOf(lang), "en"} {
		if v, ok := catalogs[c][key]; ok {
			return v, true
		}
	}
	return "", false
}

// Placeholders returns the sorted, distinct variable names in text.
func Placeholders(text string) []string {
	var out []string
	for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	slices.Sort(out)
	return out
}
```

`internal/i18n/validate.go`:

```go
package i18n

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/text/language"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ValidateLocales checks enabled_locales: valid BCP 47 tags, no duplicates
// (case-insensitive).
func ValidateLocales(tags []string) error {
	var errs []error
	seen := map[string]bool{}
	for _, t := range tags {
		if _, err := language.Parse(t); err != nil || t == "" {
			errs = append(errs, fmt.Errorf("%q is not a valid language tag", t))
			continue
		}
		if seen[strings.ToLower(t)] {
			errs = append(errs, fmt.Errorf("duplicate locale %q", t))
		}
		seen[strings.ToLower(t)] = true
	}
	return errors.Join(errs...)
}

// ValidateCustomText checks overrides against the English catalog: every
// language enabled, every key known, and only the variables the English
// string uses.
func ValidateCustomText(enabled []string, ct store.CustomText) error {
	if len(enabled) == 0 {
		enabled = []string{"en"}
	}
	var errs []error
	for prompt, langs := range ct {
		for lang, screens := range langs {
			if !slices.ContainsFunc(enabled, func(e string) bool { return strings.EqualFold(e, lang) }) {
				errs = append(errs, fmt.Errorf("custom_text.%s: %q is not an enabled locale", prompt, lang))
				continue
			}
			for screen, keys := range screens {
				for k, text := range keys {
					full := prompt + "." + screen + "." + k
					en, ok := catalogs["en"][full]
					if !ok {
						errs = append(errs, fmt.Errorf("custom_text.%s.%s: unknown key %q", prompt, lang, full))
						continue
					}
					allowed := Placeholders(en)
					for _, v := range Placeholders(text) {
						if !slices.Contains(allowed, v) {
							errs = append(errs, fmt.Errorf("custom_text.%s.%s: %q uses ${%s}, which %q does not support", prompt, lang, full, v, full))
						}
					}
				}
			}
		}
	}
	return errors.Join(errs...)
}
```

`internal/i18n/keys.go` lists the keys that Go code passes to `T`. Templates name their own keys.

```go
package i18n

// Keys used from Go code. The catalog test checks each exists in en.json.
const (
	KeyWrongCredentials       = "login.login.wrong-credentials"
	KeyUserBlocked            = "login.login.user-blocked"
	KeyEmailInUse             = "signup.signup.email-in-use"
	KeyInvalidUsername        = "signup.signup.invalid-username"
	KeyTooManyAttempts        = "zeroauthy.common.too-many-attempts"
	KeyPasswordTooLong        = "zeroauthy.signup.password-too-long"
	KeyPasswordTooShort       = "zeroauthy.signup.password-too-short"
	KeyPasswordClasses        = "zeroauthy.signup.password-character-classes"
	KeyErrSessionExpired      = "zeroauthy.error.session-expired"
	KeyErrNoConnection        = "zeroauthy.error.no-connection"
	KeyErrSignupDisabled      = "zeroauthy.error.signup-disabled"
	KeyErrServer              = "zeroauthy.error.server-error"
	KeyErrInvalidRequest      = "zeroauthy.error.invalid-request"
	KeyErrLogoutUnknownClient = "zeroauthy.error.logout-unknown-client"
	KeyErrLogoutURL           = "zeroauthy.error.logout-url-not-allowed"
	KeyErrLogoutInvalid       = "zeroauthy.error.logout-invalid"
)
```

- [ ] **Step 5: Run**

Run: `go mod tidy && go test -race ./internal/i18n/ && go build ./...`
Expected: PASS. In `go.mod`, `golang.org/x/text` is no longer marked `// indirect`.

If `TestNegotiate` "wildcard ignored" or "garbage header" fails because `ParseAcceptLanguage` returns tags the code does not expect, fix `match` and do not change the test. The expected behaviour is that the request falls back to the default.

- [ ] **Step 6: Commit**

```bash
git add internal/i18n internal/store/types.go go.mod go.sum
git commit -m "feat(i18n): catalogs, language negotiation, localizer and custom-text validation"
```

---

### Task 2: Tenant locales and custom text in store and seed

**Files:**
- Modify: `internal/store/memory/clone.go`, `pkg/storetest/tenants.go`
- Modify: `internal/seed/seed.go`, `internal/seed/validate.go`, `internal/seed/apply.go`, `internal/seed/seed_test.go`

**Interfaces:**
- Consumes: `store.Tenant.EnabledLocales`, `store.CustomText`, `i18n.ValidateLocales` and `i18n.ValidateCustomText` (Task 1).
- Produces: the seed keys `tenants[].enabled_locales` and `tenants[].custom_text`.

- [ ] **Step 1: Failing tests**

In `pkg/storetest/tenants.go` `newTenant`, add:

```go
		EnabledLocales: []string{"en", "fr"},
		CustomText:     store.CustomText{"login": {"fr": {"login": {"title": "Connexion"}}}},
```

Then add a copy test to `testTenants`:

```go
	t.Run("CustomTextIsCopied", func(t *testing.T) {
		s := open(t, newStore)
		in := newTenant("acme")
		mustNoErr(t, s.Tenants().Create(ctx, in))
		in.CustomText["login"]["fr"]["login"]["title"] = "mutated"
		in.EnabledLocales[0] = "xx"
		got, err := s.Tenants().Get(ctx, in.ID)
		mustNoErr(t, err)
		got.CustomText["login"]["fr"]["login"]["title"] = "mutated-too"
		again, _ := s.Tenants().Get(ctx, in.ID)
		mustEqual(t, again.CustomText["login"]["fr"]["login"]["title"], "Connexion")
		mustEqual(t, again.EnabledLocales, []string{"en", "fr"})
	})
```

In `internal/seed/seed_test.go`, add to the `TestValidation` table:

```go
		"bad locale":          {`tenants: [{name: a, enabled_locales: ["not a tag"]}]`, "not a valid language tag"},
		"text for disabled":   {`tenants: [{name: a, custom_text: {login: {fr: {login: {title: x}}}}}]`, "not an enabled locale"},
		"unknown text key":    {`tenants: [{name: a, custom_text: {login: {en: {login: {nope: x}}}}}]`, "unknown key"},
		"foreign variable":    {`tenants: [{name: a, custom_text: {login: {en: {login: {title: "Hi ${userName}"}}}}}]`, "${userName}"},
```

Then append:

```go
func TestApplyLocalesAndCustomText(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(`
tenants:
  - name: acme
    enabled_locales: [en, fr]
    custom_text:
      login:
        fr:
          login:
            title: "Connexion à ${companyName}"
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if len(tn.EnabledLocales) != 2 || tn.EnabledLocales[1] != "fr" ||
		tn.CustomText["login"]["fr"]["login"]["title"] != "Connexion à ${companyName}" {
		t.Fatalf("tenant = %+v", tn)
	}
}
```

Run: `go test ./internal/store/... ./internal/seed/`
Expected: FAIL. The memory driver shares the maps, and the seed rejects the unknown fields.

- [ ] **Step 2: Implement**

In `internal/store/memory/clone.go`, update `cloneTenant` as follows:

```go
	c.EnabledLocales = slices.Clone(t.EnabledLocales)
	c.CustomText = cloneCustomText(t.CustomText)
```

and add:

```go
func cloneCustomText(ct store.CustomText) store.CustomText {
	if ct == nil {
		return nil
	}
	out := store.CustomText{}
	for p, langs := range ct {
		out[p] = map[string]map[string]map[string]string{}
		for l, screens := range langs {
			out[p][l] = map[string]map[string]string{}
			for s, keys := range screens {
				out[p][l][s] = maps.Clone(keys)
			}
		}
	}
	return out
}
```

In `internal/seed/seed.go` `Tenant`, add:

```go
	EnabledLocales      []string         `yaml:"enabled_locales"`
	CustomText          store.CustomText `yaml:"custom_text"`
```

Import `internal/store` if it is not already imported.

In `internal/seed/validate.go` `(*Tenant).validate`, after the `allowed_logout_urls` loop, add:

```go
	if err := i18n.ValidateLocales(t.EnabledLocales); err != nil {
		fail("enabled_locales: %v", err)
	}
	if err := i18n.ValidateCustomText(t.EnabledLocales, t.CustomText); err != nil {
		fail("%v", err)
	}
```

In `internal/seed/apply.go`, set these in both the create and update branches, next to `AllowedLogoutURLs`:

```go
		tn.EnabledLocales = slices.Clone(in.EnabledLocales)
		tn.CustomText = in.CustomText
```

- [ ] **Step 3: Run and commit**

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: PASS, and vet and gofmt print nothing.

```bash
git add internal/store pkg/storetest internal/seed
git commit -m "feat(seed): tenant enabled_locales and custom_text"
```

---

### Task 3: Localized templates and messages

This task converts every visible string to a key. It also wires one `Localizer` per request into each handler. English output stays word-for-word the same, so existing tests keep passing.

**Files:**
- Modify: `internal/ui/ui.go`, `internal/ui/ui_test.go`, all of `internal/ui/templates/*.html` except `web_message.html`
- Modify: `internal/identity/identity.go` (`PolicyError` gains `Key` and `Vars`)
- Modify: `internal/authz/request.go`, `response.go`, `handlers.go`
- Modify: `internal/login/login.go`
- Modify: `internal/oidc/logout.go`, `rp_logout.go`
- Create: `internal/i18n/catalog_test.go`

**Interfaces:**
- Consumes: Task 1's `i18n` API.
- Produces:
  - `ui.Tenant.L *i18n.Localizer`
  - `ui.TenantView(t *store.Tenant, l *i18n.Localizer) ui.Tenant`
  - `ui.RenderErrorDetail(w, status int, t ui.Tenant, message, detail string)`
  - `ui.RenderFormPost(w, l *i18n.Localizer, action string, params url.Values)`
  - `authz.Request.UILocales` (the `ui_locales` parameter, kept in transactions)
  - `identity.PolicyError{Reason, Key string; Vars []string}`

- [ ] **Step 1: Failing tests**

Create `internal/i18n/catalog_test.go`. It keeps `en.json`, the templates and `keys.go` in sync:

```go
package i18n

import (
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
	files, err := filepath.Glob("../ui/templates/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("templates: %v", err)
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
	return used
}

func TestCatalogMatchesUsage(t *testing.T) {
	used := usedKeys(t)
	for _, k := range used {
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
```

Append these to `internal/ui/ui_test.go`, adding imports for `internal/i18n` and `internal/store`:

```go
func frenchTenant() *store.Tenant {
	return &store.Tenant{Name: "acme", EnabledLocales: []string{"en", "fr"}, CustomText: store.CustomText{
		"login": {"fr": {"login": {"title": "Connexion", "buttonText": "Continuer"}}},
	}}
}

func TestRenderLoginLocalized(t *testing.T) {
	tn := frenchTenant()
	rec := httptest.NewRecorder()
	RenderLogin(rec, 200, TenantView(tn, i18n.New(tn, "fr")), LoginData{State: "st", CSRF: "cs"})
	body := rec.Body.String()
	for _, want := range []string{`<html lang="fr" dir="ltr">`, "Connexion", "Continuer", "Email or username"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
}

func TestRTLDirection(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderLoggedOut(rec, TenantView(&store.Tenant{Name: "acme"}, i18n.New(nil, "ar")))
	if !strings.Contains(rec.Body.String(), `<html lang="ar" dir="rtl">`) {
		t.Fatalf("body = %s", rec.Body)
	}
}

func TestCustomTextIsEscaped(t *testing.T) {
	tn := &store.Tenant{Name: `<b>acme</b>`, CustomText: store.CustomText{
		"login": {"en": {"login": {"title": `<script>alert(1)</script> ${companyName}`}}},
	}}
	rec := httptest.NewRecorder()
	RenderLogin(rec, 200, TenantView(tn, i18n.New(tn, "en")), LoginData{State: "st", CSRF: "cs"})
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)") || strings.Contains(body, "<b>acme</b>") {
		t.Fatalf("custom text or variable not escaped:\n%s", body)
	}
}

func TestRenderErrorDetail(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderErrorDetail(rec, 400, Tenant{Name: "Acme"}, "Localized message", "redirect_uri is not registered")
	body := rec.Body.String()
	if rec.Code != 400 || !strings.Contains(body, "Localized message") || !strings.Contains(body, "redirect_uri is not registered") {
		t.Fatalf("got %d %s", rec.Code, body)
	}
}
```

Wherever an existing test calls `RenderFormPost(rec, action, params)`, change the call to `RenderFormPost(rec, nil, action, params)`.

Run: `go test ./internal/ui/ ./internal/i18n/`
Expected: FAIL. `TenantView` has the wrong arity, `RenderErrorDetail` is undefined, and the catalog test reports unused keys.

- [ ] **Step 2: The `ui` package**

In `internal/ui/ui.go`:

1. Add the template functions and parse every page with them:

```go
var funcs = template.FuncMap{
	// t renders a catalog key: {{t .Tenant.L "login.login.title" "name" "value"}}.
	"t": func(l *i18n.Localizer, key string, kv ...string) string { return l.T(key, kv...) },
	// tv renders a key whose variables are a slice: {{tv .Tenant.L .Data.ErrorKey .Data.ErrorVars}}.
	"tv": func(l *i18n.Localizer, key string, kv []string) string { return l.T(key, kv...) },
}

func parsePage(names ...string) *template.Template {
	return template.Must(template.New("").Funcs(funcs).ParseFS(files, names...))
}
```

and build `pages`, `formPost` and `webMessage` with `parsePage(...)`.

2. Add `L *i18n.Localizer` to `Tenant`, and change `TenantView`:

```go
// TenantView builds the page branding and language for a tenant.
func TenantView(t *store.Tenant, l *i18n.Localizer) Tenant {
	name := t.FriendlyName
	if name == "" {
		name = t.Name
	}
	return Tenant{Name: name, LogoURL: t.Branding.LogoURL, PrimaryColor: t.Branding.PrimaryColor, L: l}
}
```

3. In `render`, add `if t.L == nil { t.L = i18n.Default() }` before writing.

4. The error page takes a message and an optional technical detail:

```go
type errorData struct{ Message, Detail string }

func RenderError(w http.ResponseWriter, status int, t Tenant, message string) {
	RenderErrorDetail(w, status, t, message, "")
}

// RenderErrorDetail shows a localized message and an optional technical
// detail (OAuth error descriptions stay English).
func RenderErrorDetail(w http.ResponseWriter, status int, t Tenant, message, detail string) {
	render(w, status, "error", t, errorData{Message: message, Detail: detail}, "'self'")
}
```

5. `RenderFormPost(w http.ResponseWriter, l *i18n.Localizer, action string, params url.Values)` treats a nil `l` as `i18n.Default()`. Its template data gains `"L": l`.

- [ ] **Step 3: Templates**

`templates/layout.html`: replace the `<html lang="en">` line, the `<title>`, the logo, and the `<p class="sub">` line as follows. Leave the CSS unchanged; it has no left- or right-specific properties.

```html
<html lang="{{.Tenant.L.Lang}}" dir="{{.Tenant.L.Dir}}">
```

```html
<title>{{block "doctitle" .}}{{template "title" .}}{{end}} · {{.Tenant.Name}}</title>
```

```html
{{if .Tenant.LogoURL}}<img src="{{.Tenant.LogoURL}}" alt="{{t .Tenant.L "zeroauthy.layout.logoAltText"}}">{{end}}
<h1>{{template "title" .}}</h1>
<p class="sub">{{block "description" .}}{{.Tenant.Name}}{{end}}</p>
```

`templates/login.html`:

```html
{{define "title"}}{{t .Tenant.L "login.login.title"}}{{end}}
{{define "description"}}{{t .Tenant.L "login.login.description"}}{{end}}
{{define "content"}}
{{if .Data.Error}}<p class="alert" role="alert">{{.Data.Error}}</p>{{end}}
<form method="post" action="/u/login" novalidate>
<input type="hidden" name="state" value="{{.Data.State}}">
<input type="hidden" name="csrf" value="{{.Data.CSRF}}">
<label for="username">{{t .Tenant.L "login.login.usernamePlaceholder"}}</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" value="{{.Data.Login}}" required autofocus>
<label for="password">{{t .Tenant.L "login.login.passwordPlaceholder"}}</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">{{t .Tenant.L "login.login.buttonText"}}</button>
</form>
{{if .Data.SignupURL}}<p class="alt">{{t .Tenant.L "login.login.signupActionText"}} <a href="{{.Data.SignupURL}}">{{t .Tenant.L "login.login.signupActionLinkText"}}</a></p>{{end}}
{{end}}
```

`templates/signup.html`:

```html
{{define "title"}}{{t .Tenant.L "signup.signup.title"}}{{end}}
{{define "description"}}{{t .Tenant.L "signup.signup.description"}}{{end}}
{{define "content"}}
{{if .Data.Error}}<p class="alert" role="alert">{{.Data.Error}}</p>{{end}}
<form method="post" action="/u/signup" novalidate>
<input type="hidden" name="state" value="{{.Data.State}}">
<input type="hidden" name="csrf" value="{{.Data.CSRF}}">
<label for="email">{{t .Tenant.L "signup.signup.emailPlaceholder"}}</label>
<input id="email" name="email" type="email" autocomplete="email" value="{{.Data.Email}}" required autofocus>
{{if .Data.RequiresUsername}}
<label for="username">{{t .Tenant.L "signup.signup.usernamePlaceholder"}}</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" value="{{.Data.Username}}" required>
{{end}}
<label for="password">{{t .Tenant.L "signup.signup.passwordPlaceholder"}}</label>
<input id="password" name="password" type="password" autocomplete="new-password" required>
<button type="submit">{{t .Tenant.L "signup.signup.buttonText"}}</button>
</form>
<p class="alt">{{t .Tenant.L "signup.signup.loginActionText"}} <a href="{{.Data.LoginURL}}">{{t .Tenant.L "signup.signup.loginActionLinkText"}}</a></p>
{{end}}
```

`templates/error.html`:

```html
{{define "title"}}{{t .Tenant.L "zeroauthy.error.title"}}{{end}}
{{define "content"}}
<p class="alert" role="alert">{{.Data.Message}}</p>
{{if .Data.Detail}}<p class="alt"><small>{{.Data.Detail}}</small></p>{{end}}
<p class="alt">{{t .Tenant.L "zeroauthy.error.description"}}</p>
{{end}}
```

`templates/logged_out.html`:

```html
{{define "title"}}{{t .Tenant.L "zeroauthy.logged-out.title"}}{{end}}
{{define "content"}}
<p>{{t .Tenant.L "zeroauthy.logged-out.description"}}</p>
<p class="alt">{{t .Tenant.L "zeroauthy.logged-out.hint"}}</p>
{{end}}
```

`templates/logout_confirm.html`:

```html
{{define "doctitle"}}{{t .Tenant.L "logout.logout.pageTitle"}}{{end}}
{{define "title"}}{{t .Tenant.L "logout.logout.title"}}{{end}}
{{define "content"}}
<p>{{t .Tenant.L "logout.logout.description"}}</p>
<form method="post" action="/oidc/logout">
<input type="hidden" name="csrf" value="{{.Data.CSRF}}">
<input type="hidden" name="confirm" value="yes">
{{range $name, $values := .Data.Fields}}{{range $values}}<input type="hidden" name="{{$name}}" value="{{.}}">
{{end}}{{end}}<button type="submit">{{t .Tenant.L "logout.logout.acceptButtonText"}}</button>
</form>
{{end}}
```

`templates/form_post.html`:

```html
<!doctype html>
<html lang="{{.L.Lang}}" dir="{{.L.Dir}}">
<head><meta charset="utf-8"><title>{{t .L "zeroauthy.form-post.title"}}</title></head>
<body>
<form method="post" action="{{.Action}}">
{{range $k, $vs := .Params}}{{range $vs}}<input type="hidden" name="{{$k}}" value="{{.}}">
{{end}}{{end}}<noscript><button type="submit">{{t .L "zeroauthy.form-post.buttonText"}}</button></noscript>
</form>
<script nonce="{{.Nonce}}">document.forms[0].submit();</script>
</body>
</html>
```

The login and signup headers now show a description sentence instead of the bare tenant name. If an existing test asserts the old subtitle exactly, update it to the new English sentence and say so in the report.

- [ ] **Step 4: Messages and wiring**

`internal/identity/identity.go`: give `PolicyError` the fields `Key string` and `Vars []string`, and keep `Reason`. Set them where each error is built:
- too long: `Key: i18n.KeyPasswordTooLong`
- too short: `Key: i18n.KeyPasswordTooShort, Vars: []string{"min", strconv.Itoa(minLen)}`
- character classes: `Key: i18n.KeyPasswordClasses, Vars: []string{"count", strconv.Itoa(p.RequireCharacterClasses)}`

In `CheckUsername` (`internal/identity/database.go`), set `Key: i18n.KeyInvalidUsername`.

`internal/authz/request.go`: add `UILocales string` to `Request`, `"ui_locales"` to `paramNames`, and `case "ui_locales": return &r.UILocales` to `field`.

`internal/authz/handlers.go`:
- `Authorize`: replace `view := ui.TenantView(res.Tenant)` with `view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, r.URL.Query().Get("ui_locales")))`. The non-redirectable branch renders `ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrInvalidRequest), verr.Description)`.
- `Resume`: do the same, using `txn.Params["ui_locales"]`.

`internal/authz/response.go`, `form_post` case:

```go
	case "form_post":
		l := i18n.Default()
		if res, ok := tenant.FromContext(r.Context()); ok {
			l = i18n.ForRequest(res.Tenant, r, req.UILocales)
		}
		ui.RenderFormPost(w, l, req.RedirectURI, params)
```

`internal/login/login.go`:
- Delete the `msg*` constants.
- In `load`, after the connection is found, build the view in the transaction's language with the client's name:

```go
	clientName := txn.ClientID
	if c, err := h.Store.Clients().Get(ctx, res.Tenant.ID, txn.ClientID); err == nil && c.Name != "" {
		clientName = c.Name
	}
	l := i18n.ForRequest(res.Tenant, r, txn.Params["ui_locales"]).WithVar("clientName", clientName)
	return &flow{res: res, view: ui.TenantView(res.Tenant, l), txn: txn, conn: conn}, nil
```

- In `fail`, build the view as `ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, ""))`, with no transaction. The messages become `view.L.T(i18n.KeyErrSessionExpired)`, `…KeyErrNoConnection` and `…KeyErrServer`.
- Replace each `data.Error = msgX` and `ui.RenderError(…, msgX)` with `f.view.L.T(<key>)` as follows:

| Old | Key |
|---|---|
| `msgTooMany` | `i18n.KeyTooManyAttempts` |
| `msgBadCredentials` | `i18n.KeyWrongCredentials` |
| `msgBlocked` | `i18n.KeyUserBlocked` |
| `msgUserExists` | `i18n.KeyEmailInUse` |
| `msgSignupDisabled` | `i18n.KeyErrSignupDisabled` |

- A `PolicyError` with a key renders `f.view.L.T(pe.Key, pe.Vars...)`. One without a key keeps `capitalize(pe.Reason) + "."`.

`internal/oidc/logout.go` and `rp_logout.go`:
- Delete the `msgLogout*` constants.
- `Logout`: `view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, ""))`.
- `OidcLogout`: parse the form first. If parsing fails, use `ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, ""))` to render `KeyErrLogoutInvalid`. Otherwise use `i18n.ForRequest(res.Tenant, r, r.Form.Get("ui_locales"))`. This drops the "ui_locales is ignored" behaviour from D-0015.
- Messages map as follows: `msgLogoutUnknownClient` becomes `KeyErrLogoutUnknownClient`, `msgLogoutURL` becomes `KeyErrLogoutURL`, `msgLogoutInvalid` becomes `KeyErrLogoutInvalid`, and `msgLogoutServer` becomes `KeyErrServer`. Each is rendered with `view.L.T(key)`.
- `endSession` takes `view ui.Tenant` already and needs no other change.
- In `api/authentication.yaml`, change the `/oidc/logout` `ui_locales` description to "Language for the confirmation and logged-out pages (first entry only)". Run `go generate ./...`.

- [ ] **Step 5: Run and commit**

Run: `go test -race ./... && go vet ./... && gofmt -l . && go generate ./... && git diff --exit-code internal/gen`
Expected:
- everything passes;
- the existing login, signup and logout tests pass unchanged, apart from any subtitle assertion noted in Step 3;
- the catalog test passes, so every key is used and every used key exists.

```bash
git add internal api
git commit -m "feat(ui): localized hosted pages with per-request language selection"
```

---

### Task 4: End-to-end localization tests across handlers

This task adds tests only, unless one of them exposes a defect. If it does, fix the defect with the failing test first and report DONE_WITH_CONCERNS.

**Files:**
- Modify: `internal/login/login_test.go`, `internal/authz/handlers_test.go`, `internal/oidc/logout_test.go`

**Interfaces:**
- Consumes: everything from Task 3.
- Produces: none.

- [ ] **Step 1: Login and signup**

In `internal/login/login_test.go`, change the `acme` tenant in `loginSeed` to add the following. Existing tests are unaffected, because they never request French.

```yaml
    enabled_locales: [en, fr]
    custom_text:
      login:
        fr:
          login:
            title: "Connexion"
            wrong-credentials: "Identifiant ou mot de passe incorrect."
      signup:
        fr:
          signup:
            title: "Créer un compte"
```

Read `browser.begin` (around line 117) before writing the test. Pass `ui_locales` the same way the other tests pass extra `/authorize` parameters, using its `extra ...string` pairs. Then append:

```go
func TestLoginPagesFollowUILocales(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	rec, state, csrf := b.begin(t, "ui_locales", "fr")
	body := rec.Body.String()
	if !strings.Contains(body, `lang="fr"`) || !strings.Contains(body, "Connexion") || !strings.Contains(body, "Email or username") {
		t.Fatalf("login page not French with English fallback:\n%s", body)
	}
	// A failed login keeps the transaction's language, error included.
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"wrong"}})
	if !strings.Contains(rec.Body.String(), "Identifiant ou mot de passe incorrect.") || !strings.Contains(rec.Body.String(), `lang="fr"`) {
		t.Fatalf("failed login not French:\n%s", rec.Body)
	}
	rec = b.do(t, "GET", "/u/signup?state="+url.QueryEscape(state), nil)
	if !strings.Contains(rec.Body.String(), "Créer un compte") {
		t.Fatalf("signup not French:\n%s", rec.Body)
	}
}

func TestLoginPageFollowsAcceptLanguageAndPolicyVariables(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	rec, state, csrf := b.begin(t)
	if !strings.Contains(rec.Body.String(), `lang="en"`) {
		t.Fatal("default must be English")
	}
	// A short password shows the English policy text with ${min} filled in.
	rec = b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"new@acme.test"}, "password": {"short"}})
	if !strings.Contains(rec.Body.String(), "at least 8 characters") {
		t.Fatalf("policy message:\n%s", rec.Body)
	}
}
```

If `begin` cannot send an `Accept-Language` header, add an `acceptLanguage string` field to `browser` and set the header in `do` when it is non-empty. Then add a third test: with `b.acceptLanguage = "fr-CA,fr;q=0.9"` and no `ui_locales`, the login page has `lang="fr"`.

- [ ] **Step 2: `/authorize` error page and `form_post`**

In `internal/authz/fixture_test.go`, add to the `acme` tenant `enabled_locales: [en, fr]` and:

```yaml
    custom_text:
      zeroauthy:
        fr:
          error:
            invalid-request: "La demande de l'application n'a pas pu aboutir."
          form-post:
            buttonText: "Poursuivre"
```

Append to `internal/authz/handlers_test.go`:

```go
func TestErrorPageAndFormPostAreLocalized(t *testing.T) {
	e := newEnv(t)
	rec := e.get(t, with(goodQuery(), "redirect_uri", "https://evil.test/cb", "ui_locales", "fr"))
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "La demande de l'application n'a pas pu aboutir.") ||
		!strings.Contains(rec.Body.String(), "redirect_uri") {
		t.Fatalf("error page = %d %s", rec.Code, rec.Body)
	}
	ck := e.login(t, fixedNow())
	rec = e.get(t, with(goodQuery(), "response_mode", "form_post", "ui_locales", "fr"), ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Poursuivre") || !strings.Contains(rec.Body.String(), `lang="fr"`) {
		t.Fatalf("form_post = %d %s", rec.Code, rec.Body)
	}
}
```

- [ ] **Step 3: Logout pages**

In `internal/oidc/logout_test.go` `newLogoutEnv`, give the `acme` tenant `EnabledLocales: []string{"en", "fr"}` and:

```go
CustomText: store.CustomText{
	"logout":    {"fr": {"logout": {"title": "Se déconnecter ?"}}},
	"zeroauthy": {"fr": {"logged-out": {"title": "Vous êtes déconnecté"}}},
},
```

Append:

```go
func TestLogoutPagesAreLocalized(t *testing.T) {
	e := newLogoutEnv(t, nil)
	ck, _ := e.login(t)
	// /oidc/logout honours its own ui_locales on the confirmation page.
	rec := e.do(t, "GET", rp(url.Values{"client_id": {"spa"}, "post_logout_redirect_uri": {"https://app.acme.test/bye"}, "ui_locales": {"fr"}}), nil, ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Se déconnecter ?") {
		t.Fatalf("confirmation = %d %s", rec.Code, rec.Body)
	}
	// /v2/logout follows Accept-Language.
	r := httptest.NewRequest("GET", "https://acme.example.test/v2/logout", nil)
	r.Header.Set("Accept-Language", "fr")
	out := httptest.NewRecorder()
	e.srv.ServeHTTP(out, r)
	if out.Code != 200 || !strings.Contains(out.Body.String(), "Vous êtes déconnecté") {
		t.Fatalf("logged-out page = %d %s", out.Code, out.Body)
	}
}
```

- [ ] **Step 4: Run and commit**

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: PASS.

```bash
git add internal
git commit -m "test: localization across login, authorize and logout pages"
```

---

### Task 5: Browser test and documentation

**Files:**
- Modify: `tests/e2e/seed.yaml`
- Create: `tests/e2e/m6-i18n.spec.mjs`, `docs/i18n.md`
- Modify: `docs/compat/decisions.md`, `docs/compat/matrix.md`, `README.md` (only if it lists features), `docs/superpowers/plan-1-followups.md`

- [ ] **Step 1: Seed**

Add the following to the `e2e` tenant in `tests/e2e/seed.yaml`:

```yaml
    enabled_locales: [en, fr]
    custom_text:
      login:
        fr:
          login:
            title: "Connexion à ${companyName}"
            buttonText: "Continuer"
```

- [ ] **Step 2: Spec**

Create `tests/e2e/m6-i18n.spec.mjs`:

```js
// Black-box test (CLEAN_ROOM.md): auth0-spa-js passes ui_locales through
// its public API; zeroauthy renders the login page in French.
import { test, expect } from '@playwright/test';

const SPA = 'https://localhost:3443/';

async function ready(page) {
  await expect(page.locator('body')).toHaveAttribute('data-ready', /true|error/, { timeout: 20_000 });
}

test('ui_locales=fr renders a French login page, then login completes', async ({ page }) => {
  await page.goto(SPA);
  await ready(page);
  await page.evaluate(() => window.__za.client.loginWithRedirect({ authorizationParams: { ui_locales: 'fr' } }));
  await page.waitForURL(/localhost:8443\/u\/login/);
  await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
  await expect(page.locator('h1')).toHaveText('Connexion à E2E');
  await expect(page.locator('button[type=submit]')).toHaveText('Continuer');
  await expect(page.locator('label[for=password]')).toHaveText('Password'); // English fallback
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  await page.click('button[type=submit]');
  await page.waitForURL(SPA);
  await ready(page);
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(true);
});

test.describe('browser language', () => {
  test.use({ locale: 'fr-FR' });
  test('Accept-Language fr-FR selects the enabled fr', async ({ page }) => {
    await page.goto(SPA);
    await ready(page);
    await page.click('#login');
    await page.waitForURL(/localhost:8443\/u\/login/);
    await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
  });
});
```

Run: `./tests/e2e/run-browser.sh`
Expected: `5 passed`.

Debug a failure from the server log and the Playwright trace only. Never read SDK source.

- [ ] **Step 3: Docs**

Append to `docs/compat/decisions.md`:

```markdown
## D-0016: Hosted page languages and custom text

- **Context:** Auth0's public docs describe language selection (`enabled_locales`, `ui_locales`, `Accept-Language`) and per-prompt custom text with `${variables}`. They do not say how region tags relate to base languages, or how missing text falls back.
- **Sources:** https://auth0.com/docs/customize/internationalization-and-localization/universal-login-internationalization; https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements; RFC 5646; RFC 9110 §12.5.4.
- **Decision:**
  - **Language selection:** the language is chosen in this order:
    1. the first `ui_locales` entry, if enabled;
    2. otherwise the first enabled `Accept-Language` entry, by weight;
    3. otherwise the tenant default (the first of `enabled_locales`, else `en`).
    A region tag is matched by an enabled base language (`fr-CA` → `fr`).
  - **Text lookup:** text comes from, in order:
    1. tenant custom text for the language;
    2. the built-in catalog for the language;
    3. the built-in catalog for the base language;
    4. English.
  - **Custom text shape:** prompt → language → screen → key, using Auth0's documented identifiers where a screen matches, and the `zeroauthy` prompt otherwise.
  - **Variables:** `${companyName}` and `${clientName}`, plus message-specific ones. Overrides may use only the variables of the English string. Unset variables render empty.
  - **`/oidc/logout`:** now honours `ui_locales`, which replaces the D-0015 note.
  - **OAuth `error_description`:** stays English.
- **Rationale:** It follows the documented selection order and custom-text shape, so configuration written for Auth0 keeps working. English fallback guarantees that a page never shows a missing string.
```

Also edit D-0015's `ui_locales is ignored` bullet to read `ui_locales selects the page language (D-0016)`.

In `docs/compat/matrix.md`, add this row:

```markdown
| Hosted page languages (`ui_locales`, `Accept-Language`, `enabled_locales`, per-tenant `custom_text`) | Implemented | English catalog only; verified with @auth0/auth0-spa-js 2.28.3 (`ui_locales`) and browser `Accept-Language`; custom-text Management API planned (sub-project 3) |
```

Create `docs/i18n.md`:

~~~markdown
# Translating zeroauthy

Hosted pages (login, signup, logout, errors) read their text from
`internal/i18n/locales/<language>.json`. English (`en.json`) is the
reference; any key a language does not translate falls back to English.

## Add a language

1. Copy `internal/i18n/locales/en.json` to `<tag>.json`, where `<tag>` is a
   BCP 47 tag in lowercase (`fr`, `pt-br`).
2. Translate the values. Keep every `${variable}` exactly as in English;
   you may move it within the sentence. Write your own wording — do not
   copy text from other products.
3. Run `go test ./internal/i18n/`. It fails on unknown keys or changed
   variables.
4. Tenants use the language by listing it in `enabled_locales`.

## Per-tenant wording

Operators override any key per tenant in the seed file:

```yaml
custom_text:
  login:            # prompt
    fr:             # language (must be in enabled_locales)
      login:        # screen
        title: "Connexion à ${companyName}"
```

Available variables: `${companyName}`, `${clientName}`, and the ones the
English string for that key uses.
~~~

In `docs/superpowers/plan-1-followups.md`, add a `## Plan 4 follow-ups` section with these items:
- `PUT /prompts/{prompt}/custom-text/{language}` and `GET /prompts/{prompt}/custom-text/{language}` are planned for sub-project 3; storage is ready.
- RTL layout needs a visual review once an RTL catalog exists.
- Email templates must use the catalog in milestone 6.

If `README.md` has a feature list, add "Localized hosted pages (`ui_locales`, `Accept-Language`, per-tenant text)".

- [ ] **Step 4: Verify and commit**

Run: `go test -race ./... && go vet ./... && gofmt -l . && make e2e`
Expected: everything passes. run-m3 reports OK, and run-browser reports `5 passed`.

```bash
git add tests/e2e docs README.md
git commit -m "test(e2e): French login via ui_locales and Accept-Language; i18n docs"
```

---

## Plan Self-Review (completed by the planner)

**Spec coverage:**
- §3 selection: Task 1, wired in Task 3, tested in Tasks 4 and 5.
- §4 lookup and variables: Task 1.
- §5 catalogs and keys: Tasks 1 and 3, including the catalog test.
- §6 tenant settings and validation: Tasks 1 and 2.
- §7 code changes: Task 3.
- §8 tests: Tasks 1 through 5.
- §9 docs: Task 5.
- §10 out of scope: Out of Scope section.

**Rulings taken while planning:**
1. **Variables in overrides:** the spec rejected placeholders that "differ from the English string". This plan reads that as "an override may use only the variables the English string uses". Omitting a variable is allowed.
2. **Error page:** `/authorize` error pages show a localized generic message, plus the English OAuth description as a technical detail.
3. **Default subtitle:** the login and signup headers gain an original description sentence, `login.login.description` and `signup.signup.description`, in place of the bare tenant name.

**Type consistency:**
- `TenantView(t, l)`, `Localizer.T/Lang/Dir/WithVar`, `ForRequest` and `Key*` are used identically in Tasks 3 and 4.
- `store.CustomText` is used identically in Tasks 1, 2 and 4.
- `RenderFormPost(w, l, action, params)` is used in Task 3 only.

**Review Focus mapping:**
1. Task 1 `TestNegotiate`.
2. Task 1 `TestNegotiate` ("only the first ui_locales entry counts", "disabled ui_locales falls through").
3. Task 3 `TestCustomTextIsEscaped`.
4. Task 1 `TestValidateCustomText` and Task 2 "foreign variable".
5. Task 4 `TestLoginPagesFollowUILocales`.
