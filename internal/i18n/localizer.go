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
		for customLang, screens := range langs {
			if !strings.EqualFold(customLang, lang) {
				continue
			}
			for screen, keys := range screens {
				for k, v := range keys {
					l.custom[prompt+"."+screen+"."+k] = v
				}
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

// Lang returns the chosen language tag ("en" for a nil localizer).
func (l *Localizer) Lang() string {
	if l == nil || l.lang == "" {
		return "en"
	}
	return l.lang
}

// Dir returns "rtl" for right-to-left languages and "ltr" otherwise.
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
