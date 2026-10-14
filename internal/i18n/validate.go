package i18n

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/text/language"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ValidateLocales checks enabled_locales: valid BCP 47 tags written in
// canonical form, naming a language (no "und", private-use "x-" or
// grandfathered "i-" tags), with no duplicates (case-insensitive).
func ValidateLocales(tags []string) error {
	var errs []error
	seen := map[string]bool{}
	for _, t := range tags {
		if err := checkLocale(t); err != nil {
			errs = append(errs, err)
			continue
		}
		if seen[strings.ToLower(t)] {
			errs = append(errs, fmt.Errorf("duplicate locale %q", t))
		}
		seen[strings.ToLower(t)] = true
	}
	return errors.Join(errs...)
}

func checkLocale(t string) error {
	tag, err := language.Parse(t)
	if err != nil || t == "" {
		return fmt.Errorf("%q is not a valid language tag", t)
	}
	lower := strings.ToLower(t)
	switch {
	case strings.HasPrefix(lower, "x-"):
		return fmt.Errorf("%q is not a valid language tag: private-use tags are not supported", t)
	case strings.HasPrefix(lower, "i-"):
		return fmt.Errorf("%q is not a valid language tag: grandfathered tags are not supported", t)
	}
	if _, conf := tag.Base(); conf != language.Exact {
		return fmt.Errorf("%q is not a valid language tag: undetermined language", t)
	}
	if c := tag.String(); c != t {
		return fmt.Errorf("%q is not in canonical form; use %q", t, c)
	}
	return nil
}

// zeroauthyPrompt is the custom-text prompt for zeroauthy's own keys.
const zeroauthyPrompt = "zeroauthy"

// universalVars are set on every page, so any text may use them.
var universalVars = []string{"companyName", "clientName"}

// ValidateCustomText checks overrides against the English catalog: every
// language enabled and every text non-empty. Keys in en.json may use only
// the variables the English string uses, plus the page-wide companyName and
// clientName. Unknown keys are rejected under the zeroauthy prompt and
// accepted but ignored elsewhere (documented Auth0 keys for screens
// zeroauthy does not render).
func ValidateCustomText(enabled []string, ct store.CustomText) error {
	if len(enabled) == 0 {
		enabled = []string{"en"}
	}
	var errs []error
	for prompt, langs := range ct {
		seenLang := map[string]bool{}
		for lang, screens := range langs {
			if seenLang[strings.ToLower(lang)] {
				errs = append(errs, fmt.Errorf("custom_text.%s: language %q is given more than once (case-insensitive)", prompt, lang))
				continue
			}
			seenLang[strings.ToLower(lang)] = true
			if _, err := language.Parse(lang); err != nil || lang == "" {
				errs = append(errs, fmt.Errorf("custom_text.%s: %q is not a valid language tag", prompt, lang))
				continue
			}
			if !slices.ContainsFunc(enabled, func(e string) bool { return strings.EqualFold(e, lang) }) {
				errs = append(errs, fmt.Errorf("custom_text.%s: %q is not an enabled locale", prompt, lang))
				continue
			}
			for screen, keys := range screens {
				for k, text := range keys {
					full := prompt + "." + screen + "." + k
					if strings.TrimSpace(text) == "" {
						errs = append(errs, fmt.Errorf("custom_text.%s.%s: %q is empty; remove it to use the built-in text", prompt, lang, full))
						continue
					}
					en, ok := catalogs["en"][full]
					if !ok {
						// Auth0 documents many keys for screens zeroauthy does
						// not render; accept and ignore them. The zeroauthy
						// prompt is ours, so an unknown key there is a typo.
						if prompt == zeroauthyPrompt {
							errs = append(errs, fmt.Errorf("custom_text.%s.%s: unknown key %q", prompt, lang, full))
						}
						continue
					}
					allowed := append(Placeholders(en), universalVars...)
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
