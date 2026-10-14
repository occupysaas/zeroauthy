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

// universalVars are set on every page, so any text may use them.
var universalVars = []string{"companyName", "clientName"}

// ValidateCustomText checks overrides against the English catalog: every
// language enabled, every key known, and only the variables the English
// string uses, plus the page-wide companyName and clientName.
func ValidateCustomText(enabled []string, ct store.CustomText) error {
	if len(enabled) == 0 {
		enabled = []string{"en"}
	}
	var errs []error
	for prompt, langs := range ct {
		for lang, screens := range langs {
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
					en, ok := catalogs["en"][full]
					if !ok {
						errs = append(errs, fmt.Errorf("custom_text.%s.%s: unknown key %q", prompt, lang, full))
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
