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
