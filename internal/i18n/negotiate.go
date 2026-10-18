package i18n

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/text/language"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Enabled returns the tenant's enabled locales; the first is the default.
func Enabled(t *store.Tenant) []string {
	if t == nil || len(t.EnabledLocales) == 0 {
		return []string{"en"}
	}
	return slices.Clone(t.EnabledLocales)
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
	for _, tag := range acceptedTags(acceptLanguage) {
		if l, ok := match(enabled, tag); ok {
			return l
		}
	}
	return enabled[0]
}

// maxAcceptEntries bounds the Accept-Language entries considered: only the
// first 1024 comma-separated entries.
const maxAcceptEntries = 1024

// acceptedTags returns the tags of an Accept-Language header in descending
// q order (header order breaks ties), skipping q=0 and malformed entries. The
// q parameter name is matched case-insensitively (RFC 9110 §12.4.2). It
// is deliberately tolerant: one bad entry never discards the rest, unlike
// language.ParseAcceptLanguage, which fails the whole header.
func acceptedTags(header string) []string {
	type entry struct {
		tag string
		q   float64
	}
	var entries []entry
	// SplitN caps the work before splitting; the extra element holds the
	// unsplit remainder and is dropped.
	for i, part := range strings.SplitN(header, ",", maxAcceptEntries+1) {
		if i >= maxAcceptEntries {
			break
		}
		fields := strings.Split(part, ";")
		tag := strings.TrimSpace(fields[0])
		if tag == "" || tag == "*" {
			continue
		}
		q := 1.0
		for _, p := range fields[1:] {
			p = strings.TrimSpace(p)
			if name, v, ok := strings.Cut(p, "="); ok && strings.EqualFold(strings.TrimSpace(name), "q") {
				v = strings.TrimSpace(v)
				f, err := strconv.ParseFloat(v, 64)
				if err != nil || f < 0 || f > 1 {
					q = 0
				} else {
					q = f
				}
			}
		}
		if q > 0 {
			entries = append(entries, entry{tag, q})
		}
	}
	slices.SortStableFunc(entries, func(a, b entry) int { return cmp.Compare(b.q, a.q) })
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.tag
	}
	return out
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
