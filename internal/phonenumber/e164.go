// Package phonenumber holds pure E.164 normalization and country resolution.
package phonenumber

import (
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/phonerules"
)

// ErrInvalidPhone reports a number that cannot be normalised to E.164.
var ErrInvalidPhone = errors.New("invalid phone number")

// NormalizeE164 strips spaces, dashes, dots and parentheses and returns the
// number as +<digits>. A number without a leading + (or 00) needs defaultRegion
// (ISO 3166 alpha-2) to supply the calling code; a single leading trunk 0 is
// dropped outside the +1 region. The result has phonerules.Limits.PhoneDigitsMin
// to PhoneDigitsMax digits and never starts with 0.
func NormalizeE164(raw, defaultRegion string) (string, error) {
	var b strings.Builder
	for i, r := range strings.TrimSpace(raw) {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && i == 0:
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '.' || r == '(' || r == ')':
		default:
			return "", ErrInvalidPhone
		}
	}
	s := b.String()
	var digits string
	switch {
	case strings.HasPrefix(s, "+"):
		digits = s[1:]
	case strings.HasPrefix(s, "00"):
		if defaultRegion == "" {
			return "", ErrInvalidPhone
		}
		digits = s[2:]
	default:
		code, ok := regionCode[strings.ToUpper(defaultRegion)]
		if !ok || s == "" {
			return "", ErrInvalidPhone
		}
		switch {
		case code == "1":
			// National trunk prefix 1 in front of a 10-digit number.
			if len(s) == 11 && s[0] == '1' {
				s = s[1:]
			}
		case !keepLeadingZero[strings.ToUpper(defaultRegion)]:
			s = strings.TrimPrefix(s, "0")
		}
		digits = code + s
	}
	lim := phonerules.Limits
	if len(digits) < lim.PhoneDigitsMin || len(digits) > lim.PhoneDigitsMax || digits[0] == '0' {
		return "", ErrInvalidPhone
	}
	return "+" + digits, nil
}

// keepLeadingZero lists regions whose national numbers begin with a 0 that is
// part of the number, not a trunk prefix.
var keepLeadingZero = map[string]bool{"IT": true, "SM": true, "VA": true}

// CountryCode returns the ISO 3166 alpha-2 country of an E.164 number from the
// in-tree calling-code table, or "" when unknown. +1 resolves to CA for the
// Canadian area codes and otherwise to US (the table has no other NANP split
// except the Caribbean entries).
func CountryCode(e164 string) string {
	if !strings.HasPrefix(e164, "+") || len(e164) < 2 {
		return ""
	}
	digits := e164[1:]
	for _, c := range digits {
		if c < '0' || c > '9' {
			return ""
		}
	}
	if digits[0] == '1' && len(digits) >= 4 {
		if c, ok := nanpArea[digits[1:4]]; ok {
			return c
		}
		return "US"
	}
	for n := 3; n >= 1; n-- {
		if len(digits) < n {
			continue
		}
		if c, ok := callingCode[digits[:n]]; ok {
			if digits[:n] == "7" && len(digits) > 1 && (digits[1] == '6' || digits[1] == '7') {
				return "KZ"
			}
			return c
		}
	}
	return ""
}

// Countries lists supported ISO country codes in stable order.
func Countries() []string { return slices.Sorted(maps.Keys(regionCode)) }
