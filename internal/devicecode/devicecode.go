// Package devicecode generates, validates and formats the user codes of
// the device authorization grant (RFC 8628).
package devicecode

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"unicode"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

const (
	CharsetBase20 = "base20"
	CharsetDigits = "digits"
	DefaultMask   = "****-****"
	Base20        = "BCDFGHJKLMNPQRSTVWXZ" // D2
	Digits        = "0123456789"

	maxMaskLen = 20
)

// Settings returns the effective charset and mask ("" selects defaults).
// The default mask for digits is three groups of three.
func Settings(t *store.Tenant) (charset, mask string) {
	charset, mask = t.DeviceFlowCharset, t.DeviceFlowMask
	if charset == "" {
		charset = CharsetBase20
	}
	if mask == "" {
		mask = DefaultMask
		if charset == CharsetDigits {
			mask = "***-***-***"
		}
	}
	return charset, mask
}

func alphabet(charset string) string {
	if charset == CharsetDigits {
		return Digits
	}
	return Base20
}

// ValidateMask checks a mask for charset: only '*', '-' and ' ' (D2);
// at least 8 (base20) or 9 (digits) '*'; at most 20 characters.
func ValidateMask(charset, mask string) error {
	if charset != CharsetBase20 && charset != CharsetDigits {
		return fmt.Errorf("charset %q must be %s or %s", charset, CharsetBase20, CharsetDigits)
	}
	if len(mask) > maxMaskLen {
		return fmt.Errorf("mask must be at most %d characters", maxMaskLen)
	}
	stars := 0
	for _, r := range mask {
		switch r {
		case '*':
			stars++
		case '-', ' ':
		default:
			return fmt.Errorf("mask may only contain '*', '-' and ' '")
		}
	}
	need := 8
	if charset == CharsetDigits {
		need = 9
	}
	if stars < need {
		return fmt.Errorf("mask needs at least %d '*' for charset %s", need, charset)
	}
	return nil
}

// Generate returns a random code shaped by mask, '*' replaced by a
// crypto/rand character from charset.
// An unknown charset is an error.
func Generate(charset, mask string) (string, error) {
	if charset != CharsetBase20 && charset != CharsetDigits {
		return "", fmt.Errorf("devicecode: unknown charset %q", charset)
	}
	chars := alphabet(charset)
	max := big.NewInt(int64(len(chars)))
	var b strings.Builder
	for _, r := range mask {
		if r != '*' {
			b.WriteRune(r)
			continue
		}
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic("devicecode: crypto/rand failed: " + err.Error())
		}
		b.WriteByte(chars[n.Int64()])
	}
	return b.String(), nil
}

// Normalize upper-cases s and drops every character that is not a letter
// or digit. The result is what gets hashed.
func Normalize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Format re-applies mask to a normalized code for display; a code whose
// length does not match the mask's placeholders is returned unchanged.
func Format(normalized, mask string) string {
	if len([]rune(normalized)) != strings.Count(mask, "*") {
		return normalized
	}
	rs := []rune(normalized)
	var b strings.Builder
	i := 0
	for _, r := range mask {
		if r == '*' {
			b.WriteRune(rs[i])
			i++
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
