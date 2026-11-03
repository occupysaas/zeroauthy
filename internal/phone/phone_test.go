package phone

import (
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/phonerules"
)

func TestNormalizeE164(t *testing.T) {
	ok := []struct{ raw, region, want string }{
		{"+1 (415) 555-0100", "", "+14155550100"},
		{"+44 20 7946 0958", "", "+442079460958"},
		{"(415) 555-0100", "US", "+14155550100"},
		{"020 7946 0958", "GB", "+442079460958"},
		{"0044 20 7946 0958", "US", "+442079460958"},
		{"+1-415-555-0100", "GB", "+14155550100"},
		{"  +12345678  ", "", "+12345678"},
	}
	for _, c := range ok {
		got, err := NormalizeE164(c.raw, c.region)
		if err != nil || got != c.want {
			t.Errorf("NormalizeE164(%q,%q)=%q,%v want %q", c.raw, c.region, got, err, c.want)
		}
	}
	bad := []struct{ raw, region string }{
		{"0044 20 7946 0958", ""},
		{"4155550100", ""},
		{"+1234567", ""},          // 7 digits
		{"+1234567890123456", ""}, // 16 digits
		{"+1 415 555 0100 ext 5", ""},
		{"+1415555010a", ""},
		{"", "US"},
		{"+", ""},
		{"+0155501000", ""},
		{"4155550100", "ZZ"},
		{"+1 415 +555 0100", ""},
	}
	for _, c := range bad {
		if got, err := NormalizeE164(c.raw, c.region); !errors.Is(err, ErrInvalidPhone) || got != "" {
			t.Errorf("NormalizeE164(%q,%q)=%q,%v want ErrInvalidPhone", c.raw, c.region, got, err)
		}
	}
	if _, err := NormalizeE164("+123456789012345", ""); err != nil {
		t.Errorf("15 digits rejected: %v", err)
	}
}

func TestCountryCode(t *testing.T) {
	for e164, want := range map[string]string{
		"+442079460958":  "GB",
		"+14155550100":   "US",
		"+16475550100":   "CA",
		"+14165550100":   "CA",
		"+18765550100":   "JM",
		"+33142685300":   "FR",
		"+4915112345678": "DE",
		"+61291234567":   "AU",
		"+351912345678":  "PT",
		"+972501234567":  "IL",
		"+79123456789":   "RU",
		"+77011234567":   "KZ",
		"+0000000":       "",
		"":               "",
		"14155550100":    "",
	} {
		if got := CountryCode(e164); got != want {
			t.Errorf("CountryCode(%q)=%q want %q", e164, got, want)
		}
	}
}

func TestMaskPhone(t *testing.T) {
	for _, n := range []string{"+14155550100", "+442079460958", "+1", "1234", "12345", ""} {
		if got, want := Mask(n), phonerules.MaskPhone(n); got != want {
			t.Errorf("Mask(%q)=%q want %q", n, got, want)
		}
	}
	if got := Mask("+14155556220"); got != "XXXXXXXX6220" {
		t.Errorf("Mask=%q", got)
	}
	if got := Mask("1234"); got != "XXXX" {
		t.Errorf("short Mask=%q", got)
	}
}
