package devicecode

import (
	"regexp"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestGenerate(t *testing.T) {
	re := regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)
	seen := map[string]bool{}
	for range 1000 {
		c := Generate(CharsetBase20, "****-****")
		if !re.MatchString(c) {
			t.Fatalf("bad code %q", c)
		}
		if seen[c] {
			t.Fatalf("duplicate %q", c)
		}
		seen[c] = true
	}
	d := regexp.MustCompile(`^\d{3}-\d{3}-\d{3}$`)
	for range 1000 {
		if c := Generate(CharsetDigits, "***-***-***"); !d.MatchString(c) {
			t.Fatalf("bad code %q", c)
		}
	}
}

func TestNormalize(t *testing.T) {
	for _, in := range []string{"bcdf-ghjk", "BCDF GHJK", " bcdfghjk\n"} {
		if got := Normalize(in); got != "BCDFGHJK" {
			t.Errorf("Normalize(%q) = %q", in, got)
		}
	}
}

func TestFormat(t *testing.T) {
	if got := Format("BCDFGHJK", "****-****"); got != "BCDF-GHJK" {
		t.Errorf("got %q", got)
	}
	if got := Format("BCDF", "****-****"); got != "BCDF" {
		t.Errorf("got %q", got)
	}
}

func TestValidateMask(t *testing.T) {
	cases := []struct {
		charset, mask string
		ok            bool
	}{
		{CharsetBase20, "****-***", false},
		{CharsetBase20, "****-****", true},
		{CharsetDigits, "*********", true},
		{CharsetDigits, "****-****", false},
		{CharsetBase20, strings.Repeat("*", 21), false},
		{CharsetBase20, "****_****", false},
	}
	for _, c := range cases {
		if err := ValidateMask(c.charset, c.mask); (err == nil) != c.ok {
			t.Errorf("ValidateMask(%q, %q) = %v", c.charset, c.mask, err)
		}
	}
	cs, m := Settings(&store.Tenant{})
	if err := ValidateMask(cs, m); err != nil {
		t.Errorf("defaults: %v", err)
	}
	cs, m = Settings(&store.Tenant{DeviceFlowCharset: CharsetDigits})
	if err := ValidateMask(cs, m); err != nil {
		t.Errorf("digits defaults: %v", err)
	}
}
