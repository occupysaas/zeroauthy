package passwordless

import (
	"encoding/base64"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/phonerules"
)

func TestNewCodeLength(t *testing.T) {
	if phonerules.Limits.OTPLengthMin != 4 || phonerules.Limits.OTPLengthMax < 10 {
		t.Fatalf("unexpected limits %+v", phonerules.Limits)
	}
	for length := 4; length <= 10; length++ {
		var seen [10]int
		for i := 0; i < 10000; i++ {
			c := NewCode(length)
			if len(c) != length {
				t.Fatalf("length %d: got %q", length, c)
			}
			for _, r := range c {
				if r < '0' || r > '9' {
					t.Fatalf("non-digit in %q", c)
				}
				seen[r-'0']++
			}
		}
		for d, n := range seen {
			if n == 0 {
				t.Errorf("length %d: digit %d never produced", length, d)
			}
			// 10000*length samples over 10 digits; allow wide tolerance.
			exp := 10000 * length / 10
			if n < exp*8/10 || n > exp*12/10 {
				t.Errorf("length %d: digit %d count %d outside 20%% of %d", length, d, n, exp)
			}
		}
	}
}

func TestNewCodeLeadingZeros(t *testing.T) {
	for i := 0; i < 10000; i++ {
		if NewCode(6)[0] == '0' {
			return
		}
	}
	t.Fatal("no leading zero in 10000 codes")
}

func TestNewLinkToken(t *testing.T) {
	a, b := NewLinkToken(), NewLinkToken()
	raw, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil || len(raw) != phonerules.Limits.LinkTokenBytes || len(raw) != 32 {
		t.Fatalf("token %q decode=%v len=%d", a, err, len(raw))
	}
	if a == b {
		t.Fatal("tokens repeat")
	}
}
