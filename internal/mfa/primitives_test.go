package mfa

import (
	"bytes"
	"encoding/base32"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mfarules"
)

func TestTOTPRFC6238Vectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, v := range []struct {
		at   int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}} {
		if step, ok := VerifyTOTP(secret, v.code, time.Unix(v.at, 0)); !ok || step != v.at/30 {
			t.Errorf("time %d: step=%d ok=%v", v.at, step, ok)
		}
	}
	if _, ok := VerifyTOTP("invalid!", "287082", time.Unix(59, 0)); ok {
		t.Error("invalid secret accepted")
	}
	if _, ok := VerifyTOTP(secret, " 287082", time.Unix(59, 0)); ok {
		t.Error("malformed code accepted")
	}
	s := NewTOTPSecret()
	if len(s) != 32 {
		t.Fatalf("secret length %d", len(s))
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s); err != nil {
		t.Fatal(err)
	}
}
func TestTOTPWindow(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, delta := range []int64{-2, -1, 0, 1, 2} {
		step, ok := VerifyTOTP(secret, "287082", time.Unix(59+delta*30, 0))
		if ok != (delta >= -1 && delta <= 1) || (ok && step != 1) {
			t.Errorf("delta %d: %d %v", delta, step, ok)
		}
	}
}
func TestRecoveryCodeFormat(t *testing.T) {
	seen := map[string]bool{}
	re := regexp.MustCompile(`^[A-Z0-9]{24}$`)
	for i := 0; i < 10000; i++ {
		s := NewRecoveryCode()
		if !re.MatchString(s) || seen[s] {
			t.Fatalf("invalid or duplicate %q", s)
		}
		seen[s] = true
	}
}
func TestNormalizeRecoveryCode(t *testing.T) {
	if got := NormalizeRecoveryCode(" ab-cD 12 "); got != "ABCD12" {
		t.Fatal(got)
	}
}
func TestIDFormats(t *testing.T) {
	for i := 0; i < 100; i++ {
		if !regexp.MustCompile(mfarules.MethodIDPattern).MatchString(NewMethodID("totp")) || !regexp.MustCompile(mfarules.EnrollmentIDPattern).MatchString(NewEnrollmentID()) {
			t.Fatal("invalid ID")
		}
		if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(NewEmailCode()) {
			t.Fatal("invalid email code")
		}
	}
}
func TestTOTPURI(t *testing.T) {
	got := TOTPURI("Example & Co", "a+b@example.com", "ABC234")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/Example & Co:a+b@example.com" || u.Query().Get("issuer") != "Example & Co" || u.Query().Get("secret") != "ABC234" {
		t.Fatal(got)
	}
	if strings.Contains(got, " ") {
		t.Fatal(got)
	}
}
func TestQRSVGDecodes(t *testing.T) {
	const fixed = "otpauth://totp/Example:person%40example.com?issuer=Example&secret=JBSWY3DPEHPK3PXP"
	golden, err := os.ReadFile("testdata/totp.svg")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(QRSVG(fixed), golden) {
		t.Fatal("QR differs from independently decoded golden SVG")
	}
	if QRSVG(strings.Repeat("x", 214)) != nil {
		t.Fatal("oversize input accepted")
	}

	convert, e := exec.LookPath("convert")
	if e != nil {
		t.Skip("ImageMagick unavailable")
	}
	decoder, e := exec.LookPath("zbarimg")
	if e != nil {
		t.Skip("zbarimg unavailable")
	}
	for _, value := range []string{"hello", fixed, strings.Repeat("a", 20), strings.Repeat("a", 40), strings.Repeat("a", 60), strings.Repeat("a", 80), strings.Repeat("a", 100), strings.Repeat("a", 120), strings.Repeat("a", 150), strings.Repeat("a", 180), strings.Repeat("a", 200)} {
		dir := t.TempDir()
		svg := filepath.Join(dir, "qr.svg")
		png := filepath.Join(dir, "qr.png")
		if err := os.WriteFile(svg, QRSVG(value), 0600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(convert, "-density", "300", svg, png).CombinedOutput(); err != nil {
			t.Fatalf("convert: %v %s", err, out)
		}
		out, err := exec.Command(decoder, "--quiet", "--raw", png).Output()
		if err != nil || strings.TrimSpace(string(out)) != value {
			t.Fatalf("decode length %d: %v %q", len(value), err, out)
		}
	}
}
