package httpx

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("POST", "/u/login", nil)
	r.RemoteAddr = "10.0.0.1:4444"
	r.Header.Set("X-Forwarded-For", "spoofed, 203.0.113.9")
	if got := ClientIP(r, false); got != "10.0.0.1" {
		t.Errorf("untrusted = %q", got)
	}
	if got := ClientIP(r, true); got != "203.0.113.9" {
		t.Errorf("trusted = %q", got)
	}
	r.Header.Del("X-Forwarded-For")
	if got := ClientIP(r, true); got != "10.0.0.1" {
		t.Errorf("no header = %q", got)
	}
}

func TestRecordedIP(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":         "203.0.113.9",
		"2001:DB8::1":         "2001:db8::1",
		"fe80::1%eth0":        "fe80::1",
		"::ffff:192.0.2.1":    "::ffff:192.0.2.1",
		"not-an-ip":           "",
		"203.0.113.9\x00evil": "",
		"<script>":            "",
		"":                    "",
	} {
		if got := CanonicalIP(in); got != want {
			t.Errorf("CanonicalIP(%q) = %q, want %q", in, got, want)
		}
	}
	r := httptest.NewRequest("POST", "/u/login", nil)
	r.RemoteAddr = "10.0.0.1:4444"
	r.Header.Set("X-Forwarded-For", "10.0.0.2, "+strings.Repeat("x", 300))
	if got := RecordedIP(r, true); got != "" {
		t.Errorf("hostile header = %q", got)
	}
	if got := RecordedIP(r, false); got != "10.0.0.1" {
		t.Errorf("untrusted = %q", got)
	}
}

// An address established by an authenticated proxy boundary wins over
// forwarded headers and the peer, whatever the legacy trust setting.
func TestClientIPFromContext(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.1")
	r = r.WithContext(WithClientIP(r.Context(), netip.MustParseAddr("2001:db8::7")))
	for _, trust := range []bool{true, false} {
		if got := ClientIP(r, trust); got != "2001:db8::7" {
			t.Errorf("trust=%v: %q", trust, got)
		}
	}
}
