package httpx

import (
	"net/http/httptest"
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
