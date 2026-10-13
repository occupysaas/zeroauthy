package tenant

import "testing"

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"acme.example.test":      "acme.example.test",
		"ACME.Example.TEST":      "acme.example.test",
		"acme.example.test.":     "acme.example.test",
		"acme.example.test:443":  "acme.example.test",
		"acme.example.test.:443": "acme.example.test",
		"localhost:8443":         "localhost:8443",
		" acme.example.test ":    "acme.example.test",
		"[::1]:8443":             "[::1]:8443",
		"[::1]:443":              "[::1]",
		"[::1]":                  "[::1]",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
