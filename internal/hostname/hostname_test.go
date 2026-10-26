package hostname

import "testing"

func TestNormalize(t *testing.T) {
	for _, tt := range []struct {
		in, want string
		operator bool
	}{
		{"BÜCHER.customer.example.", "xn--bcher-kva.customer.example", false},
		{"LOCALHOST:8080", "localhost:8080", true},
		{"localhost", "localhost", true},
		{"login.example:443", "", false},
		{"https://login.example", "", true},
		{"a..example", "", true},
	} {
		var got string
		var err error
		if tt.operator {
			got, err = NormalizeOperatorHost(tt.in)
		} else {
			got, err = NormalizeDNSName(tt.in)
		}
		if got != tt.want || (err != nil) != (tt.want == "") {
			t.Errorf("%q: got (%q,%v), want %q", tt.in, got, err, tt.want)
		}
	}
}

// Privileged aliases retain legacy local/IP forms and use the same :443
// equivalence as tenant host routing. Public custom-domain names remain DNS-only.
func TestOperatorLegacyHostEquivalence(t *testing.T) {
	for _, tt := range []struct{ raw, want string }{
		{"127.0.0.1", "127.0.0.1"},
		{"127.0.0.1:443", "127.0.0.1"},
		{"127.0.0.1:8443", "127.0.0.1:8443"},
		{"[::1]", "[::1]"},
		{"[::1]:443", "[::1]"},
		{"[::1]:8443", "[::1]:8443"},
		{"[0:0:0:0:0:0:0:1]:443", "[::1]"},
		{"[2001:DB8::1]:65535", "[2001:db8::1]:65535"},
		{"LOCALHOST:443", "localhost"},
		{"LOGIN.Example.COM.:443", "login.example.com"},
		{"BÜCHER.customer.example.:443", "xn--bcher-kva.customer.example"},
	} {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := NormalizeOperatorHost(tt.raw)
			if err != nil || got != tt.want {
				t.Fatalf("got (%q,%v),want %q", got, err, tt.want)
			}
		})
	}
	for _, raw := range []string{"127.0.0.1:0", "127.0.0.1:65536", "[::1]:-1", "[::1]:abc", "[bad]:443", "user@127.0.0.1:443", "https://127.0.0.1", "127.0.0.1/path"} {
		t.Run("invalid/"+raw, func(t *testing.T) {
			if got, err := NormalizeOperatorHost(raw); err == nil {
				t.Fatalf("accepted invalid operator host: %q", got)
			}
		})
	}
	for _, raw := range []string{"127.0.0.1", "127.0.0.1:443", "[::1]", "[::1]:443", "::1"} {
		t.Run("public/"+raw, func(t *testing.T) {
			if got, err := NormalizeDNSName(raw); err == nil {
				t.Fatalf("accepted public IP alias: %q", got)
			}
		})
	}
}
