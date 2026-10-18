package tenant

import "testing"

func TestValidNameAndDomain(t *testing.T) {
	for name, want := range map[string]bool{"acme": true, "a-1": true, "a": true, "": false, "-a": false, "a-": false,
		"Acme": false, "a.b": false, "a_b": false, string(make([]byte, 64)): false} {
		if ValidName(name) != want {
			t.Errorf("ValidName(%q) = %v", name, !want)
		}
	}
	for d, want := range map[string]bool{"login.acme.test": true, "127.0.0.1:8443": true, "[::1]:8443": true,
		"": false, "a/b": false, "user@host": false, "host?x": false, "host#x": false, "https://host": false} {
		if ValidDomain(d) != want {
			t.Errorf("ValidDomain(%q) = %v", d, !want)
		}
	}
}
