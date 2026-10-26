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
