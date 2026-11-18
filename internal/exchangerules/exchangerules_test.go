package exchangerules

import (
	"strings"
	"testing"
)

func TestValidateSubjectTokenType(t *testing.T) {
	for in, want := range map[string]string{
		"urn:acme:legacy":                 "",
		"https://acme.example/t":          "",
		"http://acme.example/t":           "https://",
		"urn:ietf:params:x":               "reserved",
		"URN:Auth0:x-token":               "https://",
		"https://okta.com/x":              "reserved",
		"urn:a":                           "8 to 100",
		"urn:" + strings.Repeat("a", 100): "8 to 100",
	} {
		err := ValidateSubjectTokenType(in)
		if (want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", in, err, want)
		}
	}
	if ValidateName("ab") == nil || ValidateName("abc") != nil || ValidateName(strings.Repeat("a", 51)) == nil {
		t.Error("name bounds")
	}
}
