package federation

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFederationProfile(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		bad        bool
	}{
		{"minimal", `{"user_id":"subject"}`, false}, {"false retained", `{"user_id":"subject","email_verified":false}`, false},
		{"missing subject", `{"email":"a@example.com"}`, true}, {"empty subject", `{"user_id":""}`, true},
		{"delimiters", `{"user_id":"provider|part|subject"}`, false}, {"nul", `{"user_id":"a\u0000b"}`, true},
		{"limit", `{"user_id":"` + strings.Repeat("é", 512) + `"}`, false}, {"over limit", `{"user_id":"` + strings.Repeat("é", 513) + `"}`, true},
		{"null string", `{"user_id":"s","email":null}`, true}, {"verification string", `{"user_id":"s","email_verified":"false"}`, true},
		{"http picture", `{"user_id":"s","picture":"http://example.com/a"}`, true},
		{"root metadata", `{"user_id":"s","app_metadata":{}}`, true}, {"blocked", `{"user_id":"s","blocked":false}`, true},
		{"identities", `{"user_id":"s","identities":[]}`, true}, {"password", `{"user_id":"s","password":"x"}`, true},
		{"local claims", `{"user_id":"s","roles":["admin"]}`, true},
		{"extra ignored", `{"user_id":"s","unmapped_claim":"x"}`, false},
		{"explicit metadata", `{"user_id":"s","user_metadata":{"theme":"dark"}}`, false},
		{"metadata array", `{"user_id":"s","user_metadata":[]}`, true},
		{"pollution", `{"user_id":"s","user_metadata":{"nested":{"__proto__":{}}}}`, true},
		{"metadata too large", `{"user_id":"s","user_metadata":{"x":"` + strings.Repeat("x", 16384) + `"}}`, true},
		{"invalid utf8", string([]byte{'{', '"', 'u', 's', 'e', 'r', '_', 'i', 'd', '"', ':', '"', 255, '"', '}'}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NormalizeProfile(json.RawMessage(tc.body))
			if (err != nil) != tc.bad {
				t.Fatalf("error=%v bad=%v", err, tc.bad)
			}
			if !tc.bad {
				if p.Subject == "" {
					t.Fatal("subject lost")
				}
				if tc.name == "false retained" && (p.EmailVerified == nil || *p.EmailVerified) {
					t.Fatal("false presence lost")
				}
				if tc.name == "minimal" && p.EmailVerified != nil {
					t.Fatal("absent converted to false")
				}
			}
		})
	}
}
