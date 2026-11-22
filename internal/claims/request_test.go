package claims

import (
	"strings"
	"testing"
)

func TestClaimsParse(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"absent", "", true}, {"empty", `{}`, true},
		{"core", `{"userinfo":{"given_name":{"essential":true},"nickname":null,"email":{"essential":true},"email_verified":{"essential":true}},"id_token":{"auth_time":{"essential":true},"acr":{"values":["urn:mace:incommon:iap:silver"]}}}`, true},
		{"unknown members", `{"extension":{"anything":true},"id_token":{"nickname":{"extension":true}}}`, true},
		{"null", `null`, false}, {"array", `[]`, false}, {"scalar", `"claims"`, false},
		{"target scalar", `{"userinfo":true}`, false}, {"target null", `{"id_token":null}`, false},
		{"claim scalar", `{"id_token":{"email":true}}`, false},
		{"essential type", `{"id_token":{"email":{"essential":"true"}}}`, false},
		{"values type", `{"id_token":{"email":{"values":"yes"}}}`, false},
		{"two value controls", `{"id_token":{"email":{"value":"one","values":["two"]}}}`, false},
		{"essential null", `{"id_token":{"email":{"essential":null}}}`, false},
		{"values null", `{"id_token":{"email":{"values":null}}}`, false},
		{"invalid UTF-8", string([]byte{123, 34, 120, 34, 58, 34, 255, 34, 125}), false},
		{"trailing json", `{} {}`, false}, {"trailing garbage", `{}x`, false},
		{"byte limit", `{"unknown":"` + strings.Repeat("é", 2048) + `"}`, false},
		{"at limit", `{}` + strings.Repeat(" ", 4094), true},
		{"over limit", `{}` + strings.Repeat(" ", 4095), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRequest(tc.raw)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, want %v: %v", err == nil, tc.valid, err)
			}
			if err != nil && !strings.Contains(err.Error(), "invalid_request") {
				t.Fatalf("wrong error: %v", err)
			}
		})
	}
	req, err := ParseRequest(`{"id_token":{"email":null,"nickname":{"value":"nick"},"acr":{"essential":true,"values":["mfa"]}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := req.IDToken["email"]; !ok || req.IDToken["email"] != nil {
		t.Fatal("null claim lost")
	}
	if req.IDToken["nickname"].Value != "nick" || !req.IDToken["acr"].Essential || len(req.IDToken["acr"].Values) != 1 || req.IDToken["acr"].Values[0] != "mfa" {
		t.Fatalf("parsed request: %+v", req)
	}
	if req.UserInfo != nil {
		t.Fatal("absent target became present")
	}
}
