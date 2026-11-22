package claims

import "testing"

func TestACRRequest(t *testing.T) {
	for _, tc := range []struct {
		values, raw string
		want        bool
	}{
		{ACRMultiFactor, "", true}, {"unknown " + ACRMultiFactor, "", true}, {"unknown", "", false},
		{"", `{"id_token":{"acr":{"essential":true,"values":["http://schemas.openid.net/pape/policies/2007/06/multi-factor"]}}}`, true},
		{"", `{"id_token":{"acr":{"essential":true,"value":"http://schemas.openid.net/pape/policies/2007/06/multi-factor"}}}`, true},
		{"", `{"id_token":{"acr":{"values":["http://schemas.openid.net/pape/policies/2007/06/multi-factor"]}}}`, false},
		{"", `{"userinfo":{"acr":{"essential":true,"values":["http://schemas.openid.net/pape/policies/2007/06/multi-factor"]}}}`, false},
	} {
		req, err := ParseRequest(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := RequestsMFA(tc.values, req); got != tc.want {
			t.Fatalf("values=%s request=%s got=%v want=%v", tc.values, tc.raw, got, tc.want)
		}
	}
}
