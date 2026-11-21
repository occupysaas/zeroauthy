package clientrules

import "testing"

func TestOIDCSupport(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		valid bool
	}{
		{`null`, true}, {`{"is_allowed":false}`, true}, {`{"is_allowed":true,"allowed_scopes":["email"]}`, true},
		{`{"is_allowed":true,"allowed_scopes":[]}`, true}, {`{"is_allowed":true,"allow_all_scopes":true}`, true},
		{`{}`, false}, {`[]`, false}, {`{"is_allowed":null}`, false}, {`{"is_allowed":"true"}`, false},
		{`{"is_allowed":true,"allow_all_scopes":false,"allowed_scopes":[]}`, false},
		{`{"is_allowed":true,"allowed_scopes":["offline_access"]}`, false},
		{`{"is_allowed":true,"allowed_scopes":["email","email"]}`, false},
		{`{"is_allowed":true,"allowed_scopes":null}`, false}, {`{"is_allowed":true,"allow_all_scopes":null}`, false},
		{`{"is_allowed":true,"unknown":1}`, false},
	} {
		s, err := ParseOIDCSupport([]byte(tc.raw))
		if (err == nil) != tc.valid {
			t.Errorf("%s valid=%v want %v: %v", tc.raw, err == nil, tc.valid, err)
		}
		if err == nil && s != nil && ValidateOIDCSupport(s) != nil {
			t.Errorf("parsed invalid spec %s", tc.raw)
		}
	}
}
