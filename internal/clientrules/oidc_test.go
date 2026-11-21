package clientrules

import (
	"strings"
	"testing"
)

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

func TestOIDCLogoutRules(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		valid bool
	}{
		{`null`, true}, {`{}`, true}, {`{"backchannel_logout_urls":[]}`, true},
		{`{"backchannel_logout_urls":["https://rp.example/logout/{organization_id}?organization={organization_name}"]}`, true},
		{`{"backchannel_logout_urls":["http://rp.example/logout"]}`, false},
		{`{"backchannel_logout_urls":["https://rp.example/logout","https://rp2.example/logout"]}`, false},
		{`{"backchannel_logout_urls":["https://user:password@rp.example/logout"]}`, false},
		{`{"backchannel_logout_urls":["https://rp.example/logout#fragment"]}`, false},
		{`{"backchannel_logout_urls":["https://rp.example/{unknown}"]}`, false},
		{`{"backchannel_logout_urls":null}`, false},
		{`{"backchannel_logout_initiators":{"mode":"custom"}}`, false},
		{`{"backchannel_logout_initiators":{"mode":"custom","selected_initiators":["rp-logout"]}}`, false},
		{`{"backchannel_logout_initiators":{"mode":"custom","selected_initiators":["rp-logout","idp-logout","account-deactivated","mfa-phone-unenrolled","profile-changed"]}}`, true},
		{`{"backchannel_logout_initiators":{"mode":"all"}}`, true},
		{`{"backchannel_logout_initiators":{"mode":"all","selected_initiators":["unknown"]}}`, false},
		{`{"backchannel_logout_session_metadata":{"include":true}}`, true},
		{`{"backchannel_logout_session_metadata":{"include":null}}`, false},
	} {
		value, err := ParseOIDCLogout([]byte(tc.raw))
		if (err == nil) != tc.valid {
			t.Errorf("%s: valid=%v want=%v err=%v", tc.raw, err == nil, tc.valid, err)
		}
		if err == nil && value != nil {
			if err := NormalizeOIDCLogout(value); err != nil {
				t.Errorf("parsed setting invalid: %v", err)
			}
		}
	}
	value, err := ParseOIDCLogout([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if value.InitiatorsMode != "custom" || len(value.Initiators) != 2 || value.Initiators[0] != "rp-logout" || value.Initiators[1] != "idp-logout" {
		t.Fatalf("default initiators=%+v", value)
	}
	if _, err := ParseOIDCLogout([]byte(`{"backchannel_logout_urls":["https://rp.example/` + strings.Repeat("x", 2048) + `"]}`)); err == nil {
		t.Fatal("oversized receiver accepted")
	}
}
