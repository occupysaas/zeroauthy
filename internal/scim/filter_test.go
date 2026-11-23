package scim

import (
	"strings"
	"testing"
)

func TestParsePath(t *testing.T) {
	for in, want := range map[string]Path{
		"userName":                        {Attr: "userName"},
		"name.givenName":                  {Attr: "name", Sub: "givenName"},
		`emails[type eq "work"].value`:    {Attr: "emails", Filter: &Filter{Op: OpEq, Path: "type", Value: "work"}, Sub: "value"},
		"emails[primary eq true].value":   {Attr: "emails", Filter: &Filter{Op: OpEq, Path: "primary", Value: true}, Sub: "value"},
		"members":                         {Attr: "members"},
		`members[value eq "auth0|u1"]`:    {Attr: "members", Filter: &Filter{Op: OpEq, Path: "value", Value: "auth0|u1"}},
		EnterpriseUser + ":department":    {URN: EnterpriseUser, Attr: "department"},
		EnterpriseUser + ":manager.value": {URN: EnterpriseUser, Attr: "manager", Sub: "value"},
		CoreUser + ":userName":            {Attr: "userName"},
	} {
		got, err := ParsePath(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got.String() != want.String() {
			t.Errorf("%s: got %s, want %s", in, got.String(), want.String())
		}
	}
	for _, bad := range []string{"", ".x", "a..b", "emails[", `emails[type eq "work"`, "emails[type eq].value", "a b", "emails[type gt 1].value", strings.Repeat("a", 300), "urn:x:y"} {
		if _, err := ParsePath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseFilter(t *testing.T) {
	for in, want := range map[string]string{
		`userName eq "jdoe"`:                                       `(userName eq "jdoe")`,
		`USERNAME EQ "jdoe"`:                                       `(USERNAME eq "jdoe")`,
		`externalId eq "x" and active eq true`:                     `((externalId eq "x") and (active eq true))`,
		`userName eq "a" or userName eq "b" and active eq false`:   `((userName eq "a") or ((userName eq "b") and (active eq false)))`,
		`(userName eq "a" or userName eq "b") and active eq false`: `(((userName eq "a") or (userName eq "b")) and (active eq false))`,
		`emails.value eq "a@b.c"`:                                  `(emails.value eq "a@b.c")`,
		`emails[type eq "work"].value eq "a@b.c"`:                  `(emails[type eq "work"].value eq "a@b.c")`,
		`displayName eq "Sales \"EMEA\""`:                          `(displayName eq "Sales \"EMEA\"")`,
		`x eq null`:                                                `(x eq null)`,
		`x eq 42`:                                                  `(x eq 42)`,
	} {
		f, err := ParseFilter(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got := f.String(); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"", "userName", `userName eq`, `userName co "x"`, `userName ne "x"`, `userName pr`, `not (userName eq "x")`,
		`userName eq "x" and`, `(userName eq "x"`, `userName eq "x")`, `userName eq "unterminated`, `userName eq x`, "userName eq \"\xd2\xff\"", strings.Repeat(`(`, 40) + `a eq "b"` + strings.Repeat(`)`, 40)} {
		if _, err := ParseFilter(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
