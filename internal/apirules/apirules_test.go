package apirules

import (
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// FromResourceServer and Apply are inverses, so an update that changes
// nothing leaves an API as it was.
func TestFromResourceServerApplyRoundTrip(t *testing.T) {
	for _, rs := range []*store.ResourceServer{
		{Name: "Orders", SigningAlg: SigningAlg, Scopes: []store.Scope{{Value: "read:orders", Description: "Read"}, {Value: "write:orders"}},
			TokenLifetime: 3600, TokenLifetimeForWeb: 600, AllowOfflineAccess: true,
			SkipConsentForVerifiableFirstPartyClients: true,
			SubjectTypeAuthorization:                  store.SubjectTypeAuthorization{User: store.PolicyDenyAll, Client: store.PolicyRequireClientGrant}},
		{SigningAlg: SigningAlg, SubjectTypeAuthorization: store.SubjectTypeAuthorization{User: store.PolicyAllowAll, Client: store.PolicyDenyAll}},
	} {
		s := FromResourceServer(rs)
		got := &store.ResourceServer{}
		Apply(got, &s)
		if !reflect.DeepEqual(got, rs) {
			t.Errorf("%q: round trip\n got %+v\nwant %+v", rs.Name, got, rs)
		}
	}
}

func TestNormalizeDefaults(t *testing.T) {
	s := Spec{Identifier: "https://api.test"}
	if errs := Normalize(&s); len(errs) > 0 {
		t.Fatal(errs)
	}
	if s.SkipConsentForVerifiableFirstPartyClients == nil || *s.SkipConsentForVerifiableFirstPartyClients ||
		s.SubjectTypeAuthorization != (store.SubjectTypeAuthorization{User: store.PolicyAllowAll, Client: store.PolicyRequireClientGrant}) {
		t.Fatalf("defaults = %+v", s)
	}
}

func TestNormalizeRefusals(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	scopes := func(s ...store.Scope) []store.Scope { return s }
	for name, tc := range map[string]struct {
		s    Spec
		want string
	}{
		"no identifier":             {Spec{}, "identifier"},
		"identifier too long":       {Spec{Identifier: long(601)}, "identifier"},
		"name too long":             {Spec{Identifier: "x", Name: long(201)}, "name"},
		"name with <":               {Spec{Identifier: "x", Name: "a<b"}, "name"},
		"name with >":               {Spec{Identifier: "x", Name: "a>b"}, "name"},
		"empty scope":               {Spec{Identifier: "x", Scopes: scopes(store.Scope{})}, "scope"},
		"long scope":                {Spec{Identifier: "x", Scopes: scopes(store.Scope{Value: long(281)})}, "scope"},
		"long description":          {Spec{Identifier: "x", Scopes: scopes(store.Scope{Value: "a", Description: long(501)})}, "description"},
		"duplicate scope":           {Spec{Identifier: "x", Scopes: scopes(store.Scope{Value: "a"}, store.Scope{Value: "a"})}, "duplicate scope"},
		"negative lifetime":         {Spec{Identifier: "x", TokenLifetime: -1}, "token_lifetime"},
		"huge lifetime":             {Spec{Identifier: "x", TokenLifetime: 2592001}, "token_lifetime"},
		"huge web lifetime":         {Spec{Identifier: "x", TokenLifetimeForWeb: 2592001}, "token_lifetime_for_web"},
		"web above lifetime":        {Spec{Identifier: "x", TokenLifetime: 100, TokenLifetimeForWeb: 101, CheckWebLifetime: true}, "token_lifetime_for_web"},
		"web above default":         {Spec{Identifier: "x", TokenLifetimeForWeb: DefaultTokenLifetime + 1, CheckWebLifetime: true}, "token_lifetime_for_web"},
		"bad user policy":           {Spec{Identifier: "x", SubjectTypeAuthorization: store.SubjectTypeAuthorization{User: "maybe"}}, `subject_type_authorization.user.policy "maybe"`},
		"client allow_all":          {Spec{Identifier: "x", SubjectTypeAuthorization: store.SubjectTypeAuthorization{Client: store.PolicyAllowAll}}, `subject_type_authorization.client.policy "allow_all"`},
		"stored web is not checked": {Spec{Identifier: "x", TokenLifetime: 100, TokenLifetimeForWeb: 7200}, ""},
	} {
		errs := Normalize(&tc.s)
		if tc.want == "" {
			if len(errs) > 0 {
				t.Errorf("%s: %v", name, errs)
			}
			continue
		}
		if len(errs) == 0 || !strings.Contains(errs[0].Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, errs, tc.want)
		}
	}
	ok := Spec{Identifier: long(600), Name: long(200), Scopes: scopes(store.Scope{Value: long(280), Description: long(500)}),
		TokenLifetime: 2592000, TokenLifetimeForWeb: 2592000, CheckWebLifetime: true}
	if errs := Normalize(&ok); len(errs) > 0 {
		t.Errorf("limits: %v", errs)
	}
	// Identifiers are any string: no URL form, case-sensitive.
	for _, id := range []string{"urn:x", "orders", "has space", "HTTPS://API.TEST"} {
		if errs := Normalize(&Spec{Identifier: id}); len(errs) > 0 {
			t.Errorf("identifier %q: %v", id, errs)
		}
	}
}

func TestReserved(t *testing.T) {
	const mgmt = "https://acme.example.com/api/v2/"
	if err := Reserved("urn:zeroauthy:management", mgmt); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("operator audience: %v", err)
	}
	if err := Reserved(mgmt, mgmt); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("management API: %v", err)
	}
	if err := Reserved("https://acme.example.com/API/v2/", mgmt); err != nil {
		t.Errorf("another case: %v", err)
	}
	// A tenant without a host has no Management API identifier.
	if err := Reserved("", ""); err != nil {
		t.Errorf("empty: %v", err)
	}
}

func TestCheckGrant(t *testing.T) {
	defined := func(s string) bool { return s == "read:orders" || s == "write:orders" }
	cases := []struct {
		name    string
		subject string
		mgmt    bool
		scopes  []string
		want    string // substring of the one expected error; empty for none
	}{
		{"defined scopes", "client", false, []string{"read:orders", "write:orders"}, ""},
		{"no scopes", "user", false, nil, ""},
		{"undefined scope", "client", false, []string{"read:orders", "nope"}, `scope "nope" is not defined`},
		{"bad subject type", "robot", false, nil, "must be client or user"},
		{"empty scope", "client", false, []string{""}, "must be 1 to"},
		{"long scope", "client", false, []string{strings.Repeat("a", MaxGrantScope+1)}, "must be 1 to"},
		{"management scope", "client", true, []string{"read:clients"}, ""},
		{"not a management scope", "client", true, []string{"read:orders"}, "not a Management API scope"},
		{"management user grant", "user", true, []string{"read:clients"}, "machine-to-machine"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := CheckGrant(tc.subject, tc.mgmt, tc.scopes, defined)
			switch {
			case tc.want == "" && len(errs) != 0:
				t.Errorf("errors %v", errs)
			case tc.want != "" && (len(errs) != 1 || !strings.Contains(errs[0].Error(), tc.want)):
				t.Errorf("errors %v, want one containing %q", errs, tc.want)
			}
		})
	}
}

func TestIsManagementAPIIdentifier(t *testing.T) {
	for aud, want := range map[string]bool{
		"https://acme.example.com/api/v2/": true, "https://login.acme.test/api/v2/": true,
		"https://acme.example.com/api/v2": false, "http://acme.example.com/api/v2/": false,
		"https://acme.example.com/api/v2/x": false, "https://acme.example.com/api/v2/?a=b": false,
		"urn:zeroauthy:management": false, "https://api.orders.test/v1": false, "": false,
	} {
		if got := IsManagementAPIIdentifier(aud); got != want {
			t.Errorf("IsManagementAPIIdentifier(%q) = %v", aud, got)
		}
	}
}

func TestDedupeScopes(t *testing.T) {
	if got := DedupeScopes([]string{"b", "a", "b", "a", "c"}); !reflect.DeepEqual(got, []string{"b", "a", "c"}) {
		t.Errorf("DedupeScopes = %v", got)
	}
	if got := DedupeScopes(nil); got == nil || len(got) != 0 {
		t.Errorf("DedupeScopes(nil) = %#v", got)
	}
}
