package orgrules

import (
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func ptr[T any](v T) *T { return &v }

func org(mut func(*store.Organization)) store.Organization {
	o := store.Organization{Name: "acme", DisplayName: "Acme"}
	if mut != nil {
		mut(&o)
	}
	return o
}

func meta(n int) map[string]string {
	m := map[string]string{}
	for i := 0; i < n; i++ {
		m["k"+strings.Repeat("x", i)] = "v"
	}
	return m
}

func TestOrgRules(t *testing.T) {
	nameMax, displayMax := Limit("name_chars_max"), Limit("display_name_chars_max")
	keysMax, keyMax, valMax := Limit("metadata_keys_max"), Limit("metadata_key_chars_max"), Limit("metadata_value_chars_max")
	tests := []struct {
		name string
		in   store.Organization
		ok   bool
	}{
		{"name at limit", org(func(o *store.Organization) { o.Name = strings.Repeat("a", nameMax) }), true},
		{"name over limit", org(func(o *store.Organization) { o.Name = strings.Repeat("a", nameMax+1) }), false},
		{"name empty", org(func(o *store.Organization) { o.Name, o.DisplayName = "", "x" }), false},
		{"name digit first", org(func(o *store.Organization) { o.Name = "1a" }), true},
		{"name with dash and underscore", org(func(o *store.Organization) { o.Name = "a-b_c" }), true},
		{"name leading dash", org(func(o *store.Organization) { o.Name = "-a" }), false},
		{"name leading underscore", org(func(o *store.Organization) { o.Name = "_a" }), false},
		{"name uppercase", org(func(o *store.Organization) { o.Name = "Acme" }), false},
		{"name space", org(func(o *store.Organization) { o.Name = "a b" }), false},
		{"display at limit", org(func(o *store.Organization) { o.DisplayName = strings.Repeat("é", displayMax) }), true},
		{"display over limit", org(func(o *store.Organization) { o.DisplayName = strings.Repeat("é", displayMax+1) }), false},
		{"third party allow", org(func(o *store.Organization) { o.ThirdPartyClientAccess = "allow" }), true},
		{"third party bogus", org(func(o *store.Organization) { o.ThirdPartyClientAccess = "maybe" }), false},
		{"logo https", org(func(o *store.Organization) { o.Branding = &store.OrgBranding{LogoURL: ptr("https://x.test/l.png")} }), true},
		{"logo http", org(func(o *store.Organization) { o.Branding = &store.OrgBranding{LogoURL: ptr("http://x.test/l.png")} }), false},
		{"logo no host", org(func(o *store.Organization) { o.Branding = &store.OrgBranding{LogoURL: ptr("https:///l.png")} }), false},
		{"logo null with colors", org(func(o *store.Organization) {
			o.Branding = &store.OrgBranding{Colors: &store.OrgColors{Primary: "#fff", PageBackground: "#000000"}}
		}), true},
		{"colors missing background", org(func(o *store.Organization) {
			o.Branding = &store.OrgBranding{Colors: &store.OrgColors{Primary: "#fff"}}
		}), false},
		{"colors empty", org(func(o *store.Organization) { o.Branding = &store.OrgBranding{Colors: &store.OrgColors{}} }), false},
		{"color word", org(func(o *store.Organization) {
			o.Branding = &store.OrgBranding{Colors: &store.OrgColors{Primary: "red", PageBackground: "#000"}}
		}), false},
		{"metadata at key count", org(func(o *store.Organization) { o.Metadata = meta(keysMax) }), true},
		{"metadata over key count", org(func(o *store.Organization) { o.Metadata = meta(keysMax + 1) }), false},
		{"metadata key at limit", org(func(o *store.Organization) { o.Metadata = map[string]string{strings.Repeat("k", keyMax): "v"} }), true},
		{"metadata key over limit", org(func(o *store.Organization) { o.Metadata = map[string]string{strings.Repeat("k", keyMax+1): "v"} }), false},
		{"metadata key underscore first", org(func(o *store.Organization) { o.Metadata = map[string]string{"_k": "v"} }), false},
		{"metadata key dash", org(func(o *store.Organization) { o.Metadata = map[string]string{"a-b": "v"} }), false},
		{"metadata key word chars", org(func(o *store.Organization) { o.Metadata = map[string]string{"a_1B": "v"} }), true},
		{"metadata value at limit", org(func(o *store.Organization) { o.Metadata = map[string]string{"k": strings.Repeat("v", valMax)} }), true},
		{"metadata value over limit", org(func(o *store.Organization) { o.Metadata = map[string]string{"k": strings.Repeat("v", valMax+1)} }), false},
		{"metadata empty value (null)", org(func(o *store.Organization) { o.Metadata = map[string]string{"k": ""} }), false},
		{"metadata empty key", org(func(o *store.Organization) { o.Metadata = map[string]string{"": "v"} }), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NormalizeOrganization(tc.in)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v, error %v", tc.ok, err)
			}
		})
	}

	t.Run("defaults and copies", func(t *testing.T) {
		in := org(func(o *store.Organization) {
			o.DisplayName = ""
			o.Metadata = map[string]string{"k": "v"}
			o.Branding = &store.OrgBranding{LogoURL: ptr("https://x.test/l.png")}
		})
		out, err := NormalizeOrganization(in)
		if err != nil {
			t.Fatal(err)
		}
		if out.DisplayName != "acme" || out.ThirdPartyClientAccess != "block" {
			t.Fatalf("defaults %#v", out)
		}
		out.Metadata["k"] = "changed"
		*out.Branding.LogoURL = "https://changed.test"
		if in.Metadata["k"] != "v" || *in.Branding.LogoURL != "https://x.test/l.png" {
			t.Fatal("normalized organization shares memory with input")
		}
		empty, err := NormalizeOrganization(org(func(o *store.Organization) {
			o.Metadata = map[string]string{}
			o.Branding = &store.OrgBranding{}
		}))
		if err != nil || empty.Metadata != nil || empty.Branding != nil {
			t.Fatalf("empty metadata and branding are unset: %#v %v", empty, err)
		}
	})

	t.Run("connections", func(t *testing.T) {
		cases := []struct {
			name     string
			strategy string
			oc       store.OrganizationConnection
			ok       bool
		}{
			{"database defaults", store.StrategyDatabase, store.OrganizationConnection{ConnectionID: "c", ShowAsButton: true}, true},
			{"database hide button", store.StrategyDatabase, store.OrganizationConnection{ConnectionID: "c"}, false},
			{"enterprise hide button", "waad", store.OrganizationConnection{ConnectionID: "c"}, true},
			{"oidc hide button", "oidc", store.OrganizationConnection{ConnectionID: "c"}, true},
			{"social hide button", "google", store.OrganizationConnection{ConnectionID: "c"}, false},
			{"social shown", "google", store.OrganizationConnection{ConnectionID: "c", ShowAsButton: true}, true},
			{"signup with auto-membership", store.StrategyDatabase, store.OrganizationConnection{ConnectionID: "c", ShowAsButton: true, AssignMembershipOnLogin: true, IsSignupEnabled: true}, true},
			{"signup without auto-membership", store.StrategyDatabase, store.OrganizationConnection{ConnectionID: "c", ShowAsButton: true, IsSignupEnabled: true}, false},
			{"signup on enterprise", "waad", store.OrganizationConnection{ConnectionID: "c", ShowAsButton: true, AssignMembershipOnLogin: true, IsSignupEnabled: true}, false},
			{"no connection id", store.StrategyDatabase, store.OrganizationConnection{ShowAsButton: true}, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if err := ValidateConnection(tc.strategy, tc.oc); (err == nil) != tc.ok {
					t.Fatalf("ok=%v, error %v", tc.ok, err)
				}
			})
		}
	})

	t.Run("ids", func(t *testing.T) {
		a, b := NewID(), NewID()
		if a == b || !ValidID(a) || len(a) != len(IDPrefix)+Limit("organization_id_random_chars") {
			t.Fatalf("ids %q %q", a, b)
		}
		for _, bad := range []string{"", "org_", "org_short", a + "x", "rol_" + a[4:], "org_" + strings.Repeat("-", 16)} {
			if ValidID(bad) {
				t.Fatalf("%q accepted", bad)
			}
		}
	})

	t.Run("limits come from the inventory", func(t *testing.T) {
		if l := Limits(); l.OrganizationsPerTenant != 10000 || l.ConnectionsPerOrganization != 50 || l.RolesPerMember != 50 {
			t.Fatalf("limits %#v", l)
		}
	})

	t.Run("sort", func(t *testing.T) {
		for in, want := range map[string]struct {
			field string
			desc  bool
			ok    bool
		}{
			"": {"", false, true}, "name:1": {"name", false, true}, "name:-1": {"name", true, true},
			"display_name:-1": {"display_name", true, true}, "created_at:1": {"created_at", false, true},
			"name": {ok: false}, "name:2": {ok: false}, "id:1": {ok: false}, "name:+1": {ok: false},
		} {
			f, d, err := ParseSort(in)
			if (err == nil) != want.ok || f != want.field || d != want.desc {
				t.Fatalf("%q: %q %v %v", in, f, d, err)
			}
		}
	})

	t.Run("page", func(t *testing.T) {
		p := store.OrgPage{}
		if m, err := NormalizePage(&p); err != nil || m != Offset || p.PerPage != 50 {
			t.Fatalf("%v %v %#v", m, err, p)
		}
		p = store.OrgPage{Take: 7, Page: 3}
		if m, err := NormalizePage(&p); err != nil || m != Checkpoint || p.Page != 0 || p.Take != 7 {
			t.Fatalf("%v %v %#v", m, err, p)
		}
		p = store.OrgPage{From: "x"}
		if m, err := NormalizePage(&p); err != nil || m != Checkpoint || p.Take != 50 {
			t.Fatalf("%v %v %#v", m, err, p)
		}
		for _, bad := range []store.OrgPage{{PerPage: 101}, {Take: 101}, {Page: 1001}, {Page: -1}, {Take: -1}} {
			if _, err := NormalizePage(&bad); err == nil {
				t.Fatalf("%#v accepted", bad)
			}
		}
		c := Cursor{Scope: "t/", Sort: "name:1", Key: "a", ID: "i"}
		got, err := DecodeCursor(EncodeCursor(c), "t/", "name:1")
		if err != nil || got != c {
			t.Fatalf("%#v %v", got, err)
		}
		if _, err := DecodeCursor(EncodeCursor(c), "u/", "name:1"); err == nil {
			t.Fatal("cursor moved across scope")
		}
		if _, err := DecodeCursor("!!", "t/", ""); err == nil {
			t.Fatal("garbage cursor accepted")
		}
	})
}
