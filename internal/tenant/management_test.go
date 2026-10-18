package tenant

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestManagementAPIIdentifier(t *testing.T) {
	acme := &store.Tenant{Name: "acme", Domains: []string{"login.acme.test", "auth.acme.test"}}
	bare := &store.Tenant{Name: "bare"}
	for _, tc := range []struct {
		t    *store.Tenant
		base string
		want string
	}{
		// With a base domain the identifier stays on <name>.<base>, even
		// when the tenant has custom domains (M11).
		{acme, "example.com", "https://acme.example.com/api/v2/"},
		{acme, "Example.COM.", "https://acme.example.com/api/v2/"},
		{acme, "localhost:8443", "https://acme.localhost:8443/api/v2/"},
		{acme, "example.com:443", "https://acme.example.com/api/v2/"},
		// Without one, the first domain.
		{acme, "", "https://login.acme.test/api/v2/"},
		{bare, "example.com", "https://bare.example.com/api/v2/"},
		{bare, "", ""},
		{nil, "example.com", ""},
	} {
		if got := ManagementAPIIdentifier(tc.t, tc.base); got != tc.want {
			t.Errorf("ManagementAPIIdentifier(%v, %q) = %q, want %q", tc.t, tc.base, got, tc.want)
		}
	}
}

func TestIssuers(t *testing.T) {
	acme := &store.Tenant{Name: "acme", Domains: []string{"login.acme.test"}}
	got := Issuers(acme, "example.com")
	want := []string{"https://acme.example.com/", "https://login.acme.test/"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Issuers = %v, want %v", got, want)
	}
	if got := Issuers(acme, ""); len(got) != 1 || got[0] != "https://login.acme.test/" {
		t.Errorf("Issuers without base = %v", got)
	}
}
