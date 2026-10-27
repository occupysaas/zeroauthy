package apirules

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestRBACResourceServerRules(t *testing.T) {
	for _, dialect := range []string{"access_token", "access_token_authz", "rfc9068_profile", "rfc9068_profile_authz"} {
		spec := Spec{Identifier: "https://api.test", EnforcePolicies: true, TokenDialect: dialect}
		if errs := Normalize(&spec); len(errs) > 0 {
			t.Fatal(errs)
		}
		rs := &store.ResourceServer{}
		Apply(rs, &spec)
		back := FromResourceServer(rs)
		if !back.EnforcePolicies || back.TokenDialect != dialect {
			t.Fatalf("roundtrip=%+v", back)
		}
	}
	spec := Spec{Identifier: "https://api.test"}
	if errs := Normalize(&spec); len(errs) > 0 || spec.EnforcePolicies || spec.TokenDialect != "access_token" {
		t.Fatalf("defaults=%+v %v", spec, errs)
	}
	spec.TokenDialect = "unknown"
	if len(Normalize(&spec)) == 0 {
		t.Fatal("accepted unknown dialect")
	}
}
