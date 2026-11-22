package apirules

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestDPoPPolicyRules(t *testing.T) {
	for _, tc := range []struct {
		mechanism  string
		required   bool
		forClients string
		valid      bool
	}{{"dpop", false, "", true}, {"none", false, "", true}, {"mtls", true, "", false}, {"none", true, "", false}, {"dpop", true, "public_clients", true}, {"dpop", true, "unknown", false}} {
		s := Spec{Identifier: "https://api.example", ProofOfPossession: &store.ProofOfPossession{Mechanism: tc.mechanism, Required: tc.required, RequiredFor: tc.forClients}}
		errs := Normalize(&s)
		if (len(errs) == 0) != tc.valid {
			t.Fatalf("%v %v", tc, errs)
		}
		if tc.valid {
			rs := &store.ResourceServer{}
			Apply(rs, &s)
			back := FromResourceServer(rs)
			if back.ProofOfPossession == nil || back.ProofOfPossession.Mechanism != tc.mechanism {
				t.Fatal("policy lost")
			}
			back.ProofOfPossession.Mechanism = "changed"
			if rs.ProofOfPossession.Mechanism != tc.mechanism {
				t.Fatal("alias")
			}
		}
	}
}
