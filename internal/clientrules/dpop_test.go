package clientrules

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestDPoPClientRuleRoundTrip(t *testing.T) {
	c := &store.Client{RequireProofOfPossession: true}
	s := FromClient(c)
	out := &store.Client{}
	Apply(out, &s)
	if !out.RequireProofOfPossession {
		t.Fatal("requirement lost")
	}
}
