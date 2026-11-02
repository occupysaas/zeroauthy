package main

import (
	"encoding/json"
	"testing"
)

func TestCompareGuardianPolicies(t *testing.T) {
	m := testManifest()
	m.Resources = append(m.Resources, ManifestResource{Name: "guardianPolicies", Status: "included"})
	for _, policy := range []string{`{"policies":["all-applications"]}`, `{"policies":[]}`} {
		source, target := comparisonFixture(), comparisonFixture()
		source.Resources["guardianPolicies"], target.Resources["guardianPolicies"] = json.RawMessage(policy), json.RawMessage(policy)
		if r := Compare(source, target, m, Domains{}); !r.Equivalent {
			t.Fatalf("equal policies: %+v", r.Differences)
		}
		target.Resources["guardianPolicies"] = json.RawMessage(`{"policies":["confidence-score"]}`)
		if Compare(source, target, m, Domains{}).Equivalent {
			t.Fatal("changed policy escaped comparison")
		}
		delete(target.Resources, "guardianPolicies")
		if Compare(source, target, m, Domains{}).Equivalent {
			t.Fatal("missing policy treated as explicit none")
		}
	}
}
