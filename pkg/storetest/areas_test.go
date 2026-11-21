package storetest

import (
	"slices"
	"testing"
)

// Suites drivers run by name with RunSuites instead of through Run, because
// they test an optional store capability.
var namedOnlySuites = []string{"ConnectionKeys"} // capability connection_keys.v1

// Every suite Run executes belongs to exactly one area, so area shards
// together cover the whole suite.
func TestAreasCoverEverySuiteOnce(t *testing.T) {
	area := map[string]string{}
	for a, suites := range Areas {
		for _, s := range suites {
			if prev, dup := area[s]; dup {
				t.Errorf("suite %q is in areas %q and %q", s, prev, a)
			}
			area[s] = a
			if _, ok := Suites[s]; !ok {
				t.Errorf("area %q names unknown suite %q", a, s)
			}
		}
	}
	for _, s := range suiteOrder {
		if _, ok := area[s]; !ok {
			t.Errorf("suite %q has no area", s)
		}
	}
	if len(area) != len(suiteOrder) {
		t.Errorf("areas hold %d suites, suiteOrder %d", len(area), len(suiteOrder))
	}
	for name := range Suites {
		if !slices.Contains(suiteOrder, name) && !slices.Contains(namedOnlySuites, name) {
			t.Errorf("suite %q is not in suiteOrder, so Run never executes it", name)
		}
	}
}

// An include list and the matching skip list partition the suites.
func TestSelectSuitesPartitions(t *testing.T) {
	for _, list := range []string{"identity", "oauth,runtime", " orgs , tenancy "} {
		in, err := selectSuites(list, "")
		if err != nil {
			t.Fatal(err)
		}
		out, err := selectSuites("", list)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range suiteOrder {
			if in[s] == out[s] {
				t.Errorf("%q: suite %q in both or neither shard", list, s)
			}
		}
		if len(in) == 0 || len(out) == 0 {
			t.Errorf("%q: empty shard (in %d, out %d)", list, len(in), len(out))
		}
	}
}

func TestSelectSuitesDefaultsAndErrors(t *testing.T) {
	if sel, err := selectSuites("", ""); err != nil || sel != nil {
		t.Errorf("no lists = %v, %v; want all suites (nil)", sel, err)
	}
	if _, err := selectSuites("idenity", ""); err == nil {
		t.Error("misspelt area accepted")
	}
	if _, err := selectSuites("", "nope"); err == nil {
		t.Error("unknown skip area accepted")
	}
	if _, err := selectSuites("oauth", "orgs"); err == nil {
		t.Error("both lists accepted")
	}
}
