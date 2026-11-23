package federation

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestMatchHomeRealm(t *testing.T) {
	c := &store.Connection{ID: "c", Name: "corp", Strategy: "oidc", EnabledClients: []string{"client"}, Extra: map[string]any{"domain_aliases": []any{"corp.example", "xn--bcher-kva.example"}}}
	for _, tc := range []struct {
		email string
		match bool
	}{{"a@corp.example", true}, {"A@CORP.EXAMPLE", true}, {"a@bücher.example", true}, {"a@sub.corp.example", false}, {"alice", false}, {"name <a@corp.example>", false}} {
		if got := MatchHomeRealm(tc.email, []*store.Connection{c}); (got != nil) != tc.match {
			t.Errorf("%s: %v", tc.email, got)
		}
	}
}
func TestHRDOrder(t *testing.T) {
	a := &store.Connection{ID: "a", Strategy: "oidc", Extra: map[string]any{"domain_aliases": []any{"corp.example"}}}
	b := *a
	b.ID = "b"
	if got := MatchHomeRealm("a@corp.example", []*store.Connection{&b, a}); got == nil || got.ID != "b" {
		t.Fatal(got)
	}
}

// samlp connections take part in home realm discovery (Plan 37a).
func TestMatchHomeRealmSAML(t *testing.T) {
	c := &store.Connection{ID: "s", Name: "corp-saml", Strategy: "samlp", EnabledClients: []string{"client"}, Extra: map[string]any{"domain_aliases": []any{"saml.example"}}}
	if got := MatchHomeRealm("a@saml.example", []*store.Connection{c}); got != c {
		t.Fatalf("samlp HRD: %v", got)
	}
}

// adfs connections take part in home realm discovery (Plan 37b).
func TestMatchHomeRealmADFS(t *testing.T) {
	c := &store.Connection{ID: "a", Name: "corp-adfs", Strategy: "adfs", EnabledClients: []string{"client"}, Extra: map[string]any{"domain_aliases": []any{"adfs.example"}}}
	if got := MatchHomeRealm("a@adfs.example", []*store.Connection{c}); got != c {
		t.Fatalf("adfs HRD: %v", got)
	}
}
