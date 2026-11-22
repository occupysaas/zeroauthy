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
