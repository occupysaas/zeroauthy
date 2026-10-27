package rbacrules

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
	"testing"
)

func TestRBACRules(t *testing.T) {
	for _, name := range []string{"", "  ", "bad\nname", strings.Repeat("x", 129)} {
		if len(NormalizeRole(&store.Role{Name: name})) == 0 {
			t.Fatalf("accepted %q", name)
		}
	}
	if len(NormalizeRole(&store.Role{Name: "读者", Description: "description"})) != 0 {
		t.Fatal("valid Unicode role rejected")
	}
	for _, p := range []store.RBACPage{{Page: -1}, {PerPage: 101}, {Take: 101}, {Page: 1, From: "cursor"}} {
		if NormalizePage(&p) == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
	p := store.RBACPage{}
	if NormalizePage(&p) != nil || p.PerPage != 50 {
		t.Fatal("default page")
	}
}
