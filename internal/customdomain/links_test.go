package customdomain_test

import (
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
)

func TestCheckOrigin(t *testing.T) {
	const canonical, alias = "https://acme.auth.example.test", "https://login.acme.test"
	for _, tc := range []struct {
		stored, request string
		ok              bool
	}{
		{alias, alias, true},
		{canonical, canonical, true},
		{"", canonical, true}, // legacy rows mean the pinned canonical origin
		{"", alias, false},    // never the first presenter's host
		{alias, canonical, false},
		{canonical, alias, false},
		{"", "", false},
	} {
		err := customdomain.CheckOrigin(tc.stored, canonical, tc.request)
		if (err == nil) != tc.ok || err != nil && !errors.Is(err, customdomain.ErrOriginMismatch) {
			t.Errorf("CheckOrigin(%q, %q) = %v", tc.stored, tc.request, err)
		}
	}
	if err := customdomain.CheckOrigin("", "", "https://x.test"); err == nil {
		t.Error("legacy row on a tenant without canonical identity accepted")
	}
}
