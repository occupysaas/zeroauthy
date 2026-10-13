package oauth

import (
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestResolveScopes(t *testing.T) {
	defined := []store.Scope{{Value: "a"}, {Value: "b"}, {Value: "c"}}
	granted := []string{"a", "b", "removed"}
	cases := []struct {
		requested, want, wantErr string
	}{
		{requested: "", want: "a b"},                     // default: everything granted and still defined
		{requested: "b", want: "b"},                      // narrowing
		{requested: "  b   a b ", want: "b a"},           // whitespace and duplicates
		{requested: "a c", want: "a"},                    // c defined but not granted → dropped
		{requested: "removed", wantErr: "invalid_scope"}, // granted but no longer defined
		{requested: "zzz", wantErr: "invalid_scope"},
	}
	for _, tc := range cases {
		got, oerr := resolveScopes(tc.requested, granted, defined)
		if tc.wantErr != "" {
			if oerr == nil || oerr.Code != tc.wantErr {
				t.Errorf("resolveScopes(%q) err = %+v, want %s", tc.requested, oerr, tc.wantErr)
			}
			continue
		}
		if oerr != nil || strings.Join(got, " ") != tc.want {
			t.Errorf("resolveScopes(%q) = %v, %+v; want %q", tc.requested, got, oerr, tc.want)
		}
	}
}
