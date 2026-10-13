// internal/oauth/scopes.go
package oauth

import (
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// resolveScopes returns the scopes to issue. Only scopes that are both
// granted to the client and still defined by the resource server count.
// With no request, all of them are issued. Requested scopes that don't
// count are dropped. If a request names scopes and none count, the result
// is invalid_scope rather than an empty token.
func resolveScopes(requested string, granted []string, defined []store.Scope) ([]string, *Error) {
	var valid []string
	for _, g := range granted {
		if slices.ContainsFunc(defined, func(s store.Scope) bool { return s.Value == g }) {
			valid = append(valid, g)
		}
	}
	req := strings.Fields(requested)
	if len(req) == 0 {
		return valid, nil
	}
	var out []string
	for _, r := range req {
		if slices.Contains(valid, r) && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, invalidScope("none of the requested scopes are granted to this client")
	}
	return out, nil
}
