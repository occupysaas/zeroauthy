package apirules

import (
	"fmt"
	"net/url"
	"slices"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

// MaxGrantScope bounds one scope of a client grant, as a scope an API
// defines (D-0041).
const MaxGrantScope = MaxScopeValue

// IsManagementAPIIdentifier reports whether aud has the form of a tenant's
// Management API identifier (tenant.ManagementAPIIdentifier): an https URL
// whose path is /api/v2/. Which tenant's it is depends on the base domain.
func IsManagementAPIIdentifier(aud string) bool {
	u, err := url.Parse(aud)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Path == "/api/v2/" &&
		u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

// CheckGrant reports everything wrong with a client grant of scopes to an
// API, whoever writes it: the seed and the Management API (Plan 14 review
// focus 1 and 3).
//   - subjectType must be client or user.
//   - A grant to a Management API (mgmt) is for machine-to-machine clients
//     only, and may carry Management API scopes only.
//   - Any other grant may carry only scopes the API defines (defined).
func CheckGrant(subjectType string, mgmt bool, scopes []string, defined func(scope string) bool) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if subjectType != store.SubjectTypeClient && subjectType != store.SubjectTypeUser {
		fail("subject_type %q must be client or user", subjectType)
	}
	if mgmt && subjectType == store.SubjectTypeUser {
		fail("the Management API accepts machine-to-machine (client) grants only")
	}
	for _, s := range scopes {
		n := utf8.RuneCountInString(s)
		switch {
		case n < 1 || n > MaxGrantScope:
			fail("scope %q must be 1 to %d characters", s, MaxGrantScope)
		case mgmt && !tenantsetup.IsManagementAPIScope(s):
			fail("scope %q is not a Management API scope", s)
		case !mgmt && !defined(s):
			fail("scope %q is not defined by the API", s)
		}
	}
	return errs
}

// DedupeScopes drops repeated scopes, keeping the first of each.
func DedupeScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
