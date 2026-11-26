package tenant

import (
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// MyAccountPath is the path of the My Account API audience (Plan 42a).
const MyAccountPath = "/me/"

// MyAccountIdentifier is the identifier of t's My Account API: its canonical
// host followed by /me/. A tenant without a canonical host, and the reserved
// system tenant, have none.
func MyAccountIdentifier(t *store.Tenant) string {
	if t == nil || t.Reserved || t.CanonicalHost == "" {
		return ""
	}
	return MyAccountAudience(t.CanonicalHost)
}

// MyAccountAudience is the My Account audience of tokens issued on host
// (LR42a-10): each host of a tenant has its own.
func MyAccountAudience(host string) string { return "https://" + host + MyAccountPath }

// IsMyAccountAPI reports whether rs is t's My Account API.
func IsMyAccountAPI(t *store.Tenant, rs *store.ResourceServer) bool {
	id := MyAccountIdentifier(t)
	return rs != nil && rs.IsSystem && id != "" && rs.Identifier == id
}

// APIIdentifier maps an audience requested on res's host to the identifier
// of the API it names: the host's My Account audience names the My Account
// API, stored under the canonical identifier. Other audiences, the
// canonical identifier included (flows store it and validate it again), are
// returned unchanged; a token is minted for its host's audience either way
// (TokenAudience), so it is only accepted on that host. ok is false for
// no audience the caller may use; it is reserved and currently always true.
func APIIdentifier(res Resolved, aud string) (id string, ok bool) {
	if canonical := MyAccountIdentifier(res.Tenant); canonical != "" && strings.HasSuffix(aud, MyAccountPath) && aud == MyAccountAudience(res.Host) {
		return canonical, true
	}
	if canonical := MyOrgIdentifier(res.Tenant); canonical != "" && strings.HasSuffix(aud, store.MyOrgAPIPath) && aud == MyOrgAudience(res.Host) {
		return canonical, true
	}
	return aud, true
}

// TokenAudience is the audience a token for rs carries when issued on
// res's host: the host's own audience for the My Account and My
// Organization APIs, the identifier otherwise.
func TokenAudience(res Resolved, rs *store.ResourceServer) string {
	switch {
	case IsMyAccountAPI(res.Tenant, rs):
		return MyAccountAudience(res.Host)
	case IsMyOrgAPI(res.Tenant, rs):
		return MyOrgAudience(res.Host)
	}
	return rs.Identifier
}

// IsUserSystemAPI reports whether rs is one of the system APIs that users
// call (My Account, My Organization): its tokens follow the user-flow
// decision, unlike the Management API's.
func IsUserSystemAPI(t *store.Tenant, rs *store.ResourceServer) bool {
	return IsMyAccountAPI(t, rs) || IsMyOrgAPI(t, rs)
}

// MyOrgIdentifier is the identifier of t's My Organization API (Plan 42b):
// its canonical host followed by /my-org/.
func MyOrgIdentifier(t *store.Tenant) string {
	if t == nil || t.Reserved || t.CanonicalHost == "" {
		return ""
	}
	return MyOrgAudience(t.CanonicalHost)
}

// MyOrgAudience is the My Organization audience of tokens issued on host.
func MyOrgAudience(host string) string { return "https://" + host + store.MyOrgAPIPath }

// IsMyOrgAPI reports whether rs is t's My Organization API.
func IsMyOrgAPI(t *store.Tenant, rs *store.ResourceServer) bool {
	id := MyOrgIdentifier(t)
	return rs != nil && rs.IsSystem && id != "" && rs.Identifier == id
}
