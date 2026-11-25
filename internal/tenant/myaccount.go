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
// of the API it names. The host's My Account audience names the My Account
// API (stored under the canonical identifier); the canonical My Account
// audience requested on any other host names nothing, so ok is false.
// Other audiences are returned unchanged.
func APIIdentifier(res Resolved, aud string) (id string, ok bool) {
	canonical := MyAccountIdentifier(res.Tenant)
	switch {
	case canonical == "" || !strings.HasSuffix(aud, MyAccountPath):
		return aud, true
	case aud == MyAccountAudience(res.Host):
		return canonical, true
	case aud == canonical:
		return "", false
	}
	return aud, true
}

// TokenAudience is the audience a token for rs carries when issued on
// res's host: the host's My Account audience for the My Account API, the
// identifier otherwise.
func TokenAudience(res Resolved, rs *store.ResourceServer) string {
	if IsMyAccountAPI(res.Tenant, rs) {
		return MyAccountAudience(res.Host)
	}
	return rs.Identifier
}
