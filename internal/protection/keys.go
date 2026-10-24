// Package protection holds shared authentication protection primitives.
package protection

import (
	"net/netip"

	"github.com/zeroauthy/zeroauthy/internal/loginid"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// CanonicalIP unmaps IPv4 and removes zones. Invalid input shares a stable,
// non-IP bucket which can never match an IP or CIDR allowlist.
func CanonicalIP(raw string) string {
	if ip, err := netip.ParseAddr(raw); err == nil {
		return ip.WithZone("").Unmap().String()
	}
	return "unknown"
}

// LoginKey uses stable connection IDs. Callers resolve known aliases before
// passing identifier; unknown identifiers still receive the same normalization.
func LoginKey(tenantID, connectionID, identifier, ip, mode string) store.ProtectionKey {
	k := store.ProtectionKey{TenantID: tenantID, Kind: store.ProtectionBruteForce, ConnectionID: connectionID, Identifier: loginid.Normalize(identifier)}
	if mode != "count_per_identifier" {
		k.IP = CanonicalIP(ip)
	}
	return k
}

// IdentityIdentifier is the common key for an identity's email/username aliases.
// Linked identities retain their own profile instead of the primary user's.
func IdentityIdentifier(u *store.User, id *store.Identity) string {
	email, username := u.IdentityLogin(id)
	if email != "" {
		return loginid.Normalize(email)
	}
	if username != "" {
		return loginid.Normalize(username)
	}
	return loginid.Normalize(id.UserID)
}
