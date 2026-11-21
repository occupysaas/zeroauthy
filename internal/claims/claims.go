// Package claims builds the OpenID Connect standard claims for a user.
package claims

import (
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ForUser returns the claims a user's ID token and /userinfo response
// carry for the granted scopes (OpenID Connect Core §5.4).
func ForUser(u *store.User, scopes []string) map[string]any {
	return Select(u, PrimaryProfile(u), scopes, nil, "userinfo")
}

// Name is the display name, falling back to the email or username.
func Name(u *store.User) string {
	switch {
	case u.Name != "":
		return u.Name
	case u.Email != "":
		return u.Email
	default:
		return u.Username
	}
}

// Nickname falls back to the email's local part or the username.
func Nickname(u *store.User) string {
	switch {
	case u.Nickname != "":
		return u.Nickname
	case u.Email != "":
		return strings.SplitN(u.Email, "@", 2)[0]
	default:
		return u.Username
	}
}
