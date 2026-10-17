// Package claims builds the OpenID Connect standard claims for a user.
package claims

import (
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ForUser returns the claims a user's ID token and /userinfo response
// carry for the granted scopes (OpenID Connect Core §5.4).
func ForUser(u *store.User, scopes []string) map[string]any {
	out := map[string]any{"sub": u.UserID}
	if slices.Contains(scopes, "profile") {
		out["name"] = Name(u)
		out["nickname"] = Nickname(u)
		out["updated_at"] = u.UpdatedAt.Unix()
		if u.Picture != "" {
			out["picture"] = u.Picture
		}
		if u.GivenName != "" {
			out["given_name"] = u.GivenName
		}
		if u.FamilyName != "" {
			out["family_name"] = u.FamilyName
		}
	}
	if slices.Contains(scopes, "email") {
		out["email"] = u.Email
		out["email_verified"] = u.EmailVerified
	}
	return out
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
