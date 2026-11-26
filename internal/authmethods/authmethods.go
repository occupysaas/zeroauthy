// Package authmethods lists a user's authentication methods for the
// Management API and the My Account API (Plan 42a), so the same method has
// the same ID on both (LR42a-5).
package authmethods

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Method is one authentication method: a stored authenticator, or the
// password of a database identity (Authenticator nil).
type Method struct {
	ID, Type  string
	CreatedAt time.Time
	// Usage is primary for passwords and passkeys, secondary otherwise.
	Usage         []string
	Authenticator *store.Authenticator
	// Identity is the database identity a password belongs to.
	Identity          *store.Identity
	LastPasswordReset *time.Time
}

// passwordPrefix starts password method IDs.
const passwordPrefix = "password|"

// PasswordID is the ID of the password of the database identity whose
// user ID (without the provider) is identityUserID.
func PasswordID(identityUserID string) string {
	return passwordPrefix + base64.RawURLEncoding.EncodeToString([]byte(identityUserID))
}

// PasswordIdentity returns the identity user ID a password method ID names.
func PasswordIdentity(id string) (string, bool) {
	rest, ok := strings.CutPrefix(id, passwordPrefix)
	if !ok {
		return "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(b) == 0 {
		return "", false
	}
	return string(b), true
}

// Authenticators are the user's stored authenticators, pending ones
// included: the Management API's listing.
func Authenticators(ctx context.Context, st store.Store, tid, uid string) ([]store.Authenticator, error) {
	return st.MFA().ListAuthenticators(ctx, tid, uid)
}

// Passwords are the user's database identities that have a password.
func Passwords(u *store.User) []store.Identity {
	out := []store.Identity{}
	for _, id := range u.Identities {
		if id.Provider == store.StrategyDatabase && (id.PasswordHash != "" || id.ImportedHash != "") {
			out = append(out, id)
		}
	}
	return out
}

// List is the user's methods as the My Account API lists them: one
// password per database identity with a password, then the confirmed
// authenticators (passkeys are always confirmed). Pending enrollments are
// not methods yet.
func List(ctx context.Context, st store.Store, u *store.User) ([]Method, error) {
	out := []Method{}
	for _, id := range Passwords(u) {
		id := id
		out = append(out, Method{ID: PasswordID(id.UserID), Type: "password", CreatedAt: u.CreatedAt, Usage: []string{"primary"}, Identity: &id, LastPasswordReset: u.LastPasswordReset})
	}
	all, err := Authenticators(ctx, st, u.TenantID, u.UserID)
	if err != nil {
		return nil, err
	}
	for i := range all {
		a := &all[i]
		if !a.Confirmed && a.Type != "passkey" {
			continue
		}
		usage := []string{"secondary"}
		if a.Type == "passkey" {
			usage = []string{"primary"}
		}
		out = append(out, Method{ID: a.ID, Type: a.Type, CreatedAt: a.CreatedAt, Usage: usage, Authenticator: a})
	}
	return out, nil
}

// Find is the method of List with ID id, or store.ErrNotFound.
func Find(ctx context.Context, st store.Store, u *store.User, id string) (*Method, error) {
	all, err := List(ctx, st, u)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, store.ErrNotFound
}
