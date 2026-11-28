// Package userlink moves a secondary user's identity onto a primary user:
// the operation behind POST /api/v2/users/{id}/identities and Plan 40's
// api.authentication.setPrimaryUser. Callers run their own eligibility
// checks first and call Move inside a transaction that holds the
// primary's user lock.
package userlink

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ErrIdentityHeld means the primary already holds the moved identity.
var ErrIdentityHeld = errors.New("userlink: identity already exists on the primary")

// HoldsIdentity reports whether u holds the (provider, userID) identity.
func HoldsIdentity(u *store.User, provider, userID string) bool {
	return slices.ContainsFunc(u.Identities, func(id store.Identity) bool { return id.Provider == provider && id.UserID == userID })
}

// Move links sec into p through tx: sec's own identity own moves to p with
// its profile data, sec's passkeys move when passkeys is true, sec is
// deleted (with everything that names it), p's version bumps. The
// secondary goes first, so its logins are free for the primary; a
// federated identity's index entry moves to the primary in this
// transaction, and its sealed token record (keyed by identity) stays
// (Plan 24).
func Move(ctx context.Context, tx store.Store, p, sec *store.User, own *store.Identity, passkeys bool, now time.Time) error {
	moved := store.Identity{Connection: own.Connection, Provider: own.Provider, UserID: own.UserID, PasswordHash: own.PasswordHash, ImportedHash: own.ImportedHash,
		ProfileData: map[string]any{"email": sec.Email, "email_verified": sec.EmailVerified}, ProviderData: maps.Clone(own.ProviderData)}
	if sec.Username != "" {
		moved.ProfileData["username"] = sec.Username
	}
	// Move credentials before user deletion cascades remove the secondary's MFA.
	if passkeys {
		if err := tx.WebAuthn().MovePasskeys(ctx, p.TenantID, sec.UserID, p.UserID, ""); err != nil {
			return err
		}
	}
	sec.Identities = nil
	if err := tx.Users().Update(ctx, sec); err != nil {
		return err
	}
	if err := tx.Users().Delete(ctx, p.TenantID, sec.UserID); err != nil {
		return err
	}
	p.Identities = append(p.Identities, moved)
	p.UpdatedAt = now
	if err := tx.Users().Update(ctx, p); errors.Is(err, store.ErrConflict) {
		return ErrIdentityHeld
	} else if err != nil {
		return err
	}
	_, err := tx.Users().BumpVersion(ctx, p.TenantID, p.UserID)
	return err
}
