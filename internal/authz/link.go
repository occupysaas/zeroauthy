package authz

import (
	"context"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/userlink"
)

// linkRefused refuses a login whose api.authentication.setPrimaryUser
// cannot be applied: access_denied, nothing changed (Plan 40).
type linkRefused struct{ reason string }

func (e *linkRefused) Error() string { return e.reason }

// linkPrimary links the session's user, as a secondary, into primaryID
// inside commitLogin's transaction, and moves the session to the primary.
// stored is true when sess already exists in the store (its row goes with
// the secondary and is recreated for the primary). Two logins of one
// secondary racing into different primaries serialize on the secondary's
// user lock: the second finds it gone and is refused.
func (h *Handlers) linkPrimary(ctx context.Context, res tenant.Resolved, sess *store.LoginSession, primaryID string, stored bool) error {
	tid := res.Tenant.ID
	if primaryID == sess.UserID {
		return &linkRefused{"the primary user is the current user"}
	}
	p, err := h.Store.Users().GetForUpdate(ctx, tid, primaryID)
	if errors.Is(err, store.ErrNotFound) {
		return &linkRefused{"the primary user does not exist"}
	}
	if err != nil {
		return err
	}
	if p.Blocked {
		return &linkRefused{"the primary user is blocked"}
	}
	sec, err := h.Store.Users().GetForUpdate(ctx, tid, sess.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return &linkRefused{"the user was already linked"}
	}
	if err != nil {
		return err
	}
	if federation.RequireMicrosoftUser(ctx, h.Store, p) != nil || federation.RequireMicrosoftUser(ctx, h.Store, sec) != nil {
		return &linkRefused{"the account cannot be linked"}
	}
	own := sec.OwnIdentity()
	if own == nil || len(sec.Identities) > 1 {
		return &linkRefused{"the user has linked identities"}
	}
	if userlink.HoldsIdentity(p, own.Provider, own.UserID) {
		return &linkRefused{"the identity already exists on the primary user"}
	}
	passkeys, err := store.WebAuthnAvailable(ctx, h.Store)
	if err != nil {
		return err
	}
	var current *store.LoginSession
	if stored {
		if current, err = h.Store.Sessions().GetForUpdate(ctx, tid, sess.ID); err != nil {
			return err
		}
	}
	if err = userlink.Move(ctx, h.Store, p, sec, own, passkeys, h.now()); errors.Is(err, userlink.ErrIdentityHeld) {
		return &linkRefused{"the identity already exists on the primary user"}
	} else if err != nil {
		return err
	}
	sess.UserID = p.UserID
	if stored {
		// The secondary's deletion removed its sessions; this one continues
		// for the primary with the same ID and cookie.
		current.UserID = p.UserID
		if err = h.Store.Sessions().Create(ctx, current); err != nil {
			return err
		}
	}
	h.log().InfoContext(ctx, "linked account from post-login Action", "tenant", tid, "user_id", p.UserID, "secondary", sec.UserID)
	return nil
}

// recordMethods stores api.authentication.recordMethod calls on an existing
// session: each URL becomes a performed method and the session gains MFA
// proof, so the ID token's amr carries mfa (Plan 40).
func (h *Handlers) recordMethods(ctx context.Context, res tenant.Resolved, sess *store.LoginSession, methods []string) error {
	now := h.now()
	for _, m := range methods {
		am := store.AuthMethod{Name: m, At: now}
		if err := h.Store.Sessions().AddMethod(ctx, res.Tenant.ID, sess.ID, am); err != nil {
			return err
		}
		sess.AuthMethods = append(sess.AuthMethods, am)
	}
	if err := h.Store.Sessions().MarkMFA(ctx, res.Tenant.ID, sess.ID, now); err != nil {
		return err
	}
	sess.MFAAt = now
	return nil
}
