package mgmt

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// RevokeSession ends a session and its online and offline grants atomically.
// Ordinary DELETE session intentionally keeps independent offline grants.
func (h *Handlers) RevokeSession(w http.ResponseWriter, r *http.Request, id string) {
	ctx, tn := r.Context(), resolved(r)
	if !h.refreshIISupported(w, r) {
		return
	}
	if !storableText(id) {
		writeJSON(w, http.StatusAccepted, map[string]any{})
		return
	}
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		// Acquire the same tenant lock as token mints before discovering
		// owners. Ordinary logout may already have removed the session row.
		if _, err := tx.Tenants().Get(ctx, tn.ID); err != nil {
			return err
		}
		session, err := tx.Sessions().GetForUpdate(ctx, tn.ID, id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		owners, err := tx.RefreshTokens().SessionOwners(ctx, tn.ID, id)
		if err != nil {
			return err
		}
		if session != nil {
			owners = append(owners, session.UserID)
		}
		slices.Sort(owners)
		owners = slices.Compact(owners)
		for _, uid := range owners {
			if _, err := tx.Users().GetForUpdate(ctx, tn.ID, uid); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		if _, err := tx.RefreshTokens().RevokeBySession(ctx, tn.ID, id, h.now()); err != nil {
			return err
		}
		for _, uid := range owners {
			if _, err := tx.Users().BumpVersion(ctx, tn.ID, uid); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		if session != nil {
			return tx.Sessions().Delete(ctx, tn.ID, id)
		}
		return nil
	})
	if err != nil {
		Fail(w, internalError(h, r, "revoke session", err))
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{})
}

func checkOnlineSupport(ctx context.Context, st store.Store) error {
	e := store.CheckRefreshTokensIISupport(ctx, st)
	if errors.Is(e, store.ErrRefreshTokensIIUnavailable) && !errors.Is(e, store.ErrRefreshTokensIISupportLost) {
		return badBody("online access requires storage support")
	}
	return e
}
