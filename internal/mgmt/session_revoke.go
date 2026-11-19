package mgmt

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
)

// RevokeSession ends a session and its online and offline grants atomically.
// Ordinary DELETE session intentionally keeps independent offline grants.
func (h *Handlers) RevokeSession(w http.ResponseWriter, r *http.Request, id string) {
	ctx, tn := r.Context(), resolved(r)
	if e := store.CheckRefreshTokensIISupport(ctx, h.Store); e != nil {
		if errors.Is(e, store.ErrRefreshTokensIIUnavailable) && !errors.Is(e, store.ErrRefreshTokensIISupportLost) {
			WriteError(w, http.StatusNotImplemented, "refresh_tokens_unavailable", "This operation requires refresh token storage support")
		} else {
			Fail(w, internalError(h, r, "check session revoke capability", e))
		}
		return
	}
	if !storableText(id) {
		writeJSON(w, http.StatusAccepted, map[string]any{})
		return
	}
	s, err := h.Store.Sessions().Get(ctx, tn.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusAccepted, map[string]any{})
		return
	}
	if err == nil {
		err = h.Store.WithTx(ctx, func(tx store.Store) error {
			if _, e := tx.Users().GetForUpdate(ctx, tn.ID, s.UserID); e != nil && !errors.Is(e, store.ErrNotFound) {
				return e
			}
			current, e := tx.Sessions().Get(ctx, tn.ID, id)
			if errors.Is(e, store.ErrNotFound) {
				return nil
			}
			if e != nil {
				return e
			}
			if current.UserID != s.UserID {
				return store.ErrNotFound
			}
			if _, e = tx.RefreshTokens().RevokeBySession(ctx, tn.ID, id, h.now()); e != nil {
				return e
			}
			if _, e := tx.Users().BumpVersion(ctx, tn.ID, s.UserID); e != nil && !errors.Is(e, store.ErrNotFound) {
				return e
			}
			return tx.Sessions().Delete(ctx, tn.ID, id)
		})
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
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
