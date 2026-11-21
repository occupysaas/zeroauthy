package mgmt

import (
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
)

// Metadata mutation does not update browser interaction timestamps.
func (h *Handlers) UpdateSession(w http.ResponseWriter, r *http.Request, id string) {
	if !h.refreshIISupported(w, r) {
		return
	}
	md, err := readTokenMetadata(r, "session_metadata")
	if err != nil {
		Fail(w, err)
		return
	}
	if !storableText(id) {
		Fail(w, errNoSession)
		return
	}
	ctx, tid := r.Context(), resolved(r).ID
	s, err := h.Store.Sessions().Get(ctx, tid, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !sessionLive(s, h.now())) {
		Fail(w, errNoSession)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "load session metadata", err))
		return
	}
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		if _, e := tx.Users().GetForUpdate(ctx, tid, s.UserID); e != nil {
			return e
		}
		current, e := tx.Sessions().GetForUpdate(ctx, tid, id)
		if e != nil {
			return e
		}
		if current.UserID != s.UserID || !sessionLive(current, h.now()) {
			return store.ErrNotFound
		}
		s, e = tx.Sessions().UpdateMetadata(ctx, tid, id, md)
		return e
	})
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errNoSession)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "update session metadata", err))
		return
	}
	writeJSON(w, 200, sessionJSON(s))
}
