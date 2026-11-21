package mgmt

import (
	"errors"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Users' grants (U9, D-0043): Auth0's object, with its field name clientID.

func grantJSON(g *store.UserGrant) map[string]any {
	scope := slices.Clone(g.Scopes)
	slices.Sort(scope)
	if scope == nil {
		scope = []string{}
	}
	return map[string]any{"id": g.ID, "clientID": g.ClientID, "user_id": g.UserID, "audience": g.Audience, "scope": scope}
}

// GetGrants lists grants in ID order, filtered by user_id, client_id and
// audience. An unknown user gives an empty list.
func (h *Handlers) GetGrants(w http.ResponseWriter, r *http.Request) {
	if err := checkQueryText(r, "user_id", "client_id", "audience"); err != nil {
		Fail(w, err)
		return
	}
	q := r.URL.Query()
	f := store.UserGrantFilter{UserID: q.Get("user_id"), ClientID: q.Get("client_id"), Audience: q.Get("audience")}
	page, perPage, totals, err := Page(r)
	if err != nil {
		Fail(w, err)
		return
	}
	got, total, err := h.Store.UserGrants().List(r.Context(), resolved(r).ID, f, store.Page{Offset: page * perPage, Limit: perPage})
	if err != nil {
		Fail(w, internalError(h, r, "list grants", err))
		return
	}
	out := make([]map[string]any, len(got))
	for i, g := range got {
		out[i] = grantJSON(g)
	}
	WritePage(w, "grants", out, page, perPage, total, totals)
}

// DeleteGrant deletes one grant, also when there is none.
func (h *Handlers) DeleteGrant(w http.ResponseWriter, r *http.Request, id string) {
	var n int
	var err error
	if id != "" && storableText(id) {
		n, err = h.deleteGrants(r, id, "")
	}
	if err != nil {
		Fail(w, internalError(h, r, "delete grant", err))
		return
	}
	if n != 0 {
		logDetails(r, "delete grant", "grant_id", id)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// DeleteGrantsByUser deletes every grant of the user in user_id, which is
// required.
func (h *Handlers) DeleteGrantsByUser(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		Fail(w, badQuery("Query validation error: user_id is required"))
		return
	}
	if !storableText(userID) {
		Fail(w, errUnstorableQuery)
		return
	}
	n, err := h.deleteGrants(r, "", userID)
	if err != nil {
		Fail(w, internalError(h, r, "delete grants", err))
		return
	}
	logDetails(r, "delete user grants", "user_id", userID, "grants", n)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// deleteGrants deletes either the named grant or the user's grants. An initially
// legacy plugin retains its existing deletion semantics (LR48-12).
func (h *Handlers) deleteGrants(r *http.Request, id, userID string) (int, error) {
	ctx, tid := r.Context(), resolved(r).ID
	if err := store.CheckRefreshTokensIISupport(ctx, h.Store); err != nil {
		if !errors.Is(err, store.ErrRefreshTokensIIUnavailable) || errors.Is(err, store.ErrRefreshTokensIISupportLost) {
			return 0, err
		}
		if id == "" {
			return h.Store.UserGrants().DeleteByUser(ctx, tid, userID)
		}
		if err := h.Store.UserGrants().Delete(ctx, tid, id); errors.Is(err, store.ErrNotFound) {
			return 0, nil
		} else if err != nil {
			return 0, err
		}
		return 1, nil
	}

	// Locate the owner before the transaction so its first lock is the same
	// one used by token minting. Re-read the grant after acquiring that lock.
	if id != "" {
		g, err := h.Store.UserGrants().Get(ctx, tid, id)
		if errors.Is(err, store.ErrNotFound) {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		userID = g.UserID
	}
	n := 0
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		_, err := tx.Users().GetForUpdate(ctx, tid, userID)
		hasUser := err == nil
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		var grants []*store.UserGrant
		if id == "" {
			grants, err = tx.UserGrants().ListByUser(ctx, tid, userID)
			if err != nil {
				return err
			}
		} else {
			g, err := tx.UserGrants().Get(ctx, tid, id)
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			if g.UserID != userID {
				return store.ErrConflict
			}
			grants = []*store.UserGrant{g}
		}
		at := h.now()
		for _, g := range grants {
			if err := tx.UserGrants().Delete(ctx, tid, g.ID); err != nil {
				return err
			}
			if _, err := tx.RefreshTokens().RevokeByUserClient(ctx, tid, userID, g.ClientID, g.Audience, at); err != nil {
				return err
			}
			n++
		}
		if n > 0 && hasUser {
			_, err = tx.Users().BumpVersion(ctx, tid, userID)
			return err
		}
		return nil
	})
	return n, err
}
