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
	err := h.Store.UserGrants().Delete(r.Context(), resolved(r).ID, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		Fail(w, internalError(h, r, "delete grant", err))
		return
	}
	if err == nil {
		h.audit(r, "delete grant", "grant_id", id)
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
	n, err := h.Store.UserGrants().DeleteByUser(r.Context(), resolved(r).ID, userID)
	if err != nil {
		Fail(w, internalError(h, r, "delete grants", err))
		return
	}
	h.audit(r, "delete user grants", "user_id", userID, "grants", n)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
