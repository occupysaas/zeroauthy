package mgmt

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *Handlers) refreshIISupported(w http.ResponseWriter, r *http.Request) bool {
	err := store.CheckRefreshTokensIISupport(r.Context(), h.Store)
	if err == nil {
		return true
	}
	if errors.Is(err, store.ErrRefreshTokensIIUnavailable) && !errors.Is(err, store.ErrRefreshTokensIISupportLost) {
		WriteError(w, 501, "refresh_tokens_unavailable", "This operation requires refresh token storage support")
	} else {
		Fail(w, internalError(h, r, "check refresh token capability", err))
	}
	return false
}

// GetRefreshTokens uses token IDs as exclusive ascending checkpoints.
func (h *Handlers) GetRefreshTokens(w http.ResponseWriter, r *http.Request) {
	if !h.refreshIISupported(w, r) {
		return
	}
	q := r.URL.Query()
	user := q.Get("user_id")
	if user == "" {
		Fail(w, badQuery("user_id is required"))
		return
	}
	if err := checkQueryText(r, "user_id", "client_id", "from"); err != nil {
		Fail(w, err)
		return
	}
	if len(q.Get("from")) > 256 {
		Fail(w, errBadCheckpoint)
		return
	}
	if err := h.userForSessions(r, user); err != nil {
		Fail(w, err)
		return
	}
	take, err := checkpointTake(r)
	if err != nil {
		Fail(w, err)
		return
	}
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	ctx, tid := r.Context(), resolved(r).ID
	from := q.Get("from")
	items := make([]*store.RefreshToken, 0, take+1)
	for len(items) <= take {
		page, next, e := h.Store.RefreshTokens().ListByUserPage(ctx, tid, user, q.Get("client_id"), from, 100)
		if e != nil {
			Fail(w, internalError(h, r, "list refresh tokens", e))
			return
		}
		for _, rt := range page {
			if rt.Access != "online" && tokenLive(rt, h.now()) {
				items = append(items, rt)
				if len(items) > take {
					break
				}
			}
		}
		if next == "" || len(items) > take {
			break
		}
		if next <= from {
			Fail(w, internalError(h, r, "list refresh token checkpoint", store.ErrInvalid))
			return
		}
		from = next
	}
	out := map[string]any{}
	if len(items) > take {
		items = items[:take]
		out["next"] = items[len(items)-1].ID
	}
	views := make([]map[string]any, len(items))
	for i, rt := range items {
		views[i] = project(refreshTokenJSON(rt, h.userinfoAudience(r)), fields, include)
	}
	out["refresh_tokens"] = views
	writeJSON(w, 200, out)
}

type revokeSelector struct {
	ids          []string
	user, client string
	audience     *string
}

func readRevokeSelector(r *http.Request) (revokeSelector, error) {
	var s revokeSelector
	b, err := decodeObject(r)
	if err != nil {
		return s, err
	}
	for k := range b {
		if k != "ids" && k != "user_id" && k != "client_id" && k != "audience" {
			return s, badBody("unknown revocation selector")
		}
	}
	if raw, ok := b["ids"]; ok {
		if len(b) != 1 || json.Unmarshal(raw, &s.ids) != nil || len(s.ids) < 1 || len(s.ids) > 100 {
			return s, badBody("ids must contain between 1 and 100 IDs and cannot be combined with other selectors")
		}
		for _, id := range s.ids {
			if id == "" || len(id) > 256 || !storableText(id) {
				return s, badBody("invalid refresh token ID")
			}
		}
		slices.Sort(s.ids)
		s.ids = slices.Compact(s.ids)
		return s, nil
	}
	raw, ok := b["user_id"]
	if !ok || json.Unmarshal(raw, &s.user) != nil || s.user == "" || !validUserID(s.user) {
		return s, badBody("user_id is required")
	}
	if raw, ok := b["client_id"]; ok {
		if json.Unmarshal(raw, &s.client) != nil || s.client == "" || !storableText(s.client) || len(s.client) > 256 {
			return s, badBody("invalid client_id")
		}
	}
	if raw, ok := b["audience"]; ok {
		var audience string
		if s.client == "" || string(raw) == "null" || json.Unmarshal(raw, &audience) != nil || !storableText(audience) || utf8.RuneCountInString(audience) > 600 {
			return s, badBody("audience requires client_id")
		}
		s.audience = &audience
	}
	return s, nil
}

// RevokeRefreshTokens runs synchronously while retaining the public 202 response.
func (h *Handlers) RevokeRefreshTokens(w http.ResponseWriter, r *http.Request) {
	if !h.refreshIISupported(w, r) {
		return
	}
	sel, err := readRevokeSelector(r)
	if err != nil {
		Fail(w, err)
		return
	}
	ctx, tid := r.Context(), resolved(r).ID
	records := map[string]*store.RefreshToken{}
	users := []string{}
	if sel.user != "" {
		users = append(users, sel.user)
	} else {
		for _, id := range sel.ids {
			rt, e := h.Store.RefreshTokens().Get(ctx, tid, id)
			if errors.Is(e, store.ErrNotFound) {
				continue
			}
			if e != nil {
				Fail(w, internalError(h, r, "load revocation token", e))
				return
			}
			if rt.Access != "online" {
				records[id] = rt
				users = append(users, rt.UserID)
			}
		}
	}
	slices.Sort(users)
	users = slices.Compact(users)
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		for _, u := range users {
			if _, e := tx.Users().GetForUpdate(ctx, tid, u); e != nil && !errors.Is(e, store.ErrNotFound) {
				return e
			}
		}
		if sel.user != "" {
			if _, e := tx.RefreshTokens().RevokeOfflineByUser(ctx, tid, sel.user, sel.client, sel.audience, h.now()); e != nil {
				return e
			}
		} else {
			for _, id := range sel.ids {
				prior := records[id]
				if prior == nil {
					continue
				}
				current, e := tx.RefreshTokens().Get(ctx, tid, id)
				if errors.Is(e, store.ErrNotFound) {
					continue
				}
				if e != nil {
					return e
				}
				if current.Access == "online" || current.UserID != prior.UserID || current.FamilyID != prior.FamilyID {
					continue
				}
				if e := tx.RefreshTokens().RevokeFamily(ctx, tid, current.FamilyID, h.now()); e != nil {
					return e
				}
			}
		}
		for _, u := range users {
			if _, e := tx.Users().BumpVersion(ctx, tid, u); e != nil && !errors.Is(e, store.ErrNotFound) {
				return e
			}
		}
		return nil
	})
	if err != nil {
		Fail(w, internalError(h, r, "revoke refresh tokens", err))
		return
	}
	writeJSON(w, 202, map[string]any{})
}

func readTokenMetadata(r *http.Request, key string) (map[string]string, error) {
	body, err := decodeObject(r)
	if err != nil {
		return nil, err
	}
	if len(body) != 1 {
		return nil, badBody("only %s may be updated", key)
	}
	raw, ok := body[key]
	if !ok {
		return nil, badBody("only %s may be updated", key)
	}
	if string(raw) == "null" {
		return nil, nil
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil || values == nil || len(values) > 25 {
		return nil, badBody("metadata must contain at most 25 string properties")
	}
	md := make(map[string]string, len(values))
	for k, v := range values {
		var value string
		if string(v) == "null" || json.Unmarshal(v, &value) != nil || utf8.RuneCountInString(k) > 255 || utf8.RuneCountInString(value) > 255 {
			return nil, badBody("metadata keys and string values must not exceed 255 characters")
		}
		md[k] = value
	}
	return md, nil
}

func (h *Handlers) UpdateRefreshToken(w http.ResponseWriter, r *http.Request, id string) {
	if !h.refreshIISupported(w, r) {
		return
	}
	md, err := readTokenMetadata(r, "refresh_token_metadata")
	if err != nil {
		Fail(w, err)
		return
	}
	if !storableText(id) {
		Fail(w, errNoRefreshToken)
		return
	}
	ctx, tid := r.Context(), resolved(r).ID
	rt, err := h.Store.RefreshTokens().Get(ctx, tid, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (rt.Access == "online" || !tokenLive(rt, h.now()))) {
		Fail(w, errNoRefreshToken)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "load refresh token metadata", err))
		return
	}
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		if _, e := tx.Users().GetForUpdate(ctx, tid, rt.UserID); e != nil {
			return e
		}
		current, e := tx.RefreshTokens().Get(ctx, tid, id)
		if e != nil {
			return e
		}
		if current.UserID != rt.UserID || current.Access == "online" || !tokenLive(current, h.now()) {
			return store.ErrNotFound
		}
		rt, e = tx.RefreshTokens().UpdateMetadata(ctx, tid, id, md)
		return e
	})
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errNoRefreshToken)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "update refresh token metadata", err))
		return
	}
	writeJSON(w, 200, refreshTokenJSON(rt, h.userinfoAudience(r)))
}
