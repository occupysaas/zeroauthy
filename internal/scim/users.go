package scim

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// subjectOf is the user's identity subject on the connection, or "" when
// the user has no identity there.
func (c *call) subjectOf(u *store.User) string {
	for _, id := range u.Identities {
		if id.Connection == c.conn.Name && id.Provider == c.conn.Strategy {
			if sub, ok := strings.CutPrefix(id.UserID, c.conn.Name+"|"); ok {
				return sub
			}
		}
	}
	return ""
}

// userResource renders a user as a SCIM User.
func (c *call) userResource(u *store.User) map[string]any {
	res := c.mapping.Render(u)
	schemas := []string{CoreUser}
	if _, ok := res[EnterpriseUser]; ok {
		schemas = append(schemas, EnterpriseUser)
	}
	res["schemas"] = schemas
	res["id"] = u.UserID
	if sub := c.subjectOf(u); sub != "" {
		Set(res, c.uidPath, sub)
	}
	res["active"] = !u.Blocked
	res["meta"] = meta("User", c.base()+"/Users/"+u.UserID, u.CreatedAt, u.UpdatedAt)
	return res
}

// loadUser returns the user when it has an identity on the connection;
// another connection's user is not found (Review Focus 1).
func (h *Handler) loadUser(r *http.Request, c *call, tx store.Store, forUpdate bool) (*store.User, error) {
	id := chi.URLParam(r, "id")
	if id == "" || len(id) > 1280 {
		return nil, errNotFound
	}
	var u *store.User
	var err error
	if forUpdate {
		u, err = tx.Users().GetForUpdate(r.Context(), c.tenant.ID, id)
	} else {
		u, err = tx.Users().Get(r.Context(), c.tenant.ID, id)
	}
	if errors.Is(err, store.ErrNotFound) || err == nil && c.subjectOf(u) == "" {
		return nil, errNotFound
	}
	return u, err
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request, c *call) error {
	u, err := h.loadUser(r, c, h.Store, false)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, c.userResource(u))
	return nil
}

var searchableRoot = map[string]bool{"email": true, "email_verified": true, "name": true, "given_name": true, "family_name": true, "nickname": true, "username": true}

func samePath(a, b Path) bool {
	return strings.EqualFold(a.URN, b.URN) && strings.EqualFold(a.Attr, b.Attr) && strings.EqualFold(a.Sub, b.Sub)
}

func termValue(v any) (string, store.ValueKind, error) {
	switch t := v.(type) {
	case string:
		return t, store.KindString, nil
	case bool:
		return fmt.Sprint(t), store.KindBool, nil
	case float64:
		return fmt.Sprint(t), store.KindNumber, nil
	}
	return "", 0, errorf(http.StatusBadRequest, "invalidFilter", "Filter values must be strings, booleans or numbers.")
}

// userQuery translates a SCIM filter to a user query over mapped,
// searchable attributes (Auth0: root attributes or app_metadata).
func (c *call) userQuery(f *Filter) (*store.UserQuery, error) {
	switch f.Op {
	case OpAnd, OpOr:
		l, err := c.userQuery(f.Left)
		if err != nil {
			return nil, err
		}
		r, err := c.userQuery(f.Right)
		if err != nil {
			return nil, err
		}
		op := store.QueryAnd
		if f.Op == OpOr {
			op = store.QueryOr
		}
		return &store.UserQuery{Op: op, Kids: []*store.UserQuery{l, r}}, nil
	}
	p := f.Attr()
	unsupported := errorf(http.StatusBadRequest, "invalidFilter", "Filtering on "+f.Path+" is not supported.")
	switch {
	case p.URN == "" && strings.EqualFold(p.Attr, "id") && p.Sub == "":
		s, ok := f.Value.(string)
		if !ok {
			return nil, unsupported
		}
		return &store.UserQuery{Op: store.QueryTerm, Field: "user_id", Kind: store.KindString, Value: s}, nil
	case samePath(p, c.uidPath):
		s, ok := f.Value.(string)
		if !ok {
			return nil, unsupported
		}
		return &store.UserQuery{Op: store.QueryTerm, Field: "identities.user_id", Kind: store.KindString, Value: c.conn.Name + "|" + s}, nil
	case p.URN == "" && strings.EqualFold(p.Attr, "active") && p.Sub == "":
		active := ActiveValue(f.Value)
		return &store.UserQuery{Op: store.QueryTerm, Field: "blocked", Kind: store.KindBool, Value: fmt.Sprint(!active)}, nil
	}
	e, ok := c.mapping.Find(p)
	if !ok {
		return nil, unsupported
	}
	if e.meta == "" {
		if !searchableRoot[e.auth0] {
			return nil, unsupported
		}
		field, err := store.ParseUserField(e.auth0)
		if err != nil {
			return nil, unsupported
		}
		v, kind, err := termValue(f.Value)
		if err != nil || kind != field.Kind {
			return nil, unsupported
		}
		return &store.UserQuery{Op: store.QueryTerm, Field: e.auth0, Kind: kind, Value: v}, nil
	}
	if e.meta != "app_metadata" {
		return nil, unsupported // Auth0: only app_metadata is searchable
	}
	v, kind, err := termValue(f.Value)
	if err != nil {
		return nil, err
	}
	return &store.UserQuery{Op: store.QueryTerm, Field: e.auth0, Kind: kind, Value: v}, nil
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request, c *call) error {
	start, count, err := page(r)
	if err != nil {
		return err
	}
	q := &store.UserQuery{Op: store.QueryTerm, Field: "identities.connection", Kind: store.KindString, Value: c.conn.Name}
	if raw := r.URL.Query().Get("filter"); raw != "" {
		f, err := ParseFilter(raw)
		if err != nil {
			return errorf(http.StatusBadRequest, "invalidFilter", "The filter is not valid or uses an unsupported operator (eq, and, or).")
		}
		fq, err := c.userQuery(f)
		if err != nil {
			return err
		}
		q = &store.UserQuery{Op: store.QueryAnd, Kids: []*store.UserQuery{q, fq}}
	}
	if err := q.Validate(); err != nil {
		return errorf(http.StatusBadRequest, "invalidFilter", "The filter is not valid.")
	}
	limit := count
	if limit == 0 {
		limit = 1 // only the total is wanted; the page is dropped below
	}
	users, total, err := h.Store.Users().List(r.Context(), c.tenant.ID, q, store.UserSort{Field: "created_at"}, store.Page{Offset: start - 1, Limit: limit})
	if err != nil {
		return err
	}
	var out []any
	if count > 0 {
		for _, u := range users {
			out = append(out, c.userResource(u))
		}
	}
	writeJSON(w, http.StatusOK, listResponse(total, start, out))
	return nil
}

// subjectFrom reads the user ID attribute of a resource.
func (c *call) subjectFrom(res map[string]any) (string, error) {
	v, ok := Get(res, c.uidPath)
	s, isStr := v.(string)
	if !ok || !isStr || strings.TrimSpace(s) == "" {
		return "", errorf(http.StatusBadRequest, "invalidValue", "The user ID attribute "+c.uidPath.String()+" is required.")
	}
	if err := federation.ValidateSubject(s); err != nil {
		return "", errorf(http.StatusBadRequest, "invalidValue", "The user ID attribute "+c.uidPath.String()+" is not a valid identifier.")
	}
	return s, nil
}

func refusePassword(res map[string]any) error {
	if _, ok := lookup(res, "password"); ok {
		return errorf(http.StatusBadRequest, "invalidValue", "password is not supported for enterprise connections.")
	}
	return nil
}

func applyError(err error) error {
	return errorf(http.StatusBadRequest, "invalidValue", err.Error())
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request, c *call) error {
	var res map[string]any
	if err := readBody(r, &res); err != nil {
		return err
	}
	if err := refusePassword(res); err != nil {
		return err
	}
	sub, err := c.subjectFrom(res)
	if err != nil {
		return err
	}
	now := h.now()
	u := &store.User{TenantID: c.tenant.ID, UserID: store.FederatedPublicID(c.conn.Strategy, c.conn.Name, sub), CreatedAt: now, UpdatedAt: now,
		Identities: []store.Identity{{Connection: c.conn.Name, Provider: c.conn.Strategy, UserID: c.conn.Name + "|" + sub}}}
	if err := c.mapping.Apply(res, u); err != nil {
		return applyError(err)
	}
	if v, ok := lookup(res, "active"); ok {
		u.Blocked = !ActiveValue(v)
	}
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := tx.Users().FindByIdentity(r.Context(), c.tenant.ID, c.conn.ID, sub); err == nil {
			return store.ErrConflict
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		return tx.Users().Create(r.Context(), u)
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		return errorf(http.StatusConflict, "uniqueness", "A user with this user ID attribute already exists.")
	case errors.Is(err, store.ErrInvalid):
		return errorf(http.StatusBadRequest, "invalidValue", "The user ID attribute is not valid for this connection.")
	case err != nil:
		return err
	}
	created, err := h.Store.Users().Get(r.Context(), c.tenant.ID, u.UserID)
	if err != nil {
		return err
	}
	w.Header().Set("Location", c.base()+"/Users/"+u.UserID)
	writeJSON(w, http.StatusCreated, c.userResource(created))
	return nil
}

// replace writes res over the user: mapped fields, active, and the
// immutable user ID attribute. Deactivation ends the user's sessions,
// revokes refresh tokens and sends back-channel logout (Review Focus 2).
func (h *Handler) replace(r *http.Request, c *call, res map[string]any, mutate func(cur *store.User) (map[string]any, error)) (*store.User, error) {
	var out *store.User
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		u, err := h.loadUser(r, c, tx, true)
		if err != nil {
			return err
		}
		if mutate != nil {
			if res, err = mutate(u); err != nil {
				return err
			}
		}
		if err := refusePassword(res); err != nil {
			return err
		}
		if v, ok := Get(res, c.uidPath); ok {
			if s, _ := v.(string); s != c.subjectOf(u) {
				return errorf(http.StatusBadRequest, "mutability", "The user ID attribute "+c.uidPath.String()+" cannot change.")
			}
		}
		wasBlocked := u.Blocked
		if err := c.mapping.Apply(res, u); err != nil {
			return applyError(err)
		}
		if v, ok := lookup(res, "active"); ok {
			u.Blocked = !ActiveValue(v)
		}
		u.UpdatedAt = h.now()
		if err := tx.Users().Update(r.Context(), u); err != nil {
			return err
		}
		if u.Blocked && !wasBlocked {
			if err := h.deactivate(r, tx, c.tenant.ID, u.UserID); err != nil {
				return err
			}
		}
		out = u
		return nil
	})
	if errors.Is(err, store.ErrConflict) {
		return nil, errorf(http.StatusConflict, "uniqueness", "The change conflicts with another user.")
	}
	return out, err
}

// deactivate applies Auth0's documented effects of active=false.
func (h *Handler) deactivate(r *http.Request, tx store.Store, tid, uid string) error {
	ctx := r.Context()
	if _, err := tx.Users().BumpVersion(ctx, tid, uid); err != nil {
		return err
	}
	if _, err := tx.RefreshTokens().RevokeByUser(ctx, tid, uid, h.now()); err != nil {
		return err
	}
	if h.EndSessions != nil {
		return h.EndSessions(ctx, tx, tid, uid)
	}
	_, err := tx.Sessions().DeleteByUser(ctx, tid, uid)
	return err
}

func (h *Handler) replaceUser(w http.ResponseWriter, r *http.Request, c *call) error {
	var res map[string]any
	if err := readBody(r, &res); err != nil {
		return err
	}
	u, err := h.replace(r, c, res, nil)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, c.userResource(u))
	return nil
}

func (h *Handler) patchUser(w http.ResponseWriter, r *http.Request, c *call) error {
	var p PatchRequest
	if err := readBody(r, &p); err != nil {
		return err
	}
	u, err := h.replace(r, c, nil, func(cur *store.User) (map[string]any, error) {
		res := c.userResource(cur)
		if err := ApplyPatch(res, p.Operations); err != nil {
			return nil, errorf(http.StatusBadRequest, "invalidPath", "The patch operations are not valid.")
		}
		return res, nil
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, c.userResource(u))
	return nil
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request, c *call) error {
	u, err := h.loadUser(r, c, h.Store, false)
	if err != nil {
		return err
	}
	if h.DeleteUser != nil {
		err = h.DeleteUser(r, u.UserID)
	} else {
		err = h.Store.Users().Delete(r.Context(), c.tenant.ID, u.UserID)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
