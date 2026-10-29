package mgmt

import (
	"errors"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Organization members and member roles (Plan 29, D-0055). Shapes follow
// internal/orgrules/inventory.json and the observation notes.

var (
	// Observed: the non-member, unknown-role and bad-cursor answers carry no
	// errorCode; an unknown user in a member batch is inexistent_user.
	errOrgNotMember   = &Error{Status: http.StatusNotFound, Message: "The user is not a member of the organization"}
	errOrgRoleMissing = &Error{Status: http.StatusNotFound, Message: "The role does not exist"}
	errOrgCursor      = &Error{Status: http.StatusBadRequest, Message: "The from parameter is not a valid checkpoint"}
)

// memberFields are the fields of a member listing; roles only on the
// organization member list.
var memberFields = []string{"user_id", "email", "picture", "name", "roles"}

// readIDBatch reads {field: [id, ...]} with 1 to batch_ids_max non-empty IDs
// (D-0055). Anything else is 400 invalid_body.
func readIDBatch(r *http.Request, field string) ([]string, error) {
	body, err := decodeObject(r)
	if err != nil {
		return nil, err
	}
	for k := range body {
		if k != field {
			return nil, badBody("unknown property %q", k)
		}
	}
	raw, ok := body[field]
	if !ok {
		return nil, badBody("%s is required", field)
	}
	var ids []string
	maxIDs := orgrules.Limit("batch_ids_max")
	if decodeStrict(raw, &ids) != nil || len(ids) < 1 || len(ids) > maxIDs || slices.Contains(ids, "") {
		return nil, badBody("%s must be an array of 1 to %d identifiers", field, maxIDs)
	}
	return ids, nil
}

// memberQuery reads a member listing's pagination and fields. allowed are
// the field names; roles reports whether the roles were asked for.
func memberQuery(r *http.Request, allowed []string, params ...string) (p store.OrgPage, checkpoint bool, project func(map[string]any) map[string]any, roles bool, err error) {
	if p, checkpoint, err = orgQuery(r, params...); err != nil {
		return
	}
	fields, include, err := Fields(r)
	if err != nil {
		return
	}
	for _, f := range fields {
		if !slices.Contains(allowed, f) {
			err = badQuery("Query validation error: fields may only name %v", allowed)
			return
		}
	}
	// Without fields every field but roles; with include_fields true (the
	// default) only the named ones; with false all but the named ones and
	// never roles (observed).
	roles = include && slices.Contains(fields, "roles")
	project = func(item map[string]any) map[string]any {
		for k := range item {
			listed := slices.Contains(fields, k)
			if len(fields) > 0 && listed != include || k == "roles" && !roles {
				delete(item, k)
			}
		}
		return item
	}
	return
}

// memberViews renders the member user IDs with the joined user fields and,
// with roles, the member's roles as {id, name}. A user deleted meanwhile is
// left out.
func (h *Handlers) memberViews(r *http.Request, tx store.Store, orgID string, ids []string, roles bool) ([]map[string]any, error) {
	tid := resolved(r).ID
	out := make([]map[string]any, 0, len(ids))
	for _, uid := range ids {
		u, err := tx.Users().Get(r.Context(), tid, uid)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		item := map[string]any{"user_id": u.UserID}
		for k, v := range map[string]string{"email": u.Email, "picture": u.Picture, "name": u.Name} {
			if v != "" {
				item[k] = v
			}
		}
		if roles {
			list, err := h.memberRoleList(r, tx, orgID, uid, store.OrgPage{PerPage: orgrules.Limit("roles_per_member_max")})
			if err != nil {
				return nil, err
			}
			views := make([]map[string]any, len(list.Items))
			for i, role := range list.Items {
				views[i] = map[string]any{"id": role.ID, "name": role.Name}
			}
			item["roles"] = views
		}
		out = append(out, item)
	}
	return out, nil
}

// memberRoleList returns a member's roles, resolved; a role deleted
// meanwhile is left out. A non-member is errOrgNotMember.
func (h *Handlers) memberRoleList(r *http.Request, tx store.Store, orgID, userID string, p store.OrgPage) (store.OrgResult[store.Role], error) {
	tid := resolved(r).ID
	res, err := tx.Organizations().MemberRoles(r.Context(), tid, orgID, userID, p)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.OrgResult[store.Role]{}, errOrgNotMember
	case errors.Is(err, store.ErrInvalid):
		return store.OrgResult[store.Role]{}, errOrgCursor
	case err != nil:
		return store.OrgResult[store.Role]{}, err
	}
	out := store.OrgResult[store.Role]{Items: []store.Role{}, Total: res.Total, Next: res.Next}
	for _, id := range res.Items {
		role, err := tx.RBAC().GetRole(r.Context(), tid, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return out, err
		}
		out.Items = append(out.Items, *role)
	}
	return out, nil
}

func (h *Handlers) ListOrganizationMembers(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := h.orgs(w); !ok {
		return
	}
	p, checkpoint, project, roles, err := memberQuery(r, memberFields, "page", "per_page", "include_totals", "from", "take", "fields", "include_fields")
	if err != nil {
		Fail(w, err)
		return
	}
	// The listing takes either member scope; the roles need theirs.
	if roles && !callerHas(r, "read:organization_member_roles") {
		Fail(w, insufficientScope("read:organization_member_roles"))
		return
	}
	var items []map[string]any
	var res store.OrgResult[string]
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := loadOrg(r, tx.Organizations(), id); err != nil {
			return err
		}
		if res, err = tx.Organizations().Members(r.Context(), resolved(r).ID, id, p); errors.Is(err, store.ErrInvalid) {
			return errOrgCursor
		} else if err != nil {
			return err
		}
		items, err = h.memberViews(r, tx, id, res.Items, roles)
		return err
	})
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	for i := range items {
		items[i] = project(items[i])
	}
	writeOrgList(w, "members", items, res.Total, res.Next, p, checkpoint, false)
}

func (h *Handlers) AddOrganizationMembers(w http.ResponseWriter, r *http.Request, id string) {
	h.changeMembers(w, r, id, true)
}

func (h *Handlers) RemoveOrganizationMembers(w http.ResponseWriter, r *http.Request, id string) {
	h.changeMembers(w, r, id, false)
}

// changeMembers adds (all or none; an unknown user is 404 inexistent_user)
// or removes members. Both are idempotent; removal keeps role assignments.
func (h *Handlers) changeMembers(w http.ResponseWriter, r *http.Request, id string, add bool) {
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	if !orgrules.ValidID(id) {
		Fail(w, errOrganizationURI)
		return
	}
	ids, err := readIDBatch(r, "members")
	if err != nil {
		Fail(w, err)
		return
	}
	if _, err := loadOrg(r, orgs, id); err != nil {
		h.orgError(w, r, err)
		return
	}
	tid := resolved(r).ID
	action := "remove organization members"
	if add {
		action = "add organization members"
		err = orgs.AddMembers(r.Context(), tid, id, ids)
	} else {
		err = orgs.RemoveMembers(r.Context(), tid, id, ids)
	}
	if errors.Is(err, store.ErrNotFound) {
		// The organization was found above, so a user is missing (or the
		// organization was deleted meanwhile).
		err = errUserNotFound
	}
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	h.audit(r, action, "id", id, "members", len(ids))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ListOrganizationMemberRoles(w http.ResponseWriter, r *http.Request, id, userID string) {
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	// Offset only: take and from are refused (observed).
	p, _, err := orgQuery(r, "page", "per_page", "include_totals")
	if err != nil {
		Fail(w, err)
		return
	}
	if _, err := loadOrg(r, orgs, id); err != nil {
		h.orgError(w, r, err)
		return
	}
	res, err := h.memberRoleList(r, h.Store, id, userID, p)
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	items := make([]map[string]any, len(res.Items))
	for i, role := range res.Items {
		items[i] = roleView(role)
	}
	writeOrgList(w, "roles", items, res.Total, "", p, false, false)
}

func (h *Handlers) AddOrganizationMemberRoles(w http.ResponseWriter, r *http.Request, id, userID string) {
	h.changeMemberRoles(w, r, id, userID, true)
}

func (h *Handlers) RemoveOrganizationMemberRoles(w http.ResponseWriter, r *http.Request, id, userID string) {
	h.changeMemberRoles(w, r, id, userID, false)
}

// changeMemberRoles assigns or removes a member's roles, idempotently. The
// user must be a member (404); an assigned role must exist (404, nothing
// assigned); removal for a user that does not exist is 404 inexistent_user
// (all observed). A member holds at most roles_per_member_max roles.
func (h *Handlers) changeMemberRoles(w http.ResponseWriter, r *http.Request, id, userID string, add bool) {
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	if !orgrules.ValidID(id) {
		Fail(w, errOrganizationURI)
		return
	}
	ids, err := readIDBatch(r, "roles")
	if err != nil {
		Fail(w, err)
		return
	}
	if _, err := loadOrg(r, orgs, id); err != nil {
		h.orgError(w, r, err)
		return
	}
	tid := resolved(r).ID
	if !add {
		if _, err := h.getUser(r, userID); err != nil {
			Fail(w, err)
			return
		}
	}
	member, err := orgs.IsMember(r.Context(), tid, id, userID)
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	if !member {
		Fail(w, errOrgNotMember)
		return
	}
	switch err := orgs.ChangeMemberRoles(r.Context(), tid, id, userID, add, ids); {
	case errors.Is(err, store.ErrNotFound):
		// Membership was checked, so a role is missing (or the member was
		// removed meanwhile).
		Fail(w, errOrgRoleMissing)
		return
	case errors.Is(err, store.ErrPrecondition):
		Fail(w, badBody("a member can have at most %d roles in an organization (D-0055)", orgrules.Limit("roles_per_member_max")))
		return
	case err != nil:
		h.orgError(w, r, err)
		return
	}
	action := "remove organization member roles"
	if add {
		action = "assign organization member roles"
	}
	h.audit(r, action, "id", id, "user_id", userID, "roles", len(ids))
	w.WriteHeader(http.StatusNoContent)
}

// checkpointQuery reads from and take of a checkpoint-only listing; with
// neither, the first page of the default size.
func checkpointQuery(r *http.Request, params ...string) (store.OrgPage, error) {
	p, _, err := orgQuery(r, params...)
	if err == nil && p.From == "" && p.Take == 0 {
		p.Take = orgrules.Limit("take_default")
	}
	return p, err
}

// ListOrganizationMemberEffectiveRoles lists the member's roles with their
// sources. Until groups exist (Plan 38) every role is a direct one.
func (h *Handlers) ListOrganizationMemberEffectiveRoles(w http.ResponseWriter, r *http.Request, id, userID string) {
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	p, err := checkpointQuery(r, "from", "take")
	if err != nil {
		Fail(w, err)
		return
	}
	if _, err := loadOrg(r, orgs, id); err != nil {
		h.orgError(w, r, err)
		return
	}
	res, err := h.memberRoleList(r, h.Store, id, userID, p)
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	items := make([]map[string]any, len(res.Items))
	for i, role := range res.Items {
		items[i] = roleView(role)
		items[i]["sources"] = []string{"direct"}
	}
	writeOrgList(w, "roles", items, 0, res.Next, p, true, false)
}

// ListOrganizationRoleMembers lists the current members holding a role,
// checkpoint style only; page, per_page and include_totals are ignored
// (observed).
func (h *Handlers) ListOrganizationRoleMembers(w http.ResponseWriter, r *http.Request, id, roleID string) {
	if _, ok := h.orgs(w); !ok {
		return
	}
	q := r.URL.Query()
	for _, k := range []string{"page", "per_page", "include_totals"} {
		q.Del(k)
	}
	stripped := r.Clone(r.Context())
	stripped.URL.RawQuery = q.Encode()
	p, _, project, _, err := memberQuery(stripped, memberFields[:4], "from", "take", "fields", "include_fields")
	if err == nil && p.From == "" && p.Take == 0 {
		p.Take = orgrules.Limit("take_default")
	}
	if err != nil {
		Fail(w, err)
		return
	}
	var items []map[string]any
	var res store.OrgResult[string]
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := loadOrg(r, tx.Organizations(), id); err != nil {
			return err
		}
		res, err = tx.Organizations().RoleMembers(r.Context(), resolved(r).ID, id, roleID, p)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return errOrgRoleMissing
		case errors.Is(err, store.ErrInvalid):
			return errOrgCursor
		case err != nil:
			return err
		}
		items, err = h.memberViews(r, tx, id, res.Items, false)
		return err
	})
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	for i := range items {
		items[i] = project(items[i])
	}
	writeOrgList(w, "members", items, 0, res.Next, p, true, false)
}
