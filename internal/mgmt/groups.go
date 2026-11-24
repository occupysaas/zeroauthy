package mgmt

import (
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Directory groups (Plan 37c, D-0150): groups belong to one connection and
// are created by SCIM; the Management API reads and deletes them and
// assigns roles to them, tenant-wide or in an organization.

var (
	errDirectoryUnavailable = &Error{Status: http.StatusNotImplemented, Code: "not_implemented", Message: "The storage backend does not support directory groups and SCIM"}
	errGroupNotFound        = &Error{Status: http.StatusNotFound, Code: "inexistent_group", Message: "The group does not exist"}
	errGroupID              = &Error{Status: http.StatusBadRequest, Code: "invalid_uri", Message: "Path validation error: the group id is invalid"}
	errGroupRoleNotFound    = &Error{Status: http.StatusNotFound, Code: "inexistent_role", Message: "The role does not exist"}
	errGroupCursor          = &Error{Status: http.StatusBadRequest, Code: "invalid_query_string", Message: "The checkpoint ID provided in the 'from' parameter has expired or is invalid, please remove the checkpoint ID and try again"}
)

// maxGroupIDs bounds the IDs of one role/group assignment body.
const maxGroupIDs = 50

var groupIDPattern = regexp.MustCompile(`^grp_[1-9A-HJ-NP-Za-km-z]{14,22}$`)

func validGroupID(id string) bool { return groupIDPattern.MatchString(id) }

// directory returns the store's directory, or writes 501 when a storage
// plugin lacks scim.v1.
func (h *Handlers) directory(w http.ResponseWriter) (store.Directory, bool) {
	if !store.DirectoryAvailable(h.Store) {
		Fail(w, errDirectoryUnavailable)
		return nil, false
	}
	return h.Store.Directory(), true
}

// groupError maps store errors of group routes.
func (h *Handlers) groupError(w http.ResponseWriter, r *http.Request, err error) {
	var typed *Error
	switch {
	case errors.As(err, &typed):
		Fail(w, typed)
	case errors.Is(err, store.ErrDirectoryUnavailable):
		Fail(w, errDirectoryUnavailable)
	case errors.Is(err, store.ErrNotFound):
		Fail(w, errGroupNotFound)
	default:
		Fail(w, internalError(h, r, "groups", err))
	}
}

func groupView(tn *store.Tenant, g *store.Group) map[string]any {
	out := map[string]any{"id": g.ID, "name": g.Name, "connection_id": g.ConnectionID, "tenant_name": tn.Name,
		"created_at": g.CreatedAt.UTC().Format(time.RFC3339Nano), "updated_at": g.UpdatedAt.UTC().Format(time.RFC3339Nano)}
	if g.ExternalID != "" {
		out["external_id"] = g.ExternalID
	}
	return out
}

// loadGroup checks the ID shape and loads the tenant's group.
func loadGroup(r *http.Request, d store.Directory, id string) (*store.Group, error) {
	if !validGroupID(id) {
		return nil, errGroupID
	}
	g, err := d.GetGroup(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errGroupNotFound
	}
	return g, err
}

// groupPage is a group list's pagination: an offset and a limit, from page
// and per_page or from a checkpoint cursor (from, take).
type groupPage struct {
	offset, limit int
	checkpoint    bool
	totals        bool
	page          int
}

// groupCursor encodes a checkpoint position. The offset cursor is opaque to
// clients; a group added or removed meanwhile can shift a later page by one
// (LR37c ruling: directory group lists are small and change rarely).
func groupCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursorPrefix + "g" + strconv.Itoa(offset)))
}

func decodeGroupCursor(from string) (int, bool) {
	b, err := base64.RawURLEncoding.DecodeString(from)
	raw, ok := strings.CutPrefix(string(b), cursorPrefix+"g")
	if err != nil || !ok || raw == "" || len(raw) > 9 {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	return n, err == nil && n >= 0 && strconv.Itoa(n) == raw
}

// readGroupPage reads the pagination. With pages false only from and take
// are accepted (checkpoint lists).
func readGroupPage(r *http.Request, pages bool) (groupPage, error) {
	q := r.URL.Query()
	var p groupPage
	if !pages || q.Has("from") || q.Has("take") {
		take, err := takeParam(r)
		if err != nil {
			return p, err
		}
		p.checkpoint, p.limit = true, take
		if from := q.Get("from"); from != "" {
			n, ok := decodeGroupCursor(from)
			if !ok {
				return p, errGroupCursor
			}
			p.offset = n
		}
		return p, nil
	}
	page, perPage, totals, err := Page(r)
	if err != nil {
		return p, err
	}
	p.offset, p.limit, p.totals, p.page = page*perPage, perPage, totals, page
	return p, nil
}

// writeGroupList writes one page as a bare array, the totals object or the
// checkpoint object.
func writeGroupList(w http.ResponseWriter, name string, items []map[string]any, total int, p groupPage) {
	if items == nil {
		items = []map[string]any{}
	}
	switch {
	case p.checkpoint:
		out := map[string]any{name: items}
		if p.offset+len(items) < total {
			out["next"] = groupCursor(p.offset + len(items))
		}
		writeJSON(w, http.StatusOK, out)
	case p.totals:
		writeJSON(w, http.StatusOK, map[string]any{name: items, "start": p.offset, "limit": p.limit, "total": total})
	default:
		writeJSON(w, http.StatusOK, items)
	}
}

// window returns items[offset:offset+limit].
func window[T any](items []T, p groupPage) []T {
	if p.offset >= len(items) {
		return nil
	}
	return items[p.offset:min(len(items), p.offset+p.limit)]
}

// ListGroups serves GET /groups.
func (h *Handlers) ListGroups(w http.ResponseWriter, r *http.Request) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	p, err := readGroupPage(r, true)
	if err != nil {
		Fail(w, err)
		return
	}
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	q := r.URL.Query()
	f := store.GroupFilter{ConnectionID: q.Get("connection_id"), Name: q.Get("name"), ExternalID: q.Get("external_id"), NamePrefix: q.Get("search")}
	if len(f.Name) > 128 || len(f.ExternalID) > 256 || len(f.NamePrefix) > 256 || len(f.ConnectionID) > 256 {
		Fail(w, badQuery("Query validation error: a filter value is too long"))
		return
	}
	tn := resolved(r)
	groups, total, err := d.ListGroups(r.Context(), tn.ID, f, store.Page{Offset: p.offset, Limit: p.limit})
	if err != nil {
		h.groupError(w, r, err)
		return
	}
	items := make([]map[string]any, len(groups))
	for i, g := range groups {
		items[i] = project(groupView(tn, g), fields, include)
	}
	writeGroupList(w, "groups", items, total, p)
}

// GetGroup serves GET /groups/{id}.
func (h *Handlers) GetGroup(w http.ResponseWriter, r *http.Request, id string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	g, err := loadGroup(r, d, id)
	if err != nil {
		h.groupError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, groupView(resolved(r), g))
}

// DeleteGroup serves DELETE /groups/{id}: the group, its memberships and
// role assignments go.
func (h *Handlers) DeleteGroup(w http.ResponseWriter, r *http.Request, id string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	if _, err := loadGroup(r, d, id); err != nil {
		h.groupError(w, r, err)
		return
	}
	if err := d.DeleteGroup(r.Context(), resolved(r).ID, id); err != nil {
		h.groupError(w, r, err)
		return
	}
	logDetails(r, "delete group", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// ListGroupMembers serves GET /groups/{id}/members (checkpoint only).
func (h *Handlers) ListGroupMembers(w http.ResponseWriter, r *http.Request, id string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	p, err := readGroupPage(r, false)
	if err != nil {
		Fail(w, err)
		return
	}
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	g, err := loadGroup(r, d, id)
	if err != nil {
		h.groupError(w, r, err)
		return
	}
	ms, total, err := d.ListGroupMembers(r.Context(), resolved(r).ID, id, store.Page{Offset: p.offset, Limit: p.limit})
	if err != nil {
		h.groupError(w, r, err)
		return
	}
	items := make([]map[string]any, len(ms))
	for i, m := range ms {
		items[i] = project(map[string]any{"id": m.UserID, "member_type": "user", "type": "connection", "connection_id": g.ConnectionID,
			"created_at": m.CreatedAt.UTC().Format(time.RFC3339Nano)}, fields, include)
	}
	writeGroupList(w, "members", items, total, p)
}

// roleViews loads the roles of ids, sorted by name then ID; a role deleted
// meanwhile is left out.
func (h *Handlers) roleViews(r *http.Request, tx store.Store, ids []string) ([]map[string]any, error) {
	var roles []store.Role
	for _, id := range ids {
		role, err := tx.RBAC().GetRole(r.Context(), resolved(r).ID, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		roles = append(roles, *role)
	}
	slices.SortFunc(roles, func(a, b store.Role) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	out := make([]map[string]any, len(roles))
	for i, role := range roles {
		out[i] = roleView(role)
	}
	return out, nil
}

// listGroupRoles writes the roles of a group, tenant-wide or in org.
func (h *Handlers) listGroupRoles(w http.ResponseWriter, r *http.Request, d store.Directory, id, org string) {
	p, err := readGroupPage(r, false)
	if err != nil {
		Fail(w, err)
		return
	}
	if _, err := loadGroup(r, d, id); err != nil {
		h.groupError(w, r, err)
		return
	}
	grants, err := d.ListGroupRoles(r.Context(), resolved(r).ID, id, "", org)
	if err != nil {
		h.groupError(w, r, err)
		return
	}
	ids := make([]string, len(grants))
	for i, g := range grants {
		ids[i] = g.RoleID
	}
	items, err := h.roleViews(r, h.Store, ids)
	if err != nil {
		h.groupError(w, r, err)
		return
	}
	writeGroupList(w, "roles", window(items, p), len(items), p)
}

// ListGroupRoles serves GET /groups/{id}/roles: tenant-wide group roles.
func (h *Handlers) ListGroupRoles(w http.ResponseWriter, r *http.Request, id string) {
	if d, ok := h.directory(w); ok {
		h.listGroupRoles(w, r, d, id, "")
	}
}

// readIDList reads {field: [...]} with 1 to maxGroupIDs non-empty IDs.
func readIDList(r *http.Request, field string) ([]string, error) {
	body, err := decodeObject(r)
	if err != nil {
		return nil, err
	}
	if len(body) != 1 || body[field] == nil {
		return nil, badBody("%s is required", field)
	}
	var ids []string
	if err := decodeStrict(body[field], &ids); err != nil || len(ids) < 1 || len(ids) > maxGroupIDs {
		return nil, badBody("%s must contain 1 to %d identifiers", field, maxGroupIDs)
	}
	for _, id := range ids {
		if id == "" || len(id) > 256 {
			return nil, badBody("identifiers must be 1 to 256 characters")
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// changeGroupRoles assigns (add) or removes roles of groups in org ("" =
// tenant-wide) in one transaction: every group must exist (and, in an
// organization, belong to one of its connections) and, when adding, every
// role must exist.
func (h *Handlers) changeGroupRoles(r *http.Request, groups, roles []string, org string, add bool) error {
	tid := resolved(r).ID
	return h.Store.WithTx(r.Context(), func(tx store.Store) error {
		d := tx.Directory()
		var enabled []string
		if org != "" {
			var err error
			if enabled, err = orgConnectionIDs(r, tx, org); err != nil {
				return err
			}
		}
		for _, gid := range groups {
			g, err := loadGroup(r, d, gid)
			if err != nil {
				return err
			}
			if org != "" && !slices.Contains(enabled, g.ConnectionID) {
				return badBody("the group's connection is not enabled on the organization")
			}
		}
		if add {
			for _, rid := range roles {
				if _, err := tx.RBAC().GetRole(r.Context(), tid, rid); errors.Is(err, store.ErrNotFound) {
					return errGroupRoleNotFound
				} else if err != nil {
					return err
				}
			}
		}
		for _, gid := range groups {
			var err error
			if add {
				err = d.AddGroupRoles(r.Context(), tid, gid, org, roles)
			} else {
				err = d.RemoveGroupRoles(r.Context(), tid, gid, org, roles)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (h *Handlers) groupRolesBody(w http.ResponseWriter, r *http.Request, id, org string, add bool) {
	if _, ok := h.directory(w); !ok {
		return
	}
	if !validGroupID(id) {
		Fail(w, errGroupID)
		return
	}
	roles, err := readIDList(r, "roles")
	if err != nil {
		Fail(w, err)
		return
	}
	if err := h.changeGroupRoles(r, []string{id}, roles, org, add); err != nil {
		h.groupOrgError(w, r, err)
		return
	}
	logDetails(r, "change group roles", "id", id, "organization", org, "add", add)
	w.WriteHeader(http.StatusNoContent)
}

// AssignGroupRoles serves POST /groups/{id}/roles.
func (h *Handlers) AssignGroupRoles(w http.ResponseWriter, r *http.Request, id string) {
	h.groupRolesBody(w, r, id, "", true)
}

// RemoveGroupRoles serves DELETE /groups/{id}/roles.
func (h *Handlers) RemoveGroupRoles(w http.ResponseWriter, r *http.Request, id string) {
	h.groupRolesBody(w, r, id, "", false)
}

// groupsByID loads groups in ID order, leaving out any deleted meanwhile.
func groupsByID(r *http.Request, d store.Directory, ids []string) ([]*store.Group, error) {
	slices.Sort(ids)
	ids = slices.Compact(ids)
	out := make([]*store.Group, 0, len(ids))
	for _, id := range ids {
		g, err := d.GetGroup(r.Context(), resolved(r).ID, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

func (h *Handlers) writeGroups(w http.ResponseWriter, r *http.Request, groups []*store.Group, p groupPage) {
	tn := resolved(r)
	page := window(groups, p)
	items := make([]map[string]any, len(page))
	for i, g := range page {
		items[i] = groupView(tn, g)
	}
	writeGroupList(w, "groups", items, len(groups), p)
}

// ListRoleGroups serves GET /roles/{id}/groups: groups holding the role
// tenant-wide.
func (h *Handlers) ListRoleGroups(w http.ResponseWriter, r *http.Request, id string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	p, err := readGroupPage(r, false)
	if err != nil {
		Fail(w, err)
		return
	}
	if _, err := h.Store.RBAC().GetRole(r.Context(), resolved(r).ID, id); errors.Is(err, store.ErrNotFound) {
		Fail(w, errGroupRoleNotFound)
		return
	} else if err != nil {
		h.groupError(w, r, err)
		return
	}
	grants, err := d.ListGroupRoles(r.Context(), resolved(r).ID, "", id, "")
	if err != nil {
		h.groupError(w, r, err)
		return
	}
	ids := make([]string, len(grants))
	for i, g := range grants {
		ids[i] = g.GroupID
	}
	groups, err := groupsByID(r, d, ids)
	if err != nil {
		h.groupError(w, r, err)
		return
	}
	h.writeGroups(w, r, groups, p)
}

func (h *Handlers) roleGroupsBody(w http.ResponseWriter, r *http.Request, id string, add bool) {
	if _, ok := h.directory(w); !ok {
		return
	}
	groups, err := readIDList(r, "groups")
	if err != nil {
		Fail(w, err)
		return
	}
	for _, g := range groups {
		if !validGroupID(g) {
			Fail(w, badBody("groups must contain group identifiers"))
			return
		}
	}
	if _, err := h.Store.RBAC().GetRole(r.Context(), resolved(r).ID, id); errors.Is(err, store.ErrNotFound) {
		Fail(w, errGroupRoleNotFound)
		return
	} else if err != nil {
		h.groupError(w, r, err)
		return
	}
	if err := h.changeGroupRoles(r, groups, []string{id}, "", add); err != nil {
		h.groupError(w, r, err)
		return
	}
	logDetails(r, "change role groups", "id", id, "add", add)
	w.WriteHeader(http.StatusNoContent)
}

// AssignRoleGroups serves POST /roles/{id}/groups.
func (h *Handlers) AssignRoleGroups(w http.ResponseWriter, r *http.Request, id string) {
	h.roleGroupsBody(w, r, id, true)
}

// RemoveRoleGroups serves DELETE /roles/{id}/groups.
func (h *Handlers) RemoveRoleGroups(w http.ResponseWriter, r *http.Request, id string) {
	h.roleGroupsBody(w, r, id, false)
}

// ListUserGroups serves GET /users/{id}/groups: the user's groups, oldest
// membership first, with membership_created_at.
func (h *Handlers) ListUserGroups(w http.ResponseWriter, r *http.Request, id string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	p, err := readGroupPage(r, true)
	if err != nil {
		Fail(w, err)
		return
	}
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if err := h.userForSessions(r, id); err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	ms, err := d.ListUserGroups(r.Context(), tn.ID, id)
	if err != nil {
		h.groupError(w, r, err)
		return
	}
	var items []map[string]any
	for _, m := range ms {
		g, err := d.GetGroup(r.Context(), tn.ID, m.GroupID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			h.groupError(w, r, err)
			return
		}
		v := groupView(tn, g)
		v["membership_created_at"] = m.CreatedAt.UTC().Format(time.RFC3339Nano)
		items = append(items, project(v, fields, include))
	}
	writeGroupList(w, "groups", window(items, p), len(items), p)
}

// sourceGroups writes the groups granting role to the user, tenant-wide
// (org "") or in org only.
func (h *Handlers) sourceGroups(w http.ResponseWriter, r *http.Request, d store.Directory, uid, role, org string) {
	p, err := readGroupPage(r, false)
	if err != nil {
		Fail(w, err)
		return
	}
	if role == "" || len(role) > 256 {
		Fail(w, badQuery("Query validation error: role_id is required"))
		return
	}
	sources, err := store.UserGroupRoleSources(r.Context(), h.Store, resolved(r).ID, uid, org, org != "")
	if err != nil {
		h.groupError(w, r, err)
		return
	}
	groups, err := groupsByID(r, d, sources[role])
	if err != nil {
		h.groupError(w, r, err)
		return
	}
	h.writeGroups(w, r, groups, p)
}

// ListUserRoleSourceGroups serves GET
// /users/{id}/effective-roles/sources/groups?role_id=.
func (h *Handlers) ListUserRoleSourceGroups(w http.ResponseWriter, r *http.Request, id string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	if err := h.userForSessions(r, id); err != nil {
		Fail(w, err)
		return
	}
	h.sourceGroups(w, r, d, id, r.URL.Query().Get("role_id"), "")
}

// orgConnectionIDs lists the connection IDs enabled on an organization.
func orgConnectionIDs(r *http.Request, tx store.Store, org string) ([]string, error) {
	if _, err := loadOrg(r, tx.Organizations(), org); err != nil {
		return nil, err
	}
	var out []string
	for page := 0; page < 1000; page++ {
		res, err := tx.Organizations().Connections(r.Context(), resolved(r).ID, org, store.OrgPage{Page: page, PerPage: 100})
		if err != nil {
			return nil, err
		}
		for _, c := range res.Items {
			out = append(out, c.ConnectionID)
		}
		if len(res.Items) < 100 {
			break
		}
	}
	return out, nil
}

// groupOrgError maps errors of organization group routes: a missing
// organization is the organization's 404.
func (h *Handlers) groupOrgError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrOrganizationsUnavailable) || errors.Is(err, store.ErrOrganizationsIIUnavailable) {
		h.orgError(w, r, err)
		return
	}
	h.groupError(w, r, err)
}

// ListOrganizationGroups serves GET /organizations/{id}/groups: the groups
// of the organization's enabled connections.
func (h *Handlers) ListOrganizationGroups(w http.ResponseWriter, r *http.Request, id string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	if _, ok := h.orgs(w); !ok {
		return
	}
	p, err := readGroupPage(r, false)
	if err != nil {
		Fail(w, err)
		return
	}
	conns, err := orgConnectionIDs(r, h.Store, id)
	if err != nil {
		h.groupOrgError(w, r, err)
		return
	}
	slices.Sort(conns)
	var groups []*store.Group
	for _, c := range conns {
		gs, _, err := d.ListGroups(r.Context(), resolved(r).ID, store.GroupFilter{ConnectionID: c}, store.Page{})
		if err != nil {
			h.groupError(w, r, err)
			return
		}
		groups = append(groups, gs...)
	}
	h.writeGroups(w, r, groups, p)
}

// ListOrganizationGroupRoles serves GET
// /organizations/{id}/groups/{group_id}/roles.
func (h *Handlers) ListOrganizationGroupRoles(w http.ResponseWriter, r *http.Request, id, groupID string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	if _, err := loadOrg(r, orgs, id); err != nil {
		h.orgError(w, r, err)
		return
	}
	h.listGroupRoles(w, r, d, groupID, id)
}

func (h *Handlers) orgGroupRolesBody(w http.ResponseWriter, r *http.Request, id, groupID string, add bool) {
	if _, ok := h.orgs(w); !ok {
		return
	}
	if !orgrules.ValidID(id) {
		Fail(w, errOrganizationURI)
		return
	}
	h.groupRolesBody(w, r, groupID, id, add)
}

// AssignOrganizationGroupRoles serves POST
// /organizations/{id}/groups/{group_id}/roles.
func (h *Handlers) AssignOrganizationGroupRoles(w http.ResponseWriter, r *http.Request, id, groupID string) {
	h.orgGroupRolesBody(w, r, id, groupID, true)
}

// RemoveOrganizationGroupRoles serves DELETE
// /organizations/{id}/groups/{group_id}/roles.
func (h *Handlers) RemoveOrganizationGroupRoles(w http.ResponseWriter, r *http.Request, id, groupID string) {
	h.orgGroupRolesBody(w, r, id, groupID, false)
}

// ListOrganizationMemberRoleSourceGroups serves GET
// /organizations/{id}/members/{user_id}/effective-roles/sources/groups.
func (h *Handlers) ListOrganizationMemberRoleSourceGroups(w http.ResponseWriter, r *http.Request, id, userID string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	if _, err := loadOrg(r, orgs, id); err != nil {
		h.orgError(w, r, err)
		return
	}
	member, err := orgs.IsMember(r.Context(), resolved(r).ID, id, userID)
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	if !member {
		Fail(w, errOrgNotMember)
		return
	}
	h.sourceGroups(w, r, d, userID, r.URL.Query().Get("role_id"), id)
}
