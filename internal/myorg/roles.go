package myorg

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// offsetCursor encodes a list position as an opaque cursor.
func offsetCursor(n int) string { return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(n))) }

func parseOffset(from string) (int, bool) {
	if from == "" {
		return 0, true
	}
	b, err := base64.RawURLEncoding.DecodeString(from)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(string(b))
	return n, err == nil && n >= 0
}

// visibleRoles are the roles the operator made visible to the API
// (LR42b-2), as stored roles.
func (h *Handlers) visibleRoles(ctx context.Context, c *Caller) ([]*store.Role, error) {
	repo, err := store.MyOrg(ctx, h.Store)
	if err != nil {
		return nil, err
	}
	ids, err := repo.ListMyOrgVisibleRoles(ctx, c.TenantID)
	if err != nil {
		return nil, err
	}
	out := []*store.Role{}
	for _, id := range ids {
		r, err := h.Store.RBAC().GetRole(ctx, c.TenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (h *Handlers) listRoles(w http.ResponseWriter, r *http.Request, c *Caller) {
	p, prob := page(r)
	if prob != nil {
		writeProblem(w, r, prob)
		return
	}
	start, ok := parseOffset(p.From)
	if !ok {
		writeProblem(w, r, invalidQuery("from", "from is not a valid cursor."))
		return
	}
	name := strings.ToLower(r.URL.Query().Get("name"))
	if len(name) > 300 {
		writeProblem(w, r, invalidQuery("name", "name is too long."))
		return
	}
	roles, err := h.visibleRoles(r.Context(), c)
	if err != nil {
		h.event(r, c, "my_organization_api_role_failed")
		h.fail(w, r, "list roles", err)
		return
	}
	roles = slices.DeleteFunc(roles, func(role *store.Role) bool { return name != "" && !strings.Contains(strings.ToLower(role.Name), name) })
	out := []any{}
	for i := start; i < len(roles) && len(out) < p.Take; i++ {
		out = append(out, roleView(roles[i]))
	}
	body := map[string]any{"roles": out}
	if next := start + len(out); next < len(roles) {
		body["next"] = offsetCursor(next)
	}
	writeJSON(w, r, http.StatusOK, body)
}

func (h *Handlers) listMemberRoles(w http.ResponseWriter, r *http.Request, c *Caller) {
	uid := chi.URLParam(r, "user_id")
	p, prob := page(r)
	if prob != nil {
		writeProblem(w, r, prob)
		return
	}
	if err := h.requireMember(r.Context(), c, uid); err != nil {
		h.fail(w, r, "list member roles", err)
		return
	}
	roles, next, err := h.memberRoles(r.Context(), c, uid, store.OrgPage{From: p.From, Take: p.Take})
	if errors.Is(err, store.ErrInvalid) {
		writeProblem(w, r, invalidQuery("from", "from is not a valid cursor."))
		return
	}
	if err != nil {
		h.fail(w, r, "list member roles", err)
		return
	}
	out := map[string]any{"roles": roles}
	if next != "" {
		out["next"] = next
	}
	writeJSON(w, r, http.StatusOK, out)
}

type roleChange struct {
	RoleIDs []string `json:"role_ids"`
}

func readRoleChange(r *http.Request) ([]string, *Problem) {
	var b roleChange
	if p := decode(r, &b); p != nil {
		return nil, p
	}
	ids := slices.Compact(slices.Sorted(slices.Values(b.RoleIDs)))
	if len(b.RoleIDs) < 1 || len(b.RoleIDs) > 10 || len(ids) != len(b.RoleIDs) || slices.Contains(ids, "") {
		return nil, badRequest("invalid_body", "role_ids must hold 1 to 10 distinct role IDs.", ValidationError{Detail: "1 to 10 distinct", Field: "role_ids", Source: "body"})
	}
	return ids, nil
}

// callerPermissions are the my_org permissions the caller holds through
// their roles in the organization.
func (h *Handlers) callerPermissions(ctx context.Context, c *Caller) (map[string]bool, error) {
	out := map[string]bool{}
	from := ""
	for {
		res, err := h.Store.Organizations().MemberRoles(ctx, c.TenantID, c.Org.ID, c.UserID, store.OrgPage{From: from, Take: 100})
		if err != nil {
			return nil, err
		}
		for _, rid := range res.Items {
			perms, err := h.rolePermissions(ctx, c, rid)
			if err != nil {
				return nil, err
			}
			for _, p := range perms {
				out[p] = true
			}
		}
		if res.Next == "" {
			return out, nil
		}
		from = res.Next
	}
}

// checkAssignable refuses roles not visible to the API, roles above the
// caller's my_org permissions when the application enforces the ceiling,
// and assignments to the caller when it restricts self-assignment
// (LR42b-2).
func (h *Handlers) checkAssignable(ctx context.Context, c *Caller, target string, roleIDs []string) error {
	repo, err := store.MyOrg(ctx, h.Store)
	if err != nil {
		return err
	}
	visible, err := repo.ListMyOrgVisibleRoles(ctx, c.TenantID)
	if err != nil {
		return err
	}
	for _, id := range roleIDs {
		if !slices.Contains(visible, id) {
			return forbiddenDetail("The role " + id + " cannot be assigned through the My Organization API.")
		}
	}
	if target != "" && target == c.UserID && c.Config.EnforceSelfAssignmentRestriction {
		return forbiddenDetail("Administrators cannot assign roles to themselves.")
	}
	if !c.Config.EnforcePermissionCeiling {
		return nil
	}
	own, err := h.callerPermissions(ctx, c)
	if err != nil {
		return err
	}
	for _, id := range roleIDs {
		perms, err := h.rolePermissions(ctx, c, id)
		if err != nil {
			return err
		}
		for _, p := range perms {
			if !own[p] {
				return forbiddenDetail("The role " + id + " has permissions above your own.")
			}
		}
	}
	return nil
}

func (h *Handlers) assignRoles(w http.ResponseWriter, r *http.Request, c *Caller) {
	uid := chi.URLParam(r, "user_id")
	ids, prob := readRoleChange(r)
	if prob != nil {
		writeProblem(w, r, prob)
		return
	}
	ctx := r.Context()
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		hx := h.withStore(tx)
		if err := hx.requireMember(ctx, c, uid); err != nil {
			return err
		}
		if err := hx.checkAssignable(ctx, c, uid, ids); err != nil {
			return err
		}
		return tx.Organizations().ChangeMemberRoles(ctx, c.TenantID, c.Org.ID, uid, true, ids)
	})
	h.roleOutcome(w, r, c, "assign member roles", err)
}

func (h *Handlers) unassignRoles(w http.ResponseWriter, r *http.Request, c *Caller) {
	uid := chi.URLParam(r, "user_id")
	ids, prob := readRoleChange(r)
	if prob != nil {
		writeProblem(w, r, prob)
		return
	}
	ctx := r.Context()
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		hx := h.withStore(tx)
		if err := hx.requireMember(ctx, c, uid); err != nil {
			return err
		}
		if err := hx.checkAssignable(ctx, c, "", ids); err != nil {
			return err
		}
		if err := hx.guardLastAdmin(ctx, c, uid, ids); err != nil {
			return err
		}
		return tx.Organizations().ChangeMemberRoles(ctx, c.TenantID, c.Org.ID, uid, false, ids)
	})
	h.roleOutcome(w, r, c, "unassign member roles", err)
}

func (h *Handlers) roleOutcome(w http.ResponseWriter, r *http.Request, c *Caller, what string, err error) {
	if err != nil {
		h.event(r, c, "my_organization_api_member_failed")
		h.fail(w, r, what, err)
		return
	}
	h.event(r, c, "my_organization_api_member_succeeded")
	w.Header().Set("x-correlation-id", correlationID(r))
	w.WriteHeader(http.StatusNoContent)
}
