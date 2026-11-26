package myorg

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// adminRoles are the tenant roles carrying permissions on the My
// Organization API.
func (h *Handlers) adminRoles(ctx context.Context, c *Caller) (map[string]bool, error) {
	out := map[string]bool{}
	for p := 0; ; p++ {
		res, err := h.Store.RBAC().ListRoles(ctx, c.TenantID, store.RBACPage{Page: p, PerPage: 50})
		if err != nil {
			return nil, err
		}
		for _, role := range res.Items {
			perms, err := h.rolePermissions(ctx, c, role.ID)
			if err != nil {
				return nil, err
			}
			if len(perms) > 0 {
				out[role.ID] = true
			}
		}
		if (p+1)*50 >= res.Total || len(res.Items) == 0 {
			return out, nil
		}
	}
}

// rolePermissions are a role's permissions on the My Organization API.
func (h *Handlers) rolePermissions(ctx context.Context, c *Caller, roleID string) ([]string, error) {
	out := []string{}
	for p := 0; ; p++ {
		res, err := h.Store.RBAC().RolePermissions(ctx, c.TenantID, roleID, store.RBACPage{Page: p, PerPage: 50})
		if err != nil {
			return nil, err
		}
		for _, g := range res.Items {
			if g.Key.ResourceServerIdentifier == c.API.Identifier && strings.Contains(g.Key.PermissionName, ":my_org:") {
				out = append(out, g.Key.PermissionName)
			}
		}
		if (p+1)*50 >= res.Total || len(res.Items) == 0 {
			slices.Sort(out)
			return slices.Compact(out), nil
		}
	}
}

// guardLastAdmin refuses a change that leaves the organization without a
// member holding a role with my_org permissions (LR42b-8): removing uid
// (removeRoles nil) or removing removeRoles from uid.
func (h *Handlers) guardLastAdmin(ctx context.Context, c *Caller, uid string, removeRoles []string) error {
	admin, err := h.adminRoles(ctx, c)
	if err != nil {
		return err
	}
	holders := map[string]bool{}
	for rid := range admin {
		from := ""
		for {
			res, err := h.Store.Organizations().RoleMembers(ctx, c.TenantID, c.Org.ID, rid, store.OrgPage{From: from, Take: 100})
			if err != nil {
				return err
			}
			for _, m := range res.Items {
				if m == uid && (removeRoles == nil || slices.Contains(removeRoles, rid)) {
					continue
				}
				holders[m] = true
			}
			if res.Next == "" {
				break
			}
			from = res.Next
		}
	}
	if len(holders) == 0 {
		return problem(http.StatusConflict, "last_admin", "Conflict", "The organization's last administrator cannot lose administration.")
	}
	return nil
}
