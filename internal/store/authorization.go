package store

import (
	"context"
	"slices"
)

// OrganizationAuthorizationSnapshot reads direct permissions, tenant roles and
// only the active organization's member roles in one transaction. The RBAC
// snapshot acquires the same tenant authorization lock used by policy writers.
// A removed membership fails closed even though its role assignments persist.
func OrganizationAuthorizationSnapshot(ctx context.Context, st Store, tid, uid, orgID, audience string) (*AuthorizationSnapshot, error) {
	if orgID == "" {
		return st.RBAC().Snapshot(ctx, tid, uid, audience)
	}
	var out *AuthorizationSnapshot
	err := st.WithTx(ctx, func(tx Store) error {
		var err error
		out, err = tx.RBAC().Snapshot(ctx, tid, uid, audience)
		if err != nil {
			return err
		}
		if out == nil || out.API == nil {
			return ErrInvalid
		}
		if _, err = tx.Organizations().Get(ctx, tid, orgID); err != nil {
			return err
		}
		member, err := tx.Organizations().IsMember(ctx, tid, orgID, uid)
		if err != nil {
			return err
		}
		if !member {
			return ErrNotFound
		}
		declared := map[string]bool{}
		for _, s := range out.API.Scopes {
			declared[s.Value] = true
		}
		for page := 0; ; page++ {
			roles, err := tx.Organizations().MemberRoles(ctx, tid, orgID, uid, OrgPage{Page: page, PerPage: 100})
			if err != nil {
				return err
			}
			for _, role := range roles.Items {
				for p := 0; ; p++ {
					perms, err := tx.RBAC().RolePermissions(ctx, tid, role, RBACPage{Page: p, PerPage: 100})
					if err != nil {
						return err
					}
					for _, perm := range perms.Items {
						if perm.Key.ResourceServerIdentifier == audience && declared[perm.Key.PermissionName] {
							out.Permissions = append(out.Permissions, perm.Key.PermissionName)
						}
					}
					if len(perms.Items) < 100 {
						break
					}
				}
			}
			if len(roles.Items) < 100 {
				break
			}
		}
		slices.Sort(out.Permissions)
		out.Permissions = slices.Compact(out.Permissions)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
