package store

import (
	"context"
	"slices"
)

// OrganizationAuthorizationSnapshot reads direct permissions, tenant roles,
// only the active organization's member roles, and the roles of the user's
// directory groups (Plan 37c: tenant-wide group roles always, organization
// group roles only in that organization) in one transaction. The RBAC
// snapshot acquires the same tenant authorization lock used by policy
// writers. A removed membership fails closed even though its role
// assignments persist.
func OrganizationAuthorizationSnapshot(ctx context.Context, st Store, tid, uid, orgID, audience string) (*AuthorizationSnapshot, error) {
	groups := DirectoryAvailable(st)
	if orgID == "" {
		// The tenant path stays the plain RBAC snapshot (callers pass a
		// transaction view when they need one); group roles are added after.
		out, err := st.RBAC().Snapshot(ctx, tid, uid, audience)
		if err != nil || !groups || out == nil || out.API == nil {
			return out, err
		}
		roles, err := UserGroupRoles(ctx, st, tid, uid, "")
		if err != nil {
			return nil, err
		}
		if err := addRolePermissions(ctx, st, tid, audience, out, roles); err != nil {
			return nil, err
		}
		return out, nil
	}
	var out *AuthorizationSnapshot
	err := st.WithTx(ctx, func(tx Store) error {
		var err error
		out, err = tx.RBAC().Snapshot(ctx, tid, uid, audience)
		if err != nil {
			return err
		}
		var roles []string
		if orgID != "" {
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
			for page := 0; ; page++ {
				res, err := tx.Organizations().MemberRoles(ctx, tid, orgID, uid, OrgPage{Page: page, PerPage: 100})
				if err != nil {
					return err
				}
				roles = append(roles, res.Items...)
				if len(res.Items) < 100 {
					break
				}
			}
		}
		{
			gr, err := UserGroupRoles(ctx, tx, tid, uid, orgID)
			if err != nil {
				return err
			}
			roles = append(roles, gr...)
		}
		return addRolePermissions(ctx, tx, tid, audience, out, roles)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// addRolePermissions adds the permissions of roles for audience that the
// API still declares, sorted and without duplicates.
func addRolePermissions(ctx context.Context, st Store, tid, audience string, out *AuthorizationSnapshot, roles []string) error {
	if len(roles) == 0 || out == nil || out.API == nil {
		return nil
	}
	declared := map[string]bool{}
	for _, s := range out.API.Scopes {
		declared[s.Value] = true
	}
	roles = slices.Clone(roles)
	slices.Sort(roles)
	for _, role := range slices.Compact(roles) {
		for p := 0; ; p++ {
			perms, err := st.RBAC().RolePermissions(ctx, tid, role, RBACPage{Page: p, PerPage: 100})
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
	slices.Sort(out.Permissions)
	out.Permissions = slices.Compact(out.Permissions)
	return nil
}

// UserGroupRoles returns the role IDs the user holds through directory
// groups: tenant-wide group roles, plus organization group roles of orgID
// when it is not empty.
func UserGroupRoles(ctx context.Context, st Store, tid, uid, orgID string) ([]string, error) {
	sources, err := UserGroupRoleSources(ctx, st, tid, uid, orgID, false)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(sources))
	for role := range sources {
		out = append(out, role)
	}
	slices.Sort(out)
	return out, nil
}

// UserGroupRoleSources maps each role the user holds through groups to the
// groups granting it. With orgOnly, only organization group roles of orgID
// count (organization effective roles); otherwise tenant-wide group roles,
// plus orgID's when it is not empty.
func UserGroupRoleSources(ctx context.Context, st Store, tid, uid, orgID string, orgOnly bool) (map[string][]string, error) {
	out := map[string][]string{}
	if !DirectoryAvailable(st) {
		return out, nil
	}
	memberships, err := st.Directory().ListUserGroups(ctx, tid, uid)
	if err != nil {
		return nil, err
	}
	var scopes []string
	if !orgOnly {
		scopes = append(scopes, "")
	}
	if orgID != "" {
		scopes = append(scopes, orgID)
	}
	for _, m := range memberships {
		for _, org := range scopes {
			grants, err := st.Directory().ListGroupRoles(ctx, tid, m.GroupID, "", org)
			if err != nil {
				return nil, err
			}
			for _, g := range grants {
				if !slices.Contains(out[g.RoleID], g.GroupID) {
					out[g.RoleID] = append(out[g.RoleID], g.GroupID)
				}
			}
		}
	}
	return out, nil
}
