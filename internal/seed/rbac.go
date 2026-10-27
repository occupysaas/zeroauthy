package seed

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func applyRole(ctx context.Context, st store.Store, tenantID string, in Role, createOnly bool) error {
	return st.WithTx(ctx, func(tx store.Store) error {
		var role *store.Role
		for page := 0; ; page++ {
			found, err := tx.RBAC().ListRoles(ctx, tenantID, store.RBACPage{Page: page, PerPage: 100, NameFilter: in.Name})
			if err != nil {
				return err
			}
			for _, v := range found.Items {
				if v.Name == in.Name {
					copy := v
					role = &copy
					break
				}
			}
			if role != nil || (page+1)*100 >= found.Total {
				break
			}
		}
		if role != nil && createOnly {
			return nil
		}
		if role == nil {
			role = &store.Role{TenantID: tenantID, ID: "rol_" + secrets.RandomString(18), Name: in.Name, Description: in.Description}
			if err := tx.RBAC().CreateRole(ctx, role); err != nil {
				return err
			}
		} else {
			role.Description = in.Description
			if err := tx.RBAC().UpdateRole(ctx, role); err != nil {
				return err
			}
			// Gather before mutating so pagination is stable.
			old := []store.PermissionKey{}
			for page := 0; ; page++ {
				found, err := tx.RBAC().RolePermissions(ctx, tenantID, role.ID, store.RBACPage{Page: page, PerPage: 100})
				if err != nil {
					return err
				}
				for _, v := range found.Items {
					old = append(old, v.Key)
				}
				if (page+1)*100 >= found.Total {
					break
				}
			}
			for len(old) > 0 {
				n := min(len(old), 100)
				if err := tx.RBAC().ChangeRolePermissions(ctx, tenantID, role.ID, false, old[:n]); err != nil {
					return err
				}
				old = old[n:]
			}
		}
		keys := make([]store.PermissionKey, 0, len(in.Permissions))
		for _, k := range in.Permissions {
			keys = append(keys, store.PermissionKey{ResourceServerIdentifier: k.ResourceServerIdentifier, PermissionName: k.PermissionName})
		}
		for len(keys) > 0 {
			n := min(len(keys), 100)
			if err := tx.RBAC().ChangeRolePermissions(ctx, tenantID, role.ID, true, keys[:n]); err != nil {
				return err
			}
			keys = keys[n:]
		}
		return nil
	})
}
