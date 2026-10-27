package grpcstore

import (
	"context"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

type clientRBAC struct{ c *Client }

func (c *Client) RBAC() store.RBAC { return clientRBAC{c} }
func (c *Client) CheckRBACSupport(ctx context.Context) error {
	v, err := c.rpc.RBACCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		return capabilityError(err, store.ErrRBACUnavailable)
	}
	if err := errFromPB(v.GetError()); err != nil {
		return err
	}
	if v.Version < 1 {
		return store.ErrRBACUnavailable
	}
	return nil
}
func (s *Server) RBACCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.RBACCapabilitiesResult, error) {
	return &storev1.RBACCapabilitiesResult{Version: 1}, nil
}
func roleToPB(r *store.Role) *storev1.RBACRole {
	if r == nil {
		return nil
	}
	return &storev1.RBACRole{TenantId: r.TenantID, Id: r.ID, Name: r.Name, Description: r.Description}
}
func roleFromPB(r *storev1.RBACRole) *store.Role {
	if r == nil {
		return nil
	}
	return &store.Role{TenantID: r.TenantId, ID: r.Id, Name: r.Name, Description: r.Description}
}
func keysToPB(keys []store.PermissionKey) []*storev1.RBACPermissionKey {
	out := []*storev1.RBACPermissionKey{}
	for _, k := range keys {
		out = append(out, &storev1.RBACPermissionKey{ResourceServerIdentifier: k.ResourceServerIdentifier, PermissionName: k.PermissionName})
	}
	return out
}
func keysFromPB(keys []*storev1.RBACPermissionKey) []store.PermissionKey {
	out := []store.PermissionKey{}
	for _, k := range keys {
		out = append(out, store.PermissionKey{ResourceServerIdentifier: k.GetResourceServerIdentifier(), PermissionName: k.GetPermissionName()})
	}
	return out
}
func pageToPB(p store.RBACPage) *storev1.RBACPage {
	return &storev1.RBACPage{Page: int64(p.Page), PerPage: int64(p.PerPage), NameFilter: p.NameFilter, From: p.From, Take: int64(p.Take)}
}
func pageFromPB(p *storev1.RBACPage) store.RBACPage {
	return store.RBACPage{Page: int(p.GetPage()), PerPage: int(p.GetPerPage()), NameFilter: p.GetNameFilter(), From: p.GetFrom(), Take: int(p.GetTake())}
}
func grantToPB(g store.PermissionGrant) *storev1.RBACPermissionGrant {
	pb := &storev1.RBACPermissionGrant{Key: keysToPB([]store.PermissionKey{g.Key})[0], ResourceServerName: g.ResourceServerName, Description: g.Description}
	for _, s := range g.Sources {
		pb.Sources = append(pb.Sources, &storev1.RBACSource{Type: s.Type, Id: s.ID, Name: s.Name})
	}
	return pb
}
func grantFromPB(g *storev1.RBACPermissionGrant) store.PermissionGrant {
	v := store.PermissionGrant{Key: keysFromPB([]*storev1.RBACPermissionKey{g.GetKey()})[0], ResourceServerName: g.GetResourceServerName(), Description: g.GetDescription(), Sources: []store.PermissionSource{}}
	for _, s := range g.GetSources() {
		v.Sources = append(v.Sources, store.PermissionSource{Type: s.GetType(), ID: s.GetId(), Name: s.GetName()})
	}
	return v
}
func rbacRPCError(v *storev1.RBACResponse, err error) error {
	if err != nil {
		return fmt.Errorf("storage plugin RBAC: %w", capabilityError(err, store.ErrRBACUnavailable))
	}
	return errFromPB(v.GetError())
}
func (r clientRBAC) CreateRole(ctx context.Context, role *store.Role) error {
	v, err := r.c.rpc.RBACCreateRole(ctx, &storev1.RBACRequest{TxId: r.c.txID, Role: roleToPB(role)})
	return rbacRPCError(v, err)
}
func (srv *Server) RBACCreateRole(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		return s.RBAC().CreateRole(ctx, roleFromPB(q.Role))
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) GetRole(ctx context.Context, tid, id string) (*store.Role, error) {
	v, err := r.c.rpc.RBACGetRole(ctx, &storev1.RBACRequest{TxId: r.c.txID, TenantId: tid, Id: id})
	if err := rbacRPCError(v, err); err != nil {
		return nil, err
	}
	return roleFromPB(v.Role), nil
}
func (srv *Server) RBACGetRole(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		v, err := s.RBAC().GetRole(ctx, q.TenantId, q.Id)
		out.Role = roleToPB(v)
		return err
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) UpdateRole(ctx context.Context, role *store.Role) error {
	v, err := r.c.rpc.RBACUpdateRole(ctx, &storev1.RBACRequest{TxId: r.c.txID, Role: roleToPB(role)})
	return rbacRPCError(v, err)
}
func (srv *Server) RBACUpdateRole(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		return s.RBAC().UpdateRole(ctx, roleFromPB(q.Role))
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) DeleteRole(ctx context.Context, tid, id string) error {
	v, err := r.c.rpc.RBACDeleteRole(ctx, &storev1.RBACRequest{TxId: r.c.txID, TenantId: tid, Id: id})
	return rbacRPCError(v, err)
}
func (srv *Server) RBACDeleteRole(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		return s.RBAC().DeleteRole(ctx, q.TenantId, q.Id)
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) ListRoles(ctx context.Context, tid string, p store.RBACPage) (store.RBACResult[store.Role], error) {
	v, err := r.c.rpc.RBACListRoles(ctx, &storev1.RBACRequest{TxId: r.c.txID, TenantId: tid, Page: pageToPB(p)})
	out := store.RBACResult[store.Role]{Items: []store.Role{}}
	if err := rbacRPCError(v, err); err != nil {
		return out, err
	}
	out.Total = int(v.Total)
	out.Next = v.Next
	for _, x := range v.Roles {
		if role := roleFromPB(x); role != nil {
			out.Items = append(out.Items, *role)
		}
	}
	return out, nil
}
func (srv *Server) RBACListRoles(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		v, err := s.RBAC().ListRoles(ctx, q.TenantId, pageFromPB(q.Page))
		if err != nil {
			return err
		}
		out.Total = int64(v.Total)
		out.Next = v.Next
		for _, x := range v.Items {
			out.Roles = append(out.Roles, roleToPB(&x))
		}
		return nil
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) RolePermissions(ctx context.Context, tid, id string, p store.RBACPage) (store.RBACResult[store.PermissionGrant], error) {
	v, err := r.c.rpc.RBACRolePermissions(ctx, &storev1.RBACRequest{TxId: r.c.txID, TenantId: tid, Id: id, Page: pageToPB(p)})
	out := store.RBACResult[store.PermissionGrant]{Items: []store.PermissionGrant{}}
	if err := rbacRPCError(v, err); err != nil {
		return out, err
	}
	out.Total = int(v.Total)
	out.Next = v.Next
	for _, x := range v.Grants {
		out.Items = append(out.Items, grantFromPB(x))
	}
	return out, nil
}
func (srv *Server) RBACRolePermissions(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		v, err := s.RBAC().RolePermissions(ctx, q.TenantId, q.Id, pageFromPB(q.Page))
		if err != nil {
			return err
		}
		out.Total = int64(v.Total)
		out.Next = v.Next
		for _, x := range v.Items {
			out.Grants = append(out.Grants, grantToPB(x))
		}
		return nil
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) ChangeRolePermissions(ctx context.Context, tid, id string, add bool, keys []store.PermissionKey) error {
	v, err := r.c.rpc.RBACChangeRolePermissions(ctx, &storev1.RBACRequest{TxId: r.c.txID, TenantId: tid, Id: id, Add: add, Keys: keysToPB(keys)})
	return rbacRPCError(v, err)
}
func (srv *Server) RBACChangeRolePermissions(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		return s.RBAC().ChangeRolePermissions(ctx, q.TenantId, q.Id, q.Add, keysFromPB(q.Keys))
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) RoleUsers(ctx context.Context, tid, id string, p store.RBACPage) (store.RBACResult[store.User], error) {
	v, err := r.c.rpc.RBACRoleUsers(ctx, &storev1.RBACRequest{TxId: r.c.txID, TenantId: tid, Id: id, Page: pageToPB(p)})
	out := store.RBACResult[store.User]{Items: []store.User{}}
	if err := rbacRPCError(v, err); err != nil {
		return out, err
	}
	out.Total = int(v.Total)
	out.Next = v.Next
	for _, x := range v.Users {
		u, e := userFromPB(x)
		if e != nil {
			return out, e
		}
		if u != nil {
			out.Items = append(out.Items, *u)
		}
	}
	return out, nil
}
func (srv *Server) RBACRoleUsers(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		v, err := s.RBAC().RoleUsers(ctx, q.TenantId, q.Id, pageFromPB(q.Page))
		if err != nil {
			return err
		}
		out.Total = int64(v.Total)
		out.Next = v.Next
		for _, x := range v.Items {
			u, e := userToPB(&x)
			if e != nil {
				return e
			}
			out.Users = append(out.Users, u)
		}
		return nil
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) AssignRoleUsers(ctx context.Context, tid, id string, ids []string) error {
	v, err := r.c.rpc.RBACAssignRoleUsers(ctx, &storev1.RBACRequest{TxId: r.c.txID, TenantId: tid, Id: id, Ids: ids})
	return rbacRPCError(v, err)
}
func (srv *Server) RBACAssignRoleUsers(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		return s.RBAC().AssignRoleUsers(ctx, q.TenantId, q.Id, q.Ids)
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) UserRoles(ctx context.Context, tid, id string, p store.RBACPage) (store.RBACResult[store.Role], error) {
	v, err := r.c.rpc.RBACUserRoles(ctx, &storev1.RBACRequest{TxId: r.c.txID, TenantId: tid, Id: id, Page: pageToPB(p)})
	out := store.RBACResult[store.Role]{Items: []store.Role{}}
	if err := rbacRPCError(v, err); err != nil {
		return out, err
	}
	out.Total = int(v.Total)
	out.Next = v.Next
	for _, x := range v.Roles {
		if role := roleFromPB(x); role != nil {
			out.Items = append(out.Items, *role)
		}
	}
	return out, nil
}
func (srv *Server) RBACUserRoles(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		v, err := s.RBAC().UserRoles(ctx, q.TenantId, q.Id, pageFromPB(q.Page))
		if err != nil {
			return err
		}
		out.Total = int64(v.Total)
		out.Next = v.Next
		for _, x := range v.Items {
			out.Roles = append(out.Roles, roleToPB(&x))
		}
		return nil
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) ChangeUserRoles(ctx context.Context, tid, id string, add bool, ids []string) error {
	v, err := r.c.rpc.RBACChangeUserRoles(ctx, &storev1.RBACRequest{TxId: r.c.txID, TenantId: tid, Id: id, Add: add, Ids: ids})
	return rbacRPCError(v, err)
}
func (srv *Server) RBACChangeUserRoles(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		return s.RBAC().ChangeUserRoles(ctx, q.TenantId, q.Id, q.Add, q.Ids)
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) UserPermissions(ctx context.Context, tid, id string, p store.RBACPage) (store.RBACResult[store.PermissionGrant], error) {
	v, err := r.c.rpc.RBACUserPermissions(ctx, &storev1.RBACRequest{TxId: r.c.txID, TenantId: tid, Id: id, Page: pageToPB(p)})
	out := store.RBACResult[store.PermissionGrant]{Items: []store.PermissionGrant{}}
	if err := rbacRPCError(v, err); err != nil {
		return out, err
	}
	out.Total = int(v.Total)
	out.Next = v.Next
	for _, x := range v.Grants {
		out.Items = append(out.Items, grantFromPB(x))
	}
	return out, nil
}
func (srv *Server) RBACUserPermissions(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		v, err := s.RBAC().UserPermissions(ctx, q.TenantId, q.Id, pageFromPB(q.Page))
		if err != nil {
			return err
		}
		out.Total = int64(v.Total)
		out.Next = v.Next
		for _, x := range v.Items {
			out.Grants = append(out.Grants, grantToPB(x))
		}
		return nil
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) ChangeUserPermissions(ctx context.Context, tid, id string, add bool, keys []store.PermissionKey) error {
	v, err := r.c.rpc.RBACChangeUserPermissions(ctx, &storev1.RBACRequest{TxId: r.c.txID, TenantId: tid, Id: id, Add: add, Keys: keysToPB(keys)})
	return rbacRPCError(v, err)
}
func (srv *Server) RBACChangeUserPermissions(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		return s.RBAC().ChangeUserPermissions(ctx, q.TenantId, q.Id, q.Add, keysFromPB(q.Keys))
	})
	out.Error = errToPB(err)
	return out, nil
}
func (r clientRBAC) Snapshot(ctx context.Context, tid, id, aud string) (*store.AuthorizationSnapshot, error) {
	v, err := r.c.rpc.RBACSnapshot(ctx, &storev1.RBACRequest{TxId: r.c.txID, TenantId: tid, Id: id, Audience: aud})
	if err := rbacRPCError(v, err); err != nil {
		return nil, err
	}
	if v.Snapshot == nil {
		return nil, fmt.Errorf("missing RBAC snapshot")
	}
	api, err := resourceServerFromPB(v.Snapshot.Api)
	if err != nil || api == nil {
		if err == nil {
			err = fmt.Errorf("missing RBAC API")
		}
		return nil, err
	}
	return &store.AuthorizationSnapshot{API: api, Permissions: append([]string{}, v.Snapshot.Permissions...)}, nil
}
func (srv *Server) RBACSnapshot(ctx context.Context, q *storev1.RBACRequest) (*storev1.RBACResponse, error) {
	out := &storev1.RBACResponse{}
	err := srv.with(q.TxId, func(s store.Store) error {
		v, err := s.RBAC().Snapshot(ctx, q.TenantId, q.Id, q.Audience)
		if err != nil {
			return err
		}
		api, err := resourceServerToPB(v.API)
		if err != nil {
			return err
		}
		out.Snapshot = &storev1.RBACSnapshot{Api: api, Permissions: v.Permissions}
		return nil
	})
	out.Error = errToPB(err)
	return out, nil
}
