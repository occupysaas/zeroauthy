package store

import (
	"context"
	"errors"
)

var ErrRBACUnavailable = errors.New("store: RBAC capability unavailable")

// RBACSupporter is implemented by remote stores that negotiate RBAC support.
type RBACSupporter interface{ CheckRBACSupport(context.Context) error }

type Role struct{ TenantID, ID, Name, Description string }
type PermissionKey struct{ ResourceServerIdentifier, PermissionName string }
type PermissionSource struct{ Type, ID, Name string }
type PermissionGrant struct {
	Key                             PermissionKey
	ResourceServerName, Description string
	Sources                         []PermissionSource
}
type RBACPage struct {
	Page, PerPage    int
	NameFilter, From string
	Take             int
}
type RBACResult[T any] struct {
	Items []T
	Total int
	Next  string
}
type AuthorizationSnapshot struct {
	API         *ResourceServer
	Permissions []string
}

type RBAC interface {
	CreateRole(context.Context, *Role) error
	GetRole(context.Context, string, string) (*Role, error)
	UpdateRole(context.Context, *Role) error
	DeleteRole(context.Context, string, string) error
	ListRoles(context.Context, string, RBACPage) (RBACResult[Role], error)
	RolePermissions(context.Context, string, string, RBACPage) (RBACResult[PermissionGrant], error)
	ChangeRolePermissions(context.Context, string, string, bool, []PermissionKey) error
	RoleUsers(context.Context, string, string, RBACPage) (RBACResult[User], error)
	AssignRoleUsers(context.Context, string, string, []string) error
	UserRoles(context.Context, string, string, RBACPage) (RBACResult[Role], error)
	ChangeUserRoles(context.Context, string, string, bool, []string) error
	UserPermissions(context.Context, string, string, RBACPage) (RBACResult[PermissionGrant], error)
	ChangeUserPermissions(context.Context, string, string, bool, []PermissionKey) error
	Snapshot(context.Context, string, string, string) (*AuthorizationSnapshot, error)
}

// UnimplementedRBAC fails closed for stores awaiting an RBAC implementation.
type UnimplementedRBAC struct{}

func (UnimplementedRBAC) CreateRole(context.Context, *Role) error { return ErrRBACUnavailable }
func (UnimplementedRBAC) GetRole(context.Context, string, string) (*Role, error) {
	return nil, ErrRBACUnavailable
}
func (UnimplementedRBAC) UpdateRole(context.Context, *Role) error          { return ErrRBACUnavailable }
func (UnimplementedRBAC) DeleteRole(context.Context, string, string) error { return ErrRBACUnavailable }
func (UnimplementedRBAC) ListRoles(context.Context, string, RBACPage) (RBACResult[Role], error) {
	return RBACResult[Role]{}, ErrRBACUnavailable
}
func (UnimplementedRBAC) RolePermissions(context.Context, string, string, RBACPage) (RBACResult[PermissionGrant], error) {
	return RBACResult[PermissionGrant]{}, ErrRBACUnavailable
}
func (UnimplementedRBAC) ChangeRolePermissions(context.Context, string, string, bool, []PermissionKey) error {
	return ErrRBACUnavailable
}
func (UnimplementedRBAC) RoleUsers(context.Context, string, string, RBACPage) (RBACResult[User], error) {
	return RBACResult[User]{}, ErrRBACUnavailable
}
func (UnimplementedRBAC) AssignRoleUsers(context.Context, string, string, []string) error {
	return ErrRBACUnavailable
}
func (UnimplementedRBAC) UserRoles(context.Context, string, string, RBACPage) (RBACResult[Role], error) {
	return RBACResult[Role]{}, ErrRBACUnavailable
}
func (UnimplementedRBAC) ChangeUserRoles(context.Context, string, string, bool, []string) error {
	return ErrRBACUnavailable
}
func (UnimplementedRBAC) UserPermissions(context.Context, string, string, RBACPage) (RBACResult[PermissionGrant], error) {
	return RBACResult[PermissionGrant]{}, ErrRBACUnavailable
}
func (UnimplementedRBAC) ChangeUserPermissions(context.Context, string, string, bool, []PermissionKey) error {
	return ErrRBACUnavailable
}
func (UnimplementedRBAC) Snapshot(context.Context, string, string, string) (*AuthorizationSnapshot, error) {
	return nil, ErrRBACUnavailable
}
