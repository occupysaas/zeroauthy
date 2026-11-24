package server

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
)

// Directory group routes (Plan 37c).

func (a mgmtAPI) ListGroups(w http.ResponseWriter, r *http.Request, _ mgmtapi.ListGroupsParams) {
	scoped(w, r, a.h.ListGroups, "read:groups")
}
func (a mgmtAPI) GetGroup(w http.ResponseWriter, r *http.Request, id mgmtapi.GroupID) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetGroup(w, r, id) }, "read:groups")
}
func (a mgmtAPI) DeleteGroup(w http.ResponseWriter, r *http.Request, id mgmtapi.GroupID) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteGroup(w, r, id) }, "delete:groups")
}
func (a mgmtAPI) ListGroupMembers(w http.ResponseWriter, r *http.Request, id mgmtapi.GroupID, _ mgmtapi.ListGroupMembersParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListGroupMembers(w, r, id) }, "read:group_members")
}
func (a mgmtAPI) ListGroupRoles(w http.ResponseWriter, r *http.Request, id mgmtapi.GroupID, _ mgmtapi.ListGroupRolesParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListGroupRoles(w, r, id) }, "read:group_roles")
}
func (a mgmtAPI) AssignGroupRoles(w http.ResponseWriter, r *http.Request, id mgmtapi.GroupID) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.AssignGroupRoles(w, r, id) }, "create:group_roles")
}
func (a mgmtAPI) RemoveGroupRoles(w http.ResponseWriter, r *http.Request, id mgmtapi.GroupID) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.RemoveGroupRoles(w, r, id) }, "delete:group_roles")
}
func (a mgmtAPI) ListRoleGroups(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.ListRoleGroupsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListRoleGroups(w, r, id) }, "read:group_roles")
}
func (a mgmtAPI) AssignRoleGroups(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.AssignRoleGroups(w, r, id) }, "create:group_roles")
}
func (a mgmtAPI) RemoveRoleGroups(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.RemoveRoleGroups(w, r, id) }, "delete:group_roles")
}
func (a mgmtAPI) ListUserGroups(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.ListUserGroupsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListUserGroups(w, r, id) }, "read:groups")
}
func (a mgmtAPI) ListUserRoleSourceGroups(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.ListUserRoleSourceGroupsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListUserRoleSourceGroups(w, r, id) }, "read:user_role_source_groups")
}
func (a mgmtAPI) ListOrganizationGroups(w http.ResponseWriter, r *http.Request, id mgmtapi.OrganizationId, _ mgmtapi.ListOrganizationGroupsParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListOrganizationGroups(w, r, id) }, "read:organization_groups")
}
func (a mgmtAPI) ListOrganizationGroupRoles(w http.ResponseWriter, r *http.Request, id mgmtapi.OrganizationId, groupID mgmtapi.GroupID, _ mgmtapi.ListOrganizationGroupRolesParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListOrganizationGroupRoles(w, r, id, groupID) }, "read:organization_group_roles")
}
func (a mgmtAPI) AssignOrganizationGroupRoles(w http.ResponseWriter, r *http.Request, id mgmtapi.OrganizationId, groupID mgmtapi.GroupID) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.AssignOrganizationGroupRoles(w, r, id, groupID) }, "create:organization_group_roles")
}
func (a mgmtAPI) RemoveOrganizationGroupRoles(w http.ResponseWriter, r *http.Request, id mgmtapi.OrganizationId, groupID mgmtapi.GroupID) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.RemoveOrganizationGroupRoles(w, r, id, groupID) }, "delete:organization_group_roles")
}
func (a mgmtAPI) ListOrganizationMemberRoleSourceGroups(w http.ResponseWriter, r *http.Request, id mgmtapi.OrganizationId, userID mgmtapi.MemberUserId, _ mgmtapi.ListOrganizationMemberRoleSourceGroupsParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.ListOrganizationMemberRoleSourceGroups(w, r, id, userID)
	}, "read:organization_member_role_source_groups")
}
