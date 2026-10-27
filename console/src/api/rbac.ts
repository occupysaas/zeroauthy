import type { components } from './schema'

// Keep management response types at the API boundary; components never depend
// on storage/protobuf representations.
export type Role = components['schemas']['Role']
export type RolePage = components['schemas']['RolePage']
export type PermissionKey = components['schemas']['RBACPermissionKey']
export type PermissionSource = components['schemas']['RBACPermissionSource']
export type Permission = components['schemas']['RBACPermission']
export type PermissionPage = components['schemas']['RBACPermissionPage']
export type RoleUser = components['schemas']['RoleUser']
export type RoleUserPage = components['schemas']['RoleUserPage']
export type OffsetPage = { page: number; per_page: number }
