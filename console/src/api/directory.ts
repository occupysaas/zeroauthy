import type { components } from './schema'

// Directory groups and SCIM (Plan 37c) at the API boundary.
export type Group = components['schemas']['Group']
export type GroupPage = components['schemas']['GroupPage']
export type GroupCheckpoint = components['schemas']['GroupCheckpoint']
export type GroupMember = components['schemas']['GroupMember']
export type GroupMemberPage = components['schemas']['GroupMemberPage']
export type GroupRolePage = components['schemas']['GroupRolePage']
export type UserGroup = components['schemas']['UserGroup']
export type UserGroupPage = components['schemas']['UserGroupPage']
export type ScimMappingItem = components['schemas']['ScimMappingItem']
export type ScimConfiguration = components['schemas']['ScimConfiguration']
export type ScimToken = components['schemas']['ScimToken']
export type ScimTokenCreated = components['schemas']['ScimTokenCreated']
export type ScimTokenCreate = components['schemas']['ScimTokenCreate']

// The scopes a SCIM token can hold (ScimTokenCreate.scopes).
export const scimScopes = ['get:users', 'post:users', 'put:users', 'patch:users', 'delete:users', 'get:groups', 'post:groups', 'put:groups', 'patch:groups', 'delete:groups'] as const

// The strategies that accept SCIM provisioning.
export const scimStrategies = ['samlp', 'oidc', 'okta', 'waad']

// Self-service SSO (Plan 37c Phase B).
export type SelfServiceProfile = components['schemas']['SelfServiceProfile']
export type SelfServiceProfileCreate = components['schemas']['CreateSelfServiceProfileRequestContent']
export type SelfServiceProfileUpdate = components['schemas']['UpdateSelfServiceProfileRequestContent']
export type SsoTicketRequest = components['schemas']['CreateSelfServiceProfileSsoTicketRequestContent']
export type ConnectionProfile = components['schemas']['ConnectionProfile']
export type ConnectionProfileCreate = components['schemas']['CreateConnectionProfileRequestContent']

// The strategies the self-service assistant can configure (D-0150 Q7).
export const selfServiceStrategies = ['samlp', 'oidc', 'okta', 'waad', 'adfs'] as const
