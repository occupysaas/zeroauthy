import type { components } from '../../api/schema'
import { ApiError, type EventType } from '../../api/client'
export { useActionContext as useEventContext } from '../actions/context'
export const unavailable = (e: unknown) => e instanceof ApiError && e.status === 501 && e.errorCode === 'events_unavailable'
export const eventTypes: EventType[] = ['connection.created', 'connection.deleted', 'connection.updated', 'group.created', 'group.deleted', 'group.member.added', 'group.member.deleted', 'group.role.assigned', 'group.role.deleted', 'group.updated', 'organization.connection.added', 'organization.connection.removed', 'organization.connection.updated', 'organization.created', 'organization.deleted', 'organization.group.role.assigned', 'organization.group.role.deleted', 'organization.member.added', 'organization.member.deleted', 'organization.member.role.assigned', 'organization.member.role.deleted', 'organization.updated', 'user.created', 'user.deleted', 'user.updated']
export const awsRegions: components['schemas']['EventsEventStreamEventBridgeAWSRegionEnum'][] = ['af-south-1', 'ap-east-1', 'ap-east-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4', 'ap-southeast-5', 'ap-southeast-6', 'ap-southeast-7', 'ca-central-1', 'ca-west-1', 'eu-central-1', 'eu-central-2', 'eu-north-1', 'eu-south-1', 'eu-south-2', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'il-central-1', 'me-central-1', 'me-south-1', 'mx-central-1', 'sa-east-1', 'us-gov-east-1', 'us-gov-west-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']
export function validDate(value: string): boolean {
 if(!value) return true
 if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) return false
 const date = new Date(value)
 return Number.isFinite(date.getTime()) && date.toISOString().replace('.000Z', 'Z') === value
}
