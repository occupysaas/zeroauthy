import { ApiError } from '../../api/client'
export { useActionContext as useMonitoringContext } from '../actions/context'
export const unavailable = (e: unknown) => e instanceof ApiError && e.status === 501 && e.errorCode === 'logs_unavailable'
export function executionIDs(details: Record<string, unknown> | undefined): string[] {
  const actions = details?.actions
  if (!actions || typeof actions !== 'object' || !('executions' in actions) || !Array.isArray(actions.executions)) return []
  return actions.executions.filter((id): id is string => typeof id === 'string')
}
