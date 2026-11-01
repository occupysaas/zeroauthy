import inventory from '../../../../internal/logrules/inventory.json'
import type { components } from '../../api/schema'
import type { LogStream } from '../../api/client'
// The same frozen inventory generates the API contracts. Consume its field
// flags and enums so the form cannot drift from the eight server sink schemas.
export interface SinkField {
 name: keyof components['schemas']['LogStreamSinkPatch']
 type: string
 required: boolean
 secret: boolean
 values?: string[]
 pattern?: string
}
export interface SinkSchema { type: LogStream['type']; delivered: boolean; fields: SinkField[] }
export const sinks = inventory.sinks as SinkSchema[]
export const categories = inventory.categories as components['schemas']['LogStreamFilter']['name'][]
export const piiFields: components['schemas']['LogStreamPII']['log_fields'] = ['first_name', 'last_name', 'username', 'email', 'phone', 'address']
export const cloudStream = (type: string) => sinks.find(s => s.type === type)?.delivered === false
