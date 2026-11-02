import type { GuardianConfigurationRoute } from '../../api/client'
export interface ConfigField { name: string; secret?: boolean; kind?: 'boolean' | 'number' | 'lines'; options?: string[] }
export interface Configuration { route: GuardianConfigurationRoute; title: string; fields: ConfigField[]; writeOnly?: boolean }
const twilio: ConfigField[] = [{ name: 'from' }, { name: 'messaging_service_sid' }, { name: 'sid' }, { name: 'auth_token', secret: true }]
const templates: ConfigField[] = [{ name: 'enrollment_message' }, { name: 'verification_message' }]
const phoneProvider: ConfigField[] = [{ name: 'provider', options: ['auth0', 'twilio', 'phone-message-hook'] }]
export const configurations: Configuration[] = [
  { route: 'sms/providers/twilio', title: 'smsTwilio', fields: twilio },
  { route: 'phone/providers/twilio', title: 'phoneTwilio', fields: twilio },
  { route: 'sms/templates', title: 'smsTemplates', fields: templates },
  { route: 'phone/templates', title: 'phoneTemplates', fields: templates },
  { route: 'sms/selected-provider', title: 'smsProvider', fields: phoneProvider },
  { route: 'phone/selected-provider', title: 'phoneProvider', fields: phoneProvider },
  { route: 'phone/message-types', title: 'phoneMessages', fields: [{ name: 'message_types', kind: 'lines' }] },
  { route: 'phone/settings', title: 'phoneSettings', fields: [{ name: 'otp_length', kind: 'number' }, { name: 'otp_expiration_time', kind: 'number' }] },
  { route: 'push-notification/providers/apns', title: 'apns', fields: [{ name: 'sandbox', kind: 'boolean' }, { name: 'bundle_id' }, { name: 'p12', secret: true }] },
  { route: 'push-notification/providers/fcm', title: 'fcm', writeOnly: true, fields: [{ name: 'server_key', secret: true }] },
  { route: 'push-notification/providers/fcmv1', title: 'fcmv1', writeOnly: true, fields: [{ name: 'server_credentials', secret: true }] },
  { route: 'push-notification/providers/sns', title: 'sns', fields: ['aws_access_key_id', 'aws_region', 'sns_apns_platform_application_arn', 'sns_gcm_platform_application_arn'].map(name => ({ name })).concat([{ name: 'aws_secret_access_key', secret: true }] as ConfigField[]) },
  { route: 'push-notification/selected-provider', title: 'pushProvider', fields: [{ name: 'provider', options: ['guardian', 'sns', 'direct'] }] },
  { route: 'duo/settings', title: 'duo', fields: [{ name: 'ikey' }, { name: 'host' }, { name: 'skey', secret: true }] },
]
