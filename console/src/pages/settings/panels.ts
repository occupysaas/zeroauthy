import { field, type Panel } from './forms'
import type { TenantSettingsPatch } from '../../api/client'
const settings = { load: (api, tenant) => api.getTenantSettings(tenant), save: (api, tenant, patch) => api.updateTenantSettings(tenant, patch as TenantSettingsPatch) } satisfies Pick<Panel, 'load' | 'save'>
export const settingsPanels: Panel[] = [
  { ...settings, key: 'general', title: 'policy.general', fields: [field('friendly_name'), field('picture_url', 'url'), field('support_email', 'email'), field('support_url', 'url')] },
  { ...settings, key: 'sessions', title: 'policy.sessions', hint: 'policy.hoursHint', fields: [
    ...['session_lifetime', 'idle_session_lifetime', 'ephemeral_session_lifetime', 'idle_ephemeral_session_lifetime'].map(p => field(p, 'number', { min: 0 })),
    field('session_cookie.mode', undefined, { options: ['persistent', 'non-persistent'] }),
  ] },
  { ...settings, key: 'languages', title: 'policy.languages', fields: [field('enabled_locales', 'lines', { hint: 'policy.localesHint' })] },
  { ...settings, key: 'advanced', title: 'policy.advanced', fields: [
    field('default_audience'), field('default_directory'), field('allowed_logout_urls', 'lines', { hint: 'policy.linesHint' }),
    field('device_flow.charset', undefined, { options: ['base20', 'digits'] }), field('device_flow.mask'),
    field('pushed_authorization_requests_supported', 'toggle'), field('skip_non_verifiable_callback_uri_confirmation_prompt', 'toggle'),
    field('default_redirection_uri', 'url', { hint: 'policy.future' }),
    ...['change_pwd_flow_v1', 'enable_apis_section', 'enable_client_connections', 'enable_pipeline2', 'enable_dynamic_client_registration', 'disable_management_api_sms_obfuscation', 'trust_azure_adfs_email_verified_connection_property', 'custom_domains_provisioning'].map(p => field('flags.' + p, 'toggle', { hint: 'policy.future' })),
    field('flags.disable_impersonation', 'toggle', { readonly: true, hint: 'policy.readonly' }),
  ] },
]
