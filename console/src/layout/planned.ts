// Sections the console will have once their Management API slice ships
// (design §2 and docs/superpowers/plan-1-followups.md). Each names the
// /api/v2 resources behind it; the sidebar shows them disabled until the
// slice moves the entry into Shell.vue's live sections.
export interface Planned {
  key: string
  label: string
  api: string
  when: string
}

export const planned: Planned[] = [
  { key: 'users', label: 'Users', api: '/api/v2/users, /api/v2/jobs/users-imports, /api/v2/tickets/password-change', when: 'slice 4' },
  { key: 'settings', label: 'Tenant settings', api: '/api/v2/tenants/settings', when: 'slice 5' },
  { key: 'attack-protection', label: 'Attack protection', api: '/api/v2/attack-protection', when: 'slice 5' },
  { key: 'social', label: 'Social connections', api: '/api/v2/connections (social strategies)', when: 'slice 6' },
  { key: 'roles', label: 'Roles', api: '/api/v2/roles', when: 'later' },
  { key: 'organizations', label: 'Organizations', api: '/api/v2/organizations', when: 'later' },
  { key: 'mfa', label: 'Multi-factor', api: '/api/v2/guardian', when: 'later' },
  { key: 'actions', label: 'Actions', api: '/api/v2/actions', when: 'later' },
  { key: 'branding', label: 'Branding', api: '/api/v2/branding, /api/v2/prompts', when: 'later' },
  { key: 'emails', label: 'Email templates', api: '/api/v2/email-templates, /api/v2/emails/provider', when: 'later' },
  { key: 'domains', label: 'Custom domains', api: '/api/v2/custom-domains', when: 'later' },
  { key: 'logs', label: 'Logs', api: '/api/v2/logs, /api/v2/log-streams', when: 'later' },
]
