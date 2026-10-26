// The one list of console sections: the sidebar renders it and the router
// adds a route for every planned entry. Shipping a slice later means flipping
// its status to 'live' and giving it a real page.

export interface Planned {
  planned: 'slice 4' | 'slice 5' | 'slice 6' | 'later'
  api: string[]
}

export interface Section {
  key: string // route name
  label: string // i18n key
  group?: string // i18n key; undefined = top of the sidebar
  path: string // relative to /t/:tenant/, '' for home
  status: 'live' | Planned
  systemOnly?: boolean
}

export const sections: Section[] = [
  { key: 'home', label: 'nav.home', path: '', status: 'live' },
  { key: 'applications', label: 'nav.applications', group: 'navGroup.applications', path: 'applications', status: 'live' },
  { key: 'apis', label: 'nav.apis', group: 'navGroup.applications', path: 'apis', status: 'live' },
  { key: 'connections', label: 'nav.connections', group: 'navGroup.authentication', path: 'connections', status: 'live' },
  { key: 'social', label: 'nav.social', group: 'navGroup.authentication', path: 'social', status: { planned: 'slice 6', api: ['/api/v2/connections (social strategies)'] } },
  {
    key: 'users',
    label: 'nav.users',
    group: 'navGroup.userManagement',
    path: 'users',
    status: 'live',
  },
  { key: 'roles', label: 'nav.roles', group: 'navGroup.userManagement', path: 'roles', status: { planned: 'later', api: ['/api/v2/roles'] } },
  { key: 'organizations', label: 'nav.organizations', group: 'navGroup.userManagement', path: 'organizations', status: { planned: 'later', api: ['/api/v2/organizations'] } },
  { key: 'attack-protection', label: 'nav.attackProtection', group: 'navGroup.security', path: 'attack-protection', status: 'live' },
  { key: 'mfa', label: 'nav.mfa', group: 'navGroup.security', path: 'mfa', status: { planned: 'later', api: ['/api/v2/guardian/*'] } },
  { key: 'actions', label: 'nav.actions', group: 'navGroup.actions', path: 'actions', status: { planned: 'later', api: ['/api/v2/actions'] } },
  { key: 'branding', label: 'nav.branding', group: 'navGroup.branding', path: 'branding', status: 'live' },
  { key: 'emails', label: 'nav.emails', group: 'navGroup.branding', path: 'emails', status: 'live' },
  { key: 'custom-domains', label: 'nav.customDomains', group: 'navGroup.branding', path: 'custom-domains', status: { planned: 'later', api: ['/api/v2/custom-domains'] } },
  { key: 'logs', label: 'nav.logs', group: 'navGroup.monitoring', path: 'logs', status: { planned: 'later', api: ['/api/v2/logs', '/api/v2/log-streams'] } },
  { key: 'settings', label: 'nav.settings', group: 'navGroup.settings', path: 'settings', status: 'live' },
  { key: 'operators', label: 'nav.operators', group: 'navGroup.system', path: 'operators', status: 'live', systemOnly: true },
]

export function isPlanned(s: Section): s is Section & { status: Planned } {
  return s.status !== 'live'
}

/** The sections to list for a tenant; system-only ones need the reserved tenant. */
export function visibleSections(reserved: boolean): Section[] {
  return sections.filter((s) => reserved || !s.systemOnly)
}

/** The catalog key naming when a planned section ships, e.g. 'plannedWhen.slice4'. */
export function plannedWhenKey(p: Planned): string {
  return 'plannedWhen.' + p.planned.replace(' ', '')
}
