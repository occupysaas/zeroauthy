import { h, type Component } from 'vue'
import { isPlanned, sections } from '../../layout/sections'
import Actions from './Actions.vue'
import Branding from './Branding.vue'
import Emails from './Emails.vue'
import MultiFactor from './MultiFactor.vue'
import CustomDomains from './CustomDomains.vue'
import Logs from './Logs.vue'
import Organizations from './Organizations.vue'
import Roles from './Roles.vue'
import Social from './Social.vue'
import PlannedPage from './PlannedPage.vue'

/** A planned page with no preview of its own: just the frame for the section. */
function bare(key: string): Component {
  return { name: `Planned_${key}`, render: () => h(PlannedPage, { sectionKey: key }) }
}

/** Dedicated pages by section key; the rest use the bare frame until designed. */
const dedicated: Record<string, Component> = {
  actions: Actions,
  mfa: MultiFactor,
  branding: Branding,
  emails: Emails,
  social: Social,
  roles: Roles,
  organizations: Organizations,
  'custom-domains': CustomDomains,
  logs: Logs,
}

/** The page behind each planned route, by section key. */
export const plannedPages: Record<string, Component> = Object.fromEntries(
  sections.filter(isPlanned).map((s) => [s.key, dedicated[s.key] ?? bare(s.key)]),
)
