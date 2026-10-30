import OrganizationList from './pages/organizations/List.vue'
import OrganizationCreate from './pages/organizations/Create.vue'
import OrganizationDetail from './pages/organizations/Detail.vue'
import ModuleLibrary from './pages/actions/modules/ModuleLibrary.vue'
import ModuleEditor from './pages/actions/modules/ModuleEditor.vue'
import ModuleVersions from './pages/actions/modules/ModuleVersions.vue'
import { createRouter, createWebHistory, type RouteRecordRaw, type Router, type RouterHistory } from 'vue-router'
import type { Api } from './api/client'
import type { Auth } from './auth/auth'
import type { Services } from './context'
import ActionsExecution from './pages/actions/Execution.vue'
import ActionsTriggers from './pages/actions/Triggers.vue'
import ActionsTestPanel from './pages/actions/TestPanel.vue'
import ActionsVersions from './pages/actions/Versions.vue'
import ActionsEditor from './pages/actions/Editor.vue'
import ActionsLibrary from './pages/actions/Library.vue'
import ApiCreate from './pages/apis/Create.vue'
import CustomDomains from './pages/custom-domains/CustomDomains.vue'
import CustomDomainDetail from './pages/custom-domains/DomainDetail.vue'
import ApiDetail from './pages/apis/Detail.vue'
import ApiList from './pages/apis/List.vue'
import ApplicationCreate from './pages/applications/Create.vue'
import ApplicationDetail from './pages/applications/Detail.vue'
import ApplicationList from './pages/applications/List.vue'
import ConnectionCreate from './pages/connections/Create.vue'
import ConnectionDetail from './pages/connections/Detail.vue'
import ConnectionList from './pages/connections/List.vue'
import EnterpriseCreate from './pages/connections/enterprise/Create.vue'
import EnterpriseList from './pages/connections/enterprise/List.vue'
import SocialCreate from './pages/connections/social/Create.vue'
import SocialDetail from './pages/connections/social/Detail.vue'
import SocialList from './pages/connections/social/List.vue'
import Callback from './pages/Callback.vue'
import Home from './pages/Home.vue'
import NotFound from './pages/NotFound.vue'
import OperatorList from './pages/operators/List.vue'
import RoleList from './pages/roles/List.vue'
import RoleCreate from './pages/roles/Create.vue'
import RoleDetail from './pages/roles/Detail.vue'
import UserCreate from './pages/users/Create.vue'
import UserDetail from './pages/users/Detail.vue'
import UserList from './pages/users/List.vue'
import UserImportExport from './pages/users/ImportExport.vue'
import { plannedPages } from './pages/planned'
import Settings from './pages/settings/TenantSettings.vue'
import AttackProtection from './pages/attack-protection/AttackProtection.vue'
import Branding from './pages/branding/Branding.vue'
import EmailSettings from './pages/emails/Emails.vue'
import Root from './pages/Root.vue'
import { isPlanned, sections } from './layout/sections'
import { useTenantsStore, type TenantsStore } from './stores/tenants'

declare module 'vue-router' {
  interface RouteMeta {
    // public routes need no sign-in; bare ones show no shell.
    public?: boolean
    bare?: boolean
    // the section key of a planned route
    section?: string
  }
}

// A section's create and edit forms are child routes of its list: they open
// as modals over the list, so the sidebar keeps its place.
export const routes: RouteRecordRaw[] = [
  { path: '/', name: 'root', component: Root },
  { path: '/callback', name: 'callback', component: Callback, meta: { public: true, bare: true } },
  { path: '/t/:tenant/', name: 'home', component: Home },
  {
    path: '/t/:tenant/applications',
    name: 'applications',
    component: ApplicationList,
    children: [{ path: 'new', name: 'application-new', component: ApplicationCreate }, { path: ':id', name: 'application', component: ApplicationDetail }],
  },
  {
    path: '/t/:tenant/apis',
    name: 'apis',
    component: ApiList,
    children: [{ path: 'new', name: 'api-new', component: ApiCreate }, { path: ':id', name: 'api', component: ApiDetail }],
  },
  {
    path: '/t/:tenant/connections',
    name: 'connections',
    component: ConnectionList,
    children: [{ path: 'new', name: 'connection-new', component: ConnectionCreate }, { path: ':id', name: 'connection', component: ConnectionDetail }],
  },
  {
    path: '/t/:tenant/social',
    name: 'social',
    component: SocialList,
    children: [{ path: 'new', name: 'social-new', component: SocialCreate }, { path: ':id', name: 'social-connection', component: SocialDetail }],
  },
  {
    path: '/t/:tenant/enterprise',
    name: 'enterprise',
    component: EnterpriseList,
    children: [{ path: 'new', name: 'enterprise-new', component: EnterpriseCreate }, { path: ':id', name: 'enterprise-connection', component: SocialDetail }],
  },
  {
    path: '/t/:tenant/organizations',
    name: 'organizations',
    component: OrganizationList,
    children: [{ path: 'new', name: 'organization-new', component: OrganizationCreate }, { path: ':id', name: 'organization', component: OrganizationDetail }],
  },
  {
    path: '/t/:tenant/roles',
    name: 'roles',
    component: RoleList,
    children: [{ path: 'new', name: 'role-new', component: RoleCreate }, { path: ':id', name: 'role', component: RoleDetail }],
  },
  {
    path: '/t/:tenant/users',
    name: 'users',
    component: UserList,
    children: [{ path: 'new', name: 'user-new', component: UserCreate }, { path: ':id', name: 'user', component: UserDetail }],
  },
  { path: '/t/:tenant/users/import-export', name: 'users-import-export', component: UserImportExport },
  { path: '/t/:tenant/operators', name: 'operators', component: OperatorList },
  { path: '/t/:tenant/settings', name: 'settings', component: Settings },
  { path: '/t/:tenant/attack-protection', name: 'attack-protection', component: AttackProtection },
  { path: '/t/:tenant/emails', name: 'emails', component: EmailSettings },
  { path: '/t/:tenant/branding', name: 'branding', component: Branding },
  {
    path: '/t/:tenant/custom-domains',
    name: 'custom-domains',
    component: CustomDomains,
    children: [{ path: ':id', name: 'custom-domain', component: CustomDomainDetail }],
  },
  { path: '/t/:tenant/actions', name: 'actions', component: ActionsLibrary },
  { path: '/t/:tenant/actions/triggers/:trigger?', name: 'action-triggers', component: ActionsTriggers },
  { path: '/t/:tenant/actions/executions', name: 'action-execution', component: ActionsExecution },
  { path: '/t/:tenant/actions/modules', name: 'action-modules', component: ModuleLibrary },
  { path: '/t/:tenant/actions/modules/:id', name: 'action-module-editor', component: ModuleEditor },
  { path: '/t/:tenant/actions/modules/:id/versions', name: 'action-module-versions', component: ModuleVersions },
  { path: '/t/:tenant/actions/:id', name: 'action-editor', component: ActionsEditor },
  { path: '/t/:tenant/actions/:id/versions', name: 'action-versions', component: ActionsVersions },
  { path: '/t/:tenant/actions/:id/test', name: 'action-test', component: ActionsTestPanel },
  ...sections.filter(isPlanned).map((s) => ({
    path: '/t/:tenant/' + s.path,
    name: s.key,
    component: plannedPages[s.key]!,
    meta: { section: s.key },
  })),
  { path: '/:rest(.*)*', name: 'not-found', component: NotFound },
]

// installGuards signs the operator in before any page but the callback,
// and loads the tenants once.
export function installGuards(
  router: Router,
  s: { auth: Pick<Auth, 'user' | 'login'>; tenants: Pick<TenantsStore, 'loaded' | 'load'>; api: Api },
): void {
  router.beforeEach(async (to) => {
    if (to.meta.public) return true
    if (!s.auth.user.authenticated) {
      await s.auth.login(to.fullPath, true)
      return false
    }
    if (!s.tenants.loaded) await s.tenants.load(s.api)
    return true
  })
}

export function createConsoleRouter(s: Services, history: RouterHistory = createWebHistory('/admin/')): Router {
  const router = createRouter({ history, routes })
  installGuards(router, { auth: s.auth, tenants: useTenantsStore(), api: s.api })
  return router
}
