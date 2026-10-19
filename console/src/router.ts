import { createRouter, createWebHistory, type RouteRecordRaw, type Router, type RouterHistory } from 'vue-router'
import type { Api } from './api/client'
import type { Auth } from './auth/auth'
import type { Services } from './context'
import ApiCreate from './pages/apis/Create.vue'
import ApiDetail from './pages/apis/Detail.vue'
import ApiList from './pages/apis/List.vue'
import ApplicationCreate from './pages/applications/Create.vue'
import ApplicationDetail from './pages/applications/Detail.vue'
import ApplicationList from './pages/applications/List.vue'
import ConnectionCreate from './pages/connections/Create.vue'
import ConnectionDetail from './pages/connections/Detail.vue'
import ConnectionList from './pages/connections/List.vue'
import Callback from './pages/Callback.vue'
import Home from './pages/Home.vue'
import NotFound from './pages/NotFound.vue'
import OperatorList from './pages/operators/List.vue'
import { plannedPages } from './pages/planned'
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

export const routes: RouteRecordRaw[] = [
  { path: '/', name: 'root', component: Root },
  { path: '/callback', name: 'callback', component: Callback, meta: { public: true, bare: true } },
  { path: '/t/:tenant/', name: 'home', component: Home },
  { path: '/t/:tenant/applications', name: 'applications', component: ApplicationList },
  { path: '/t/:tenant/applications/new', name: 'application-new', component: ApplicationCreate },
  { path: '/t/:tenant/applications/:id', name: 'application', component: ApplicationDetail },
  { path: '/t/:tenant/apis', name: 'apis', component: ApiList },
  { path: '/t/:tenant/apis/new', name: 'api-new', component: ApiCreate },
  { path: '/t/:tenant/apis/:id', name: 'api', component: ApiDetail },
  { path: '/t/:tenant/connections', name: 'connections', component: ConnectionList },
  { path: '/t/:tenant/connections/new', name: 'connection-new', component: ConnectionCreate },
  { path: '/t/:tenant/connections/:id', name: 'connection', component: ConnectionDetail },
  { path: '/t/:tenant/operators', name: 'operators', component: OperatorList },
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
