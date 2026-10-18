import { createRouter, createWebHistory, type RouteRecordRaw, type Router, type RouterHistory } from 'vue-router'
import type { Services } from './context'
import ApiCreate from './pages/apis/Create.vue'
import ApiDetail from './pages/apis/Detail.vue'
import ApiList from './pages/apis/List.vue'
import ApplicationCreate from './pages/applications/Create.vue'
import ApplicationDetail from './pages/applications/Detail.vue'
import ApplicationList from './pages/applications/List.vue'
import Callback from './pages/Callback.vue'
import Home from './pages/Home.vue'
import NotFound from './pages/NotFound.vue'
import OperatorList from './pages/operators/List.vue'
import Root from './pages/Root.vue'

declare module 'vue-router' {
  interface RouteMeta {
    // public routes need no sign-in; bare ones show no shell.
    public?: boolean
    bare?: boolean
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
  { path: '/t/:tenant/operators', name: 'operators', component: OperatorList },
  { path: '/:rest(.*)*', name: 'not-found', component: NotFound },
]

// installGuards signs the operator in before any page but the callback,
// and loads the tenants once.
export function installGuards(router: Router, s: Pick<Services, 'auth' | 'tenants'>): void {
  router.beforeEach(async (to) => {
    if (to.meta.public) return true
    if (!s.auth.user.authenticated) {
      await s.auth.login(to.fullPath, true)
      return false
    }
    if (!s.tenants.state.loaded) await s.tenants.load()
    return true
  })
}

export function createConsoleRouter(s: Services, history: RouterHistory = createWebHistory('/admin/')): Router {
  const router = createRouter({ history, routes })
  installGuards(router, s)
  return router
}
