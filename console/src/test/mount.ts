import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import type { Component } from 'vue'
import { servicesKey } from '../context'
import { useTenantsStore } from '../stores/tenants'
import RouteModal from '../ui/RouteModal.vue'
import { viewDepthKey } from 'vue-router'
import type { SystemTenant } from '../api/client'
import { fakeServices, memoryRouter, tenant, type Call, type Reply } from './services'

// mountAt mounts page at path, signed in, with the API answered by handler
// (the tenant list included).
export async function mountAt(page: Component, path: string, handler: (c: Call) => Reply | Promise<Reply>, tenantExtra: Partial<SystemTenant> = {}) {
  const { services, calls, pinia, i18n } = fakeServices((c) =>
    c.url.endsWith('/api/console/tenants') ? { status: 200, body: [tenant('acme', tenantExtra), tenant('system', { reserved: true })] } : handler(c),
  )
  await useTenantsStore().load(services.api)
  calls.length = 0 // keep only the page's own calls
  const router = memoryRouter()
  await router.push(path)
  // A list's RouterView shows its create or edit modal: mounted on its own,
  // the page must still know where it sits among the matched routes.
  const depth = router.currentRoute.value.matched.findIndex((r) => r.components?.default === page)
  const wrapper = mount(page, {
    attachTo: document.body,
    global: { plugins: [router, pinia, i18n], provide: { [servicesKey as symbol]: services, ...(depth >= 0 ? { [viewDepthKey as symbol]: depth + 1 } : {}) } },
  })
  await flushPromises()
  return { wrapper: portaled(wrapper), router, calls }
}

// portaled lets a test query a page shown as a route modal the same way as
// any other: the modal renders in a portal on document.body, outside the
// mounted element.
function portaled<W extends VueWrapper>(wrapper: W): W {
  if (!wrapper.findComponent(RouteModal).exists()) return wrapper
  const body = new DOMWrapper(document.body)
  const queries = new Set<PropertyKey>(['find', 'findAll', 'get', 'text', 'html'])
  return new Proxy(wrapper, {
    get(target, key, receiver) {
      if (queries.has(key)) return (body[key as keyof DOMWrapper<Element>] as (...a: unknown[]) => unknown).bind(body)
      return Reflect.get(target, key, receiver)
    },
  })
}

// topDialog is the dialog on top: a confirmation opened from a modal page
// sits above that page's own dialog.
export function topDialog(): Element | undefined {
  return Array.from(document.body.querySelectorAll('[role="dialog"]')).at(-1)
}

// dialogCount is how many dialogs are open.
export function dialogCount(): number {
  return document.body.querySelectorAll('[role="dialog"]').length
}

// confirmPrompt presses the confirm button of the dialog on top.
export async function confirmPrompt() {
  topDialog()!.querySelector<HTMLButtonElement>('button[type="submit"]')!.click()
  await flushPromises()
}

export function apiError(status: number, errorCode: string, message: string) {
  return { status, body: { statusCode: status, error: 'Error', errorCode, message } }
}
