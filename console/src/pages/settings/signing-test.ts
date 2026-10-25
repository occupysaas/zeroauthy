import { mount } from '@vue/test-utils'
import type { Component } from 'vue'
import { servicesKey } from '../../context'
import { fakeServices, tenant, type Call, type Reply } from '../../test/services'

export function signingMount(component: Component, handler: (c: Call) => Reply | Promise<Reply>) {
  const { services, calls, pinia, i18n } = fakeServices(handler)
  const wrapper = mount(component, {
    props: { tenant: tenant('acme') }, attachTo: document.body,
    global: { plugins: [pinia, i18n], provide: { [servicesKey as symbol]: services } },
  })
  return { wrapper, calls }
}
export function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(r => { resolve = r })
  return { promise, resolve }
}
