import { defineStore } from 'pinia'
import type { Api, SystemTenant, TenantCreate } from '../api/client'

// The tenants the operator manages, for the switcher and every
// tenant-scoped page.
export const useTenantsStore = defineStore('tenants', {
  state: () => ({
    list: [] as SystemTenant[],
    loaded: false,
    error: '',
    revision: 0,
  }),
  actions: {
    async load(api: Api): Promise<void> {
      const revision = ++this.revision
      try {
        const list = await api.listTenants()
        if (revision !== this.revision) return
        this.list = list
        this.error = ''
      } catch (e) {
        if (revision !== this.revision) return
        this.list = []
        this.error = e instanceof Error ? e.message : String(e)
      } finally {
        if (revision === this.revision) this.loaded = true
      }
    },

    find(name: string): SystemTenant | undefined {
      return this.list.find((t) => t.name === name)
    },

    // first is where /admin/ leads: the first tenant that is not the system
    // tenant, or the system tenant when it is alone.
    first(): SystemTenant | undefined {
      return this.list.find((t) => !t.reserved) ?? this.list[0]
    },

    async create(api: Api, body: TenantCreate): Promise<SystemTenant> {
      const t = await api.createTenant(body)
      this.list = [...this.list, t].sort((a, b) => a.name.localeCompare(b.name))
      return t
    },
  },
})

export type TenantsStore = ReturnType<typeof useTenantsStore>
