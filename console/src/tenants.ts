import { reactive } from 'vue'
import type { Api, SystemTenant, TenantCreate } from './api/client'

// The tenants the operator manages, for the switcher and every
// tenant-scoped page.
export class Tenants {
  readonly state = reactive({
    list: [] as SystemTenant[],
    loaded: false,
    error: '',
  })

  constructor(private api: Api) {}

  async load(): Promise<void> {
    try {
      this.state.list = await this.api.listTenants()
      this.state.error = ''
    } catch (e) {
      this.state.error = e instanceof Error ? e.message : String(e)
    } finally {
      this.state.loaded = true
    }
  }

  find(name: string): SystemTenant | undefined {
    return this.state.list.find((t) => t.name === name)
  }

  // first is where /admin/ leads: the first tenant that is not the system
  // tenant, or the system tenant when it is alone.
  first(): SystemTenant | undefined {
    return this.state.list.find((t) => !t.reserved) ?? this.state.list[0]
  }

  async create(body: TenantCreate): Promise<SystemTenant> {
    const t = await this.api.createTenant(body)
    this.state.list = [...this.state.list, t].sort((a, b) => a.name.localeCompare(b.name))
    return t
  }
}
