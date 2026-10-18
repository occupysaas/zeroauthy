import type { components } from './schema'

// A thin, typed wrapper over fetch for the Management API (on each
// tenant's own host) and the system API (on the system host).

export type Client = components['schemas']['Client']
export type ClientCreate = components['schemas']['ClientCreate']
export type ClientUpdate = components['schemas']['ClientUpdate']
export type ClientPage = components['schemas']['ClientPage']
export type AppType = components['schemas']['AppType']
export type SystemTenant = components['schemas']['SystemTenant']
export type TenantCreate = components['schemas']['TenantCreate']
export type ManagementError = components['schemas']['ManagementError']

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly errorCode: string,
    message: string,
  ) {
    super(message)
  }
}

type Query = Record<string, string | number | boolean | undefined>

export class Api {
  constructor(
    // systemOrigin is where the system API lives (the console's origin).
    private systemOrigin: string,
    private token: () => Promise<string>,
    private fetchFn: typeof fetch = (...a) => window.fetch(...a),
  ) {}

  async request<T>(origin: string, method: string, path: string, opts: { query?: Query; body?: unknown } = {}): Promise<T> {
    const url = new URL(path, origin)
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined && v !== '') url.searchParams.set(k, String(v))
    }
    const headers: Record<string, string> = { Authorization: 'Bearer ' + (await this.token()) }
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
    const res = await this.fetchFn(url.toString(), {
      method,
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    })
    if (res.status === 204) return undefined as T
    const body = (await res.json().catch(() => null)) as unknown
    if (!res.ok) {
      const e = (body ?? {}) as Partial<ManagementError>
      throw new ApiError(res.status, e.errorCode ?? '', e.message ?? res.statusText ?? 'Request failed')
    }
    return body as T
  }

  // tenantOrigin is where a tenant's Management API answers.
  static tenantOrigin(t: Pick<SystemTenant, 'host'>): string {
    return 'https://' + t.host
  }

  listClients(t: SystemTenant, q: { page: number; per_page: number; app_type?: string }): Promise<ClientPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/clients', { query: { ...q, include_totals: true } })
  }

  getClient(t: SystemTenant, id: string): Promise<Client> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/clients/' + encodeURIComponent(id))
  }

  createClient(t: SystemTenant, body: ClientCreate): Promise<Client> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/clients', { body })
  }

  updateClient(t: SystemTenant, id: string, body: ClientUpdate): Promise<Client> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/clients/' + encodeURIComponent(id), { body })
  }

  deleteClient(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/clients/' + encodeURIComponent(id))
  }

  rotateSecret(t: SystemTenant, id: string): Promise<Client> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/clients/' + encodeURIComponent(id) + '/rotate-secret')
  }

  listTenants(): Promise<SystemTenant[]> {
    return this.request(this.systemOrigin, 'GET', '/api/system/tenants')
  }

  createTenant(body: TenantCreate): Promise<SystemTenant> {
    return this.request(this.systemOrigin, 'POST', '/api/system/tenants', { body })
  }
}
