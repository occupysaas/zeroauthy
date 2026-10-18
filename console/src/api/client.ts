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
export type ResourceServer = components['schemas']['ResourceServer']
export type ResourceServerCreate = components['schemas']['ResourceServerCreate']
export type ResourceServerUpdate = components['schemas']['ResourceServerUpdate']
export type ResourceServerPage = components['schemas']['ResourceServerPage']
export type ResourceServerScope = components['schemas']['ResourceServerScope']
export type ClientGrant = components['schemas']['ClientGrant']
export type ClientGrantCreate = components['schemas']['ClientGrantCreate']
export type ClientGrantUpdate = components['schemas']['ClientGrantUpdate']
export type ClientGrantPage = components['schemas']['ClientGrantPage']
export type Operator = components['schemas']['Operator']
export type OperatorInvite = components['schemas']['OperatorInvite']
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

  listResourceServers(t: SystemTenant, q: { page: number; per_page: number }): Promise<ResourceServerPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/resource-servers', { query: { ...q, include_totals: true } })
  }

  getResourceServer(t: SystemTenant, id: string): Promise<ResourceServer> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/resource-servers/' + encodeURIComponent(id))
  }

  createResourceServer(t: SystemTenant, body: ResourceServerCreate): Promise<ResourceServer> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/resource-servers', { body })
  }

  updateResourceServer(t: SystemTenant, id: string, body: ResourceServerUpdate): Promise<ResourceServer> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/resource-servers/' + encodeURIComponent(id), { body })
  }

  deleteResourceServer(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/resource-servers/' + encodeURIComponent(id))
  }

  listClientGrants(t: SystemTenant, q: { page: number; per_page: number; client_id?: string; audience?: string }): Promise<ClientGrantPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/client-grants', { query: { ...q, include_totals: true } })
  }

  createClientGrant(t: SystemTenant, body: ClientGrantCreate): Promise<ClientGrant> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/client-grants', { body })
  }

  updateClientGrant(t: SystemTenant, id: string, body: ClientGrantUpdate): Promise<ClientGrant> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/client-grants/' + encodeURIComponent(id), { body })
  }

  deleteClientGrant(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/client-grants/' + encodeURIComponent(id))
  }

  // The *All methods read every page (100 at a time) of a listing that the
  // screens need whole: the APIs and machine-to-machine applications to
  // pick from, and the grants for one API or application.
  async allResourceServers(t: SystemTenant): Promise<ResourceServer[]> {
    return collect((page) => this.listResourceServers(t, { page, per_page: ALL_PER_PAGE }).then((r) => ({ items: r.resource_servers, total: r.total })))
  }

  async allMachineClients(t: SystemTenant): Promise<Client[]> {
    return collect((page) => this.listClients(t, { page, per_page: ALL_PER_PAGE, app_type: 'non_interactive' }).then((r) => ({ items: r.clients, total: r.total })))
  }

  async allClientGrants(t: SystemTenant, filter: { client_id?: string; audience?: string }): Promise<ClientGrant[]> {
    return collect((page) => this.listClientGrants(t, { page, per_page: ALL_PER_PAGE, ...filter }).then((r) => ({ items: r.client_grants, total: r.total })))
  }

  listTenants(): Promise<SystemTenant[]> {
    return this.request(this.systemOrigin, 'GET', '/api/system/tenants')
  }

  listOperators(): Promise<Operator[]> {
    return this.request(this.systemOrigin, 'GET', '/api/system/operators')
  }

  inviteOperator(email: string): Promise<OperatorInvite> {
    return this.request(this.systemOrigin, 'POST', '/api/system/operators', { body: { email } })
  }

  deleteOperator(id: string): Promise<void> {
    return this.request(this.systemOrigin, 'DELETE', '/api/system/operators/' + encodeURIComponent(id))
  }

  createTenant(body: TenantCreate): Promise<SystemTenant> {
    return this.request(this.systemOrigin, 'POST', '/api/system/tenants', { body })
  }
}

const ALL_PER_PAGE = 100

async function collect<T>(fetchPage: (page: number) => Promise<{ items: T[]; total: number }>): Promise<T[]> {
  const out: T[] = []
  for (let page = 0; ; page++) {
    const r = await fetchPage(page)
    out.push(...r.items)
    if (r.items.length === 0 || out.length >= r.total) return out
  }
}
