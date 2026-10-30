<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, type Connection, type User } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import { onModalClosed } from '../../ui/routeModal'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Tag from '../../ui/Tag.vue'
import SearchHelp from './SearchHelp.vue'
import { relativeTime } from './policy'

const { t, locale } = useI18n()

const PER_PAGE = 20
// The server reaches only the first 1000 results.
const MAX_DEPTH = 1000

const { api } = useServices()
const tenant = useTenant()
const route = useRoute()
const router = useRouter()

const q = computed(() => (typeof route.query.q === 'string' ? route.query.q : ''))
const conn = computed(() => (typeof route.query.connection === 'string' ? route.query.connection : ''))
const sort = computed(() => (typeof route.query.sort === 'string' ? route.query.sort : ''))
const page = computed(() => Math.max(0, Number(route.query.page ?? 0) || 0))

const text = ref(q.value)
const users = ref<User[]>([])
const total = ref(0)
const loading = ref(true)
const error = ref('')
// A 400 is the search or the paging being refused: its message goes under the box.
const searchError = ref('')
const connections = ref<Connection[]>([])
const now = Date.now()

onMounted(async () => {
  const tn = tenant.value
  if (!tn) return
  try {
    connections.value = await api.allDatabaseConnections(tn)
  } catch {
    // The filter is a convenience; the list works without it.
  }
})

// seq numbers the requests so a slow, older answer cannot overwrite a newer one.
let seq = 0
async function load() {
  const tn = tenant.value
  if (!tn) return
  const mine = ++seq
  loading.value = true
  error.value = ''
  searchError.value = ''
  try {
    const res = await api.listUsers(tn, { q: q.value, page: page.value, per_page: PER_PAGE, sort: sort.value, connection: conn.value })
    if (mine !== seq) return
    users.value = res.users
    total.value = res.total
  } catch (e) {
    if (mine !== seq) return
    users.value = []
    if (e instanceof ApiError && e.status === 400) searchError.value = e.message
    else error.value = errorMessage(e)
  } finally {
    if (mine === seq) loading.value = false
  }
}
watch([tenant, q, conn, sort, page], load, { immediate: true })
watch(q, (v) => (text.value = v))

function go(next: { q?: string; connection?: string; sort?: string; page?: number }) {
  const m = { q: q.value, connection: conn.value, sort: sort.value, page: page.value, ...next }
  const query: Record<string, string> = {}
  if (m.q) query.q = m.q
  if (m.connection) query.connection = m.connection
  if (m.sort) query.sort = m.sort
  if (m.page) query.page = String(m.page)
  void router.push({ query })
}
function search() {
  go({ q: text.value, page: 0 })
}

// Columns the server can sort by, with the field it sorts on.
const sortable = { email: 'email', logins: 'logins_count', last: 'last_login' } as const
type Col = keyof typeof sortable
function dir(c: Col): 'ascending' | 'descending' | 'none' {
  if (sort.value === sortable[c] + ':1') return 'ascending'
  if (sort.value === sortable[c] + ':-1') return 'descending'
  return 'none'
}
function toggle(c: Col) {
  go({ sort: sortable[c] + (dir(c) === 'ascending' ? ':-1' : ':1'), page: 0 })
}

const from = computed(() => (total.value === 0 ? 0 : page.value * PER_PAGE + 1))
const to = computed(() => Math.min(total.value, (page.value + 1) * PER_PAGE))
const atDepth = computed(() => (page.value + 2) * PER_PAGE > MAX_DEPTH)
const filtered = computed(() => q.value !== '' || conn.value !== '')

function label(u: User): string {
  return u.name || u.email || u.user_id || ''
}
function connectionOf(u: User): string {
  return u.identities?.[0]?.connection ?? ''
}
function ago(iso: string): string {
  return relativeTime(iso, now, locale.value)
}
onModalClosed(load)
</script>

<template>
  <div v-if="tenant">
    <div class="row mb-4">
      <h1 class="m-0">{{ t('users.title') }}</h1>
      <span class="flex-1" />
      <RouterLink class="rounded border border-rule bg-surface px-3.5 py-1.5 font-bold text-text no-underline hover:bg-active" :to="{ name: 'users-import-export', params: { tenant: tenant.name } }">{{ t('users.importExport') }}</RouterLink>
      <RouterLink class="create rounded border border-accent bg-accent px-3.5 py-1.5 font-bold text-accent-text no-underline hover:border-accent-hover hover:bg-accent-hover hover:text-accent-text" :to="{ name: 'user-new', params: { tenant: tenant.name } }">{{ t('users.create') }}</RouterLink>
    </div>

    <form class="row mb-4 items-start" role="search" @submit.prevent="search">
      <div class="flex-1">
        <Field id="users-search" :label="t('users.search')" :hint="t('users.searchHint')" :error="searchError">
          <input id="users-search" v-model="text" type="search" autocomplete="off" spellcheck="false" :aria-invalid="!!searchError" :aria-describedby="'users-search-hint' + (searchError ? ' users-search-error' : '')" />
        </Field>
      </div>
      <Field id="users-connection" :label="t('users.connectionFilter')">
        <select id="users-connection" :value="conn" @change="go({ connection: ($event.target as HTMLSelectElement).value, page: 0 })">
          <option value="">{{ t('users.allConnections') }}</option>
          <option v-for="c in connections" :key="c.id" :value="c.name">{{ c.name }}</option>
        </select>
      </Field>
      <div class="row self-end">
        <Button variant="primary" type="submit">{{ t('users.searchSubmit') }}</Button>
        <SearchHelp />
      </div>
    </form>

    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t('loading') }}</p>
    <div v-else-if="searchError" />
    <div v-else-if="users.length === 0" class="card empty [&_p]:my-1">
      <template v-if="filtered">
        <p>{{ t('users.noMatch') }}</p>
      </template>
      <template v-else>
        <p>{{ t('users.empty') }}</p>
        <p class="muted">{{ t('users.emptyHint') }}</p>
      </template>
    </div>
    <template v-else>
      <table class="data">
        <thead>
          <tr>
            <th scope="col" :aria-sort="dir('email')">
              <button type="button" class="cursor-pointer border-0 bg-transparent p-0 font-sans font-bold text-text" :aria-label="t('users.sortBy', { column: t('users.nameEmail') })" @click="toggle('email')">{{ t('users.nameEmail') }}<span aria-hidden="true">{{ dir('email') === 'ascending' ? ' ▲' : dir('email') === 'descending' ? ' ▼' : '' }}</span></button>
            </th>
            <th scope="col">{{ t('users.connection') }}</th>
            <th scope="col" :aria-sort="dir('logins')">
              <button type="button" class="cursor-pointer border-0 bg-transparent p-0 font-sans font-bold text-text" :aria-label="t('users.sortBy', { column: t('users.logins') })" @click="toggle('logins')">{{ t('users.logins') }}<span aria-hidden="true">{{ dir('logins') === 'ascending' ? ' ▲' : dir('logins') === 'descending' ? ' ▼' : '' }}</span></button>
            </th>
            <th scope="col" :aria-sort="dir('last')">
              <button type="button" class="cursor-pointer border-0 bg-transparent p-0 font-sans font-bold text-text" :aria-label="t('users.sortBy', { column: t('users.lastLogin') })" @click="toggle('last')">{{ t('users.lastLogin') }}<span aria-hidden="true">{{ dir('last') === 'ascending' ? ' ▲' : dir('last') === 'descending' ? ' ▼' : '' }}</span></button>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in users" :key="u.user_id">
            <td>
              <RouterLink :to="{ name: 'user', params: { tenant: tenant.name, id: u.user_id ?? '' } }">{{ label(u) }}</RouterLink>
              <Tag v-if="u.blocked" class="ml-2">{{ t('users.blocked') }}</Tag>
              <br v-if="u.name && u.email" />
              <span v-if="u.name && u.email" class="muted">{{ u.email }}</span>
            </td>
            <td>{{ connectionOf(u) }}</td>
            <td>{{ u.logins_count ?? 0 }}</td>
            <td>
              <time v-if="u.last_login" :datetime="u.last_login" :title="new Date(u.last_login).toLocaleString(locale)">{{ ago(u.last_login) }}</time>
              <span v-else class="muted">{{ t('users.never') }}</span>
            </td>
          </tr>
        </tbody>
      </table>
      <nav class="row mt-3" :aria-label="t('navPages')">
        <span class="muted" aria-live="polite">{{ t('users.range', { from, to, total }) }}</span>
        <span v-if="atDepth && to < total" class="muted">{{ t('users.pageLimit') }}</span>
        <span class="flex-1" />
        <Button :disabled="page === 0" @click="go({ page: page - 1 })">{{ t('users.previous') }}</Button>
        <Button :disabled="to >= total || atDepth" @click="go({ page: page + 1 })">{{ t('users.next') }}</Button>
      </nav>
    </template>
    <RouterView />
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
