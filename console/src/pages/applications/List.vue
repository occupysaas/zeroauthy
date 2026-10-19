<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { Client } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import { appTypes } from './defaults'

const { t, te } = useI18n()

// typeLabel names an application type; one this console does not know shows as is.
function typeLabel(type: string): string {
  return te(`apps.types.${type}.label`) ? t(`apps.types.${type}.label`) : type
}

const PER_PAGE = 20

const { api } = useServices()
const tenant = useTenant()
const route = useRoute()
const router = useRouter()

const page = computed(() => Math.max(0, Number(route.query.page ?? 0) || 0))
const type = computed(() => (typeof route.query.type === 'string' ? route.query.type : ''))

const clients = ref<Client[]>([])
const total = ref(0)
const loading = ref(true)
const error = ref('')

async function load() {
  const tn = tenant.value
  if (!tn) return
  loading.value = true
  error.value = ''
  try {
    const res = await api.listClients(tn, { page: page.value, per_page: PER_PAGE, app_type: type.value || undefined })
    clients.value = res.clients
    total.value = res.total
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}

watch([tenant, page, type], load, { immediate: true })

function setQuery(q: { page?: number; type?: string }) {
  const next = { page: q.page ?? page.value, type: q.type ?? type.value }
  void router.push({ query: { ...(next.page ? { page: String(next.page) } : {}), ...(next.type ? { type: next.type } : {}) } })
}

const from = computed(() => (total.value === 0 ? 0 : page.value * PER_PAGE + 1))
const to = computed(() => Math.min(total.value, (page.value + 1) * PER_PAGE))
</script>

<template>
  <div v-if="tenant">
    <div class="row head">
      <h1>{{ t('apps.title') }}</h1>
      <span class="spacer" />
      <RouterLink class="create" :to="{ name: 'application-new', params: { tenant: tenant.name } }">{{ t('apps.create') }}</RouterLink>
    </div>
    <div class="row filters">
      <label for="type-filter">{{ t('apps.filter') }}</label>
      <select id="type-filter" :value="type" @change="setQuery({ page: 0, type: ($event.target as HTMLSelectElement).value })">
        <option value="">{{ t('apps.allTypes') }}</option>
        <option v-for="at in appTypes" :key="at" :value="at">{{ t(`apps.types.${at}.label`) }}</option>
      </select>
    </div>

    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t('loading') }}</p>
    <div v-else-if="clients.length === 0" class="card empty">
      <p>{{ type ? t('apps.emptyFiltered') : t('apps.empty') }}</p>
      <p v-if="!type" class="muted">{{ t('apps.emptyHint') }}</p>
    </div>
    <template v-else>
      <table class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('apps.name') }}</th>
            <th scope="col">{{ t('apps.type') }}</th>
            <th scope="col">{{ t('apps.clientID') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in clients" :key="c.client_id">
            <td>
              <RouterLink :to="{ name: 'application', params: { tenant: tenant.name, id: c.client_id } }">{{ c.name }}</RouterLink>
            </td>
            <td>{{ typeLabel(c.app_type) }}</td>
            <td><code>{{ c.client_id }}</code></td>
          </tr>
        </tbody>
      </table>
      <nav class="row pager" :aria-label="t('navPages')">
        <span class="muted" aria-live="polite">{{ t('apps.range', { from, to, total }) }}</span>
        <span class="spacer" />
        <Button :disabled="page === 0" @click="setQuery({ page: page - 1 })">{{ t('apps.previous') }}</Button>
        <Button :disabled="to >= total" @click="setQuery({ page: page + 1 })">{{ t('apps.next') }}</Button>
      </nav>
    </template>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>

<style scoped>
.head h1 {
  margin: 0;
}
.head {
  margin-bottom: 1rem;
}
.spacer {
  flex: 1;
}
.create {
  background: var(--accent);
  color: var(--accent-text);
  font-weight: 600;
  padding: 0.45rem 0.9rem;
  border-radius: 6px;
  text-decoration: none;
}
.filters {
  margin-bottom: 1rem;
}
.filters select {
  width: auto;
}
.empty p {
  margin: 0.25rem 0;
}
.pager {
  margin-top: 0.75rem;
}
</style>
