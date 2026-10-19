<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { ResourceServer } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'

const { t } = useI18n()

const PER_PAGE = 20

const { api } = useServices()
const tenant = useTenant()
const route = useRoute()
const router = useRouter()

const page = computed(() => Math.max(0, Number(route.query.page ?? 0) || 0))
const servers = ref<ResourceServer[]>([])
const total = ref(0)
const loading = ref(true)
const error = ref('')

async function load() {
  const tn = tenant.value
  if (!tn) return
  loading.value = true
  error.value = ''
  try {
    const res = await api.listResourceServers(tn, { page: page.value, per_page: PER_PAGE })
    servers.value = res.resource_servers
    total.value = res.total
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}
watch([tenant, page], load, { immediate: true })

function goto(p: number) {
  void router.push({ query: p ? { page: String(p) } : {} })
}
const from = computed(() => (total.value === 0 ? 0 : page.value * PER_PAGE + 1))
const to = computed(() => Math.min(total.value, (page.value + 1) * PER_PAGE))
</script>

<template>
  <div v-if="tenant">
    <div class="row head">
      <h1>{{ t('apis.title') }}</h1>
      <span class="spacer" />
      <RouterLink class="create" :to="{ name: 'api-new', params: { tenant: tenant.name } }">{{ t('apis.create') }}</RouterLink>
    </div>

    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t('loading') }}</p>
    <div v-else-if="servers.length === 0" class="card empty">
      <p>{{ t('apis.empty') }}</p>
      <p class="muted">{{ t('apis.emptyHint') }}</p>
    </div>
    <template v-else>
      <table class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('apis.name') }}</th>
            <th scope="col">{{ t('apis.identifier') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in servers" :key="s.id">
            <td>
              <RouterLink :to="{ name: 'api', params: { tenant: tenant.name, id: s.id } }">{{ s.name || t('apis.unnamed') }}</RouterLink>
              <span v-if="s.is_system" class="badge" data-testid="system-badge">{{ t('apis.system') }}</span>
            </td>
            <td><code>{{ s.identifier }}</code></td>
          </tr>
        </tbody>
      </table>
      <nav class="row pager" aria-label="Pages">
        <span class="muted" aria-live="polite">{{ t('apis.range', { from, to, total }) }}</span>
        <span class="spacer" />
        <Button :disabled="page === 0" @click="goto(page - 1)">{{ t('apis.previous') }}</Button>
        <Button :disabled="to >= total" @click="goto(page + 1)">{{ t('apis.next') }}</Button>
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
.empty p {
  margin: 0.25rem 0;
}
.pager {
  margin-top: 0.75rem;
}
.badge {
  margin-left: 0.5rem;
  font-size: 0.75rem;
  font-weight: 600;
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 0.1rem 0.5rem;
  color: var(--text-2);
}
</style>
