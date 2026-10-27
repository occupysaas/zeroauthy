<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { Connection } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import { connectionRoute } from './social/social'

const { t, te } = useI18n()

// strategyLabel names a connection strategy; one this console does not know shows as is.
function strategyLabel(strategy: string | undefined): string {
  const s = strategy ?? ''
  return te(`social.strategies.${s}`) ? t(`social.strategies.${s}`) : te(`conns.strategies.${s}`) ? t(`conns.strategies.${s}`) : s
}

const PER_PAGE = 20

const { api } = useServices()
const tenant = useTenant()
const route = useRoute()
const router = useRouter()

const page = computed(() => Math.max(0, Number(route.query.page ?? 0) || 0))
const connections = ref<Connection[]>([])
const total = ref(0)
const loading = ref(true)
const error = ref('')
// The list does not carry the enabled applications; each row asks for its
// own count. A number, or '…' while waiting, or '—' when it failed.
const counts = reactive<Record<string, number | string>>({})

async function load() {
  const tn = tenant.value
  if (!tn) return
  loading.value = true
  error.value = ''
  try {
    const res = await api.listConnections(tn, { page: page.value, per_page: PER_PAGE })
    connections.value = res.connections
    total.value = res.total
    for (const c of res.connections) {
      counts[c.id] = '…'
      api.allConnectionClients(tn, c.id).then(
        (ids) => (counts[c.id] = ids.length),
        () => (counts[c.id] = '—'),
      )
    }
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
    <div class="row mb-4">
      <h1 class="m-0">{{ t('conns.title') }}</h1>
      <span class="flex-1" />
      <RouterLink class="create rounded border border-accent bg-accent px-3.5 py-1.5 font-bold text-accent-text no-underline hover:border-accent-hover hover:bg-accent-hover hover:text-accent-text" :to="{ name: 'connection-new', params: { tenant: tenant.name } }">{{ t('conns.create') }}</RouterLink>
    </div>

    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t('loading') }}</p>
    <div v-else-if="connections.length === 0" class="card empty [&_p]:my-1">
      <p>{{ t('conns.empty') }}</p>
      <p class="muted">{{ t('conns.emptyHint') }}</p>
    </div>
    <template v-else>
      <table class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('conns.name') }}</th>
            <th scope="col">{{ t('conns.strategy') }}</th>
            <th scope="col">{{ t('conns.enabledApps') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in connections" :key="c.id">
            <td>
              <RouterLink :to="{ name: connectionRoute(c), params: { tenant: tenant.name, id: c.id } }">{{ c.name }}</RouterLink>
            </td>
            <td>{{ strategyLabel(c.strategy) }}</td>
            <td :data-testid="'count-' + c.id">{{ counts[c.id] ?? '…' }}</td>
          </tr>
        </tbody>
      </table>
      <nav class="row mt-3" :aria-label="t('navPages')">
        <span class="muted" aria-live="polite">{{ t('conns.range', { from, to, total }) }}</span>
        <span class="flex-1" />
        <Button :disabled="page === 0" @click="goto(page - 1)">{{ t('conns.previous') }}</Button>
        <Button :disabled="to >= total" @click="goto(page + 1)">{{ t('conns.next') }}</Button>
      </nav>
    </template>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
