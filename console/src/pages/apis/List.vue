<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { ResourceServer } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Tag from '../../ui/Tag.vue'

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
    <div class="row mb-4">
      <h1 class="m-0">{{ t('apis.title') }}</h1>
      <span class="flex-1" />
      <RouterLink class="create rounded border border-accent bg-accent px-3.5 py-1.5 font-bold text-accent-text no-underline hover:border-accent-hover hover:bg-accent-hover hover:text-accent-text" :to="{ name: 'api-new', params: { tenant: tenant.name } }">{{ t('apis.create') }}</RouterLink>
    </div>

    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t('loading') }}</p>
    <div v-else-if="servers.length === 0" class="card empty [&_p]:my-1">
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
              <Tag v-if="s.is_system" class="ml-2" data-testid="system-badge">{{ t('apis.system') }}</Tag>
            </td>
            <td><code>{{ s.identifier }}</code></td>
          </tr>
        </tbody>
      </table>
      <nav class="row mt-3" :aria-label="t('navPages')">
        <span class="muted" aria-live="polite">{{ t('apis.range', { from, to, total }) }}</span>
        <span class="flex-1" />
        <Button :disabled="page === 0" @click="goto(page - 1)">{{ t('apis.previous') }}</Button>
        <Button :disabled="to >= total" @click="goto(page + 1)">{{ t('apis.next') }}</Button>
      </nav>
    </template>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
