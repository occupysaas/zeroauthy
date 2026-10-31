<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { errorMessage } from '../context'
import type { LogStat } from '../api/client'
import { unavailable, useMonitoringContext } from './logs/shared'
import DailyActivity from './logs/DailyActivity.vue'
import { useI18n } from 'vue-i18n'
import { homeLinks } from '../links'
import Banner from '../ui/Banner.vue'
import CopyButton from '../ui/CopyButton.vue'

const { t } = useI18n()

const { api, tenant, key, capture, current } = useMonitoringContext()
const stats = ref<LogStat[]>([]), active = ref<number>(), statsError = ref(''), activeError = ref(''), missing = ref(false)
const count = ref<number | null>(null)
const countError = ref('')

const discovery = computed(() => (tenant.value ? 'https://' + tenant.value.host + '/.well-known/openid-configuration' : ''))

watch(key, async () => {
  const c = capture()
  count.value = null; countError.value = ''; stats.value = []; active.value = undefined; statsError.value = ''; activeError.value = ''; missing.value = false
  if (!c) return
  const to = new Date(); const from = new Date(Date.UTC(to.getUTCFullYear(), to.getUTCMonth(), to.getUTCDate() - 29))
  const date = (d: Date) => d.toISOString().slice(0, 10).replaceAll('-', '')
  await Promise.allSettled([
    (async () => { try { const r = await api.listClients(c.tenant, { page: 0, per_page: 1 }); if(current(c)) count.value = r.total } catch(e) { if(current(c)) countError.value = errorMessage(e) } })(),
    (async () => { try { const r = await api.dailyStats(c.tenant, { from: date(from), to: date(to) }); if(current(c)) stats.value = Array.isArray(r) ? r : [] } catch(e) { if(current(c)) { if(unavailable(e)) missing.value = true; else statsError.value = errorMessage(e) } } })(),
    (async () => { try { const r = await api.activeUsers(c.tenant); if(current(c)) active.value = r } catch(e) { if(current(c)) { if(unavailable(e)) missing.value = true; else activeError.value = errorMessage(e) } } })(),
  ])
}, { immediate: true })
</script>

<template>
  <Banner v-if="!tenant" kind="error">{{ t('unknownTenant') }}</Banner>
  <template v-else>
    <h1>{{ tenant.friendly_name || tenant.name }}</h1>
    <Banner v-if="tenant.seeded" kind="warn">{{ t('seededBanner') }}</Banner>
    <section class="card stack" aria-labelledby="home-tenant">
      <h2 id="home-tenant" class="visually-hidden">{{ t('tenant') }}</h2>
      <dl class="m-0 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 max-md:grid-cols-1">
        <dt class="font-bold text-muted">{{ t('domain') }}</dt>
        <dd class="row m-0">
          <code>{{ tenant.host }}</code>
          <CopyButton :value="tenant.host" :label="t('domain')" />
        </dd>
        <template v-if="tenant.domains.length">
          <dt class="font-bold text-muted">{{ t('domains') }}</dt>
          <dd class="m-0">
            <code v-for="d in tenant.domains" :key="d" class="block">{{ d }}</code>
          </dd>
        </template>
        <dt class="font-bold text-muted">{{ t('discoveryURL') }}</dt>
        <dd class="row m-0">
          <a :href="discovery" target="_blank" rel="noopener noreferrer" class="mono">{{ discovery }}</a>
          <CopyButton :value="discovery" :label="t('discoveryURL')" />
        </dd>
        <dt class="font-bold text-muted">{{ t('managementAPI') }}</dt>
        <dd class="row m-0">
          <code>{{ tenant.management_api_identifier }}</code>
          <CopyButton :value="tenant.management_api_identifier" :label="t('managementAPI')" />
        </dd>
      </dl>
    </section>
    <Banner v-if="missing" kind="warn">{{ t('monitor.unavailable') }}</Banner>
    <Banner v-if="statsError" kind="error">{{ statsError }}</Banner>
    <DailyActivity v-else-if="!missing" :stats="stats" class="mt-4" />
    <section v-if="!missing" class="card stack mt-4"><h2>{{ t('monitor.activeUsers') }}</h2><Banner v-if="activeError" kind="error">{{ activeError }}</Banner><strong v-else data-testid="active-users" class="text-3xl">{{ active ?? '…' }}</strong></section>
    <h2>{{ t('applicationCount') }}</h2>
    <p v-if="countError" class="muted" role="alert">{{ countError }}</p>
    <p v-else>
      <RouterLink :to="{ name: 'applications', params: { tenant: tenant.name } }">
        <i18n-t keypath="appCount" scope="global" tag="span">
          <template #count>
            <strong data-testid="app-count">{{ count ?? '…' }}</strong>
          </template>
        </i18n-t>
      </RouterLink>
    </p>
    <h2>{{ t('learnMore') }}</h2>
    <ul class="m-0 list-disc pl-6">
      <li v-for="l in homeLinks" :key="l.href">
        <a :href="l.href" target="_blank" rel="noopener noreferrer">{{ t(l.titleKey) }}</a>
      </li>
    </ul>
  </template>
</template>
