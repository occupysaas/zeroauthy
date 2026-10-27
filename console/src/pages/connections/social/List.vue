<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Connection } from '../../../api/client'
import { errorMessage, useServices, useTenant } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import { useRoute } from 'vue-router'
import { isEnterpriseConnection, isSocialConnection } from './social'

const { t } = useI18n()
const { api } = useServices()
const tenant = useTenant()
const route = useRoute()
const enterprise = computed(() => String(route.name).startsWith('enterprise'))
const audience = computed(() => enterprise.value ? 'enterprise' : 'social')
const connections = ref<Connection[]>([])
const loading = ref(true)
const error = ref('')
let seq = 0

async function load() {
  const tn = tenant.value
  if (!tn) return
  const mine = ++seq
  loading.value = true
  error.value = ''
  try {
    const all = await api.allConnections(tn)
    if (mine !== seq) return // a newer tenant or reload answered first
    connections.value = all.filter(enterprise.value ? isEnterpriseConnection : isSocialConnection)
  } catch (e) {
    if (mine === seq) error.value = errorMessage(e)
  } finally {
    if (mine === seq) loading.value = false
  }
}
watch(tenant, load, { immediate: true })
</script>

<template>
  <div v-if="tenant">
    <div class="row mb-4 flex-wrap gap-2">
      <h1 class="m-0">{{ t(`${audience}.title`) }}</h1>
      <span class="flex-1" />
      <RouterLink class="create rounded border border-accent bg-accent px-3.5 py-1.5 font-bold text-accent-text no-underline hover:border-accent-hover hover:bg-accent-hover hover:text-accent-text" :to="{ name: enterprise ? 'enterprise-new' : 'social-new', params: { tenant: tenant.name } }">{{ t(`${audience}.create`) }}</RouterLink>
    </div>
    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t('loading') }}</p>
    <div v-else-if="connections.length === 0" class="card empty [&_p]:my-1">
      <p>{{ t(`${audience}.empty`) }}</p>
      <p class="muted">{{ t(`${audience}.emptyHint`) }}</p>
    </div>
    <div v-else class="overflow-x-auto">
      <table class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('social.name') }}</th>
            <th scope="col">{{ t('social.strategy') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in connections" :key="c.id">
            <td>
              <RouterLink :to="{ name: enterprise ? 'enterprise-connection' : 'social-connection', params: { tenant: tenant.name, id: c.id } }">{{ c.name }}</RouterLink>
            </td>
            <td>{{ t(`social.strategies.${c.strategy}`) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
