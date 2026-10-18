<script setup lang="ts">
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ApiError, type Client } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { t } from '../../strings'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ApisTab from './ApisTab.vue'
import AdvancedTab from './AdvancedTab.vue'
import DangerZone from './DangerZone.vue'
import QuickStart from './QuickStart.vue'
import SettingsTab from './SettingsTab.vue'

const { api } = useServices()
const tenant = useTenant()
const route = useRoute()
const client = ref<Client | null>(null)
const error = ref('')
const notFound = ref(false)
const tab = ref('quickstart')

async function load() {
  const tn = tenant.value
  const id = route.params.id
  if (!tn || typeof id !== 'string') return
  error.value = ''
  notFound.value = false
  client.value = null
  try {
    client.value = await api.getClient(tn, id)
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound.value = true
    else error.value = errorMessage(e)
  }
}
watch([tenant, () => route.params.id], load, { immediate: true })

function rotated(c: Client) {
  client.value = c
  tab.value = 'settings'
}
</script>

<template>
  <div v-if="tenant">
    <RouterLink :to="{ name: 'applications', params: { tenant: tenant.name } }">← {{ t.apps.back }}</RouterLink>
    <Banner v-if="notFound" kind="error">{{ t.notFoundBody }}</Banner>
    <Banner v-else-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t.retry }}</Button>
    </Banner>
    <p v-else-if="!client" class="muted" role="status">{{ t.loading }}</p>
    <template v-else>
      <h1>{{ client.name }}</h1>
      <p class="muted">{{ t.apps.types[client.app_type]?.label ?? client.app_type }}</p>
      <TabsRoot v-model="tab">
        <TabsList class="tabs" :aria-label="client.name">
          <TabsTrigger class="tab" value="quickstart">{{ t.quick.tab }}</TabsTrigger>
          <TabsTrigger class="tab" value="settings">{{ t.apps.settings }}</TabsTrigger>
          <TabsTrigger class="tab" value="advanced">{{ t.apps.advanced }}</TabsTrigger>
          <TabsTrigger class="tab" value="apis">{{ t.grants.tab }}</TabsTrigger>
          <TabsTrigger class="tab" value="danger">{{ t.apps.danger }}</TabsTrigger>
        </TabsList>
        <TabsContent value="quickstart">
          <QuickStart :tenant="tenant" :client="client" />
        </TabsContent>
        <TabsContent value="settings">
          <SettingsTab :tenant="tenant" :client="client" @saved="client = $event" />
        </TabsContent>
        <TabsContent value="advanced">
          <AdvancedTab :tenant="tenant" :client="client" @saved="client = $event" />
        </TabsContent>
        <TabsContent value="apis">
          <ApisTab :tenant="tenant" :client="client" />
        </TabsContent>
        <TabsContent value="danger">
          <DangerZone :tenant="tenant" :client="client" @rotated="rotated" />
        </TabsContent>
      </TabsRoot>
    </template>
  </div>
  <Banner v-else kind="error">{{ t.unknownTenant }}</Banner>
</template>

<style scoped>
h1 {
  margin: 0.75rem 0 0;
}
.tabs {
  display: flex;
  gap: 0.25rem;
  border-bottom: 1px solid var(--border);
  margin: 1rem 0;
}
.tab {
  font: inherit;
  background: transparent;
  color: var(--text-2);
  border: 0;
  border-bottom: 2px solid transparent;
  padding: 0.5rem 0.9rem;
  cursor: pointer;
}
.tab[data-state='active'] {
  color: var(--text);
  border-bottom-color: var(--accent);
  font-weight: 600;
}
</style>
