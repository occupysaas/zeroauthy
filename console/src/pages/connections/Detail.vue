<script setup lang="ts">
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ApiError, type Connection } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { t } from '../../strings'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ClientsTab from './ClientsTab.vue'
import CustomDbTab from './CustomDbTab.vue'
import DangerZone from './DangerZone.vue'
import PasswordTab from './PasswordTab.vue'
import SettingsTab from './SettingsTab.vue'

const { api } = useServices()
const tenant = useTenant()
const route = useRoute()
// The connection is the body of the last GET or PATCH. Every save builds
// its options from it, so a save from one tab keeps what the others hold.
const connection = ref<Connection | null>(null)
const error = ref('')
const notFound = ref(false)
const tab = ref('settings')

async function load() {
  const tn = tenant.value
  const id = route.params.id
  if (!tn || typeof id !== 'string') return
  error.value = ''
  notFound.value = false
  connection.value = null
  try {
    connection.value = await api.getConnection(tn, id)
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound.value = true
    else error.value = errorMessage(e)
  }
}
watch([tenant, () => route.params.id], load, { immediate: true })
</script>

<template>
  <div v-if="tenant">
    <RouterLink :to="{ name: 'connections', params: { tenant: tenant.name } }">← {{ t.conns.back }}</RouterLink>
    <Banner v-if="notFound" kind="error">{{ t.notFoundBody }}</Banner>
    <Banner v-else-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t.retry }}</Button>
    </Banner>
    <p v-else-if="!connection" class="muted" role="status">{{ t.loading }}</p>
    <template v-else>
      <h1>{{ connection.name }}</h1>
      <p class="muted">
        {{ t.conns.strategies[connection.strategy ?? ''] ?? connection.strategy }} · <code>{{ connection.id }}</code>
      </p>
      <Banner v-if="tenant.seeded" kind="warn">{{ t.seededBanner }}</Banner>
      <TabsRoot v-model="tab">
        <TabsList class="tabs" :aria-label="connection.name">
          <TabsTrigger class="tab" value="settings">{{ t.conns.settings }}</TabsTrigger>
          <TabsTrigger class="tab" value="password">{{ t.conns.password }}</TabsTrigger>
          <TabsTrigger class="tab" value="customdb">{{ t.conns.customDb }}</TabsTrigger>
          <TabsTrigger class="tab" value="clients">{{ t.conns.applications }}</TabsTrigger>
          <TabsTrigger class="tab" value="danger">{{ t.conns.danger }}</TabsTrigger>
        </TabsList>
        <TabsContent value="settings">
          <SettingsTab :tenant="tenant" :connection="connection" @saved="connection = $event" />
        </TabsContent>
        <TabsContent value="password">
          <PasswordTab :tenant="tenant" :connection="connection" @saved="connection = $event" />
        </TabsContent>
        <TabsContent value="customdb">
          <CustomDbTab :tenant="tenant" :connection="connection" @saved="connection = $event" />
        </TabsContent>
        <TabsContent value="clients">
          <ClientsTab :tenant="tenant" :connection="connection" />
        </TabsContent>
        <TabsContent value="danger">
          <DangerZone :tenant="tenant" :connection="connection" />
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
  flex-wrap: wrap;
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
