<script setup lang="ts">
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ApiError, type ResourceServer } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ClientsTab from './ClientsTab.vue'
import DangerZone from './DangerZone.vue'
import PermissionsTab from './PermissionsTab.vue'
import SettingsTab from './SettingsTab.vue'

const { t } = useI18n()

const { api } = useServices()
const tenant = useTenant()
const route = useRoute()
const server = ref<ResourceServer | null>(null)
const error = ref('')
const notFound = ref(false)
const tab = ref('settings')

async function load() {
  const tn = tenant.value
  const id = route.params.id
  if (!tn || typeof id !== 'string') return
  error.value = ''
  notFound.value = false
  server.value = null
  try {
    server.value = await api.getResourceServer(tn, id)
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound.value = true
    else error.value = errorMessage(e)
  }
}
watch([tenant, () => route.params.id], load, { immediate: true })
</script>

<template>
  <div v-if="tenant">
    <RouterLink :to="{ name: 'apis', params: { tenant: tenant.name } }">← {{ t('apis.back') }}</RouterLink>
    <Banner v-if="notFound" kind="error">{{ t('notFoundBody') }}</Banner>
    <Banner v-else-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="!server" class="muted" role="status">{{ t('loading') }}</p>
    <template v-else>
      <h1>
        {{ server.name || t('apis.unnamed') }}
        <span v-if="server.is_system" class="badge" data-testid="system-badge">{{ t('apis.system') }}</span>
      </h1>
      <p class="muted"><code>{{ server.identifier }}</code></p>
      <TabsRoot v-model="tab">
        <TabsList class="tabs" :aria-label="server.name || server.identifier">
          <TabsTrigger class="tab" value="settings">{{ t('apis.settings') }}</TabsTrigger>
          <TabsTrigger class="tab" value="permissions">{{ t('apis.permissions') }}</TabsTrigger>
          <TabsTrigger class="tab" value="clients">{{ t('apis.machineApps') }}</TabsTrigger>
          <TabsTrigger v-if="!server.is_system" class="tab" value="danger">{{ t('apis.danger') }}</TabsTrigger>
        </TabsList>
        <TabsContent value="settings">
          <SettingsTab :tenant="tenant" :server="server" @saved="server = $event" />
        </TabsContent>
        <TabsContent value="permissions">
          <PermissionsTab :tenant="tenant" :server="server" @saved="server = $event" />
        </TabsContent>
        <TabsContent value="clients">
          <ClientsTab :tenant="tenant" :server="server" />
        </TabsContent>
        <TabsContent v-if="!server.is_system" value="danger">
          <DangerZone :tenant="tenant" :server="server" />
        </TabsContent>
      </TabsRoot>
    </template>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
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
.badge {
  margin-left: 0.5rem;
  font-size: 0.75rem;
  font-weight: 600;
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 0.1rem 0.5rem;
  color: var(--text-2);
  vertical-align: middle;
}
</style>
