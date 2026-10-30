<script setup lang="ts">
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ApiError, type ResourceServer } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import RouteModal from '../../ui/RouteModal.vue'
import Button from '../../ui/Button.vue'
import ClientsTab from './ClientsTab.vue'
import DangerZone from './DangerZone.vue'
import PermissionsTab from './PermissionsTab.vue'
import SettingsTab from './SettingsTab.vue'
import Tag from '../../ui/Tag.vue'

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
  <RouteModal v-if="tenant" :title="server ? server.name || t('apis.unnamed') : t('apis.title')" back="apis" wide>
    <Banner v-if="notFound" kind="error">{{ t('notFoundBody') }}</Banner>
    <Banner v-else-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="!server" class="muted" role="status">{{ t('loading') }}</p>
    <template v-else>
      <p class="muted">
        <code>{{ server.identifier }}</code>
        <Tag v-if="server.is_system" class="ml-2 align-middle" data-testid="system-badge">{{ t('apis.system') }}</Tag>
      </p>
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
  </RouteModal>
</template>
