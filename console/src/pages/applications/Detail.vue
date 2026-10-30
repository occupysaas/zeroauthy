<script setup lang="ts">
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ApiError, type Client } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import RouteModal from '../../ui/RouteModal.vue'
import Button from '../../ui/Button.vue'
import ApisTab from './ApisTab.vue'
import ConnectionsTab from './ConnectionsTab.vue'
import AdvancedTab from './AdvancedTab.vue'
import DangerZone from './DangerZone.vue'
import QuickStart from './QuickStart.vue'
import SettingsTab from './SettingsTab.vue'

const { t, te } = useI18n()

// typeLabel names an application type; one this console does not know shows as is.
function typeLabel(type: string): string {
  return te(`apps.types.${type}.label`) ? t(`apps.types.${type}.label`) : type
}

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
  <RouteModal v-if="tenant" :title="client?.name ?? t('apps.title')" back="applications" wide>
    <Banner v-if="notFound" kind="error">{{ t('notFoundBody') }}</Banner>
    <Banner v-else-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="!client" class="muted" role="status">{{ t('loading') }}</p>
    <template v-else>
      <p class="muted">{{ typeLabel(client.app_type) }}</p>
      <TabsRoot v-model="tab">
        <TabsList class="tabs" :aria-label="client.name">
          <TabsTrigger class="tab" value="quickstart">{{ t('quick.tab') }}</TabsTrigger>
          <TabsTrigger class="tab" value="settings">{{ t('apps.settings') }}</TabsTrigger>
          <TabsTrigger class="tab" value="advanced">{{ t('apps.advanced') }}</TabsTrigger>
          <TabsTrigger class="tab" value="apis">{{ t('grants.tab') }}</TabsTrigger>
          <TabsTrigger class="tab" value="connections">{{ t('appConns.tab') }}</TabsTrigger>
          <TabsTrigger class="tab" value="danger">{{ t('apps.danger') }}</TabsTrigger>
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
        <TabsContent value="connections">
          <ConnectionsTab :tenant="tenant" :client="client" />
        </TabsContent>
        <TabsContent value="danger">
          <DangerZone :tenant="tenant" :client="client" @rotated="rotated" />
        </TabsContent>
      </TabsRoot>
    </template>
  </RouteModal>
</template>
