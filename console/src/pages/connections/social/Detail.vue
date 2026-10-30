<script setup lang="ts">
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ApiError, type Connection } from '../../../api/client'
import { errorMessage, useServices, useTenant } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import RouteModal from '../../../ui/RouteModal.vue'
import Button from '../../../ui/Button.vue'
import ClientsTab from '../ClientsTab.vue'
import DangerZone from '../DangerZone.vue'
import Settings from './Settings.vue'
import { isFederated } from './social'

const { t } = useI18n()
const { api } = useServices()
const tenant = useTenant()
const route = useRoute()
const audience = computed(() => String(route.name).startsWith('enterprise') ? 'enterprise' : 'social')
const connection = ref<Connection | null>(null)
const error = ref('')
const notFound = ref(false)
const tab = ref('settings')
let seq = 0

// A reload keeps the shown connection (and the editor's draft) when it
// fails; only a different connection or tenant clears it.
async function load() {
  const tn = tenant.value
  const id = route.params.id
  if (!tn || typeof id !== 'string') return
  const mine = ++seq
  error.value = ''
  notFound.value = false
  if (connection.value?.id !== id) connection.value = null
  try {
    const c = await api.getConnection(tn, id)
    if (mine !== seq) return // a newer navigation answered first
    if (!isFederated(c)) notFound.value = true
    else connection.value = c
  } catch (e) {
    if (mine !== seq) return
    if (e instanceof ApiError && e.status === 404) notFound.value = true
    else error.value = errorMessage(e)
  }
}
watch([tenant, () => route.params.id], load, { immediate: true })
</script>

<template>
  <RouteModal v-if="tenant" :title="connection?.name ?? t(`${audience}.title`)" :back="audience" wide>
    <Banner v-if="notFound" kind="error">{{ t('notFoundBody') }}</Banner>
    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-if="!connection && !notFound && !error" class="muted" role="status">{{ t('loading') }}</p>
    <template v-if="connection">
      <p class="muted">
        {{ t(`social.strategies.${connection.strategy}`) }} · <code>{{ connection.id }}</code>
      </p>
      <Banner v-if="tenant.seeded" kind="warn">{{ t('seededBanner') }}</Banner>
      <TabsRoot v-model="tab">
        <TabsList class="tabs flex-wrap" :aria-label="connection.name">
          <TabsTrigger class="tab" value="settings">{{ t('social.settings') }}</TabsTrigger>
          <TabsTrigger class="tab" value="clients">{{ t('social.applications') }}</TabsTrigger>
          <TabsTrigger class="tab" value="danger">{{ t('social.danger') }}</TabsTrigger>
        </TabsList>
        <TabsContent value="settings">
          <Settings :tenant="tenant" :connection="connection" @saved="connection = $event" />
        </TabsContent>
        <TabsContent value="clients">
          <ClientsTab :tenant="tenant" :connection="connection" />
        </TabsContent>
        <TabsContent value="danger">
          <DangerZone :tenant="tenant" :connection="connection" />
        </TabsContent>
      </TabsRoot>
    </template>
  </RouteModal>
</template>
