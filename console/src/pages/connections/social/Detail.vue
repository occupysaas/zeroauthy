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
import EnterpriseSettings from '../enterprise/Settings.vue'
import Mapping from '../enterprise/Mapping.vue'
import Keys from '../enterprise/Keys.vue'
import Provisioning from '../enterprise/Provisioning.vue'
import { scimStrategies } from '../../../api/directory'
import LoginExperience from '../enterprise/LoginExperience.vue'
import SamlSettings from '../enterprise/SamlSettings.vue'
import AdfsSettings from '../enterprise/AdfsSettings.vue'
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
const oidc = computed(() => ['oidc','okta'].includes(connection.value?.strategy ?? ''))
const scimConnection = computed(() => scimStrategies.includes(connection.value?.strategy ?? ''))
const enterpriseConnection = computed(() => ['oidc','okta','waad','samlp','adfs'].includes(connection.value?.strategy ?? ''))
const saml = computed(() => connection.value?.strategy === 'samlp')
const adfs = computed(() => connection.value?.strategy === 'adfs')
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
          <TabsTrigger v-if="oidc" class="tab" value="mapping">Mapping</TabsTrigger><TabsTrigger v-if="oidc" class="tab" value="keys">Keys</TabsTrigger><TabsTrigger v-if="enterpriseConnection" class="tab" value="experience">Login experience</TabsTrigger><TabsTrigger v-if="scimConnection" class="tab" value="provisioning">{{ t('scim.tab') }}</TabsTrigger>
          <TabsTrigger class="tab" value="clients">{{ t('social.applications') }}</TabsTrigger>
          <TabsTrigger class="tab" value="danger">{{ t('social.danger') }}</TabsTrigger>
        </TabsList>
        <TabsContent value="settings">
          <SamlSettings v-if="saml" :tenant="tenant" :connection="connection" @saved="connection = $event" /><AdfsSettings v-else-if="adfs" :tenant="tenant" :connection="connection" @saved="connection = $event" /><EnterpriseSettings v-else-if="oidc" :tenant="tenant" :connection="connection" @saved="connection = $event" /><Settings v-else :tenant="tenant" :connection="connection" @saved="connection = $event" />
        </TabsContent>
        <TabsContent v-if="oidc" value="mapping"><Mapping :tenant="tenant" :connection="connection" @saved="connection = $event" /></TabsContent><TabsContent v-if="oidc" value="keys"><Keys :tenant="tenant" :connection="connection" /></TabsContent><TabsContent v-if="enterpriseConnection" value="experience"><LoginExperience :tenant="tenant" :connection="connection" @saved="connection = $event" /></TabsContent><TabsContent v-if="scimConnection" value="provisioning"><Provisioning :tenant="tenant" :connection="connection" /></TabsContent>
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
