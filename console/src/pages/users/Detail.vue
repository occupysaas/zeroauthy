<script setup lang="ts">
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { ApiError, type User, type UserIdentity } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Tag from '../../ui/Tag.vue'
import ActionsMenu from './ActionsMenu.vue'
import AppsTab from './AppsTab.vue'
import DetailsTab from './DetailsTab.vue'
import IdentitiesTab from './IdentitiesTab.vue'
import MetadataTab from './MetadataTab.vue'
import RawTab from './RawTab.vue'
import SessionsTab from './SessionsTab.vue'

const { t } = useI18n()
const { api } = useServices()
const tenant = useTenant()
const route = useRoute()
const user = ref<User | null>(null)
const error = ref('')
const notFound = ref(false)
const tab = ref('details')

// seq keeps an older answer from replacing a newer one.
let seq = 0
async function load() {
  const tn = tenant.value
  const id = route.params.id
  if (!tn || typeof id !== 'string') return
  const mine = ++seq
  error.value = ''
  notFound.value = false
  user.value = null
  try {
    const u = await api.getUser(tn, id)
    if (mine === seq) user.value = u
  } catch (e) {
    if (mine !== seq) return
    if (e instanceof ApiError && e.status === 404) notFound.value = true
    else error.value = errorMessage(e)
  }
}
watch([tenant, () => route.params.id], load, { immediate: true })

function identities(list: UserIdentity[]) {
  if (user.value) user.value = { ...user.value, identities: list }
}
</script>

<template>
  <div v-if="tenant">
    <RouterLink :to="{ name: 'users', params: { tenant: tenant.name } }">← {{ t('users.back') }}</RouterLink>
    <Banner v-if="notFound" kind="error">{{ t('notFoundBody') }}</Banner>
    <Banner v-else-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="!user" class="muted" role="status">{{ t('loading') }}</p>
    <template v-else>
      <h1 class="mt-3 mb-0">
        {{ user.name || user.email || user.user_id }}
        <Tag v-if="user.blocked" class="ml-2">{{ t('users.blocked') }}</Tag>
      </h1>
      <p class="muted">{{ user.user_id }}</p>
      <ActionsMenu :tenant="tenant" :user="user" @updated="user = $event" />
      <TabsRoot v-model="tab" class="mt-4">
        <TabsList class="tabs" :aria-label="user.name || user.email || user.user_id">
          <TabsTrigger class="tab" value="details">{{ t('userd.tabs.details') }}</TabsTrigger>
          <TabsTrigger class="tab" value="metadata">{{ t('userd.tabs.metadata') }}</TabsTrigger>
          <TabsTrigger class="tab" value="identities">{{ t('userd.tabs.identities') }}</TabsTrigger>
          <TabsTrigger class="tab" value="sessions">{{ t('userd.tabs.sessions') }}</TabsTrigger>
          <TabsTrigger class="tab" value="apps">{{ t('userd.tabs.apps') }}</TabsTrigger>
          <TabsTrigger class="tab" value="raw">{{ t('userd.tabs.raw') }}</TabsTrigger>
        </TabsList>
        <TabsContent value="details"><DetailsTab :tenant="tenant" :user="user" @saved="user = $event" /></TabsContent>
        <TabsContent value="metadata"><MetadataTab :tenant="tenant" :user="user" @saved="user = $event" /></TabsContent>
        <TabsContent value="identities"><IdentitiesTab :tenant="tenant" :user="user" @identities="identities" /></TabsContent>
        <TabsContent value="sessions"><SessionsTab :tenant="tenant" :user="user" /></TabsContent>
        <TabsContent value="apps"><AppsTab :tenant="tenant" :user="user" /></TabsContent>
        <TabsContent value="raw"><RawTab :user="user" /></TabsContent>
      </TabsRoot>
    </template>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
