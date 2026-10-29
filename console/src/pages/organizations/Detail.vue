<script setup lang="ts">
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, type Organization } from '../../api/client'
import { useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ConfirmDialog from '../users/ConfirmDialog.vue'
import SettingsTab from './SettingsTab.vue'
import BrandingTab from './BrandingTab.vue'
import ConnectionsTab from './ConnectionsTab.vue'
import MembersTab from './MembersTab.vue'
import { usePanel } from './context'
const { t } = useI18n(), { api } = useServices(), tenant = useTenant(), route = useRoute(), router = useRouter()
const tabs = [{ key: 'settings', label: 'orgs.settings' }, { key: 'branding', label: 'orgs.branding' }, { key: 'connections', label: 'orgs.connections' }, { key: 'members', label: 'orgs.members' }]
const organization = ref<Organization>(), tab = ref('settings'), deleteOpen = ref(false), notFound = ref(false)
const { error, busy, reloadRequired, load, change } = usePanel(() => [tenant.value?.host, route.params.id], async () => {
  if (!tenant.value || typeof route.params.id !== 'string') return
  try { return await api.getOrganization(tenant.value, route.params.id) }
  catch (e) { if (e instanceof ApiError && e.status === 404) return; throw e }
}, value => { organization.value = value; notFound.value = !value; if (!value) deleteOpen.value = false }, () => { organization.value = undefined; tab.value = 'settings'; deleteOpen.value = false; notFound.value = false })
async function remove() {
  const tn = tenant.value, id = organization.value?.id
  if (!tn || !id) return
  await change(() => api.deleteOrganization(tn, id), async () => { await router.push({ name: 'organizations', params: { tenant: tn.name } }) })
}
</script>
<template>
  <div v-if="tenant" class="stack"><RouterLink :to="{ name: 'organizations', params: { tenant: tenant.name } }">← {{ t('orgs.back') }}</RouterLink>
    <Banner v-if="notFound" kind="error">{{ t('notFoundBody') }}</Banner><Banner v-else-if="error" kind="error">{{ error }} <Button :disabled="busy" @click="load">{{ t('retry') }}</Button></Banner>
    <p v-else-if="!organization" role="status">{{ t('loading') }}</p>
    <template v-if="organization"><h1>{{ organization.display_name }}</h1><code>{{ organization.id }}</code>
      <TabsRoot v-model="tab"><TabsList class="tabs" :aria-label="organization.display_name"><TabsTrigger v-for="item in tabs" :key="item.key" class="tab" :value="item.key">{{ t(item.label) }}</TabsTrigger></TabsList>
        <TabsContent value="settings"><SettingsTab :tenant="tenant" :organization-id="organization.id" @saved="organization = $event" /><section class="card mt-4"><Button variant="danger" :disabled="busy || reloadRequired" @click="deleteOpen = true">{{ t('orgs.delete') }}</Button></section></TabsContent>
        <TabsContent value="branding"><BrandingTab :tenant="tenant" :organization-id="organization.id" @saved="organization = $event" /></TabsContent>
        <TabsContent value="connections"><ConnectionsTab :tenant="tenant" :organization-id="organization.id" /></TabsContent>
        <TabsContent value="members"><MembersTab :tenant="tenant" :organization-id="organization.id" /></TabsContent>
      </TabsRoot>
    </template>
    <ConfirmDialog v-model:open="deleteOpen" :title="t('orgs.deleteTitle')" :description="t('orgs.deleteHint')" :confirm-label="t('orgs.delete')" :busy="busy" :disabled="reloadRequired" :error="error" @confirm="remove" />
  </div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
