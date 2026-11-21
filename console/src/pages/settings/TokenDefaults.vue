<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SystemTenant, TenantSettings } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ConfirmDialog from '../../ui/ConfirmDialog.vue'
import QuotaEditor from '../token-settings/QuotaEditor.vue'
import { quotaDraft, quotaValue } from '../token-settings/quota'
import { usePanel } from '../organizations/context'
const props = defineProps<{ tenant: SystemTenant }>()
const { t } = useI18n(), { api } = useServices()
const clearOpen = ref(false)
const clients = ref(quotaDraft()), organizations = ref(quotaDraft()), initialClients = ref(false), initialOrganizations = ref(false)
function apply(settings: TenantSettings) { initialClients.value = !!settings.default_token_quota?.clients; initialOrganizations.value = !!settings.default_token_quota?.organizations; clients.value = quotaDraft(settings.default_token_quota?.clients); organizations.value = quotaDraft(settings.default_token_quota?.organizations) }
const { loading, busy, error, status, reloadRequired, load, change, capture, current } = usePanel(() => props.tenant.host, () => api.getTenantSettings(props.tenant), apply, () => { clearOpen.value = false; clients.value = quotaDraft(); organizations.value = quotaDraft(); initialClients.value = false; initialOrganizations.value = false })
async function clear() { const mine = capture(), tenant = props.tenant; await change(async () => { const result = await api.updateTenantSettings(tenant, { default_token_quota: null }); if (current(mine)) { apply(result); clearOpen.value = false; status.value = t('saved') } }, () => {}) }
async function save() {
  error.value = ''
  let a, b
  try { a = quotaValue(clients.value); b = quotaValue(organizations.value) } catch (e) { error.value = errorMessage(e); return }
  const mine = capture(), tenant = props.tenant
  if ((!a && initialClients.value) || (!b && initialOrganizations.value)) { error.value = t('rt48.defaultRemoval'); return }
  await change(async () => {
    const result = await api.updateTenantSettings(tenant, { default_token_quota: a || b ? { ...(a ? { clients: { ...a } } : {}), ...(b ? { organizations: { ...b } } : {}) } : null })
    if (current(mine)) { apply(result); status.value = t('saved') }
  }, () => {})
}
</script>
<template>
  <section class="card stack"><h2 class="m-0">{{ t('rt48.defaults') }}</h2><Banner v-if="error" kind="error">{{ error }}</Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <form v-else class="stack" novalidate @submit.prevent="save">
      <fieldset class="stack" :disabled="busy || reloadRequired"><p class="muted m-0">{{ t('rt48.partialQuota') }}</p><QuotaEditor tenant-default id="tenant-client-quota" v-model="clients" :lock-enabled="initialClients" :label="t('rt48.clientDefaults')" /><QuotaEditor tenant-default id="tenant-org-quota" v-model="organizations" :lock-enabled="initialOrganizations" :label="t('rt48.orgDefaults')" /></fieldset>
      <div class="row"><Button type="submit" variant="primary" :disabled="busy || reloadRequired">{{ t('save') }}</Button><Button v-if="reloadRequired" @click="load">{{ t('retry') }}</Button><Button v-if="initialClients || initialOrganizations" variant="danger" :disabled="busy" @click="clearOpen = true">{{ t('rt48.removeDefaults') }}</Button><span role="status">{{ status }}</span></div>
    </form>
    <ConfirmDialog v-model:open="clearOpen" :title="t('rt48.removeDefaults')" :description="t('rt48.removeDefaultsHint')" :confirm-label="t('rt48.removeDefaults')" :busy="busy" :error="error" @confirm="clear" />
  </section>
</template>
