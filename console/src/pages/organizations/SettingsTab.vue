<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type Organization, type SystemTenant } from '../../api/client'
import { useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { metadataValue, usePanel, validName } from './context'
const props = defineProps<{ tenant: SystemTenant; organizationId: string }>(), emit = defineEmits<{ saved: [Organization] }>()
const { t } = useI18n(), { api } = useServices()
const name = ref(''), displayName = ref(''), metadata = ref('{}'), access = ref('block'), nameError = ref('')
function apply(org: Organization) { name.value = org.name; displayName.value = org.display_name; metadata.value = JSON.stringify(org.metadata ?? {}, null, 2); access.value = org.third_party_client_access }
const { loading, error, busy, status, reloadRequired, load, change, capture, current } = usePanel(() => [props.tenant.host, props.organizationId], () => api.getOrganization(props.tenant, props.organizationId), apply, () => { name.value = ''; displayName.value = ''; metadata.value = '{}'; access.value = 'block'; nameError.value = '' })
async function save() {
  error.value = ''; nameError.value = ''
  if (!validName(name.value)) { nameError.value = t('orgs.invalidName'); return }
  if ([...displayName.value].length < 1 || [...displayName.value].length > 255) { error.value = t('orgs.invalidDisplayName'); return }
  const value = metadataValue(metadata.value), mine = capture()
  if (!value) { error.value = t('orgs.invalidMetadata'); return }
  await change(async () => {
    try {
      const result = await api.updateOrganization(props.tenant, props.organizationId, { name: name.value, display_name: displayName.value, metadata: value, third_party_client_access: access.value })
      if (current(mine)) { apply(result); emit('saved', result); status.value = t('saved') }
    } catch (e) {
      if (current(mine) && e instanceof ApiError && e.status === 409) { nameError.value = e.message; return }
      throw e
    }
  }, () => {})
}
</script>
<template>
  <div class="stack"><Banner v-if="error" kind="error">{{ error }}</Banner>
    <Banner v-if="reloadRequired" kind="error">{{ t('orgs.uncertain') }} <Button :disabled="busy" @click="load">{{ t('orgs.reload') }}</Button></Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <form v-else class="card stack" novalidate @submit.prevent="save">
      <Field id="organization-name" :label="t('orgs.name')" :error="nameError"><input id="organization-name" v-model="name" required maxlength="50" :aria-invalid="!!nameError" aria-describedby="organization-name-error" /></Field>
      <Field id="organization-display-name" :label="t('orgs.displayName')"><input id="organization-display-name" v-model="displayName" required maxlength="255" /></Field>
      <Field id="organization-metadata" :label="t('orgs.metadata')" :hint="t('orgs.metadataHint')"><textarea id="organization-metadata" v-model="metadata" spellcheck="false" aria-describedby="organization-metadata-hint" /></Field>
      <Field id="organization-third-party" :label="t('orgs.thirdParty')"><select id="organization-third-party" v-model="access"><option value="block">{{ t('orgs.block') }}</option><option value="allow">{{ t('orgs.allow') }}</option></select></Field>
      <div class="row"><Button type="submit" variant="primary" :disabled="busy || reloadRequired">{{ t('save') }}</Button><span role="status">{{ status }}</span></div>
    </form>
  </div>
</template>
