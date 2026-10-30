<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { ApiError } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import RouteModal from '../../ui/RouteModal.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { validName } from './context'
const { t } = useI18n(), { api } = useServices(), tenant = useTenant(), router = useRouter()
const name = ref(''), displayName = ref(''), nameError = ref(''), error = ref(''), busy = ref(false)
let epoch = 0
watch(tenant, () => { ++epoch; name.value = ''; displayName.value = ''; nameError.value = ''; error.value = ''; busy.value = false })
onBeforeUnmount(() => { ++epoch })
async function submit() {
  const tn = tenant.value, mine = epoch
  if (!tn || busy.value) return
  nameError.value = ''; error.value = ''
  if (!validName(name.value)) { nameError.value = t('orgs.invalidName'); return }
  if ([...displayName.value].length > 255) { error.value = t('orgs.invalidDisplayName'); return }
  busy.value = true
  try {
    const org = await api.createOrganization(tn, { name: name.value, ...(displayName.value ? { display_name: displayName.value } : {}) })
    if (mine === epoch) await router.push({ name: 'organization', params: { tenant: tn.name, id: org.id } })
  } catch (e) { if (mine === epoch) { if (e instanceof ApiError && e.status === 409) nameError.value = e.message; else error.value = errorMessage(e) } }
  finally { if (mine === epoch) busy.value = false }
}
</script>
<template>
  <RouteModal v-if="tenant" v-slot="{ close }" :title="t('orgs.create')" back="organizations">
    <form class="stack" novalidate @submit.prevent="submit"><Banner v-if="error" kind="error">{{ error }}</Banner>
      <Field id="organization-name" :label="t('orgs.name')" :error="nameError"><input id="organization-name" v-model="name" maxlength="50" required :aria-invalid="!!nameError" aria-describedby="organization-name-error" /></Field>
      <Field id="organization-display-name" :label="t('orgs.displayName')"><input id="organization-display-name" v-model="displayName" maxlength="255" /></Field>
      <div class="row"><Button type="submit" variant="primary" :disabled="busy">{{ t('orgs.create') }}</Button><Button @click="close">{{ t('cancel') }}</Button></div>
    </form>
  </RouteModal>
</template>
