<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
const { t } = useI18n(),
  { api } = useServices(),
  tenant = useTenant(),
  router = useRouter()
const name = ref(''),
  description = ref(''),
  error = ref(''),
  busy = ref(false)
let epoch = 0
watch(tenant, () => {
  ++epoch
  name.value = ''
  description.value = ''
  error.value = ''
  busy.value = false
})
onBeforeUnmount(() => {
  ++epoch
})
async function submit() {
  const tn = tenant.value,
    mine = epoch
  if (!tn || busy.value) return
  if (!name.value.trim()) {
    error.value = t('rbac.roleRequired')
    return
  }
  busy.value = true
  error.value = ''
  try {
    const role = await api.createRole(tn, { name: name.value, description: description.value })
    if (mine === epoch) await router.push({ name: 'role', params: { tenant: tn.name, id: role.id } })
  } catch (e) {
    if (mine === epoch) error.value = errorMessage(e)
  } finally {
    if (mine === epoch) busy.value = false
  }
}
</script>
<template>
  <div v-if="tenant" class="stack">
    <RouterLink :to="{ name: 'roles', params: { tenant: tenant.name } }">← {{ t('rbac.back') }}</RouterLink>
    <h1>{{ t('rbac.create') }}</h1>
    <form class="card stack" @submit.prevent="submit">
      <Banner v-if="error" kind="error">{{ error }}</Banner
      ><Field id="role-name" :label="t('rbac.name')"><input id="role-name" v-model="name" required maxlength="128" /></Field
      ><Field id="role-description" :label="t('rbac.description')">
        <textarea id="role-description" v-model="description" maxlength="255" /></Field
      ><Button variant="primary" type="submit" :disabled="busy">{{ t('rbac.create') }}</Button>
    </form>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
