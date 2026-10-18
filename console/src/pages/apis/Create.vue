<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ApiError } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { t } from '../../strings'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'

const { api } = useServices()
const tenant = useTenant()
const router = useRouter()
const name = ref('')
const identifier = ref('')
const errors = reactive<Record<string, string>>({})
const general = ref('')
const busy = ref(false)

function validate(): boolean {
  for (const k of Object.keys(errors)) delete errors[k]
  if (!name.value.trim()) errors.name = t.apis.nameRequired
  if (!identifier.value.trim()) errors.identifier = t.apis.identifierRequired
  else if (identifier.value.length > 600) errors.identifier = t.apis.identifierTooLong
  return Object.keys(errors).length === 0
}

async function submit() {
  const tn = tenant.value
  general.value = ''
  if (!tn || !validate()) return
  busy.value = true
  try {
    const s = await api.createResourceServer(tn, { name: name.value.trim(), identifier: identifier.value.trim(), signing_alg: 'RS256' })
    await router.push({ name: 'api', params: { tenant: tn.name, id: s.id } })
  } catch (e) {
    // A duplicate or reserved identifier belongs to that field.
    if (e instanceof ApiError && ['resource_server_conflict', 'reserved_identifier'].includes(e.errorCode)) errors.identifier = e.message
    else general.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div v-if="tenant">
    <RouterLink :to="{ name: 'apis', params: { tenant: tenant.name } }">← {{ t.apis.back }}</RouterLink>
    <h1>{{ t.apis.createTitle }}</h1>
    <form class="card stack" novalidate @submit.prevent="submit">
      <Banner v-if="general" kind="error">{{ general }}</Banner>
      <Field id="api-name" :label="t.apis.name" :hint="t.apis.nameHint" :error="errors.name">
        <input id="api-name" v-model="name" type="text" maxlength="200" autocomplete="off" :aria-invalid="!!errors.name" :aria-describedby="'api-name-hint' + (errors.name ? ' api-name-error' : '')" />
      </Field>
      <Field id="api-identifier" :label="t.apis.identifier" :hint="t.apis.identifierHint" :error="errors.identifier">
        <input
          id="api-identifier"
          v-model="identifier"
          type="text"
          autocomplete="off"
          spellcheck="false"
          :aria-invalid="!!errors.identifier"
          :aria-describedby="'api-identifier-hint' + (errors.identifier ? ' api-identifier-error' : '')"
        />
      </Field>
      <Field id="api-alg" :label="t.apis.signingAlg" :hint="t.apis.signingAlgHint">
        <input id="api-alg" :value="t.apis.signingAlgValue" type="text" readonly aria-describedby="api-alg-hint" />
      </Field>
      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy">{{ busy ? t.creating : t.apis.createSubmit }}</Button>
      </div>
    </form>
  </div>
  <Banner v-else kind="error">{{ t.unknownTenant }}</Banner>
</template>
