<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import type { AppType } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { t } from '../../strings'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { appTypes, defaultsFor } from './defaults'

const { api } = useServices()
const tenant = useTenant()
const router = useRouter()
const name = ref('')
const type = ref<AppType>('spa')
const error = ref('')
const busy = ref(false)

async function submit() {
  const tn = tenant.value
  if (!tn || !name.value.trim()) return
  busy.value = true
  error.value = ''
  try {
    const c = await api.createClient(tn, { name: name.value.trim(), ...defaultsFor(type.value) })
    await router.push({ name: 'application', params: { tenant: tn.name, id: c.client_id } })
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div v-if="tenant">
    <RouterLink :to="{ name: 'applications', params: { tenant: tenant.name } }">← {{ t.apps.back }}</RouterLink>
    <h1>{{ t.apps.createTitle }}</h1>
    <form class="card stack" novalidate @submit.prevent="submit">
      <Banner v-if="error" kind="error">{{ error }}</Banner>
      <Field id="app-name" :label="t.apps.name">
        <input id="app-name" v-model="name" type="text" required maxlength="255" autocomplete="off" />
      </Field>
      <fieldset>
        <legend>{{ t.apps.type }}</legend>
        <label v-for="at in appTypes" :key="at" class="choice">
          <input v-model="type" type="radio" name="app-type" :value="at" :aria-describedby="'help-' + at" />
          <span>
            <strong>{{ t.apps.types[at]!.label }}</strong>
            <span :id="'help-' + at" class="muted">{{ t.apps.types[at]!.help }}</span>
          </span>
        </label>
      </fieldset>
      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy || !name.trim()">{{ busy ? t.creating : t.apps.createSubmit }}</Button>
      </div>
    </form>
  </div>
  <Banner v-else kind="error">{{ t.unknownTenant }}</Banner>
</template>

<style scoped>
fieldset {
  border: 0;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.5rem;
}
legend {
  font-weight: 600;
  margin-bottom: 0.4rem;
}
.choice {
  display: flex;
  gap: 0.6rem;
  align-items: flex-start;
  padding: 0.6rem 0.75rem;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  cursor: pointer;
}
.choice:has(input:checked) {
  border-color: var(--accent);
  background: var(--accent-soft);
}
.choice span {
  display: grid;
}
.choice input {
  margin-top: 0.3rem;
}
</style>
