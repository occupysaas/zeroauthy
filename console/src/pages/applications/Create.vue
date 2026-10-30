<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import type { AppType } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import RouteModal from '../../ui/RouteModal.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { appTypes, defaultsFor } from './defaults'

const { t } = useI18n()

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
  <RouteModal v-if="tenant" v-slot="{ close }" :title="t('apps.createTitle')" back="applications">
    <form class="stack" novalidate @submit.prevent="submit">
      <Banner v-if="error" kind="error">{{ error }}</Banner>
      <Field id="app-name" :label="t('apps.name')">
        <input id="app-name" v-model="name" type="text" required maxlength="255" autocomplete="off" />
      </Field>
      <fieldset class="m-0 grid gap-2 border-0 p-0">
        <legend class="mb-1.5 font-bold">{{ t('apps.type') }}</legend>
        <label v-for="at in appTypes" :key="at" class="flex cursor-pointer items-start gap-2.5 rounded border border-hair px-3 py-2.5 has-[:checked]:border-accent has-[:checked]:bg-active [&_input]:mt-1.5 [&_span]:grid">
          <input v-model="type" type="radio" name="app-type" :value="at" :aria-describedby="'help-' + at" />
          <span>
            <strong>{{ t(`apps.types.${at}.label`) }}</strong>
            <span :id="'help-' + at" class="muted">{{ t(`apps.types.${at}.help`) }}</span>
          </span>
        </label>
      </fieldset>
      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy || !name.trim()">{{ busy ? t('creating') : t('apps.createSubmit') }}</Button>
        <Button @click="close">{{ t('cancel') }}</Button>
      </div>
    </form>
  </RouteModal>
</template>
