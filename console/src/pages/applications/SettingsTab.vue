<script setup lang="ts">
import { reactive, ref, watch } from 'vue'
import { ApiError, type Client, type ClientUpdate, type SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { t } from '../../strings'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import CopyButton from '../../ui/CopyButton.vue'
import Field from '../../ui/Field.vue'
import { fieldErrors, lines } from './defaults'
import SecretField from './SecretField.vue'

const props = defineProps<{ tenant: SystemTenant; client: Client }>()
const emit = defineEmits<{ saved: [Client] }>()
const { api } = useServices()

const form = reactive({ name: '', callbacks: '', logout: '', webOrigins: '', allowedOrigins: '' })
const errors = reactive<Record<string, string>>({})
const general = ref('')
const status = ref('')
const busy = ref(false)

function reset(c: Client) {
  form.name = c.name
  form.callbacks = c.callbacks.join('\n')
  form.logout = c.allowed_logout_urls.join('\n')
  form.webOrigins = c.web_origins.join('\n')
  form.allowedOrigins = c.allowed_origins.join('\n')
}
watch(() => props.client, reset, { immediate: true })

// Which message parts belong to which field.
const fieldKeys = {
  name: ['name'],
  callbacks: ['callback'],
  logout: ['allowed_logout_urls'],
  webOrigins: ['web_origins'],
  allowedOrigins: ['allowed_origins'],
}

async function save() {
  busy.value = true
  general.value = ''
  status.value = ''
  for (const k of Object.keys(errors)) delete errors[k]
  const body: ClientUpdate = {
    name: form.name.trim(),
    callbacks: lines(form.callbacks),
    allowed_logout_urls: lines(form.logout),
    web_origins: lines(form.webOrigins),
    allowed_origins: lines(form.allowedOrigins),
  }
  try {
    const c = await api.updateClient(props.tenant, props.client.client_id, body)
    status.value = t.saved
    emit('saved', c)
  } catch (e) {
    if (e instanceof ApiError && e.errorCode === 'invalid_body') {
      const split = fieldErrors(e.message, fieldKeys)
      Object.assign(errors, split.byField)
      general.value = split.general
    } else {
      general.value = errorMessage(e)
    }
  } finally {
    busy.value = false
  }
}

function describedBy(id: string, hint: boolean): string {
  return [hint ? id + '-hint' : '', errors[id.replace('app-', '')] ? id + '-error' : ''].filter(Boolean).join(' ')
}
</script>

<template>
  <div class="stack">
    <section class="card stack" :aria-label="t.apps.clientID">
      <div>
        <span class="label">{{ t.apps.domain }}</span>
        <div class="row">
          <code>{{ tenant.host }}</code>
          <CopyButton :value="tenant.host" :label="t.apps.domain" />
        </div>
      </div>
      <div>
        <span class="label">{{ t.apps.clientID }}</span>
        <div class="row">
          <code data-testid="client-id">{{ client.client_id }}</code>
          <CopyButton :value="client.client_id" :label="t.apps.clientID" />
        </div>
      </div>
      <SecretField :client="client" />
    </section>

    <form class="card stack" novalidate @submit.prevent="save">
      <Banner v-if="general" kind="error">{{ general }}</Banner>
      <Field id="app-name" :label="t.apps.name" :error="errors.name">
        <input id="app-name" v-model="form.name" type="text" maxlength="255" :aria-invalid="!!errors.name" :aria-describedby="describedBy('app-name', false)" />
      </Field>
      <Field id="app-callbacks" :label="t.apps.callbacks" :hint="t.apps.callbacksHint" :error="errors.callbacks">
        <textarea id="app-callbacks" v-model="form.callbacks" spellcheck="false" :aria-invalid="!!errors.callbacks" :aria-describedby="describedBy('app-callbacks', true)" />
      </Field>
      <Field id="app-logout" :label="t.apps.logoutURLs" :hint="t.apps.logoutURLsHint" :error="errors.logout">
        <textarea id="app-logout" v-model="form.logout" spellcheck="false" :aria-invalid="!!errors.logout" :aria-describedby="describedBy('app-logout', true)" />
      </Field>
      <Field id="app-webOrigins" :label="t.apps.webOrigins" :hint="t.apps.webOriginsHint" :error="errors.webOrigins">
        <textarea id="app-webOrigins" v-model="form.webOrigins" spellcheck="false" :aria-invalid="!!errors.webOrigins" :aria-describedby="describedBy('app-webOrigins', true)" />
      </Field>
      <Field id="app-allowedOrigins" :label="t.apps.allowedOrigins" :hint="t.apps.allowedOriginsHint" :error="errors.allowedOrigins">
        <textarea id="app-allowedOrigins" v-model="form.allowedOrigins" spellcheck="false" :aria-invalid="!!errors.allowedOrigins" :aria-describedby="describedBy('app-allowedOrigins', true)" />
      </Field>
      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy || !form.name.trim()">{{ busy ? t.saving : t.save }}</Button>
        <span class="muted" role="status">{{ status }}</span>
      </div>
    </form>
  </div>
</template>

<style scoped>
.label {
  font-weight: 600;
}
</style>
