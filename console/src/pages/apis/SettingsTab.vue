<script setup lang="ts">
import { reactive, ref, watch } from 'vue'
import { ApiError, type ResourceServer, type ResourceServerUpdate, type SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { t } from '../../strings'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import CopyButton from '../../ui/CopyButton.vue'
import Field from '../../ui/Field.vue'
import { fieldErrors } from '../applications/defaults'

const props = defineProps<{ tenant: SystemTenant; server: ResourceServer }>()
const emit = defineEmits<{ saved: [ResourceServer] }>()
const { api } = useServices()

const MAX_LIFETIME = 2592000
const userPolicies = ['allow_all', 'require_client_grant', 'deny_all']
const clientPolicies = ['require_client_grant', 'deny_all']

const form = reactive({ name: '', lifetime: '', lifetimeWeb: '', offline: false, skipConsent: false, user: 'allow_all', client: 'require_client_grant' })
const errors = reactive<Record<string, string>>({})
const general = ref('')
const status = ref('')
const busy = ref(false)

function reset(s: ResourceServer) {
  form.name = s.name ?? ''
  form.lifetime = String(s.token_lifetime)
  form.lifetimeWeb = String(s.token_lifetime_for_web)
  form.offline = s.allow_offline_access
  form.skipConsent = s.skip_consent_for_verifiable_first_party_clients
  form.user = s.subject_type_authorization.user.policy
  form.client = s.subject_type_authorization.client.policy
}
watch(() => props.server, reset, { immediate: true })

function seconds(text: string): number | null {
  return /^\d+$/.test(text.trim()) && Number(text) >= 1 && Number(text) <= MAX_LIFETIME ? Number(text) : null
}

function validate(): { lifetime: number; web: number } | null {
  for (const k of Object.keys(errors)) delete errors[k]
  const lifetime = seconds(form.lifetime)
  const web = seconds(form.lifetimeWeb)
  if (lifetime === null) errors.lifetime = t.apis.lifetimeInvalid
  if (web === null) errors.lifetimeWeb = t.apis.lifetimeInvalid
  else if (lifetime !== null && web > lifetime) errors.lifetimeWeb = t.apis.lifetimeWebTooLong
  if (!props.server.is_system && props.server.name && !form.name.trim()) errors.name = t.apis.nameRequired
  return Object.keys(errors).length === 0 ? { lifetime: lifetime!, web: web! } : null
}

const fieldKeys = { name: ['name'], lifetimeWeb: ['token_lifetime_for_web'], lifetime: ['token_lifetime'] }

async function save() {
  general.value = ''
  status.value = ''
  const ok = validate()
  if (!ok) return
  busy.value = true
  // A system API takes only its token lifetimes; the server refuses the rest.
  const body: ResourceServerUpdate = { token_lifetime: ok.lifetime, token_lifetime_for_web: ok.web }
  if (!props.server.is_system) {
    if (form.name.trim()) body.name = form.name.trim()
    body.allow_offline_access = form.offline
    body.skip_consent_for_verifiable_first_party_clients = form.skipConsent
    body.subject_type_authorization = { user: { policy: form.user as 'allow_all' }, client: { policy: form.client as 'deny_all' } }
  }
  try {
    const s = await api.updateResourceServer(props.tenant, props.server.id, body)
    status.value = t.saved
    emit('saved', s)
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

function describedBy(id: string, key: string): string {
  return [id + '-hint', errors[key] ? id + '-error' : ''].join(' ')
}
</script>

<template>
  <div class="stack">
    <Banner v-if="server.is_system" kind="info">{{ t.apis.systemNote }}</Banner>
    <section class="card stack" :aria-label="t.apis.identifier">
      <div>
        <span class="label">{{ t.apis.identifier }}</span>
        <div class="row">
          <code data-testid="identifier">{{ server.identifier }}</code>
          <CopyButton :value="server.identifier" :label="t.apis.identifier" />
        </div>
        <p class="muted hint">{{ t.apis.identifierHint }}</p>
      </div>
      <div>
        <span class="label">{{ t.apis.signingAlg }}</span>
        <div><code>{{ server.signing_alg }}</code></div>
      </div>
    </section>

    <form class="card stack" novalidate @submit.prevent="save">
      <Banner v-if="general" kind="error">{{ general }}</Banner>
      <Field id="api-name" :label="t.apis.name" :error="errors.name">
        <input id="api-name" v-model="form.name" type="text" maxlength="200" :disabled="server.is_system" :aria-invalid="!!errors.name" />
      </Field>
      <Field id="api-lifetime" :label="t.apis.tokenLifetime" :hint="t.apis.tokenLifetimeHint" :error="errors.lifetime">
        <input id="api-lifetime" v-model="form.lifetime" type="text" inputmode="numeric" :aria-invalid="!!errors.lifetime" :aria-describedby="describedBy('api-lifetime', 'lifetime')" />
      </Field>
      <Field id="api-lifetime-web" :label="t.apis.tokenLifetimeWeb" :hint="t.apis.tokenLifetimeWebHint" :error="errors.lifetimeWeb">
        <input
          id="api-lifetime-web"
          v-model="form.lifetimeWeb"
          type="text"
          inputmode="numeric"
          :aria-invalid="!!errors.lifetimeWeb"
          :aria-describedby="describedBy('api-lifetime-web', 'lifetimeWeb')"
        />
      </Field>
      <label class="check">
        <input v-model="form.offline" type="checkbox" :disabled="server.is_system" />
        <span>
          <strong>{{ t.apis.allowOffline }}</strong>
          <span class="muted">{{ t.apis.allowOfflineHint }}</span>
        </span>
      </label>
      <label class="check">
        <input v-model="form.skipConsent" type="checkbox" :disabled="server.is_system" />
        <span>
          <strong>{{ t.apis.skipConsent }}</strong>
          <span class="muted">{{ t.apis.skipConsentHint }}</span>
        </span>
      </label>
      <Field id="api-user-policy" :label="t.apis.userPolicy">
        <select id="api-user-policy" v-model="form.user" :disabled="server.is_system">
          <option v-for="p in userPolicies" :key="p" :value="p">{{ t.apis.policies[p] }}</option>
        </select>
      </Field>
      <Field id="api-client-policy" :label="t.apis.clientPolicy">
        <select id="api-client-policy" v-model="form.client" :disabled="server.is_system">
          <option v-for="p in clientPolicies" :key="p" :value="p">{{ t.apis.policies[p] }}</option>
        </select>
      </Field>
      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy">{{ busy ? t.saving : t.save }}</Button>
        <span class="muted" role="status">{{ status }}</span>
      </div>
    </form>
  </div>
</template>

<style scoped>
.label {
  font-weight: 600;
}
.hint {
  margin: 0.25rem 0 0;
}
.check {
  display: flex;
  gap: 0.6rem;
  align-items: flex-start;
}
.check span {
  display: grid;
}
.check input {
  margin-top: 0.3rem;
}
</style>
