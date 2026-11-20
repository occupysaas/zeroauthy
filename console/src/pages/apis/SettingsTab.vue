<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { ApiError, type ResourceServer, type ResourceServerUpdate, type SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import CopyButton from '../../ui/CopyButton.vue'
import Field from '../../ui/Field.vue'
import { fieldErrors } from '../applications/defaults'

const { t } = useI18n()

const props = defineProps<{ tenant: SystemTenant; server: ResourceServer }>()
const emit = defineEmits<{ saved: [ResourceServer] }>()
const { api } = useServices()

const MAX_LIFETIME = 2592000
const userPolicies = ['allow_all', 'require_client_grant', 'deny_all']
const clientPolicies = ['require_client_grant', 'deny_all']

const form = reactive({ alg: 'RS256' as 'RS256' | 'HS256' | 'PS256', secret: '', name: '', lifetime: '', lifetimeWeb: '', offline: false, skipConsent: false, user: 'allow_all', client: 'require_client_grant', rbac: false, profile: 'access_token', permissions: false, online: false, ephemeral: false, proof: 'none' as 'none' | 'dpop', proofRequired: false, proofFor: 'all_clients' as 'all_clients' | 'public_clients' })
const errors = reactive<Record<string, string>>({})
const general = ref('')
const status = ref('')
const busy = ref(false)
const secretShown = ref(false)
const algs = ['RS256', 'PS256', 'HS256'] as const
const MIN_SECRET = 16
let epoch = 0
let context = ''
const baseProfile = computed({ get: () => form.profile, set: (value: string) => { form.profile = value } })
onBeforeUnmount(() => { ++epoch })

function reset(s: ResourceServer) {
  ++epoch
  busy.value = false
  const nextContext = props.tenant.host + '/' + s.id
  if (context !== nextContext) status.value = ''
  context = nextContext
  general.value = ''
  form.alg = s.signing_alg
  form.secret = ''
  secretShown.value = false
  form.rbac = s.enforce_policies
  form.profile = String(s.token_dialect).startsWith('rfc9068_') ? 'rfc9068_profile' : 'access_token'
  form.permissions = String(s.token_dialect).endsWith('_authz')
  form.name = s.name ?? ''
  form.lifetime = String(s.token_lifetime)
  form.lifetimeWeb = String(s.token_lifetime_for_web)
  form.offline = s.allow_offline_access
  form.online = s.allow_online_access === true; form.ephemeral = s.allow_online_access_with_ephemeral_sessions === true
  form.proof = s.proof_of_possession?.mechanism === 'dpop' ? 'dpop' : 'none'; form.proofRequired = s.proof_of_possession?.required === true; form.proofFor = s.proof_of_possession?.required_for ?? 'all_clients'
  form.skipConsent = s.skip_consent_for_verifiable_first_party_clients
  form.user = s.subject_type_authorization.user.policy
  form.client = s.subject_type_authorization.client.policy
}
watch(() => [props.tenant.host, props.server] as const, () => reset(props.server), { immediate: true })

function seconds(text: string): number | null {
  return /^\d+$/.test(text.trim()) && Number(text) >= 1 && Number(text) <= MAX_LIFETIME ? Number(text) : null
}

function validate(): { lifetime: number; web: number } | null {
  for (const k of Object.keys(errors)) delete errors[k]
  const lifetime = seconds(form.lifetime)
  const web = seconds(form.lifetimeWeb)
  if (lifetime === null) errors.lifetime = t('apis.lifetimeInvalid')
  if (web === null) errors.lifetimeWeb = t('apis.lifetimeInvalid')
  else if (lifetime !== null && web > lifetime) errors.lifetimeWeb = t('apis.lifetimeWebTooLong')
  if (!props.server.is_system && props.server.name && !form.name.trim()) errors.name = t('apis.nameRequired')
  if (!props.server.is_system && form.alg === 'HS256' && form.secret.trim() && form.secret.trim().length < MIN_SECRET) errors.secret = t('apis.secretTooShort', { min: MIN_SECRET })
  return Object.keys(errors).length === 0 ? { lifetime: lifetime!, web: web! } : null
}

const fieldKeys = { secret: ['signing_secret'], name: ['name'], lifetimeWeb: ['token_lifetime_for_web'], lifetime: ['token_lifetime'] }

async function save() {
  general.value = ''
  status.value = ''
  const ok = validate()
  if (!ok) return
  const mine = epoch
  busy.value = true
  // A system API takes only its token lifetimes; the server refuses the rest.
  const body: ResourceServerUpdate = { token_lifetime: ok.lifetime, token_lifetime_for_web: ok.web }
  if (!props.server.is_system) {
    if (form.name.trim()) body.name = form.name.trim()
    body.enforce_policies = form.rbac
    if (form.alg !== props.server.signing_alg || (form.alg === 'HS256' && form.secret.trim())) body.signing_alg = form.alg
    if (form.alg === 'HS256' && form.secret.trim()) body.signing_secret = form.secret.trim()
    body.token_dialect = (form.profile + (form.permissions ? '_authz' : '')) as ResourceServerUpdate['token_dialect']
    body.allow_offline_access = form.offline
    body.allow_online_access = form.online; body.allow_online_access_with_ephemeral_sessions = form.ephemeral
    body.proof_of_possession = form.proof === 'none' ? null : { mechanism: 'dpop', required: form.proofRequired, required_for: form.proofFor }
    body.skip_consent_for_verifiable_first_party_clients = form.skipConsent
    body.subject_type_authorization = { user: { policy: form.user as 'allow_all' }, client: { policy: form.client as 'deny_all' } }
  }
  try {
    const s = await api.updateResourceServer(props.tenant, props.server.id, body)
    if (mine !== epoch) return
    status.value = t('saved')
    emit('saved', s)
  } catch (e) {
    if (mine !== epoch) return
    if (e instanceof ApiError && e.errorCode === 'invalid_body') {
      const split = fieldErrors(e.message, fieldKeys)
      Object.assign(errors, split.byField)
      general.value = split.general
    } else {
      general.value = errorMessage(e)
    }
  } finally {
    if (mine === epoch) busy.value = false
  }
}

function describedBy(id: string, key: string): string {
  return [id + '-hint', errors[key] ? id + '-error' : ''].join(' ')
}
</script>

<template>
  <div class="stack">
    <Banner v-if="server.is_system" kind="info">{{ t('apis.systemNote') }}</Banner>
    <section class="card stack" :aria-label="t('apis.identifier')">
      <div>
        <span class="font-bold">{{ t('apis.identifier') }}</span>
        <div class="row">
          <code data-testid="identifier">{{ server.identifier }}</code>
          <CopyButton :value="server.identifier" :label="t('apis.identifier')" />
        </div>
        <p class="muted m-0 mt-1">{{ t('apis.identifierHint') }}</p>
      </div>
      <div>
        <span class="font-bold">{{ t('apis.signingAlg') }}</span>
        <div><code>{{ server.signing_alg }}</code></div>
      </div>
      <div v-if="server.signing_alg === 'HS256' && server.signing_secret">
        <span id="api-secret-label" class="font-bold">{{ t('apis.signingSecret') }}</span>
        <div class="row">
          <code aria-labelledby="api-secret-label" data-testid="signing-secret">{{ secretShown ? server.signing_secret : '•'.repeat(24) }}</code>
          <Button variant="ghost" :aria-pressed="secretShown" @click="secretShown = !secretShown">{{ secretShown ? t('apps.hide') : t('apps.reveal') }}</Button>
          <CopyButton :value="server.signing_secret" :label="t('apis.signingSecret')" />
        </div>
      </div>
    </section>

    <form class="card stack" novalidate @submit.prevent="save">
      <Banner v-if="general" kind="error">{{ general }}</Banner>
      <Field id="api-name" :label="t('apis.name')" :error="errors.name">
        <input id="api-name" v-model="form.name" type="text" maxlength="200" :disabled="server.is_system" :aria-invalid="!!errors.name" />
      </Field>
      <Field id="api-alg" :label="t('apis.signingAlg')" :hint="t('apis.signingAlgHint')">
        <select id="api-alg" v-model="form.alg" :disabled="server.is_system" aria-describedby="api-alg-hint">
          <option v-for="a in algs" :key="a" :value="a">{{ a }}</option>
        </select>
      </Field>
      <Field v-if="form.alg === 'HS256' && !server.is_system" id="api-secret" :label="t('apis.newSecret')" :hint="t('apis.newSecretHint', { min: MIN_SECRET })" :error="errors.secret">
        <input id="api-secret" v-model="form.secret" type="password" autocomplete="new-password" spellcheck="false" :aria-invalid="!!errors.secret" :aria-describedby="describedBy('api-secret', 'secret')" />
      </Field>
      <Field id="api-lifetime" :label="t('apis.tokenLifetime')" :hint="t('apis.tokenLifetimeHint')" :error="errors.lifetime">
        <input id="api-lifetime" v-model="form.lifetime" type="text" inputmode="numeric" :aria-invalid="!!errors.lifetime" :aria-describedby="describedBy('api-lifetime', 'lifetime')" />
      </Field>
      <Field id="api-lifetime-web" :label="t('apis.tokenLifetimeWeb')" :hint="t('apis.tokenLifetimeWebHint')" :error="errors.lifetimeWeb">
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
        <input id="api-offline" v-model="form.offline" type="checkbox" :disabled="server.is_system" />
        <span>
          <strong>{{ t('apis.allowOffline') }}</strong>
          <span class="muted">{{ t('apis.allowOfflineHint') }}</span>
        </span>
      </label>
      <fieldset v-if="!server.is_system" class="stack"><legend>{{ t('rt48.refresh') }}</legend>
        <label class="check"><input id="api-online" v-model="form.online" type="checkbox" />{{ t('rt48.online') }}</label>
        <label class="check"><input id="api-online-ephemeral" v-model="form.ephemeral" type="checkbox" />{{ t('rt48.ephemeral') }}</label>
        <p class="muted m-0">{{ t('rt48.onlineHint') }}</p>
      </fieldset>
      <fieldset v-if="!server.is_system" class="stack"><legend>{{ t('rt48.proof') }}</legend>
        <Field id="api-proof-mechanism" :label="t('rt48.mechanism')"><select id="api-proof-mechanism" v-model="form.proof"><option value="none">{{ t('rt48.noProof') }}</option><option value="dpop">{{ t('rt48.dpop') }}</option></select></Field>
        <template v-if="form.proof === 'dpop'"><label class="check"><input id="api-proof-required" v-model="form.proofRequired" type="checkbox" />{{ t('rt48.required') }}</label>
          <Field id="api-proof-for" :label="t('rt48.requiredFor')"><select id="api-proof-for" v-model="form.proofFor" :disabled="!form.proofRequired"><option value="all_clients">{{ t('rt48.allClients') }}</option><option value="public_clients">{{ t('rt48.publicClients') }}</option></select></Field>
        </template>
      </fieldset>
      <label class="check">
        <input id="api-skip-consent" v-model="form.skipConsent" type="checkbox" :disabled="server.is_system" />
        <span>
          <strong>{{ t('apis.skipConsent') }}</strong>
          <span class="muted">{{ t('apis.skipConsentHint') }}</span>
        </span>
      </label>
      <Field id="api-user-policy" :label="t('apis.userPolicy')">
        <select id="api-user-policy" v-model="form.user" :disabled="server.is_system">
          <option v-for="p in userPolicies" :key="p" :value="p">{{ t(`apis.policies.${p}`) }}</option>
        </select>
      </Field>
      <Field id="api-client-policy" :label="t('apis.clientPolicy')">
        <select id="api-client-policy" v-model="form.client" :disabled="server.is_system">
          <option v-for="p in clientPolicies" :key="p" :value="p">{{ t(`apis.policies.${p}`) }}</option>
        </select>
      </Field>
      <fieldset class="stack">
        <legend>{{ t('rbac.title') }}</legend>
        <label class="check"><input id="api-rbac" v-model="form.rbac" type="checkbox" :disabled="server.is_system"/><span>{{t('rbac.enable')}}</span></label>
        <Field id="api-profile" :label="t('rbac.profile')"><select id="api-profile" v-model="baseProfile" :disabled="server.is_system"><option value="access_token">{{t('rbac.auth0')}}</option><option value="rfc9068_profile">{{t('rbac.rfc')}}</option></select></Field>
        <label class="check"><input id="api-permissions-claim" v-model="form.permissions" type="checkbox" :disabled="server.is_system || !form.rbac"/><span>{{t('rbac.include')}}</span></label>
        <p class="muted">{{t('rbac.expiry')}}</p>
      </fieldset>
      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy">{{ busy ? t('saving') : t('save') }}</Button>
        <span class="muted" role="status">{{ status }}</span>
      </div>
    </form>
  </div>
</template>
