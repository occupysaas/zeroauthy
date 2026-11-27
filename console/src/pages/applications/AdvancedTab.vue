<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { ApiError, type Client, type ClientCredential, type ClientUpdate, type SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'

const { t, te } = useI18n()

// Catalog keys for the grant types; the URN and URL grants have dotted names.
const GRANT_KEYS: Record<string, string> = {
  'http://auth0.com/oauth/grant-type/password-realm': 'passwordRealm',
  'urn:ietf:params:oauth:grant-type:device_code': 'deviceCode',
  'urn:openid:params:grant-type:ciba': 'ciba',
}
const CIBA = 'urn:openid:params:grant-type:ciba'
// The CIBA channels; only email is delivered (D-0100).
const channelChoices = ['email', 'guardian-push', 'my-account'] as const
type Channel = (typeof channelChoices)[number]
// grantLabel names a grant type; one this console does not know shows as is.
function grantLabel(g: string): string {
  const key = `apps.grants.${GRANT_KEYS[g] ?? g}`
  return te(key) ? t(key) : g
}

const props = defineProps<{ tenant: SystemTenant; client: Client }>()
const emit = defineEmits<{ saved: [Client] }>()
const { api } = useServices()

const offered = [
  'authorization_code',
  'refresh_token',
  'client_credentials',
  'password',
  'http://auth0.com/oauth/grant-type/password-realm',
  'urn:ietf:params:oauth:grant-type:device_code',
  CIBA,
]

type AuthMethod = NonNullable<Client['token_endpoint_auth_method']> | 'private_key_jwt'
const refIds = (refs?: { id?: string }[]) => (refs ?? []).flatMap((r) => (r.id ? [r.id] : []))

const form = reactive({
  grants: [] as string[],
  authMethod: 'none' as AuthMethod,
  pkjIds: [] as string[],
  jarRequired: false,
  jarIds: [] as string[],
  exchange: false,
  idTokenLifetime: 36000,
  rotation: 'non-rotating' as 'rotating' | 'non-rotating',
  expiration: 'non-expiring' as 'expiring' | 'non-expiring',
  requirePAR: false,
  channels: [] as Channel[],
})
const error = ref('')
const status = ref('')
const busy = ref(false)

watch(
  () => props.client,
  (c) => {
    form.grants = [...c.grant_types]
    const pkj = c.client_authentication_methods?.private_key_jwt
    form.authMethod = pkj ? 'private_key_jwt' : (c.token_endpoint_auth_method ?? 'none')
    form.pkjIds = refIds(pkj?.credentials)
    form.jarRequired = c.signed_request_object?.required ?? false
    form.jarIds = refIds(c.signed_request_object?.credentials)
    form.exchange = !!c.token_exchange?.allow_any_profile_of_type?.includes('custom_authentication')
    form.idTokenLifetime = c.jwt_configuration.lifetime_in_seconds ?? 36000
    form.rotation = c.refresh_token.rotation_type ?? 'non-rotating'
    form.expiration = c.refresh_token.expiration_type ?? 'non-expiring'
    form.requirePAR = c.require_pushed_authorization_requests
    form.channels = [...((c.async_approval_notification_channels ?? []) as Channel[])]
  },
  { immediate: true },
)

// The public keys the application has, for the private_key_jwt and JAR choices.
// A storage plugin without the capability answers 501: those controls then
// explain themselves instead of failing on save.
const credentials = ref<ClientCredential[]>([])
const credentialsUnavailable = ref(false)
let epoch = 0
onBeforeUnmount(() => { ++epoch })
async function loadCredentials() {
  const mine = ++epoch
  credentials.value = []
  credentialsUnavailable.value = false
  try {
    const list = await api.listClientCredentials(props.tenant, props.client.client_id)
    if (mine === epoch) credentials.value = list
  } catch (e) {
    if (mine !== epoch) return
    if (e instanceof ApiError && e.status === 501) credentialsUnavailable.value = true
    else error.value = errorMessage(e)
  }
}
watch(() => props.tenant.host + '/' + props.client.client_id, () => { void loadCredentials() }, { immediate: true })

const wasPrivateKeyJwt = computed(() => !!props.client.client_authentication_methods?.private_key_jwt)
const authMethods = computed<AuthMethod[]>(() => [
  'none', 'client_secret_post', 'client_secret_basic',
  ...(!credentialsUnavailable.value || wasPrivateKeyJwt.value ? (['private_key_jwt'] as const) : []),
])
const initialExchange = computed(() => !!props.client.token_exchange?.allow_any_profile_of_type?.includes('custom_authentication'))
const signedChanged = computed(() => {
  const so = props.client.signed_request_object
  return form.jarRequired !== (so?.required ?? false) || [...form.jarIds].sort().join() !== refIds(so?.credentials).sort().join()
})

// Grants the client has that the console does not offer stay listed.
const grantChoices = computed(() => [...offered, ...props.client.grant_types.filter((g) => !offered.includes(g))])

async function save() {
  busy.value = true
  error.value = ''
  status.value = ''
  const body: ClientUpdate = {
    grant_types: form.grants,
    jwt_configuration: { lifetime_in_seconds: Number(form.idTokenLifetime) },
    refresh_token: { rotation_type: form.rotation, expiration_type: form.expiration },
    require_pushed_authorization_requests: form.requirePAR,
  }
  if (form.authMethod === 'private_key_jwt') {
    if (form.pkjIds.length === 0) {
      error.value = t('apps.pkjNeedsKey')
      busy.value = false
      return
    }
    body.client_authentication_methods = { private_key_jwt: { credentials: form.pkjIds.map((id) => ({ id })) } }
    // Moving to private_key_jwt clears the method in the same request; one
    // already there must not send it again.
    if (!wasPrivateKeyJwt.value) body.token_endpoint_auth_method = null
  } else {
    if (wasPrivateKeyJwt.value) body.client_authentication_methods = null
    body.token_endpoint_auth_method = form.authMethod
  }
  if (signedChanged.value) {
    // No requirement and no keys is the unset state, which the API takes as null.
    body.signed_request_object = form.jarRequired || form.jarIds.length ? { required: form.jarRequired, credentials: form.jarIds.map((id) => ({ id })) } : (null as never)
  }
  const initialChannels = [...(props.client.async_approval_notification_channels ?? [])].sort().join()
  if ([...form.channels].sort().join() !== initialChannels) {
    body.async_approval_notification_channels = form.channels.length ? form.channels : (null as never)
  }
  if (form.exchange !== initialExchange.value) {
    body.token_exchange = form.exchange ? { allow_any_profile_of_type: ['custom_authentication'] } : null
  }
  try {
    const c = await api.updateClient(props.tenant, props.client.client_id, body)
    status.value = t('saved')
    emit('saved', c)
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <form class="card stack" novalidate @submit.prevent="save">
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <fieldset class="m-0 grid gap-1.5 border-0 p-0">
      <legend class="p-0 font-bold">{{ t('apps.grantTypes') }}</legend>
      <p class="m-0 muted">{{ t('apps.grantTypesHint') }}</p>
      <label v-for="g in grantChoices" :key="g" class="check">
        <input v-model="form.grants" type="checkbox" :value="g" />
        {{ grantLabel(g) }}
      </label>
    </fieldset>
    <fieldset v-if="form.grants.includes(CIBA) || form.channels.length" class="m-0 grid gap-1.5 border-0 p-0" data-testid="ciba-channels">
      <legend class="p-0 font-bold">{{ t('apps.cibaChannels') }}</legend>
      <p class="m-0 muted">{{ t('apps.cibaChannelsHint') }}</p>
      <label v-for="ch in channelChoices" :key="ch" class="check">
        <input v-model="form.channels" type="checkbox" :value="ch" />
        {{ t(`apps.cibaChannel.${ch}`) }}
      </label>
    </fieldset>
    <Field id="app-auth-method" :label="t('apps.authMethod')">
      <select id="app-auth-method" v-model="form.authMethod">
        <option v-for="m in authMethods" :key="m" :value="m">{{ t(`apps.authMethods.${m}`) }}</option>
      </select>
    </Field>
    <fieldset v-if="form.authMethod === 'private_key_jwt'" class="m-0 grid gap-1.5 border-0 p-0" data-testid="pkj-keys">
      <legend class="p-0 font-bold">{{ t('apps.pkjKeys') }}</legend>
      <p class="m-0 muted">{{ credentials.length ? t('apps.pkjKeysHint') : t('apps.noKeysYet') }}</p>
      <label v-for="c in credentials" :key="c.id" class="check">
        <input v-model="form.pkjIds" type="checkbox" :value="c.id" />
        {{ c.name || c.id }} ({{ c.alg }})
      </label>
    </fieldset>
    <p v-if="credentialsUnavailable" class="m-0 muted" data-testid="creds-unavailable">{{ t('apps.credentialsUnavailable') }}</p>
    <fieldset class="m-0 grid gap-1.5 border-0 p-0" :disabled="credentialsUnavailable && !form.jarRequired && !form.jarIds.length">
      <legend class="p-0 font-bold">{{ t('apps.jar') }}</legend>
      <p class="m-0 muted">{{ t('apps.jarHint') }}</p>
      <label class="check">
        <input v-model="form.jarRequired" type="checkbox" />
        {{ t('apps.jarRequired') }}
      </label>
      <p class="m-0 muted">{{ credentials.length ? t('apps.jarKeysHint') : t('apps.noKeysYet') }}</p>
      <label v-for="c in credentials" :key="c.id" class="check">
        <input v-model="form.jarIds" type="checkbox" :value="c.id" />
        {{ c.name || c.id }} ({{ c.alg }})
      </label>
    </fieldset>
    <div class="grid gap-1.5">
      <label class="check">
        <input v-model="form.exchange" type="checkbox" :disabled="!client.is_first_party || (credentialsUnavailable && !form.exchange)" aria-describedby="app-exchange-hint" />
        {{ t('apps.exchange') }}
      </label>
      <p id="app-exchange-hint" class="m-0 muted" data-testid="exchange-hint">{{ client.is_first_party ? t('apps.exchangeHint') : t('apps.exchangeThirdParty') }}</p>
    </div>
    <Field id="app-id-ttl" :label="t('apps.idTokenLifetime')">
      <input id="app-id-ttl" v-model.number="form.idTokenLifetime" type="number" min="0" step="1" />
    </Field>
    <div class="row [&>*]:min-w-48 [&>*]:flex-1">
      <Field id="app-rotation" :label="t('apps.rotation')">
        <select id="app-rotation" v-model="form.rotation">
          <option value="rotating">{{ t('apps.rotating') }}</option>
          <option value="non-rotating">{{ t('apps.nonRotating') }}</option>
        </select>
      </Field>
      <Field id="app-expiration" :label="t('apps.expiration')">
        <select id="app-expiration" v-model="form.expiration">
          <option value="expiring">{{ t('apps.expiring') }}</option>
          <option value="non-expiring">{{ t('apps.nonExpiring') }}</option>
        </select>
      </Field>
    </div>
    <label class="check">
      <input v-model="form.requirePAR" type="checkbox" />
      {{ t('apps.requirePAR') }}
    </label>
    <div>
      <span class="font-bold">{{ t('apps.party') }}</span>
      <p data-testid="party" class="m-0">
        {{ client.is_first_party ? t('apps.firstParty') : t('apps.thirdParty', { mode: client.third_party_security_mode ?? 'strict' }) }}
      </p>
      <p class="m-0 muted">{{ t('apps.partyFixed') }}</p>
    </div>
    <div class="row">
      <Button variant="primary" type="submit" :disabled="busy">{{ busy ? t('saving') : t('save') }}</Button>
      <span class="muted" role="status">{{ status }}</span>
    </div>
  </form>
</template>
