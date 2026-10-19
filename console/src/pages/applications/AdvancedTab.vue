<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import type { Client, ClientUpdate, SystemTenant } from '../../api/client'
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
}
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
]

const form = reactive({
  grants: [] as string[],
  authMethod: 'none' as Client['token_endpoint_auth_method'],
  idTokenLifetime: 36000,
  rotation: 'non-rotating' as 'rotating' | 'non-rotating',
  expiration: 'non-expiring' as 'expiring' | 'non-expiring',
  requirePAR: false,
})
const error = ref('')
const status = ref('')
const busy = ref(false)

watch(
  () => props.client,
  (c) => {
    form.grants = [...c.grant_types]
    form.authMethod = c.token_endpoint_auth_method
    form.idTokenLifetime = c.jwt_configuration.lifetime_in_seconds ?? 36000
    form.rotation = c.refresh_token.rotation_type ?? 'non-rotating'
    form.expiration = c.refresh_token.expiration_type ?? 'non-expiring'
    form.requirePAR = c.require_pushed_authorization_requests
  },
  { immediate: true },
)

const authMethods = ['none', 'client_secret_post', 'client_secret_basic'] as const

// Grants the client has that the console does not offer stay listed.
const grantChoices = computed(() => [...offered, ...props.client.grant_types.filter((g) => !offered.includes(g))])

async function save() {
  busy.value = true
  error.value = ''
  status.value = ''
  const body: ClientUpdate = {
    grant_types: form.grants,
    token_endpoint_auth_method: form.authMethod,
    jwt_configuration: { lifetime_in_seconds: Number(form.idTokenLifetime) },
    refresh_token: { rotation_type: form.rotation, expiration_type: form.expiration },
    require_pushed_authorization_requests: form.requirePAR,
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
    <fieldset>
      <legend>{{ t('apps.grantTypes') }}</legend>
      <p class="muted">{{ t('apps.grantTypesHint') }}</p>
      <label v-for="g in grantChoices" :key="g" class="check">
        <input v-model="form.grants" type="checkbox" :value="g" />
        {{ grantLabel(g) }}
      </label>
    </fieldset>
    <Field id="app-auth-method" :label="t('apps.authMethod')">
      <select id="app-auth-method" v-model="form.authMethod">
        <option v-for="m in authMethods" :key="m" :value="m">{{ t(`apps.authMethods.${m}`) }}</option>
      </select>
    </Field>
    <Field id="app-id-ttl" :label="t('apps.idTokenLifetime')">
      <input id="app-id-ttl" v-model.number="form.idTokenLifetime" type="number" min="0" step="1" />
    </Field>
    <div class="row two">
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
      <span class="label">{{ t('apps.party') }}</span>
      <p data-testid="party">
        {{ client.is_first_party ? t('apps.firstParty') : t('apps.thirdParty', { mode: client.third_party_security_mode ?? 'strict' }) }}
      </p>
      <p class="muted">{{ t('apps.partyFixed') }}</p>
    </div>
    <div class="row">
      <Button variant="primary" type="submit" :disabled="busy">{{ busy ? t('saving') : t('save') }}</Button>
      <span class="muted" role="status">{{ status }}</span>
    </div>
  </form>
</template>

<style scoped>
fieldset {
  border: 0;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.35rem;
}
legend,
.label {
  font-weight: 600;
}
fieldset p,
div > p {
  margin: 0;
}
.check {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}
.two > * {
  flex: 1;
  min-width: 12rem;
}
</style>
