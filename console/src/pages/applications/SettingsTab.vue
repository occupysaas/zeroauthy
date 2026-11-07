<script setup lang="ts">
import { reactive, ref, watch } from 'vue'
import { ApiError, type Client, type ClientUpdate, type SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import CopyButton from '../../ui/CopyButton.vue'
import Field from '../../ui/Field.vue'
import { fieldErrors, lines } from './defaults'
import { useMfaScope } from '../security/scope'
import SecretField from './SecretField.vue'

const { t } = useI18n()

const props = defineProps<{ tenant: SystemTenant; client: Client }>()
const emit = defineEmits<{ saved: [Client] }>()
const { api } = useServices()

const form = reactive({ name: '', callbacks: '', logout: '', webOrigins: '', allowedOrigins: '',
  passkeyGrant: false, iosEnabled: false, androidEnabled: false, iosTeam: '', iosBundle: '', androidPackage: '', fingerprints: '',
  organizationUsage: 'deny' as 'deny' | 'allow' | 'require',
  organizationBehavior: 'no_prompt' as 'no_prompt' | 'pre_login_prompt' | 'post_login_prompt',
  discovery: [] as ('email' | 'organization_name')[],
})
const errors = reactive<Record<string, string>>({})
const general = ref('')
const status = ref('')
const busy = ref(false)
const { key, capture, current } = useMfaScope(() => props.tenant, () => props.client.client_id)
let initialMobile = ''
watch(key, () => { busy.value = false; general.value = ''; status.value = ''; reset(props.client); for (const k of Object.keys(errors)) delete errors[k] }, { flush: 'sync' })

function reset(c: Client) {
  form.passkeyGrant = c.grant_types.includes('urn:okta:params:oauth:grant-type:webauthn')
  form.iosEnabled = !!c.mobile?.ios; form.androidEnabled = !!c.mobile?.android
  form.iosTeam = c.mobile?.ios?.team_id ?? ''; form.iosBundle = c.mobile?.ios?.app_bundle_identifier ?? ''
  form.androidPackage = c.mobile?.android?.app_package_name ?? ''; form.fingerprints = (c.mobile?.android?.sha256_cert_fingerprints ?? []).join('\n')
  initialMobile = JSON.stringify(mobileSettings())
  form.organizationUsage = c.organization_usage ?? 'deny'
  form.organizationBehavior = c.organization_require_behavior ?? 'no_prompt'
  form.discovery = [...(c.organization_discovery_methods ?? [])]
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

function mobileSettings(): NonNullable<ClientUpdate['mobile']> {
  const iosPresent = form.iosEnabled || !!form.iosTeam || !!form.iosBundle
  const androidPresent = form.androidEnabled || !!form.androidPackage || !!form.fingerprints
  const mobile: NonNullable<ClientUpdate['mobile']> = {}
  if (iosPresent) mobile.ios = { team_id: form.iosTeam, app_bundle_identifier: form.iosBundle }
  if (androidPresent) mobile.android = { app_package_name: form.androidPackage, ...(form.fingerprints ? { sha256_cert_fingerprints: lines(form.fingerprints) } : {}) }
  return mobile
}

async function save() {
  if (busy.value) return
  const captured = capture(); if (!captured) return
  busy.value = true
  general.value = ''
  status.value = ''
  for (const k of Object.keys(errors)) delete errors[k]
  if ((form.organizationBehavior === 'post_login_prompt' && !props.client.oidc_conformant) ||
      (form.organizationUsage === 'require' && props.client.grant_types.some(g => ['password', 'http://auth0.com/oauth/grant-type/password-realm', 'urn:ietf:params:oauth:grant-type:device_code'].includes(g)))) {
    general.value = t('orgs.invalidApplication'); busy.value = false; return
  }
  const body: ClientUpdate = {
    organization_usage: form.organizationUsage,
    organization_require_behavior: form.organizationBehavior,
    organization_discovery_methods: form.organizationBehavior === 'pre_login_prompt' && form.discovery.length ? [...form.discovery] : null,
    name: form.name.trim(),
    callbacks: lines(form.callbacks),
    allowed_logout_urls: lines(form.logout),
    web_origins: lines(form.webOrigins),
    allowed_origins: lines(form.allowedOrigins),
  }
  const grant = 'urn:okta:params:oauth:grant-type:webauthn'
  if (form.passkeyGrant !== props.client.grant_types.includes(grant)) body.grant_types = form.passkeyGrant ? [...props.client.grant_types, grant] : props.client.grant_types.filter(item => item !== grant)
  const mobile = mobileSettings()
  if (JSON.stringify(mobile) !== initialMobile) body.mobile = mobile
  try {
    const c = await api.updateClient(captured.tenant, captured.id, body)
    if (!current(captured)) return
    status.value = t('saved')
    emit('saved', c)
  } catch (e) {
    if (!current(captured)) return
    if (e instanceof ApiError && e.errorCode === 'invalid_body') {
      const split = fieldErrors(e.message, fieldKeys)
      Object.assign(errors, split.byField)
      general.value = split.general
    } else {
      general.value = errorMessage(e)
    }
  } finally {
    if (current(captured)) busy.value = false
  }
}

function describedBy(id: string, hint: boolean): string {
  return [hint ? id + '-hint' : '', errors[id.replace('app-', '')] ? id + '-error' : ''].filter(Boolean).join(' ')
}
</script>

<template>
  <div class="stack">
    <section class="card stack" :aria-label="t('apps.clientID')">
      <div>
        <span class="font-bold">{{ t('apps.domain') }}</span>
        <div class="row">
          <code>{{ tenant.host }}</code>
          <CopyButton :value="tenant.host" :label="t('apps.domain')" />
        </div>
      </div>
      <div>
        <span class="font-bold">{{ t('apps.clientID') }}</span>
        <div class="row">
          <code data-testid="client-id">{{ client.client_id }}</code>
          <CopyButton :value="client.client_id" :label="t('apps.clientID')" />
        </div>
      </div>
      <SecretField :client="client" />
    </section>

    <form class="card stack" novalidate @submit.prevent="save">
      <Banner v-if="general" kind="error">{{ general }}</Banner>
      <Field id="app-name" :label="t('apps.name')" :error="errors.name">
        <input id="app-name" v-model="form.name" type="text" maxlength="255" :aria-invalid="!!errors.name" :aria-describedby="describedBy('app-name', false)" />
      </Field>
      <Field id="app-callbacks" :label="t('apps.callbacks')" :hint="t('apps.callbacksHint')" :error="errors.callbacks">
        <textarea id="app-callbacks" v-model="form.callbacks" spellcheck="false" :aria-invalid="!!errors.callbacks" :aria-describedby="describedBy('app-callbacks', true)" />
      </Field>
      <Field id="app-logout" :label="t('apps.logoutURLs')" :hint="t('apps.logoutURLsHint')" :error="errors.logout">
        <textarea id="app-logout" v-model="form.logout" spellcheck="false" :aria-invalid="!!errors.logout" :aria-describedby="describedBy('app-logout', true)" />
      </Field>
      <Field id="app-webOrigins" :label="t('apps.webOrigins')" :hint="t('apps.webOriginsHint')" :error="errors.webOrigins">
        <textarea id="app-webOrigins" v-model="form.webOrigins" spellcheck="false" :aria-invalid="!!errors.webOrigins" :aria-describedby="describedBy('app-webOrigins', true)" />
      </Field>
      <Field id="app-allowedOrigins" :label="t('apps.allowedOrigins')" :hint="t('apps.allowedOriginsHint')" :error="errors.allowedOrigins">
        <textarea id="app-allowedOrigins" v-model="form.allowedOrigins" spellcheck="false" :aria-invalid="!!errors.allowedOrigins" :aria-describedby="describedBy('app-allowedOrigins', true)" />
      </Field>
      <Field id="app-organization-usage" :label="t('orgs.usage')"><select id="app-organization-usage" v-model="form.organizationUsage"><option value="deny">{{ t('orgs.deny') }}</option><option value="allow">{{ t('orgs.allowUsage') }}</option><option value="require">{{ t('orgs.require') }}</option></select></Field>
      <Field id="app-organization-behavior" :label="t('orgs.behavior')"><select id="app-organization-behavior" v-model="form.organizationBehavior"><option value="no_prompt">{{ t('orgs.noPrompt') }}</option><option value="pre_login_prompt">{{ t('orgs.prePrompt') }}</option><option value="post_login_prompt" :disabled="!client.oidc_conformant">{{ t('orgs.postPrompt') }}</option></select></Field>
      <fieldset class="stack"><legend>{{ t('orgs.discovery') }}</legend><p id="organization-discovery-hint">{{ t('orgs.discoveryHint') }}</p>
        <label v-for="method in ['email', 'organization_name'] as const" :key="method"><input :id="'app-organization-discovery-' + method" v-model="form.discovery" type="checkbox" :value="method" :disabled="form.organizationBehavior !== 'pre_login_prompt'" aria-describedby="organization-discovery-hint" /> {{ method === 'email' ? t('orgs.email') : t('orgs.organizationName') }}</label>
      </fieldset>
      <label><input id="app-passkey-grant" v-model="form.passkeyGrant" type="checkbox" /> {{ t('passkeys.grant') }}</label>
      <fieldset class="stack"><legend>{{ t('passkeys.devices') }}</legend>
        <label><input id="app-ios-enabled" v-model="form.iosEnabled" type="checkbox" @change="!form.iosEnabled && (form.iosTeam = '', form.iosBundle = '')" /> {{ t('passkeys.iosEnabled') }}</label>
        <Field id="app-ios-team" :label="t('passkeys.iosTeam')"><input id="app-ios-team" v-model="form.iosTeam" /></Field>
        <Field id="app-ios-bundle" :label="t('passkeys.iosBundle')"><input id="app-ios-bundle" v-model="form.iosBundle" /></Field>
        <label><input id="app-android-enabled" v-model="form.androidEnabled" type="checkbox" @change="!form.androidEnabled && (form.androidPackage = '', form.fingerprints = '')" /> {{ t('passkeys.androidEnabled') }}</label>
        <Field id="app-android-package" :label="t('passkeys.androidPackage')"><input id="app-android-package" v-model="form.androidPackage" /></Field>
        <Field id="app-android-fingerprints" :label="t('passkeys.fingerprints')" :hint="t('passkeys.fingerprintsHint')"><textarea id="app-android-fingerprints" v-model="form.fingerprints" rows="3" /></Field>
      </fieldset>
      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy || !form.name.trim()">{{ busy ? t('saving') : t('save') }}</Button>
        <span class="muted" role="status">{{ status }}</span>
      </div>
    </form>
  </div>
</template>
