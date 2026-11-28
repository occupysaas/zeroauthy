<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ApiError, type Client, type ConnectionCreate } from '../../../api/client'
import { errorMessage, useServices, useTenant } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import RouteModal from '../../../ui/RouteModal.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import ScriptEditor from './ScriptEditor.vue'
import MicrosoftOptions from './MicrosoftOptions.vue'
import GitHubOptions from './GitHubOptions.vue'
import DescriptorOptions from './DescriptorOptions.vue'
import { adfsCallback, adfsRealm, applePEM, githubFlagOptions, samlACS, samlCertificate, APPLE_IDENTIFIER, callbackURLs, defaultScript, httpsURL, MAX_SCRIPT_BYTES, NAME, socialStrategies, enterpriseStrategies, MICROSOFT_GUID, microsoftTenant, utf8Bytes, descriptorFlagsOf, descriptorOf, descriptorOptions, freeformList, type Options, type FederatedStrategy } from './social'

const { t } = useI18n()
const { api } = useServices()
const tenant = useTenant()
const router = useRouter()
const route = useRoute()
const enterprise = computed(() => String(route.name).startsWith('enterprise'))
const audience = computed(() => enterprise.value ? 'enterprise' : 'social')
const strategies = computed(() => enterprise.value ? enterpriseStrategies : socialStrategies)

// The draft lives only in memory: the client secret is never persisted in
// the browser.
const draft = reactive({
  strategy: (enterprise.value ? 'oidc' : 'google-oauth2') as FederatedStrategy,
  name: '',
  displayName: '',
  clientId: '',
  clientSecret: '',
  appleTeam: '', appleKID: '', appleKey: '', appleName: true,
  email: true,
  githubFlags: {} as Record<string, boolean>,
  profile: true,
  authorizationURL: '',
  tokenURL: '',
  scope: '',
  script: defaultScript,
  discoveryURL: '',
  channel: 'back_channel',
  oktaDomain: '',
  workspaceDomain: '',
  scopes: 'openid profile email',
  microsoftMode: 'single',
  tenantDomain: '',
  samlSource: 'metadata' as 'metadata' | 'manual',
  samlMetadataURL: '',
  samlSignIn: '',
  samlCert: '',
  adDomain: '',
  adfsSource: 'server' as 'server' | 'xml',
  adfsServer: '',
  adfsXML: '',
  descFlags: {} as Record<string, boolean>,
  freeform: '',
  community: '',
  protocol: 'oauth2',
  freeScope: '',
  baseUrl: '',
})
const descriptor = computed(() => descriptorOf(draft.strategy))
watch(() => draft.strategy, () => {
  const d = descriptor.value
  if (d) draft.descFlags = descriptorFlagsOf(d, {})
})
const errors = reactive<Record<string, string>>({})
const general = ref('')
const uncertain = ref(false)
const busy = ref(false)
const clients = ref<Client[]>([])
const chosen = ref<string[]>([])
const clientsError = ref('')
const callbacks = computed(() => (tenant.value ? callbackURLs(tenant.value, draft.strategy) : []))

onMounted(async () => {
  const tn = tenant.value
  if (!tn) return
  try {
    const all: Client[] = []
    for (let p = 0; ; p++) {
      const r = await api.listClients(tn, { page: p, per_page: 100 })
      all.push(...r.clients)
      if (r.clients.length === 0 || all.length >= r.total) break
    }
    if (tenant.value?.name === tn.name) clients.value = all
  } catch (e) {
    clientsError.value = errorMessage(e)
  }
})

function need(key: string, value: string) {
  if (!value.trim()) errors[key] = t('social.required')
}

function validate(): boolean {
  for (const k of Object.keys(errors)) delete errors[k]
  const n = draft.name.trim()
  if (!n) errors.name = t('social.nameRequired')
  else if (n.length > 128 || !NAME.test(n)) errors.name = t('social.nameInvalid')
  if (draft.strategy === 'ad') return Object.keys(errors).length === 0
  if (draft.strategy === 'adfs') {
    if (draft.adfsSource === 'server' ? !draft.adfsServer.trim() : !draft.adfsXML.trim()) errors[draft.adfsSource === 'server' ? 'adfsServer' : 'adfsXML'] = t('social.required')
    return Object.keys(errors).length === 0
  }
  if (draft.strategy === 'samlp') {
    if (draft.samlSource === 'metadata') {
      if (!httpsURL(draft.samlMetadataURL.trim())) errors.samlMetadataURL = t('social.httpsRequired')
    } else {
      if (!httpsURL(draft.samlSignIn.trim())) errors.samlSignIn = t('social.httpsRequired')
      if (!samlCertificate(draft.samlCert)) errors.samlCert = t('saml37.certInvalid')
    }
    return Object.keys(errors).length === 0
  }
  need('clientId', draft.clientId)
  if (draft.strategy === 'apple') {
    if (!APPLE_IDENTIFIER.test(draft.appleTeam)) errors.appleTeam = t('social.appleIdentifier')
    if (!APPLE_IDENTIFIER.test(draft.appleKID)) errors.appleKID = t('social.appleIdentifier')
    if (!applePEM(draft.appleKey)) errors.appleKey = t('social.applePEM')
  } else if (draft.strategy !== 'oidc' || draft.channel === 'back_channel') need('clientSecret', draft.clientSecret)
  if (draft.strategy === 'windowslive' || draft.strategy === 'waad') {
    if (!MICROSOFT_GUID.test(draft.clientId.trim())) errors.clientId = t('social.microsoftClientId')
    if (draft.strategy === 'waad' && draft.microsoftMode === 'single' && !microsoftTenant(draft.tenantDomain)) errors.tenantDomain = t('social.microsoftTenantInvalid')
  }
  if (draft.strategy === 'oauth2') {
    for (const k of ['authorizationURL', 'tokenURL'] as const) {
      if (!httpsURL(draft[k].trim())) errors[k] = t('social.httpsRequired')
    }
    need('scope', draft.scope)
    if (!draft.script.trim()) errors.script = t('social.required')
    else if (utf8Bytes(draft.script) > MAX_SCRIPT_BYTES) errors.script = t('social.scriptTooLarge', { max: MAX_SCRIPT_BYTES })
  }
  if (draft.strategy === 'oidc') {
    if (!httpsURL(draft.discoveryURL.trim())) errors.discoveryURL = t('social.httpsRequired')
    if (!draft.scopes.split(/\s+/).includes('openid')) errors.scopes = t('social.openidRequired')
  }
  if (draft.strategy === 'google-apps' && (!draft.workspaceDomain.includes('.') || draft.workspaceDomain.length > 253 || !draft.workspaceDomain.toLowerCase().split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)))) errors.workspaceDomain = 'Enter the primary Google Workspace domain, such as example.com.'
  const d = descriptor.value
  if (d?.fields.includes('community_base_url') && !httpsURL(draft.community.trim())) errors.community = t('social.httpsRequired')
  if (d?.base_url_hosts.length && !d.base_url_hosts.some((h) => draft.baseUrl === `https://${h}`)) errors.baseUrl = t('social.exactRegionRequired')
  if (d?.free_scope && (freeformList(draft.freeScope).length > 20 || freeformList(draft.freeScope).some((s) => s.length > 128))) errors.freeform = t('social.freeformScopesInvalid')
  if (d?.freeform_scopes && (freeformList(draft.freeform).length > 20 || freeformList(draft.freeform).some((s) => s.length > 128))) errors.freeform = t('social.freeformScopesInvalid')
  if (draft.strategy === 'okta' && (!draft.oktaDomain || draft.oktaDomain.length > 253 || !draft.oktaDomain.toLowerCase().split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)))) errors.oktaDomain = 'Enter a DNS host name without a scheme, port or path.'
  return Object.keys(errors).length === 0
}

function body(): ConnectionCreate {
  let options: Options = { client_id: draft.clientId.trim(), client_secret: draft.clientSecret }
  switch (draft.strategy) {
    case 'ad':
      options = draft.adDomain.trim() ? { tenant_domain: draft.adDomain.trim().toLowerCase() } : {}
      break
    case 'adfs':
      options = draft.adfsSource === 'server' ? { adfs_server: draft.adfsServer.trim() } : { fedMetadataXml: draft.adfsXML.trim() }
      break
    case 'samlp':
      options = draft.samlSource === 'metadata' ? { metadataUrl: draft.samlMetadataURL.trim() } : { signInEndpoint: draft.samlSignIn.trim(), signingCert: draft.samlCert.trim() }
      break
    case 'apple':
      delete options.client_secret
      Object.assign(options, { team_id: draft.appleTeam, kid: draft.appleKID, app_secret: draft.appleKey, name: draft.appleName, email: draft.email })
      break
    case 'github':
      Object.assign(options, githubFlagOptions(draft.email, draft.githubFlags))
      break
    case 'windowslive':
      options.client_id = draft.clientId.trim().toLowerCase()
      options.strategy_version = 2
      break
    case 'waad':
      Object.assign(options, { client_id: draft.clientId.trim().toLowerCase(), identity_api: 'microsoft-identity-platform-v2.0', waad_protocol: 'openid-connect', userid_attribute: 'oid', useCommonEndpoint: draft.microsoftMode === 'organizations' })
      if (draft.microsoftMode === 'single') options.tenant_domain = microsoftTenant(draft.tenantDomain)
      break
    case 'google-oauth2':
      options.email = draft.email
      options.profile = draft.profile
      break
    case 'oauth2':
      Object.assign(options, { authorizationURL: draft.authorizationURL.trim(), tokenURL: draft.tokenURL.trim(), scope: draft.scope.trim(), scripts: { fetchUserProfile: draft.script } })
      break
    case 'oidc':
      Object.assign(options, { type: draft.channel, discovery_url: draft.discoveryURL.trim(), scopes: draft.scopes.trim() })
      if (draft.channel === 'front_channel') delete options.client_secret
      break
    case 'google-apps':
      Object.assign(options, { domain: draft.workspaceDomain.toLowerCase(), tenant_domain: draft.workspaceDomain.toLowerCase() })
      break
    case 'okta':
      Object.assign(options, { type: 'back_channel', domain: draft.oktaDomain.toLowerCase(), scope: draft.scopes.trim() })
      break
    default:
      if (descriptor.value) Object.assign(options, descriptorOptions(descriptor.value, draft.descFlags, draft.freeform, { community: draft.community, protocol: draft.protocol, scope: draft.freeScope, baseUrl: draft.baseUrl }))
  }
  const b: Record<string, unknown> = { name: draft.name.trim(), strategy: draft.strategy, options, enabled_clients: chosen.value }
  if (draft.displayName.trim()) b.display_name = draft.displayName.trim()
  return b as ConnectionCreate
}

async function submit() {
  const tn = tenant.value
  general.value = ''
  uncertain.value = false
  if (!tn || busy.value || !validate()) return
  busy.value = true
  try {
    const c = await api.createConnection(tn, body())
    draft.clientSecret = ''
    draft.appleKey = ''
    await router.push({ name: enterprise.value ? 'enterprise-connection' : 'social-connection', params: { tenant: tn.name, id: c.id } })
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.errorCode === 'connection_conflict') errors.name = e.message
      else general.value = errorMessage(e)
    } else {
      // The request may have reached the server: never claim either way.
      uncertain.value = true
    }
  } finally {
    busy.value = false
  }
}

function describedBy(id: string, key: string, hint = false): string {
  return [hint ? id + '-hint' : '', errors[key] ? id + '-error' : ''].filter(Boolean).join(' ') || ''
}
</script>

<template>
  <RouteModal v-if="tenant" v-slot="{ close }" :title="t(`${audience}.createTitle`)" :back="audience" wide>
    <form class="stack" novalidate @submit.prevent="submit">
      <Banner v-if="general" kind="error">{{ general }}</Banner>
      <Banner v-if="uncertain" kind="warn">{{ t('social.uncertainCreate') }}</Banner>
      <fieldset class="stack m-0 border-0 p-0">
        <legend class="p-0 font-bold">{{ t('social.strategy') }}</legend>
        <label v-for="s in strategies" :key="s" class="check">
          <input v-model="draft.strategy" type="radio" name="strategy" :value="s" />
          <span>{{ t(`social.strategies.${s}`) }}</span>
        </label>
        <p v-if="draft.strategy === 'oidc'" class="muted" data-testid="oidc-subset">{{ t('social.oidcSubset') }}</p>
      </fieldset>
      <RouterLink v-if="!enterprise" :to="{ name: 'enterprise-new', params: { tenant: tenant.name } }">{{ t('social.enterpriseLink') }}</RouterLink>
      <MicrosoftOptions v-if="draft.strategy === 'windowslive' || draft.strategy === 'waad'" v-model:mode="draft.microsoftMode" v-model:tenant-domain="draft.tenantDomain" :strategy="draft.strategy" :error="errors.tenantDomain" />
      <Field id="social-name" :label="t('social.name')" :hint="t('social.nameHint')" :error="errors.name">
        <input id="social-name" v-model="draft.name" type="text" maxlength="128" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.name" :aria-describedby="describedBy('social-name', 'name', true)" />
      </Field>
      <Field id="social-display" :label="t('social.displayName')" :hint="t('social.displayNameHint')">
        <input id="social-display" v-model="draft.displayName" type="text" maxlength="128" autocomplete="off" aria-describedby="social-display-hint" />
      </Field>
      <template v-if="draft.strategy === 'samlp'">
        <Field id="saml-source" :label="t('saml37.source')"><select id="saml-source" v-model="draft.samlSource"><option value="metadata">{{ t('saml37.fromMetadata') }}</option><option value="manual">{{ t('saml37.manual') }}</option></select></Field>
        <Field v-if="draft.samlSource === 'metadata'" id="saml-metadata-url" :label="t('saml37.metadataURL')" :error="errors.samlMetadataURL"><input id="saml-metadata-url" v-model="draft.samlMetadataURL" type="url" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.samlMetadataURL" /></Field>
        <template v-else>
          <Field id="saml-signin" :label="t('saml37.signIn')" :error="errors.samlSignIn"><input id="saml-signin" v-model="draft.samlSignIn" type="url" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.samlSignIn" /></Field>
          <Field id="saml-cert" :label="t('saml37.signingCert')" :hint="t('saml37.signingCertHint')" :error="errors.samlCert"><textarea id="saml-cert" v-model="draft.samlCert" rows="7" spellcheck="false" :aria-invalid="!!errors.samlCert" /></Field>
        </template>
        <p class="muted" data-testid="saml-acs">{{ t('saml37.acs') }} <code>{{ samlACS(tenant, draft.name.trim() || '{name}') }}</code></p>
      </template>
      <template v-if="draft.strategy === 'ad'">
        <Field id="ad-domain" :label="t('ad38.domain')" :hint="t('ad38.domainHint')"><input id="ad-domain" v-model="draft.adDomain" type="text" autocomplete="off" spellcheck="false" /></Field>
        <p class="muted" data-testid="ad-create-hint">{{ t('ad38.createHint') }}</p>
      </template>
      <template v-if="draft.strategy === 'adfs'">
        <Field id="adfs-source" :label="t('wsfed37.source')"><select id="adfs-source" v-model="draft.adfsSource"><option value="server">{{ t('wsfed37.fromServer') }}</option><option value="xml">{{ t('wsfed37.fromXML') }}</option></select></Field>
        <Field v-if="draft.adfsSource === 'server'" id="adfs-server" :label="t('wsfed37.server')" :hint="t('wsfed37.serverHint')" :error="errors.adfsServer"><input id="adfs-server" v-model="draft.adfsServer" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.adfsServer" /></Field>
        <Field v-else id="adfs-xml" :label="t('wsfed37.xml')" :error="errors.adfsXML"><textarea id="adfs-xml" v-model="draft.adfsXML" rows="7" spellcheck="false" :aria-invalid="!!errors.adfsXML" /></Field>
        <dl class="m-0 break-all muted" data-testid="adfs-rp"><dt>{{ t('wsfed37.realm') }}</dt><dd><code>{{ adfsRealm(tenant, draft.name.trim() || '{name}') }}</code></dd><dt>{{ t('wsfed37.callback') }}</dt><dd><code>{{ adfsCallback(tenant) }}</code></dd></dl>
      </template>
      <Field v-if="draft.strategy !== 'samlp' && draft.strategy !== 'adfs' && draft.strategy !== 'ad'" id="social-client-id" :label="t(draft.strategy === 'apple' ? 'social.appleServices' : 'social.clientId')" :error="errors.clientId">
        <input id="social-client-id" v-model="draft.clientId" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.clientId" :aria-describedby="describedBy('social-client-id', 'clientId')" />
      </Field>
      <Field v-if="draft.strategy !== 'apple' && draft.strategy !== 'samlp' && draft.strategy !== 'adfs' && draft.strategy !== 'ad' && (draft.strategy !== 'oidc' || draft.channel === 'back_channel')" id="social-client-secret" :label="t('social.clientSecret')" :hint="t('social.clientSecretNew')" :error="errors.clientSecret">
        <input id="social-client-secret" v-model="draft.clientSecret" type="password" autocomplete="new-password" spellcheck="false" :aria-invalid="!!errors.clientSecret" :aria-describedby="describedBy('social-client-secret', 'clientSecret', true)" />
      </Field>
      <template v-if="draft.strategy === 'apple'">
        <Field id="apple-team" :label="t('social.appleTeam')" :error="errors.appleTeam"><input id="apple-team" v-model="draft.appleTeam" maxlength="10" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.appleTeam" :aria-describedby="errors.appleTeam ? 'apple-team-error' : undefined" /></Field>
        <Field id="apple-kid" :label="t('social.appleKID')" :error="errors.appleKID"><input id="apple-kid" v-model="draft.appleKID" maxlength="10" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.appleKID" :aria-describedby="errors.appleKID ? 'apple-kid-error' : undefined" /></Field>
        <Field id="apple-key" :label="t('social.appleKey')" :hint="t('social.appleKeyHint')" :error="errors.appleKey"><textarea id="apple-key" v-model="draft.appleKey" rows="7" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.appleKey" :aria-describedby="errors.appleKey ? 'apple-key-hint apple-key-error' : 'apple-key-hint'" /></Field>
        <label class="check"><input id="apple-name" v-model="draft.appleName" type="checkbox" /> {{ t('social.appleName') }}</label>
        <label class="check"><input id="apple-email" v-model="draft.email" type="checkbox" /> {{ t('social.googleEmail') }}</label>
      </template>
      <GitHubOptions v-if="draft.strategy === 'github'" v-model:email="draft.email" v-model:flags="draft.githubFlags" />
      <DescriptorOptions v-if="descriptor" v-model:flags="draft.descFlags" v-model:freeform="draft.freeform" v-model:community="draft.community" v-model:protocol="draft.protocol" v-model:scope="draft.freeScope" v-model:base-url="draft.baseUrl" :descriptor="descriptor" :community-error="errors.community" :freeform-error="errors.freeform" :base-url-error="errors.baseUrl" />
      <template v-if="draft.strategy === 'google-oauth2'">
        <label class="check"><input v-model="draft.email" type="checkbox" /> <span>{{ t('social.googleEmail') }}</span></label>
        <label class="check"><input v-model="draft.profile" type="checkbox" /> <span>{{ t('social.googleProfile') }}</span></label>
      </template>
      <template v-if="draft.strategy === 'oauth2'">
        <Field id="social-authorize" :label="t('social.authorizationURL')" :error="errors.authorizationURL">
          <input id="social-authorize" v-model="draft.authorizationURL" type="url" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.authorizationURL" :aria-describedby="describedBy('social-authorize', 'authorizationURL')" />
        </Field>
        <Field id="social-token" :label="t('social.tokenURL')" :error="errors.tokenURL">
          <input id="social-token" v-model="draft.tokenURL" type="url" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.tokenURL" :aria-describedby="describedBy('social-token', 'tokenURL')" />
        </Field>
        <Field id="social-scope" :label="t('social.scope')" :hint="t('social.scopeHint')" :error="errors.scope">
          <input id="social-scope" v-model="draft.scope" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.scope" :aria-describedby="describedBy('social-scope', 'scope', true)" />
        </Field>
        <ScriptEditor id="social-script" v-model="draft.script" :label="t('social.script')" :error="errors.script" />
      </template>
      <Field v-if="draft.strategy === 'google-apps'" id="workspace-domain" label="Google Workspace domain" hint="Only accounts of this Workspace can sign in." :error="errors.workspaceDomain"><input id="workspace-domain" v-model="draft.workspaceDomain" maxlength="253" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.workspaceDomain" /></Field>
      <Field v-if="draft.strategy === 'okta'" id="okta-domain" label="Okta domain" :error="errors.oktaDomain"><input id="okta-domain" v-model="draft.oktaDomain" maxlength="253" autocomplete="off" :aria-invalid="!!errors.oktaDomain" /></Field>
      <template v-if="draft.strategy === 'oidc'">
        <Field id="oidc-channel" label="Login channel"><select id="oidc-channel" v-model="draft.channel"><option value="back_channel">Authorization code (back channel)</option><option value="front_channel">ID token form post (front channel)</option></select></Field>
        <Field id="social-discovery" :label="t('social.discoveryURL')" :error="errors.discoveryURL">
          <input id="social-discovery" v-model="draft.discoveryURL" type="url" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.discoveryURL" :aria-describedby="describedBy('social-discovery', 'discoveryURL')" />
        </Field>
        <Field id="social-scopes" :label="t('social.scopes')" :hint="t('social.scopesHint')" :error="errors.scopes">
          <input id="social-scopes" v-model="draft.scopes" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.scopes" :aria-describedby="describedBy('social-scopes', 'scopes', true)" />
        </Field>
      </template>
      <section v-if="draft.strategy !== 'samlp' && draft.strategy !== 'adfs' && draft.strategy !== 'ad'" class="stack" aria-labelledby="social-callbacks">
        <h2 id="social-callbacks" class="m-0 text-base">{{ t('social.callbacks') }}</h2>
        <p class="muted">{{ t('social.callbacksHint') }}</p>
        <p v-if="draft.strategy === 'github'" class="muted" data-testid="github-callbacks">{{ t('social.githubCallbacks') }}</p>
        <ul class="m-0 break-all" data-testid="callbacks">
          <li v-for="u in callbacks" :key="u"><code>{{ u }}</code></li>
        </ul>
      </section>
      <fieldset class="stack m-0 border-0 p-0">
        <legend class="p-0 font-bold">{{ t('social.enableOnCreate') }}</legend>
        <Banner v-if="clientsError" kind="error">{{ clientsError }}</Banner>
        <p v-else-if="clients.length === 0" class="muted">{{ t('social.noApps') }}</p>
        <label v-for="c in clients" :key="c.client_id" class="check">
          <input v-model="chosen" type="checkbox" :value="c.client_id" />
          <span>{{ c.name }}</span>
        </label>
      </fieldset>
      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy">{{ busy ? t('creating') : t('social.createSubmit') }}</Button>
        <Button @click="close">{{ t('cancel') }}</Button>
      </div>
    </form>
  </RouteModal>
</template>
