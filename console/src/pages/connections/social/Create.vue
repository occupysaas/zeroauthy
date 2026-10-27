<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ApiError, type Client, type ConnectionCreate } from '../../../api/client'
import { errorMessage, useServices, useTenant } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import ScriptEditor from './ScriptEditor.vue'
import { callbackURLs, defaultScript, httpsURL, MAX_SCRIPT_BYTES, NAME, socialStrategies, utf8Bytes, type Options, type SocialStrategy } from './social'

const { t } = useI18n()
const { api } = useServices()
const tenant = useTenant()
const router = useRouter()

// The draft lives only in memory: the client secret is never persisted in
// the browser.
const draft = reactive({
  strategy: 'google-oauth2' as SocialStrategy,
  name: '',
  displayName: '',
  clientId: '',
  clientSecret: '',
  email: true,
  profile: true,
  authorizationURL: '',
  tokenURL: '',
  scope: '',
  script: defaultScript,
  discoveryURL: '',
  scopes: 'openid profile email',
})
const errors = reactive<Record<string, string>>({})
const general = ref('')
const uncertain = ref(false)
const busy = ref(false)
const clients = ref<Client[]>([])
const chosen = ref<string[]>([])
const clientsError = ref('')
const callbacks = computed(() => (tenant.value ? callbackURLs(tenant.value) : []))

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
  need('clientId', draft.clientId)
  need('clientSecret', draft.clientSecret)
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
  return Object.keys(errors).length === 0
}

function body(): ConnectionCreate {
  const options: Options = { client_id: draft.clientId.trim(), client_secret: draft.clientSecret }
  switch (draft.strategy) {
    case 'google-oauth2':
      options.email = draft.email
      options.profile = draft.profile
      break
    case 'oauth2':
      Object.assign(options, { authorizationURL: draft.authorizationURL.trim(), tokenURL: draft.tokenURL.trim(), scope: draft.scope.trim(), scripts: { fetchUserProfile: draft.script } })
      break
    case 'oidc':
      Object.assign(options, { type: 'back_channel', discovery_url: draft.discoveryURL.trim(), scopes: draft.scopes.trim() })
      break
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
    await router.push({ name: 'social-connection', params: { tenant: tn.name, id: c.id } })
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
  <div v-if="tenant">
    <RouterLink :to="{ name: 'social', params: { tenant: tenant.name } }">← {{ t('social.back') }}</RouterLink>
    <h1>{{ t('social.createTitle') }}</h1>
    <form class="card stack" novalidate @submit.prevent="submit">
      <Banner v-if="general" kind="error">{{ general }}</Banner>
      <Banner v-if="uncertain" kind="warn">{{ t('social.uncertainCreate') }}</Banner>
      <fieldset class="stack m-0 border-0 p-0">
        <legend class="p-0 font-bold">{{ t('social.strategy') }}</legend>
        <label v-for="s in socialStrategies" :key="s" class="check">
          <input v-model="draft.strategy" type="radio" name="strategy" :value="s" />
          <span>{{ t(`social.strategies.${s}`) }}</span>
        </label>
        <p v-if="draft.strategy === 'oidc'" class="muted" data-testid="oidc-subset">{{ t('social.oidcSubset') }}</p>
      </fieldset>
      <Field id="social-name" :label="t('social.name')" :hint="t('social.nameHint')" :error="errors.name">
        <input id="social-name" v-model="draft.name" type="text" maxlength="128" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.name" :aria-describedby="describedBy('social-name', 'name', true)" />
      </Field>
      <Field id="social-display" :label="t('social.displayName')" :hint="t('social.displayNameHint')">
        <input id="social-display" v-model="draft.displayName" type="text" maxlength="128" autocomplete="off" aria-describedby="social-display-hint" />
      </Field>
      <Field id="social-client-id" :label="t('social.clientId')" :error="errors.clientId">
        <input id="social-client-id" v-model="draft.clientId" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.clientId" :aria-describedby="describedBy('social-client-id', 'clientId')" />
      </Field>
      <Field id="social-client-secret" :label="t('social.clientSecret')" :hint="t('social.clientSecretNew')" :error="errors.clientSecret">
        <input id="social-client-secret" v-model="draft.clientSecret" type="password" autocomplete="new-password" spellcheck="false" :aria-invalid="!!errors.clientSecret" :aria-describedby="describedBy('social-client-secret', 'clientSecret', true)" />
      </Field>
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
      <template v-if="draft.strategy === 'oidc'">
        <Field id="social-discovery" :label="t('social.discoveryURL')" :error="errors.discoveryURL">
          <input id="social-discovery" v-model="draft.discoveryURL" type="url" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.discoveryURL" :aria-describedby="describedBy('social-discovery', 'discoveryURL')" />
        </Field>
        <Field id="social-scopes" :label="t('social.scopes')" :hint="t('social.scopesHint')" :error="errors.scopes">
          <input id="social-scopes" v-model="draft.scopes" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.scopes" :aria-describedby="describedBy('social-scopes', 'scopes', true)" />
        </Field>
      </template>
      <section class="stack" aria-labelledby="social-callbacks">
        <h2 id="social-callbacks" class="m-0 text-base">{{ t('social.callbacks') }}</h2>
        <p class="muted">{{ t('social.callbacksHint') }}</p>
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
      </div>
    </form>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
