<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type Connection, type ConnectionUpdate, type SystemTenant } from '../../../api/client'
import { errorMessage, useServices } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import ScriptEditor from './ScriptEditor.vue'
import MicrosoftOptions from './MicrosoftOptions.vue'
import { callbackURLs, optionsOf, type Options } from './social'

const { t } = useI18n()
const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const emit = defineEmits<{ saved: [Connection] }>()
const { api } = useServices()

const syncModes = ['on_each_login', 'on_first_login', 'never_on_login'] as const

// The editable draft. It is reset from the connection only when another
// connection is shown or after a save of ours: a failed reload in the parent
// never discards edits.
const draft = reactive({ displayName: '', showAsButton: true, active: true, sync: 'on_each_login', scope: '', scopes: '', email: true, profile: true, newSecret: '' })
const errors = reactive<Record<string, string>>({})
const general = ref('')
const status = ref('')
const uncertain = ref(false)
const busy = ref(false)

const strategy = computed(() => props.connection.strategy ?? '')
const options = computed(() => optionsOf(props.connection))
const script = computed(() => {
  const s = (options.value.scripts as Options | undefined)?.fetchUserProfile
  return typeof s === 'string' ? s : ''
})
const callbacks = computed(() => callbackURLs(props.tenant))

function reset(c: Connection) {
  const o = optionsOf(c)
  const top = c as Record<string, unknown>
  draft.displayName = typeof top.display_name === 'string' ? top.display_name : ''
  draft.showAsButton = top.show_as_button !== false
  draft.active = (top.authentication as Options | undefined)?.active !== false
  draft.sync = typeof o.set_user_root_attributes === 'string' ? o.set_user_root_attributes : 'on_each_login'
  draft.scope = typeof o.scope === 'string' ? o.scope : ''
  draft.scopes = typeof o.scopes === 'string' ? o.scopes : ''
  draft.email = o.email !== false
  draft.profile = o.profile !== false
  draft.newSecret = ''
}
watch(() => props.connection.id, () => reset(props.connection), { immediate: true })

function validate(): boolean {
  for (const k of Object.keys(errors)) delete errors[k]
  if (draft.newSecret && !draft.newSecret.trim()) errors.newSecret = t('social.required')
  if (strategy.value === 'oauth2' && !draft.scope.trim()) errors.scope = t('social.required')
  if (strategy.value === 'oidc' && !draft.scopes.split(/\s+/).includes('openid')) errors.scopes = t('social.openidRequired')
  return Object.keys(errors).length === 0
}

async function save() {
  general.value = ''
  status.value = ''
  uncertain.value = false
  if (busy.value || !validate()) return
  // options replaces the stored options whole, so start from every option
  // the connection returned (the immutable ones included); the secret is
  // sent only when replaced.
  const opts: Options = { ...options.value }
  delete opts.client_secret
  if (draft.sync === 'on_each_login' && opts.set_user_root_attributes === undefined) delete opts.set_user_root_attributes
  else opts.set_user_root_attributes = draft.sync
  if (strategy.value === 'oauth2') opts.scope = draft.scope.trim()
  if (strategy.value === 'oidc') opts.scopes = draft.scopes.trim()
  if (strategy.value === 'google-oauth2') {
    opts.email = draft.email
    opts.profile = draft.profile
    delete opts.scope
  }
  if (draft.newSecret) opts.client_secret = draft.newSecret
  const body: Record<string, unknown> = {
    options: opts,
    show_as_button: draft.showAsButton,
    authentication: { active: draft.active },
  }
  if (draft.displayName.trim()) body.display_name = draft.displayName.trim()
  const tenantName = props.tenant.name
  const id = props.connection.id
  busy.value = true
  try {
    const saved = await api.updateConnection(props.tenant, id, body as ConnectionUpdate)
    if (props.tenant.name !== tenantName || props.connection.id !== id) return // navigated away
    emit('saved', saved)
    reset(saved)
    status.value = t('social.saved')
  } catch (e) {
    if (e instanceof ApiError) general.value = errorMessage(e)
    else uncertain.value = true
  } finally {
    busy.value = false
  }
}

function fixed(key: string): string {
  const v = options.value[key]
  return typeof v === 'string' ? v : ''
}
</script>

<template>
  <form class="card stack" novalidate @submit.prevent="save">
    <Banner v-if="general" kind="error">{{ general }}</Banner>
    <Banner v-if="uncertain" kind="warn">{{ t('social.uncertainSave') }}</Banner>
    <p v-if="status" class="muted" role="status">{{ status }}</p>
    <p v-if="strategy === 'oidc'" class="muted" data-testid="oidc-subset">{{ t('social.oidcSubset') }}</p>

    <Field id="social-display" :label="t('social.displayName')" :hint="t('social.displayNameHint')">
      <input id="social-display" v-model="draft.displayName" type="text" maxlength="128" autocomplete="off" aria-describedby="social-display-hint" />
    </Field>
    <label class="check"><input id="social-button" v-model="draft.showAsButton" type="checkbox" /> <span>{{ t('social.showAsButton') }}</span></label>
    <p class="muted">{{ t('social.showAsButtonHint') }}</p>
    <label class="check"><input id="social-active" v-model="draft.active" type="checkbox" /> <span>{{ t('social.active') }}</span></label>

    <Field id="social-client-id" :label="t('social.clientId')" :hint="t('social.clientIdFixed')">
      <input id="social-client-id" :value="fixed('client_id')" type="text" readonly aria-describedby="social-client-id-hint" />
    </Field>
    <Field id="social-secret" :label="t('social.clientSecretReplace')" :hint="t('social.clientSecretKeep')" :error="errors.newSecret">
      <input id="social-secret" v-model="draft.newSecret" type="password" autocomplete="new-password" spellcheck="false" :aria-invalid="!!errors.newSecret" :aria-describedby="errors.newSecret ? 'social-secret-hint social-secret-error' : 'social-secret-hint'" />
    </Field>

    <MicrosoftOptions v-if="strategy === 'windowslive' || strategy === 'waad'" :strategy="strategy" :mode="options.useCommonEndpoint === true ? 'organizations' : 'single'" :tenant-domain="fixed('tenant_domain')" readonly />

    <template v-if="strategy === 'google-oauth2'">
      <label class="check"><input v-model="draft.email" type="checkbox" /> <span>{{ t('social.googleEmail') }}</span></label>
      <label class="check"><input v-model="draft.profile" type="checkbox" /> <span>{{ t('social.googleProfile') }}</span></label>
    </template>
    <template v-if="strategy === 'oauth2'">
      <Field id="social-authorize" :label="t('social.authorizationURL') + ' · ' + t('social.immutable')">
        <input id="social-authorize" :value="fixed('authorizationURL')" type="url" readonly />
      </Field>
      <Field id="social-token" :label="t('social.tokenURL') + ' · ' + t('social.immutable')">
        <input id="social-token" :value="fixed('tokenURL')" type="url" readonly />
      </Field>
      <Field id="social-scope" :label="t('social.scope')" :hint="t('social.scopeHint')" :error="errors.scope">
        <input id="social-scope" v-model="draft.scope" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.scope" aria-describedby="social-scope-hint" />
      </Field>
      <ScriptEditor id="social-script" :model-value="script" :label="t('social.script') + ' · ' + t('social.immutable')" readonly />
    </template>
    <template v-if="strategy === 'oidc'">
      <Field id="social-discovery" :label="t('social.discoveryURL') + ' · ' + t('social.immutable')">
        <input id="social-discovery" :value="fixed('discovery_url')" type="url" readonly />
      </Field>
      <Field id="social-scopes" :label="t('social.scopes')" :hint="t('social.scopesHint')" :error="errors.scopes">
        <input id="social-scopes" v-model="draft.scopes" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.scopes" aria-describedby="social-scopes-hint" />
      </Field>
    </template>

    <Field id="social-sync" :label="t('social.sync')">
      <select id="social-sync" v-model="draft.sync">
        <option v-for="m in syncModes" :key="m" :value="m">{{ t(`social.syncOptions.${m}`) }}</option>
      </select>
    </Field>

    <section class="stack" aria-labelledby="social-callbacks">
      <h2 id="social-callbacks" class="m-0 text-base">{{ t('social.callbacks') }}</h2>
      <p class="muted">{{ t('social.callbacksHint') }}</p>
      <ul class="m-0 break-all" data-testid="callbacks">
        <li v-for="u in callbacks" :key="u"><code>{{ u }}</code></li>
      </ul>
    </section>
    <div class="row">
      <Button variant="primary" type="submit" :disabled="busy">{{ t('social.save') }}</Button>
    </div>
  </form>
</template>
