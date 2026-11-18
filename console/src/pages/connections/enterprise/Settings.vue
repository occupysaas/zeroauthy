<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import type { Connection, SystemTenant } from '../../../api/client'
import { errorMessage, useServices } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import StoredMark from '../StoredMark.vue'
import { optionsOf, type Options } from '../social/social'
const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const emit = defineEmits<{ saved: [Connection] }>()
const { api } = useServices()
const options = computed(() => optionsOf(props.connection))
const draft = reactive({ channel: 'back_channel', scope: '', pkce: 'auto', auth: '', alg: 'RS256', aud: 'issuer', enc: '', encs: '', nonce: true, par: false, parURL: '', secret: '', metadata: '', authorization_endpoint: '', token_endpoint: '', jwks_uri: '', userinfo_endpoint: '' })
const error = ref(''), status = ref(''), busy = ref(false)
const endpoints = ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint'] as const
const signing = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'ES256', 'ES384']
const encryption = ['RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']
const stored = ['tenant_domain', 'useOauthSpecScope', 'non_persistent_attrs', 'id_token_session_expiry_supported', 'upstream_params']
watch(() => [props.tenant.name, props.connection.id], () => {
 const o = options.value
 draft.channel = props.connection.strategy === 'okta' ? 'back_channel' : String(o.type ?? 'front_channel')
 draft.scope = String(o.scope ?? o.scopes ?? 'openid profile email')
 draft.pkce = String((o.connection_settings as Options | undefined)?.pkce ?? 'auto')
 draft.auth = String(o.token_endpoint_auth_method ?? ''); draft.alg = String(o.token_endpoint_auth_signing_alg ?? 'RS256'); draft.aud = String(o.token_endpoint_jwtca_aud_format ?? 'issuer')
 draft.enc = String(o.id_token_encrypted_response_alg ?? ''); draft.encs = ((o.id_token_encrypted_response_encs as string[] | undefined) ?? []).join(' ')
 draft.nonce = o.send_back_channel_nonce !== false; draft.par = o.enable_pushed_authorization_requests === true; draft.parURL = String(o.pushed_authorization_request_endpoint ?? '')
 draft.metadata = o.oidc_metadata ? JSON.stringify(o.oidc_metadata, null, 2) : ''; draft.secret = ''
 for (const k of endpoints) draft[k] = String(o[k] ?? '')
 error.value = ''; status.value = ''; busy.value = false
}, { immediate: true })
async function save() {
 if (busy.value || props.tenant.seeded) return
 error.value = ''; status.value = ''
 const opts: Options = { ...options.value, type: draft.channel, scope: draft.scope, connection_settings: { ...((options.value.connection_settings as Options | undefined) ?? {}), pkce: draft.pkce }, send_back_channel_nonce: draft.nonce }
 delete opts.scopes; delete opts.client_secret
 if (draft.channel === 'back_channel') {
  if (draft.auth) opts.token_endpoint_auth_method = draft.auth; else delete opts.token_endpoint_auth_method
  opts.token_endpoint_auth_signing_alg = draft.alg; opts.token_endpoint_jwtca_aud_format = draft.aud
  opts.enable_pushed_authorization_requests = draft.par
  if (draft.parURL) opts.pushed_authorization_request_endpoint = draft.parURL; else delete opts.pushed_authorization_request_endpoint
  if (draft.secret) opts.client_secret = draft.secret
 } else { delete opts.token_endpoint_auth_method; delete opts.enable_pushed_authorization_requests; delete opts.pushed_authorization_request_endpoint }
 if (draft.enc) opts.id_token_encrypted_response_alg = draft.enc; else delete opts.id_token_encrypted_response_alg
 opts.id_token_encrypted_response_encs = draft.encs.split(/\s+/).filter(Boolean)
 for (const k of endpoints) { if (draft[k]) opts[k] = draft[k]; else delete opts[k] }
 try { if (draft.metadata.trim()) { const m: unknown = JSON.parse(draft.metadata); if (!m || Array.isArray(m) || typeof m !== 'object') throw Error('Metadata must be a JSON object.'); opts.oidc_metadata = m } else delete opts.oidc_metadata } catch (e) { error.value = errorMessage(e); return }
 const tn = props.tenant, id = props.connection.id!
 busy.value = true
 try { const saved = await api.updateConnection(tn, id, { options: opts }); if (props.tenant.name !== tn.name || props.connection.id !== id) return; draft.secret = ''; status.value = 'Saved.'; emit('saved', saved) } catch (e) { if (props.tenant.name === tn.name && props.connection.id === id) error.value = errorMessage(e) } finally { if (props.tenant.name === tn.name && props.connection.id === id) busy.value = false }
}
</script>
<template>
 <form class="stack" @submit.prevent="save">
  <Banner v-if="error" kind="error">{{ error }}</Banner><p v-if="status" role="status">{{ status }}</p>
  <Field id="enterprise-client-id" label="Client ID"><input id="enterprise-client-id" :value="options.client_id" readonly /></Field>
  <Field v-if="options.domain" id="enterprise-domain" label="Okta domain"><input id="enterprise-domain" :value="options.domain" readonly /></Field>
  <Field v-if="options.discovery_url" id="enterprise-discovery" label="Discovery URL"><input id="enterprise-discovery" :value="options.discovery_url" readonly /></Field>
  <Field v-if="options.issuer" id="enterprise-issuer" label="Issuer"><input id="enterprise-issuer" :value="options.issuer" readonly /></Field>
  <Field v-if="connection.strategy === 'oidc'" id="enterprise-channel" label="Login channel"><select id="enterprise-channel" v-model="draft.channel"><option value="back_channel">Authorization code (back channel)</option><option value="front_channel">ID token form post (front channel)</option></select></Field>
  <Field id="enterprise-scope" label="Scopes"><input id="enterprise-scope" v-model="draft.scope" /></Field>
  <Field id="enterprise-pkce" label="PKCE"><select id="enterprise-pkce" v-model="draft.pkce"><option v-for="mode in ['auto','S256','plain','disabled']" :key="mode" :value="mode">{{ mode }}{{ mode === 'plain' || mode === 'disabled' ? ' (weaker)' : '' }}</option></select></Field>
  <Banner v-if="draft.pkce === 'plain' || draft.pkce === 'disabled'" kind="warn">This PKCE mode provides weaker protection. Prefer S256 when supported by the provider.</Banner>
  <template v-if="draft.channel === 'back_channel'">
   <Field id="enterprise-auth" label="Token endpoint authentication"><select id="enterprise-auth" v-model="draft.auth"><option value="">Use discovery</option><option value="client_secret_post">Client secret POST</option><option value="private_key_jwt">Private key JWT</option></select></Field>
   <Field id="enterprise-secret" label="Replace client secret" hint="Leave empty to keep the stored secret."><input id="enterprise-secret" v-model="draft.secret" type="password" autocomplete="new-password" /></Field>
   <template v-if="draft.auth === 'private_key_jwt'"><Field id="enterprise-assertion-alg" label="Assertion signing algorithm"><select id="enterprise-assertion-alg" v-model="draft.alg"><option v-for="alg in signing" :key="alg">{{ alg }}</option></select></Field><Field id="enterprise-assertion-aud" label="Assertion audience"><select id="enterprise-assertion-aud" v-model="draft.aud"><option value="issuer">Issuer</option><option value="token_endpoint">Token endpoint</option></select></Field></template>
   <label class="check"><input v-model="draft.nonce" type="checkbox" /> Send and validate a back-channel nonce</label>
   <label class="check"><input v-model="draft.par" type="checkbox" /> Use pushed authorization requests</label>
   <Field v-if="draft.par" id="enterprise-par" label="PAR endpoint" hint="Leave empty to use provider metadata."><input id="enterprise-par" v-model="draft.parURL" type="url" /></Field>
  </template>
  <Field id="enterprise-encryption" label="ID token encryption"><select id="enterprise-encryption" v-model="draft.enc"><option value="">Unencrypted ID tokens</option><option v-for="alg in encryption" :key="alg">{{ alg }}</option></select></Field>
  <Field v-if="draft.enc" id="enterprise-encryption-content" label="Allowed content algorithms" hint="Space-separated; empty accepts the supported algorithms."><input id="enterprise-encryption-content" v-model="draft.encs" /></Field>
  <details><summary>Provider endpoints and metadata</summary><p>All endpoints require HTTPS. Nonempty metadata takes precedence over discovery.</p><Field v-for="key in endpoints" :id="`enterprise-${key}`" :key="key" :label="key"><input :id="`enterprise-${key}`" v-model="draft[key]" type="url" /></Field><Field id="enterprise-metadata" label="OIDC metadata (JSON)"><textarea id="enterprise-metadata" v-model="draft.metadata" rows="8" spellcheck="false" /></Field></details>
  <p v-for="key in stored.filter(key => options[key] !== undefined)" :key="key"><code>{{ key }}</code><StoredMark /></p>
  <Button type="submit" variant="primary" :disabled="busy || tenant.seeded">Save settings</Button>
 </form>
</template>
