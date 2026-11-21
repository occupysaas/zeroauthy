<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Client, ClientUpdate, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
const props = defineProps<{ tenant: SystemTenant; client: Client }>()
const emit = defineEmits<{ saved: [Client] }>()
const { api } = useServices(), { t } = useI18n()
type LogoutSettings = NonNullable<ClientUpdate['oidc_logout']>
type Initiator = NonNullable<NonNullable<LogoutSettings['backchannel_logout_initiators']>['selected_initiators']>[number]
const knownScopes = ['profile','email','address','phone'] as const
type Scope = typeof knownScopes[number]
const required: Initiator[] = ['rp-logout', 'idp-logout']
const optional: Initiator[] = ['password-changed', 'session-expired', 'session-revoked', 'account-deleted', 'email-identifier-changed']
const form = reactive({ url: '', mode: 'custom' as 'custom'|'all', initiators: [...required], metadata: false, alg: 'RS256' as 'RS256'|'PS256'|'HS256', support: false, allowed: true, allScopes: true, scopes: '' })
const busy = ref(false), error = ref(''), status = ref('')
let epoch = 0
watch(() => [props.tenant.host, props.client] as const, () => {
 ++epoch; busy.value = false; error.value = ''; status.value = ''
 const logout = props.client.oidc_logout, support = props.client.oidc_support
 form.url = logout?.backchannel_logout_urls?.[0] ?? ''
 form.mode = logout?.backchannel_logout_initiators?.mode ?? 'custom'
 form.initiators = [...new Set([...required, ...(logout?.backchannel_logout_initiators?.selected_initiators ?? [])])]
 form.metadata = logout?.backchannel_logout_session_metadata?.include ?? false
 form.alg = props.client.jwt_configuration.alg ?? 'RS256'
 form.support = support != null; form.allowed = support?.is_allowed ?? true
 form.allScopes = support?.allow_all_scopes ?? (support?.allowed_scopes == null); form.scopes = (support?.allowed_scopes ?? []).join(' ')
}, { immediate: true })
onBeforeUnmount(() => ++epoch)
const canHS256 = computed(() => (props.client.client_secret?.length ?? 0) >= 32 && !['spa','native'].includes(props.client.app_type) && ['client_secret_basic','client_secret_post'].includes(props.client.token_endpoint_auth_method ?? '') && !props.client.client_authentication_methods?.private_key_jwt)
function receiverValid(raw: string) {
 if (new TextEncoder().encode(raw).length > 2048 || /\s/.test(raw) || raw.includes('#')) return false
 const expanded = raw.replaceAll('{organization_name}', 'organization').replaceAll('{organization_id}', 'org_0123456789abcdef')
 if (/[{}]/.test(expanded)) return false
 try { const u = new URL(expanded); return u.protocol === 'https:' && !!u.hostname && !u.username && !u.password } catch { return false }
}
async function save() {
 if (busy.value) return
 const mine = epoch, tenant = props.tenant, id = props.client.client_id
 error.value = ''; status.value = ''
 if (form.url && !receiverValid(form.url)) { error.value = t('oidc41.invalidURL'); return }
 if (form.alg === 'HS256' && !canHS256.value) { error.value = t('oidc41.hsHint'); return }
 const body: ClientUpdate = {}
 const old = props.client.oidc_logout
 const selected = [...new Set([...required, ...form.initiators])]
 if (form.url !== (old?.backchannel_logout_urls?.[0] ?? '') || form.mode !== (old?.backchannel_logout_initiators?.mode ?? 'custom') || JSON.stringify(selected) !== JSON.stringify(old?.backchannel_logout_initiators?.selected_initiators ?? required) || form.metadata !== (old?.backchannel_logout_session_metadata?.include ?? false)) {
  body.oidc_logout = form.url ? { backchannel_logout_urls: [form.url], backchannel_logout_initiators: {mode:form.mode,selected_initiators:selected}, backchannel_logout_session_metadata:{include:form.metadata} } : null
 }
 if (form.alg !== (props.client.jwt_configuration.alg ?? 'RS256')) body.jwt_configuration = {alg:form.alg}
 const requested = [...new Set(form.scopes.trim().split(/\s+/).filter(Boolean))]
 if (form.support && !form.allScopes && requested.some(s => !(knownScopes as readonly string[]).includes(s))) { error.value = t('oidc41.invalidScopes'); return }
 const scopes = requested.filter((s): s is Scope => (knownScopes as readonly string[]).includes(s))
 const support: ClientUpdate['oidc_support'] = form.support ? (form.allScopes ? {is_allowed:form.allowed,allow_all_scopes:true} : {is_allowed:form.allowed,allowed_scopes:scopes}) : null
 const oldSupport = props.client.oidc_support
 const oldAll = oldSupport?.allow_all_scopes ?? (oldSupport?.allowed_scopes == null)
 if (form.support !== (oldSupport != null) || (form.support && (form.allowed !== oldSupport?.is_allowed || form.allScopes !== oldAll || (!form.allScopes && JSON.stringify(scopes) !== JSON.stringify(oldSupport?.allowed_scopes ?? []))))) body.oidc_support = support
 if (!Object.keys(body).length) return
 busy.value = true
 try { const result = await api.updateClient(tenant,id,body); if (mine !== epoch) return; emit('saved',result);status.value=t('saved') }
 catch (e) { if (mine === epoch) error.value=errorMessage(e) }
 finally { if (mine === epoch) busy.value=false }
}
</script>
<template>
 <form class="card stack" data-testid="oidc-settings" novalidate @submit.prevent="save">
  <Banner v-if="error" kind="error">{{ error }}</Banner>
  <fieldset class="stack" :disabled="busy">
   <legend>{{ t('oidc41.logout') }}</legend>
   <Field id="oidc-logout-url" :label="t('oidc41.receiver')" :hint="t('oidc41.receiverHint')"><input id="oidc-logout-url" v-model="form.url" type="text" maxlength="2048" aria-describedby="oidc-logout-url-hint" /></Field>
   <Field id="oidc-mode" :label="t('oidc41.initiators')"><select id="oidc-mode" v-model="form.mode"><option value="custom">{{ t('oidc41.custom') }}</option><option value="all">{{ t('oidc41.all') }}</option></select></Field>
   <div v-if="form.mode === 'custom'" class="stack">
    <label v-for="name in required" :key="name"><input :data-initiator="name" type="checkbox" checked disabled /> {{ t(`oidc41.initiator.${name}`) }}</label>
    <label v-for="name in optional" :key="name"><input :id="'oidc-initiator-'+name" v-model="form.initiators" :value="name" type="checkbox" /> {{ t(`oidc41.initiator.${name}`) }}</label>
   </div>
   <label><input id="oidc-metadata" v-model="form.metadata" type="checkbox" /> {{ t('oidc41.metadata') }}</label>
  </fieldset>
  <fieldset class="stack" :disabled="busy">
   <legend>{{ t('oidc41.tokens') }}</legend>
   <Field id="oidc-alg" :label="t('oidc41.algorithm')" :hint="canHS256 ? '' : t('oidc41.hsHint')"><select id="oidc-alg" v-model="form.alg"><option value="RS256">RS256</option><option value="PS256">PS256</option><option value="HS256" :disabled="!canHS256">HS256</option></select></Field>
   <label><input id="oidc-support-configured" v-model="form.support" type="checkbox" /> {{ t('oidc41.configure') }}</label>
   <template v-if="form.support">
    <label><input id="oidc-allowed" v-model="form.allowed" type="checkbox" /> {{ t('oidc41.allowed') }}</label>
    <label><input id="oidc-all-scopes" v-model="form.allScopes" type="checkbox" /> {{ t('oidc41.allScopes') }}</label>
    <Field v-if="!form.allScopes" id="oidc-scopes" :label="t('oidc41.scopes')" :hint="t('oidc41.scopeHint')"><input id="oidc-scopes" v-model="form.scopes" type="text" /></Field>
   </template>
  </fieldset>
  <div class="actions"><Button type="submit" :busy="busy">{{ t('save') }}</Button><span v-if="status" role="status">{{ status }}</span></div>
 </form>
</template>
