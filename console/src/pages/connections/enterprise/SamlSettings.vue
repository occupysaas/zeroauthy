<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Connection, SystemTenant } from '../../../api/client'
import { errorMessage, useServices } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import { httpsURL, optionsOf, samlACS, samlCertificate, type Options } from '../social/social'
// samlp connection settings (Plan 37a): zeroauthy is the service provider.
const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const emit = defineEmits<{ saved: [Connection] }>()
const { api } = useServices(), { t } = useI18n()
const draft = reactive({ signIn: '', signOut: '', cert: '', signRequest: false, disableSignout: false, idp: false, idpClient: '', idpQuery: '', fields: '{}' })
const errors = reactive<Record<string, string>>({})
const error = ref(''), status = ref(''), busy = ref(false)
watch(() => [props.tenant.name, props.connection] as const, () => {
 const o = optionsOf(props.connection), idp = (o.idpinitiated ?? {}) as Options
 Object.assign(draft, { signIn: String(o.signInEndpoint ?? ''), signOut: String(o.signOutEndpoint ?? ''), cert: '', signRequest: o.signSAMLRequest === true, disableSignout: o.disableSignout === true,
  idp: idp.enabled === true, idpClient: String(idp.client_id ?? ''), idpQuery: String(idp.client_authorizequery ?? ''), fields: JSON.stringify(o.fieldsMap ?? {}, null, 2) })
 for (const k of Object.keys(errors)) delete errors[k]
 error.value = ''; status.value = ''; busy.value = false
}, { immediate: true })
const entityID = computed(() => String(optionsOf(props.connection).entityId || `urn:auth0:${props.tenant.name}:${props.connection.name}`))
const acs = computed(() => samlACS(props.tenant, props.connection.name ?? ''))
const spMetadata = computed(() => `https://${props.tenant.host}/samlp/metadata?connection=${encodeURIComponent(props.connection.name ?? '')}`)
async function save() {
 if (busy.value || props.tenant.seeded) return
 for (const k of Object.keys(errors)) delete errors[k]
 error.value = ''; status.value = ''
 if (!httpsURL(draft.signIn.trim())) errors.signIn = t('social.httpsRequired')
 if (draft.signOut.trim() && !httpsURL(draft.signOut.trim())) errors.signOut = t('social.httpsRequired')
 if (draft.cert.trim() && !samlCertificate(draft.cert)) errors.cert = t('saml37.certInvalid')
 let fields: unknown
 try { fields = JSON.parse(draft.fields) } catch { fields = undefined }
 if (fields === null || typeof fields !== 'object' || Array.isArray(fields)) errors.fields = t('saml37.invalidJSON')
 if (Object.keys(errors).length) return
 // Thumbprints are read-only and recomputed by the server from the
 // certificates; a pasted certificate replaces the stored one.
 const options: Options = { ...optionsOf(props.connection), signInEndpoint: draft.signIn.trim(), signSAMLRequest: draft.signRequest, disableSignout: draft.disableSignout, fieldsMap: fields as Options,
  idpinitiated: { enabled: draft.idp, client_id: draft.idpClient.trim(), client_authorizequery: draft.idpQuery.trim() } }
 if (draft.signOut.trim()) options.signOutEndpoint = draft.signOut.trim(); else delete options.signOutEndpoint
 delete options.thumbprints; delete options.thumbprints_sha384
 if (draft.cert.trim()) options.signingCert = draft.cert.trim()
 const tn = props.tenant, id = props.connection.id!
 busy.value = true
 try { const saved = await api.updateConnection(tn, id, { options }); if (props.tenant.name !== tn.name || props.connection.id !== id) return; status.value = t('saved'); emit('saved', saved) }
 catch (e) { if (props.tenant.name === tn.name && props.connection.id === id) error.value = errorMessage(e) }
 finally { if (props.tenant.name === tn.name && props.connection.id === id) busy.value = false }
}
</script>
<template>
 <form class="stack" data-testid="saml-connection" novalidate @submit.prevent="save">
  <Banner v-if="error" kind="error">{{ error }}</Banner>
  <section class="stack" data-testid="saml-sp" aria-labelledby="saml-sp-title">
   <h2 id="saml-sp-title" class="m-0 text-base">{{ t('saml37.sp') }}</h2>
   <dl class="m-0 break-all">
    <dt>{{ t('saml37.entityID') }}</dt><dd><code>{{ entityID }}</code></dd>
    <dt>{{ t('saml37.acs') }}</dt><dd><code>{{ acs }}</code></dd>
    <dt>{{ t('saml37.spMetadata') }}</dt><dd><code>{{ spMetadata }}</code></dd>
   </dl>
  </section>
  <fieldset class="stack" :disabled="busy || tenant.seeded">
   <Field id="saml-signin" :label="t('saml37.signIn')" :error="errors.signIn"><input id="saml-signin" v-model="draft.signIn" type="url" spellcheck="false" :aria-invalid="!!errors.signIn" /></Field>
   <Field id="saml-signout" :label="t('saml37.signOut')" :error="errors.signOut"><input id="saml-signout" v-model="draft.signOut" type="url" spellcheck="false" :aria-invalid="!!errors.signOut" /></Field>
   <Field id="saml-cert" :label="t('saml37.signingCert')" :hint="t('saml37.replaceCertHint')" :error="errors.cert"><textarea id="saml-cert" v-model="draft.cert" rows="6" spellcheck="false" :aria-invalid="!!errors.cert" /></Field>
   <label class="check"><input id="saml-sign-request" v-model="draft.signRequest" type="checkbox" /> {{ t('saml37.signRequest') }}</label>
   <label class="check"><input id="saml-disable-signout" v-model="draft.disableSignout" type="checkbox" /> {{ t('saml37.disableSignout') }}</label>
   <label class="check"><input id="saml-idp" v-model="draft.idp" type="checkbox" /> {{ t('saml37.idpInitiated') }}</label>
   <template v-if="draft.idp">
    <Field id="saml-idp-client" :label="t('saml37.idpClient')"><input id="saml-idp-client" v-model="draft.idpClient" type="text" spellcheck="false" /></Field>
    <Field id="saml-idp-query" :label="t('saml37.idpQuery')"><input id="saml-idp-query" v-model="draft.idpQuery" type="text" spellcheck="false" /></Field>
   </template>
   <Field id="saml-fields" :label="t('saml37.fieldsMap')" :error="errors.fields"><textarea id="saml-fields" v-model="draft.fields" rows="6" spellcheck="false" :aria-invalid="!!errors.fields" /></Field>
  </fieldset>
  <p v-if="status" role="status">{{ status }}</p>
  <Button type="submit" variant="primary" :disabled="busy || tenant.seeded">{{ t('save') }}</Button>
 </form>
</template>
