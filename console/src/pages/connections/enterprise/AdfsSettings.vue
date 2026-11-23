<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Connection, SystemTenant } from '../../../api/client'
import { errorMessage, useServices } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import { adfsCallback, adfsRealm, optionsOf, type Options } from '../social/social'
// adfs connection settings (Plan 37b): zeroauthy is the WS-Fed relying party.
const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const emit = defineEmits<{ saved: [Connection] }>()
const { api } = useServices(), { t } = useI18n()
const draft = reactive({ source: 'server' as 'server' | 'xml', server: '', xml: '', userID: '', emailVerified: false })
const errors = reactive<Record<string, string>>({})
const error = ref(''), status = ref(''), busy = ref(false)
// Derived from the metadata by the server; never sent back.
const readOnly = ['signInEndpoint', 'thumbprints', 'thumbprints_sha384', 'prev_thumbprints']
watch(() => [props.tenant.name, props.connection] as const, () => {
 const o = optionsOf(props.connection)
 Object.assign(draft, { source: typeof o.fedMetadataXml === 'string' ? 'xml' : 'server', server: String(o.adfs_server ?? ''), xml: String(o.fedMetadataXml ?? ''),
  userID: String(o.user_id_attribute ?? ''), emailVerified: o.should_trust_email_verified_connection === 'always_set_emails_as_verified' })
 for (const k of Object.keys(errors)) delete errors[k]
 error.value = ''; status.value = ''; busy.value = false
}, { immediate: true })
const realm = computed(() => adfsRealm(props.tenant, props.connection.name ?? '', optionsOf(props.connection).entityId))
const signIn = computed(() => String(optionsOf(props.connection).signInEndpoint ?? ''))
async function save() {
 if (busy.value || props.tenant.seeded) return
 for (const k of Object.keys(errors)) delete errors[k]
 error.value = ''; status.value = ''
 if (draft.source === 'server' ? !draft.server.trim() : !draft.xml.trim()) errors[draft.source] = t('social.required')
 if (Object.keys(errors).length) return
 const options: Options = { ...optionsOf(props.connection) }
 for (const k of [...readOnly, 'adfs_server', 'fedMetadataXml', 'user_id_attribute', 'should_trust_email_verified_connection']) delete options[k]
 if (draft.source === 'server') options.adfs_server = draft.server.trim(); else options.fedMetadataXml = draft.xml.trim()
 if (draft.userID.trim()) options.user_id_attribute = draft.userID.trim()
 if (draft.emailVerified) options.should_trust_email_verified_connection = 'always_set_emails_as_verified'
 const tn = props.tenant, id = props.connection.id!
 busy.value = true
 try { const saved = await api.updateConnection(tn, id, { options }); if (props.tenant.name !== tn.name || props.connection.id !== id) return; status.value = t('saved'); emit('saved', saved) }
 catch (e) { if (props.tenant.name === tn.name && props.connection.id === id) error.value = errorMessage(e) }
 finally { if (props.tenant.name === tn.name && props.connection.id === id) busy.value = false }
}
</script>
<template>
 <form class="stack" data-testid="adfs-connection" novalidate @submit.prevent="save">
  <Banner v-if="error" kind="error">{{ error }}</Banner>
  <dl class="m-0 break-all" data-testid="adfs-rp">
   <dt>{{ t('wsfed37.realm') }}</dt><dd><code>{{ realm }}</code></dd>
   <dt>{{ t('wsfed37.callback') }}</dt><dd><code>{{ adfsCallback(tenant) }}</code></dd>
   <template v-if="signIn"><dt>{{ t('saml37.signIn') }}</dt><dd><code>{{ signIn }}</code></dd></template>
  </dl>
  <fieldset class="stack" :disabled="busy || tenant.seeded">
   <Field id="adfs-source" :label="t('wsfed37.source')"><select id="adfs-source" v-model="draft.source"><option value="server">{{ t('wsfed37.fromServer') }}</option><option value="xml">{{ t('wsfed37.fromXML') }}</option></select></Field>
   <Field v-if="draft.source === 'server'" id="adfs-server" :label="t('wsfed37.server')" :hint="t('wsfed37.serverHint')" :error="errors.server"><input id="adfs-server" v-model="draft.server" type="text" spellcheck="false" :aria-invalid="!!errors.server" /></Field>
   <Field v-else id="adfs-xml" :label="t('wsfed37.xml')" :error="errors.xml"><textarea id="adfs-xml" v-model="draft.xml" rows="7" spellcheck="false" :aria-invalid="!!errors.xml" /></Field>
   <Field id="adfs-user-id" :label="t('wsfed37.userIdAttribute')"><input id="adfs-user-id" v-model="draft.userID" type="text" maxlength="128" spellcheck="false" /></Field>
   <label class="check"><input id="adfs-email-verified" v-model="draft.emailVerified" type="checkbox" /> {{ t('wsfed37.emailVerified') }}</label>
  </fieldset>
  <p v-if="status" role="status">{{ status }}</p>
  <Button type="submit" variant="primary" :disabled="busy || tenant.seeded">{{ t('save') }}</Button>
 </form>
</template>
