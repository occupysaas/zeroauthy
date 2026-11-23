<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Connection, SystemTenant } from '../../../api/client'
import { errorMessage, useServices } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import { optionsOf, type Options } from '../social/social'
// ad connection settings (Plan 38a): the provisioning ticket for Auth0's
// AD/LDAP Connector, its status and the options zeroauthy applies. The
// connector-managed options are shown, never sent back.
const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const emit = defineEmits<{ saved: [Connection] }>()
const { api } = useServices(), { t } = useI18n()
const managed = ['agentIP', 'agentMode', 'agentVersion', 'signInEndpoint', 'certs', 'thumbprints', 'thumbprints_sha384']
const draft = reactive({ domain: '', aliases: '', ips: '', kerberos: false, hideReset: false, bruteForce: true, noCache: false })
const error = ref(''), status = ref(''), busy = ref(false)
const online = ref<boolean | null>(null), statusError = ref('')
const list = (v: unknown) => Array.isArray(v) ? v.filter(x => typeof x === 'string').join(', ') : ''
const split = (s: string) => s.split(',').map(x => x.trim()).filter(Boolean)
watch(() => [props.tenant.name, props.connection] as const, () => {
 const o = optionsOf(props.connection)
 Object.assign(draft, { domain: String(o.tenant_domain ?? ''), aliases: list(o.domain_aliases), ips: list(o.ips), kerberos: o.kerberos === true,
  hideReset: o.disable_self_service_change_password === true, bruteForce: o.brute_force_protection !== false, noCache: o.disable_cache === true })
 error.value = ''; status.value = ''; busy.value = false
}, { immediate: true })
const ticket = computed(() => String((props.connection as Record<string, unknown>).provisioning_ticket_url ?? ''))
const agent = computed(() => {
 const o = optionsOf(props.connection)
 return { version: String(o.agentVersion ?? ''), address: String(o.agentIP ?? ''), signIn: String(o.signInEndpoint ?? ''), thumbprints: Array.isArray(o.thumbprints) ? o.thumbprints.map(String) : [] }
})
async function check() {
 const tn = props.tenant, id = props.connection.id!
 online.value = null; statusError.value = ''
 try { const ok = await api.getConnectionStatus(tn, id); if (props.connection.id === id) online.value = ok }
 catch (e) { if (props.connection.id === id) statusError.value = errorMessage(e) }
}
onMounted(check)
async function save() {
 if (busy.value || props.tenant.seeded) return
 error.value = ''; status.value = ''
 const options: Options = { ...optionsOf(props.connection) }
 for (const k of [...managed, 'tenant_domain', 'domain_aliases', 'ips']) delete options[k]
 if (draft.domain.trim()) options.tenant_domain = draft.domain.trim().toLowerCase()
 if (split(draft.aliases).length) options.domain_aliases = split(draft.aliases)
 if (split(draft.ips).length) options.ips = split(draft.ips)
 Object.assign(options, { kerberos: draft.kerberos, disable_self_service_change_password: draft.hideReset, brute_force_protection: draft.bruteForce, disable_cache: draft.noCache })
 const tn = props.tenant, id = props.connection.id!
 busy.value = true
 try { const saved = await api.updateConnection(tn, id, { options }); if (props.tenant.name !== tn.name || props.connection.id !== id) return; status.value = t('saved'); emit('saved', saved) }
 catch (e) { if (props.tenant.name === tn.name && props.connection.id === id) error.value = errorMessage(e) }
 finally { if (props.tenant.name === tn.name && props.connection.id === id) busy.value = false }
}
</script>
<template>
 <form class="stack" data-testid="ad-connection" novalidate @submit.prevent="save">
  <Banner v-if="error" kind="error">{{ error }}</Banner>
  <dl class="m-0 break-all" data-testid="ad-connector">
   <dt>{{ t('ad38.ticket') }}</dt><dd><code data-testid="ad-ticket">{{ ticket }}</code><p class="muted">{{ t('ad38.ticketHint') }}</p></dd>
   <dt>{{ t('ad38.status') }}</dt>
   <dd data-testid="ad-status">
    <span v-if="statusError" class="error">{{ statusError }}</span>
    <span v-else-if="online === null">{{ t('ad38.checking') }}</span>
    <span v-else>{{ online ? t('ad38.online') : t('ad38.offline') }}</span>
    <Button type="button" variant="secondary" @click="check">{{ t('ad38.refresh') }}</Button>
   </dd>
   <template v-if="agent.version || agent.address"><dt>{{ t('ad38.agent') }}</dt><dd>{{ t('ad38.version') }} {{ agent.version }} · {{ t('ad38.address') }} {{ agent.address }}</dd></template>
   <template v-if="agent.signIn"><dt>{{ t('ad38.signIn') }}</dt><dd><code>{{ agent.signIn }}</code></dd></template>
   <template v-if="agent.thumbprints.length"><dt>{{ t('ad38.certificates') }}</dt><dd><code v-for="p in agent.thumbprints" :key="p" class="block">{{ p }}</code></dd></template>
  </dl>
  <fieldset class="stack" :disabled="busy || tenant.seeded">
   <Field id="ad-domain" :label="t('ad38.domain')" :hint="t('ad38.domainHint')"><input id="ad-domain" v-model="draft.domain" type="text" spellcheck="false" /></Field>
   <Field id="ad-aliases" :label="t('ad38.aliases')" :hint="t('ad38.aliasesHint')"><input id="ad-aliases" v-model="draft.aliases" type="text" spellcheck="false" /></Field>
   <Field id="ad-ips" :label="t('ad38.ips')" :hint="t('ad38.ipsHint')"><input id="ad-ips" v-model="draft.ips" type="text" spellcheck="false" /></Field>
   <label class="check"><input id="ad-kerberos" v-model="draft.kerberos" type="checkbox" /> {{ t('ad38.kerberos') }}</label>
   <label class="check"><input id="ad-hide-reset" v-model="draft.hideReset" type="checkbox" /> {{ t('ad38.changePassword') }}</label>
   <label class="check"><input id="ad-brute-force" v-model="draft.bruteForce" type="checkbox" /> {{ t('ad38.bruteForce') }}</label>
   <label class="check"><input id="ad-cache" v-model="draft.noCache" type="checkbox" /> {{ t('ad38.cache') }}</label>
  </fieldset>
  <p v-if="status" role="status">{{ status }}</p>
  <Button type="submit" variant="primary" :disabled="busy || tenant.seeded">{{ t('save') }}</Button>
 </form>
</template>
