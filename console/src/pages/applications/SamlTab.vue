<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Client, ClientUpdate, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
// The SAML2 Web App add-on (Plan 37a): zeroauthy is the identity provider.
const props = defineProps<{ tenant: SystemTenant; client: Client }>()
const emit = defineEmits<{ saved: [Client] }>()
const { api } = useServices(), { t } = useI18n()
type Addon = NonNullable<NonNullable<ClientUpdate['addons']>['samlp']>
const enabled = ref(false), settings = ref('{}'), busy = ref(false), error = ref(''), status = ref('')
let epoch = 0
watch(() => [props.tenant.host, props.client] as const, () => {
 ++epoch; busy.value = false; error.value = ''; status.value = ''
 const addon = props.client.addons?.samlp
 enabled.value = addon != null
 settings.value = JSON.stringify(addon ?? {}, null, 2)
}, { immediate: true })
onBeforeUnmount(() => ++epoch)
const base = computed(() => `https://${props.tenant.host}/samlp/${encodeURIComponent(props.client.client_id)}`)
const usage = computed(() => ({
 login: base.value,
 metadata: `https://${props.tenant.host}/samlp/metadata/${encodeURIComponent(props.client.client_id)}`,
 logout: `${base.value}/logout`,
 issuer: props.client.addons?.samlp?.issuer || `urn:${props.tenant.host}`,
}))
function parsed(): Addon | undefined {
 try {
  const v = JSON.parse(settings.value)
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Addon : undefined
 } catch { return undefined }
}
async function save() {
 if (busy.value) return
 const mine = epoch, tenant = props.tenant, id = props.client.client_id
 error.value = ''; status.value = ''
 let body: ClientUpdate
 if (enabled.value) {
  const addon = parsed()
  if (!addon) { error.value = t('saml37.invalidJSON'); return }
  body = { addons: { samlp: addon } }
 } else {
  if (props.client.addons?.samlp == null) return
  body = { addons: { samlp: null } }
 }
 busy.value = true
 try { const result = await api.updateClient(tenant, id, body); if (mine !== epoch) return; emit('saved', result); status.value = t('saved') }
 catch (e) { if (mine === epoch) error.value = errorMessage(e) }
 finally { if (mine === epoch) busy.value = false }
}
</script>
<template>
 <form class="card stack" data-testid="saml-settings" novalidate @submit.prevent="save">
  <Banner v-if="error" kind="error">{{ error }}</Banner>
  <fieldset class="stack" :disabled="busy">
   <label><input id="saml-enabled" v-model="enabled" type="checkbox" /> {{ t('saml37.enable') }}</label>
   <Field v-if="enabled" id="saml-settings" :label="t('saml37.settings')" :hint="t('saml37.settingsHint')"><textarea id="saml-settings" v-model="settings" rows="14" spellcheck="false" aria-describedby="saml-settings-hint" /></Field>
  </fieldset>
  <section v-if="client.addons?.samlp" class="stack" data-testid="saml-usage" aria-labelledby="saml-usage-title">
   <h2 id="saml-usage-title" class="m-0 text-base">{{ t('saml37.usage') }}</h2>
   <dl class="m-0 break-all">
    <dt>{{ t('saml37.loginURL') }}</dt><dd><code>{{ usage.login }}</code></dd>
    <dt>{{ t('saml37.metadata') }}</dt><dd><code>{{ usage.metadata }}</code></dd>
    <dt>{{ t('saml37.logoutURL') }}</dt><dd><code>{{ usage.logout }}</code></dd>
    <dt>{{ t('saml37.issuer') }}</dt><dd><code>{{ usage.issuer }}</code></dd>
   </dl>
  </section>
  <div class="actions"><Button type="submit" :busy="busy">{{ t('save') }}</Button><span v-if="status" role="status">{{ status }}</span></div>
 </form>
</template>
