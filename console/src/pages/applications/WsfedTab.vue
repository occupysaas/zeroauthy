<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Client, ClientUpdate, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
// The WS-Fed Web App add-on (Plan 37b): zeroauthy is the WS-Federation
// identity provider. As in Auth0, the reply URLs are the application's
// callbacks and the realms are client_aliases.
const props = defineProps<{ tenant: SystemTenant; client: Client }>()
const emit = defineEmits<{ saved: [Client] }>()
const { api } = useServices(), { t } = useI18n()
const enabled = ref(false), aliases = ref(''), busy = ref(false), error = ref(''), status = ref('')
let epoch = 0
watch(() => [props.tenant.host, props.client] as const, () => {
 ++epoch; busy.value = false; error.value = ''; status.value = ''
 enabled.value = props.client.addons?.wsfed != null
 aliases.value = (props.client.client_aliases ?? []).join('\n')
}, { immediate: true })
onBeforeUnmount(() => ++epoch)
const host = computed(() => `https://${props.tenant.host}`)
const usage = computed(() => ({
 login: `${host.value}/wsfed/${encodeURIComponent(props.client.client_id)}`,
 metadata: `${host.value}/wsfed/FederationMetadata/2007-06/FederationMetadata.xml`,
 realms: [props.client.client_id, ...(props.client.client_aliases ?? [])],
 issuer: `urn:${props.tenant.host}`,
}))
async function save() {
 if (busy.value) return
 const mine = epoch, tenant = props.tenant, id = props.client.client_id
 error.value = ''; status.value = ''
 const list = aliases.value.split('\n').map(s => s.trim()).filter(s => s !== '')
 // PATCH replaces the whole addons object: keep the SAML add-on.
 const addons: NonNullable<ClientUpdate['addons']> = { ...(props.client.addons?.samlp ? { samlp: props.client.addons.samlp } : {}), wsfed: enabled.value ? (props.client.addons?.wsfed ?? {}) : null }
 const body: ClientUpdate = { addons, client_aliases: list }
 busy.value = true
 try { const result = await api.updateClient(tenant, id, body); if (mine !== epoch) return; emit('saved', result); status.value = t('saved') }
 catch (e) { if (mine === epoch) error.value = errorMessage(e) }
 finally { if (mine === epoch) busy.value = false }
}
</script>
<template>
 <form class="card stack" data-testid="wsfed-settings" novalidate @submit.prevent="save">
  <Banner v-if="error" kind="error">{{ error }}</Banner>
  <fieldset class="stack" :disabled="busy">
   <label><input id="wsfed-enabled" v-model="enabled" type="checkbox" /> {{ t('wsfed37.enable') }}</label>
   <Field id="wsfed-aliases" :label="t('wsfed37.realms')" :hint="t('wsfed37.realmsHint')"><textarea id="wsfed-aliases" v-model="aliases" rows="4" spellcheck="false" aria-describedby="wsfed-aliases-hint" /></Field>
   <p class="m-0">{{ t('wsfed37.callbacksHint') }}</p>
  </fieldset>
  <section v-if="client.addons?.wsfed" class="stack" data-testid="wsfed-usage" aria-labelledby="wsfed-usage-title">
   <h2 id="wsfed-usage-title" class="m-0 text-base">{{ t('wsfed37.usage') }}</h2>
   <dl class="m-0 break-all">
    <dt>{{ t('wsfed37.loginURL') }}</dt><dd><code>{{ usage.login }}</code></dd>
    <dt>{{ t('wsfed37.metadata') }}</dt><dd><code>{{ usage.metadata }}</code></dd>
    <dt>{{ t('wsfed37.realmsAccepted') }}</dt><dd><code v-for="r in usage.realms" :key="r" class="block">{{ r }}</code></dd>
    <dt>{{ t('wsfed37.issuer') }}</dt><dd><code>{{ usage.issuer }}</code></dd>
   </dl>
  </section>
  <div class="actions"><Button type="submit" :busy="busy">{{ t('save') }}</Button><span v-if="status" role="status">{{ status }}</span></div>
 </form>
</template>
