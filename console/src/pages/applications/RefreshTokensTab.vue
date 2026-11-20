<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Client, ClientUpdate, ResourceServer, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import QuotaEditor from '../token-settings/QuotaEditor.vue'
import { quotaDraft, quotaValue } from '../token-settings/quota'
const props = defineProps<{ tenant: SystemTenant; client: Client }>(), emit = defineEmits<{ saved: [Client] }>()
const { t } = useI18n(), { api } = useServices()
const form = reactive({ rotation: 'non-rotating' as 'rotating'|'non-rotating', expiration: 'non-expiring' as 'expiring'|'non-expiring', leeway: '0', absolute: '', idle: '', proof: false })
const quota = ref(quotaDraft()), policies = ref<{ audience: string; scope: string[] }[]>([]), servers = ref<ResourceServer[]>([])
const error = ref(''), status = ref(''), busy = ref(false), loadingApis = ref(false)
let epoch = 0
const audiences = computed(() => servers.value.filter(s => !s.is_system && s.identifier !== props.tenant.management_api_identifier && s.identifier !== 'urn:zeroauthy:management'))
function scopes(audience: string) { return audiences.value.find(s => s.identifier === audience)?.scopes ?? [] }
watch(() => [props.tenant.host, props.client] as const, async () => {
  const mine = ++epoch; error.value = ''; status.value = ''; busy.value = false
  form.rotation = props.client.refresh_token.rotation_type ?? 'non-rotating'; form.expiration = props.client.refresh_token.expiration_type ?? 'non-expiring'
  form.leeway = String(props.client.refresh_token.leeway ?? 0); form.absolute = String(props.client.refresh_token.token_lifetime ?? ''); form.idle = String(props.client.refresh_token.idle_token_lifetime ?? '')
  form.proof = props.client.require_proof_of_possession === true
  quota.value = quotaDraft(props.client.token_quota)
  policies.value = (props.client.refresh_token.policies ?? []).map(p => ({ audience: p.audience, scope: [...p.scope] }))
  servers.value = []; loadingApis.value = props.client.is_first_party
  if (!props.client.is_first_party) return
  try { const values = await api.allResourceServers(props.tenant); if (mine === epoch) servers.value = values }
  catch (e) { if (mine === epoch) error.value = errorMessage(e) }
  finally { if (mine === epoch) loadingApis.value = false }
}, { immediate: true })
onBeforeUnmount(() => ++epoch)
function add() { if (policies.value.length < 10) policies.value.push({ audience: '', scope: [] }) }
async function save() {
  if (busy.value) return
  error.value = ''; status.value = ''
  const mine = epoch, tenant = props.tenant, id = props.client.client_id
  try {
    const refresh: NonNullable<ClientUpdate['refresh_token']> = { rotation_type: form.rotation, expiration_type: form.expiration }
    for (const [key, text] of [['leeway', form.leeway], ['token_lifetime', form.absolute], ['idle_token_lifetime', form.idle]] as const) {
      if (!text.trim()) continue
      if (!/^\d+$/.test(text.trim()) || !Number.isSafeInteger(Number(text))) throw new Error(t('rt48.invalidSeconds'))
      refresh[key] = Number(text)
    }
    if (props.client.is_first_party) {
      if (policies.value.length > 10 || policies.value.some(p => !p.audience || [...p.audience].length > 600 || p.scope.some(s => [...s].length > 280)) || new Set(policies.value.map(p => p.audience)).size !== policies.value.length) throw new Error(t('rt48.invalidPolicies'))
      refresh.policies = policies.value.length ? policies.value.map(p => ({ audience: p.audience, scope: [...p.scope] })) : null
    }
    const body: ClientUpdate = { refresh_token: refresh, require_proof_of_possession: form.proof, token_quota: quotaValue(quota.value) }
    busy.value = true
    const result = await api.updateClient(tenant, id, body)
    if (mine !== epoch) return
    emit('saved', result); status.value = t('saved')
  } catch (e) { if (mine === epoch) error.value = errorMessage(e) }
  finally { if (mine === epoch) busy.value = false }
}
</script>
<template>
  <form class="card stack" data-testid="refresh-settings" novalidate @submit.prevent="save">
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <fieldset class="stack" :disabled="busy"><legend>{{ t('rt48.refresh') }}</legend>
      <div class="grid gap-4 sm:grid-cols-2">
        <Field id="refresh-rotation" :label="t('apps.rotation')"><select id="refresh-rotation" v-model="form.rotation"><option value="rotating">{{ t('apps.rotating') }}</option><option value="non-rotating">{{ t('apps.nonRotating') }}</option></select></Field>
        <Field id="refresh-expiration" :label="t('apps.expiration')"><select id="refresh-expiration" v-model="form.expiration"><option value="expiring">{{ t('apps.expiring') }}</option><option value="non-expiring">{{ t('apps.nonExpiring') }}</option></select></Field>
      </div>
      <Field id="refresh-leeway" :label="t('rt48.leeway')" :hint="t('rt48.leewayHint')"><input id="refresh-leeway" v-model="form.leeway" type="text" inputmode="numeric" aria-describedby="refresh-leeway-hint" /></Field>
      <div v-if="form.expiration === 'expiring'" class="grid gap-4 sm:grid-cols-2">
        <Field id="refresh-absolute" :label="t('rt48.absolute')"><input id="refresh-absolute" v-model="form.absolute" type="text" inputmode="numeric" /></Field>
        <Field id="refresh-idle" :label="t('rt48.idle')"><input id="refresh-idle" v-model="form.idle" type="text" inputmode="numeric" /></Field>
      </div>
    </fieldset>
    <fieldset v-if="client.is_first_party" class="stack" data-testid="mrrt-editor" :disabled="busy"><legend>{{ t('rt48.mrrt') }}</legend>
      <p class="muted m-0">{{ t('rt48.mrrtHint') }}</p><p v-if="loadingApis" role="status">{{ t('loading') }}</p>
      <div v-for="(policy, i) in policies" :key="i" class="card stack">
        <Field :id="'mrrt-audience-' + i" :label="t('rt48.api')"><select :id="'mrrt-audience-' + i" v-model="policy.audience" @change="policy.scope = []"><option value="" disabled>{{ t('rt48.chooseApi') }}</option><option v-if="policy.audience && !audiences.some(s => s.identifier === policy.audience)" :value="policy.audience">{{ policy.audience }}</option><option v-for="s in audiences" :key="s.id" :value="s.identifier">{{ s.name || s.identifier }}</option></select></Field>
        <fieldset class="stack"><legend>{{ t('userd.scopes') }}</legend><label v-for="(scope, j) in scopes(policy.audience)" :key="scope.value" class="check"><input :id="`mrrt-scope-${i}-${j}`" v-model="policy.scope" type="checkbox" :value="scope.value" />{{ scope.value }}</label><label v-for="scope in policy.scope.filter(s => !scopes(policy.audience).some(x => x.value === s))" :key="scope" class="check"><input v-model="policy.scope" type="checkbox" :value="scope" />{{ scope }}</label></fieldset>
        <Button @click="policies.splice(i, 1)">{{ t('rt48.removePolicy') }}</Button>
      </div>
      <Button data-testid="mrrt-add" :disabled="policies.length >= 10 || loadingApis" @click="add">{{ t('rt48.addPolicy') }}</Button>
    </fieldset>
    <fieldset class="stack" :disabled="busy"><legend>{{ t('rt48.proof') }}</legend><label class="check"><input id="app-require-proof" v-model="form.proof" type="checkbox" />{{ t('rt48.requireProof') }}</label><p class="muted m-0">{{ t('rt48.publicHint') }}</p></fieldset>
    <QuotaEditor id="app-quota" v-model="quota" :label="t('rt48.appQuota')" />
    <div class="row"><Button type="submit" variant="primary" :disabled="busy">{{ t('save') }}</Button><span role="status">{{ status }}</span></div>
  </form>
</template>
