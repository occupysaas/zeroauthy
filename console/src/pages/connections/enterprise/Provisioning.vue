<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type Connection, type ScimConfiguration, type ScimMappingItem, type ScimToken, type SystemTenant } from '../../../api/client'
import { scimScopes } from '../../../api/directory'
import { errorMessage, useServices } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import ConfirmDialog from '../../../ui/ConfirmDialog.vue'
// SCIM provisioning of an enterprise connection (Plan 37c): configuration,
// attribute mapping and tokens. A new token is shown once.
const props = defineProps<{ tenant: SystemTenant; connection: Connection }>(),
  { t } = useI18n(),
  { api } = useServices()
const config = ref<ScimConfiguration | null>(null),
  tokens = ref<ScimToken[]>([]),
  uid = ref(''),
  mapping = ref<ScimMappingItem[]>([]),
  scopes = ref<string[]>([...scimScopes]),
  lifetime = ref(''),
  secret = ref(''),
  loading = ref(true),
  busy = ref(false),
  error = ref(''),
  status = ref(''),
  disableOpen = ref(false)
const endpoint = computed(() => 'https://' + props.tenant.host + '/scim/v2/connections/' + props.connection.id)
const locked = computed(() => busy.value || !!props.tenant.seeded)
let generation = 0
function show(c: ScimConfiguration | null) {
  config.value = c
  uid.value = c?.user_id_attribute ?? ''
  mapping.value = (c?.mapping ?? []).map((m) => ({ ...m }))
}
async function load() {
  const mine = ++generation,
    tn = props.tenant,
    id = props.connection.id!
  loading.value = true
  error.value = ''
  secret.value = ''
  try {
    let c: ScimConfiguration | null = null
    try {
      c = await api.getScimConfiguration(tn, id)
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 404)) throw e
    }
    const list = c ? await api.listScimTokens(tn, id) : []
    if (mine !== generation) return
    show(c)
    tokens.value = list
  } catch (e) {
    if (mine === generation) error.value = errorMessage(e)
  } finally {
    if (mine === generation) loading.value = false
  }
}
watch(() => [props.tenant.name, props.connection.id], load, { immediate: true })
onBeforeUnmount(() => {
  generation++
})
async function run(fn: () => Promise<void>) {
  if (locked.value) return
  const mine = generation
  busy.value = true
  error.value = ''
  status.value = ''
  try {
    await fn()
  } catch (e) {
    if (mine === generation) error.value = errorMessage(e)
  } finally {
    if (mine === generation) busy.value = false
  }
}
const enable = () =>
  run(async () => {
    show(await api.createScimConfiguration(props.tenant, props.connection.id!))
    tokens.value = []
  })
const save = () =>
  run(async () => {
    show(await api.updateScimConfiguration(props.tenant, props.connection.id!, { user_id_attribute: uid.value.trim(), mapping: mapping.value }))
    status.value = t('saved')
  })
const resetMapping = () =>
  run(async () => {
    const res = await api.getScimDefaultMapping(props.tenant, props.connection.id!)
    mapping.value = (res.mapping ?? []).map((m) => ({ ...m }))
  })
const disable = () =>
  run(async () => {
    await api.deleteScimConfiguration(props.tenant, props.connection.id!)
    disableOpen.value = false
    show(null)
    tokens.value = []
  })
const generate = () =>
  run(async () => {
    const life = lifetime.value.trim()
    const created = await api.createScimToken(props.tenant, props.connection.id!, {
      scopes: scopes.value as ScimTokenScopes,
      ...(life ? { token_lifetime: Number(life) } : {}),
    })
    secret.value = created.token ?? ''
    tokens.value = await api.listScimTokens(props.tenant, props.connection.id!)
  })
const revoke = (id: string) =>
  run(async () => {
    await api.deleteScimToken(props.tenant, props.connection.id!, id)
    tokens.value = tokens.value.filter((x) => x.token_id !== id)
  })
type ScimTokenScopes = NonNullable<Parameters<typeof api.createScimToken>[2]['scopes']>
</script>
<template>
  <section class="stack" :aria-label="t('scim.title')">
    <p>{{ t('scim.intro') }}</p>
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else-if="!config">
      <p class="card empty">{{ t('scim.disabled') }}</p>
      <div><Button data-testid="scim-enable" variant="primary" :disabled="locked" @click="enable">{{ t('scim.enable') }}</Button></div>
    </template>
    <template v-else>
      <Field id="scim-endpoint" :label="t('scim.endpoint')"><input id="scim-endpoint" :value="endpoint" readonly /></Field>
      <form class="card stack" @submit.prevent="save">
        <Field id="scim-uid" :label="t('scim.userIdAttribute')"><input id="scim-uid" v-model="uid" required maxlength="256" /></Field>
        <h3>{{ t('scim.mapping') }}</h3>
        <div v-for="(m, i) in mapping" :key="i" class="row">
          <Field :id="'scim-auth0-' + i" :label="t('scim.auth0')"><input :id="'scim-auth0-' + i" v-model="m.auth0" required maxlength="256" /></Field
          ><Field :id="'scim-attr-' + i" :label="t('scim.scimAttr')"><input :id="'scim-attr-' + i" v-model="m.scim" required maxlength="256" /></Field
          ><Button :disabled="locked" @click="mapping.splice(i, 1)">{{ t('scim.removeMapping') }}</Button>
        </div>
        <div class="row">
          <Button :disabled="locked || mapping.length >= 100" @click="mapping.push({ auth0: '', scim: '' })">{{ t('scim.addMapping') }}</Button
          ><Button :disabled="locked" @click="resetMapping">{{ t('scim.resetMapping') }}</Button><span class="flex-1" /><Button
            type="submit"
            variant="primary"
            :disabled="locked"
            >{{ t('scim.save') }}</Button
          ><span role="status">{{ status }}</span>
        </div>
      </form>
      <section class="card stack">
        <h3>{{ t('scim.tokens') }}</h3>
        <p class="muted">{{ t('scim.limit') }}</p>
        <Banner v-if="secret" kind="info"
          >{{ t('scim.tokenOnce') }} <code data-testid="scim-secret">{{ secret }}</code></Banner
        >
        <p v-if="tokens.length === 0" class="empty">{{ t('scim.noTokens') }}</p>
        <table v-else class="data">
          <thead>
            <tr>
              <th scope="col">ID</th>
              <th scope="col">{{ t('scim.scopes') }}</th>
              <th scope="col">{{ t('scim.expires') }}</th>
              <th scope="col">{{ t('scim.lastUsed') }}</th>
              <th scope="col"><span class="visually-hidden">{{ t('scim.revoke') }}</span></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="tok in tokens" :key="tok.token_id">
              <td><code>{{ tok.token_id }}</code></td>
              <td>{{ (tok.scopes ?? []).join(' ') }}</td>
              <td>{{ tok.valid_until ?? t('scim.never') }}</td>
              <td>{{ tok.last_used_at ?? t('scim.unused') }}</td>
              <td><Button variant="danger" :disabled="locked" @click="revoke(tok.token_id!)">{{ t('scim.revoke') }}</Button></td>
            </tr>
          </tbody>
        </table>
        <fieldset class="stack">
          <legend>{{ t('scim.scopes') }}</legend>
          <label v-for="s in scimScopes" :key="s" class="row"><input v-model="scopes" type="checkbox" :value="s" /> {{ s }}</label>
        </fieldset>
        <Field id="scim-lifetime" :label="t('scim.lifetime')"><input id="scim-lifetime" v-model="lifetime" inputmode="numeric" pattern="[0-9]*" /></Field>
        <div>
          <Button data-testid="scim-generate" :disabled="locked || scopes.length === 0" @click="generate">{{ t('scim.newToken') }}</Button>
        </div>
      </section>
      <section class="card stack">
        <Button variant="danger" :disabled="locked" @click="disableOpen = true">{{ t('scim.disable') }}</Button>
      </section>
    </template>
    <ConfirmDialog
      v-model:open="disableOpen"
      :title="t('scim.disableTitle')"
      :description="t('scim.disableHint')"
      :confirm-label="t('scim.disable')"
      :busy="busy"
      :error="error"
      @confirm="disable"
    />
  </section>
</template>
