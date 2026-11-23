<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, type SelfServiceProfile, type SsoTicketRequest } from '../../api/client'
import { selfServiceStrategies } from '../../api/directory'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ConfirmDialog from '../../ui/ConfirmDialog.vue'
import Field from '../../ui/Field.vue'
import RouteModal from '../../ui/RouteModal.vue'
const { t } = useI18n(),
  { api } = useServices(),
  tenant = useTenant(),
  route = useRoute(),
  router = useRouter()
type Strategy = NonNullable<SelfServiceProfile['allowed_strategies']>[number]
const profile = ref<SelfServiceProfile | null>(null),
  name = ref(''),
  description = ref(''),
  strategies = ref<string[]>([]),
  logo = ref(''),
  color = ref(''),
  intro = ref(''),
  newConn = ref(''),
  existingConn = ref(''),
  clients = ref(''),
  ttl = ref(''),
  provisioning = ref(false),
  domains = ref(''),
  ticket = ref(''),
  revokeValue = ref(''),
  status = ref(''),
  error = ref(''),
  notFound = ref(false),
  busy = ref(false),
  deleteOpen = ref(false)
let epoch = 0
function show(p: SelfServiceProfile) {
  profile.value = p
  name.value = p.name ?? ''
  description.value = p.description ?? ''
  strategies.value = [...(p.allowed_strategies ?? [])]
  logo.value = p.branding?.logo_url ?? ''
  color.value = p.branding?.colors?.primary ?? ''
}
async function load() {
  const current = ++epoch,
    tn = tenant.value,
    id = route.params.id
  if (!tn || typeof id !== 'string') return
  error.value = ''
  notFound.value = false
  try {
    const [p, text] = await Promise.all([api.getSelfServiceProfile(tn, id), api.getSelfServiceCustomText(tn, id)])
    if (current !== epoch) return
    show(p)
    intro.value = text.introduction ?? ''
  } catch (e) {
    if (current !== epoch) return
    if (e instanceof ApiError && e.status === 404) notFound.value = true
    else error.value = errorMessage(e)
  }
}
watch([tenant, () => route.params.id], load, { immediate: true })
onBeforeUnmount(() => {
  ++epoch
})
async function run(fn: () => Promise<void>) {
  if (busy.value || !tenant.value || !profile.value) return
  const current = epoch
  busy.value = true
  error.value = ''
  status.value = ''
  try {
    await fn()
  } catch (e) {
    if (current === epoch) error.value = errorMessage(e)
  } finally {
    if (current === epoch) busy.value = false
  }
}
const list = (v: string) =>
  v
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
const save = () =>
  run(async () => {
    const tn = tenant.value!,
      id = profile.value!.id!
    const branding = logo.value || color.value ? { ...(logo.value ? { logo_url: logo.value } : {}), ...(color.value ? { colors: { primary: color.value } } : {}) } : null
    show(
      await api.updateSelfServiceProfile(tn, id, {
        name: name.value.trim(),
        description: description.value.trim() || null,
        allowed_strategies: strategies.value as Strategy[],
        branding,
      }),
    )
    await api.setSelfServiceCustomText(tn, id, intro.value ? { introduction: intro.value } : {})
    status.value = t('saved')
  })
const createTicket = () =>
  run(async () => {
    const body: SsoTicketRequest = existingConn.value.trim() ? { connection_id: existingConn.value.trim() } : { connection_config: { name: newConn.value.trim() } }
    if (clients.value.trim()) body.enabled_clients = list(clients.value)
    if (ttl.value.trim()) body.ttl_sec = Number(ttl.value)
    if (provisioning.value) body.provisioning_config = { scopes: ['get:users', 'post:users', 'put:users', 'patch:users', 'delete:users', 'get:groups', 'post:groups', 'put:groups', 'patch:groups', 'delete:groups'] }
    if (domains.value.trim()) body.domain_aliases_config = { domain_verification: 'optional', pending_domains: list(domains.value) }
    ticket.value = (await api.createSsoTicket(tenant.value!, profile.value!.id!, body)).ticket ?? ''
  })
const revoke = () =>
  run(async () => {
    await api.revokeSsoTicket(tenant.value!, profile.value!.id!, revokeValue.value.trim())
    revokeValue.value = ''
    status.value = t('ssso.revoked')
  })
const remove = () =>
  run(async () => {
    await api.deleteSelfServiceProfile(tenant.value!, profile.value!.id!)
    deleteOpen.value = false
    await router.push({ name: 'self-service', params: { tenant: tenant.value!.name } })
  })
</script>
<template>
  <RouteModal v-if="tenant" :title="profile?.name ?? t('ssso.title')" back="self-service" wide>
    <Banner v-if="notFound" kind="error">{{ t('notFoundBody') }}</Banner>
    <p v-else-if="!profile && !error" role="status">{{ t('loading') }}</p>
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <template v-if="profile">
      <code>{{ profile.id }}</code>
      <form class="card stack" @submit.prevent="save">
        <Field id="ssso-edit-name" :label="t('ssso.name')"><input id="ssso-edit-name" v-model="name" required maxlength="100" /></Field>
        <Field id="ssso-description" :label="t('ssso.description')"><input id="ssso-description" v-model="description" maxlength="140" /></Field>
        <fieldset class="stack">
          <legend>{{ t('ssso.strategies') }}</legend>
          <label v-for="s in selfServiceStrategies" :key="s" class="row"><input v-model="strategies" type="checkbox" :value="s" /> {{ s }}</label>
        </fieldset>
        <Field id="ssso-logo" :label="t('ssso.logo')"><input id="ssso-logo" v-model="logo" type="url" maxlength="1024" /></Field>
        <Field id="ssso-color" :label="t('ssso.color')"><input id="ssso-color" v-model="color" maxlength="7" pattern="#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})" /></Field>
        <Field id="ssso-intro" :label="t('ssso.intro_text')"><textarea id="ssso-intro" v-model="intro" maxlength="2000" /></Field>
        <div class="row">
          <Button type="submit" variant="primary" :disabled="busy || tenant.seeded">{{ t('ssso.save') }}</Button><span role="status">{{ status }}</span>
        </div>
      </form>
      <section class="card stack">
        <h3>{{ t('ssso.tickets') }}</h3>
        <form class="stack" @submit.prevent="createTicket">
          <Field id="ssso-new-conn" :label="t('ssso.newConnection')"><input id="ssso-new-conn" v-model="newConn" maxlength="128" /></Field>
          <Field id="ssso-existing-conn" :label="t('ssso.existingConnection')"><input id="ssso-existing-conn" v-model="existingConn" /></Field>
          <Field id="ssso-clients" :label="t('ssso.clients')"><input id="ssso-clients" v-model="clients" /></Field>
          <Field id="ssso-ttl" :label="t('ssso.ttl')"><input id="ssso-ttl" v-model="ttl" inputmode="numeric" pattern="[0-9]*" /></Field>
          <Field id="ssso-domains" :label="t('ssso.domains')"><input id="ssso-domains" v-model="domains" /></Field>
          <label class="row"><input v-model="provisioning" type="checkbox" /> {{ t('ssso.provisioning') }}</label>
          <div>
            <Button type="submit" :disabled="busy || (!newConn.trim() && !existingConn.trim()) || tenant.seeded">{{ t('ssso.createTicket') }}</Button>
          </div>
        </form>
        <Banner v-if="ticket" kind="info"
          >{{ t('ssso.ticketOnce') }} <code data-testid="ssso-ticket">{{ ticket }}</code></Banner
        >
        <form class="row" @submit.prevent="revoke">
          <Field id="ssso-revoke" :label="t('ssso.revokeValue')"><input id="ssso-revoke" v-model="revokeValue" autocomplete="off" /></Field
          ><Button type="submit" :disabled="busy || !revokeValue.trim() || tenant.seeded">{{ t('ssso.revoke') }}</Button>
        </form>
      </section>
      <section class="card stack">
        <Button variant="danger" :disabled="busy || tenant.seeded" @click="deleteOpen = true">{{ t('ssso.delete') }}</Button>
      </section>
    </template>
    <ConfirmDialog
      v-model:open="deleteOpen"
      :title="t('ssso.deleteTitle')"
      :description="t('ssso.deleteHint')"
      :confirm-label="t('ssso.delete')"
      :busy="busy"
      :error="error"
      @confirm="remove"
    />
  </RouteModal>
</template>
