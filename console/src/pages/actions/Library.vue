<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ApiError, type Action, type ActionTrigger } from '../../api/client'
import { errorMessage } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Modal from '../../ui/Modal.vue'
import Pager from '../roles/Pager.vue'
import ActionNav from './ActionNav.vue'
import { buildStatusKey, useActionContext } from './context'
const { t } = useI18n(), router = useRouter(), ctx = useActionContext(), { api, tenant, key, capture, current } = ctx
const items = ref<Action[]>([]), triggers = ref<ActionTrigger[]>([]), total = ref(0), page = ref(0)
const loading = ref(false), busy = ref(false), error = ref(''), creating = ref(false), name = ref(''), trigger = ref('post-login')
const deleting = ref(false), selected = ref<Action>(), forceRequired = ref(false), force = ref(false), deleteError = ref('')
let listSeq = 0
let deletionContext: ReturnType<typeof capture>
async function load() {
  const c = capture(), seq = ++listSeq
  if (!c) return
  loading.value = true; error.value = ''
  try {
    const [list, available] = await Promise.all([api.listActions(c.tenant, { page: page.value, per_page: 20 }), api.listActionTriggers(c.tenant)])
    if (!current(c) || seq !== listSeq) return
    items.value = list.actions; total.value = list.total; triggers.value = available.triggers
  } catch (e) { if (current(c) && seq === listSeq) error.value = errorMessage(e) }
  finally { if (current(c) && seq === listSeq) loading.value = false }
}
watch(key, () => {
  items.value = []; triggers.value = []; total.value = 0; page.value = 0; creating.value = false; deleting.value = false; selected.value = undefined; deletionContext = undefined; force.value = false; forceRequired.value = false; name.value = ''; busy.value = false
  void load()
}, { immediate: true })
async function create() {
  const c = capture()
  if (!c || busy.value || !name.value || !triggers.value.some(v => v.id === trigger.value)) return
  busy.value = true; error.value = ''
  try {
    const created = await api.createAction(c.tenant, { runtime: 'node22', name: name.value, supported_triggers: [{ id: trigger.value as ActionTrigger['id'] }] })
    if (current(c)) { creating.value = false; await router.push({ name: 'action-editor', params: { tenant: c.tenant.name, id: created.id } }) }
  } catch (e) { if (current(c)) error.value = errorMessage(e) }
  finally { if (current(c)) busy.value = false }
}
function askDelete(a: Action) {
  deletionContext = capture(); selected.value = a; forceRequired.value = false; force.value = false; deleteError.value = ''; deleting.value = true
}
async function remove() {
  const c = deletionContext, a = selected.value
  if (!current(c) || !c || !a || busy.value || (forceRequired.value && !force.value)) return
  busy.value = true; deleteError.value = ''
  try {
    await api.deleteAction(c.tenant, a.id, forceRequired.value && force.value)
    if (current(c)) { deleting.value = false; await load() }
  } catch (e) {
    if (!current(c)) return
    deleteError.value = errorMessage(e)
    // The API uses 400 for an Action still bound to a trigger. Force is
    // offered only after refusal and always requires a second confirmation.
    if (e instanceof ApiError && e.status === 400 && /bound.*(?:trigger|force)/i.test(deleteError.value)) { forceRequired.value = true; force.value = false }
  } finally { if (current(c)) busy.value = false }
}
function goto(n: number) { page.value = n; void load() }
</script>
<template>
  <div v-if="tenant" class="stack">
    <ActionNav />
    <div class="row"><h1>{{ t('actions.title') }}</h1><span class="flex-1" /><Button variant="primary" @click="creating = true">{{ t('actions.create') }}</Button></div>
    <p class="muted">{{ t('actions.libraryHint') }}</p>
    <Banner v-if="error" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else>
      <p v-if="!items.length" class="card empty">{{ t('actions.empty') }}</p>
      <table v-else class="data"><thead><tr><th scope="col">{{ t('actions.name') }}</th><th scope="col">{{ t('actions.trigger') }}</th><th scope="col">{{ t('actions.status') }}</th><th scope="col">{{ t('actions.manage') }}</th></tr></thead>
        <tbody><tr v-for="a in items" :key="a.id"><td><RouterLink :to="{ name: 'action-editor', params: { tenant: tenant.name, id: a.id } }">{{ a.name }}</RouterLink></td><td>{{ a.supported_triggers[0]?.id }}</td><td>{{ t(buildStatusKey(a.status)) }}</td><td><Button :aria-label="t('actions.deleteNamed', { name: a.name })" @click="askDelete(a)">{{ t('actions.delete') }}</Button></td></tr></tbody>
      </table>
      <Pager :page="page" :total="total" :busy="loading" @change="goto" />
    </template>
    <Modal v-model:open="creating" :title="t('actions.create')" :description="t('actions.createHint')">
      <form class="stack" @submit.prevent="create">
        <Field id="action-name" :label="t('actions.name')"><input id="action-name" v-model="name" required maxlength="128" :disabled="busy" /></Field>
        <Field id="action-trigger" :label="t('actions.trigger')"><select id="action-trigger" v-model="trigger" :disabled="busy"><option v-for="tr in triggers" :key="tr.id" :value="tr.id">{{ tr.id }}</option></select></Field>
        <Button type="submit" variant="primary" :disabled="busy || !triggers.length">{{ t('actions.create') }}</Button>
        <Banner v-if="error" kind="error">{{ error }}</Banner>
      </form>
    </Modal>
    <Modal v-model:open="deleting" :title="t('actions.deleteNamed', { name: selected?.name })" :description="t('actions.deleteHint')">
      <Banner v-if="deleteError" kind="error">{{ deleteError }}</Banner>
      <label v-if="forceRequired" class="row" for="force-delete"><input id="force-delete" v-model="force" type="checkbox" :disabled="busy" />{{ t('actions.forceHint') }}</label>
      <Button data-testid="confirm-delete" variant="danger" :disabled="busy || (forceRequired && !force)" @click="remove">{{ t(forceRequired ? 'actions.forceDelete' : 'actions.confirmDelete') }}</Button>
    </Modal>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
