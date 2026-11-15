<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type Action, type TokenExchangeProfile } from '../../api/client'
import { errorMessage } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Modal from '../../ui/Modal.vue'
import ActionNav from './ActionNav.vue'
import { useActionContext } from './context'

const { t } = useI18n()
const { api, tenant, key, capture, current } = useActionContext()

// A token exchange profile binds a subject token type to a deployed Action of
// the custom-token-exchange trigger. The type is what a caller sends as
// subject_token_type; the name is for people.
const TRIGGER = 'custom-token-exchange'
const items = ref<TokenExchangeProfile[]>([])
const actions = ref<Action[]>([])
const loading = ref(false)
const error = ref('')
const unavailable = ref(false)
const busy = ref(false)
const editing = ref(false)
const target = ref<TokenExchangeProfile | null>(null)
const form = ref({ name: '', subjectTokenType: '', actionId: '' })
const errors = ref<Record<string, string>>({})
const formError = ref('')
const deleting = ref(false)
const deleteError = ref('')
let reads = 0

const deployed = computed(() => actions.value.filter((a) => a.deployed_version && a.supported_triggers.some((tr) => tr.id === TRIGGER)))
const actionName = (id: string) => actions.value.find((a) => a.id === id)?.name ?? id

async function load() {
  const c = capture(), seq = ++reads
  if (!c) return
  loading.value = true
  error.value = ''
  unavailable.value = false
  try {
    const [list, acts] = await Promise.all([api.allTokenExchangeProfiles(c.tenant), api.allActions(c.tenant, TRIGGER)])
    if (!current(c) || seq !== reads) return
    items.value = list
    actions.value = acts
  } catch (e) {
    if (!current(c) || seq !== reads) return
    if (e instanceof ApiError && e.status === 501) unavailable.value = true
    else error.value = errorMessage(e)
  } finally {
    if (current(c) && seq === reads) loading.value = false
  }
}
watch(key, () => {
  items.value = []; actions.value = []; editing.value = false; deleting.value = false; target.value = null; busy.value = false; formError.value = ''; deleteError.value = ''
  void load()
}, { immediate: true })

function openCreate() {
  target.value = null
  form.value = { name: '', subjectTokenType: '', actionId: '' }
  errors.value = {}; formError.value = ''
  editing.value = true
}
function openEdit(p: TokenExchangeProfile) {
  target.value = p
  form.value = { name: p.name, subjectTokenType: p.subject_token_type, actionId: p.action_id }
  errors.value = {}; formError.value = ''
  editing.value = true
}

function validate(): boolean {
  const e: Record<string, string> = {}
  const name = form.value.name.trim(), type = form.value.subjectTokenType.trim()
  if (name.length < 3 || name.length > 50) e.name = t('tep.nameInvalid')
  if (type.length < 8 || type.length > 100 || !(type.startsWith('https://') || type.startsWith('urn:'))) e.type = t('tep.typeInvalid')
  if (!target.value && !form.value.actionId) e.action = t('tep.actionRequired')
  errors.value = e
  return Object.keys(e).length === 0
}

async function save() {
  const c = capture()
  if (!c || busy.value || !validate()) return
  const seq = reads
  busy.value = true
  formError.value = ''
  const name = form.value.name.trim(), type = form.value.subjectTokenType.trim()
  try {
    if (target.value) await api.updateTokenExchangeProfile(c.tenant, target.value.id, { name, subject_token_type: type })
    else await api.createTokenExchangeProfile(c.tenant, { name, subject_token_type: type, action_id: form.value.actionId, type: 'custom_authentication' })
    if (!current(c)) return
    editing.value = false
    reads = seq
    await load()
  } catch (e) {
    if (!current(c)) return
    if (e instanceof ApiError && e.errorCode === 'token_exchange_profile_conflict') errors.value = { type: e.message }
    else formError.value = errorMessage(e)
  } finally {
    if (current(c)) busy.value = false
  }
}

function askDelete(p: TokenExchangeProfile) { target.value = p; deleteError.value = ''; deleting.value = true }
async function remove() {
  const c = capture(), p = target.value
  if (!c || !p || busy.value) return
  busy.value = true
  deleteError.value = ''
  try {
    await api.deleteTokenExchangeProfile(c.tenant, p.id)
    if (!current(c)) return
    deleting.value = false
    await load()
  } catch (e) {
    if (current(c)) deleteError.value = errorMessage(e)
  } finally {
    if (current(c)) busy.value = false
  }
}
</script>

<template>
  <div v-if="tenant" class="stack">
    <ActionNav />
    <div class="row">
      <h1>{{ t('tep.title') }}</h1>
      <span class="flex-1" />
      <Button variant="primary" :disabled="unavailable" @click="openCreate">{{ t('tep.create') }}</Button>
    </div>
    <p class="muted">{{ t('tep.hint') }}</p>
    <Banner v-if="unavailable" kind="warn">{{ t('tep.unavailable') }}</Banner>
    <Banner v-if="error" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else-if="!unavailable">
      <p v-if="!items.length" class="card empty">{{ t('tep.empty') }}</p>
      <table v-else class="data">
        <thead><tr><th scope="col">{{ t('tep.name') }}</th><th scope="col">{{ t('tep.subjectTokenType') }}</th><th scope="col">{{ t('tep.action') }}</th><th scope="col">{{ t('actions.manage') }}</th></tr></thead>
        <tbody>
          <tr v-for="p in items" :key="p.id">
            <td>{{ p.name }}</td>
            <td><code>{{ p.subject_token_type }}</code></td>
            <td>{{ actionName(p.action_id) }}</td>
            <td class="row">
              <Button :aria-label="t('tep.editNamed', { name: p.name })" @click="openEdit(p)">{{ t('tep.edit') }}</Button>
              <Button :aria-label="t('tep.deleteNamed', { name: p.name })" @click="askDelete(p)">{{ t('tep.delete') }}</Button>
            </td>
          </tr>
        </tbody>
      </table>
    </template>

    <Modal v-model:open="editing" :title="target ? t('tep.editTitle') : t('tep.create')" :description="t('tep.formHint')">
      <form class="stack" novalidate @submit.prevent="save">
        <Banner v-if="formError" kind="error">{{ formError }}</Banner>
        <Field id="tep-name" :label="t('tep.name')" :error="errors.name">
          <input id="tep-name" v-model="form.name" type="text" maxlength="50" autocomplete="off" :disabled="busy" :aria-invalid="!!errors.name" :aria-describedby="errors.name ? 'tep-name-error' : undefined" />
        </Field>
        <Field id="tep-type" :label="t('tep.subjectTokenType')" :hint="t('tep.typeHint')" :error="errors.type">
          <input id="tep-type" v-model="form.subjectTokenType" type="text" maxlength="100" autocomplete="off" spellcheck="false" :disabled="busy" :aria-invalid="!!errors.type" :aria-describedby="'tep-type-hint' + (errors.type ? ' tep-type-error' : '')" />
        </Field>
        <Field id="tep-action" :label="t('tep.action')" :hint="target ? t('tep.actionFixed') : deployed.length ? t('tep.actionHint') : t('tep.noActions')" :error="errors.action">
          <select id="tep-action" v-model="form.actionId" :disabled="busy || !!target" :aria-invalid="!!errors.action" :aria-describedby="'tep-action-hint' + (errors.action ? ' tep-action-error' : '')">
            <option v-if="target" :value="target.action_id">{{ actionName(target.action_id) }}</option>
            <template v-else>
              <option value="" disabled>{{ t('tep.chooseAction') }}</option>
              <option v-for="a in deployed" :key="a.id" :value="a.id">{{ a.name }}</option>
            </template>
          </select>
        </Field>
        <div class="row">
          <Button type="submit" variant="primary" :disabled="busy">{{ busy ? t('saving') : target ? t('save') : t('tep.create') }}</Button>
          <Button @click="editing = false">{{ t('cancel') }}</Button>
        </div>
      </form>
    </Modal>
    <Modal v-model:open="deleting" :title="t('tep.deleteNamed', { name: target?.name })" :description="t('tep.deleteBody')">
      <Banner v-if="deleteError" kind="error">{{ deleteError }}</Banner>
      <div class="row">
        <Button data-testid="confirm-delete" variant="danger" :disabled="busy" @click="remove">{{ t('tep.delete') }}</Button>
        <Button @click="deleting = false">{{ t('cancel') }}</Button>
      </div>
    </Modal>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
