<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type Client, type ClientCredential, type ClientCredentialCreate, type SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Modal from '../../ui/Modal.vue'

const { t } = useI18n()

// The public keys an application proves itself with (private_key_jwt) or
// signs authorization request objects with. The server never returns a PEM.
const props = defineProps<{ tenant: SystemTenant; client: Client }>()
const emit = defineEmits<{ saved: [Client] }>()
const { api } = useServices()

const MAX_CREDENTIALS = 2
const algs = ['RS256', 'RS384', 'PS256'] as const

const credentials = ref<ClientCredential[]>([])
const loading = ref(true)
const unavailable = ref(false)
const error = ref('')
const status = ref('')
const addError = ref('')
const busy = ref(false)
const removing = ref<ClientCredential | null>(null)
const removeError = ref('')
const form = reactive({ type: 'public_key' as 'public_key' | 'x509_cert', name: '', pem: '', alg: 'RS256' as (typeof algs)[number], parseExpiry: false, expires: '' })
const errors = reactive<Record<string, string>>({})

// epoch rejects replies that belong to another application or tenant, or to a
// page that is gone.
let epoch = 0
const scope = computed(() => props.tenant.host + '/' + props.client.client_id)
onBeforeUnmount(() => { ++epoch })

async function load() {
  const mine = ++epoch
  const tn = props.tenant, id = props.client.client_id
  loading.value = true
  error.value = ''
  unavailable.value = false
  credentials.value = []
  try {
    const list = await api.listClientCredentials(tn, id)
    if (mine === epoch) credentials.value = list
  } catch (e) {
    if (mine !== epoch) return
    if (e instanceof ApiError && e.status === 501) unavailable.value = true
    else error.value = errorMessage(e)
  } finally {
    if (mine === epoch) loading.value = false
  }
}
watch(scope, () => { status.value = ''; addError.value = ''; busy.value = false; removing.value = null; void load() }, { immediate: true })

const full = computed(() => credentials.value.length >= MAX_CREDENTIALS)

function validate(): boolean {
  for (const k of Object.keys(errors)) delete errors[k]
  if (!form.pem.trim()) errors.pem = t('cred.pemRequired')
  if (form.name.length > 128) errors.name = t('cred.nameTooLong')
  return Object.keys(errors).length === 0
}

async function add() {
  addError.value = ''
  status.value = ''
  if (busy.value || full.value || !validate()) return
  const mine = epoch
  const tn = props.tenant, id = props.client.client_id
  const body: ClientCredentialCreate = { credential_type: form.type, pem: form.pem.trim(), alg: form.alg }
  if (form.name.trim()) body.name = form.name.trim()
  if (form.type === 'x509_cert' && form.parseExpiry) body.parse_expiry_from_cert = true
  else if (form.expires) body.expires_at = new Date(form.expires + 'T00:00:00Z').toISOString()
  busy.value = true
  try {
    const c = await api.createClientCredential(tn, id, body)
    if (mine !== epoch) return
    credentials.value = [...credentials.value, c]
    form.name = ''; form.pem = ''; form.parseExpiry = false; form.expires = ''
    status.value = t('cred.added')
  } catch (e) {
    if (mine !== epoch) return
    if (e instanceof ApiError && e.status === 501) unavailable.value = true
    else addError.value = errorMessage(e)
  } finally {
    if (mine === epoch) busy.value = false
  }
}

async function remove() {
  const target = removing.value
  if (!target || busy.value) return
  const mine = epoch
  const tn = props.tenant, id = props.client.client_id
  busy.value = true
  removeError.value = ''
  try {
    await api.deleteClientCredential(tn, id, target.id)
    // Removing a key also drops it from the application's settings: refresh them.
    const fresh = await api.getClient(tn, id)
    if (mine !== epoch) return
    credentials.value = credentials.value.filter((c) => c.id !== target.id)
    removing.value = null
    status.value = t('cred.removed')
    emit('saved', fresh)
  } catch (e) {
    if (mine === epoch) removeError.value = errorMessage(e)
  } finally {
    if (mine === epoch) busy.value = false
  }
}

function date(iso?: string): string {
  return iso ? iso.slice(0, 10) : t('cred.never')
}
</script>

<template>
  <div class="stack">
    <p v-if="loading" class="muted" role="status">{{ t('loading') }}</p>
    <Banner v-else-if="unavailable" kind="warn">{{ t('cred.unavailable') }}</Banner>
    <Banner v-else-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <template v-else>
      <section class="card stack" :aria-label="t('cred.title')">
        <p class="m-0 muted">{{ t('cred.hint', { max: MAX_CREDENTIALS }) }}</p>
        <p v-if="credentials.length === 0" class="m-0" data-testid="cred-empty">{{ t('cred.empty') }}</p>
        <ul v-else class="m-0 grid list-none gap-3 p-0">
          <li v-for="c in credentials" :key="c.id" class="row flex-nowrap justify-between" data-testid="credential">
            <div class="grid gap-0.5">
              <strong>{{ c.name || c.id }}</strong>
              <span class="muted">{{ t('cred.summary', { type: t(`cred.types.${c.credential_type}`), alg: c.alg }) }}</span>
              <span class="muted">{{ t('cred.kid') }}: <code>{{ c.kid }}</code></span>
              <span class="muted">{{ t('cred.expires') }}: {{ date(c.expires_at) }}</span>
            </div>
            <Button variant="danger" :aria-label="t('cred.removeNamed', { name: c.name || c.id })" @click="(removeError = ''), (removing = c)">{{ t('cred.remove') }}</Button>
          </li>
        </ul>
        <p v-if="status" class="m-0" role="status">{{ status }}</p>
      </section>

      <form class="card stack" novalidate @submit.prevent="add">
        <h3 class="m-0">{{ t('cred.addTitle') }}</h3>
        <Banner v-if="addError" kind="error">{{ addError }}</Banner>
        <p v-if="full" class="m-0 muted" data-testid="cred-full">{{ t('cred.full', { max: MAX_CREDENTIALS }) }}</p>
        <div class="row [&>*]:min-w-48 [&>*]:flex-1">
          <Field id="cred-type" :label="t('cred.type')">
            <select id="cred-type" v-model="form.type">
              <option value="public_key">{{ t('cred.types.public_key') }}</option>
              <option value="x509_cert">{{ t('cred.types.x509_cert') }}</option>
            </select>
          </Field>
          <Field id="cred-alg" :label="t('cred.alg')">
            <select id="cred-alg" v-model="form.alg">
              <option v-for="a in algs" :key="a" :value="a">{{ a }}</option>
            </select>
          </Field>
        </div>
        <Field id="cred-name" :label="t('cred.name')" :error="errors.name">
          <input id="cred-name" v-model="form.name" type="text" maxlength="128" autocomplete="off" :aria-invalid="!!errors.name" :aria-describedby="errors.name ? 'cred-name-error' : undefined" />
        </Field>
        <Field id="cred-pem" :label="t('cred.pem')" :hint="t('cred.pemHint')" :error="errors.pem">
          <textarea id="cred-pem" v-model="form.pem" spellcheck="false" autocomplete="off" :aria-invalid="!!errors.pem" :aria-describedby="'cred-pem-hint' + (errors.pem ? ' cred-pem-error' : '')" />
        </Field>
        <label v-if="form.type === 'x509_cert'" class="check">
          <input v-model="form.parseExpiry" type="checkbox" />
          {{ t('cred.parseExpiry') }}
        </label>
        <Field v-if="!form.parseExpiry" id="cred-expires" :label="t('cred.expiresOn')" :hint="t('cred.expiresHint')">
          <input id="cred-expires" v-model="form.expires" type="date" aria-describedby="cred-expires-hint" />
        </Field>
        <div class="row">
          <Button variant="primary" type="submit" :disabled="busy || full">{{ busy ? t('saving') : t('cred.add') }}</Button>
        </div>
      </form>
    </template>

    <Modal :open="!!removing" :title="t('cred.removeConfirm')" :description="t('cred.removeBody')" @update:open="(v: boolean) => { if (!v) removing = null }">
      <Banner v-if="removeError" kind="error">{{ removeError }}</Banner>
      <div class="row">
        <Button variant="danger" :disabled="busy" @click="remove">{{ t('cred.remove') }}</Button>
        <Button @click="removing = null">{{ t('cancel') }}</Button>
      </div>
    </Modal>
  </div>
</template>
