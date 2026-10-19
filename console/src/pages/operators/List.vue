<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ApiError, type Operator, type OperatorInvite } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import CopyButton from '../../ui/CopyButton.vue'
import Field from '../../ui/Field.vue'
import Modal from '../../ui/Modal.vue'

const { t } = useI18n()

const { api } = useServices()
const tenant = useTenant()

const operators = ref<Operator[]>([])
const loading = ref(true)
const error = ref('')
const status = ref('')
const onSystem = computed(() => tenant.value?.reserved === true)

async function load() {
  loading.value = true
  error.value = ''
  try {
    operators.value = await api.listOperators()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}
onMounted(() => {
  if (onSystem.value) void load()
})

function when(iso: string): string {
  return iso.slice(0, 10)
}
function scope(o: Operator): string {
  return o.tenants.includes('*') ? t('operators.allTenants') : o.tenants.join(', ')
}

// Invite: the link lives only in this component's state, while the dialog
// shows it; closing the dialog drops it.
const inviting = ref(false)
const email = ref('')
const emailError = ref('')
const inviteError = ref('')
const busy = ref(false)
const invite = ref<OperatorInvite | null>(null)

function openInvite() {
  email.value = ''
  emailError.value = ''
  inviteError.value = ''
  invite.value = null
  inviting.value = true
}
function closeInvite(open: boolean) {
  inviting.value = open
  if (!open) invite.value = null
}

async function sendInvite() {
  emailError.value = ''
  inviteError.value = ''
  const v = email.value.trim()
  if (!v) {
    emailError.value = t('operators.emailRequired')
    return
  }
  if (!/^[^\s@]+@[^\s@]+$/.test(v)) {
    emailError.value = t('operators.emailInvalid')
    return
  }
  busy.value = true
  try {
    const res = await api.inviteOperator(v)
    invite.value = res
    operators.value = [...operators.value.filter((o) => o.user_id !== res.user_id), withoutLink(res)].sort((a, b) => a.user_id.localeCompare(b.user_id))
  } catch (e) {
    inviteError.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
function withoutLink(i: OperatorInvite): Operator {
  return { user_id: i.user_id, email: i.email, tenants: i.tenants, created_at: i.created_at }
}

// Remove, with confirmation. The server refuses the last operator.
const removing = ref<Operator | null>(null)
const removeOpen = computed({
  get: () => removing.value !== null,
  set: (v: boolean) => {
    if (!v) removing.value = null
  },
})
const removeError = ref('')
const removeCode = ref('')

function askRemove(o: Operator) {
  removeError.value = ''
  removeCode.value = ''
  removing.value = o
}
async function remove() {
  const o = removing.value
  if (!o) return
  busy.value = true
  removeError.value = ''
  removeCode.value = ''
  try {
    await api.deleteOperator(o.user_id)
    operators.value = operators.value.filter((x) => x.user_id !== o.user_id)
    status.value = t('operators.removed', { email: o.email })
    removing.value = null
  } catch (e) {
    if (e instanceof ApiError && e.errorCode === 'last_operator') {
      removeCode.value = 'last_operator'
      removeError.value = t('operators.lastOperator')
    } else if (e instanceof ApiError && e.status === 404) {
      operators.value = operators.value.filter((x) => x.user_id !== o.user_id)
      removing.value = null
      error.value = t('operators.gone')
    } else {
      removeError.value = errorMessage(e)
    }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div v-if="tenant && onSystem">
    <div class="row head">
      <h1>{{ t('operators.title') }}</h1>
      <span class="spacer" />
      <Button variant="primary" @click="openInvite">{{ t('operators.invite') }}</Button>
    </div>
    <p class="muted">{{ t('operators.hint') }}</p>

    <p v-if="status" role="status" data-testid="status">{{ status }}</p>
    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t('loading') }}</p>
    <div v-else-if="operators.length === 0" class="card"><p>{{ t('operators.empty') }}</p></div>
    <table v-else class="data">
      <thead>
        <tr>
          <th scope="col">{{ t('operators.email') }}</th>
          <th scope="col">{{ t('operators.tenants') }}</th>
          <th scope="col">{{ t('operators.created') }}</th>
          <th scope="col"><span class="visually-hidden">{{ t('operators.remove') }}</span></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="o in operators" :key="o.user_id" :data-testid="'operator-' + o.email">
          <td>{{ o.email }}</td>
          <td>{{ scope(o) }}</td>
          <td>{{ when(o.created_at) }}</td>
          <td>
            <Button variant="danger" :aria-label="t('operators.removeLabel', { email: o.email })" @click="askRemove(o)">{{ t('operators.remove') }}</Button>
          </td>
        </tr>
      </tbody>
    </table>

    <Modal :open="inviting" :title="invite ? t('operators.linkTitle') + ' ' + invite.email : t('operators.inviteTitle')" :description="invite ? t('operators.linkHint') : t('operators.inviteBody')" @update:open="closeInvite">
      <div v-if="invite" class="stack" data-testid="invite-link">
        <Field id="invite-url" :label="t('operators.link')">
          <input id="invite-url" type="text" readonly :value="invite.setup_url" />
        </Field>
        <div class="row">
          <CopyButton :value="invite.setup_url" :label="t('operators.link')" />
          <Button variant="primary" @click="closeInvite(false)">{{ t('operators.done') }}</Button>
        </div>
      </div>
      <form v-else class="stack" novalidate @submit.prevent="sendInvite">
        <Banner v-if="inviteError" kind="error">{{ inviteError }}</Banner>
        <Field id="invite-email" :label="t('operators.inviteEmail')" :error="emailError">
          <input id="invite-email" v-model="email" type="email" autocomplete="off" :aria-invalid="!!emailError" :aria-describedby="emailError ? 'invite-email-error' : undefined" />
        </Field>
        <div class="row">
          <Button variant="primary" type="submit" :disabled="busy">{{ busy ? t('operators.inviting') : t('operators.sendInvite') }}</Button>
          <Button @click="closeInvite(false)">{{ t('cancel') }}</Button>
        </div>
      </form>
    </Modal>

    <Modal v-model:open="removeOpen" :title="t('operators.removeTitle')" :description="removing ? t('operators.removeBody', { email: removing.email }) : ''">
      <div class="stack">
        <Banner v-if="removeError" kind="error"><span :data-testid="removeCode ? 'error-' + removeCode : 'error'">{{ removeError }}</span></Banner>
        <div class="row">
          <Button variant="danger" :disabled="busy || removeCode === 'last_operator'" @click="remove">{{ busy ? t('operators.removing') : t('operators.remove') }}</Button>
          <Button @click="removing = null">{{ t('cancel') }}</Button>
        </div>
      </div>
    </Modal>
  </div>
  <Banner v-else-if="tenant" kind="error">{{ t('notFoundBody') }}</Banner>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>

<style scoped>
.head h1 {
  margin: 0;
}
.spacer {
  flex: 1;
}
p {
  margin: 0.25rem 0 1rem;
}
</style>
