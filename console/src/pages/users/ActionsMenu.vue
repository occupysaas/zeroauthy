<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import type { SystemTenant, User, UserUpdate } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Button from '../../ui/Button.vue'
import Banner from '../../ui/Banner.vue'
import Field from '../../ui/Field.vue'
import ConfirmDialog from './ConfirmDialog.vue'
import TicketDialog from './TicketDialog.vue'

const { t } = useI18n()
const props = defineProps<{ tenant: SystemTenant; user: User }>()
const emit = defineEmits<{ updated: [User]; blocks: [] }>()
const { api } = useServices()
const router = useRouter()

const uid = computed(() => props.user.user_id ?? '')
const busy = ref(false)
const error = ref('')
const notice = ref('')

type Dialog = 'block' | 'password' | 'email' | 'reset' | 'verify' | 'delete' | null
const dialog = ref<Dialog>(null)
const is = (d: Exclude<Dialog, null>) =>
  computed({
    get: () => dialog.value === d,
    set: (v: boolean) => {
      if (!v && dialog.value === d) dialog.value = null
    },
  })
const blockOpen = is('block')
const passwordOpen = is('password')
const emailOpen = is('email')
const resetOpen = is('reset')
const verifyOpen = is('verify')
const deleteOpen = is('delete')

const password = ref('')
const email = ref('')
const typed = ref('')

function ask(d: Exclude<Dialog, null>) {
  error.value = ''
  notice.value = ''
  password.value = ''
  email.value = ''
  typed.value = ''
  dialog.value = d
}

// patch sends one change; email and password are never sent together.
async function patch(body: UserUpdate) {
  busy.value = true
  error.value = ''
  try {
    emit('updated', await api.updateUser(props.tenant, uid.value, body))
    dialog.value = null
    return true
  } catch (e) {
    error.value = errorMessage(e)
    return false
  } finally {
    busy.value = false
  }
}

// sendVerification queues the verification email job and reports it; the
// job runs in the background, so this says queued, not delivered.
async function sendVerification() {
  busy.value = true
  notice.value = ''
  error.value = ''
  try {
    const job = await api.createVerificationEmailJob(props.tenant, uid.value)
    notice.value = t('userd.verificationQueued', { id: job.id })
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}

async function unblock() {
  notice.value = ''
  error.value = ''
  if (await patch({ blocked: false })) notice.value = t('userd.unblocked')
}

// What the user must type to delete: the email, or the ID without one.
const confirmWith = computed(() => props.user.email || uid.value)

async function remove() {
  busy.value = true
  error.value = ''
  try {
    await api.deleteUser(props.tenant, uid.value)
    dialog.value = null
    await router.push({ name: 'users', params: { tenant: props.tenant.name } })
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div>
    <div class="row" role="group" :aria-label="t('userd.actions')">
      <Button v-if="!user.blocked" @click="ask('block')">{{ t('userd.block') }}</Button>
      <Button v-else @click="unblock">{{ t('userd.unblock') }}</Button>
      <Button @click="emit('blocks')">{{ t('policy.viewBlocks') }}</Button>
      <Button @click="ask('password')">{{ t('userd.changePassword') }}</Button>
      <Button @click="ask('email')">{{ t('userd.changeEmail') }}</Button>
      <Button @click="ask('reset')">{{ t('userd.createResetLink') }}</Button>
      <Button :disabled="busy" @click="sendVerification">{{ busy ? t('userd.sendingVerification') : t('userd.sendVerification') }}</Button>
      <Button @click="ask('verify')">{{ t('userd.createVerifyLink') }}</Button>
      <Button variant="danger" @click="ask('delete')">{{ t('userd.delete') }}</Button>
    </div>
    <Banner v-if="error && dialog === null" kind="error" class="mt-3">{{ error }}</Banner>
    <p v-if="notice" role="status" class="muted">{{ notice }}</p>

    <ConfirmDialog v-model:open="blockOpen" :title="t('userd.blockConfirm')" :description="t('userd.blockBody')" :confirm-label="t('userd.blockConfirm')" :busy="busy" :error="error" @confirm="patch({ blocked: true })" />

    <ConfirmDialog v-model:open="passwordOpen" :title="t('userd.changePassword')" :description="t('userd.passwordBody')" :confirm-label="t('userd.setPassword')" :busy="busy" :error="error" :disabled="!password" :danger="false" @confirm="patch({ password })">
      <Field id="action-password" :label="t('users.password')">
        <input id="action-password" v-model="password" type="password" autocomplete="new-password" />
      </Field>
    </ConfirmDialog>

    <ConfirmDialog v-model:open="emailOpen" :title="t('userd.changeEmail')" :description="t('userd.emailBody')" :confirm-label="t('userd.setEmail')" :busy="busy" :error="error" :disabled="!email.trim()" :danger="false" @confirm="patch({ email: email.trim() })">
      <Field id="action-email" :label="t('users.email')">
        <input id="action-email" v-model="email" type="email" autocomplete="off" />
      </Field>
    </ConfirmDialog>

    <TicketDialog v-model:open="resetOpen" :tenant="tenant" :user-id="uid" kind="password" />
    <TicketDialog v-model:open="verifyOpen" :tenant="tenant" :user-id="uid" kind="verify" />

    <ConfirmDialog v-model:open="deleteOpen" :title="t('userd.deleteTitle')" :description="t('userd.deleteBody', { name: confirmWith })" :confirm-label="t('userd.delete')" :busy="busy" :error="error" :disabled="typed !== confirmWith" @confirm="remove">
      <p class="m-0">{{ t('userd.cascadeIntro') }}</p>
      <ul class="m-0">
        <li>{{ t('userd.cascade.sessions') }}</li>
        <li>{{ t('userd.cascade.tokens') }}</li>
        <li>{{ t('userd.cascade.grants') }}</li>
        <li>{{ t('userd.cascade.tickets') }}</li>
      </ul>
      <Field id="delete-confirm" :label="t('userd.deleteLabel', { name: confirmWith })">
        <input id="delete-confirm" v-model="typed" type="text" autocomplete="off" spellcheck="false" />
      </Field>
    </ConfirmDialog>
  </div>
</template>
