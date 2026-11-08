<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ConsoleAuthenticationMethod, SystemTenant, User } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ConfirmDialog from '../../ui/ConfirmDialog.vue'
import Modal from '../../ui/Modal.vue'
import { mfaUnavailable, useMfaScope } from '../security/scope'
import { formatTime } from './policy'
const props = defineProps<{ tenant: SystemTenant; user: User }>()
const { t, locale } = useI18n(), { api } = useServices()
const { key, capture, current } = useMfaScope(() => props.tenant, () => props.user.user_id ?? '')
// Keep a public projection only, never opaque method metadata or response objects.
type Method = ConsoleAuthenticationMethod
const methods = ref<Method[]>([]), loading = ref(false), busy = ref(false), error = ref(''), notice = ref(''), unavailable = ref(false)
const confirm = ref(false), action = ref<'delete' | 'passkey' | 'all' | 'recovery' | 'invalidate'>('all'), target = ref('')
const passkeys = computed(() => methods.value.filter(item => item.type === 'passkey'))
const mfaMethods = computed(() => methods.value.filter(item => item.type !== 'passkey'))
const renameOpen = ref(false), renameID = ref(''), renameName = ref('')
const recovery = ref(''), recoveryOpen = ref(false)
function clearRecovery() { recovery.value = ''; recoveryOpen.value = false }
watch(recoveryOpen, open => { if(!open) recovery.value = '' }, { flush: 'sync' })
onBeforeUnmount(clearRecovery)
function fail(e: unknown) { unavailable.value = mfaUnavailable(e); error.value = unavailable.value ? t('mfa.unavailable') : errorMessage(e) }
async function read(c: ReturnType<typeof capture>) {
  if(!c) return
  const all: Method[] = []
  for(let page = 0; ; page++) {
    const result = await api.getAuthenticationMethods(c.tenant, c.id, page)
    if(!current(c)) return
    const items = Array.isArray(result) ? result : result.authenticators ?? []
    all.push(...items.map(({ id, type, name, created_at, last_auth_at, phone_number, relying_party_identifier, credential_device_type, credential_backed_up, aaguid }) => ({ id, type, name, created_at, last_auth_at, phone_number, relying_party_identifier, credential_device_type, credential_backed_up, aaguid })))
    if(Array.isArray(result) || items.length === 0 || all.length >= (result.total ?? Infinity) || items.length < 100) break
  }
  if(current(c)) methods.value = all
}
async function load() {
  const c = capture(); renameOpen.value = false; renameID.value = ''; renameName.value = ''; clearRecovery(); confirm.value = false; target.value = ''; busy.value = false; error.value = ''; notice.value = ''; methods.value = []; unavailable.value = false
  if(!c) return
  loading.value = true
  try { await read(c) } catch(e) { if(current(c)) fail(e) } finally { if(current(c)) loading.value = false }
}
watch(key, load, { immediate: true, flush: 'sync' })
function ask(value: typeof action.value, id = '') { clearRecovery(); action.value = value; target.value = id; error.value = ''; notice.value = ''; confirm.value = true }
async function perform() {
  const c = capture(); if(!c || busy.value) return
  const requested = action.value, method = target.value
  busy.value = true; error.value = ''; notice.value = ''; clearRecovery()
  try {
    if(requested === 'recovery') {
      const result = await api.regenerateRecoveryCode(c.tenant, c.id)
      if(current(c)) { recovery.value = result.recovery_code ?? ''; recoveryOpen.value = !!recovery.value }
      // The returned object never enters a store or the ordinary page state.
      result.recovery_code = undefined
    } else if(requested === 'invalidate') {
      await api.invalidateRememberBrowser(c.tenant, c.id)
      if(current(c)) notice.value = t('mfa.browserInvalidated')
    } else {
      await api.deleteAuthenticationMethod(c.tenant, c.id, requested === 'delete' || requested === 'passkey' ? method : undefined)
      if(!current(c)) return
      methods.value = requested === 'all' ? methods.value.filter(item => item.type === 'passkey') : methods.value.filter(item => item.id !== method)
    }
    if(current(c)) confirm.value = false
  } catch(e) { if(current(c)) fail(e) }
  finally { if(current(c)) busy.value = false }
}
function rename(method: Method) { renameID.value = method.id; renameName.value = method.name; renameOpen.value = true; error.value = '' }
async function saveName() {
  const c = capture(); if (!c || busy.value || !renameName.value.trim() || [...renameName.value].length > 20) return
  busy.value = true; error.value = ''; const id = renameID.value
  try { const result = await api.renameAuthenticationMethod(c.tenant, c.id, id, renameName.value); if (current(c)) { methods.value = methods.value.map(item => item.id === id ? result : item); renameOpen.value = false } }
  catch (e) { if (current(c)) fail(e) }
  finally { if (current(c)) busy.value = false }
}
async function invite() {
  const c = capture(); if(!c || busy.value) return
  clearRecovery(); busy.value = true; error.value = ''; notice.value = ''
  try {
    // Deliberately discard ticket URL and ID: this operation sends mail only.
    await api.inviteMfa(c.tenant, { user_id: c.id, send_mail: true })
    if(current(c)) notice.value = t('mfa.invitationSent')
  } catch(e) { if(current(c)) fail(e) }
  finally { if(current(c)) busy.value = false }
}
</script>
<template>
  <section class="stack">
    <h2>{{ t('mfa.userTab') }}</h2>
    <Banner v-if="error" kind="error">{{ error }} <Button v-if="!confirm" @click="load">{{ t('retry') }}</Button></Banner>
    <Banner v-if="notice">{{ notice }}</Banner><p v-if="loading" role="status">{{ t('loading') }}</p>
    <template v-if="!unavailable">
      <p v-if="!loading && !mfaMethods.length" class="muted">{{ t('mfa.noMethods') }}</p>
      <table v-if="mfaMethods.length" class="data" data-mfa-methods><thead><tr><th>{{ t('mfa.type') }}</th><th>{{ t('mfa.name') }}</th><th>{{ t('passkeys.rpid') }}</th><th>{{ t('mfa.enrolled') }}</th><th>{{ t('mfa.lastUsed') }}</th><th>{{ t('userd.actions') }}</th></tr></thead>
        <tbody><tr v-for="(method, index) in mfaMethods" :key="method.id"><td>{{ method.type }}</td><td>{{ method.name }} <span v-if="method.type === 'phone'">{{ method.phone_number }}</span></td>
          <td>{{ method.relying_party_identifier }}</td><td><time :datetime="method.created_at">{{ formatTime(method.created_at, locale) }}</time></td>
          <td><time v-if="method.last_auth_at" :datetime="method.last_auth_at">{{ formatTime(method.last_auth_at, locale) }}</time><span v-else>{{ t('users.never') }}</span></td>
          <td><Button :id="'delete-method-' + index" variant="danger" :disabled="busy || loading" @click="ask('delete', method.id)">{{ t('mfa.deleteOne') }}</Button></td></tr></tbody>
      </table>
      <div class="row flex-wrap">
        <Button id="delete-all-methods" variant="danger" :disabled="busy || loading" @click="ask('all')">{{ t('mfa.deleteAll') }}</Button>
        <Button id="regenerate-recovery" :disabled="busy || loading" @click="ask('recovery')">{{ t('mfa.regenerate') }}</Button>
        <Button id="invalidate-browser" :disabled="busy || loading" @click="ask('invalidate')">{{ t('mfa.invalidate') }}</Button>
        <Button id="invite-mfa" :disabled="busy || loading" @click="invite">{{ t('mfa.invite') }}</Button>
      </div>
    </template>
    <section v-if="!unavailable" class="stack" data-passkeys>
      <h2>{{ t('passkeys.title') }}</h2><p v-if="!loading && !passkeys.length" class="muted">{{ t('passkeys.noPasskeys') }}</p>
      <table v-if="passkeys.length" class="data"><thead><tr><th>{{ t('mfa.name') }}</th><th>{{ t('passkeys.rpid') }}</th><th>{{ t('passkeys.synced') }}</th><th>{{ t('passkeys.backedUp') }}</th><th>{{ t('passkeys.aaguid') }}</th><th>{{ t('passkeys.created') }}</th><th>{{ t('mfa.lastUsed') }}</th><th>{{ t('userd.actions') }}</th></tr></thead>
        <tbody><tr v-for="(method, index) in passkeys" :key="method.id"><td>{{ method.name }}</td><td>{{ method.relying_party_identifier }}</td><td>{{ t(method.credential_device_type === 'multi_device' ? 'passkeys.yes' : 'passkeys.no') }}</td><td>{{ t(method.credential_backed_up ? 'passkeys.yes' : 'passkeys.no') }}</td><td>{{ method.aaguid }}</td><td><time :datetime="method.created_at">{{ formatTime(method.created_at, locale) }}</time></td><td><time v-if="method.last_auth_at" :datetime="method.last_auth_at">{{ formatTime(method.last_auth_at, locale) }}</time><span v-else>{{ t('users.never') }}</span></td><td><Button :id="'rename-passkey-' + index" :disabled="busy || loading" @click="rename(method)">{{ t('passkeys.rename') }}</Button><Button :id="'delete-passkey-' + index" variant="danger" :disabled="busy || loading" @click="ask('passkey', method.id)">{{ t('passkeys.delete') }}</Button></td></tr></tbody>
      </table>
    </section>
    <Modal v-model:open="renameOpen" :title="t('passkeys.renameTitle')"><form id="rename-passkey-form" class="stack" @submit.prevent="saveName"><Banner v-if="error" kind="error">{{ error }}</Banner><label for="passkey-name">{{ t('mfa.name') }}</label><input id="passkey-name" v-model="renameName" maxlength="20" required /><Button type="submit" :disabled="busy || !renameName.trim()">{{ t('save') }}</Button></form></Modal>
    <ConfirmDialog v-model:open="confirm" :title="action === 'passkey' ? t('passkeys.deleteTitle') : t(`mfa.confirm.${action}`)" :description="action === 'passkey' ? t('passkeys.deleteBody') : t(`mfa.confirmBody.${action}`)" :confirm-label="t('mfa.proceed')" :busy="busy" :error="error" @confirm="perform" />
    <Modal v-model:open="recoveryOpen" :title="t('mfa.recoveryTitle')" :description="t('mfa.recoveryHint')"><div class="stack"><code data-recovery-code>{{ recovery }}</code><Button id="dismiss-recovery" @click="clearRecovery">{{ t('mfa.recoveryDone') }}</Button></div></Modal>
  </section>
</template>
