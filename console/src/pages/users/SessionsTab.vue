<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SystemTenant, User, UserRefreshToken, UserSession } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ConfirmDialog from '../../ui/ConfirmDialog.vue'
import MetadataEditor from '../token-settings/MetadataEditor.vue'
import { formatTime } from './policy'

const { t, locale } = useI18n()
const props = defineProps<{ tenant: SystemTenant; user: User }>()
const { api } = useServices()

const TAKE = 50
const uid = () => props.user.user_id ?? ''
let epoch = 0
onBeforeUnmount(() => ++epoch)

// One list with its own checkpoint cursor, loading and error.
function pager<T>(fetch: (from?: string) => Promise<{ items: T[]; next?: string }>) {
  const items = ref<T[]>([]) as { value: T[] }
  const loading = ref(true)
  const error = ref('')
  const next = ref<string | undefined>()
  async function load(more = false) {
    const mine = epoch
    loading.value = true
    error.value = ''
    try {
      const r = await fetch(more ? next.value : undefined)
      if (mine !== epoch) return
      items.value = more ? [...items.value, ...r.items] : r.items
      // A short page is the last; next is present on every non-empty page.
      next.value = r.items.length >= TAKE ? r.next : undefined
    } catch (e) {
      if (mine === epoch) error.value = errorMessage(e)
    } finally {
      if (mine === epoch) loading.value = false
    }
  }
  return { items, loading, error, next, load }
}

const all = ref<'sessions' | 'tokens' | null>(null), open = ref(false), busy = ref(false), allError = ref(''), actionError = ref('')
const selectedSession = ref<UserSession | null>(null), sessionOpen = ref(false), sessionBusy = ref(false), sessionError = ref('')
const sessions = pager<UserSession>(async (from) => {
  const r = await api.listUserSessions(props.tenant, uid(), { take: TAKE, from })
  return { items: r.sessions, next: r.next }
})
const tokens = pager<UserRefreshToken>(async (from) => {
  const r = await api.listUserRefreshTokens(props.tenant, uid(), { take: TAKE, from })
  return { items: r.tokens, next: r.next }
})
watch(() => [props.tenant.host, uid()], () => { ++epoch; selectedSession.value = null; sessionOpen.value = false; sessionBusy.value = false; sessionError.value = ''; actionError.value = ''; all.value = null; open.value = false; busy.value = false; allError.value = ''; sessions.next.value = undefined; tokens.next.value = undefined; sessions.items.value = []; tokens.items.value = []; void sessions.load(); void tokens.load() }, { immediate: true, flush: 'sync' })

async function saveSessionMetadata(s: UserSession, value: Record<string, string>) {
  const mine = epoch, tenant = props.tenant
  const result = await api.updateSessionMetadata(tenant, s.id, value)
  if (mine === epoch) sessions.items.value = sessions.items.value.map(x => x.id === s.id ? result : x)
}
async function saveTokenMetadata(k: UserRefreshToken, value: Record<string, string>) {
  const mine = epoch, tenant = props.tenant
  const result = await api.updateRefreshTokenMetadata(tenant, k.id, value)
  if (mine === epoch) tokens.items.value = tokens.items.value.map(x => x.id === k.id ? result : x)
}
function askSession(s: UserSession) { selectedSession.value = s; sessionError.value = ''; sessionOpen.value = true }
async function revokeSessionAndTokens() {
  if (!selectedSession.value || sessionBusy.value) return
  const mine = epoch, tenant = props.tenant, id = selectedSession.value.id
  sessionBusy.value = true; sessionError.value = ''
  try {
    await api.revokeSession(tenant, id)
    if (mine !== epoch) return
    sessions.items.value = sessions.items.value.filter(x => x.id !== id)
    tokens.items.value = tokens.items.value.filter(x => x.session_id !== id)
    sessionOpen.value = false
  } catch (e) { if (mine === epoch) sessionError.value = errorMessage(e) }
  finally { if (mine === epoch) sessionBusy.value = false }
}
async function revokeSession(s: UserSession) {
  const mine = epoch, tenant = props.tenant
  actionError.value = ''
  try {
    await api.deleteSession(tenant, s.id)
    if (mine !== epoch) return
    sessions.items.value = sessions.items.value.filter((x) => x.id !== s.id)
  } catch (e) {
    if (mine === epoch) actionError.value = errorMessage(e)
  }
}
async function revokeToken(k: UserRefreshToken) {
  const mine = epoch, tenant = props.tenant
  actionError.value = ''
  try {
    await api.deleteRefreshToken(tenant, k.id)
    if (mine !== epoch) return
    tokens.items.value = tokens.items.value.filter((x) => x.id !== k.id)
  } catch (e) {
    if (mine === epoch) actionError.value = errorMessage(e)
  }
}

function askAll(w: 'sessions' | 'tokens') {
  all.value = w
  allError.value = ''
  open.value = true
}
async function revokeAll() {
  if (busy.value) return
  const mine = epoch, tenant = props.tenant, id = uid(), kind = all.value
  busy.value = true
  allError.value = ''
  try {
    if (kind === 'sessions') {
      await api.deleteUserSessions(tenant, id)
      if (mine !== epoch) return
      sessions.items.value = []
      sessions.next.value = undefined
    } else {
      await api.deleteUserRefreshTokens(tenant, id)
      if (mine !== epoch) return
      tokens.items.value = []
      tokens.next.value = undefined
    }
    open.value = false
  } catch (e) {
    if (mine === epoch) allError.value = errorMessage(e)
  } finally {
    if (mine === epoch) busy.value = false
  }
}

const when = (iso: string | null) => (iso ? formatTime(iso, locale.value) : t('users.never'))
</script>

<template>
  <div class="stack">
    <Banner v-if="actionError" kind="error">{{ actionError }}</Banner>

    <section class="stack" aria-labelledby="sessions-title">
      <div class="row">
        <h2 id="sessions-title" class="m-0">{{ t('userd.sessions') }}</h2>
        <span class="flex-1" />
        <Button v-if="sessions.items.value.length > 0" variant="danger" @click="askAll('sessions')">{{ t('userd.revokeAllSessions') }}</Button>
      </div>
      <Banner v-if="sessions.error.value" kind="error">
        {{ sessions.error.value }}
        <Button variant="ghost" @click="sessions.load()">{{ t('retry') }}</Button>
      </Banner>
      <p v-else-if="sessions.loading.value && sessions.items.value.length === 0" class="muted" role="status">{{ t('loading') }}</p>
      <div v-else-if="sessions.items.value.length === 0" class="card empty"><p>{{ t('userd.noSessions') }}</p></div>
      <table v-else class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('userd.device') }}</th>
            <th scope="col">{{ t('userd.ip') }}</th>
            <th scope="col">{{ t('userd.applications') }}</th>
            <th scope="col">{{ t('userd.lastActive') }}</th>
            <th scope="col"><span class="visually-hidden">{{ t('userd.actions') }}</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in sessions.items.value" :key="s.id">
            <td>{{ s.device.last_user_agent || s.device.initial_user_agent }}</td>
            <td>{{ s.device.last_ip || s.device.initial_ip }}</td>
            <td>{{ s.clients.map((c) => c.client_id).join(', ') }}</td>
            <td>{{ when(s.last_interacted_at) }}</td>
            <td class="stack"><MetadataEditor :id="s.id" :metadata="s.session_metadata" :save="value => saveSessionMetadata(s, value)" />
              <Button variant="danger" :data-testid="'revoke-session-' + s.id" @click="askSession(s)">{{ t('rt48.sessionRevoke') }}</Button>
              <Button :aria-label="t('userd.revokeSession', { id: s.id })" @click="revokeSession(s)">{{ t('rt48.sessionDelete') }}</Button><p class="muted m-0">{{ t('rt48.sessionDeleteHint') }}</p>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="sessions.next.value" class="row">
        <Button :disabled="sessions.loading.value" @click="sessions.load(true)">{{ t('userd.moreSessions') }}</Button>
      </div>
    </section>

    <section class="stack" aria-labelledby="tokens-title">
      <div class="row">
        <h2 id="tokens-title" class="m-0">{{ t('userd.tokens') }}</h2>
        <span class="flex-1" />
        <Button v-if="tokens.items.value.length > 0" variant="danger" @click="askAll('tokens')">{{ t('userd.revokeAllTokens') }}</Button>
      </div>
      <Banner v-if="tokens.error.value" kind="error">
        {{ tokens.error.value }}
        <Button variant="ghost" @click="tokens.load()">{{ t('retry') }}</Button>
      </Banner>
      <p v-else-if="tokens.loading.value && tokens.items.value.length === 0" class="muted" role="status">{{ t('loading') }}</p>
      <div v-else-if="tokens.items.value.length === 0" class="card empty"><p>{{ t('userd.noTokens') }}</p></div>
      <table v-else class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('userd.application') }}</th>
            <th scope="col">{{ t('userd.api') }}</th>
            <th scope="col">{{ t('userd.created') }}</th>
            <th scope="col">{{ t('userd.lastUsed') }}</th>
            <th scope="col"><span class="visually-hidden">{{ t('userd.actions') }}</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="k in tokens.items.value" :key="k.id">
            <td><code>{{ k.client_id }}</code></td>
            <td>{{ k.resource_servers.map((r) => r.audience).join(', ') }}</td>
            <td>{{ when(k.created_at) }}</td>
            <td>{{ when(k.last_exchanged_at) }}
              <details><summary>{{ t('rt48.tokenDevices') }}</summary><dl>
                <dt>{{ t('rt48.initialIP') }}</dt><dd>{{ k.device?.initial_ip || '—' }}</dd><dt>{{ t('rt48.lastIP') }}</dt><dd>{{ k.device?.last_ip || '—' }}</dd>
                <dt>{{ t('rt48.initialAgent') }}</dt><dd>{{ k.device?.initial_user_agent || '—' }}</dd><dt>{{ t('rt48.lastAgent') }}</dt><dd>{{ k.device?.last_user_agent || '—' }}</dd>
              </dl></details>
              <MetadataEditor :id="k.id" :metadata="k.refresh_token_metadata" :save="value => saveTokenMetadata(k, value)" />
            </td>
            <td><Button variant="danger" :aria-label="t('userd.revokeToken', { id: k.id })" @click="revokeToken(k)">{{ t('userd.revoke') }}</Button></td>
          </tr>
        </tbody>
      </table>
      <div v-if="tokens.next.value" class="row">
        <Button :disabled="tokens.loading.value" @click="tokens.load(true)">{{ t('userd.moreTokens') }}</Button>
      </div>
    </section>

    <ConfirmDialog v-model:open="sessionOpen" :title="t('rt48.sessionRevoke')" :description="t('rt48.sessionRevokeBody')" :confirm-label="t('rt48.sessionRevoke')" :busy="sessionBusy" :error="sessionError" @confirm="revokeSessionAndTokens" />
    <ConfirmDialog
      v-model:open="open"
      :title="all === 'sessions' ? t('userd.revokeAllSessions') : t('userd.revokeAllTokens')"
      :description="all === 'sessions' ? t('userd.revokeAllSessionsBody') : t('userd.revokeAllTokensBody')"
      :confirm-label="t('userd.revokeAll')"
      :busy="busy"
      :error="allError"
      @confirm="revokeAll"
    />
  </div>
</template>
