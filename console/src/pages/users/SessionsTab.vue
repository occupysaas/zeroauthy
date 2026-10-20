<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SystemTenant, User, UserRefreshToken, UserSession } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ConfirmDialog from './ConfirmDialog.vue'
import { formatTime } from './policy'

const { t, locale } = useI18n()
const props = defineProps<{ tenant: SystemTenant; user: User }>()
const { api } = useServices()

const TAKE = 50
const uid = () => props.user.user_id ?? ''

// One list with its own checkpoint cursor, loading and error.
function pager<T>(fetch: (from?: string) => Promise<{ items: T[]; next?: string }>) {
  const items = ref<T[]>([]) as { value: T[] }
  const loading = ref(true)
  const error = ref('')
  const next = ref<string | undefined>()
  async function load(more = false) {
    loading.value = true
    error.value = ''
    try {
      const r = await fetch(more ? next.value : undefined)
      items.value = more ? [...items.value, ...r.items] : r.items
      // A short page is the last; next is present on every non-empty page.
      next.value = r.items.length >= TAKE ? r.next : undefined
    } catch (e) {
      error.value = errorMessage(e)
    } finally {
      loading.value = false
    }
  }
  return { items, loading, error, next, load }
}

const sessions = pager<UserSession>(async (from) => {
  const r = await api.listUserSessions(props.tenant, uid(), { take: TAKE, from })
  return { items: r.sessions, next: r.next }
})
const tokens = pager<UserRefreshToken>(async (from) => {
  const r = await api.listUserRefreshTokens(props.tenant, uid(), { take: TAKE, from })
  return { items: r.tokens, next: r.next }
})
onMounted(() => {
  void sessions.load()
  void tokens.load()
})

const actionError = ref('')
async function revokeSession(s: UserSession) {
  actionError.value = ''
  try {
    await api.deleteSession(props.tenant, s.id)
    sessions.items.value = sessions.items.value.filter((x) => x.id !== s.id)
  } catch (e) {
    actionError.value = errorMessage(e)
  }
}
async function revokeToken(k: UserRefreshToken) {
  actionError.value = ''
  try {
    await api.deleteRefreshToken(props.tenant, k.id)
    tokens.items.value = tokens.items.value.filter((x) => x.id !== k.id)
  } catch (e) {
    actionError.value = errorMessage(e)
  }
}

const all = ref<'sessions' | 'tokens' | null>(null)
const open = ref(false)
const busy = ref(false)
const allError = ref('')
function askAll(w: 'sessions' | 'tokens') {
  all.value = w
  allError.value = ''
  open.value = true
}
async function revokeAll() {
  busy.value = true
  allError.value = ''
  try {
    if (all.value === 'sessions') {
      await api.deleteUserSessions(props.tenant, uid())
      sessions.items.value = []
      sessions.next.value = undefined
    } else {
      await api.deleteUserRefreshTokens(props.tenant, uid())
      tokens.items.value = []
      tokens.next.value = undefined
    }
    open.value = false
  } catch (e) {
    allError.value = errorMessage(e)
  } finally {
    busy.value = false
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
            <td><Button variant="danger" :aria-label="t('userd.revokeSession', { id: s.id })" @click="revokeSession(s)">{{ t('userd.revoke') }}</Button></td>
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
            <td>{{ when(k.last_exchanged_at) }}</td>
            <td><Button variant="danger" :aria-label="t('userd.revokeToken', { id: k.id })" @click="revokeToken(k)">{{ t('userd.revoke') }}</Button></td>
          </tr>
        </tbody>
      </table>
      <div v-if="tokens.next.value" class="row">
        <Button :disabled="tokens.loading.value" @click="tokens.load(true)">{{ t('userd.moreTokens') }}</Button>
      </div>
    </section>

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
