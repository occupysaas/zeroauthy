<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SystemTenant, User, UserIdentity } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Tag from '../../ui/Tag.vue'
import ConfirmDialog from '../../ui/ConfirmDialog.vue'

const { t } = useI18n()
const props = defineProps<{ tenant: SystemTenant; user: User }>()
const emit = defineEmits<{ identities: [UserIdentity[]] }>()
const { api } = useServices()

const DB = 'auth0|'
const query = ref('')
const results = ref<User[] | null>(null)
const searching = ref(false)
const searchError = ref('')
const status = ref('')

// The first identity is the user's own; only linked ones can be unlinked.
const own = () => props.user.identities?.[0]

async function search() {
  if (!query.value.trim()) return
  searching.value = true
  searchError.value = ''
  status.value = ''
  results.value = null
  try {
    const r = await api.listUsers(props.tenant, { q: query.value, page: 0, per_page: 20 })
    results.value = r.users.filter((u) => u.user_id?.startsWith(DB) && u.user_id !== props.user.user_id)
  } catch (e) {
    searchError.value = errorMessage(e)
  } finally {
    searching.value = false
  }
}

const linking = ref<User | null>(null)
const unlinking = ref<UserIdentity | null>(null)
const open = ref(false)
const openUnlink = ref(false)
const busy = ref(false)
const error = ref('')

function askLink(u: User) {
  linking.value = u
  error.value = ''
  open.value = true
}
function askUnlink(i: UserIdentity) {
  unlinking.value = i
  error.value = ''
  openUnlink.value = true
}

async function link() {
  const u = linking.value
  if (!u?.user_id) return
  busy.value = true
  error.value = ''
  try {
    emit('identities', await api.linkUser(props.tenant, props.user.user_id ?? '', u.user_id.slice(DB.length)))
    open.value = false
    results.value = (results.value ?? []).filter((r) => r.user_id !== u.user_id)
    status.value = t('userd.linked')
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}

async function unlink() {
  const i = unlinking.value
  if (!i) return
  busy.value = true
  error.value = ''
  try {
    emit('identities', await api.unlinkUser(props.tenant, props.user.user_id ?? '', i.provider, i.user_id))
    openUnlink.value = false
    status.value = t('userd.unlinked')
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}

function emailOf(i: UserIdentity): string {
  const e = i.profileData?.email
  return typeof e === 'string' ? e : ''
}
</script>

<template>
  <div class="stack">
    <p v-if="status" role="status" class="m-0">{{ status }}</p>
    <ul class="m-0 list-none stack p-0">
      <li v-for="i in user.identities ?? []" :key="i.provider + '|' + i.user_id" class="card row flex-nowrap justify-between">
        <div>
          <strong>{{ i.connection }}</strong>
          <Tag v-if="i === own()" class="ml-2">{{ t('userd.main') }}</Tag>
          <br />
          <code>{{ i.provider }}|{{ i.user_id }}</code>
          <template v-if="emailOf(i)"><br /><span class="muted">{{ emailOf(i) }}</span></template>
        </div>
        <Button v-if="i !== own()" variant="danger" @click="askUnlink(i)">{{ t('userd.unlink') }}</Button>
      </li>
    </ul>

    <section class="card stack" aria-labelledby="link-title">
      <h2 id="link-title" class="m-0">{{ t('userd.linkTitle') }}</h2>
      <p class="muted m-0">{{ t('userd.linkHint') }}</p>
      <form class="row items-start" role="search" @submit.prevent="search">
        <div class="flex-1">
          <Field id="link-search" :label="t('users.search')" :hint="t('users.searchHint')">
            <input id="link-search" v-model="query" type="search" autocomplete="off" spellcheck="false" />
          </Field>
        </div>
        <Button class="self-end" type="submit" :disabled="searching">{{ t('users.searchSubmit') }}</Button>
      </form>
      <Banner v-if="searchError" kind="error">{{ searchError }}</Banner>
      <p v-else-if="searching" class="muted m-0" role="status">{{ t('loading') }}</p>
      <p v-else-if="results && results.length === 0" class="muted m-0">{{ t('userd.linkNone') }}</p>
      <ul v-else-if="results" class="m-0 list-none p-0" data-testid="link-results">
        <li v-for="r in results" :key="r.user_id" class="row flex-nowrap justify-between">
          <span>{{ r.email || r.name || r.user_id }} <span class="muted">{{ r.user_id }}</span></span>
          <Button @click="askLink(r)">{{ t('userd.link') }}</Button>
        </li>
      </ul>
    </section>

    <ConfirmDialog v-model:open="open" :title="t('userd.linkConfirm')" :description="t('userd.linkWarn', { who: linking?.email || linking?.user_id || '' })" :confirm-label="t('userd.linkConfirm')" :busy="busy" :error="error" :danger="false" @confirm="link" />
    <ConfirmDialog v-model:open="openUnlink" :title="t('userd.unlinkConfirm')" :description="t('userd.unlinkWarn')" :confirm-label="t('userd.unlinkConfirm')" :busy="busy" :error="error" @confirm="unlink" />
  </div>
</template>
